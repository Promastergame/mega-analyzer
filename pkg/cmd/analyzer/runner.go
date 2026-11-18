package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"mega-analyzer/pkg/debugger"
	"mega-analyzer/pkg/gamemode"
	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/artifacts"
	"mega-analyzer/pkg/internal/attackchain"
	"mega-analyzer/pkg/internal/cache"
	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/correlation"
	"mega-analyzer/pkg/internal/decisionai"
	"mega-analyzer/pkg/internal/deobfuscation"
	"mega-analyzer/pkg/internal/evidencegraph"
	"mega-analyzer/pkg/internal/ipaloader"
	"mega-analyzer/pkg/internal/pipeline"
	"mega-analyzer/pkg/internal/report"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/internal/verdict"
	"mega-analyzer/pkg/logger"
	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/ml/training"

	apperrors "mega-analyzer/pkg/internal/errors"
)

// crackPointHighConfidence mirrors crackpoint.HighConfidenceThreshold for the
// merged TotalHighConf count, without importing the engine package here.
const crackPointHighConfidence = 0.75

// ═══════════════════════════════════════════════════════════════════════════════
// APPLICATION
// ═══════════════════════════════════════════════════════════════════════════════

type App struct {
	opts     *CLIOptions
	theme    Theme
	output   *Output
	profiler *Profiler // pprof profiler

	extractor         *apkloader.Extractor
	tempDir           string // для cleanup в конце анализа
	originalAPKPath   string // оригинальный путь к APK файлу (до распаковки)
	bundleScan        *apkloader.BundleScanResult
	bundleScanSeconds float64
	staticOutputs     []types.StaticOutputStage
	bundleFindings    []types.ArtifactFinding // direct JS/HBC input coverage and findings
	ipaFindings       []types.ArtifactFinding // IPA permission audit findings
	ipaCrackPoints    []types.CrackPoint      // iOS license/IAP/jailbreak gates

	// lastPatchPoints holds the scored methods from the most recent --ml-patch
	// run (set in runMLPatch, consumed by buildMLFeedback to populate
	// AnalysisFeedback.MethodFeatures before saveToMLHistory persists it).
	lastPatchPoints []ml.PatchPoint
	outputCleaned   bool

	// exitCode задаётся assessExit (только с -exit-codes).
	exitCode int

	// interrupted is set by the SIGINT/SIGTERM monitor in setupContext.
	// Post-pipeline stages check it to skip heavy work (GNN with its own
	// detached budget, ML patch predictor, history) so Ctrl+C exits fast
	// instead of grinding through minutes of partial-result processing.
	interrupted atomic.Bool

	// save_log tee state: when --save_log is set, logWriter fans console output
	// out to both os.Stdout and logFile; savedLogPath is the resolved file path.
	logFile      *os.File
	logWriter    io.Writer
	savedLogPath string

	// tui holds the interactive wizard's state when it was used to gather
	// options, so the Results screen can be populated with the real
	// analysis outcome once it completes (see showResults in
	// tui_results.go). Nil when running in -notui / classic CLI mode.
	tui *tuiState
}

func NewApp() *App {
	return &App{}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUN — основной flow приложения
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) Run(args []string) error {
	// 1. Parse CLI
	opts, err := a.parseFlags(args)
	if err != nil {
		return err
	}
	a.opts = opts

	// --save_log: make sure the log file is flushed and closed when Run returns.
	defer func() {
		if a.logFile != nil {
			_ = a.logFile.Close()
		}
	}()

	// Explicit, validated web-only elevation precedes every action dispatcher.
	if opts.Admin {
		return runAdminWeb(opts)
	}

	if opts.ExplainResult != "" {
		return a.runEvidenceExplain()
	}
	if opts.DecisionAIInput != "" {
		return a.runDecisionAIRequest()
	}
	if opts.Minecraft {
		return runMinecraft(opts)
	}

	// Ensure profiler is stopped on exit
	if a.opts.PprofAddr != "" || a.opts.CPUProfile != "" || a.opts.MemProfile != "" {
		defer func() {
			if a.profiler != nil {
				a.profiler.Stop()
			}
		}()
	}

	// ══════════════════════════════════════════════════════════════════════════
	// SANDBOX STREAM COMMAND — real-time telemetry stream for Zig GUI
	// ══════════════════════════════════════════════════════════════════════════
	if opts.SandboxStream {
		if err := a.runSandboxStream(); err != nil {
			return err
		}
		return nil
	}

	// ══════════════════════════════════════════════════════════════════════════
	// APK PATCH EDITOR COMMAND — launch native Zig GUI editor
	// ══════════════════════════════════════════════════════════════════════════
	if opts.IsAPKEditorCommand() {
		patchesPath := ""
		if opts.Target != "" {
			possiblePatches := filepath.Join(opts.Target, "patches.json")
			if _, err := os.Stat(possiblePatches); err == nil {
				patchesPath = possiblePatches
			} else if opts.Output != "" {
				possibleOutPatches := filepath.Join(opts.Output, "patches.json")
				if _, err := os.Stat(possibleOutPatches); err == nil {
					patchesPath = possibleOutPatches
				}
			}
		}
		if err := LaunchAPKEditor(opts.Target, patchesPath); err != nil {
			return err
		}
		a.output.Success("Launched the native Zig APK Patch Editor for: %s", opts.Target)
		return nil
	}

	// ══════════════════════════════════════════════════════════════════════════
	// ASSET SCAN — find 3D models, textures and obfuscated images in a file,
	// folder or APK, render them to PNG, and optionally open the Zig editor.
	// Runs before Validate() on purpose: it needs no analysis target.
	// ══════════════════════════════════════════════════════════════════════════
	if opts.AssetScan != "" {
		return runAssetScan(opts)
	}

	// ══════════════════════════════════════════════════════════════════════════
	// WEB UI — local drag-and-drop analysis server
	// ══════════════════════════════════════════════════════════════════════════
	if opts.Web {
		return runWebUIOptions(opts)
	}

	// REST API — served by the same executable; no analyzer-api sidecar binary.
	if opts.APIServer {
		if err := opts.Validate(); err != nil {
			return err
		}
		if err := a.initialize(); err != nil {
			return err
		}
		return a.handleAPIServer()
	}

	// ══════════════════════════════════════════════════════════════════════════
	// WEB IMPORT — html-body / curl / raw-request (no target required)
	// ══════════════════════════════════════════════════════════════════════════
	if opts.HTMLBody != "" || opts.CurlCmd != "" || opts.RawRequest != "" {
		if err := a.initialize(); err != nil {
			return err
		}
		return a.handleWebScanOnly()
	}

	// ══════════════════════════════════════════════════════════════════════════
	// STANDALONE WEB SCAN — --web-scan without a file target
	// ══════════════════════════════════════════════════════════════════════════
	if opts.WebScan && opts.Target == "" {
		if err := a.initialize(); err != nil {
			return err
		}
		return a.handleWebScanOnly()
	}

	// ══════════════════════════════════════════════════════════════════════════
	// ML COMMANDS — не требуют target
	// ══════════════════════════════════════════════════════════════════════════
	if opts.IsMLCommand() {
		if err := opts.Validate(); err != nil {
			return err
		}

		runner, err := NewMLRunner(opts)
		if err != nil {
			return err
		}

		if err := runner.Run(); err != nil {
			return err
		}
		return nil
	}

	// ══════════════════════════════════════════════════════════════════════════
	// DECODE COMMAND — decode APK to directory (apktool-style, no analysis)
	// ══════════════════════════════════════════════════════════════════════════
	if opts.IsDecodeCommand() {
		if err := opts.Validate(); err != nil {
			return err
		}
		if err := a.initialize(); err != nil {
			return err
		}
		if err := a.handleDecode(); err != nil {
			return err
		}
		return nil
	}

	// ══════════════════════════════════════════════════════════════════════════
	// JS DEOBFUSCATION COMMAND — standalone React Native / JS bundle deobfuscator
	// ══════════════════════════════════════════════════════════════════════════
	if opts.IsJSDeobfuscateCommand() {
		if err := opts.Validate(); err != nil {
			return err
		}
		if err := a.initialize(); err != nil {
			return err
		}
		if err := a.handleJSDeobfuscate(); err != nil {
			return err
		}
		return nil
	}

	// ══════════════════════════════════════════════════════════════════════════
	// JS PATCH COMMAND — smart React Native / Hermes bundle patcher
	// ══════════════════════════════════════════════════════════════════════════
	if opts.IsJSPatchCommand() {
		if err := opts.Validate(); err != nil {
			return err
		}
		if err := a.initialize(); err != nil {
			return err
		}
		if err := a.handleJSPatch(); err != nil {
			return err
		}
		return nil
	}

	// ══════════════════════════════════════════════════════════════════════════
	// BUILD / REBUILD COMMAND — build APK from directory
	// ══════════════════════════════════════════════════════════════════════════
	if opts.IsBuildCommand() {
		if err := opts.Validate(); err != nil {
			return err
		}

		if err := a.initialize(); err != nil {
			return err
		}

		if err := a.handleRebuild(); err != nil {
			return err
		}
		return nil
	}

	// ══════════════════════════════════════════════════════════════════════════
	// SANDBOX COMMAND — detonation / process sandbox
	// ══════════════════════════════════════════════════════════════════════════
	if opts.IsSandboxCommand() {
		if err := opts.Validate(); err != nil {
			return err
		}

		if err := a.initialize(); err != nil {
			return err
		}

		if err := a.handleSandbox(); err != nil {
			return err
		}
		return nil
	}

	// ══════════════════════════════════════════════════════════════════════════
	// PRIVATE SERVER TOOLKIT COMMANDS
	// ══════════════════════════════════════════════════════════════════════════
	if opts.IsInterceptCommand() {
		if err := a.handleIntercept(); err != nil {
			return err
		}
		return nil
	}

	if opts.IsServgenCommand() {
		if err := a.handleServgen(); err != nil {
			return err
		}
		return nil
	}

	if opts.IsFuzzCommand() {
		if err := a.handleFuzz(); err != nil {
			return err
		}
		return nil
	}

	if opts.IsLabDNSCommand() {
		if err := a.handleLabDNS(); err != nil {
			return err
		}
		return nil
	}

	if opts.IsVersionDiffCommand() {
		if err := opts.Validate(); err != nil {
			return err
		}
		if err := a.initialize(); err != nil {
			return err
		}
		return a.handleVersionDiff()
	}

	if opts.IsFirmwareCommand() && opts.NoTUI {
		if err := opts.Validate(); err != nil {
			return err
		}
		if err := a.initialize(); err != nil {
			return err
		}
		return a.handleFirmware()
	}

	// ══════════════════════════════════════════════════════════════════════════
	// MAKE-SERVER — authorized-lab Elixir/OTP private server generator
	// ══════════════════════════════════════════════════════════════════════════
	if opts.IsMakeServerCommand() && opts.NoTUI {
		if err := opts.Validate(); err != nil {
			return err
		}
		if err := a.initialize(); err != nil {
			return err
		}
		return a.handleMakeServer()
	}

	// 2. Handle special actions (не требуют инициализации)
	if handled, err := a.handleSpecialActions(); handled || err != nil {
		return err
	}

	if !opts.NoTUI {
		tuiOpts, run, err := a.runTUIWizard(opts)
		if errors.Is(err, errTUIUnsupported) {
			// Interactive TUI isn't available on this platform yet.
			// Fall through to direct CLI mode using whatever flags
			// the user already provided.
			fmt.Fprintln(os.Stderr, "interactive TUI not supported on this platform — running in CLI mode")
			opts.NoTUI = true
			a.opts = opts
		} else {
			if err != nil {
				return err
			}
			if !run {
				return nil
			}
			opts = tuiOpts
			a.opts = opts
		}
	}

	// 3. Validate options
	if err := opts.Validate(); err != nil {
		return fmt.Errorf("invalid options: %w", err)
	}

	// 3.5. Post-TUI dispatch — standalone commands that can be triggered from TUI
	if opts.IsMakeServerCommand() {
		if err := a.initialize(); err != nil {
			return err
		}
		return a.handleMakeServer()
	}
	if opts.IsFirmwareCommand() {
		if err := a.initialize(); err != nil {
			return err
		}
		return a.handleFirmware()
	}
	if opts.IsVersionDiffCommand() {
		if err := a.initialize(); err != nil {
			return err
		}
		return a.handleVersionDiff()
	}

	// 4. Initialize subsystems
	if err := a.initialize(); err != nil {
		return err
	}

	// 4.4. BinZAP bytecode path — the former cmd/binzap tool now runs in-process
	// from the same analyzer executable. It is complementary to the Rust native
	// backend below: BinZAP handles APK/Smali/ASM, Rust handles PE/ELF.
	if opts.Binzap {
		absTarget, err := filepath.Abs(opts.Target)
		if err != nil {
			return fmt.Errorf("invalid BinZAP target: %w", err)
		}
		return a.handleBinzap(absTarget)
	}

	// 4.5. Machine-Code analysis path — direct PE / ELF / .so forensics that
	// bypasses the APK/DEX/Smali pipeline. Activated explicitly with
	// --scan-native or auto-detected for raw native binary targets.
	if a.shouldRunMachineCode() {
		absTarget, err := filepath.Abs(opts.Target)
		if err != nil {
			return fmt.Errorf("invalid machine-code target: %w", err)
		}
		return a.handleMachineCode(absTarget)
	}

	// 5. Build config before input preparation. Preparation is part of the
	// analysis and must respect the selected profile and cancellation/timeout.
	cfg := a.buildConfig()

	// 6. Setup context before extraction/decompilation so Ctrl-C and --timeout
	// also stop the expensive APK preparation phase.
	ctx, stop := a.setupContext()
	defer stop()

	analysisStarted := time.Now()

	// 7. Prepare target (распаковка APK/DEX если нужно)
	absTarget, err := a.prepareTarget(ctx, cfg)
	if err != nil {
		return err
	}
	defer a.cleanup() // cleanup temp после анализа

	// 8. Print config
	a.output.PrintConfig(opts, absTarget)

	// Validate/prepare the output dir BEFORE the expensive analysis so a
	// -clean-output refusal fails fast (seconds) instead of discarding a
	// 30-minute run after it. The later clean sites reuse the outputCleaned
	// guard and become no-ops.
	if opts.CleanOutput && !a.outputCleaned {
		earlyOut := a.opts.Output
		if earlyOut == "" {
			earlyOut = "analysis_output"
		}
		if err := cleanOutputDir(earlyOut); err != nil {
			return err
		}
		a.outputCleaned = true
	}

	// IDE invokes this mode for an already decoded APK folder. The ML patch
	// predictor itself consumes every eligible .smali file (including libraries
	// when requested); a preceding generic pipeline run would additionally parse
	// the original classes*.dex and resources, then the predictor would read the
	// same Smali again. Skip only that duplicate generic pass here.
	if opts.MLPatch && opts.MLPatchDirectSmali {
		outputDir := a.opts.Output
		if outputDir == "" {
			outputDir = "analysis_output"
		}
		if a.opts.CleanOutput && !a.outputCleaned {
			if err := cleanOutputDir(outputDir); err != nil {
				return err
			}
			a.outputCleaned = true
		}
		a.output.Info("ML patch direct Smali mode: skipping duplicate DEX/resource pipeline pass")
		started := time.Now()
		patchFiles, err := a.runMLPatch(ctx, absTarget, outputDir, nil)
		if err != nil {
			return fmt.Errorf("ml patcher failed: %w", err)
		}
		a.output.Info("ML patch direct scan completed in %s", time.Since(started).Round(time.Millisecond))
		a.output.PrintNextSteps(outputDir, !a.opts.NoHTML, patchFiles)
		return nil
	}

	// 9. Run analysis

	result, elapsed, err := a.runAnalysis(ctx, cfg, absTarget)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// 9.5 Inject artifact findings (e.g. native scan findings, IPA findings)
	if a.extractor != nil {
		result.ArtifactFindings = append(result.ArtifactFindings, a.extractor.GetFindings()...)
	}
	result.ArtifactFindings = append(result.ArtifactFindings, a.bundleFindings...)
	if len(a.ipaFindings) > 0 {
		result.ArtifactFindings = append(result.ArtifactFindings, a.ipaFindings...)
	}
	// A multi-ABI native library repeated the same finding once per
	// lib/<abi>/ copy (JNI surface ×5, raw syscall ×3, numeric PIN ×2 on a
	// single clean APK). Merge identical per-ABI copies before reports and
	// the evidence graph are built so the dedup stays consistent everywhere.
	result.ArtifactFindings = dedupeArtifactFindings(result.ArtifactFindings)

	// 9.55 Merge cross-format crack points (JAR / native / iOS) into the unified
	// aggregation so they reach the CLI summary, reports, dashboard and the ML
	// patch-boost (predictor.SetCrackPoints reads result.CrackPoint.Points).
	a.mergeCrossFormatCrackPoints(result)

	// 9.56 Known-set verdict (opt-in -known-set): known-bad = loud alert,
	// known-good = info note. Append-only: never skips analysis.
	if hashTarget := a.originalAPKPath; hashTarget != "" {
		a.applyKnownSetFileHash(result, hashTarget)
	} else {
		a.applyKnownSetFileHash(result, absTarget)
	}

	// 9.6 Machine-Code side-car scan — full native reports for every .so
	// when --scan-native is enabled together with an APK / directory target.
	if a.opts.MachineCode {
		mcReports, err := a.runMachineCodeSidecar(absTarget, a.opts.Output)
		if err != nil {
			a.output.Warning("Machine-code side-car scan failed: %v", err)
		} else {
			result.MachineCodeReports = mcReports
		}
	}

	// Resolve output dir once for all generators. NOTE: -clean-output was
	// already applied before the analysis (fail fast); the guarded sites in
	// generateReports stay as no-ops. Cleaning here — after correlation or
	// sidecars wrote files — would delete just-written reports, so never
	// clean past this point.
	outputDir := a.opts.Output
	if outputDir == "" {
		outputDir = "analysis_output"
	}
	// Static correlation now receives the real analysis result. This activates
	// Android exploit-chain templates without re-running the scanner.
	if cfg.EnableCorrelations {
		engine := correlation.NewEngine(attackchain.DefaultChains())
		correlated := engine.Run(correlation.Input{Static: result, SessionID: filepath.Base(absTarget)})
		if correlated != nil {
			correlationDir := filepath.Join(outputDir, "correlation")
			if _, _, writeErr := correlation.WriteReports(correlated, correlationDir); writeErr != nil {
				a.output.Warning("Static correlation report write failed: %v", writeErr)
			} else {
				a.output.Info("Static correlation: %d findings, %d attack chains", correlated.Stats.TotalFindings, correlated.Stats.TotalChains)
			}
		}
	}

	a.runSidecarModules(result, absTarget, outputDir, a.originalAPKPath)

	// 9.7 Integrated website analysis (status, passive, or active vulnscan)
	if a.opts.WebScan {
		if err := a.handleWebScan(result, outputDir); err != nil {
			a.output.Warning("Web analysis failed: %v", err)
		}
	}

	// Artifacts live under the managed result folder, never the upload temp.
	staticOutputErr := a.runStaticOutputs(ctx, absTarget, outputDir)
	if staticOutputErr != nil {
		a.output.Warning("Requested static outputs incomplete: %v", staticOutputErr)
	}

	a.finalizeBundleSummary(result, elapsed, time.Since(analysisStarted))
	if result.BundleAnalysis != nil {
		elapsed = time.Duration(result.Duration)
	}

	// 10. Generate reports
	if err := a.generateReports(ctx, result, outputDir); err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	// 10.05 OBB / Data / Cache deep scanner
	if a.opts.OBBScan {
		if err := a.handleOBBScan(outputDir); err != nil {
			a.output.Warning("OBB scanner failed: %v", err)
		}
	}

	// 10.06 Cache security analyzer
	if a.opts.CacheScan {
		if err := a.handleCacheScan(outputDir); err != nil {
			a.output.Warning("Cache analyzer failed: %v", err)
		}
	}

	// 10.07 ML-Apli-Cache script (predictive exploitation analysis)
	if a.opts.MLCacheScript {
		if err := a.handleMLCacheScript(outputDir); err != nil {
			a.output.Warning("ML-Apli-Cache script failed: %v", err)
		}
	}

	// 10.1 Experimental modules (AEG / Mach-O / BinSim / Reach)
	if a.opts.MLEx {
		if _, err := a.runExperimental(ctx, result, absTarget, outputDir); err != nil {
			a.output.Warning("Experimental subsystem failed: %v", err)
		} else {
			// Re-generate reports so experimental findings show up too.
			if err := a.generateReports(ctx, result, outputDir); err != nil {
				return fmt.Errorf("report refresh failed: %w", err)
			}
		}
	}

	// 10.2 ML patch predictor (optional)
	var patchFiles []GeneratedFile
	if a.opts.SARIF {
		patchFiles = append(patchFiles, GeneratedFile{
			Name: "analysis.sarif",
			Desc: "SARIF code-scanning report",
		})
	}
	if a.opts.MLPatch && !a.interrupted.Load() {
		patchFiles, err = a.runMLPatch(ctx, absTarget, outputDir, result)
		if err != nil {
			return fmt.Errorf("ml patcher failed: %w", err)
		}
	} else if a.interrupted.Load() {
		a.output.Info("Interrupted — skipping ML patch predictor (partial reports only)")
	}

	// 10.5 Save to ML history (для будущих suggestions).
	// Skipped on interrupt: partial runs must not train future suggestions.
	if !a.interrupted.Load() {
		a.saveToMLHistory(result, absTarget)
	}

	// 10.8 Gamemode Integration (only for static analysis targets). Also
	// runs whenever the interactive wizard was used (a.tui != nil) even
	// without --gamemode, so the TUI's own Results screen has real data to
	// show instead of "No analysis data yet" once the run completes.
	// Skipped on interrupt: it re-runs a full directory prediction pass.
	if (a.opts.GameMode || a.tui != nil) && !a.interrupted.Load() {
		if a.opts.GameMode {
			a.output.Info("Triggering Epic Game Mode scoring...")
		}

		// 1. Create a PatchPredictor to collect the PatchPoints
		mode := a.mlPatchMode()

		cfg := ml.DefaultPredictorConfig()
		cfg.IncludeLibraries = a.opts.MLPatchIncludeLibs
		if a.opts.MLPatchMinScore >= 0 {
			cfg.MinScore = a.opts.MLPatchMinScore
		}
		cfg.Mode = mode

		predictor := ml.NewPatchPredictorWithConfig(io.Discard, cfg)
		if s, err := training.NewEnsembleModelScorer(); err == nil && s.IsLoaded() {
			predictor.SetTrainedRiskScorer(s)
		}
		predictor.SetCrackPoints(crackPointsFromResult(result))
		if result.CallGraph != nil {
			predictor.SetCallGraph(result.CallGraph)
		}
		prediction, err := predictor.PredictFromDirectory(absTarget)
		var points []ml.PatchPoint
		if err == nil && prediction != nil {
			points = collectPatchPoints(prediction)
		} else {
			points = []ml.PatchPoint{}
		}

		// 2. Process GameMode scoring
		gmm := gamemode.NewEpicGameModeManager("default")
		gmm.Enable(true)

		isStatic := true
		isPatcher := a.opts.MLPatch
		isFeedback := a.opts.MarkRelevant != "" || a.opts.MarkNoise != "" || a.opts.MLPatchFeedbackImport != "" || a.opts.MLPatchFeedbackExport != "" || a.opts.FeedbackFile != ""

		enhanced := gmm.ProcessAnalysis(result, points, isStatic, isPatcher, isFeedback)

		// 3. Print the Epic gaming retro-style terminal output!
		if a.opts.GameMode {
			apkName := filepath.Base(a.opts.Target)
			epicOutput := gmm.FormatEpicResult(apkName, enhanced, prediction)
			fmt.Println(epicOutput)
		}

		// 4. Feed the interactive wizard's Results screen, if it was used.
		if a.tui != nil && enhanced.HasGameData() {
			a.tui.showResults(enhanced.GameData)
		}
	}

	// 11. Print results
	a.output.PrintResults(result, elapsed)
	a.output.PrintNextSteps(outputDir, !a.opts.NoHTML, patchFiles)

	a.assessExit(result)

	return staticOutputErr
}

// ═══════════════════════════════════════════════════════════════════════════════
// PARSE FLAGS
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) parseFlags(args []string) (*CLIOptions, error) {
	parser := NewCLIParser()
	return parser.Parse(args)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SPECIAL ACTIONS — --version, --help, --list-profiles
// ═══════════════════════════════════════════════════════════════════════════════

// handleSpecialActions обрабатывает флаги, не требующие полного запуска.
// Возвращает (handled=true, nil) если действие выполнено.
func (a *App) handleSpecialActions() (bool, error) {
	switch {
	case a.opts.CacheClear:
		cm := cache.NewCacheManager("")
		if err := cm.Clear(); err != nil {
			return true, fmt.Errorf("failed to clear cache: %w", err)
		}
		fmt.Println("✓ Cache cleared successfully")
		return true, nil

	case a.opts.CacheStats:
		cm := cache.NewCacheManager("")
		stats, err := cm.GetStats()
		if err != nil {
			return true, fmt.Errorf("failed to get cache stats: %w", err)
		}
		stats.Print()
		return true, nil

	case a.opts.CachePrune:
		cm := cache.NewCacheManager("")
		removed, err := cm.Prune(a.opts.CachePruneDays)
		if err != nil {
			return true, fmt.Errorf("failed to prune cache: %w", err)
		}
		fmt.Printf("✓ Pruned %d cache files (older than %d days)\n", removed, a.opts.CachePruneDays)
		return true, nil

	case a.opts.ValidateConfig != "":
		result, err := config.ValidateConfigFile(a.opts.ValidateConfig)
		if err != nil {
			return true, fmt.Errorf("failed to validate config: %w", err)
		}
		result.Print()
		if !result.Valid {
			return true, fmt.Errorf("config validation failed")
		}
		return true, nil

	case a.opts.Completion != "":
		cmd := NewCompletionCommand(a.opts.Completion)
		if err := cmd.Run(); err != nil {
			return true, fmt.Errorf("failed to generate completion: %w", err)
		}
		return true, nil

	case a.opts.LaunchDebugger:
		target := a.opts.Target
		if target == "" {
			return true, fmt.Errorf("--debugger requires a target binary path")
		}
		if err := debugger.RunREPL(target, a.opts.DebugEntry); err != nil {
			return true, fmt.Errorf("debugger error: %w", err)
		}
		return true, nil

	case a.opts.Version:
		a.printVersion()
		return true, nil

	case a.opts.ToolsInfo:
		a.printToolsInfo()
		return true, nil

	case a.opts.Help:
		NewCLIParser().printUsage()
		return true, nil

	case a.opts.ListProfiles:
		a.listProfiles()
		return true, nil
	}
	return false, nil
}

func (a *App) printToolsInfo() {
	fmt.Printf("%s tools (bundled tools are unpacked on first use to %s):\n", AppName, apkloader.ToolsCacheDir())
	for _, t := range apkloader.ToolsReport() {
		if t.Path == "" {
			fmt.Printf("  %-9s MISSING\n", t.Name)
			continue
		}
		v := ""
		if t.Version != "" {
			v = "  (" + t.Version + ")"
		}
		fmt.Printf("  %-9s %-9s %s%s\n", t.Name, t.Source, t.Path, v)
	}
}

func (a *App) printVersion() {
	fmt.Printf("%s v%s\n", AppName, Version)
	fmt.Printf("Build: %s (%s)\n", BuildDate, CommitHash)
}

func (a *App) listProfiles() {
	fmt.Println("Available analysis profiles:")
	fmt.Println()

	profiles := []AnalysisProfile{ProfileQuick, ProfileBalanced, ProfileDeep, ProfileParanoid}
	for _, p := range profiles {
		marker := "  "
		if p == ProfileBalanced {
			marker = "* "
		}
		fmt.Printf("%s%-10s - %s\n", marker, p, p.Description())
	}

	fmt.Println()
	fmt.Println("* = default")
}

// ═══════════════════════════════════════════════════════════════════════════════
// INITIALIZE — theme, output, logger
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) initialize() error {
	// Theme & output
	a.theme = DetectTheme(a.opts.NoColor)
	a.output = NewOutput(a.theme, a.opts.Quiet)
	if a.opts.SaveLog {
		if err := a.setupSaveLog(); err != nil {
			a.output.Warning("--save_log disabled: %v", err)
		} else if a.logWriter != nil {
			a.output = NewOutputWithWriter(a.theme, a.opts.Quiet, a.logWriter)
			// Keep the animated progress bar on the real terminal; only the
			// regular report text is teed into the --save_log file.
			a.output.SetProgressWriter(os.Stdout)
		}
	}
	a.output.SetTUI(!a.opts.NoTUI)

	// Profiler (if enabled)
	if a.opts.PprofAddr != "" || a.opts.CPUProfile != "" || a.opts.MemProfile != "" {
		a.profiler = NewProfiler(a.opts.PprofAddr)
		a.profiler.Enable()
		if err := a.profiler.Start(); err != nil {
			a.output.Warning("Failed to start profiler: %v", err)
		}
	}

	// APK/DEX loader
	a.extractor = apkloader.NewExtractor()

	// Logger
	if err := a.setupLogger(); err != nil {
		return fmt.Errorf("failed to init logger: %w", err)
	}

	// Banner
	a.output.PrintBanner()

	if a.opts.SaveLog && a.savedLogPath != "" {
		a.output.Info("Full session log -> %s (--save_log, format=%s)", a.savedLogPath, a.opts.SaveLogFormat)
	}

	return nil
}

func (a *App) setupLogger() error {
	level := logger.InfoLevel
	disableConsole := true // отключить консоль чтобы не мешать progress bar

	switch {
	case a.opts.DebugVerbose:
		level = logger.DebugLevel
		disableConsole = false // в дебаге пишем в консоль
	case a.opts.Quiet:
		level = logger.ErrorLevel
	}

	logPath := ""
	if a.opts.Output != "" {
		// In rebuild mode `Output` is the path to the produced APK file,
		// not a directory. Joining "analyzer.log" onto it would force the
		// logger to MkdirAll a folder named like the APK, which then makes
		// the rebuilder fail because the destination ZIP path is suddenly
		// a directory. Detect that case and put the log next to the APK
		// instead.
		if a.opts.IsRebuildCommand() {
			logPath = filepath.Join(filepath.Dir(a.opts.Output), "analyzer.log")
		} else {
			logPath = filepath.Join(a.opts.Output, "analyzer.log")
		}
	}

	return logger.Init(logger.Config{
		Level:          level,
		OutputPath:     logPath,
		DisableConsole: disableConsole,
	})
}

// ════════════════════════════════════════════════════���══════════════════════════
// CONTEXT — graceful shutdown без goroutine leak
// ═══════════════════════════════════════════════════════════════════════════════

// setupContext создаёт context с timeout и signal handling.
// Возвращает stop-функцию, которая ОБЯЗАТЕЛЬНО должна быть вызвана (defer stop()).
func (a *App) setupContext() (context.Context, context.CancelFunc) {
	var ctx context.Context
	var cancel context.CancelFunc

	// Базовый context с timeout (0 = без лимита)
	if a.opts.Timeout > 0 {
		ctx, cancel = context.WithTimeout(
			context.Background(),
			time.Duration(a.opts.Timeout)*time.Second,
		)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}

	// Signal handling
	sigCtx, sigStop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)

	// Мониторинг сигнала для вывода предупреждения
	go func() {
		<-sigCtx.Done()
		// Проверяем: это сигнал или обычное завершение?
		if ctx.Err() == nil {
			// ctx ещё жив → значит, был сигнал
			a.interrupted.Store(true)
			a.output.ClearProgress()
			a.output.Warning("Interrupted — stopping workers (heavy stages will be skipped)...")
		}
	}()

	// stop = отменяем всё + освобождаем signal subscription
	stop := func() {
		// Cancel the parent first: normal cleanup must not look like a signal.
		cancel()
		sigStop()
	}

	return sigCtx, stop
}

// ═══════════════════════════════════════════════════════════════════════════════
// VALIDATION & PREPARATION
// ═══════════════════════════════════════════════════════════════════════════════

// prepareTarget проверяет target и подготавливает его для анализа
// Если это APK/DEX — распаковывает контейнер, сохраняя classes*.dex как есть.
// DEX разбирается анализатором напрямую; Smali-файлы создаёт только -decode.
func (a *App) prepareTarget(ctx context.Context, cfg *config.Config) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	absTarget, err := filepath.Abs(a.opts.Target)
	if err != nil {
		return "", apperrors.WrapWithHint(err, "invalid target path")
	}

	info, err := os.Stat(absTarget)
	if err != nil {
		if os.IsNotExist(err) {
			return "", apperrors.WithHint(
				fmt.Errorf("target not found: %s", absTarget),
				apperrors.HintCheckFile,
			)
		}
		return "", apperrors.WrapWithHint(err, "cannot access target")
	}

	// Если это файл — определяем тип и распаковываем
	if !info.IsDir() {
		a.output.Info("Detected input: %s (%d bytes)", filepath.Base(absTarget), info.Size())
		if isStandaloneBundle(absTarget) {
			return a.prepareBundle(ctx, absTarget)
		}
		lower := strings.ToLower(absTarget)
		if strings.HasSuffix(lower, ".ipa") {
			return a.extractIPA(ctx, absTarget)
		}
		return a.extractAPKorDEX(ctx, cfg, absTarget)
	}

	// Папка — используем как есть
	return absTarget, nil
}

// extractAPKorDEX распаковывает APK или DEX файл
func (a *App) extractAPKorDEX(ctx context.Context, cfg *config.Config, filePath string) (string, error) {
	a.output.Info("Preparing APK/DEX for analysis...")
	// Static analysis consumes DEX through an in-memory IR.  This is distinct
	// from --decode: no .smali files are materialised in the temporary folder.
	// State this explicitly because every DEX class is still reported as an
	// analysis unit and the old summary label made it look like a decode ran.
	a.output.Info("Direct DEX analysis: in-memory IR only; use --decode to write .smali files")

	// Сохраняем оригинальный путь к APK
	a.originalAPKPath = filePath

	// PrepareInput определит тип и распакует. Ни один профиль анализа не
	// материализует Smali на диск; -decode использует отдельный DecodeAPK API.
	_ = cfg
	extractedPath, err := a.extractor.PrepareInputWithOptions(ctx, filePath, apkloader.PrepareOptions{})
	if err != nil {
		return "", apperrors.WrapWithHint(err, "failed to extract APK/DEX")
	}

	// Сохраняем temp path для cleanup
	a.tempDir = extractedPath

	a.output.Success("Extracted to: %s", extractedPath)
	return extractedPath, nil
}

// extractIPA распаковывает iOS IPA архив и парсит Info.plist
func (a *App) extractIPA(ctx context.Context, ipaPath string) (outDir string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	a.output.Info("Preparing iOS IPA for analysis...")

	a.originalAPKPath = ipaPath

	if !ipaloader.DetectIPA(ipaPath) {
		return "", fmt.Errorf("not a valid IPA archive: %s", ipaPath)
	}

	tempDir, err := os.MkdirTemp("", "ipa_extracted_*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	a.tempDir = tempDir
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tempDir)
			a.tempDir = ""
		}
	}()

	if err := ipaloader.ExtractIPA(ctx, ipaPath, tempDir); err != nil {
		return "", fmt.Errorf("failed to extract IPA: %w", err)
	}

	appDir, err := ipaloader.FindMainBundle(ctx, tempDir)
	if err != nil {
		return "", err
	}
	plists, err := ipaloader.BundlePlists(ctx, appDir)
	if err != nil {
		return "", err
	}
	bundleID := ""
	a.ipaFindings = nil
	for i, plistPath := range plists {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		meta, pErr := ipaloader.ParseInfoPlist(plistPath)
		if pErr == nil && meta != nil {
			if i == 0 {
				bundleID = meta.BundleID
				a.output.Success("IPA metadata: %s v%s (minOS: %s, %d permissions)",
					meta.BundleID, meta.Version, meta.MinOS, len(meta.Permissions))
			}
			relPath, relErr := filepath.Rel(tempDir, plistPath)
			if relErr != nil {
				return "", relErr
			}
			a.ipaFindings = append(a.ipaFindings, ipaloader.AuditPermissions(meta, filepath.ToSlash(relPath))...)
		} else if pErr != nil {
			if i == 0 {
				return "", fmt.Errorf("parse main bundle Info.plist: %w", pErr)
			}
			a.output.Warning("Failed to parse Info.plist: %v", pErr)
		}
	}

	// Crack-point + embedded-secret scan over the app's Mach-O binaries.
	points, secretFindings := ipaloader.CrackPointsForIPA(ctx, tempDir, bundleID)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	a.ipaCrackPoints = points
	a.ipaFindings = append(a.ipaFindings, secretFindings...)
	if len(points) > 0 {
		a.output.Info("iOS crack points found: %d", len(points))
	}

	a.output.Success("IPA extracted to: %s", tempDir)
	return tempDir, nil
}

// mergeCrossFormatCrackPoints folds JAR / native / iOS crack points (collected
// outside the Dalvik pipeline) into result.CrackPoint so they share the unified
// renderer, reports and ML patch-boost. With a trained keyword-relevance model
// on disk, method tokens scored as noise are dropped; without a model the
// relevance step is a no-op and nothing is filtered.
func (a *App) mergeCrossFormatCrackPoints(result *types.AnalysisResult) {
	if result == nil {
		return
	}
	var extra []types.CrackPoint
	if a.extractor != nil {
		extra = append(extra, a.extractor.GetCrackPoints()...)
	}
	extra = append(extra, a.ipaCrackPoints...)
	if len(extra) == 0 {
		return
	}

	if scorer, err := training.NewKeywordScorer(); err == nil && scorer.IsLoaded() {
		kept := extra[:0]
		for _, cp := range extra {
			if ml.IsLikelyNoise(scorer, cp.Method) {
				continue
			}
			kept = append(kept, cp)
		}
		extra = kept
	}

	if result.CrackPoint == nil {
		result.CrackPoint = &types.CrackPointResult{}
	}
	result.CrackPoint.Points = append(result.CrackPoint.Points, extra...)

	high := 0
	for _, cp := range result.CrackPoint.Points {
		if cp.Confidence >= crackPointHighConfidence {
			high++
		}
	}
	result.CrackPoint.TotalHighConf = high
}

// dedupeArtifactFindings merges artifact findings that repeat identically once
// per ABI copy of the same native library (lib/arm64-v8a/x.so,
// lib/x86_64/x.so, …). A clean 4-ABI APK reported the same JNI-surface,
// raw-syscall and numeric-PIN finding five and three times, tripling the
// artifact section without adding information. The first occurrence is kept
// and annotated; genuinely different findings (distinct payload or wording)
// are never merged.
func dedupeArtifactFindings(findings []types.ArtifactFinding) []types.ArtifactFinding {
	if len(findings) <= 1 {
		return findings
	}

	type findingKey struct {
		lib, reason, payload string
	}
	seen := make(map[findingKey]int, len(findings))
	out := make([]types.ArtifactFinding, 0, len(findings))
	for _, f := range findings {
		k := findingKey{
			lib:     strings.ToLower(filepath.Base(f.Path)),
			reason:  f.Reason,
			payload: f.Payload,
		}
		if idx, dup := seen[k]; dup {
			if !strings.Contains(out[idx].Reason, "ABI copy of this library") {
				out[idx].Reason += " (same finding in other ABI copies of this library)"
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, f)
	}
	return out
}

// cleanup удаляет временные файлы (если не --keep-temp)
func (a *App) cleanup() {
	if a.tempDir == "" || a.opts.KeepTemp {
		return
	}

	a.output.Info("Removing temp files...")
	started := time.Now()
	if err := a.extractor.Cleanup(a.tempDir); err != nil {
		a.output.Warning("Failed to cleanup temp files: %v", err)
		return
	}

	a.output.Debug("Cleaned up temporary files in %s", time.Since(started).Round(time.Millisecond))
}

// ═══════════════════════════════════════════════════════════════════════════════
// LEGACY: validateTarget для обратной совместимости
// ═══════════════════════════════════════════════════════════════════════════════

// validateTarget только проверяет, что это директория
// Использовать prepareTarget вместо этого
func (a *App) validateTarget() (string, error) {
	absTarget, err := filepath.Abs(a.opts.Target)
	if err != nil {
		return "", fmt.Errorf("invalid target path: %w", err)
	}

	info, err := os.Stat(absTarget)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("target directory not found: %s", absTarget)
		}
		return "", fmt.Errorf("cannot access target: %w", err)
	}

	if !info.IsDir() {
		return "", fmt.Errorf("target must be a directory, got file: %s", absTarget)
	}

	return absTarget, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD CONFIG — профиль как база, CLI как override
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) buildConfig() *config.Config {
	cfg := config.DefaultConfig()

	// ──── Шаг 1: применяем профиль (базовые настройки) ────
	a.applyProfile(cfg)

	// ──── Шаг 2: CLI overrides (приоритет у пользователя) ────
	cfg.Workers = a.opts.Workers
	cfg.OutputDir = a.opts.Output
	cfg.MaxFiles = a.opts.MaxFiles

	// Явные CLI-флаги перезаписывают профиль
	if a.opts.CallGraphExplicit {
		cfg.EnableCallGraph = a.opts.EnableCallGraph
	}
	if a.opts.CorrelationsExplicit {
		cfg.EnableCorrelations = a.opts.EnableCorrelations
	}

	// Deobfuscation overrides
	if a.opts.DeobfIterationsExplicit {
		cfg.DeobfuscationOptions.MaxIterations = a.opts.DeobfIterations
	}
	if a.opts.DeobfMinConfidenceExplicit {
		cfg.DeobfuscationOptions.MinConfidenceThreshold = a.opts.DeobfMinConfidence
	}

	// Toggles (booleans are usually handled by true defaults, so we only override if explicit flags existed,
	// but here we just map them directly as they are bool flags)
	cfg.DeobfuscationOptions.EnableCP = a.opts.EnableDeobfCP
	cfg.DeobfuscationOptions.EnableDCE = a.opts.EnableDeobfDCE
	cfg.DeobfuscationOptions.EnableOPR = a.opts.EnableDeobfOPR
	cfg.DeobfuscationOptions.EnablePS = a.opts.EnableDeobfPS
	cfg.DeobfuscationOptions.EnableVR = a.opts.EnableDeobfVR
	cfg.DeobfuscationOptions.EnableMR = a.opts.EnableDeobfMR
	cfg.DeobfuscationOptions.EnableNameQuality = a.opts.EnableNameQuality

	// Crack point & Anomaly overrides. These flags default to true, so mapping
	// them unconditionally would silently re-enable what a profile (quick)
	// turned off — only an explicitly passed flag may override the profile.
	if a.opts.CrackPointExplicit {
		cfg.EnableCrackPointAnalysis = a.opts.CrackPointAnalysis
	}
	if a.opts.AnomalyExplicit {
		cfg.EnableAnomalyDetection = a.opts.AnomalyDetection
	}

	// Content-Cache & Data-Flow
	cfg.EnableContentCache = a.opts.EnableContentCache
	if a.opts.ContentCacheDir != "" {
		cfg.ContentCacheDir = a.opts.ContentCacheDir
	}
	if a.opts.ContentCacheMaxDiskMB > 0 {
		cfg.ContentCacheMaxDiskMB = a.opts.ContentCacheMaxDiskMB
	}
	// The flag defaults to true; without the explicit check it would undo the
	// quick profile's EnableDataFlow=false and put the heavy second-pass
	// data-flow analysis back into every fast triage scan.
	if a.opts.DataFlowExplicit {
		cfg.EnableDataFlow = a.opts.EnableDataFlow
	}
	if a.opts.DataFlowMaxMethods > 0 {
		cfg.DataFlowMaxMethods = a.opts.DataFlowMaxMethods
	}
	if a.opts.DataFlowMaxFindings > 0 {
		cfg.DataFlowMaxFindings = a.opts.DataFlowMaxFindings
	}

	// False-positive / triage tuning. SDK/library findings are not blindly skipped:
	// strong security signals stay visible as confirmed SDK risk, while boilerplate
	// can still be suppressed to keep reports readable.
	cfg.FPFilter.StrictMode = a.opts.FPStrict
	cfg.FPFilter.ShowSuppressed = a.opts.FPShowSuppressed
	if a.opts.FPMinScore >= 0 {
		cfg.FPFilter.MinScore = a.opts.FPMinScore
	}
	if a.opts.FPSuppressedLimit >= 0 {
		cfg.FPFilter.SuppressedLimit = a.opts.FPSuppressedLimit
	}

	return cfg
}

// applyProfile устанавливает настройки профиля.
func (a *App) applyProfile(cfg *config.Config) {
	switch a.opts.Profile {
	case ProfileQuick:
		cfg.MaxFileSize = 100 * 1024 // 100KB
		cfg.EnableCallGraph = false
		cfg.EnableCorrelations = false
		// Quick is intended for fast triage. These are second-pass analyses over
		// every parsed method and dominate runtime on large DEX files.
		cfg.EnableDataFlow = false
		cfg.EnableDeobfuscation = false
		cfg.EnableCrackPointAnalysis = false
		cfg.EnableAnomalyDetection = false
		cfg.DeobfuscationOptions.MaxIterations = 1
		cfg.DeobfuscationOptions.EnableOPR = false
		cfg.DeobfuscationOptions.EnablePS = false
		cfg.DeobfuscationOptions.EnableVR = false
		cfg.DeobfuscationOptions.EnableMR = false

	case ProfileBalanced:
		// default config уже сбалансирован
		cfg.DeobfuscationOptions.MaxIterations = 5

	case ProfileDeep:
		cfg.MaxFileSize = 5 * 1024 * 1024 // 5MB
		cfg.EnableCallGraph = true
		cfg.EnableCorrelations = true
		cfg.DeobfuscationOptions.MaxIterations = 10

	case ProfileParanoid:
		cfg.MaxFileSize = 10 * 1024 * 1024 // 10MB
		cfg.EnableCallGraph = true
		cfg.EnableCorrelations = true
		cfg.DeobfuscationOptions.MaxIterations = 20
		cfg.DeobfuscationOptions.MinConfidenceThreshold = 30 // more aggressive
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RUN ANALYSIS — единственный источник Duration
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) runAnalysis(ctx context.Context, cfg *config.Config, target string) (*types.AnalysisResult, time.Duration, error) {
	a.output.Info("Starting analysis...")

	// Start CPU profiling if requested
	if a.profiler != nil && a.opts.CPUProfile != "" {
		if err := a.profiler.StartCPUProfile(a.opts.CPUProfile); err != nil {
			a.output.Warning("Failed to start CPU profiling: %v", err)
		}
	}

	a.output.Info("Initializing pipeline (patterns, cache)...")
	pipeStarted := time.Now()
	p, err := pipeline.NewPipeline(cfg)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create pipeline: %w", err)
	}
	a.output.Info("Pipeline initialized in %s", time.Since(pipeStarted).Round(time.Millisecond))

	// 🆕 v9.0.0 - Загружаем user feedback из ML history
	fbStarted := time.Now()
	if err := a.loadUserFeedbackToPipeline(p); err != nil {
		a.output.Info("Warning: Failed to load user feedback: %v", err)
	} else {
		a.output.Info("ML history loaded in %s", time.Since(fbStarted).Round(time.Millisecond))
	}

	// Register progress callback
	p.OnProgress = func(stage string, current, total int) {
		a.output.PrintProgress(stage, current, total)
		if current == total && total > 0 {
			a.output.ClearProgress()
		}
	}
	p.OnProgressStatus = func(stage string, current, total int, status string) {
		a.output.PrintProgressStatus(stage, current, total, status)
	}

	startTime := time.Now()

	result, err := p.Run(ctx, target)
	if result != nil {
		stopErr := err
		if stopErr == nil {
			stopErr = ctx.Err()
		}
		result.Run = coreRunMetadata(a.opts, cfg, result, stopErr)
	}
	if err != nil {
		if (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) && result != nil && result.Stats.AnalyzedFiles > 0 {
			a.output.Warning("Analysis stopped early (%v); generating reports from %d analyzed file(s)", err, result.Stats.AnalyzedFiles)
			err = nil
		} else {
			return nil, 0, err
		}
	}
	pipelineElapsed := time.Since(startTime)
	if pipelineElapsed >= 2*time.Second {
		for _, stage := range p.GetStageTimings() {
			a.output.Info("Timing: %s took %s", stage.Name, stage.Duration.Round(time.Millisecond))
		}
	}

	// Run GNN vulnerability classification when model weights are available:
	// either passed via -gnn-model or auto-discovered in ~/.analyzer/models.
	// Without weights the stage is skipped entirely; there is no enable flag.
	// On interrupt the stage is skipped too: it runs on a detached 120s
	// budget that would otherwise ignore Ctrl+C and grind on partial data.
	if !a.opts.SkipGNN && !a.interrupted.Load() {
		if gnnWeights := resolveGNNModelPath(a.opts.GNNModelPath); gnnWeights != "" {
			a.output.Info("Running GNN classification of visible method control-flow graphs...")
			gnnStarted := time.Now()
			// The shared analysis deadline is usually almost exhausted by now:
			// the pattern scan can consume most of -timeout, which would cancel
			// the GNN stage before it classifies (or persists) a single method.
			// Give the stage its own budget, detached from the parent deadline,
			// so a slow scan can no longer starve classification.
			const gnnStageTimeout = 120 * time.Second
			gnnCtx, gnnCancel := context.WithTimeout(context.WithoutCancel(ctx), gnnStageTimeout)
			if err := a.runGNNClassification(gnnCtx, result, gnnWeights); err != nil {
				a.output.Warning("GNN classification error: %v", err)
			}
			gnnCancel()
			a.output.Info("Timing: GNN classification took %s", time.Since(gnnStarted).Round(time.Millisecond))
		} else {
			diagnostics, _ := newGNNDiagnostics(result, "")
			finishGNNDiagnostics(diagnostics)
			diagnostics.Status, diagnostics.Reason = "unavailable", "no_supported_json_model"
			result.GNNDiagnostics = diagnostics
		}
	} else {
		a.output.Info("Skipping GNN vulnerability classification by request")
		diagnostics, _ := newGNNDiagnostics(result, "")
		finishGNNDiagnostics(diagnostics)
		diagnostics.Status, diagnostics.Reason = "skipped", "disabled_or_interrupted"
		result.GNNDiagnostics = diagnostics
	}

	// The neuroclassifier is part of the confirmation layer: an unavailable
	// model is a degraded run, not a normal one. Record the limitation on the
	// run metadata so reports show it, and keep a "complete" label from
	// hiding the gap.
	if result != nil && result.Run != nil && result.GNNDiagnostics != nil &&
		result.GNNDiagnostics.Status == "unavailable" {
		reason := result.GNNDiagnostics.Reason
		if reason == "" {
			reason = "model_not_loaded"
		}
		result.Run.Limitations = append(result.Run.Limitations,
			"Neuroclassifier (GNN) unavailable: "+reason+". ML confirmation did not run; risk scoring relies on static signals only.")
		if result.Run.Status == "complete" {
			result.Run.Status, result.Run.StopReason = "incomplete", "gnn_unavailable"
		}
	}

	// Apply ProGuard/R8 name recovery if mapping file provided
	if a.opts.ProGuardMap != "" {
		a.output.Info("Loading ProGuard/R8 mapping: %s", a.opts.ProGuardMap)
		pgMap, err := deobfuscation.LoadProGuardMap(a.opts.ProGuardMap)
		if err != nil {
			a.output.Warning("Failed to load ProGuard map: %v", err)
		} else {
			deobfuscation.ApplyProGuardMap(result, pgMap)
			a.output.Info("ProGuard map applied: %d classes, %d methods, %d fields resolved",
				pgMap.ClassMapLen(), pgMap.MethodMapLen(), pgMap.FieldMapLen())
		}
	}

	elapsed := time.Since(startTime)
	result.Duration = types.Duration(elapsed)

	// Stop CPU profiling
	if a.profiler != nil && a.opts.CPUProfile != "" {
		a.profiler.StopCPUProfile()
	}

	// Write heap profile if requested
	if a.profiler != nil && a.opts.MemProfile != "" {
		if err := a.profiler.WriteHeapProfile(a.opts.MemProfile); err != nil {
			a.output.Warning("Failed to write heap profile: %v", err)
		}
	}

	return result, elapsed, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// GENERATE REPORTS
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) generateReports(ctx context.Context, result *types.AnalysisResult, outputDir string) error {
	if result != nil && result.Run != nil && a.interrupted.Load() {
		result.Run.Status, result.Run.StopReason = "incomplete", "cancelled"
	}
	if result != nil {
		pipeline.RefreshTypedFindings(result)
		logScoreBreakdown(result)
		a.finalizeRunIdentity(result)
		result.EvidenceGraph = evidencegraph.Build(result)
	}
	a.output.Println()
	a.output.Info("Generating reports...")

	outDir := outputDir
	if outDir == "" {
		outDir = "analysis_output"
	}

	// Optional cleanup: keep one stable output dir across runs.
	if a.opts.CleanOutput && !a.outputCleaned {
		if err := cleanOutputDir(outDir); err != nil {
			return err
		}
		a.outputCleaned = true
	}

	// Create output directory
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("cannot create output directory: %w", err)
	}

	// Marker makes it safer to clean in the future.
	_ = writeOutputMarker(outDir)
	if err := writeGNNDiagnosticsReport(outDir, result); err != nil {
		a.output.Warning("GNN diagnostics report: %v", err)
	}

	// Review the same refreshed findings that the exporters will receive,
	// including late sidecars and experimental results. Cleaning must finish
	// first so it cannot delete the advisory artifacts written here.
	a.runDecisionAITriage(ctx, result, outDir)
	imageReviewer, closeImageReviewer := a.beginDecisionAIImageReview(ctx)
	defer closeImageReviewer()

	mdOpts := selectReportOptions(a.opts.Profile, a.opts.Report)
	mdOpts.EngineVersion = Version
	mdOpts.Profile = string(a.opts.Profile)
	mdOpts.Artifacts.NoImageBlur = a.opts.NoImageBlur

	registry := NewGeneratorRegistry(result, mdOpts)
	if a.opts.NoHTML {
		registry.DisableHTML()
	}
	if a.opts.NoJSON {
		registry.DisableJSON()
	}
	if a.opts.JSONCompact {
		registry.WithJSONCompact(true)
	}

	// Artifacts panel — opt-in. Zero impact when --artifacts is off.
	if a.opts.EnableArtifacts {
		if view := a.buildArtifactsView(result, outDir, imageReviewer); view != nil {
			registry.WithArtifacts(view)
			a.output.Info("Artifacts: ON  →  %d items, %d flagged",
				view.Summary.Total, view.Summary.Flagged)
		} else {
			a.output.Info("Artifacts: ON  →  no extracted artifacts found")
		}
	}
	a.finishDecisionAIImageReview(imageReviewer, result, outDir)

	err := registry.GenerateAll(outDir, a.output)
	if a.opts.SARIF {
		if sarifErr := report.NewSARIFReporter(result).Generate(outDir); sarifErr != nil {
			a.output.Warning("Failed to generate SARIF report: %v", sarifErr)
			if err == nil {
				err = sarifErr
			}
		} else {
			a.output.Success("SARIF report generated")
		}
	}
	if a.opts.ExtractPS1 {
		ps1Path := filepath.Join(outDir, "unpack_media.ps1")
		if psErr := pipeline.GenerateUnpackScript(result, ps1Path); psErr != nil {
			a.output.Warning("Failed to generate PS1 unpack script: %v", psErr)
		} else {
			a.output.Success("PS1 unpack script generated at %s", ps1Path)
		}
	}
	return err
}

// buildArtifactsView wires up the opt-in Artifacts pipeline. Returns nil
// when there's nothing to surface (no extracted dir, no artifact files).
func (a *App) buildArtifactsView(result *types.AnalysisResult, outDir string, imageReviewer *decisionai.ImageReviewer) *report.ArtifactsView {
	extractedDir := a.tempDir
	if extractedDir == "" {
		// User passed a folder directly — still walk it.
		extractedDir = result.TargetDir
	}
	if extractedDir == "" {
		return nil
	}

	// Pre-build the smali class list so JNI resolution can produce
	// deterministic links into existing hotspot anchors.
	classes := collectSmaliClassNames(result)

	// Crack-points keyed by absolute file path.
	cps := collectCrackPointsByPath(result, extractedDir)

	pipelineOpts := artifacts.Options{
		ExtractedDir:      extractedDir,
		OutputDir:         outDir,
		MaxFileMB:         a.opts.ArtifactsMaxMB,
		BudgetMB:          a.opts.ArtifactsBudgetMB,
		AllowExport:       a.opts.AllowExport,
		NoImageBlur:       a.opts.NoImageBlur,
		SmaliClasses:      classes,
		CrackPointsByPath: cps,
	}
	if imageReviewer != nil {
		pipelineOpts.ReviewImage = imageReviewer.Review
	}

	view, err := artifacts.Build(pipelineOpts)
	if err != nil {
		a.output.Warning("Artifacts pipeline failed: %v", err)
		return view
	}
	return view
}

// collectSmaliClassNames extracts class names referenced in the result so
// the JNI resolver can attach links back to existing hotspot entries.
func collectSmaliClassNames(result *types.AnalysisResult) []string {
	if result == nil {
		return nil
	}
	out := make([]string, 0, len(result.Files))
	seen := make(map[string]struct{}, len(result.Files))
	for path := range result.Files {
		clean := filepath.ToSlash(path)
		idx := strings.Index(clean, "/smali")
		if idx < 0 {
			continue
		}
		rest := clean[idx:]
		// drop "/smali[_classesN]/" prefix
		if i := strings.IndexByte(rest[1:], '/'); i >= 0 {
			rest = rest[i+2:]
		} else {
			continue
		}
		rest = strings.TrimSuffix(rest, ".smali")
		if rest == "" {
			continue
		}
		ref := "L" + rest + ";"
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		out = append(out, ref)
	}
	return out
}

func selectReportOptions(profile AnalysisProfile, preset string) report.MarkdownOptions {
	if preset != "" {
		switch preset {
		case "short":
			return report.ShortReportOptions()
		case "default":
			return report.DefaultOptions()
		case "full":
			return report.FullReportOptions()
		case "all":
			return report.AllReportOptions()
		default:
			// Validation should catch it; fallback to auto.
		}
	}

	// Auto mapping: keep report size aligned with analysis depth.
	switch profile {
	case ProfileQuick:
		return report.ShortReportOptions()
	case ProfileDeep, ProfileParanoid:
		return report.FullReportOptions()
	default:
		return report.DefaultOptions()
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ERROR HANDLING
// ═══════════════════════════════════════════════════════════════════════════════

// assessExit фиксирует код выхода по итогу скана, если включён -exit-codes.
func (a *App) assessExit(result *types.AnalysisResult) {
	if a.opts == nil || !a.opts.ExitCodes {
		return
	}
	failOn, _ := verdict.ParseFailOn(a.opts.FailOn) // формат проверен в Validate
	assessment := verdict.Assess(result, verdict.Options{
		FailOn:      failOn,
		Interrupted: a.interrupted.Load(),
	})
	a.exitCode = int(assessment.Code)
	fmt.Fprintln(os.Stderr, assessment.Summary())
}

// ExitCode — код, с которым main должен завершить процесс (0, если -exit-codes
// выключен или всё чисто).
func (a *App) ExitCode() int { return a.exitCode }

func (a *App) Fatal(err error) {
	// Fallback если тема не инициализирована
	theme := a.theme
	if theme.Reset == "" {
		theme = DarkTheme()
	}

	// Use hint error printing for better error messages
	apperrors.PrintHintError(err)

	if a.opts != nil && a.opts.ExitCodes {
		os.Exit(int(verdict.Error))
	}
	os.Exit(1)
}
