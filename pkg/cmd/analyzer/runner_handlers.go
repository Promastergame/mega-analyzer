package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"mega-analyzer/pkg/decompiler"
	"mega-analyzer/pkg/internal/apkloader"
	"mega-analyzer/pkg/internal/attackchain"
	"mega-analyzer/pkg/internal/correlation"
	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DECODE HANDLER (apktool-style — no analysis)
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) handleDecode() error {
	if a.opts.Target == "" {
		return fmt.Errorf("decode command requires a target path\n\nUsage: analyzer decode <app.apk|app.xapk|classes.dex> [-o output_dir]")
	}

	a.output.Info("📦 Mega-Analyzer unpacker & Smali decompiler")
	a.output.Info("Target: %s", a.opts.Target)

	startTime := time.Now()
	opts := decompiler.Options{
		OutputDir: a.opts.Output, Backend: decompiler.Backend(a.opts.DexBackend),
		Standalone: a.opts.Standalone, NoResources: a.opts.NoResources, NoSmali: a.opts.NoSmali,
		Headers: a.opts.SmaliHeaders && !a.opts.NoSmaliHeaders, JavaView: a.opts.JavaView,
		FrameworkDir: a.opts.FrameworkDir, CopyOriginal: a.opts.CopyOriginal, ClassCache: a.opts.ClassCache,
		Baksmali: decompiler.BaksmaliOptions{
			JarPath: a.opts.BaksmaliJar, APILevel: a.opts.SmaliAPI, Jobs: a.opts.SmaliJobs,
			JavaHeapMB: a.opts.SmaliHeapMB, UseLocals: a.opts.BaksmaliUseLocals,
			SequentialLabels: a.opts.BaksmaliSeqLabels, NoParameterRegisters: a.opts.BaksmaliNoParamRegs,
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if a.opts.Timeout > 0 && (a.opts.TimeoutExplicit || a.opts.Timeout != 300) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(a.opts.Timeout)*time.Second)
		defer cancel()
	}
	result, err := decompiler.Decode(ctx, a.opts.Target, opts)
	for _, warning := range result.Warnings {
		a.output.Warning("%s", warning)
	}
	if err != nil {
		if result.OutputDir != "" {
			a.output.Info("Partial output: %s", result.OutputDir)
		}
		return fmt.Errorf("failed to decode input: %w", err)
	}

	elapsed := time.Since(startTime)
	a.output.Success("\nDecode finished successfully.")
	a.output.Info("  Directory: %s (%d smali files)", result.OutputDir, result.SmaliFiles)
	a.output.Info("  Backend: %s", result.Backend)
	a.output.Info("  Time: %v", elapsed.Round(time.Millisecond))
	a.output.Info("Tip: open the project in the GUI editor: '%s edit %s'", selfCmd(), result.OutputDir)
	a.output.Info("Tip: rebuild it into an APK: '%s build %s -o patched.apk'", selfCmd(), result.OutputDir)

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// REBUILD HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) handleRebuild() error {
	sourceDir := a.opts.Target
	outputAPK := a.opts.Output

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if a.opts.Timeout > 0 && (a.opts.TimeoutExplicit || a.opts.Timeout != 300) {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(a.opts.Timeout)*time.Second)
		defer cancel()
	}
	absSource, cleanup, err := apkloader.PrepareBuildProject(ctx, sourceDir)
	if err != nil {
		return err
	}
	defer cleanup()

	// Validate output path
	absOutput, err := filepath.Abs(outputAPK)
	if err != nil {
		return fmt.Errorf("invalid output path: %w", err)
	}
	absInput, err := filepath.Abs(sourceDir)
	if err != nil {
		return err
	}
	if strings.EqualFold(absInput, absOutput) {
		return fmt.Errorf("output must not replace the input project")
	}
	if rel, err := filepath.Rel(absSource, absOutput); err == nil && filepath.IsLocal(rel) {
		return fmt.Errorf("write the output APK outside the source project so previous APKs are not packaged into the next build")
	}

	a.output.Info("Rebuilding APK from: %s", absSource)
	a.output.Info("Output APK: %s", absOutput)

	startTime := time.Now()

	if !a.opts.AllowExternalTools || a.opts.Standalone || apkloader.Standalone() {
		if a.opts.SmaliJar != "" || a.opts.BaksmaliJar != "" || a.opts.Aapt2Path != "" || a.opts.KsPath != "" {
			return fmt.Errorf("native build does not run --smali-jar/--baksmali-jar/--aapt2/--ks; use --allow-external-tools explicitly for these compatibility options")
		}
		previousStandalone := apkloader.Standalone()
		apkloader.SetStandalone(true)
		defer apkloader.SetStandalone(previousStandalone)
		a.output.Info("Build engine: native (no Java, Android SDK, aapt2, android.jar or d8)")
	}

	// Step 1: Create rebuilder
	var spoolThreshold int64
	if a.opts.SpoolThresholdMB > 0 {
		spoolThreshold = int64(a.opts.SpoolThresholdMB) * 1024 * 1024
	}
	rebuilder := apkloader.NewAPKRebuilderWithOptions(apkloader.BuildOptions{
		SourceDir:                 absSource,
		IncludeSignature:          !a.opts.NoSign,
		IncludeAlignment:          !a.opts.NoAlign,
		CopyOriginal:              a.opts.CopyOriginal,
		CompressionMode:           apkloader.CompressionMode(a.opts.CompressionMode),
		LargeFileSpoolThreshold:   spoolThreshold,
		NoSmaliIncremental:        !a.opts.SmaliIncremental,
		PreserveOriginalSignature: a.opts.PreserveSignature,
		SigningKeystore:           a.opts.KsPath,
		SigningKeyAlias:           a.opts.KsAlias,
		SigningStorePass:          os.Getenv(apkloader.EnvKeystorePass),
		SigningKeyPass:            os.Getenv(apkloader.EnvKeyPass),
	})

	// Wire in tool overrides from CLI
	rebuilder.UseSmali = a.opts.UseSmali
	rebuilder.UseAapt2 = a.opts.UseAapt2
	if a.opts.SmaliJar != "" {
		rebuilder.SmaliCfg.SmaliJar = a.opts.SmaliJar
	}
	if a.opts.BaksmaliJar != "" {
		rebuilder.SmaliCfg.BaksmaliJar = a.opts.BaksmaliJar
	}
	if a.opts.Aapt2Path != "" {
		rebuilder.Aapt2Cfg.Aapt2Path = a.opts.Aapt2Path
	}
	if a.opts.SmaliAPI > 0 {
		rebuilder.SmaliCfg.APILevel = a.opts.SmaliAPI
	}
	if a.opts.SmaliJobs > 0 {
		rebuilder.SmaliCfg.Jobs = a.opts.SmaliJobs
	}
	if a.opts.SmaliHeapMB > 0 {
		rebuilder.SmaliCfg.JavaHeapMB = a.opts.SmaliHeapMB
	}
	rebuilder.SmaliCfg.Verbose = a.opts.SmaliVerbose

	// Log package meta if available
	if meta := rebuilder.GetMeta(); meta != nil && meta.Package != "" {
		a.output.Info("Package: %s (v%d %s)", meta.Package, meta.VersionCode, meta.VersionName)
	}

	// Step 2: Rebuild APK
	a.output.Info("Creating ZIP archive...")
	if err := rebuilder.Rebuild(ctx, absOutput); err != nil {
		return fmt.Errorf("failed to rebuild APK: %w", err)
	}

	// Get file info for progress
	fileInfo, err := os.Stat(absOutput)
	if err != nil {
		return fmt.Errorf("built APK is unavailable: %w", err)
	}
	fileSize := fileInfo.Size()
	a.output.Success("APK created: %s (%.2f MB)", absOutput, float64(fileSize)/(1024*1024))

	// Warnings from rebuilder (smali/aapt2 fallback messages)
	for _, w := range rebuilder.GetWarnings() {
		a.output.Warning("rebuild: %s", w)
	}

	// Diagnostics carry the signing verdict (signed/verified/debug-key/
	// signer-match codes): warnings alone would hide whether the APK
	// carries a real signature or a debug one.
	for _, d := range rebuilder.GetDiagnostics() {
		switch d.Severity {
		case apkloader.DiagError, apkloader.DiagFatal:
			a.output.Error("rebuild [%s]: %s", d.Code, d.Message)
		case apkloader.DiagWarn:
			a.output.Warning("rebuild [%s]: %s", d.Code, d.Message)
		default:
			a.output.Info("rebuild [%s]: %s", d.Code, d.Message)
		}
	}

	elapsed := time.Since(startTime)

	// Final info
	finalSize := fileSize

	a.output.Success("\n✓ APK rebuilt successfully!")
	a.output.Info("  Output: %s", absOutput)
	a.output.Info("  Size: %.2f MB", float64(finalSize)/(1024*1024))
	a.output.Info("  Time: %v", elapsed.Round(time.Millisecond))

	if !a.opts.NoSign {
		a.output.Info("\nAPK signing completed. Installation and runtime behavior require validation on an Android device.")
	} else {
		a.output.Warning("\nThe APK is NOT signed. Rebuild without --no-sign, or sign manually (apksigner / --ks <keystore>).")
	}

	return nil
}

func (a *App) handleSandbox() error {
	if a.opts.SandboxRemoteConfig != "" {
		return a.handleRemoteSandbox()
	}
	absTarget, err := filepath.Abs(a.opts.Target)
	if err != nil {
		return fmt.Errorf("invalid sandbox target: %w", err)
	}

	info, err := os.Stat(absTarget)
	if err != nil {
		return fmt.Errorf("sandbox target not found: %w", err)
	}

	outputRoot := a.opts.SandboxOutput
	if outputRoot == "" {
		outputRoot = a.opts.Output
	}
	if outputRoot == "" {
		outputRoot = "analysis_output"
	}

	a.output.Info("Starting built-in sandbox...")
	a.output.Info("Target: %s", absTarget)
	if info.IsDir() {
		a.output.Info("Mode: static folder inspection")
	} else {
		a.output.Info("Mode: file detonation / inspection")
	}
	if a.opts.SandboxDuration == 0 {
		a.output.Info("Duration: until stopped (no deadline)")
	} else {
		a.output.Info("Duration: %ds", a.opts.SandboxDuration)
	}
	a.output.Info("Memory cap: %d MB", a.opts.SandboxMemoryMB)
	if a.opts.SandboxAllowNet {
		a.output.Warning("Real network access is ENABLED for this run")
	} else {
		a.output.Info("Network: blocked by default")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	report, err := sandbox.Run(ctx, sandbox.Config{
		AllowHostExecution:  a.opts.SandboxAllowHostExecution,
		TargetPath:          absTarget,
		OutputDir:           outputRoot,
		RawArgs:             a.opts.SandboxArgs,
		Duration:            time.Duration(a.opts.SandboxDuration) * time.Second,
		MaxMemoryMB:         a.opts.SandboxMemoryMB,
		BlockNetwork:        !a.opts.SandboxAllowNet,
		MonitorEvery:        time.Second,
		SandboxProfile:      a.opts.SandboxProfile,
		VSSRevert:           a.opts.SandboxVSSRevert,
		EnableKernelMonitor: a.opts.EnableKernelMonitor,
		EnableVSS:           a.opts.EnableVSS,
		EnableWFP:           a.opts.EnableWFP,
		EnableAPITracing:    a.opts.EnableAPITracing,
		EnableTimeManip:     a.opts.EnableTimeManip,
		TimeScaleFactor:     a.opts.SandboxTimeScale,
		AndroidSandbox:      a.opts.AndroidSandbox,
		AndroidAVD:          a.opts.SandboxAVD,
		AndroidAutoAVD:      a.opts.SandboxAutoAVD,
		AndroidDevice:       a.opts.SandboxDevice,
		PrivateServer:       a.opts.SandboxPrivServer,
		MaxCPUCores:         a.opts.SandboxCPUCores,
		Locale:              a.opts.SandboxLocale,
		Timezone:            a.opts.SandboxTimezone,
		Resolution:          a.opts.SandboxResolution,
		Orientation:         a.opts.SandboxOrientation,
		UninstallAfter:      a.opts.SandboxUninstall,
		CaptureTraffic:      a.opts.SandboxCapture,
		MITMProxy:           a.opts.SandboxMITM,
		Frida:               a.opts.SandboxFrida || a.opts.SandboxFridaSpawn || a.opts.SandboxFridaScript != "",
		FridaSpawn:          a.opts.SandboxFridaSpawn,
		FridaScript:         a.opts.SandboxFridaScript,
	})
	if err != nil {
		return err
	}

	a.output.Success("Sandbox session complete")
	a.output.Info("Session: %s", report.SessionID)
	a.output.Info("Workspace: %s", report.WorkspaceDir)
	a.output.Info("Input type: %s", report.InputType)
	a.output.Info("Network access: %s", report.SandboxPermissions.NetworkAccess)
	a.output.Info("Exit code: %d", report.ExitCode)
	if report.TimedOut {
		a.output.Warning("Sample hit timeout and was terminated")
	}
	if !report.Executed && report.ExecutionSkipReason != "" {
		a.output.Info("Execution: skipped (%s)", report.ExecutionSkipReason)
	}
	a.output.Info("Processes observed: %d", len(report.Processes))
	a.output.Info("Connections observed: %d", len(report.Connections))
	a.output.Info("Created files: %d", len(report.FileChanges.Created))
	a.output.Info("Modified files: %d", len(report.FileChanges.Modified))
	a.output.Info("Deleted files: %d", len(report.FileChanges.Deleted))
	a.output.Info("Persistence indicators: %d", report.Behavior.PersistenceCount)
	if report.ExploitAnalysis != nil {
		a.output.Info("Network exploitability candidates: %d (risk %d/100)",
			len(report.ExploitAnalysis.Candidates), report.ExploitAnalysis.RiskScore)
	}
	if report.MemoryAnalysis != nil {
		a.output.Info("Memory triage findings: %d (risk %d/100)",
			len(report.MemoryAnalysis.Findings), report.MemoryAnalysis.RiskScore)
	}
	if report.CacheAnalysis != nil {
		a.output.Info("Post-run cache findings: %d (risk %d/100)",
			len(report.CacheAnalysis.Findings), report.CacheAnalysis.RiskScore)
	}
	if len(report.StartedComponents) > 0 {
		a.output.Info("Sandbox components started: %s", strings.Join(report.StartedComponents, ", "))
	}
	for _, component := range report.DegradedComponents {
		a.output.Warning("Sandbox component degraded: %s/%s: %s", component.Name, component.Phase, component.Reason)
	}
	if report.AndroidProfile != nil {
		a.output.Info("Android package: %s", report.AndroidProfile.PackageName)
		a.output.Info("Android permissions: %d total, %d dangerous, %d high-risk",
			len(report.AndroidProfile.Permissions),
			report.AndroidProfile.DangerousPermissionCount,
			report.AndroidProfile.HighRiskPermissionCount)
	}
	if report.AndroidSDK != nil {
		if report.AndroidSDK.Detected {
			a.output.Info("Android SDK: detected (%s, build-tools %s)",
				report.AndroidSDK.Root,
				report.AndroidSDK.BuildToolsVersion)
		} else {
			a.output.Info("Android SDK: not detected, using built-in fallback path")
		}
	}
	for _, highlight := range report.Behavior.Highlights {
		a.output.Info("Behavior: %s", highlight)
	}
	a.output.Info("JSON report: %s", report.JSONPath)
	a.output.Info("Markdown report: %s", report.MarkdownPath)
	a.output.Info("stdout: %s", report.StdoutPath)
	a.output.Info("stderr: %s", report.StderrPath)

	// ── Post-processing: correlation + attack-chain analysis ──────────────
	a.runCorrelationStage(report, nil)

	for _, warning := range report.Warnings {
		a.output.Warning("%s", warning)
	}

	return nil
}

// runCorrelationStage executes the correlation post-processor over the
// sandbox report (and an optional static analysis result), then writes
// correlation_report.json/md next to the sandbox report and prints a
// short summary to stdout.
//
// It never returns an error — correlation is always best-effort. If
// rendering fails we surface a warning on the report.
func (a *App) runCorrelationStage(rep *sandbox.Report, static *types.AnalysisResult) {
	if rep == nil {
		return
	}
	engine := correlation.NewEngine(attackchain.DefaultChains())
	result := engine.Run(correlation.Input{
		Sandbox:   rep,
		Static:    static,
		SessionID: rep.SessionID,
	})
	if result == nil {
		return
	}

	a.output.Info("Correlation: %d findings, %d attack chains, overall risk %s (%s likelihood)",
		result.Stats.TotalFindings, result.Stats.TotalChains,
		result.OverallRisk, result.OverallLikeli)
	for _, ch := range result.Chains {
		a.output.Info("  ⛓ %s — %s / %s", ch.Name, ch.Risk, ch.Likelihood)
	}

	jsonPath, mdPath, err := correlation.WriteReports(result, rep.SessionDir)
	if err != nil {
		rep.Warnings = append(rep.Warnings,
			fmt.Sprintf("correlation report write failed: %v", err))
		return
	}
	if jsonPath != "" {
		a.output.Info("Correlation JSON: %s", jsonPath)
	}
	if mdPath != "" {
		a.output.Info("Correlation Markdown: %s", mdPath)
	}
}

// selfCmd returns the command users should type to run this binary again,
// instead of a hard-coded Windows path.
func selfCmd() string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return "analyzer"
	}
	return exe
}
