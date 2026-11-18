package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/decisionai"
	"mega-analyzer/pkg/internal/netflow"
	"mega-analyzer/pkg/internal/verdict"
	"mega-analyzer/pkg/vulnscan"
)

// ═══════════════════════════════════════════════════════════════════════════════
// VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

func (opts *CLIOptions) validateDecisionAIOptions() error {
	if opts.DecisionAIInput != "" && opts.DecisionAIURL == "" {
		opts.DecisionAIURL = decisionai.DefaultURL
	}
	if opts.DecisionAIURL != "" {
		url, err := decisionai.NormalizeURL(opts.DecisionAIURL)
		if err != nil {
			return err
		}
		opts.DecisionAIURL = url
		if opts.DecisionAIMaxFindings < 1 || opts.DecisionAIMaxFindings > 512 {
			return fmt.Errorf("--decision-ai-max-findings must be 1..512")
		}
		if opts.DecisionAIBudget < 1 || opts.DecisionAIBudget > 300 {
			return fmt.Errorf("--decision-ai-budget must be 1..300 seconds")
		}
		if opts.DecisionAIImages && (opts.DecisionAIMaxImages < 1 || opts.DecisionAIMaxImages > 512 || opts.DecisionAIImageBudget < 1 || opts.DecisionAIImageBudget > 300) {
			return fmt.Errorf("--decision-ai-max-images must be 1..512 and --decision-ai-image-budget must be 1..300 seconds")
		}
	}
	if opts.DecisionAIInput != "" {
		if opts.Target != "" || opts.Web || opts.APIServer || opts.Admin || opts.ExplainResult != "" {
			return fmt.Errorf("--decision-ai-input is a standalone JSON command; do not combine it with a target or server mode")
		}
	}
	return nil
}

func (opts *CLIOptions) validateStdinOptions() error {
	if opts.InterceptStopOnEOF && (opts.InterceptInteractive || opts.NetRemoteEdit) {
		return fmt.Errorf("-intercept-stop-on-eof cannot share stdin with interactive or remote packet editing")
	}
	return nil
}

func (opts *CLIOptions) Validate() error {
	if opts.BundleBudget != "" && opts.BundleBudget != "compact" && opts.BundleBudget != "large" {
		return fmt.Errorf("--bundle-budget must be compact|large")
	}
	if err := opts.validateDecisionAIOptions(); err != nil {
		return err
	}
	if opts.DecisionAIInput != "" {
		return nil
	}
	if _, err := verdict.ParseFailOn(opts.FailOn); err != nil {
		return err
	}
	if opts.KnownSet != "" {
		if st, err := os.Stat(opts.KnownSet); err != nil {
			return fmt.Errorf("-known-set: %w", err)
		} else if st.IsDir() {
			return fmt.Errorf("-known-set: %q is a directory, want a knownset-build bundle file", opts.KnownSet)
		}
	}
	// Compile the display filter up front so a typo fails at parse time rather
	// than silently dropping every packet once interception is already running.
	if opts.NetFilter != "" {
		if _, err := netflow.Compile(opts.NetFilter); err != nil {
			return fmt.Errorf("-net-filter: %w", err)
		}
	}
	if err := opts.validateStdinOptions(); err != nil {
		return err
	}
	if opts.APIServer {
		if opts.APIPort < 1 || opts.APIPort > 65535 {
			return fmt.Errorf("--api-port must be between 1 and 65535")
		}
		return nil
	}
	if opts.IsVersionDiffCommand() {
		if opts.DiffOld == "" || opts.DiffNew == "" {
			return fmt.Errorf("version diff requires two inputs\n\nUsage: analyzer --version-diff <old.apk|dir> <new.apk|dir>")
		}
		return nil
	}

	if opts.IsFirmwareCommand() {
		if opts.Target == "" {
			return fmt.Errorf("firmware mode requires a target path\n\nUsage: analyzer --firmware -t <firmware.bin|rootfs_dir|archive>")
		}
		return validateFirmwareTarget(opts.Target)
	}

	if opts.IsMakeServerCommand() {
		if opts.Target == "" {
			return fmt.Errorf("make-server requires a target APK/DEX/dir\n\nUsage: analyzer --make-server -t <app.apk> [--privserver-game NAME]")
		}
		if opts.MakeServerPort != 0 && (opts.MakeServerPort < 1 || opts.MakeServerPort > 65535) {
			return fmt.Errorf("--privserver-port must be between 1 and 65535")
		}
		if opts.MakeServerAdmin != 0 && (opts.MakeServerAdmin < 1 || opts.MakeServerAdmin > 65535) {
			return fmt.Errorf("--privserver-admin must be between 1 and 65535")
		}
		return nil
	}

	if opts.IsSandboxCommand() {
		return opts.validateSandboxOptions()
	}
	if opts.BinzapActive {
		opts.Binzap = true
	}
	if opts.Binzap && opts.MachineCode {
		return fmt.Errorf("--scan-bytecode and --scan-native select different formats and cannot be used for the same target")
	}

	if opts.WebScan && opts.WebScanTarget == "" {
		if opts.Target != "" {
			return fmt.Errorf("--web-scan requires --web-scan-target <url>; --target/-t %q is for APK/DEX/directory targets and is ignored in web-scan mode (did you mean --web-scan-target %q?)", opts.Target, opts.Target)
		}
		return fmt.Errorf("--web-scan-target is required when using --web-scan")
	}
	if opts.WebScan {
		mode, err := vulnscan.ParseScanMode(opts.WebScanMode)
		if err != nil {
			return err
		}
		opts.WebScanMode = string(mode)
		if opts.WebScanLabMode && mode != vulnscan.ScanModeActive {
			return fmt.Errorf("--lab-mode is only available with --web-scan-mode active")
		}
	}

	// ML commands не требуют target
	if opts.IsMLCommand() {
		return opts.validateMLOptions()
	}

	// Decode commands require target APK and output directory
	if opts.IsDecodeCommand() {
		if !opts.TimeoutExplicit {
			opts.Timeout = 0
		}
		if opts.Target == "" {
			return fmt.Errorf("decode requires target APK\n\nUsage: analyzer --decode -t <app.apk> -o <output_dir>")
		}
		if opts.Output == "" || opts.Output == "analysis_output" {
			return fmt.Errorf("decode requires output directory\n\nUsage: analyzer --decode -t <app.apk> -o <output_dir>")
		}
		switch opts.DexBackend {
		case "", "auto", "native":
			if opts.DexBackend == "" {
				opts.DexBackend = "auto"
			}
		default:
			return fmt.Errorf("invalid --dex-backend %q (valid: auto, native)", opts.DexBackend)
		}
		return nil
	}

	if opts.IsJSDeobfuscateCommand() {
		if opts.Target == "" {
			return fmt.Errorf("js-deobf requires target JS/Bundle file\n\nUsage: analyzer --js-deobf -t <index.android.bundle> [-o <output.js>]")
		}
		return nil
	}

	if opts.IsJSPatchCommand() {
		if opts.Target == "" {
			return fmt.Errorf("js-patch requires a target JS bundle file or directory\n\nUsage: analyzer --js-patch -t <index.android.bundle|dir> [--js-patch-apply write]")
		}
		switch opts.JSPatchApply {
		case "", "dry-run":
			opts.JSPatchApply = "dry-run"
		case "write":
		default:
			return fmt.Errorf("invalid --js-patch-apply: %q (valid: dry-run, write)", opts.JSPatchApply)
		}
		if opts.JSPatchMinConf == 0 {
			opts.JSPatchMinConf = 40
		}
		if opts.JSPatchMinConf < 0 || opts.JSPatchMinConf > 100 {
			return fmt.Errorf("--js-patch-min-conf must be 0–100")
		}
		return nil
	}

	// Build / Rebuild commands require a project directory or ZIP and output APK.
	if opts.IsBuildCommand() {
		if !opts.TimeoutExplicit {
			opts.Timeout = 0
		}
		if opts.AllowExternalTools && opts.Standalone {
			return fmt.Errorf("--allow-external-tools conflicts with --standalone")
		}
		cmdName := "build"
		if opts.Rebuild {
			cmdName = "rebuild"
		}
		if opts.Target == "" {
			return fmt.Errorf("%s requires target directory or project ZIP\n\nUsage: analyzer --%s -t <source_dir|project.zip> -o <output.apk>", cmdName, cmdName)
		}
		if opts.Output == "" || opts.Output == "analysis_output" {
			return fmt.Errorf("%s requires output APK path\n\nUsage: analyzer --%s -t <source_dir> -o <output.apk>", cmdName, cmdName)
		}
		switch opts.CompressionMode {
		case "", "fast", "balanced", "best":
			if opts.CompressionMode == "" {
				opts.CompressionMode = "balanced"
			}
		default:
			return fmt.Errorf("invalid --compression-mode %q (valid: fast, balanced, best)", opts.CompressionMode)
		}
		if opts.SpoolThresholdMB < 0 {
			return fmt.Errorf("--spool-threshold-mb must be >= 0")
		}
		return nil
	}

	if opts.Target == "" {
		if opts.WebScan || opts.HTMLBody != "" || opts.CurlCmd != "" || opts.RawRequest != "" {
			// No file target required for standalone web scanning / html-body
			return nil
		}
		return fmt.Errorf("target directory is required\n\nUsage: analyzer [options] <target_directory>\n       analyzer --help for more info")
	}

	if !opts.Profile.IsValid() {
		return fmt.Errorf("invalid profile: %q (valid: quick, balanced, deep, paranoid)", opts.Profile)
	}

	if opts.Workers < 1 {
		// 0 = использовать все доступные CPU ядра
		if opts.Workers == 0 {
			opts.Workers = runtime.NumCPU()
		} else {
			return fmt.Errorf("workers must be at least 1, got %d", opts.Workers)
		}
	}

	if opts.Workers > 64 {
		opts.Workers = 64
	}

	// 0 = без лимита (нет таймаута)
	if opts.Timeout < 0 {
		return fmt.Errorf("timeout cannot be negative, got %d", opts.Timeout)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 0 // unlimited
	} else if opts.Timeout < 10 {
		opts.Timeout = 10
	}

	if opts.MaxFiles < 0 {
		return fmt.Errorf("max-files must be >= 0 (0 means unlimited)")
	}
	if opts.ContentCacheMaxDiskMB < 0 {
		return fmt.Errorf("content-cache-max-disk-mb must be >= 0 (0 means unlimited)")
	}

	// Deobfuscation
	if opts.DeobfIterations < 0 {
		return fmt.Errorf("deobf-iterations must be >= 0")
	}

	if opts.DeobfMinConfidence < 0 || opts.DeobfMinConfidence > 100 {
		return fmt.Errorf("deobf-min-confidence must be between 0 and 100")
	}

	if opts.MaxFileSizeMB < 0 {
		return fmt.Errorf("max-file-size must be >= 0 (0 means profile default)")
	}

	if opts.MaxResourceSizeMB < 0 {
		return fmt.Errorf("max-resource-size must be >= 0 (0 means profile default)")
	}

	if opts.DebugVerbose && opts.Quiet {
		return fmt.Errorf("--debug and --quiet are mutually exclusive")
	}

	if opts.Report != "" {
		switch strings.ToLower(opts.Report) {
		case "short", "default", "full", "all":
			// ok
		default:
			return fmt.Errorf("invalid report preset: %q (valid: short, default, full, all)", opts.Report)
		}
	}

	if opts.MLPatchMinScore < 0 || opts.MLPatchMinScore > 100 {
		return fmt.Errorf("--ml-patch-min-score must be between 0 and 100, got %.1f", opts.MLPatchMinScore)
	}
	if opts.FPMinScore < -1 {
		return fmt.Errorf("--fp-min-score must be >= -1, got %.2f", opts.FPMinScore)
	}
	if opts.FPSuppressedLimit < -1 {
		return fmt.Errorf("--fp-suppressed-limit must be >= -1, got %d", opts.FPSuppressedLimit)
	}

	// Artifacts: sub-flags only meaningful when --artifacts is on.
	// We don't return errors when they're set without --artifacts —
	// we just log a warning would be ideal, but since validate is silent
	// we silently force defaults so the off-path stays zero-impact.
	if !opts.EnableArtifacts {
		opts.AllowExport = false
		opts.NoImageBlur = false
	} else {
		if opts.ArtifactsMaxMB < 0 {
			return fmt.Errorf("--artifacts-max-mb must be >= 0, got %d", opts.ArtifactsMaxMB)
		}
		if opts.ArtifactsBudgetMB < 0 {
			return fmt.Errorf("--artifacts-budget must be >= 0, got %d", opts.ArtifactsBudgetMB)
		}
	}

	if opts.EnableTop5 {
		opts.EnableJNI = true
		opts.EnablePrivacy = true
		opts.EnableGraphExplorer = true
	}
	if opts.EnableGraphExplorer {
		opts.EnableJNI = true
		opts.EnablePrivacy = true
	}
	// --mobsf-all expands into all five MobSF-derived analyzers.
	if opts.EnableMobSFAll {
		opts.EnableSASTRules = true
		opts.EnableTrackers = true
		opts.EnableNSCAudit = true
		opts.EnableManifestAudit = true
		opts.EnableAPKID = true
	}

	// --medium-all expands into all six medium-priority analyzers.
	if opts.EnableMediumAll {
		opts.EnablePlayStore = true
		opts.EnableSBOM = true
		opts.EnablePermMap = true
		opts.EnableCertAudit = true
		opts.EnableMalwareDomains = true
		opts.EnableNIAP = true
	}

	// Patch flags imply enabling the patcher even if user forgot --ml-patch
	if opts.MLPatchFix || opts.MLPatchIncludeLibs ||
		opts.MLPatchApplyExplicit ||
		opts.MLPatchOutput != "" {
		opts.MLPatch = true
	}

	// Export flags also imply enabling the patcher
	if len(opts.MLPatchExportFormat) > 0 || opts.MLPatchExportOutput != "" || opts.MLPatchExplain {
		opts.MLPatch = true
	}

	// Validate export formats
	if len(opts.MLPatchExportFormat) > 0 {
		validFormats := map[string]bool{"md": true, "json": true, "csv": true}
		for _, format := range opts.MLPatchExportFormat {
			if !validFormats[format] {
				return fmt.Errorf("invalid export format: %q (valid: md, json, csv)", format)
			}
		}
	}

	// Validate confidence threshold
	if opts.MLPatchConfidenceThresh < 0.0 || opts.MLPatchConfidenceThresh > 1.0 {
		return fmt.Errorf("--confidence-threshold must be between 0.0 and 1.0, got %.2f", opts.MLPatchConfidenceThresh)
	}

	switch opts.MLPatchApply {
	case "", "dry-run":
		opts.MLPatchApply = "dry-run"
	case "write":
	default:
		return fmt.Errorf("invalid --ml-patch-apply: %q (valid: dry-run, write)", opts.MLPatchApply)
	}

	switch opts.MLPatchBackend {
	case "", "smali":
		opts.MLPatchBackend = "smali"
	case "dex":
	default:
		return fmt.Errorf("invalid --ml-patch-backend: %q (valid: smali, dex)", opts.MLPatchBackend)
	}

	// --save_log: normalize the format permissively so a stray --format value
	// never aborts a long analysis run; unknown values fall back to txt.
	if opts.SaveLog {
		switch strings.ToLower(strings.TrimSpace(opts.SaveLogFormat)) {
		case "", "txt", "text", "log":
			opts.SaveLogFormat = "txt"
		case "ansi", "raw", "color", "colour":
			opts.SaveLogFormat = "ansi"
		case "md", "markdown":
			opts.SaveLogFormat = "md"
		default:
			opts.SaveLogFormat = "txt"
		}
	}

	// Experimental subsystem
	if err := opts.validateExperimentalOptions(); err != nil {
		return err
	}

	return nil
}

func validateFirmwareTarget(target string) error {
	switch strings.ToLower(filepath.Ext(cleanTUIPath(target))) {
	case ".apk", ".apks", ".xapk", ".aab", ".dex", ".ipa":
		return fmt.Errorf("%s is an app package, not a firmware image; use Start analysis", filepath.Base(cleanTUIPath(target)))
	}
	return nil
}

// validateExperimentalOptions normalizes and validates experimental flags.
//
// Rules:
//   - --aeg implies --ml-ex with selector "aeg"
//   - --ml-ex-apply implies --ml-ex
//   - negative timeout is rejected
//   - empty selector with --ml-ex defaults to "all"
//
// The actual selector is parsed against the registry inside the runner so
// that this function stays free of cross-package imports.
func (opts *CLIOptions) validateExperimentalOptions() error {
	if opts.AEG {
		opts.MLEx = true
		if opts.MLExApply == "" {
			opts.MLExApply = "aeg"
		} else if !strings.Contains(strings.ToLower(opts.MLExApply), "aeg") {
			opts.MLExApply = strings.TrimSpace(opts.MLExApply) + ",aeg"
		}
	}
	if opts.MLExApply != "" {
		opts.MLEx = true
	}
	if opts.MLEx && opts.MLExApply == "" {
		opts.MLExApply = "all"
	}
	if opts.MLExTimeout < 0 {
		return fmt.Errorf("--ml-ex-timeout must be >= 0, got %d", opts.MLExTimeout)
	}
	return nil
}

// IsMLCommand проверяет, является ли это ML-командой (не требует target)
func (opts *CLIOptions) IsMLCommand() bool {
	return opts.MLSuggest || opts.MLHistory || opts.MLStats ||
		opts.MLTrain || opts.MLTrainEnsemble ||
		opts.MLExport != "" ||
		opts.MarkRelevant != "" || opts.MarkNoise != "" ||
		opts.ShowFeedback || opts.MLApply != "" ||
		opts.PatternStats || opts.ExportPatternStats != "" ||
		opts.FeedbackFile != "" ||
		opts.MLExList || (opts.WebScan && opts.Target == "")
}

// IsSandboxCommand проверяет, является ли это командой песочницы.
func (opts *CLIOptions) IsSandboxCommand() bool {
	return opts.Sandbox || opts.AndroidSandbox || opts.SandboxRemoteConfig != ""
}

// IsDecodeCommand проверяет, является ли это командой decode (apktool-style)
func (opts *CLIOptions) IsDecodeCommand() bool {
	return opts.Decode
}

// IsBuildCommand проверяет, является ли это командой build/rebuild
func (opts *CLIOptions) IsBuildCommand() bool {
	return opts.Rebuild || opts.Build
}

// IsRebuildCommand проверяет, является ли это командой rebuilding
func (opts *CLIOptions) IsRebuildCommand() bool {
	return opts.Rebuild || opts.Build
}

// IsInterceptCommand проверяет, является ли это командой intercept
func (opts *CLIOptions) IsInterceptCommand() bool {
	return opts.Intercept
}

// IsServgenCommand проверяет, является ли это командой servgen
func (opts *CLIOptions) IsServgenCommand() bool {
	return opts.Servgen
}

// IsFuzzCommand проверяет, является ли это командой fuzz
func (opts *CLIOptions) IsFuzzCommand() bool {
	return opts.Fuzz
}

// IsLabDNSCommand проверяет, является ли это командой lab-dns
func (opts *CLIOptions) IsLabDNSCommand() bool {
	return opts.LabDNS
}

func (opts *CLIOptions) IsVersionDiffCommand() bool {
	return opts.VersionDiff
}

func (opts *CLIOptions) IsFirmwareCommand() bool {
	return opts.Firmware
}

// IsMakeServerCommand reports whether the user asked for the
// authorized-lab Elixir/OTP private server generator. It runs as a
// standalone command on top of an APK / DEX / directory target.
func (opts *CLIOptions) IsMakeServerCommand() bool {
	return opts.MakeServer
}

func (opts *CLIOptions) IsJSDeobfuscateCommand() bool {
	return opts.JSDeobfuscate
}

func (opts *CLIOptions) IsAPKEditorCommand() bool {
	return opts.OpenAPKEditor
}

// IsJSPatchCommand reports whether the user requested the JS bundle patcher.
func (opts *CLIOptions) IsJSPatchCommand() bool {
	return opts.JSPatch
}

func (opts *CLIOptions) validateSandboxOptions() error {
	if opts.SandboxRemoteConfig != "" {
		opts.Sandbox = true
		if opts.AndroidSandbox || opts.SandboxAllowHostExecution || opts.SandboxStream || opts.SandboxProfile != "" || opts.WinSandbox || opts.EnableVSS || opts.EnableWFP || opts.EnableKernelMonitor || opts.EnableTimeManip || opts.SandboxFridaScript != "" || opts.SandboxVSSRevert || (opts.SandboxTimeScale != 0 && opts.SandboxTimeScale != 1) || opts.SandboxArgs != "" || opts.SandboxAllowNet || opts.SandboxCapture || opts.SandboxMITM || opts.SandboxDevice != "" || opts.SandboxAVD != "" || opts.SandboxAutoAVD || opts.SandboxPrivServer != "" || opts.SandboxUninstall || opts.SandboxCPUCores != 0 || opts.SandboxLocale != "" || opts.SandboxTimezone != "" || opts.SandboxResolution != "" || opts.SandboxOrientation != "" || (opts.SandboxMemoryMB != 0 && opts.SandboxMemoryMB != 512) {
			return fmt.Errorf("remote VM capture cannot be combined with local, Android, stream, custom-script or native enhancement options")
		}
		// Remote execution always uses the shipped hooks and spawn mode. Network
		// and resource restrictions belong to the hypervisor, never host WFP.
		if opts.Target == "" {
			return fmt.Errorf("remote VM capture requires -t with an absolute guest EXE path")
		}
		if opts.SandboxDuration < 0 || (opts.SandboxDuration > 0 && opts.SandboxDuration < 5) || uint64(opts.SandboxDuration) > uint64((1<<63-1)/int64(time.Second)) {
			return fmt.Errorf("invalid remote sandbox duration")
		}
		if opts.IsMLCommand() || opts.IsBuildCommand() || opts.IsDecodeCommand() {
			return fmt.Errorf("remote VM capture cannot be combined with other commands")
		}
		return nil
	}
	if opts.AndroidSandbox {
		opts.Sandbox = true
	}
	if opts.Target == "" {
		return fmt.Errorf("sandbox mode requires a target path\n\nUsage: analyzer --sandbox -t <sample.exe|app.apk|smali_dir>")
	}

	if opts.IsMLCommand() {
		return fmt.Errorf("--sandbox cannot be combined with ML assistant commands")
	}

	if opts.IsBuildCommand() {
		return fmt.Errorf("--sandbox cannot be combined with --rebuild / --build")
	}
	if opts.IsDecodeCommand() {
		return fmt.Errorf("--sandbox cannot be combined with --decode")
	}

	if opts.SandboxDuration < 0 || (opts.SandboxDuration > 0 && opts.SandboxDuration < 5) {
		return fmt.Errorf("sandbox-duration must be at least 5 seconds or 0 (no deadline), got %d", opts.SandboxDuration)
	}

	if uint64(opts.SandboxDuration) > uint64((1<<63-1)/int64(time.Second)) {
		return fmt.Errorf("sandbox-duration exceeds the supported time.Duration range")
	}

	if opts.SandboxMemoryMB < 128 {
		return fmt.Errorf("sandbox-memory must be at least 128 MB, got %d", opts.SandboxMemoryMB)
	}

	if opts.SandboxCPUCores < 0 {
		return fmt.Errorf("sandbox-cpu-cores must be >= 0, got %d", opts.SandboxCPUCores)
	}

	switch strings.ToLower(strings.TrimSpace(opts.SandboxOrientation)) {
	case "", "portrait", "landscape":
		opts.SandboxOrientation = strings.ToLower(strings.TrimSpace(opts.SandboxOrientation))
	default:
		return fmt.Errorf("invalid --sandbox-orientation: %q (valid: portrait, landscape)", opts.SandboxOrientation)
	}

	if r := normalizeResolution(opts.SandboxResolution); opts.SandboxResolution != "" && r == "" {
		return fmt.Errorf("invalid --sandbox-resolution: %q (use WxH like 1080x1920, or 720p|1080p|1440p)", opts.SandboxResolution)
	} else {
		opts.SandboxResolution = r
	}

	if opts.DebugVerbose && opts.Quiet {
		return fmt.Errorf("--debug and --quiet are mutually exclusive")
	}

	if err := opts.applySandboxProfile(); err != nil {
		return err
	}

	// Validate Windows-native sandbox options
	// Only validate time scale if it's non-zero (explicitly set)
	if opts.SandboxTimeScale != 0.0 && (opts.SandboxTimeScale < 0.1 || opts.SandboxTimeScale > 1000.0) {
		return fmt.Errorf("sandbox-time-scale must be between 0.1 and 1000.0, got %.2f", opts.SandboxTimeScale)
	}

	// If time scale is 0, set to default 1.0 (real-time)
	if opts.SandboxTimeScale == 0.0 {
		opts.SandboxTimeScale = 1.0
	}

	// If any component is explicitly enabled, enable win-sandbox mode
	if opts.EnableKernelMonitor || opts.EnableVSS || opts.EnableWFP ||
		opts.EnableAPITracing || opts.EnableTimeManip {
		opts.WinSandbox = true
	}

	// If VSS revert is enabled, VSS must be enabled
	if opts.SandboxVSSRevert && !opts.EnableVSS {
		opts.EnableVSS = true
	}

	// If time manipulation is enabled via scale factor, enable the component
	if opts.SandboxTimeScale > 1.0 && !opts.EnableTimeManip {
		opts.EnableTimeManip = true
	}

	return nil
}

func (opts *CLIOptions) applySandboxProfile() error {
	profile := strings.ToLower(strings.TrimSpace(opts.SandboxProfile))
	if profile == "" {
		return nil
	}

	switch profile {
	case "basic":
	case "trace":
		opts.EnableAPITracing = true
		opts.EnableWFP = true
	case "forensic":
		opts.EnableKernelMonitor = true
		opts.EnableVSS = true
		opts.EnableWFP = true
		opts.EnableAPITracing = true
	case "paranoid":
		opts.EnableKernelMonitor = true
		opts.EnableVSS = true
		opts.EnableWFP = true
		opts.EnableAPITracing = true
		opts.EnableTimeManip = true
		if opts.SandboxTimeScale <= 1.0 {
			opts.SandboxTimeScale = 10.0
		}
	default:
		return fmt.Errorf("invalid --sandbox-profile: %q (valid: basic, trace, forensic, paranoid)", opts.SandboxProfile)
	}

	if profile != "basic" {
		opts.WinSandbox = true
	}
	return nil
}

// normalizeResolution converts a resolution string to canonical "WxH" form.
// Accepts shorthand (720p|1080p|1440p, given as portrait WxH for the Android
// emulator) or an explicit "WxH" pair. Returns "" for empty input (no change
// requested) and "" for malformed input so callers can report an error.
func normalizeResolution(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	switch s {
	case "720p", "hd":
		return "720x1280"
	case "1080p", "fhd":
		return "1080x1920"
	case "1440p", "qhd", "2k":
		return "1440x2560"
	}
	parts := strings.SplitN(s, "x", 2)
	if len(parts) != 2 {
		return ""
	}
	w, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	h, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || w < 240 || h < 240 || w > 8192 || h > 8192 {
		return ""
	}
	return fmt.Sprintf("%dx%d", w, h)
}

func (opts *CLIOptions) validateMLOptions() error {
	// Auto-enable suggest if export is requested
	if opts.MLExport != "" {
		opts.MLSuggest = true
	}

	if opts.MLConfidence < 0 || opts.MLConfidence > 1 {
		return fmt.Errorf("--ml-confidence must be between 0 and 1, got %.2f", opts.MLConfidence)
	}

	if opts.MLMaxSuggestions < 0 {
		return fmt.Errorf("--ml-max must be >= 0 (0 means unlimited)")
	}

	if opts.MarkRelevant != "" && opts.MarkNoise != "" {
		return fmt.Errorf("--mark-relevant and --mark-noise are mutually exclusive")
	}

	return nil
}
