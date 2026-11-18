package main

import (
	"flag"
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml"
)

func (p *CLIParser) Parse(args []string) (*CLIOptions, error) {
	// Normalize common subcommands so users and scripts can run `analyzer build ...`, `analyzer decode ...`, etc.
	if len(args) > 0 {
		switch args[0] {
		case "build", "rebuild", "decode", "edit":
			args = append([]string{"-" + args[0]}, args[1:]...)
		}
	}

	callerArgs := append([]string(nil), args...)

	opts := defaultCLIOptions()

	// Apply environment variable defaults (lower priority than CLI)
	p.applyEnvDefaults(opts)

	// ── Define flags ─────────────────────────────────────────────────────────

	// Target
	p.fs.StringVar(&opts.Target, "target", "", "Target directory with decompiled APK")
	p.fs.StringVar(&opts.Target, "t", "", "Target directory (shorthand)")
	p.fs.StringVar(&opts.Output, "output", opts.Output, "Output directory for reports")
	p.fs.StringVar(&opts.Output, "o", opts.Output, "Output directory (shorthand)")
	p.fs.BoolVar(&opts.Minecraft, "minecraft", false, "Inspect Minecraft JAR mods, resource packs and Bedrock MCPACK/MCADDON")

	// Performance
	p.fs.IntVar(&opts.Workers, "workers", opts.Workers, "Number of worker goroutines")
	p.fs.IntVar(&opts.Workers, "w", opts.Workers, "Workers (shorthand)")
	p.fs.IntVar(&opts.Timeout, "timeout", opts.Timeout, "Analysis timeout in seconds")
	p.fs.IntVar(&opts.MaxFiles, "max-files", 0, "Limit number of files (0=unlimited)")

	// File size limits
	p.fs.IntVar(&opts.MaxFileSizeMB, "max-file-size", 0,
		"Max code file size in MB (0=profile default)")
	p.fs.IntVar(&opts.MaxResourceSizeMB, "max-resource-size", 0,
		"Max resource/XML file size in MB (0=profile default)")

	// Profile
	var profileStr string
	p.fs.StringVar(&profileStr, "profile", "balanced", "Analysis profile")
	p.fs.StringVar(&profileStr, "p", "balanced", "Profile (shorthand)")

	// Analysis
	p.fs.StringVar(&opts.DecisionAIURL, "decision-ai-url", opts.DecisionAIURL, "Local DecisionAI origin for advisory finding triage (or MEGA_DECISION_AI_URL)")
	p.fs.StringVar(&opts.DecisionAIInput, "decision-ai-input", "", "Send a System One request JSON file to local DecisionAI; print JSON without scanning or applying changes")
	p.fs.IntVar(&opts.DecisionAIMaxFindings, "decision-ai-max-findings", 64, "Maximum findings reviewed by DecisionAI, highest severity first (1..512)")
	p.fs.IntVar(&opts.DecisionAIBudget, "decision-ai-budget", 30, "Total DecisionAI time budget in seconds (1..300)")
	p.fs.BoolVar(&opts.DecisionAIImages, "decision-ai-images", true, "Use configured local DecisionAI to filter image previews in HTML reports")
	p.fs.IntVar(&opts.DecisionAIMaxImages, "decision-ai-max-images", 512, "Maximum unique image requests for report preview filtering (1..512)")
	p.fs.IntVar(&opts.DecisionAIImageBudget, "decision-ai-image-budget", 240, "Separate total image preview review budget in seconds (1..300)")
	p.fs.BoolVar(&opts.EnableCallGraph, "callgraph", false, "Enable call graph analysis")
	p.fs.BoolVar(&opts.EnableCorrelations, "correlations", false, "Enable correlations")
	p.fs.BoolVar(&opts.EnableDeepScan, "deep-scan", false, "Enable deep bytecode scanning")
	p.fs.BoolVar(&opts.EnableMedia, "enable-media", false, "Enable deep media forensics (Polyglots, Steganography)")
	p.fs.BoolVar(&opts.ExtractPS1, "extract-ps1", false, "Generate PowerShell script to unpack embedded media payloads")

	// Output
	p.fs.BoolVar(&opts.DebugVerbose, "debug", false, "Enable debug logging")
	p.fs.BoolVar(&opts.DebugVerbose, "d", false, "Debug (shorthand)")
	p.fs.BoolVar(&opts.Quiet, "quiet", false, "Minimal output")
	p.fs.BoolVar(&opts.Quiet, "q", false, "Quiet (shorthand)")
	p.fs.BoolVar(&opts.NoColor, "no-color", false, "Disable colored output")
	var tuiOpt bool
	p.fs.BoolVar(&tuiOpt, "tui", false, "Enable fancy TUI panels")
	p.fs.StringVar(&opts.TUISection, "tui-section", "", "Open TUI section: general|analysis|mobile|compliance|artifacts|cache|reports|toolkit|network")
	p.fs.StringVar(&opts.TUISearch, "tui-search", "", "Open TUI flag search with this query")
	// -no-tui is advertised in the help text and used by the web UI
	// when it re-invokes this binary. CLI mode is already the default, so these
	// are effectively no-ops — but they must be REGISTERED, otherwise flag.Parse
	// aborts with "flag provided but not defined: -no-tui" and every scripted or
	// web-UI invocation dies before any analysis starts.
	var noTUIOpt bool
	p.fs.BoolVar(&noTUIOpt, "no-tui", false, "Disable TUI panels (CLI mode; this is the default)")
	p.fs.BoolVar(&opts.NoProfile, "no-profile", false, "Do not load settings from profile files")
	p.fs.BoolVar(&opts.JSON, "json", false, "Output as JSON to stdout")
	p.fs.BoolVar(&opts.NoHTML, "no-html", false, "Skip HTML report generation")
	p.fs.BoolVar(&opts.NoJSON, "no-json", false, "Skip JSON report generation")
	p.fs.BoolVar(&opts.JSONCompact, "json-compact", false,
		"Write analysis.json without smali method bodies (compact daily-view export; matches and evidence are kept)")
	p.fs.BoolVar(&opts.SARIF, "sarif", false, "Write analysis.sarif for GitHub/GitLab/Sonar-style code scanning")
	p.fs.BoolVar(&opts.ExitCodes, "exit-codes", false,
		"CI exit codes: 0 clean, 1 findings at -fail-on level, 2 one level below, 3 error, 4 incomplete analysis (parse failures, limits, degraded rules)")
	p.fs.StringVar(&opts.FailOn, "fail-on", "critical",
		"With -exit-codes: lowest severity that yields exit 1 (critical|high|medium|low)")
	p.fs.StringVar(&opts.KnownSet, "known-set", "",
		"Path to a knownset-build bundle: known-bad hits become loud alerts, known-good hits become info notes (analysis is never skipped)")

	// APK Patch Editor
	p.fs.BoolVar(&opts.OpenAPKEditor, "apk-editor", false, "Launch native Zig APK Patch Editor GUI")
	p.fs.BoolVar(&opts.OpenAPKEditor, "edit", false, "Launch native Zig APK Patch Editor GUI (shorthand)")

	// Asset scan (3D / textures / encrypted media)
	p.fs.StringVar(&opts.AssetScan, "assets", "",
		"Scan a file, folder or APK/ZIP for .glb, textures and obfuscated images")
	p.fs.StringVar(&opts.AssetsOut, "assets-out", "",
		"Directory for rendered PNG previews (default: <target>-assets next to the target)")
	p.fs.BoolVar(&opts.AssetsOpen, "assets-open", false,
		"Open the rendered previews in the native Zig APK Patch Editor")
	p.fs.BoolVar(&opts.AssetsJSON, "assets-json", false,
		"Emit the asset-scan report as JSON on stdout (used by the Zig editor)")
	p.fs.BoolVar(&opts.AssetsDeep, "assets-deep", false,
		"Widen the recovery search and the embedded-frame scan window")
	p.fs.BoolVar(&opts.AssetsAll, "assets-all", false,
		"Report every file walked, not just recognised assets")
	p.fs.IntVar(&opts.AssetsMaxMB, "assets-max-mb", 64,
		"Skip asset-scan entries larger than this many MB")
	p.fs.IntVar(&opts.AssetsMaxDim, "assets-max-dim", 512,
		"Longest side of a rendered preview, in pixels")
	p.fs.IntVar(&opts.AssetsMaxPrev, "assets-max-previews", 256,
		"Maximum number of PNG previews written per scan")
	p.fs.BoolVar(&opts.AssetsNoTextures, "assets-no-textures", false,
		"Do not render textures embedded in 3D models (the material map is still reported)")
	p.fs.IntVar(&opts.AssetsTextures, "assets-textures", 4,
		"How many embedded textures to render per model")
	p.fs.BoolVar(&opts.AssetsNoBytemap, "assets-no-bytemap", false,
		"Suppress byte-map fallback images, keeping only real decodes")
	p.fs.BoolVar(&opts.AssetsNoZstd, "assets-no-zstd", false,
		"Do not inflate zstd payloads; report the frame header only")
	p.fs.BoolVar(&opts.AssetsNoASTC, "assets-no-astc", false,
		"Do not decode ASTC block textures; headerless payloads stay byte maps")

	// Web UI
	p.fs.BoolVar(&opts.Web, "web", false, "Launch local web UI for drag-and-drop file analysis")
	p.fs.BoolVar(&opts.Admin, "admin", false, "Request OS administrator/root rights (only with -web)")
	p.fs.BoolVar(&opts.adminRelaunched, "admin-reexec", false, "Internal admin restart marker")
	p.fs.StringVar(&opts.adminCWD, "admin-cwd", "", "Internal admin restart directory")

	p.fs.IntVar(&opts.WebPort, "web-port", 7474, "Port for the web UI server (default 7474)")
	p.fs.StringVar(&opts.WebToken, "web-ui-token", "", "Fixed pairing token for the web UI API (default: random, printed at startup)")
	p.fs.BoolVar(&opts.APIServer, "api", false, "Launch the REST API server from this analyzer binary")
	p.fs.IntVar(&opts.APIPort, "api-port", 5000, "Port for the REST API server (default 5000)")
	p.fs.BoolVar(&opts.CleanOutput, "clean-output", false,
		"Delete output dir contents before writing reports")

	// Report
	p.fs.StringVar(&opts.Report, "report", "", "Report preset: short|default|full|all")
	p.fs.BoolVar(&opts.FPStrict, "fp-strict", false, "Suppress anything not confirmed as app/SDK risk")
	p.fs.BoolVar(&opts.FPShowSuppressed, "fp-show-suppressed", false, "Keep the full suppressed-noise log in JSON/HTML/SARIF triage data")
	p.fs.Float64Var(&opts.FPMinScore, "fp-min-score", opts.FPMinScore, "Minimum final FP-filter score to show (-1=profile default)")
	p.fs.IntVar(&opts.FPSuppressedLimit, "fp-suppressed-limit", opts.FPSuppressedLimit, "Max suppressed findings to keep (-1=profile default, 0=unlimited)")

	// APK/DEX support
	p.fs.BoolVar(&opts.KeepTemp, "keep-temp", false, "Keep temporary files after analysis")
	p.fs.BoolVar(&opts.DEXOnly, "dex-only", false, "Analyze DEX code only, skip resources")

	// ARTIFACTS — opt-in section
	p.fs.BoolVar(&opts.EnableArtifacts, "artifacts", false,
		"Extract images / 3D models / .so / other non-smali artifacts into the report")
	p.fs.BoolVar(&opts.AllowExport, "allow-export", false,
		"Allow Export buttons in HTML viewer (off by default)")
	p.fs.IntVar(&opts.ArtifactsMaxMB, "artifacts-max-mb", 10,
		"Per-file embed cap for Artifacts in MB")
	p.fs.IntVar(&opts.ArtifactsBudgetMB, "artifacts-budget", 200,
		"Total embedded bytes cap for Artifacts in MB")
	p.fs.BoolVar(&opts.NoImageBlur, "no-image-blur", false,
		"Disable blur for possibly sensitive images in HTML report")

	// Native binary analysis — Rust is an implementation detail, not a flag name.
	p.fs.BoolVar(&opts.MachineCode, "scan-native", false,
		"Analyze a native PE / ELF / EXE / DLL / SO binary")
	p.fs.BoolVar(&opts.MCRevealSecrets, "scan-native-reveal-secrets", false,
		"Show full unmasked values for embedded secrets (default: masked)")

	// Bytecode analysis — BinZAP is the internal backend, not a user concept.
	p.fs.BoolVar(&opts.Binzap, "scan-bytecode", false,
		"Analyze APK, Smali, or textual ASM bytecode")
	p.fs.BoolVar(&opts.BinzapActive, "scan-bytecode-deep", false,
		"Add offline taint/dataflow analysis without executing the target")

	// TOP-5 insight modules
	p.fs.BoolVar(&opts.EnableTop5, "top5", false,
		"Enable JNI, privacy and graph sidecar analyzers for APK/DEX targets")
	p.fs.BoolVar(&opts.EnableJNI, "jni-bridge", false,
		"Run Java/DEX to native JNI boundary analyzer")
	p.fs.BoolVar(&opts.EnablePrivacy, "privacy", false,
		"Run mobile privacy analyzer")
	p.fs.BoolVar(&opts.EnableGraphExplorer, "graph-explorer", false,
		"Generate interactive graph explorer sidecar")
	p.fs.BoolVar(&opts.VersionDiff, "version-diff", false,
		"Compare two APKs/directories and write version diff report")
	p.fs.BoolVar(&opts.VersionDiff, "diff", false,
		"Version diff mode (shorthand)")
	p.fs.StringVar(&opts.DiffOld, "diff-old", "",
		"Old APK/directory for --version-diff")
	p.fs.StringVar(&opts.DiffNew, "diff-new", "",
		"New APK/directory for --version-diff")
	p.fs.BoolVar(&opts.Firmware, "firmware", false,
		"Run Firmware / IoT analyzer for a firmware image, archive, or rootfs")

	// MOBSF-DERIVED ANALYZERS
	p.fs.BoolVar(&opts.EnableMobSFAll, "mobsf-all", false,
		"Enable all MobSF-derived analyzers (SAST rules + trackers + NSC + manifest audit + apkid)")
	p.fs.BoolVar(&opts.EnableSASTRules, "sast-rules", false,
		"Run MobSF-derived regex SAST rule scanner (OWASP / MASVS / CWE-tagged)")
	p.fs.BoolVar(&opts.EnableTrackers, "trackers", false,
		"Run Exodus-style ad/analytics tracker detection")
	p.fs.BoolVar(&opts.EnableNSCAudit, "nsc-audit", false,
		"Audit res/xml/network_security_config.xml")
	p.fs.BoolVar(&opts.EnableManifestAudit, "manifest-audit", false,
		"Deep manifest audit: exported components, deep links, debuggable / allowBackup, sharedUserId")
	p.fs.BoolVar(&opts.EnableAPKID, "apkid", false,
		"Detect compiler / packer / obfuscator / anti-analysis fingerprints")

	// MEDIUM-PRIORITY ANALYZERS
	p.fs.BoolVar(&opts.EnableMediumAll, "medium-all", false,
		"Enable all medium-priority analyzers (playstore + sbom + permmap + cert-audit + malware-domains + niap)")
	p.fs.BoolVar(&opts.EnablePlayStore, "playstore", false,
		"Lookup Play Store metadata by package name")
	p.fs.BoolVar(&opts.EnableSBOM, "sbom", false,
		"Extract SBOM from Kotlin/Java .version files")
	p.fs.BoolVar(&opts.EnablePermMap, "permmap", false,
		"Map declared permissions to actual code usage")
	p.fs.BoolVar(&opts.EnableCertAudit, "cert-audit", false,
		"Deep certificate analysis (expiry, debug key, signing scheme)")
	p.fs.BoolVar(&opts.EnableMalwareDomains, "malware-domains", false,
		"Check extracted URLs against malware domain blacklist")
	p.fs.BoolVar(&opts.EnableNIAP, "niap", false,
		"Run NIAP compliance rule scanner")

	// MAKE-SERVER — authorized-lab Elixir / OTP private server generator
	p.fs.BoolVar(&opts.MakeServer, "make-server", false,
		"Generate authorized-lab Elixir/OTP private server skeleton from the target APK/DEX/dir")
	p.fs.BoolVar(&opts.MakeServer, "privserver", false,
		"Alias for --make-server")
	p.fs.StringVar(&opts.MakeServerGame, "privserver-game", "",
		"Override the game name written into the generated project")
	p.fs.StringVar(&opts.MakeServerModule, "privserver-module", "",
		"Override the Elixir module prefix used by the generated project")
	p.fs.StringVar(&opts.MakeServerOutput, "privserver-output", "",
		"Output directory for the generated Elixir project (default: <output>/private_server)")
	p.fs.IntVar(&opts.MakeServerPort, "privserver-port", 0,
		"TCP listen port for the generated server (default: 9339)")
	p.fs.IntVar(&opts.MakeServerAdmin, "privserver-admin", 0,
		"HTTP port for the generated admin dashboard (default: 8765)")

	// APK Rebuilding / Decoding (apktool-style)
	p.fs.BoolVar(&opts.Rebuild, "rebuild", false, "Rebuild APK from a project directory or ZIP (native by default)")
	p.fs.BoolVar(&opts.Rebuild, "r", false, "Rebuild (shorthand)")
	p.fs.BoolVar(&opts.Build, "build", false, "Build APK from a project directory or ZIP (alias for --rebuild)")
	p.fs.BoolVar(&opts.Build, "b", false, "Build APK (shorthand)")
	p.fs.StringVar(&opts.BundleBudget, "bundle-budget", "large", "Hermes budgets: compact (5000 functions) or large (100000 functions, 512 MiB text cap)")
	p.fs.BoolVar(&opts.BundleExport, "bundle-export", false, "Export JS deobfuscation or Hermes disassembly during static analysis (not original JS recovery)")
	p.fs.BoolVar(&opts.BundlePatches, "bundle-patches", false, "Write read-only JS patch candidate reports during static analysis; Hermes remains scan-only")
	p.fs.BoolVar(&opts.SaveDecoded, "save-decoded", false, "Also save decoded APK/DEX (Smali/resources) under output/decoded")
	p.fs.BoolVar(&opts.Decode, "decode", false, "Decode APK or DEX to directory without analysis")
	p.fs.BoolVar(&opts.NoSign, "no-sign", false, "Skip APK signing (faster rebuild)")
	p.fs.BoolVar(&opts.NoAlign, "no-align", false, "Skip ZIP alignment")
	p.fs.BoolVar(&opts.NoResources, "no-resources", false, "Skip resource decoding")
	p.fs.BoolVar(&opts.NoSmali, "no-smali", false, "Skip smali generation")
	p.fs.BoolVar(&opts.Standalone, "standalone", false, "Forbid external tools (Java/aapt2/apksigner/zipalign); native Go only (or MEGA_STANDALONE=1)")
	p.fs.BoolVar(&opts.AllowExternalTools, "allow-external-tools", false, "Allow build to discover and execute compatibility tools; disabled by default")
	p.fs.BoolVar(&opts.JavaView, "java-view", false, "Emit per-class .java pseudocode next to smali")
	p.fs.BoolVar(&opts.NoSmaliHeaders, "no-headers", false, "Omit # Disassembled from DEX comment headers from smali files")
	p.fs.BoolVar(&opts.NoSmaliHeaders, "no-smali-header", false, "Omit smali metadata comment headers")
	p.fs.BoolVar(&opts.SmaliHeaders, "headers", false, "Include source/hash comments in native Smali")
	p.fs.StringVar(&opts.FrameworkDir, "framework-dir", "", "Framework directory for resource decoding")
	p.fs.BoolVar(&opts.CopyOriginal, "copy-original", false, "Copy original META-INF and unknown files")
	p.fs.StringVar(&opts.Aapt2Path, "aapt2", "", "Path to aapt2 binary for resource compile+link (auto-detect if unset)")
	p.fs.BoolVar(&opts.UseSmali, "use-smali", true, "Enable smali→dex assembly during rebuild (default: auto-detect)")
	p.fs.BoolVar(&opts.UseAapt2, "use-aapt2", true, "Enable aapt2 resource compile+link during rebuild (default: auto-detect)")
	// v1-v7 apkloader upgrades: decode backends, native assembly tuning, rebuild zip
	p.fs.StringVar(&opts.DexBackend, "dex-backend", "auto", "Decode backend: auto|native (both use the native Go decoder)")
	p.fs.BoolVar(&opts.ClassCache, "class-cache", true, "Cache native DEX→Smali per class in .mega-analyzer-cache.db")
	p.fs.IntVar(&opts.SmaliAPI, "smali-api", 0, "Native assembler Android API level; 0 auto-matches tree dex version")
	p.fs.IntVar(&opts.SmaliJobs, "smali-jobs", 0, "Native DEX assembly workers; 0 = automatic (up to 4)")
	p.fs.BoolVar(&opts.SmaliIncremental, "smali-incremental", true, "Incremental smali→dex via .mega-analyzer-build-cache.json")
	p.fs.StringVar(&opts.CompressionMode, "compression-mode", "balanced", "Rebuild ZIP mode: fast|balanced|best")
	p.fs.IntVar(&opts.SpoolThresholdMB, "spool-threshold-mb", 0, "Spool ZIP entries larger than N MB to temp files (0 = default 128MB)")
	p.fs.BoolVar(&opts.PreserveSignature, "preserve-signature", false, "Experimental: keep original META-INF/signing blocks, skip re-sign (valid only if signed bytes unchanged)")
	p.fs.StringVar(&opts.KsPath, "ks", "", "Keystore (JKS) for rebuild signing via apksigner; empty = generated debug key (unknown publisher)")
	p.fs.StringVar(&opts.KsAlias, "ks-alias", "", "Key alias inside --ks (empty = keystore default)")
	// Keystore passwords are NEVER flags: set ANALYZER_KEYSTORE_PASS and (optionally) ANALYZER_KEY_PASS in the environment.

	// ════════���══════════════════════════════════════════════════════════════════
	// JS / React Native Deobfuscation & Patching
	// ═══════════════════════════════════════════════════════════════════════════
	p.fs.BoolVar(&opts.JSDeobfuscate, "js-deobf", false, "Enable standalone JS bundle deobfuscator")
	p.fs.StringVar(&opts.JSDeobfuscateOut, "js-deobf-out", "", "Output file for deobfuscated JS bundle")

	p.fs.BoolVar(&opts.JSPatch, "js-patch", false, "Enable smart React Native / Hermes bundle patcher")
	p.fs.StringVar(&opts.JSPatchApply, "js-patch-apply", "dry-run", "JS patch apply mode: dry-run|write")
	p.fs.StringVar(&opts.JSPatchServerIP, "js-patch-server-ip", "", "New server address for URL replacement (e.g. 127.0.0.1:9339)")
	p.fs.BoolVar(&opts.JSPatchBackup, "js-patch-backup", false, "Create .orig backup before writing patches")
	p.fs.StringVar(&opts.JSPatchCategories, "js-patch-categories", "", "Comma-separated category whitelist (empty = all)")
	p.fs.IntVar(&opts.JSPatchMinConf, "js-patch-min-conf", 40, "Minimum confidence threshold 0-100")
	p.fs.StringVar(&opts.JSPatchOutput, "js-patch-output", "", "Output dir for JSPATCH.md / jspatch.json")

	// OBB / Data / Cache Scanner
	p.fs.BoolVar(&opts.OBBScan, "obb-scan", false, "Enable deep scan of OBB expansion files, data and cache directories")
	p.fs.StringVar(&opts.OBBDataDir, "obb-data-dir", "", "Path to Android/data/<pkg>/ or OBB directory to scan (auto-detect if unset)")
	p.fs.IntVar(&opts.OBBMaxSizeMB, "obb-max-size", 100, "Max OBB file size in MB to scan (0 = unlimited)")
	p.fs.BoolVar(&opts.OBBOutputJSON, "obb-json", true, "Write OBB_SCAN_REPORT.json with findings")

	// Cache Analyzer
	p.fs.BoolVar(&opts.CacheScan, "cache-scan", false, "Scan app cache for unencrypted saves, API keys, weak crypto")
	p.fs.StringVar(&opts.CacheDataDir, "cache-data-dir", "", "Override cache directory path (default: Android/data/<pkg>/cache)")

	// Content-Cache & Data-Flow
	p.fs.BoolVar(&opts.EnableContentCache, "enable-content-cache", false, "Enable persistent content-addressed method cache (off by default: multi-million-file cache dirs stall pipeline init for minutes)")
	p.fs.StringVar(&opts.ContentCacheDir, "content-cache-dir", defaultContentCacheDir, "Path to content cache directory")
	p.fs.Int64Var(&opts.ContentCacheMaxDiskMB, "content-cache-max-disk-mb", 2048, "Max disk space for content cache in MB")
	p.fs.BoolVar(&opts.EnableDataFlow, "enable-data-flow", true, "Enable summary-based IFDS/IDE Taint & Data-Flow analysis")
	p.fs.IntVar(&opts.DataFlowMaxMethods, "data-flow-max-methods", 200000, "Max methods for data-flow analysis")
	p.fs.IntVar(&opts.DataFlowMaxFindings, "data-flow-max-findings", 2000, "Max findings for data-flow analysis")

	// ML-Apli-Cache Script
	p.fs.BoolVar(&opts.MLCacheScript, "ml-cache-script", false, "Run ML-Apli-Cache predictive exploitation analysis on cache")

	// Web Scanner (vulnscan integration)
	p.fs.BoolVar(&opts.WebScan, "web-scan", false, "Analyze a website with the integrated vulnscan engine")
	p.fs.StringVar(&opts.WebScanTarget, "web-scan-target", "", "Target URL for website analysis")
	p.fs.StringVar(&opts.WebScanMode, "web-scan-mode", "active", "Web mode: status (one GET), passive (one response), active (full vulnerability scan)")
	p.fs.StringVar(&opts.WebScanMode, "web-mode", "active", "Alias for --web-scan-mode")
	p.fs.BoolVar(&opts.WebScanIOwnThisTarget, "i-own-this-target", false, "Acknowledge authorization (required only for active mode)")
	p.fs.BoolVar(&opts.WebScanLabMode, "lab-mode", false, "Enable destructive lab-only features (OAST, Desync)")
	p.fs.StringVar(&opts.WebScanAllowlist, "target-allowlist", "", "Comma-separated list of allowed domains")
	p.fs.StringVar(&opts.WebScanFSMConfig, "fsm-config", "", "Path to YAML file for State-Machine Fuzzing")
	p.fs.StringVar(&opts.HTMLBody, "html-body", "", "Path to an HTML file for passive-only body analysis (no active requests)")
	p.fs.StringVar(&opts.CurlCmd, "curl", "", "Scan a specific request expressed as a curl command")
	p.fs.StringVar(&opts.RawRequest, "raw-request", "", "Path to a file containing a raw HTTP request (Burp Suite format)")
	p.fs.StringVar(&opts.RawScheme, "raw-scheme", "https", "Scheme to use when importing a raw HTTP request (http|https)")

	// Private Server Toolkit
	p.fs.BoolVar(&opts.Intercept, "intercept", false, "Run MITM proxy to intercept game traffic")
	p.fs.IntVar(&opts.InterceptPort, "port", 9339, "Port to listen on for interception")
	p.fs.StringVar(&opts.InterceptUpstream, "upstream", "127.0.0.1:9339", "Upstream server to proxy to")
	p.fs.StringVar(&opts.InterceptRecord, "record", "", "File to record intercepted packets with connection metadata (JSONL)")
	p.fs.BoolVar(&opts.InterceptStopOnEOF, "intercept-stop-on-eof", false, "Stop the MITM proxy and flush its capture when stdin closes (managed sessions)")
	p.fs.BoolVar(&opts.InterceptInteractive, "interactive", false, "Enable live console prompting for altering packet payloads")
	p.fs.BoolVar(&opts.InterceptInteractive, "i", false, "Interactive mode (shorthand)")
	p.fs.BoolVar(&opts.NetJSONEvents, "net-json-events", false, "Emit @@NETEVENT@@ JSON lines on stdout for the DevMega network panel")
	p.fs.BoolVar(&opts.NetRemoteEdit, "net-remote-edit", false, "Drive packet editing from a remote DevMega client instead of the terminal prompt")
	p.fs.StringVar(&opts.InterceptFrame, "frame", "", "Reassemble TCP into real protocol frames: 'supercell' or 'len:HDR,OFF,SZ[,inclhdr]' (e.g. len:8,4,4)")
	p.fs.StringVar(&opts.NetFilter, "net-filter", "", "Display filter for intercepted traffic (fields: proto, ip[.src|.dst], port[.src|.dst], len, dir, sni, payload)")
	p.fs.BoolVar(&opts.NetFlows, "net-flows", false, "Reassemble intercepted packets into bidirectional flows and print a classified flow table")

	p.fs.BoolVar(&opts.Servgen, "servgen", false, "Generate server stub from recorded protocol")
	p.fs.StringVar(&opts.ServgenProtocol, "protocol-spec", "", "Protocol specification JSON")
	p.fs.StringVar(&opts.ServgenFromCapture, "from-capture", "", "Build the protocol spec by replaying a recorded -record JSONL capture (infers fields)")

	// Protocol-aware frame fuzzer (active MITM)
	p.fs.BoolVar(&opts.Fuzz, "fuzz", false, "Generate protocol-aware mutated frames from a capture (and optionally replay them)")
	p.fs.StringVar(&opts.FuzzCapture, "fuzz-capture", "", "Recorded -record JSONL capture to mutate (uses -frame for layout, default supercell)")
	p.fs.StringVar(&opts.FuzzTarget, "fuzz-target", "", "Optional loopback/private host:port to replay mutations against and flag anomalies")
	p.fs.StringVar(&opts.FuzzOut, "fuzz-out", "", "Optional path to write the mutation corpus as a JSON manifest")

	// Lab DNS
	p.fs.BoolVar(&opts.LabDNS, "lab-dns", false, "Run local intercepting DNS server")
	p.fs.StringVar(&opts.DNSAddr, "dns-addr", "127.0.0.1:15353", "Listen address for Lab DNS")
	p.fs.StringVar(&opts.DNSUpstream, "dns-upstream", "", "Upstream DNS server (empty = offline/refuse non-sinkholed queries)")
	p.fs.StringVar(&opts.DNSSinkholeIP, "dns-sinkhole", "127.0.0.1", "Sinkhole IP for blocked domains")

	// Sandbox / detonation
	p.fs.BoolVar(&opts.Sandbox, "sandbox", false, "Run target inside built-in sandbox mode")
	p.fs.StringVar(&opts.SandboxRemoteConfig, "sandbox-remote-config", "", "Collect from a Windows VM using a pinned TLS profile; -t is a path INSIDE the guest")
	p.fs.BoolVar(&opts.SandboxAllowHostExecution, "sandbox-allow-host-execution", false, "DANGER: allow trusted fixture execution on this host instead of a VM")
	p.fs.StringVar(&opts.SandboxArgs, "sandbox-args", "", "Raw command-line arguments for sandbox target")
	p.fs.IntVar(&opts.SandboxDuration, "sandbox-duration", opts.SandboxDuration,
		"Sandbox runtime in seconds (0 = until stopped; default 0)")
	p.fs.IntVar(&opts.SandboxMemoryMB, "sandbox-memory", opts.SandboxMemoryMB,
		"Per-process memory cap for sandbox target in MB")
	p.fs.BoolVar(&opts.SandboxAllowNet, "sandbox-allow-net", false,
		"Allow real network access for sandbox target (disabled by default)")
	p.fs.StringVar(&opts.SandboxProfile, "sandbox-profile", "",
		"Sandbox component preset: basic|trace|forensic|paranoid")
	p.fs.BoolVar(&opts.AndroidSandbox, "android-sandbox", false,
		"Enable Android-native dynamic sandbox execution via ADB")
	p.fs.StringVar(&opts.SandboxPrivServer, "sandbox-privserver", "",
		"Private server or MITM proxy to connect/redirect sandbox traffic to (e.g. 127.0.0.1:9339)")
	p.fs.StringVar(&opts.SandboxPrivServer, "sandbox-private-server", "",
		"Private server or MITM proxy to connect/redirect sandbox traffic to (alias for --sandbox-privserver)")
	p.fs.StringVar(&opts.SandboxAVD, "sandbox-avd", "",
		"Specific AVD name to launch if no device is connected")
	p.fs.BoolVar(&opts.SandboxAutoAVD, "sandbox-auto-avd", false,
		"Automatically launch the first available AVD if no device is connected")
	p.fs.StringVar(&opts.SandboxDevice, "sandbox-device", "",
		"Exact Android adb serial; do not select another device")
	p.fs.BoolVar(&opts.SandboxUninstall, "sandbox-uninstall-after", false,
		"Uninstall the app from the device after the sandbox run completes")
	p.fs.BoolVar(&opts.SandboxCapture, "sandbox-capture-traffic", false,
		"Capture raw network traffic via tcpdump on device (Android; saves capture.pcap)")
	p.fs.BoolVar(&opts.SandboxMITM, "sandbox-mitm", false,
		"Run mitmproxy on host for HTTPS interception (Android; saves intercept.har)")
	p.fs.BoolVar(&opts.SandboxFrida, "sandbox-frida", false,
		"Attach Frida to the detonated app and record instrumentation events")
	p.fs.BoolVar(&opts.SandboxFridaSpawn, "sandbox-frida-spawn", false,
		"Respawn the app under Frida so hooks are installed before application code runs (implies -sandbox-frida)")
	p.fs.StringVar(&opts.SandboxFridaScript, "sandbox-frida-script", "",
		"Path to a custom Frida instrumentation script (implies -sandbox-frida)")

	// Guest environment tuning (honored by the Android emulator; best-effort/gated on Windows host)
	p.fs.IntVar(&opts.SandboxCPUCores, "sandbox-cpu-cores", 0,
		"Cap the sandbox guest to N logical CPU cores (0 = engine default)")
	p.fs.StringVar(&opts.SandboxLocale, "sandbox-locale", "",
		"Guest locale (BCP-47, e.g. en-US) — applied to the Android emulator")
	p.fs.StringVar(&opts.SandboxTimezone, "sandbox-timezone", "",
		"Guest timezone (IANA, e.g. Europe/Moscow) — applied to the Android emulator")
	p.fs.StringVar(&opts.SandboxResolution, "sandbox-resolution", "",
		"Guest screen resolution: WxH or 720p|1080p|1440p — applied to the Android emulator")
	p.fs.StringVar(&opts.SandboxOrientation, "sandbox-orientation", "",
		"Guest screen orientation: portrait|landscape — applied to the Android emulator")

	// Windows-native sandbox enhancements
	p.fs.BoolVar(&opts.WinSandbox, "win-sandbox", false,
		"Enable Windows-native sandbox mode with kernel monitoring")
	p.fs.BoolVar(&opts.SandboxVSSRevert, "sandbox-vss-revert", false,
		"Automatically revert system changes using VSS snapshots after execution")
	p.fs.Float64Var(&opts.SandboxTimeScale, "sandbox-time-scale", opts.SandboxTimeScale,
		"Time acceleration factor (1.0=real-time, 10.0=10x faster)")
	p.fs.StringVar(&opts.SandboxOutput, "sandbox-output", "",
		"Output directory for sandbox artifacts (PCAPs, logs, snapshots)")
	p.fs.BoolVar(&opts.EnableKernelMonitor, "enable-kernel-monitor", false,
		"Enable kernel-level filesystem and registry monitoring")
	p.fs.BoolVar(&opts.EnableVSS, "enable-vss", false,
		"Enable Volume Shadow Copy snapshots for system state comparison")
	p.fs.BoolVar(&opts.EnableWFP, "enable-wfp", false,
		"Enable Windows Filtering Platform network capture")
	p.fs.BoolVar(&opts.EnableAPITracing, "enable-api-tracing", false,
		"Enable Windows API call tracing (process injection, memory operations)")
	p.fs.BoolVar(&opts.EnableTimeManip, "enable-time-manip", false,
		"Enable time manipulation (skip sleep delays, accelerate analysis)")
	p.fs.BoolVar(&opts.SandboxStream, "sandbox-stream", false,
		"Stream real-time sandbox telemetry in JSON to stdout")

	// ══════════════════════════════════════════════════════════════════════════
	// ML ASSISTANT FLAGS
	// ═════════����════════════════════════════════════════════════════════════════
	p.fs.BoolVar(&opts.MLSuggest, "suggest", false, "Run ML suggester for rule optimization")
	p.fs.StringVar(&opts.GNNModelPath, "gnn-model", "", "Path to GNN weights JSON (empty = auto-discover ~/.analyzer/models/gnn_weights.json and skip GNN when absent; __dummy__ = random test weights)")
	p.fs.BoolVar(&opts.SkipGNN, "skip-gnn", false, "Skip optional GNN classification even when model weights are available")
	p.fs.StringVar(&opts.ProGuardMap, "proguard-map", "", "Path to ProGuard/R8 mapping.txt for name recovery")
	p.fs.BoolVar(&opts.MLSuggest, "ml", false, "ML suggester (shorthand)")
	p.fs.BoolVar(&opts.MLHistory, "history", false, "Show analysis history")
	p.fs.BoolVar(&opts.MLStats, "stats", false, "Show aggregated statistics")
	p.fs.BoolVar(&opts.MLTrain, "ml-train", false, "Train keyword-relevance model from history.json")
	p.fs.BoolVar(&opts.MLTrainEnsemble, "ml-train-ensemble", false, "Train ensemble risk model from history.json")
	p.fs.BoolVar(&opts.MLTrainSoft, "ml-train-soft", false, "(reserved) include soft labels when training")
	p.fs.StringVar(&opts.MLExport, "export-suggestions", "", "Export suggestions to JSON file")
	p.fs.Float64Var(&opts.MLConfidence, "ml-confidence", opts.MLConfidence,
		"Minimum confidence threshold for suggestions (0.0-1.0)")
	p.fs.IntVar(&opts.MLMaxSuggestions, "ml-max", opts.MLMaxSuggestions,
		"Maximum suggestions to display (0=unlimited)")
	p.fs.BoolVar(&opts.MLPatch, "ml-patch", false, "Run ML patch predictor (smali patch points)")
	p.fs.BoolVar(&opts.MLPatchDirectSmali, "ml-patch-direct-smali", false, "IDE mode: scan decoded Smali directly; skip duplicate generic DEX/resource analysis")
	p.fs.BoolVar(&opts.MLPatchFix, "ml-patch-fix", false, "Also generate patched code and diffs")

	p.fs.BoolVar(&opts.MLPatchIncludeLibs, "ml-patch-include-libs", false, "Include library code in patch scan")

	// Crack Point & Anomaly
	p.fs.BoolVar(&opts.CrackPointAnalysis, "crackpoint-analysis", true, "Enable crack point discovery (default: true)")
	p.fs.Float64Var(&opts.CrackPointThreshold, "crackpoint-threshold", 0.75, "Confidence threshold for crack points")
	p.fs.BoolVar(&opts.AnomalyDetection, "anomaly-detection", true, "Enable anomaly detection (default: true)")
	p.fs.Float64Var(&opts.MLPatchMinScore, "ml-patch-min-score", opts.MLPatchMinScore,
		"Minimum patch risk score to include (0-100)")

	// ML Patch Pattern Enhancement FLAGS
	p.fs.StringVar(&opts.MLPatchMinTier, "ml-patch-min-tier", "normal",
		"Minimum pattern tier to use: elite, normal, trash")
	p.fs.BoolVar(&opts.MLPatchEnableDeprecated, "ml-patch-deprecated", false,
		"Enable deprecated patterns")
	p.fs.BoolVar(&opts.MLPatchEnableSDK, "ml-patch-sdk", true,
		"Enable SDK-specific detection")
	p.fs.BoolVar(&opts.MLPatchEnableCombination, "ml-patch-combination", true,
		"Enable pattern combination detection")
	p.fs.Float64Var(&opts.MLPatchConfidenceMin, "ml-patch-confidence", 0.3,
		"Minimum confidence threshold (0.0-1.0)")
	p.fs.BoolVar(&opts.MLPatchPrioritySort, "ml-patch-priority", true,
		"Sort by priority then score")
	p.fs.BoolVar(&opts.MLPatchCrossLanguage, "ml-patch-cross-lang", true,
		"Enable cross-language detection")

	// ML Patch Mode Selection
	p.fs.StringVar(&opts.MLPatchMode, "mode", "research",
		"Patch apply mode: research")

	// ML Patch Export and Display Options
	p.fs.BoolVar(&opts.MLPatchExplain, "explain", false,
		"Show detailed explanations for patches in terminal output")
	p.fs.StringVar(&opts.ExplainResult, "explain-result", "",
		"Explain evidence graph results from a JSON analysis result")
	p.fs.StringVar(&opts.ExplainNode, "explain-node", "",
		"Restrict explanation to a single evidence graph node")
	p.fs.StringVar(&opts.ExplainFile, "explain-file", "",
		"Restrict explanation to a single file")
	p.fs.StringVar(&opts.ExplainFormat, "explain-format", "text",
		"Explanation output format: text or json")
	var exportFormats string
	p.fs.StringVar(&exportFormats, "ml-patch-export-format", "",
		"Export formats for ML patches (e.g. md)")
	p.fs.StringVar(&exportFormats, "export-format", "", "Alias for ml-patch-export-format")
	p.fs.Float64Var(&opts.MLPatchConfidenceThresh, "confidence-threshold", 0.3,
		"Minimum confidence threshold for filtering results (0.0-1.0)")
	p.fs.StringVar(&opts.MLPatchExportOutput, "ml-patch-export-output", "",
		"Output file path for ML patches (without extension)")
	p.fs.StringVar(&opts.MLPatchExportOutput, "export-output", "", "Alias for ml-patch-export-output")
	p.fs.StringVar(&opts.MLPatchApply, "ml-patch-apply", "dry-run",
		"Patch apply mode: dry-run|write")
	p.fs.StringVar(&opts.MLPatchBackend, "ml-patch-backend", "smali",
		"Patch apply backend: smali|dex")
	p.fs.StringVar(&opts.MLPatchOutput, "ml-patch-output", "",
		"Output directory for patch artifacts")
	p.fs.StringVar(&opts.MLPatchFeedbackImport, "ml-patch-feedback-import", "",
		"Import ML patch feedback metrics JSON before scoring")
	p.fs.StringVar(&opts.MLPatchFeedbackExport, "ml-patch-feedback-export", "",
		"Export ML patch feedback metrics JSON after scoring")

	// FULL-SESSION LOG (--save_log): mirror everything printed to the console into a file.
	p.fs.BoolVar(&opts.SaveLog, "save_log", false,
		"Save the full console output to a file (see --log-output and --format)")
	p.fs.BoolVar(&opts.SaveLog, "save-log", false, "Alias for --save_log")
	p.fs.StringVar(&opts.SaveLogFormat, "format", "txt",
		"Format for --save_log: txt (strip ANSI colors) | ansi (keep colors) | md")
	p.fs.StringVar(&opts.SaveLogFormat, "log-format", "txt", "Alias for --format (used with --save_log)")
	p.fs.StringVar(&opts.SaveLogOutput, "log-output", "",
		"Destination file for --save_log (default: analysis_log.txt in the working dir)")
	p.fs.StringVar(&opts.SaveLogOutput, "save-log-output", "", "Alias for --log-output")

	// GAME MODE FLAGS
	p.fs.BoolVar(&opts.GameMode, "gamemode", false,
		"Enable Game Mode (XP, ranks and retro console output)")
	p.fs.StringVar(&opts.GameModeOutput, "gamemode-output", "terminal",
		"Game Mode output format (terminal, markdown, json)")
	p.fs.BoolVar(&opts.GameModePersist, "gamemode-persist", false,
		"Persist XP and progress in the local database")
	p.fs.BoolVar(&opts.DecoyDetection, "decoy-detection", false,
		"Enable decoy detection")
	p.fs.BoolVar(&opts.InterestingScore, "interesting-score", false,
		"Enable interesting-score calculation")
	p.fs.Float64Var(&opts.MLPatchConfidenceMin, "ml-patch-confidence-min", 0.3,
		"Minimum confidence for recommendations in game mode (alias)")
	p.fs.BoolVar(&opts.MLPatchPrioritySort, "ml-patch-priority-sort", true,
		"Sort by priority, then by score (alias)")
	p.fs.BoolVar(&opts.MLPatchCrossLanguage, "ml-patch-cross-language", true,
		"Enable cross-language detection (alias)")

	// ═══════════════════════════════════════════════════════════════════════════
	// MEDIA ANALYSIS & PATCHING (Phase 6)
	// ═══════════════════════════════════════════════════════════════════════════
	p.fs.BoolVar(&opts.MediaScan, "media-scan", false,
		"Enable media file analysis (detect steganography, extract GPS, find payloads)")
	p.fs.StringVar(&opts.MediaPayload, "media-payload", "",
		"Inject this payload into media metadata (e.g. SQLi string)")
	p.fs.StringVar(&opts.MediaStego, "media-stego", "",
		"Path to file to hide inside media via steganography (appended to EOF)")
	p.fs.BoolVar(&opts.MediaScrub, "media-scrub", false,
		"Scrub all metadata from media files (remove GPS, EXIF)")
	p.fs.BoolVar(&opts.MediaRecursivePolyglot, "media-recursive-polyglot", false,
		"If a polyglot APK/DEX is found inside a media file, feed it back into the main analyzer")

	// Feedback
	p.fs.StringVar(&opts.MarkRelevant, "mark-relevant", "",
		"Mark finding as relevant (path or keyword)")
	p.fs.StringVar(&opts.MarkNoise, "mark-noise", "",
		"Mark finding as noise (path or keyword)")
	p.fs.BoolVar(&opts.ShowFeedback, "show-feedback", false,
		"Show all saved user feedback and export to file")
	p.fs.StringVar(&opts.MLApply, "ml-apply", "",
		"Apply ML suggestions by numbers (1,3,5 or 1-10 or all)")

	// Pattern Effectiveness Tracking
	p.fs.BoolVar(&opts.PatternStats, "pattern-stats", false,
		"Display pattern effectiveness statistics")
	p.fs.StringVar(&opts.ExportPatternStats, "export-pattern-stats", "",
		"Export pattern effectiveness data to JSON file")
	p.fs.StringVar(&opts.FeedbackFile, "feedback-file", "",
		"Import feedback from JSON file to adjust pattern weights")

	// Actions
	p.fs.BoolVar(&opts.Version, "version", false, "Show version")
	p.fs.BoolVar(&opts.ToolsInfo, "tools-info", false, "Show which external tools (java for APK signing, aapt2) are available: bundled, cached or system")
	p.fs.BoolVar(&opts.Version, "v", false, "Version (shorthand)")
	p.fs.BoolVar(&opts.Help, "help", false, "Show help")
	p.fs.BoolVar(&opts.LaunchDebugger, "debugger", false, "Launch interactive machine-code debugger (pass binary path as target)")
	p.fs.StringVar(&opts.DebugEntry, "debug-entry", "", "Override entry point for debugger (hex or decimal)")
	p.fs.BoolVar(&opts.Help, "h", false, "Help (shorthand)")
	p.fs.BoolVar(&opts.ListProfiles, "list-profiles", false, "List available profiles")
	p.fs.StringVar(&opts.Completion, "completion", "", "Generate shell completion (bash|zsh|fish)")
	p.fs.StringVar(&opts.ValidateConfig, "validate-config", "", "Validate config file")

	// Cache management
	p.fs.BoolVar(&opts.CacheClear, "cache-clear", false, "Clear all cache")
	p.fs.BoolVar(&opts.CacheStats, "cache-stats", false, "Show cache statistics")
	p.fs.BoolVar(&opts.CachePrune, "cache-prune", false, "Prune old cache files")
	p.fs.IntVar(&opts.CachePruneDays, "cache-prune-days", 7, "Prune files older than N days (default: 7)")

	// Profiling
	p.fs.StringVar(&opts.PprofAddr, "pprof", "", "Enable pprof HTTP server (default: localhost:6060)")
	p.fs.StringVar(&opts.CPUProfile, "cpu-profile", "", "Write CPU profile to file")
	p.fs.StringVar(&opts.MemProfile, "mem-profile", "", "Write heap profile to file")

	// Deobfuscation
	p.fs.IntVar(&opts.DeobfIterations, "deobf-iterations", 0, "Max iterations for deobfuscation loop (0=use default)")
	p.fs.IntVar(&opts.DeobfMinConfidence, "deobf-min-confidence", 0, "Min confidence threshold (0-100, 0=use default)")
	p.fs.BoolVar(&opts.EnableDeobfCP, "enable-deobf-cp", true, "Enable Constant Propagation")
	p.fs.BoolVar(&opts.EnableDeobfDCE, "enable-deobf-dce", true, "Enable Dead Code Elimination")
	p.fs.BoolVar(&opts.EnableDeobfOPR, "enable-deobf-opr", true, "Enable Opaque Predicate Removal")
	p.fs.BoolVar(&opts.EnableDeobfPS, "enable-deobf-ps", true, "Enable Pattern Simplification")
	p.fs.BoolVar(&opts.EnableDeobfVR, "enable-deobf-vr", true, "Enable Variable Name Recovery")
	p.fs.BoolVar(&opts.EnableDeobfMR, "enable-deobf-mr", true, "Enable Method Name Recovery")
	p.fs.BoolVar(&opts.EnableNameQuality, "enable-name-quality", true, "Enable Name Quality Analysis")

	// ══════════════════════════════════════════════════════════════════════════
	// EXPERIMENTAL SUBSYSTEM (AEG, Mach-O, BinSim, Reachability)
	// ══════════════════════════════════════════════════════════════════════════
	p.fs.BoolVar(&opts.AEG, "aeg", false,
		"[experimental] Run Automated Exploit Generation (PoC scaffolds)")
	p.fs.BoolVar(&opts.MLEx, "ml-ex", false,
		"[experimental] Enable experimental modules (Mach-O / BinSim / Reach / AEG)")
	p.fs.StringVar(&opts.MLExApply, "ml-ex-apply", "",
		"[experimental] Select modules: 1-4 | macho,binsim | alice | all")
	p.fs.BoolVar(&opts.MLExList, "ml-ex-list", false,
		"[experimental] List available experimental modules and exit")
	p.fs.StringVar(&opts.MLExOutput, "ml-ex-output", "",
		"[experimental] Override output directory for experimental artifacts")
	p.fs.IntVar(&opts.MLExTimeout, "ml-ex-timeout", 120,
		"[experimental] Per-module timeout in seconds (0 = no cap)")
	p.fs.BoolVar(&opts.MLExParallel, "ml-ex-parallel", false,
		"[experimental] Run experimental modules concurrently")
	p.fs.BoolVar(&opts.MLExJSON, "ml-ex-json", true,
		"[experimental] Write experimental_report.json alongside other reports")

	// Suppress default usage
	p.fs.Usage = func() { p.printUsage() }

	// Pre-scan args for profile-related flags
	noProfile := commandLineBool(callerArgs, p.fs, "admin")
	var profileName string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-no-profile" || arg == "--no-profile" {
			noProfile = true
		} else if strings.HasPrefix(arg, "-profile=") || strings.HasPrefix(arg, "--profile=") {
			profileName = strings.SplitN(arg, "=", 2)[1]
		} else if strings.HasPrefix(arg, "-p=") {
			profileName = strings.SplitN(arg, "=", 2)[1]
		} else if arg == "-profile" || arg == "--profile" || arg == "-p" {
			if i+1 < len(args) {
				profileName = args[i+1]
				i++
			}
		}
	}

	var profilePath string
	var isBuiltIn bool

	builtInProfiles := map[string]bool{
		"quick":    true,
		"balanced": true,
		"deep":     true,
		"paranoid": true,
	}
	if profileName != "" {
		isBuiltIn = builtInProfiles[strings.ToLower(profileName)]
	}

	if noProfile {
		// Do not load any profile file
	} else if profileName == "" {
		// Default mode: try to load "analyzer.flags.txt" or "analyzer.flags.balanced.txt"
		if fsExists("analyzer.flags.txt") {
			profilePath = "analyzer.flags.txt"
		} else if fsExists("analyzer.flags.balanced.txt") {
			profilePath = "analyzer.flags.balanced.txt"
		}
		isBuiltIn = true
	} else {
		// Profile explicitly specified

		path1 := fmt.Sprintf("analyzer.flags.%s.txt", profileName)
		if fsExists(path1) {
			profilePath = path1
		} else if strings.ToLower(profileName) == "balanced" && fsExists("analyzer.flags.txt") {
			profilePath = "analyzer.flags.txt"
		} else if fsExists(profileName) {
			profilePath = profileName
		}
	}

	if profileName != "" && profilePath == "" && !isBuiltIn {
		return nil, fmt.Errorf("profile configuration file not found for custom profile %q (tried %s and analyzer.flags.%s.txt)", profileName, profileName, profileName)
	}

	if profilePath != "" {
		content, err := fsReadFile(profilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read profile file %q: %w", profilePath, err)
		}
		profileArgs, err := parseFlagsFile(content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse profile file %q: %w", profilePath, err)
		}
		// Prepend profile args so CLI args take precedence
		args = append(profileArgs, args...)
	}

	// If the profileName is a custom profile, strip the custom profile flags from args
	// so that flag parser doesn't set opts.Profile to the custom name (which would fail validation).
	if profileName != "" && !isBuiltIn {
		var filteredArgs []string
		for i := 0; i < len(args); i++ {
			arg := args[i]
			if arg == "-profile" || arg == "--profile" || arg == "-p" {
				if i+1 < len(args) && args[i+1] == profileName {
					i++ // skip value
					continue
				}
			} else if arg == fmt.Sprintf("-profile=%s", profileName) ||
				arg == fmt.Sprintf("--profile=%s", profileName) ||
				arg == fmt.Sprintf("-p=%s", profileName) {
				continue
			}
			filteredArgs = append(filteredArgs, arg)
		}
		args = filteredArgs
	}

	// ── Normalize & parse ────────────────────────────────────────────────────
	normalized := normalizeArgs(args, p.fs)

	if err := p.fs.Parse(normalized); err != nil {
		return nil, err
	}

	if opts.TUISection != "" {
		valid := false
		for _, section := range tuiSections {
			if opts.TUISection == section {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("invalid -tui-section %q (valid: %s)", opts.TUISection, strings.Join(tuiSections, ", "))
		}
	}
	if tuiOpt || opts.TUISection != "" || opts.TUISearch != "" {
		opts.NoTUI = false
	}
	// Explicitly asking for CLI mode wins over -tui, so an automated caller can
	// always force non-interactive output.
	if noTUIOpt {
		opts.NoTUI = true
	}

	// Track explicit deobf flags
	p.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "deobf-iterations":
			opts.DeobfIterationsExplicit = true
		case "deobf-min-confidence":
			opts.DeobfMinConfidenceExplicit = true
		}
	})

	// Positional subcommand check (e.g., `analyzer edit <target>` or `analyzer decode <target>`)
	if len(args) > 0 {
		cmd := strings.ToLower(args[0])
		if cmd == "edit" || cmd == "apk-editor" {
			opts.OpenAPKEditor = true
			if len(args) > 1 && !strings.HasPrefix(args[1], "-") && opts.Target == "" {
				opts.Target = args[1]
			}
		} else if cmd == "decode" {
			opts.Decode = true
			if len(args) > 1 && !strings.HasPrefix(args[1], "-") && opts.Target == "" {
				opts.Target = args[1]
			}
		}
	}

	// Positional target(s)
	if opts.VersionDiff && p.fs.NArg() >= 2 {
		if opts.DiffOld == "" {
			opts.DiffOld = p.fs.Arg(0)
		}
		if opts.DiffNew == "" {
			opts.DiffNew = p.fs.Arg(1)
		}
	} else if opts.Target == "" && p.fs.NArg() > 0 {
		arg0 := p.fs.Arg(0)
		if arg0 != "edit" && arg0 != "apk-editor" && arg0 != "decode" {
			opts.Target = arg0
		} else if p.fs.NArg() > 1 {
			opts.Target = p.fs.Arg(1)
		}
	}

	// Profile
	if profileStr != "" {
		opts.Profile = AnalysisProfile(strings.ToLower(profileStr))
	}
	if opts.Report != "" {
		opts.Report = strings.ToLower(opts.Report)
	}

	// Validate -ml-patch-min-tier: accept the canonical English tier names
	// (elite/normal/trash) or legacy Cyrillic aliases, case-insensitively,
	// and reject anything else instead of silently ignoring an unrecognized
	// value.
	if canonical, ok := ml.ResolveTier(opts.MLPatchMinTier); ok {
		opts.MLPatchMinTier = string(canonical)
	} else {
		return nil, fmt.Errorf("invalid -ml-patch-min-tier %q: expected one of elite, normal, trash", opts.MLPatchMinTier)
	}

	// Parse export formats (comma-separated)
	if exportFormats != "" {
		formats := strings.Split(exportFormats, ",")
		opts.MLPatchExportFormat = make([]string, 0, len(formats))
		for _, f := range formats {
			trimmed := strings.TrimSpace(strings.ToLower(f))
			if trimmed != "" {
				opts.MLPatchExportFormat = append(opts.MLPatchExportFormat, trimmed)
			}
		}
	}

	// ── Detect explicit flags ────────────────────────────────────────────────
	p.fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "callgraph":
			opts.CallGraphExplicit = true
		case "correlations":
			opts.CorrelationsExplicit = true
		case "enable-data-flow":
			opts.DataFlowExplicit = true
		case "crackpoint-analysis":
			opts.CrackPointExplicit = true
		case "anomaly-detection":
			opts.AnomalyExplicit = true
		case "deep-scan":
			opts.DeepScanExplicit = true
		case "max-file-size":
			opts.MaxFileSizeExplicit = true
		case "max-resource-size":
			opts.MaxResourceSizeExplicit = true
		case "ml-patch-apply":
			opts.MLPatchApplyExplicit = true
		case "timeout":
			opts.TimeoutExplicit = true
		}
	})

	if err := validateAdminFlags(opts, p.fs, callerArgs); err != nil {
		return nil, err
	}
	if err := opts.validateDecisionAIOptions(); err != nil {
		return nil, err
	}
	if err := opts.validateStdinOptions(); err != nil {
		return nil, err
	}
	return opts, nil
}
