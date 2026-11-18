package main

// ═══════════════════════════════════════════════════════════════════════════════
// CLI OPTIONS
// ═══════════════════════════════════════════════════════════════════════════════

type CLIOptions struct {
	// Target
	Target string
	Output string

	BundleBudget  string // compact|large, always bounded
	BundleExport  bool   // Persist JS deobfuscation / Hermes disassembly artifacts
	BundlePatches bool   // Read-only JS patch-candidate reports
	SaveDecoded   bool   // Decode original APK/DEX beside static reports

	Minecraft bool // Dedicated read-only Minecraft package analysis

	// Optional local DecisionAI service; no weights are bundled with analyzer.
	DecisionAIURL         string
	DecisionAIInput       string
	DecisionAIMaxFindings int
	DecisionAIBudget      int // total seconds, including all finding requests
	DecisionAIImages      bool
	DecisionAIMaxImages   int
	DecisionAIImageBudget int // separate total seconds for report preview checks

	// Sandbox / detonation
	Sandbox                   bool
	SandboxRemoteConfig       string // Host-side pinned TLS profile for a Windows guest
	SandboxAllowHostExecution bool   // Explicit trusted-fixture override; never enabled by Web UI
	SandboxArgs               string
	SandboxDuration           int // seconds
	SandboxMemoryMB           int
	SandboxAllowNet           bool
	SandboxProfile            string // basic|trace|forensic|paranoid
	AndroidSandbox            bool   // Enable Android-native sandbox mode via ADB
	SandboxPrivServer         string // Private server or MITM proxy to connect/redirect sandbox traffic to (e.g. 127.0.0.1:9339)
	SandboxAVD                string // Specific AVD name to launch
	SandboxAutoAVD            bool   // Automatically launch the first available AVD if no device is connected
	SandboxDevice             string // Exact adb serial; never falls back to another device
	SandboxUninstall          bool   // Uninstall the app from the device after the sandbox run completes
	SandboxCapture            bool   // Capture raw network traffic via tcpdump on device
	SandboxMITM               bool   // Run mitmproxy on host for HTTPS interception
	SandboxFrida              bool   // Attach Frida to the target app during detonation
	SandboxFridaSpawn         bool   // Respawn the app under Frida to hook before onCreate
	SandboxFridaScript        string // Custom Frida instrumentation script

	// Guest environment tuning (honored by the Android emulator; gated/best-effort on the Windows host)
	SandboxCPUCores    int    // Cap guest to N logical CPU cores (0 = engine default)
	SandboxLocale      string // BCP-47 guest locale, e.g. en-US (Android only)
	SandboxTimezone    string // IANA timezone, e.g. Europe/Moscow (Android only)
	SandboxResolution  string // Screen resolution WxH or shorthand (720p|1080p|1440p) (Android only)
	SandboxOrientation string // portrait|landscape (Android only)

	// Windows-native sandbox enhancements
	WinSandbox          bool    // Enable Windows-native sandbox mode
	SandboxVSSRevert    bool    // Automatic VSS rollback after execution
	SandboxTimeScale    float64 // Time acceleration factor (1.0 = real-time, 10.0 = 10x faster)
	SandboxOutput       string  // Artifact output directory for sandbox session
	EnableKernelMonitor bool    // Enable kernel-level filesystem/registry monitoring
	EnableVSS           bool    // Enable Volume Shadow Copy snapshots
	EnableWFP           bool    // Enable Windows Filtering Platform network capture
	EnableAPITracing    bool    // Enable Windows API call tracing
	EnableTimeManip     bool    // Enable time manipulation (sleep-skipping)
	SandboxStream       bool    // Stream real-time sandbox telemetry in JSON to stdout

	// Performance
	Workers  int
	Timeout  int // секунды
	MaxFiles int

	// File size limits (MB). 0 = использовать дефолт профиля.
	MaxFileSizeMB     int
	MaxResourceSizeMB int

	// Analysis
	Profile            AnalysisProfile
	EnableCallGraph    bool
	EnableMedia        bool
	ExtractPS1         bool
	EnableCorrelations bool
	EnableDeepScan     bool

	// Explicit flags — true если пользователь ЯВНО указал флаг в CLI.
	CallGraphExplicit       bool
	CorrelationsExplicit    bool
	DataFlowExplicit        bool
	CrackPointExplicit      bool
	AnomalyExplicit         bool
	DeepScanExplicit        bool
	MaxFileSizeExplicit     bool
	MaxResourceSizeExplicit bool
	MLPatchApplyExplicit    bool
	TimeoutExplicit         bool

	// Output control
	DebugVerbose bool
	Quiet        bool
	NoColor      bool
	NoTUI        bool
	TUISection   string // initial configuration section
	TUISearch    string // initial flag search query
	JSON         bool
	NoHTML       bool
	NoJSON       bool
	JSONCompact  bool
	SARIF        bool

	// CI exit codes: 0 clean, 1 findings >= FailOn, 2 findings one level
	// below, 3 error, 4 incomplete analysis. Off by default so existing
	// scripts keep seeing exit status 0 after a successful scan.
	ExitCodes bool
	FailOn    string

	// KnownSet — путь к бинарному набору knownset-build («известно хорошее /
	// известно плохое»). Только добавляет находки (bad — громкий алерт,
	// good — информационная заметка), анализ никогда не пропускается.
	KnownSet string

	// Profile files loading support
	NoProfile   bool
	ProfileFile string

	// Report
	Report      string
	CleanOutput bool

	// Post-analysis deterministic evidence explanation.
	ExplainResult string
	ExplainNode   string
	ExplainFile   string
	ExplainFormat string

	// False-positive / triage tuning
	FPStrict          bool
	FPShowSuppressed  bool
	FPMinScore        float64
	FPSuppressedLimit int

	// APK/DEX support
	KeepTemp bool
	DEXOnly  bool

	// ARTIFACTS — opt-in section: extracted images / 3D / .so / other
	EnableArtifacts   bool
	AllowExport       bool
	ArtifactsMaxMB    int
	ArtifactsBudgetMB int
	NoImageBlur       bool

	// MACHINE CODE ANALYSIS — opt-in mode for raw PE/ELF/.so binary targets.
	// When set, skips APK/DEX/Smali pipeline and dispatches directly to the
	// Rust scan-native library backend for native binary forensics. The unified
	// analyzer calls the FFI directly; it does not spawn the omnisec CLI.
	MachineCode     bool
	MCRevealSecrets bool // show full unmasked values for embedded secrets (default: masked)

	// BINZAP BYTECODE ANALYSIS — in-process Go backend for Smali / ASM / APK.
	Binzap       bool
	BinzapActive bool // add static taint/dataflow analysis; never sends network traffic

	// TOP-5 INSIGHT MODULES — opt-in MVP sidecar analyzers.
	EnableTop5          bool
	EnableJNI           bool
	EnablePrivacy       bool
	EnableGraphExplorer bool
	VersionDiff         bool
	DiffOld             string
	DiffNew             string
	Firmware            bool

	// MOBSF-DERIVED MODULES — opt-in sidecar analyzers inspired by MobSF.
	EnableMobSFAll      bool // turn on the entire MobSF-derived bundle
	EnableSASTRules     bool // run MobSF-derived regex SAST rules
	EnableTrackers      bool // run Exodus-style tracker detection
	EnableNSCAudit      bool // audit network_security_config.xml
	EnableManifestAudit bool // exported components / manifest hardening audit
	EnableAPKID         bool // packer / obfuscator / anti-analysis fingerprinting

	// MEDIUM-PRIORITY MODULES
	EnableMediumAll      bool // turn on all medium-priority analyzers
	EnablePlayStore      bool // Play Store metadata lookup
	EnableSBOM           bool // SBOM extraction from .version files
	EnablePermMap        bool // permission-to-code mapping
	EnableCertAudit      bool // certificate deep analysis
	EnableMalwareDomains bool // malware domain / URL check
	EnableNIAP           bool // NIAP compliance rules

	// Content-Cache & Data-Flow
	EnableContentCache    bool
	ContentCacheDir       string
	ContentCacheMaxDiskMB int64
	EnableDataFlow        bool
	DataFlowMaxMethods    int
	DataFlowMaxFindings   int

	// MAKE-SERVER — authorized-lab Elixir/OTP private server generator.
	MakeServer       bool
	MakeServerGame   string
	MakeServerModule string
	MakeServerOutput string
	MakeServerPort   int
	MakeServerAdmin  int

	// APK Rebuilding / Decoding (apktool-style)
	Rebuild            bool
	Build              bool // alias for Rebuild (apktool b)
	Decode             bool // decode APK to directory without analysis (apktool d)
	NoSign             bool
	NoAlign            bool
	NoResources        bool // skip resource decoding
	NoSmali            bool // skip smali generation
	NoSmaliHeaders     bool // skip # Disassembled from DEX comment headers in smali
	SmaliHeaders       bool // include source/hash comments for this decode invocation
	Standalone         bool // forbid Java/aapt2/apksigner/zipalign processes; native Go only
	AllowExternalTools bool // explicitly opt build into compatibility tool discovery/execution
	JavaView           bool // emit per-class .java pseudocode next to smali
	FrameworkDir       string
	CopyOriginal       bool   // preserve original META-INF
	Aapt2Path          string // path to aapt2 binary
	UseSmali           bool   // enable smali→dex assembly (default: auto-detect)
	UseAapt2           bool   // enable aapt2 resource compile+link (default: auto-detect)
	// v1-v7 apkloader upgrades
	DexBackend        string // decode backend: auto|native (default: auto)
	ClassCache        bool   // cache native DEX→Smali per class in .mega-analyzer-cache.db (default: true)
	SmaliAPI          int    // native assembler Android API level (0 = auto-match tree dex)
	SmaliJobs         int    // native assembler DEX workers (0 = auto)
	SmaliIncremental  bool   // incremental smali→dex via .mega-analyzer-build-cache.json (default: true)
	CompressionMode   string // rebuild zip mode: fast|balanced|best (default: fast)
	SpoolThresholdMB  int    // spool entries larger than N MB to temp files (0 = default 128MB)
	PreserveSignature bool   // experimental: keep original META-INF/signing blocks, skip re-sign
	KsPath            string // keystore for rebuild signing (apksigner); empty = generated debug key
	KsAlias           string // key alias inside --ks (empty = keystore default)

	// OBB / DATA / CACHE SCANNER
	OBBScan       bool   // enable OBB expansion file deep scan
	OBBDataDir    string // path to Android/data/<pkg>/ or OBB directory
	OBBMaxSizeMB  int    // max OBB file size to scan (default: 100)
	OBBOutputJSON bool   // write OBB_SCAN_REPORT.json

	// CACHE ANALYZER (defensive security scan)
	CacheScan    bool   // scan Android/data/<pkg>/cache for security issues
	CacheDataDir string // override cache directory path

	// ML-APLI-CACHE SCRIPT (predictive exploitation analysis)
	MLCacheScript bool // run ML-Apli-Cache predictive script on cache

	// WEB SCANNER (vulnscan integration)
	WebScan               bool   // enable active web vulnerability scan
	WebScanTarget         string // target URL for web vulnerability scan
	WebScanMode           string // status|passive|active
	WebScanIOwnThisTarget bool
	WebScanLabMode        bool
	WebScanAllowlist      string
	WebScanFSMConfig      string
	HTMLBody              string // path to HTML file for passive scan (--html-body)
	CurlCmd               string // curl command string for import (--curl)
	RawRequest            string // path to raw HTTP request file (--raw-request)
	RawScheme             string // scheme for raw request (--raw-scheme)

	// ═══════════════════════════════════════════════════════════════════════════
	// PRIVATE SERVER TOOLKIT — новые флаги
	// ═══════════════════════════════════════════════════════════════════════════
	Intercept               bool
	PatchClient             bool
	Servgen                 bool
	Fuzz                    bool
	InterceptPort           int
	InterceptUpstream       string
	InterceptRecord         string
	InterceptStopOnEOF      bool // managed sessions stop and flush when stdin closes
	InterceptInteractive    bool
	InterceptFrame          string
	NetJSONEvents           bool   // --net-json-events  emit @@NETEVENT@@ JSON lines for DevMega
	NetRemoteEdit           bool   // --net-remote-edit   drive InterceptEdit from a remote client over stdio
	NetFilter               string // --net-filter  display filter applied to intercepted traffic
	NetFlows                bool   // --net-flows   reassemble packets into classified bidirectional flows
	FuzzCapture             string
	FuzzTarget              string
	FuzzOut                 string
	PatchClientAPK          string
	PatchClientServer       string
	PatchClientBypass       bool
	PatchClientBypassTarget string
	PatchClientSSLLog       string
	ServgenProtocol         string
	ServgenFromCapture      string

	// Lab DNS
	LabDNS        bool
	DNSAddr       string
	DNSUpstream   string
	DNSSinkholeIP string

	// ═══════════════════════════════════════════════════════════════════════════
	// ML ASSISTANT — новые флаги
	// ═══════════════════════════════════════════════════════════════════════════
	MLSuggest        bool    // запустить ML suggester
	MLHistory        bool    // показать историю анализов
	MLStats          bool    // показать агрегированную статистику
	MLTrain          bool    // обучить keyword-relevance модель из history.json
	MLTrainEnsemble  bool    // обучить ensemble risk модель из history.json
	MLTrainSoft      bool    // (reserved) включить мягкие метки при обучении
	MLExport         string  // экспортировать suggestions в файл
	MLConfidence     float64 // минимальный confidence threshold
	MLMaxSuggestions int     // максимум suggestions для показа
	MLPatch          bool    // запустить ML patch predictor (smali патчи)
	// MLPatchDirectSmali запускает предиктор напрямую по декомпилированному Smali.
	// Он предназначен для IDE: исключает повторный общий проход по исходным DEX,
	// но не сокращает набор Smali-файлов, паттернов или библиотек предиктора.
	MLPatchDirectSmali bool
	MLPatchFix         bool // добавить патчи и diff в отчёт

	MLPatchIncludeLibs bool    // анализировать библиотечный код
	MLPatchMinScore    float64 // минимальный score для включения (0-100)

	// ML Patch Pattern Enhancement — новые флаги
	MLPatchMinTier           string // minimum pattern tier ("elite", "normal", "trash")
	MLPatchEnableDeprecated  bool   // включить deprecated паттерны
	MLPatchEnableSDK         bool   // включить SDK-specific detection
	MLPatchEnableCombination bool   // включить pattern combination detection

	// ═══════════════════════════════════════════════════════════════════════════
	// GAME MODE — новые флаги для геймификации
	// ═══════════════════════════════════════════════════════════════════════════
	GameMode             bool    // включить game mode с threat scoring и XP
	GameModeOutput       string  // формат вывода game mode (terminal, markdown, json)
	GameModePersist      bool    // сохранять XP и rank данные
	DecoyDetection       bool    // включить decoy detection
	InterestingScore     bool    // включить interesting scoring
	MLPatchConfidenceMin float64 // минимальный confidence threshold (0.0-1.0)
	MLPatchPrioritySort  bool    // сортировать по priority, затем по score
	MLPatchCrossLanguage bool    // включить cross-language detection

	// ML Patch Mode Selection
	MLPatchMode string
	// ML Patch Export and Display Options
	MLPatchExplain          bool     // show detailed explanations in terminal output
	MLPatchExportFormat     []string // export formats: json, md, csv (multiple allowed)
	MLPatchConfidenceThresh float64  // confidence threshold for filtering results
	MLPatchExportOutput     string   // output file path for exports
	MLPatchApply            string   // dry-run|write
	MLPatchBackend          string   // smali|dex (default: smali)
	MLPatchOutput           string   // output directory for patch artifacts
	MLPatchFeedbackImport   string   // import pattern feedback metrics JSON
	MLPatchFeedbackExport   string   // export pattern feedback metrics JSON

	// Full-session logging (--save_log): mirror the entire console session to a file.
	SaveLog       bool   // --save_log/--save-log: tee console output to a file
	SaveLogFormat string // --format/--log-format: txt (default) | ansi | md
	SaveLogOutput string // --log-output/--save-log-output: destination file path

	// Crack Point Discovery & Anomaly Detection
	CrackPointAnalysis  bool
	CrackPointThreshold float64
	AnomalyDetection    bool

	// ═══════════════════════════════════════════════════════════════════════════
	// MEDIA ANALYSIS & PATCHING (Phase 6)
	// ═══════════════════════════════════════════════════════════════════════════
	MediaScan              bool   // Включить анализ медиа файлов (stego, GPS, payloads)
	MediaPayload           string // Внедрить этот payload в метаданные медиа файла
	MediaStego             string // Путь к файлу для внедрения через стеганографию (в EOF)
	MediaScrub             bool   // Удалить все метаданные из медиа файлов (GPS, EXIF)
	MediaRecursivePolyglot bool   // Если найден APK/DEX внутри медиа, закинуть его обратно в анализатор

	// Feedback — пометить результат как relevant/noise
	MarkRelevant string // path или keyword
	MarkNoise    string // path или keyword
	ShowFeedback bool   // показать все сохраненные overrides
	MLApply      string // применить ML рекомендации по номерам (1,3,5 или 1-10 или all)

	// Pattern Effectiveness Tracking
	PatternStats       bool   // показать статистику эффективности паттернов
	ExportPatternStats string // экспортировать статистику паттернов в JSON файл
	FeedbackFile       string // импортировать feedback из JSON файла

	// Asset scan (3D / textures / encrypted media inside a file, dir or APK)
	AssetScan     string // --assets <file|dir|apk>  find .glb and friends and decode them
	AssetsOut     string // --assets-out <dir>  where PNG previews are written
	AssetsJSON    bool   // --assets-json  emit the machine-readable report on stdout
	AssetsDeep    bool   // --assets-deep  widen the recovery search
	AssetsAll     bool   // --assets-all  report every file walked, not just assets
	AssetsOpen    bool   // --assets-open  launch the Zig APK editor on the previews
	AssetsMaxMB   int    // --assets-max-mb <N>  per-entry size cap (default 64)
	AssetsMaxDim  int    // --assets-max-dim <N>  longest preview side (default 512)
	AssetsMaxPrev int    // --assets-max-previews <N>  PNG cap (default 256)

	// Suppression switches for the asset scan. An asset scan is exploratory:
	// usually one of these layers is the interesting one and the rest is
	// noise that costs time and disk.
	AssetsNoTextures bool // --assets-no-textures  skip embedded model textures
	AssetsTextures   int  // --assets-textures <N>  per-model texture cap (default 4)
	AssetsNoBytemap  bool // --assets-no-bytemap  no byte-map fallback images
	AssetsNoZstd     bool // --assets-no-zstd  do not inflate zstd payloads
	AssetsNoASTC     bool // --assets-no-astc  do not decode ASTC block textures

	// Web UI
	Admin           bool   // explicit OS elevation, web mode only
	adminRelaunched bool   // internal marker; grants no privileges
	adminCWD        string // internal absolute restart directory
	Web             bool   // --web  launch local web UI for file upload + analysis
	WebPort         int    // --web-port <port> (default 7474)
	WebToken        string // --web-ui-token <token>  fixed pairing token (default: random per run)
	APIServer       bool   // --api launch the REST API from this same executable
	APIPort         int    // --api-port <port> (default 5000)

	// Actions
	Version        bool
	ToolsInfo      bool
	Help           bool
	ListProfiles   bool
	Completion     string // --completion <shell> for bash/zsh/fish
	LaunchDebugger bool   // --debugger <binary> to launch machine-code debugger
	DebugEntry     string // --debug-entry <address> override entry point
	OpenAPKEditor  bool   // --edit / --apk-editor launch native Zig APK Patch Editor GUI

	// Config validation
	ValidateConfig string // --validate-config <path> to validate config file

	// Cache management
	CacheClear     bool // --cache-clear to clear cache
	CacheStats     bool // --cache-stats to show cache statistics
	CachePrune     bool // --cache-prune to prune old cache
	CachePruneDays int  // --cache-prune-days <N> for prune (default: 7)

	// Profiling
	PprofAddr  string // --pprof <addr> for pprof HTTP server
	CPUProfile string // --cpu-profile <file> for CPU profiling
	MemProfile string // --mem-profile <file> for heap profiling

	// Deobfuscation (🆕 v9.0.0)
	DeobfIterations    int
	DeobfMinConfidence int
	EnableDeobfCP      bool
	EnableDeobfDCE     bool
	EnableDeobfOPR     bool
	EnableDeobfPS      bool
	EnableDeobfVR      bool
	EnableDeobfMR      bool
	EnableNameQuality  bool

	// Explicit deobfuscation flags
	DeobfIterationsExplicit    bool
	DeobfMinConfidenceExplicit bool

	// JS / React Native Deobfuscation
	JSDeobfuscate    bool
	JSDeobfuscateOut string

	// ═══════════════════════════════════════════════════════════════════════════
	// JS BUNDLE PATCHER — smart React Native / Hermes bundle patcher
	// ═══════════════════════════════════════════════════════════════════════════
	JSPatch           bool   // enable JS bundle patcher
	JSPatchApply      string // "dry-run" (default) | "write"
	JSPatchServerIP   string // new server address for URL replacement (e.g. 127.0.0.1:9339)
	JSPatchBackup     bool   // create .orig backup before writing
	JSPatchCategories string // comma-separated category whitelist (empty = all)
	JSPatchMinConf    int    // minimum confidence threshold 0-100 (default: 40)
	JSPatchOutput     string // output dir for JSPATCH.md / jspatch.json

	// ═══════════════════════════════════════════════════════════════════════════
	// EXPERIMENTAL MODULES — AEG, Mach-O/iOS, Binary Similarity, Reachability
	// ═══════════════════════════════════════════════════════════════════════════
	AEG          bool   // shorthand: enable Automated Exploit Generation only
	MLEx         bool   // master switch: enable experimental subsystem
	MLExApply    string // selector: numeric (1-4), names (macho,binsim), presets (alice|all|hunter|mobile|offense)
	MLExList     bool   // list available experimental modules and exit
	MLExOutput   string // override output dir for experimental artifacts
	MLExTimeout  int    // per-module timeout in seconds (0 = no cap)
	MLExParallel bool   // run experimental modules in parallel
	MLExJSON     bool   // dump experimental result as JSON sidecar

	// GNN vulnerability classification (requires omnisec_ml_gnn build tag + Rust cdylib)
	GNNModelPath string // path to GNN weights JSON (empty = auto-discover ~/.analyzer/models/gnn_weights.json)
	SkipGNN      bool   // skip optional GNN stage even when auto-discovered weights exist

	// ProGuard / R8 deobfuscation mapping
	ProGuardMap string // path to ProGuard/R8 mapping.txt for name recovery
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYSIS PROFILE
// ═══════════════════════════════════════════════════════════════════════════════

type AnalysisProfile string

const (
	ProfileQuick    AnalysisProfile = "quick"
	ProfileBalanced AnalysisProfile = "balanced"
	ProfileDeep     AnalysisProfile = "deep"
	ProfileParanoid AnalysisProfile = "paranoid"
)

func (p AnalysisProfile) IsValid() bool {
	switch p {
	case ProfileQuick, ProfileBalanced, ProfileDeep, ProfileParanoid:
		return true
	}
	return false
}

func (p AnalysisProfile) Description() string {
	switch p {
	case ProfileQuick:
		return "Fast scan, critical patterns only (~30s)"
	case ProfileBalanced:
		return "Balanced speed and depth (~2min)"
	case ProfileDeep:
		return "Deep analysis with call graph (~5min)"
	case ProfileParanoid:
		return "Maximum depth, all patterns (~10min+)"
	default:
		return "Unknown profile"
	}
}
