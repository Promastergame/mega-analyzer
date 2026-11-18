package pipeline

import (
	"math"
	"strings"
	"sync"

	"mega-analyzer/pkg/ml/fusion"
)

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT SIGNAL TYPES AND WEIGHTS
// ═══════════════════════════════════════════════════════════════════════════════

// SignalType represents a specific type of threat indicator
type SignalType int

const (
	SignalNone SignalType = iota

	// Dynamic Code Loading
	SignalDexClassLoader
	SignalInMemoryDexClassLoader
	SignalReflectionForName
	SignalReflectionInvoke
	SignalReflectionLoadClass
	SignalReflectionDefineClass
	SignalDexFileLoad

	// Network
	SignalNetworkHTTP
	SignalNetworkHTTPS
	SignalNetworkURLConnection
	SignalNetworkOkHttp
	SignalNetworkVolley
	SignalNetworkRetrofit

	// C2/Exfiltration
	SignalDiscordWebhook
	SignalPastebin
	SignalGitHubRaw
	SignalSuspiciousTLD
	SignalHardcodedIPv4

	// File Operations
	SignalFileWrite
	SignalFileOutputStream
	SignalDexSuffix
	SignalExternalStorage

	// Obfuscation
	SignalBase64Decode
	SignalBase64LongString
	SignalXOR
	SignalAES
	SignalDES
	SignalRC4

	// WebView Abuse
	SignalWebViewLoadURL
	SignalWebViewLoadData
	SignalWebViewJSInterface
	SignalWebViewJSEnabled
	SignalWebViewOverrideURL

	// Accessibility Abuse
	SignalAccessibilityPermission
	SignalAccessibilityService
	SignalAccessibilityEvent
	SignalAccessibilityRootWindow
	SignalAccessibilityGlobalAction
	SignalAccessibilityNodeInfo

	// Stealer Permissions
	SignalPermissionSMS
	SignalPermissionContacts
	SignalPermissionCallLog
	SignalPermissionCamera
	SignalPermissionMicrophone
	SignalPermissionLocation
	SignalPermissionOverlay
	SignalPermissionInstallPackages
	SignalPermissionQueryPackages
	SignalPermissionUsageStats

	// Anti-Analysis
	SignalFrida
	SignalXposed
	SignalSubstrate
	SignalPtrace
	SignalDlopen
	SignalDebuggerCheck
	SignalEmulatorCheck
	SignalRootCheck
	SignalGeoFence

	// Native Suspicious
	SignalNativeJNIOnLoad
	SignalNativeDexLoader
	SignalNativeHTTP
	SignalNativeC2

	// Runtime-Load Detection (v11.0)
	SignalSystemLoadLibrary  // System.loadLibrary / System.load
	SignalRegisterNatives    // JNI RegisterNatives binding
	SignalEncryptedAssetDex  // Encrypted DEX/JAR in assets/res
	SignalContentProviderDex // DEX loaded via ContentProvider
	SignalAttachBaseContext  // Application.attachBaseContext hook (packer indicator)
	SignalMultiDexInstall    // MultiDex.install override

	// Meta signals (combinations)
	SignalDexFromNetwork     // DexLoader + Network + .dex
	SignalWebViewRemoteCode  // WebView + JS + Remote
	SignalAccessibilityAbuse // Permission + Service + Actions
	SignalStealerCombo       // Multiple stealer permissions
	SignalRuntimeLoadChain   // System.loadLibrary + RegisterNatives + DexClassLoader
)

// SignalWeight defines the threat weight for each signal
var SignalWeight = map[SignalType]int{
	// Dynamic Code Loading (HIGH RISK)
	SignalDexClassLoader:         8,
	SignalInMemoryDexClassLoader: 8,
	SignalReflectionForName:      0, // стандартная рефлексия → низкий вес
	SignalReflectionInvoke:       0, // стандартная рефлексия → низкий вес
	SignalReflectionLoadClass:    1, // лёгкий сигнал
	SignalReflectionDefineClass:  7,
	SignalDexFileLoad:            8,

	// Network (MEDIUM)
	SignalNetworkHTTP:          2,
	SignalNetworkHTTPS:         1,
	SignalNetworkURLConnection: 2,
	SignalNetworkOkHttp:        1,
	SignalNetworkVolley:        1,
	SignalNetworkRetrofit:      1,

	// C2/Exfiltration (HIGH)
	SignalDiscordWebhook: 8,
	SignalPastebin:       5,
	SignalGitHubRaw:      4,
	SignalSuspiciousTLD:  0, // address vocabulary is not malicious reputation
	SignalHardcodedIPv4:  0,

	// File Operations (MEDIUM)
	SignalFileWrite:        2,
	SignalFileOutputStream: 2,
	SignalDexSuffix:        4,
	SignalExternalStorage:  2,

	// Obfuscation (MEDIUM-HIGH)
	SignalBase64Decode:     3,
	SignalBase64LongString: 4,
	SignalXOR:              3,
	SignalAES:              2,
	SignalDES:              2,
	SignalRC4:              4,

	// WebView Abuse (HIGH)
	SignalWebViewLoadURL:     2,
	SignalWebViewLoadData:    2,
	SignalWebViewJSInterface: 5,
	SignalWebViewJSEnabled:   3,
	SignalWebViewOverrideURL: 3,

	// Accessibility Abuse (CRITICAL)
	SignalAccessibilityPermission:   0,
	SignalAccessibilityService:      1,
	SignalAccessibilityEvent:        0,
	SignalAccessibilityRootWindow:   1,
	SignalAccessibilityGlobalAction: 1,
	SignalAccessibilityNodeInfo:     1,

	// Declarations remain available for capability correlation without scoring
	// them as granted permissions or implemented data-stealing behavior.
	SignalPermissionSMS:             0,
	SignalPermissionContacts:        0,
	SignalPermissionCallLog:         0,
	SignalPermissionCamera:          0,
	SignalPermissionMicrophone:      0,
	SignalPermissionLocation:        0,
	SignalPermissionOverlay:         0,
	SignalPermissionInstallPackages: 0,
	SignalPermissionQueryPackages:   0,
	SignalPermissionUsageStats:      0,

	// Anti-Analysis (HIGH)
	SignalFrida:         8,
	SignalXposed:        7,
	SignalSubstrate:     7,
	SignalPtrace:        6,
	SignalDlopen:        3,
	SignalDebuggerCheck: 0, // debug flags → минимальный вес
	SignalEmulatorCheck: 4,
	SignalRootCheck:     4,
	SignalGeoFence:      2,

	// Native (MEDIUM-HIGH)
	SignalNativeJNIOnLoad: 2,
	SignalNativeDexLoader: 8,
	SignalNativeHTTP:      4,
	SignalNativeC2:        9,

	// Runtime-Load Detection (v11.0)
	SignalSystemLoadLibrary:  5,
	SignalRegisterNatives:    7,
	SignalEncryptedAssetDex:  9,
	SignalContentProviderDex: 7,
	SignalAttachBaseContext:  6,
	SignalMultiDexInstall:    4,

	// Meta signals (CRITICAL - combinations are more suspicious)
	SignalDexFromNetwork:     15,
	SignalWebViewRemoteCode:  12,
	SignalAccessibilityAbuse: 5,
	SignalStealerCombo:       14,
	SignalRuntimeLoadChain:   16,
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILE SIGNALS - Per-file detection results
// ═══════════════════════════════════════════════════════════════════════════════

// FileSignals holds all signals detected in a single file
type FileSignals struct {
	Path    string
	Signals map[SignalType]*SignalHit
	Score   int
}

// SignalHit represents a detected signal instance
type SignalHit struct {
	Type       SignalType
	Line       int
	Context    string // What was matched
	Evidence   string // The actual matched content
	Weight     int
	Correlated bool // Part of a correlation pattern
}

func NewFileSignals(path string) *FileSignals {
	return &FileSignals{
		Path:    path,
		Signals: make(map[SignalType]*SignalHit),
	}
}

func (fs *FileSignals) Add(sig SignalType, line int, context, evidence string) {
	if _, exists := fs.Signals[sig]; !exists {
		weight := adjustedWeight(fs.Path, sig, SignalWeight[sig])
		fs.Signals[sig] = &SignalHit{
			Type:     sig,
			Line:     line,
			Context:  context,
			Evidence: evidence,
			Weight:   weight,
		}
		fs.Score += weight
	}
}

func (fs *FileSignals) Has(sig SignalType) bool {
	_, ok := fs.Signals[sig]
	return ok
}

func (fs *FileSignals) HasAny(sigs ...SignalType) bool {
	for _, s := range sigs {
		if fs.Has(s) {
			return true
		}
	}
	return false
}

func (fs *FileSignals) HasAll(sigs ...SignalType) bool {
	for _, s := range sigs {
		if !fs.Has(s) {
			return false
		}
	}
	return true
}

// adjustedWeight applies context multipliers (ad SDK vs main app)
func adjustedWeight(path string, sig SignalType, base int) int {
	if base == 0 {
		return 0
	}

	// Explicit path overrides for dynamic DEX in ad SDK vs app code
	if isDynamicCodeSignal(sig) {
		lp := strings.ToLower(path)
		if strings.Contains(lp, "com/facebook/ads/") {
			return 2
		}
		if strings.Contains(lp, "app/main/") {
			return 8
		}
	}

	factor := 1.0
	if isDynamicCodeSignal(sig) {
		switch {
		case isAdSdkPath(path):
			factor = 0.3 // LOW risk when inside ad SDK
		case !isLibraryPath(path):
			factor = 1.2 // HIGHER risk in main app
		}
	}

	weighted := int(math.Round(float64(base) * factor))
	if weighted < 0 {
		return 0
	}
	return weighted
}

func isDynamicCodeSignal(sig SignalType) bool {
	return sig == SignalDexClassLoader ||
		sig == SignalInMemoryDexClassLoader ||
		sig == SignalDexFileLoad ||
		sig == SignalReflectionDefineClass ||
		sig == SignalReflectionLoadClass ||
		sig == SignalSystemLoadLibrary ||
		sig == SignalRegisterNatives ||
		sig == SignalEncryptedAssetDex ||
		sig == SignalContentProviderDex ||
		sig == SignalAttachBaseContext
}

func isAdSdkPath(path string) bool {
	p := strings.ToLower(path)
	adVendors := []string{
		"/ads/",
		"/ad/sdk",
		"/openadsdk",
		"/applovin",
		"/bytedance/sdk/openadsdk",
		"/google/android/gms/ads",
		"/facebook/ads",
		"/unityads",
		"/admob",
	}
	for _, v := range adVendors {
		if strings.Contains(p, v) {
			return true
		}
	}
	return false
}

func isLibraryPath(path string) bool {
	p := strings.ToLower(path)
	libraries := []string{
		"/androidx/", "/kotlin/", "/org/apache/", "/okhttp/",
		"/retrofit2/", "/com/google/", "/com/android/", "/com/facebook/", "/com/bytedance/",
		"/com/applovin/", "/com/adjust/", "/io/reactivex/", "/rxjava/",
	}
	for _, lib := range libraries {
		if strings.Contains(p, lib) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// APK SIGNALS - Aggregated across all files
// ═══════════════════════════════════════════════════════════════════════════════

// ApkSignals aggregates signals across an entire APK
type ApkSignals struct {
	mu sync.RWMutex

	// Per-file signals
	Files map[string]*FileSignals

	// Global flags (set if ANY file has the signal)
	GlobalSignals map[SignalType][]string // signal -> list of file paths

	// Aggregated counts
	SignalCounts map[SignalType]int

	// Total threat score
	TotalScore int

	// Correlation results
	Correlations       []Correlation  `json:"correlations,omitempty"`
	FusionIntelligence *fusion.Report `json:"fusion_intelligence,omitempty"`
}

// Correlation represents a detected multi-signal threat pattern
type Correlation struct {
	Name        string
	Description string
	Signals     []SignalType
	Files       []string
	Score       int
	Severity    ThreatSeverity
}

type ThreatSeverity int

const (
	SeverityLow ThreatSeverity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
	SeverityInfo
)

func (s ThreatSeverity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	case SeverityInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

func NewApkSignals() *ApkSignals {
	return &ApkSignals{
		Files:         make(map[string]*FileSignals),
		GlobalSignals: make(map[SignalType][]string),
		SignalCounts:  make(map[SignalType]int),
	}
}

func (as *ApkSignals) AddFileSignals(fs *FileSignals) {
	as.mu.Lock()
	defer as.mu.Unlock()

	as.Files[fs.Path] = fs
	as.TotalScore += fs.Score

	for sig := range fs.Signals {
		as.GlobalSignals[sig] = append(as.GlobalSignals[sig], fs.Path)
		as.SignalCounts[sig]++
	}
}

func (as *ApkSignals) HasGlobal(sig SignalType) bool {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return len(as.GlobalSignals[sig]) > 0
}

func (as *ApkSignals) HasAllGlobal(sigs ...SignalType) bool {
	for _, s := range sigs {
		if !as.HasGlobal(s) {
			return false
		}
	}
	return true
}

func (as *ApkSignals) HasAnyGlobal(sigs ...SignalType) bool {
	for _, s := range sigs {
		if as.HasGlobal(s) {
			return true
		}
	}
	return false
}

func (as *ApkSignals) GetSeverity() ThreatSeverity {
	switch {
	case as.TotalScore >= 50 || len(as.Correlations) >= 3:
		return SeverityCritical
	case as.TotalScore >= 30 || len(as.Correlations) >= 2:
		return SeverityHigh
	case as.TotalScore >= 15 || len(as.Correlations) >= 1:
		return SeverityMedium
	default:
		return SeverityLow
	}
}
