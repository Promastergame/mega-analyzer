package ml

import (
	"fmt"
	"regexp"
)


// ═══════════════════════════════════════════════════════════════════════════════
// VULNERABILITY SIGNALS — Phase 4
//
// Расширенный детектор реальных уязвимостей и malware-паттернов в smali.
// Дополняет pattern matching из patch_patterns.go (license, billing) набором
// сигналов которые реверсер ищет руками:
//
//   • Dynamic code loading (DexClassLoader / PathClassLoader)
//   • Reflection с decrypt strings (классика обфусцированной малвари)
//   • Runtime.exec / ProcessBuilder (shell execution)
//   • Hardcoded C2 URLs / Telegram / IP addresses
//   • SMS interception (BroadcastReceiver + getMessageBody)
//   • Overlay attacks (TYPE_APPLICATION_OVERLAY / SYSTEM_ALERT_WINDOW)
//   • AccessibilityService abuse (для не-accessibility функций)
//   • Native loader из external path (System.load)
//   • Anti-VM paranoid (5+ Build.* checks подряд)
//   • Clipboard hijacking (для крипто-кошельков)
//   • Crypto mining indicators
//   • App dropper / installer (PackageInstaller / Intent.ACTION_INSTALL)
//   • SharedPreferences password leak (хранение паролей в ясном тексте)
//
// Используется:
//   1. В scoredMethodToPoint — обогащает PatchPoint.VulnSignals
//   2. В noise filter — библиотека НЕ выбрасывается если есть VulnerabilitySignal
//   3. В новом bucket'е MalwareIndicators предсказания
// ═══════════════════════════════════════════════════════════════════════════════

// VulnKind — тип уязвимости / malware indicator.
type VulnKind string

const (
	VulnDynamicCodeLoading   VulnKind = "dynamic_code_loading"
	VulnReflectionWithCrypto VulnKind = "reflection_with_crypto"
	VulnRuntimeExec          VulnKind = "runtime_exec"
	VulnHardcodedC2          VulnKind = "hardcoded_c2"
	VulnSMSInterception      VulnKind = "sms_interception"
	VulnOverlayAttack        VulnKind = "overlay_attack"
	VulnAccessibilityAbuse   VulnKind = "accessibility_abuse"
	VulnNativeExternalLoad   VulnKind = "native_external_load"
	VulnAntiVMParanoid       VulnKind = "anti_vm_paranoid"
	VulnClipboardHijack      VulnKind = "clipboard_hijack"
	VulnCryptoMining         VulnKind = "crypto_mining"
	VulnAppDropper           VulnKind = "app_dropper"
	VulnPasswordLeak         VulnKind = "password_leak"
	VulnRootCommandExec      VulnKind = "root_command_exec"
	VulnHTTPSCertBypass      VulnKind = "https_cert_bypass"
	VulnHardcodedSecret      VulnKind = "hardcoded_secret"
	VulnInsecureTransport    VulnKind = "insecure_transport"
	VulnDebugBackend         VulnKind = "debug_backend_endpoint"
	VulnEndpointOverride     VulnKind = "runtime_endpoint_override"
	VulnClientAccountTrust   VulnKind = "client_side_account_trust"
	VulnWebViewBridge        VulnKind = "webview_js_bridge"
	VulnWeakJWTHandling      VulnKind = "weak_jwt_handling"
	// Phase 5 — Advanced threat detection
	VulnKeylogger            VulnKind = "keylogger"              // Accessibility text events + network send
	VulnScreenCapture        VulnKind = "screen_capture"         // MediaProjectionManager + exfil
	VulnTelephonyAbuse       VulnKind = "telephony_abuse"        // IMEI/IMSI/phone number harvesting
	VulnWebSocketC2          VulnKind = "websocket_c2"           // WebSocket + suspicious URL
	VulnLocationStealth      VulnKind = "location_stealth"       // Background location + immediate send
	VulnContentInjection     VulnKind = "content_injection"      // ContentProvider SQL injection
	VulnObfuscatedDexDecrypt VulnKind = "obfuscated_dex_decrypt" // XOR decrypt loop + DexClassLoader
	VulnJNIBridgeAbuse       VulnKind = "jni_bridge_abuse"       // JNI RegisterNatives + suspicious native
	// Phase 6 — Modern bypass / environment checks
	VulnBiometricBypass     VulnKind = "biometric_bypass"     // BiometricPrompt auth gate circumvention
	VulnHardwareAttestation VulnKind = "hardware_attestation" // TEE/StrongBox key attestation manipulation
	VulnDeviceBinding       VulnKind = "device_binding"       // Device ID / IMEI binding enforcement
	VulnKernelSUDetect      VulnKind = "kernelsu_detect"      // KernelSU / APatch root method
	VulnLSPosedDetect       VulnKind = "lsposed_detect"       // LSPosed / Riru framework check
	VulnAppCloneDetect      VulnKind = "app_clone_detect"     // Dual-space / clone app detection
	VulnSpeedHackDetect     VulnKind = "speed_hack_detect"    // Frame-time speed manipulation
	VulnGeoBlock            VulnKind = "geo_block"            // Geographic restriction enforcement
	VulnOAuthBypass         VulnKind = "oauth_bypass"         // OAuth2/OIDC token validation bypass
	VulnDeviceFarmDetect    VulnKind = "device_farm_detect"   // UIAutomator/cloud device farm
	VulnCertTransparency    VulnKind = "cert_transparency"    // OkHttp CT policy bypass
	VulnScreenOverlay       VulnKind = "screen_overlay"       // canDrawOverlays overlay attack
	// Modern code-level weaknesses that are useful during smali review.
	VulnWeakCrypto            VulnKind = "weak_crypto"            // ECB/RC4/MD5/SHA-1 misuse
	VulnUnsafeDeserialization VulnKind = "unsafe_deserialization" // readObject/unmarshall on untrusted data
	VulnWebViewConfig         VulnKind = "webview_unsafe_config"  // JS bridge/file access exposure
	VulnMutablePendingIntent  VulnKind = "mutable_pending_intent" // mutable PendingIntent exposure

	// ── Client-side trust / bypass surface (audit findings with bypass notes) ──
	VulnClientSideCurrency VulnKind = "client_side_currency" // coins/gems/lives trusted to client
	VulnPremiumClientGate  VulnKind = "premium_client_gate"  // isPremium/isVip boolean gate on client
	VulnLicenseCheckClient VulnKind = "license_check_client" // LVL/Play licensing verified on client
	VulnWeakRandom         VulnKind = "weak_random"          // java/util/Random for security tokens
	VulnSQLInjection       VulnKind = "sql_injection"        // rawQuery/execSQL with concatenation
	VulnPathTraversal      VulnKind = "path_traversal"       // file paths built from untrusted input
	VulnCleartextHTTP      VulnKind = "cleartext_http"       // http:// endpoints / cleartext traffic
	// Phase 7 — Client-side trust boundaries (real mobile vulns, not web SQLi/XSS)
	VulnAuthCheckBypass     VulnKind = "auth_check_bypass"     // login/session/token check done only client-side
	VulnAgeVerification     VulnKind = "age_verification"      // age gate / COPPA check bypassable client-side
	VulnPremiumFeatureGate  VulnKind = "premium_feature_gate"  // premium/pro feature unlocked by local flag
	VulnTrialPeriodCheck    VulnKind = "trial_period_check"    // trial/expiry check uses local clock only
	VulnLicenseLocalOnly    VulnKind = "license_local_only"    // license validation without server round-trip
	VulnBiometricLocalOnly  VulnKind = "biometric_local_only"  // biometric result trusted without crypto binding
	VulnSessionTokenWeak    VulnKind = "session_token_weak"    // session token predictable / no expiry check
	VulnPaymentClientSide   VulnKind = "payment_client_side"   // payment success inferred from local state
	VulnRootDetectionBypass VulnKind = "root_detection_bypass" // isRooted/checkRoot local boolean gate
	VulnEmulatorCheckBypass VulnKind = "emulator_check_bypass" // emulator/device-farm local gate
	VulnDebugCheckBypass    VulnKind = "debug_check_bypass"    // debugger/anti-debug local gate
	VulnTamperCheckBypass   VulnKind = "tamper_check_bypass"   // signature/hash/integrity local gate
)

// VulnSeverity — критичность находки. Определяет как сильно сигнал
// перевешивает library/decoy фильтры.
type VulnSeverity string

const (
	VulnSeverityCritical VulnSeverity = "critical" // malware-grade — обязательно показать даже из либы
	VulnSeverityHigh     VulnSeverity = "high"     // подозрительно — recovery из либ
	VulnSeverityMedium   VulnSeverity = "medium"   // нужно посмотреть
	VulnSeverityLow      VulnSeverity = "low"      // weak signal
)

// VulnSignal — один найденный сигнал уязвимости/malware.
type VulnSignal struct {
	Kind        VulnKind     `json:"kind"`
	Severity    VulnSeverity `json:"severity"`
	Confidence  float64      `json:"confidence"`
	Description string       `json:"description"`
	Evidence    []string     `json:"evidence"` // конкретные подтверждающие строки/calls
}

// VulnerabilitySignals — агрегат по методу.
type VulnerabilitySignals struct {
	Signals          []VulnSignal `json:"signals,omitempty"`
	HighestSeverity  VulnSeverity `json:"highest_severity,omitempty"`
	IsMalwareSuspect bool         `json:"is_malware_suspect"` // ≥1 critical/high signal
	ScoreBoost       float64      `json:"score_boost"`        // bonus к RiskScore
}

// Регулярные выражения предкомпилируем (горячий путь — тысячи методов).
var (
	reIPAddress     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`)
	reHexLong       = regexp.MustCompile(`^[A-Fa-f0-9]{32,}$`) // hash bytes / encoded payload
	reBase64Like    = regexp.MustCompile(`^[A-Za-z0-9+/]{40,}={0,2}$`)
	reSusURL        = regexp.MustCompile(`https?://[a-z0-9.-]+\.(?:tk|ga|cf|ml|gq|ru|cc|top|club|xyz|onion)\b`)
	reTelegramURL   = regexp.MustCompile(`(?:t\.me|telegram\.me|telegra\.ph)/`)
	reMiningPoolURL = regexp.MustCompile(`(?i)(?:stratum\+tcp://|\b(?:xmr|monero|crypto)?pool\.(?:com|net|org|ru|io)\b|\b(?:minerd|xmrig|coinhive|cryptonight)\b|\bmonero\b.*\b(?:wallet|miner|pool)\b)`)
	reGoogleAPIKey  = regexp.MustCompile(`AIza[0-9A-Za-z_-]{20,}`)
	reStripeLiveKey = regexp.MustCompile(`(?:sk|rk)_live_[0-9A-Za-z]{16,}`)
	reSlackToken    = regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{20,}`)
	reAWSAccessKey  = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)

	// Crypto wallet patterns (precompiled for detectClipboardHijack)
	reWalletBTC1   = regexp.MustCompile(`^1[A-Za-z0-9]{25,}$`)
	reWalletBTC3   = regexp.MustCompile(`^3[A-Za-z0-9]{25,}$`)
	reWalletBTCbc1 = regexp.MustCompile(`^bc1[a-z0-9]{25,}$`)
	reWalletETH    = regexp.MustCompile(`^0x[a-f0-9]{40}$`)
	reWalletTRX    = regexp.MustCompile(`^[T][A-Za-z0-9]{33}$`)
	reWalletDash   = regexp.MustCompile(`^X[A-Za-z0-9]{33}$`)
	walletRegexes  = []*regexp.Regexp{reWalletBTC1, reWalletBTC3, reWalletBTCbc1, reWalletETH, reWalletTRX, reWalletDash}
)

// AnalyzeVulnerabilitySignals — главная точка входа.
func AnalyzeVulnerabilitySignals(mi *MethodInfo) *VulnerabilitySignals {
	if mi == nil {
		return nil
	}
	if len(mi.Calls) == 0 && len(mi.StringConsts) == 0 {
		return nil
	}

	signals := make([]VulnSignal, 0, 4)

	if s := detectDynamicCodeLoading(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectReflectionWithCrypto(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectRuntimeExec(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectRootCommandExec(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectHardcodedC2(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectSMSInterception(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectOverlayAttack(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectAccessibilityAbuse(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectNativeExternalLoad(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectAntiVMParanoid(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectClipboardHijack(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectCryptoMining(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectAppDropper(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectPasswordLeak(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectHTTPSCertBypass(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectHardcodedSecrets(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectInsecureTransport(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectDebugBackendEndpoint(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectRuntimeEndpointOverride(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectClientSideAccountTrust(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectWebViewJSBridge(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectWeakJWTHandling(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectWeakCrypto(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectUnsafeDeserialization(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectUnsafeWebViewConfig(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectMutablePendingIntent(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectClientSideCurrency(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectPremiumClientGate(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectLicenseCheckClient(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectWeakRandom(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectSQLInjection(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectPathTraversal(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectCleartextHTTP(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectKeylogger(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectScreenCapture(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectTelephonyAbuse(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectWebSocketC2(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectLocationStealth(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectContentInjection(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectObfuscatedDexDecrypt(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectJNIBridgeAbuse(mi); s != nil {
		signals = append(signals, *s)
	}

	// Phase 7 — client-side trust boundaries
	if s := detectAuthCheckBypass(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectAgeVerification(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectPremiumFeatureGate(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectTrialPeriodCheck(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectLicenseLocalOnly(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectBiometricLocalOnly(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectSessionTokenWeak(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectPaymentClientSide(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectRootDetectionBypass(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectEmulatorCheckBypass(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectDebugCheckBypass(mi); s != nil {
		signals = append(signals, *s)
	}
	if s := detectTamperCheckBypass(mi); s != nil {
		signals = append(signals, *s)
	}

	// Extended detectors (см. vulnsignals_extra.go): Frida, hardcoded crypto,
	// WebView file access, SharedPreferences secrets, log leaks, clipboard read.
	signals = append(signals, detectExtendedSignals(mi)...)

	if len(signals) == 0 {
		return nil
	}

	// Static-evidence calibration (see signal_calibration.go): clamp every
	// confidence to its evidence tier BEFORE aggregation, so ScoreBoost and
	// all downstream consumers use calibrated values.
	signals = CalibrateVulnSignals(signals)

	// Агрегируем
	highest := VulnSeverityLow
	severityRank := map[VulnSeverity]int{
		VulnSeverityCritical: 4,
		VulnSeverityHigh:     3,
		VulnSeverityMedium:   2,
		VulnSeverityLow:      1,
	}
	var totalBoost float64
	for _, s := range signals {
		if severityRank[s.Severity] > severityRank[highest] {
			highest = s.Severity
		}
		// ScoreBoost зависит от severity и confidence
		boost := 0.0
		switch s.Severity {
		case VulnSeverityCritical:
			boost = 25.0 * s.Confidence
		case VulnSeverityHigh:
			boost = 15.0 * s.Confidence
		case VulnSeverityMedium:
			boost = 8.0 * s.Confidence
		case VulnSeverityLow:
			boost = 3.0 * s.Confidence
		}
		totalBoost += boost
	}
	// Cap чтобы один пухлый метод с 10 сигналами не зашкаливал.
	if totalBoost > 50.0 {
		totalBoost = 50.0
	}

	return &VulnerabilitySignals{
		Signals:          signals,
		HighestSeverity:  highest,
		IsMalwareSuspect: highest == VulnSeverityCritical || highest == VulnSeverityHigh,
		ScoreBoost:       totalBoost,
	}
}

// HasAny — есть ли хоть один сигнал.
func (vs *VulnerabilitySignals) HasAny() bool {
	if vs == nil {
		return false
	}
	return len(vs.Signals) > 0
}

// Explain возвращает список описаний всех найденных сигналов.
func (vs *VulnerabilitySignals) Explain() []string {
	if vs == nil || len(vs.Signals) == 0 {
		return nil
	}
	res := make([]string, 0, len(vs.Signals))
	for _, s := range vs.Signals {
		res = append(res, fmt.Sprintf("VULN [%s]: %s (conf: %.2f)", s.Severity, s.Description, s.Confidence))
	}
	return res
}

// HasAnyHighSeverity — есть ли critical/high сигнал. Нужно для library recovery.
func (vs *VulnerabilitySignals) HasAnyHighSeverity() bool {
	if vs == nil {
		return false
	}
	return vs.IsMalwareSuspect
}
