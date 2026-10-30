package pipeline

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ACCESSIBILITY ABUSE DETECTOR v3.0
//
// Архитектура:
//   1. Stateless detector — хранит только patterns (immutable)
//   2. Per-APK state — вынесен в accessibilityState (mutable, mutex-protected)
//   3. Pre-scan — один проход по content, результат кэшируется
//   4. Threat dedup — map[type]*threat, обновление score
//   5. Sigmoid scoring — не насыщается при многих мелких сигналах
//   6. Signal emission — не дублирует C2/obfuscation, отдаёт сигналы aggregator-у
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Threat levels ───────────────────────────────────────────────────────────

const (
	ThreatNone     = 0
	ThreatLow      = 1
	ThreatMedium   = 2
	ThreatHigh     = 3
	ThreatCritical = 4
)

// ─── Threat types ────────────────────────────────────────────────────────────

const (
	ThreatTypeBankingTrojan      = "BANKING_TROJAN"
	ThreatTypeKeylogger          = "KEYLOGGER"
	ThreatType2FABypass          = "2FA_BYPASS"
	ThreatTypeAccessibilityAbuse = "ACCESSIBILITY_ABUSE"
	ThreatTypeOverlayAttack      = "OVERLAY_ATTACK"
	ThreatTypeClickFraud         = "CLICK_FRAUD"
	ThreatTypeScreenScraper      = "SCREEN_SCRAPER"
	ThreatTypeSecurityKiller     = "SECURITY_APP_KILLER"
	ThreatTypeCredentialTheft    = "CREDENTIAL_THEFT"
	ThreatTypeRansomware         = "RANSOMWARE_LOCK"
	ThreatTypeSpyware            = "SPYWARE"
)

// ─── Pattern categories (для pre-scan) ───────────────────────────────────────

type patternCategory int

const (
	pcAccessibilityAPI patternCategory = iota
	pcOverlay
	pcFinancial
	pcCrypto
	pcCredential
	pcSecurityApp
	pcBankingApp
	pcGesture
	pcKeylog
	pcScreenCapture
	pcNotification
	pcPackageMonitor
	pcSubclass
	pcGeoTarget
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN SCANNER — один проход, все категории
// ═══════════════════════════════════════════════════════════════════════════════

type taggedPattern struct {
	pattern  []byte
	category patternCategory
	tag      string
	weight   float64
}

type patternHit struct {
	tp     *taggedPattern
	offset int
}

type preScanResult struct {
	hits     []*patternHit
	byCat    map[patternCategory][]*patternHit
	catCount map[patternCategory]int
	hasTag   map[string]bool
}

func newPreScanResult() *preScanResult {
	return &preScanResult{
		byCat:    make(map[patternCategory][]*patternHit),
		catCount: make(map[patternCategory]int),
		hasTag:   make(map[string]bool),
	}
}

// preScan выполняет один проход по content и находит все паттерны.
// Паттерны группируются по первому байту для быстрого пропуска.
func (d *AccessibilityAbuseDetector) preScan(content []byte) *preScanResult {
	result := newPreScanResult()

	for i := range d.patterns {
		tp := &d.patterns[i]
		if idx := bytes.Index(content, tp.pattern); idx >= 0 {
			hit := &patternHit{tp: tp, offset: idx}
			result.hits = append(result.hits, hit)
			result.byCat[tp.category] = append(result.byCat[tp.category], hit)
			result.catCount[tp.category]++
			result.hasTag[tp.tag] = true
		}
	}

	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT (deduplicated)
// ═══════════════════════════════════════════════════════════════════════════════

type AccessibilityThreat struct {
	Type        string   `json:"type"`
	Level       int      `json:"level"`
	Score       float64  `json:"score"`
	Description string   `json:"description"`
	Evidence    []string `json:"evidence"`
	FilePaths   []string `json:"file_paths"`
	HitCount    int      `json:"hit_count"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML SIGNAL — нормализованные фичи для ML системы
// ═══════════════════════════════════════════════════════════════════════════════

type AccessibilityMLSignal struct {
	// ── Raw flags ────────────────────────────────────────────────
	HasAccessibilityService bool `json:"has_accessibility_service"`
	HasInternetPermission   bool `json:"has_internet"`
	HasSMSPermissions       bool `json:"has_sms"`
	HasSystemAlertWindow    bool `json:"has_overlay"`
	HasDeviceAdmin          bool `json:"has_device_admin"`
	HasNotificationAccess   bool `json:"has_notification_access"`
	HasBootReceiver         bool `json:"has_boot_receiver"`
	HasInstallPackages      bool `json:"has_install_packages"`
	HasUsageStats           bool `json:"has_usage_stats"`
	HasFinancialKeywords    bool `json:"has_financial_keywords"`
	HasCryptoKeywords       bool `json:"has_crypto_keywords"`
	HasCredentialPattern    bool `json:"has_credential_pattern"`
	HasGeoTargeting         bool `json:"has_geo_targeting"`

	// ── Raw counters ─────────────────────────────────────────────
	AccessibilityAPICallCount int `json:"api_call_count"`
	SuspiciousMethodCount     int `json:"suspicious_method_count"`
	OverlayPatternCount       int `json:"overlay_pattern_count"`
	ClickSimulationCount      int `json:"click_simulation_count"`
	ScreenScrapingCount       int `json:"screen_scraping_count"`
	PackageMonitorCount       int `json:"package_monitor_count"`
	KeylogPatternCount        int `json:"keylog_pattern_count"`
	NotificationCaptureCount  int `json:"notification_capture_count"`
	GestureInjectionCount     int `json:"gesture_injection_count"`
	FilesAnalyzed             int `json:"files_analyzed"`

	// ── Normalized features (для ML) ─────────────────────────────
	NormalizedAPICalls  float64 `json:"norm_api_calls"`     // api_calls / files_analyzed
	BehaviorDensity     float64 `json:"behavior_density"`   // (clicks+scraping+keylog) / files
	PermissionRiskScore float64 `json:"perm_risk_score"`    // weighted permission combo (0..1)
	ContextRiskScore    float64 `json:"context_risk_score"` // financial+crypto+credential (0..1)
	ComboCount          int     `json:"combo_count"`

	// ── Итоговые ─────────────────────────────────────────────────
	DangerousCombos []string `json:"dangerous_combos"`
	ThreatScore     float64  `json:"threat_score"` // sigmoid-normalized (0..10)
	ThreatTypes     []string `json:"threat_types"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// PER-APK STATE (mutable, mutex-protected)
// ═══════════════════════════════════════════════════════════════════════════════

type accessibilityState struct {
	mu sync.Mutex

	// ── Permission flags ─────────────────────────────────────────
	hasAccessibilityService bool
	hasInternetPermission   bool
	hasSMSPermissions       bool
	hasSystemAlertWindow    bool
	hasDeviceAdmin          bool
	hasNotificationAccess   bool
	hasBootReceiver         bool
	hasInstallPackages      bool
	hasUsageStats           bool
	hasCamera               bool
	hasMicrophone           bool
	hasKeyguardDisable      bool

	// ── Context flags ────────────────────────────────────────────
	hasFinancialKeywords bool
	hasCryptoKeywords    bool
	hasCredentialPattern bool
	hasGeoTargeting      bool

	// ── Counters ─────────────────────────────────────────────────
	apiCalls             int
	suspiciousMethods    int
	overlayPatterns      int
	clickSimulations     int
	screenScrapings      int
	packageMonitors      int
	gestureInjections    int
	keylogHits           int
	notificationCaptures int
	filesAnalyzed        int

	// ── Threats (deduplicated: type → best threat) ───────────────
	threats map[string]*AccessibilityThreat
}

func newAccessibilityState() *accessibilityState {
	return &accessibilityState{
		threats: make(map[string]*AccessibilityThreat),
	}
}

// addThreat добавляет или обновляет threat (dedup по типу, сохраняет max score)
func (s *accessibilityState) addThreat(threatType string, level int, score float64, desc, evidence, file string) {
	existing, ok := s.threats[threatType]
	if !ok {
		s.threats[threatType] = &AccessibilityThreat{
			Type:        threatType,
			Level:       level,
			Score:       score,
			Description: desc,
			Evidence:    []string{evidence},
			FilePaths:   []string{file},
			HitCount:    1,
		}
		return
	}

	// Update: max score, append evidence
	existing.HitCount++
	if score > existing.Score {
		existing.Score = score
		existing.Level = level
		existing.Description = desc
	}
	// Avoid duplicate evidence
	for _, e := range existing.Evidence {
		if e == evidence {
			return
		}
	}
	if len(existing.Evidence) < 10 { // cap evidence list
		existing.Evidence = append(existing.Evidence, evidence)
	}
	// Avoid duplicate file paths
	for _, f := range existing.FilePaths {
		if f == file {
			return
		}
	}
	if len(existing.FilePaths) < 20 {
		existing.FilePaths = append(existing.FilePaths, file)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORING — sigmoid-normalized
// ═══════════════════════════════════════════════════════════════════════════════

func sigmoid(x float64) float64 {
	return 1.0 / (1.0 + math.Exp(-x))
}

func (s *accessibilityState) calculateThreatScore() float64 {
	if !s.hasAccessibilityService {
		return 0.0
	}

	// ── Permission score (weighted sum) ──────────────────────────
	permScore := 0.0
	permWeights := []struct {
		flag   bool
		weight float64
	}{
		{s.hasSystemAlertWindow, 3.0},
		{s.hasDeviceAdmin, 3.0},
		{s.hasSMSPermissions, 2.5},
		{s.hasNotificationAccess, 2.0},
		{s.hasInstallPackages, 2.0},
		{s.hasBootReceiver, 1.5},
		{s.hasKeyguardDisable, 1.5},
		{s.hasInternetPermission, 0.5},
		{s.hasUsageStats, 1.0},
		{s.hasCamera && s.hasMicrophone, 2.0},
	}
	for _, pw := range permWeights {
		if pw.flag {
			permScore += pw.weight
		}
	}

	// ── Behavioral score (log-scaled, не насыщается) ─────────────
	behaviorScore := math.Log1p(float64(s.clickSimulations))*1.5 +
		math.Log1p(float64(s.screenScrapings))*1.5 +
		math.Log1p(float64(s.keylogHits))*2.0 +
		math.Log1p(float64(s.packageMonitors))*1.0 +
		math.Log1p(float64(s.gestureInjections))*1.0 +
		math.Log1p(float64(s.notificationCaptures))*1.0

	// ── Context multiplier ───────────────────────────────────────
	contextMult := 1.0
	if s.hasFinancialKeywords {
		contextMult += 0.5
	}
	if s.hasCryptoKeywords {
		contextMult += 0.5
	}
	if s.hasCredentialPattern {
		contextMult += 0.3
	}
	if s.hasGeoTargeting {
		contextMult += 0.2
	}

	// ── Raw score ────────────────────────────────────────────────
	rawScore := (2.0 + permScore + behaviorScore) * contextMult

	// ── Sigmoid normalization: center=8, scale=3 → output 0..10 ─
	// При rawScore=0 → ~0.7, при rawScore=8 → 5.0, при rawScore=20 → ~9.8
	return 10.0 * sigmoid((rawScore-8.0)/3.0)
}

// permissionRiskNormalized возвращает нормализованный (0..1) permission risk
func (s *accessibilityState) permissionRiskNormalized() float64 {
	if !s.hasAccessibilityService {
		return 0
	}
	count := 0
	flags := []bool{
		s.hasSystemAlertWindow, s.hasDeviceAdmin, s.hasSMSPermissions,
		s.hasNotificationAccess, s.hasInstallPackages, s.hasBootReceiver,
		s.hasKeyguardDisable, s.hasUsageStats, s.hasCamera, s.hasMicrophone,
	}
	for _, f := range flags {
		if f {
			count++
		}
	}
	return math.Min(1.0, float64(count)/6.0) // 6+ dangerous permissions = 1.0
}

// contextRiskNormalized возвращает нормализованный (0..1) context risk
func (s *accessibilityState) contextRiskNormalized() float64 {
	score := 0.0
	if s.hasFinancialKeywords {
		score += 0.35
	}
	if s.hasCryptoKeywords {
		score += 0.35
	}
	if s.hasCredentialPattern {
		score += 0.2
	}
	if s.hasGeoTargeting {
		score += 0.1
	}
	return math.Min(1.0, score)
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN DETECTOR (stateless — patterns only)
// ═══════════════════════════════════════════════════════════════════════════════

type AccessibilityAbuseDetector struct {
	patterns []taggedPattern
	state    *accessibilityState
}

func NewAccessibilityAbuseDetector() *AccessibilityAbuseDetector {
	d := &AccessibilityAbuseDetector{
		state: newAccessibilityState(),
	}
	d.buildPatterns()
	return d
}

func (d *AccessibilityAbuseDetector) Name() string {
	return "accessibility_abuse_detector"
}

// ─── Pattern builder (compact) ───────────────────────────────────────────────

func mkPatterns(cat patternCategory, w float64, tags ...string) []taggedPattern {
	out := make([]taggedPattern, len(tags))
	for i, t := range tags {
		out[i] = taggedPattern{pattern: []byte(t), category: cat, tag: t, weight: w}
	}
	return out
}

func (d *AccessibilityAbuseDetector) buildPatterns() {
	d.patterns = nil

	d.patterns = append(d.patterns, mkPatterns(pcAccessibilityAPI, 2.0,
		"performglobalaction", "accessibilitynodeinfo", "performaction",
		"accessibilityevent", "dispatchgesture",
		"getrootinactivewindow",  // FIX: убрана двойная 'a'
		"getrootinaactivewindow", // оставляем оба варианта для опечаток в APK
		"findaccessibilitynodeinfosbytext",
		"findaccessibilitynodeinfosbyviewid",
		"getsource", "getchildcount", "getchild",
		"gettext", "getcontentdescription", "getclassname",
		"getpackagename", "onserviceconnected",
		"onaccessibilityevent", "getserviceinfo", "setserviceinfo",
		"getwindows",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcOverlay, 2.5,
		"type_application_overlay", "type_system_alert",
		"type_system_overlay", "type_system_error",
		"flag_not_touchable", "flag_not_focusable",
		"flag_watch_outside_touch", "flag_layout_no_limits",
		// NOTE: bare "windowmanager$layoutparams" removed — it fires on any
		// code touching window attributes (Unity Swappy frame-pacing,
		// video players, ...). An overlay verdict needs an overlay TYPE,
		// flag or addView, all of which remain above. Seen in the wild:
		// SwappyDisplayManager$1 setting preferredDisplayModeId on its own
		// Activity window scored SECURITY 8 (ultraf9.apk).
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcFinancial, 1.5,
		"banking", "payment", "wallet", "credit_card", "debit_card",
		"transfer", "transaction", "balance",
		"sberbank", "tinkoff", "vtb", "alfa-bank", "gazprombank",
		"paypal", "visa", "mastercard", "swift", "iban", "cvv", "cvc",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcCrypto, 1.5,
		"bitcoin", "ethereum", "crypto", "blockchain",
		"metamask", "trustwallet", "coinbase", "binance",
		"seed phrase", "private key", "mnemonic",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcCredential, 1.5,
		"password", "passwd", "credential", "username",
		"auth_token", "session_token", "otp",
		"verification code", "sms code",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcSecurityApp, 3.0,
		"com.avast", "com.avg", "com.kaspersky", "com.drweb",
		"com.eset", "com.bitdefender", "com.norton", "com.mcafee",
		"com.malwarebytes", "com.lookout",
		"com.google.android.gms.security",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcBankingApp, 3.0,
		"ru.sberbankmobile", "ru.tinkoff", "ru.vtb24", "ru.alfabank",
		"com.paypal", "com.chase.sig.android",
		"com.bankofamerica", "com.wells.fargo",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcGesture, 2.0,
		"dispatchgesture", "gesturedescription",
		"action_click", "action_long_click",
		"action_scroll_forward", "action_scroll_backward",
		"action_set_text", "action_paste", "action_select",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcKeylog, 2.5,
		"type_view_text_changed", "type_view_focused",
		"type_window_content_changed", "type_window_state_changed",
		"type_notification_state_changed",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcScreenCapture, 2.0,
		"mediaprojection", "createscreencapture",
		// bare "screenshot" removed: it matches user-facing strings like
		// "screenshot this debug info" — API names only.
		"takescreenshot", "screen_capture",
		"virtualdisplay",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcNotification, 2.0,
		"notificationlistenerservice", "onnotificationposted",
		"onnotificationremoved", "statusbarnotification",
		"getactivenotifications", "cancelnotification",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcPackageMonitor, 2.0,
		"getinstalledpackages", "getinstalledapplications",
		"action_uninstall_package", "action_delete",
		"package_added", "package_removed",
		"forcestoppackage", "killbackgroundprocesses",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcSubclass, 3.0,
		"landroid/accessibilityservice/accessibilityservice;",
		".super landroid/accessibilityservice/",
	)...)

	d.patterns = append(d.patterns, mkPatterns(pcGeoTarget, 1.0,
		"country_code", "sim_country", "network_country",
		"target_countries", "geo_fence", "region_filter",
	)...)
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN DETECT (thread-safe)
// ═══════════════════════════════════════════════════════════════════════════════

func (d *AccessibilityAbuseDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()

	d.state.filesAnalyzed++

	switch ctx.FileType {
	case types.FileTypeXML:
		d.detectManifest(ctx, analysis)
	case types.FileTypeSmali:
		scan := d.preScan(ctx.ContentLower)
		d.detectSmali(ctx, analysis, scan)
	case types.FileTypeJSON, types.FileTypeResource:
		scan := d.preScan(ctx.ContentLower)
		d.detectConfig(ctx, analysis, scan)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MANIFEST ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func (d *AccessibilityAbuseDetector) detectManifest(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	c := ctx.ContentLower

	// ── Permission checks ────────────────────────────────────────
	type permCheck struct {
		pattern []byte
		flag    *bool
		name    string
	}

	perms := []permCheck{
		{[]byte("bind_accessibility_service"), &d.state.hasAccessibilityService, "BIND_ACCESSIBILITY_SERVICE"},
		{[]byte("system_alert_window"), &d.state.hasSystemAlertWindow, "SYSTEM_ALERT_WINDOW"},
		{[]byte("android.permission.internet"), &d.state.hasInternetPermission, "INTERNET"}, // FIX: точный матч
		{[]byte("read_sms"), &d.state.hasSMSPermissions, "READ_SMS"},
		{[]byte("receive_sms"), &d.state.hasSMSPermissions, "RECEIVE_SMS"},
		{[]byte("send_sms"), &d.state.hasSMSPermissions, "SEND_SMS"},
		{[]byte("request_install_packages"), &d.state.hasInstallPackages, "REQUEST_INSTALL_PACKAGES"},
		{[]byte("package_usage_stats"), &d.state.hasUsageStats, "PACKAGE_USAGE_STATS"},
		{[]byte("android.permission.camera"), &d.state.hasCamera, "CAMERA"}, // FIX: точный матч
		{[]byte("record_audio"), &d.state.hasMicrophone, "RECORD_AUDIO"},
		{[]byte("disable_keyguard"), &d.state.hasKeyguardDisable, "DISABLE_KEYGUARD"},
		{[]byte("boot_completed"), &d.state.hasBootReceiver, "BOOT_COMPLETED"},
		{[]byte("quickboot_poweron"), &d.state.hasBootReceiver, "QUICKBOOT_POWERON"},
	}

	for _, p := range perms {
		if bytes.Contains(c, p.pattern) {
			*p.flag = true
		}
	}

	// Requesting the AccessibilityService permission is NOT, on its own, a
	// threat — countless legitimate apps (screen readers, automation, password
	// managers, screenshot tools) use it. We record it as an informational
	// finding only; it is escalated to a real threat exclusively when it
	// combines with an abuse signal in evaluateManifestCombos / detectSmali.
	// See plan §1.6.
	if d.state.hasAccessibilityService {
		if idx := bytes.Index(c, []byte("bind_accessibility_service")); idx >= 0 {
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategoryManifestPermission, analysis.Path,
				lineAt(ctx.LineOffsets, idx),
				"Accessibility Service permission declared (informational; risk only in combination)",
				"android.permission.BIND_ACCESSIBILITY_SERVICE",
				false,
			))
		}
		// Low-severity threat marker so the aggregator knows the surface exists,
		// without dominating the risk score on its own.
		d.state.addThreat(
			ThreatTypeAccessibilityAbuse, ThreatLow, 2.0,
			"Accessibility Service permission declared (abuse surface; benign on its own)",
			"BIND_ACCESSIBILITY_SERVICE", analysis.Path)
	}

	// ── Device admin ─────────────────────────────────────────────
	adminPatterns := [][]byte{
		[]byte("device_admin"), []byte("bind_device_admin"), []byte("deviceadminreceiver"),
	}
	for _, ap := range adminPatterns {
		if bytes.Contains(c, ap) {
			d.state.hasDeviceAdmin = true
			break
		}
	}

	// ── Notification listener ────────────────────────────────────
	notifPatterns := [][]byte{
		[]byte("bind_notification_listener_service"), []byte("notificationlistenerservice"),
	}
	for _, np := range notifPatterns {
		if bytes.Contains(c, np) {
			d.state.hasNotificationAccess = true
			break
		}
	}

	// ── AccessibilityService declaration ─────────────────────────
	// Informational only — see plan §1.6. Real risk is reported by the combo
	// evaluation below when paired with overlay/SMS/admin/financial signals.
	if bytes.Contains(c, []byte("accessibilityservice")) {
		idx := bytes.Index(c, []byte("accessibilityservice"))
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategoryManifestPermission, analysis.Path,
			lineAt(ctx.LineOffsets, idx),
			"AccessibilityService declared in manifest (informational)",
			"android:service with AccessibilityService",
			false,
		))
	}

	// ── Dangerous combos (манифест-уровень) ──────────────────────
	d.evaluateManifestCombos(ctx, analysis)
}

func (d *AccessibilityAbuseDetector) evaluateManifestCombos(_ *FileDetectContext, analysis *types.FileAnalysis) {
	s := d.state
	if !s.hasAccessibilityService {
		return
	}

	type combo struct {
		condition  bool
		threatType string
		level      int
		score      float64
		desc       string
		evidence   string
	}

	combos := []combo{
		{s.hasSystemAlertWindow, ThreatTypeOverlayAttack, ThreatCritical, 9.0,
			"🚨 Accessibility + Overlay — classic banking trojan pattern",
			"SYSTEM_ALERT_WINDOW + AccessibilityService"},
		{s.hasDeviceAdmin, ThreatTypeRansomware, ThreatCritical, 9.5,
			"🚨 Accessibility + Device Admin — ransomware/APT pattern",
			"DeviceAdmin + AccessibilityService"},
		{s.hasNotificationAccess, ThreatType2FABypass, ThreatHigh, 8.0,
			"🔴 Accessibility + Notifications — 2FA bypass risk",
			"NotificationListener + AccessibilityService"},
		{s.hasSMSPermissions, ThreatType2FABypass, ThreatCritical, 9.0,
			"🚨 Accessibility + SMS — complete 2FA interception",
			"SMS permissions + AccessibilityService"},
		{s.hasInstallPackages, ThreatTypeSpyware, ThreatHigh, 8.5,
			"🔴 Accessibility + Install — silent malware installation",
			"INSTALL_PACKAGES + AccessibilityService"},
		{s.hasKeyguardDisable, ThreatTypeRansomware, ThreatHigh, 7.5,
			"🔴 Accessibility + Keyguard disable — screen unlock exploit",
			"DISABLE_KEYGUARD + AccessibilityService"},
		{s.hasCamera && s.hasMicrophone, ThreatTypeSpyware, ThreatHigh, 8.0,
			"🔴 Accessibility + Camera + Mic — surveillance capabilities",
			"CAMERA + RECORD_AUDIO + AccessibilityService"},
	}

	for _, cb := range combos {
		if cb.condition {
			s.addThreat(cb.threatType, cb.level, cb.score, cb.desc, cb.evidence, analysis.Path)
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path, 0,
				cb.desc, cb.evidence, true,
			))
		}
	}

	// Triple combos
	if s.hasSystemAlertWindow && s.hasFinancialKeywords {
		s.addThreat(ThreatTypeBankingTrojan, ThreatCritical, 10.0,
			"🚨 BANKING TROJAN TRIFECTA: Accessibility + Overlay + Financial context",
			"Accessibility + SYSTEM_ALERT_WINDOW + financial keywords",
			analysis.Path)
	}
	if s.hasSMSPermissions && s.hasNotificationAccess {
		s.addThreat(ThreatType2FABypass, ThreatCritical, 9.5,
			"🚨 COMPLETE 2FA BYPASS: Accessibility + SMS + Notifications",
			"Intercepts both SMS and push OTP codes",
			analysis.Path)
	}
	if s.hasDeviceAdmin && s.hasBootReceiver {
		s.addThreat(ThreatTypeRansomware, ThreatCritical, 9.5,
			"🚨 PERSISTENT APT: Accessibility + Device Admin + Boot persistence",
			"Survives reboot, prevents uninstall",
			analysis.Path)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI ANALYSIS (uses pre-scan results)
// ═══════════════════════════════════════════════════════════════════════════════

func (d *AccessibilityAbuseDetector) detectSmali(ctx *FileDetectContext, analysis *types.FileAnalysis, scan *preScanResult) {
	s := d.state

	// ── 1. Accessibility API calls ──────────────────────────────
	// A single AccessibilityService API call is normal for any service that
	// uses the framework. Report informationally (non-critical); the abuse
	// combos below (keylogger, scraping+internet, set_text, …) carry the
	// criticality. See plan §1.6.
	if hits, ok := scan.byCat[pcAccessibilityAPI]; ok {
		hasContext := bytes.Contains(ctx.ContentLower, []byte("accessibility"))
		for _, hit := range hits {
			s.apiCalls++
			if hasContext {
				analysis.Matches = append(analysis.Matches, newMatch(
					types.CategorySecurity, analysis.Path,
					lineAt(ctx.LineOffsets, hit.offset),
					"AccessibilityService API: "+hit.tp.tag,
					safeSnippet(ctx.Content, hit.offset, len(hit.tp.pattern)+30),
					false,
				))
			}
		}
	}

	// ── 2. Subclass detection ───────────────────────────────────
	// Implementing AccessibilityService is what every legitimate accessibility
	// app does. Informational on its own. See plan §1.6.
	if hits, ok := scan.byCat[pcSubclass]; ok {
		for _, hit := range hits {
			s.suspiciousMethods++
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path,
				lineAt(ctx.LineOffsets, hit.offset),
				"Custom AccessibilityService implementation (informational)",
				safeSnippet(ctx.Content, hit.offset, len(hit.tp.pattern)+20),
				false,
			))
		}
	}

	// ── 3. Gesture / click simulation ───────────────────────────
	if hits, ok := scan.byCat[pcGesture]; ok {
		for _, hit := range hits {
			s.clickSimulations++
			s.gestureInjections++
			isCritical := s.clickSimulations > 2
			label := "Gesture/click simulation: " + hit.tp.tag
			if s.clickSimulations > 3 {
				label = "🚨 Multiple click simulations — auto-click fraud or auto-grant"
			}
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path,
				lineAt(ctx.LineOffsets, hit.offset),
				label,
				safeSnippet(ctx.Content, hit.offset, len(hit.tp.pattern)+20),
				isCritical,
			))
		}
		if scan.hasTag["action_set_text"] {
			s.addThreat(ThreatTypeCredentialTheft, ThreatHigh, 7.5,
				"ACTION_SET_TEXT — can auto-fill password fields",
				"performAction(ACTION_SET_TEXT)", analysis.Path)
		}
	}

	// ── 4. Screen scraping ──────────────────────────────────────
	apiScrapePatterns := []string{"getrootinactivewindow", "getrootinaactivewindow", "getwindows"}
	for _, p := range apiScrapePatterns {
		if scan.hasTag[p] {
			s.screenScrapings++
			hit := findHitByTag(scan, p)
			if hit != nil {
				analysis.Matches = append(analysis.Matches, newMatch(
					types.CategorySecurity, analysis.Path,
					lineAt(ctx.LineOffsets, hit.offset),
					"🔴 Screen content access: "+p,
					safeSnippet(ctx.Content, hit.offset, len(hit.tp.pattern)+20),
					true,
				))
			}
		}
	}
	if hits, ok := scan.byCat[pcScreenCapture]; ok {
		for _, hit := range hits {
			s.screenScrapings++
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path,
				lineAt(ctx.LineOffsets, hit.offset),
				"Screen capture: "+hit.tp.tag,
				safeSnippet(ctx.Content, hit.offset, len(hit.tp.pattern)+20),
				true,
			))
		}
	}

	// ── 5. Overlay patterns in code ─────────────────────────────
	if hits, ok := scan.byCat[pcOverlay]; ok {
		for _, hit := range hits {
			s.overlayPatterns++
			isCritical := s.hasAccessibilityService && s.overlayPatterns > 1
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path,
				lineAt(ctx.LineOffsets, hit.offset),
				"Overlay pattern: "+hit.tp.tag,
				safeSnippet(ctx.Content, hit.offset, len(hit.tp.pattern)+20),
				isCritical,
			))
		}
	}

	// ── 6. Financial context ────────────────────────────────────
	financialHits := scan.catCount[pcFinancial]
	if financialHits >= 3 {
		s.hasFinancialKeywords = true
		if s.hasAccessibilityService {
			s.addThreat(ThreatTypeBankingTrojan, ThreatCritical, 9.0,
				fmt.Sprintf("Financial keywords (%d) + AccessibilityService", financialHits),
				"Banking/payment keywords in accessibility context",
				analysis.Path)
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path, 0,
				fmt.Sprintf("🚨 BANKING TROJAN RISK: %d financial keywords + Accessibility", financialHits),
				"Financial keywords combined with accessibility abuse capabilities",
				true,
			))
		}
	}

	// ── 7. Crypto context ───────────────────────────────────────
	cryptoHits := scan.catCount[pcCrypto]
	if cryptoHits >= 2 {
		s.hasCryptoKeywords = true
		if s.hasAccessibilityService {
			s.addThreat(ThreatTypeCredentialTheft, ThreatCritical, 9.0,
				"Crypto keywords + AccessibilityService — wallet theft pattern",
				"Targets seed phrases, private keys, wallet apps",
				analysis.Path)
		}
	}

	// ── 8. Credential theft ─────────────────────────────────────
	credentialHits := scan.catCount[pcCredential]
	if credentialHits >= 3 && s.hasAccessibilityService {
		s.hasCredentialPattern = true
		s.addThreat(ThreatTypeCredentialTheft, ThreatHigh, 8.0,
			fmt.Sprintf("Credential harvesting: %d credential keywords + Accessibility", credentialHits),
			"Can read password fields via AccessibilityService",
			analysis.Path)
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity, analysis.Path, 0,
			fmt.Sprintf("🔴 Credential theft: %d credential keywords + Accessibility", credentialHits),
			"password/login/token keywords with accessibility context",
			true,
		))
	}

	// ── 9. Security app killing ─────────────────────────────────
	securityHits := scan.catCount[pcSecurityApp]
	if securityHits > 0 && s.hasAccessibilityService {
		s.addThreat(ThreatTypeSecurityKiller, ThreatCritical, 9.5,
			fmt.Sprintf("Security app targeting: %d antivirus packages + Accessibility", securityHits),
			"Can auto-uninstall security apps",
			analysis.Path)
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity, analysis.Path, 0,
			fmt.Sprintf("🚨 SECURITY KILLER: %d antivirus packages targeted", securityHits),
			"AccessibilityService can auto-click uninstall on security apps",
			true,
		))
	}

	// ── 10. Package monitoring ──────────────────────────────────
	pkgHits := scan.catCount[pcPackageMonitor]
	if pkgHits > 0 {
		s.packageMonitors += pkgHits
		if pkgHits >= 3 && s.hasAccessibilityService {
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path, 0,
				fmt.Sprintf("Package monitoring with Accessibility (%d patterns)", pkgHits),
				"Can track/kill apps",
				true,
			))
		}
	}

	// ── 11. Notification interception ───────────────────────────
	if hits, ok := scan.byCat[pcNotification]; ok {
		for _, hit := range hits {
			s.notificationCaptures++
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path,
				lineAt(ctx.LineOffsets, hit.offset),
				"Notification interception: "+hit.tp.tag,
				safeSnippet(ctx.Content, hit.offset, len(hit.tp.pattern)+20),
				s.hasAccessibilityService,
			))
		}
		if s.notificationCaptures >= 2 && s.hasSMSPermissions {
			s.addThreat(ThreatType2FABypass, ThreatCritical, 9.0,
				"Notification + SMS = complete 2FA interception",
				"Intercepts both SMS and push notification OTP codes",
				analysis.Path)
		}
	}

	// ── 12. Keylogging ──────────────────────────────────────────
	keylogHitCount := scan.catCount[pcKeylog]
	if keylogHitCount > 0 {
		s.keylogHits += keylogHitCount
	}
	hasTextChanged := scan.hasTag["type_view_text_changed"]
	hasGetText := scan.hasTag["gettext"]
	if hasTextChanged && hasGetText && s.hasAccessibilityService {
		s.addThreat(ThreatTypeKeylogger, ThreatCritical, 9.0,
			"Keylogger: TYPE_VIEW_TEXT_CHANGED + getText — captures every keystroke",
			"Records all text input including passwords",
			analysis.Path)
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity, analysis.Path, 0,
			"🚨 KEYLOGGER: text changes + text reading = keystroke capture",
			"TYPE_VIEW_TEXT_CHANGED + getText()",
			true,
		))
	} else if keylogHitCount >= 3 {
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity, analysis.Path, 0,
			fmt.Sprintf("Potential keylogging: %d input monitoring patterns", keylogHitCount),
			"Multiple text/input monitoring patterns",
			keylogHitCount >= 5,
		))
	}

	// ── 13. Banking app targeting ───────────────────────────────
	if hits, ok := scan.byCat[pcBankingApp]; ok && s.hasAccessibilityService {
		var banks []string
		for _, hit := range hits {
			banks = append(banks, hit.tp.tag)
		}
		s.addThreat(ThreatTypeBankingTrojan, ThreatCritical, 10.0,
			fmt.Sprintf("Direct banking app targeting: %s", strings.Join(banks, ", ")),
			"References banking app package names",
			analysis.Path)
		analysis.Matches = append(analysis.Matches, newMatch(
			types.CategorySecurity, analysis.Path, 0,
			fmt.Sprintf("🚨 BANKING TROJAN: targets %d banking apps", len(banks)),
			strings.Join(banks, ", "),
			true,
		))
	}

	// ── 14. Data exfiltration signal (для threat_aggregator) ────
	// НЕ дублируем C2 детекцию — просто отмечаем флаг для aggregator-а
	if s.screenScrapings > 0 && s.hasInternetPermission && s.hasAccessibilityService {
		s.addThreat(ThreatTypeSpyware, ThreatHigh, 8.5,
			"Data exfiltration risk: screen scraping + internet (verify via C2 detector)",
			"AccessibilityService reads screen + has internet access",
			analysis.Path)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG / ASSET ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func (d *AccessibilityAbuseDetector) detectConfig(ctx *FileDetectContext, analysis *types.FileAnalysis, scan *preScanResult) {
	s := d.state

	geoHits := scan.catCount[pcGeoTarget]
	if geoHits >= 2 {
		s.hasGeoTargeting = true
		if s.hasAccessibilityService {
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path, 0,
				"Geo-targeting config + AccessibilityService — region-specific activation",
				fmt.Sprintf("%d geo-targeting patterns", geoHits),
				true,
			))
		}
	}

	// C2 config patterns
	c2Tags := []string{"command_url", "c2_server", "control_server", "bot_url", "panel_url", "gate_url", "inject_url"}
	for _, tag := range c2Tags {
		lower := strings.ToLower(tag)
		if idx := bytes.Index(ctx.ContentLower, []byte(lower)); idx >= 0 {
			analysis.Matches = append(analysis.Matches, newMatch(
				types.CategorySecurity, analysis.Path,
				lineAt(ctx.LineOffsets, idx),
				"🚨 C2 server configuration: "+tag,
				safeSnippet(ctx.Content, idx, len(tag)+30),
				true,
			))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC API
// ═══════════════════════════════════════════════════════════════════════════════

func (d *AccessibilityAbuseDetector) GetThreats() []AccessibilityThreat {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()

	result := make([]AccessibilityThreat, 0, len(d.state.threats))
	for _, t := range d.state.threats {
		result = append(result, *t)
	}
	return result
}

func (d *AccessibilityAbuseDetector) GetMaxThreatLevel() int {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()

	maxLevel := ThreatNone
	for _, t := range d.state.threats {
		if t.Level > maxLevel {
			maxLevel = t.Level
		}
	}
	return maxLevel
}

func (d *AccessibilityAbuseDetector) GetMaxThreatScore() float64 {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()

	maxScore := 0.0
	for _, t := range d.state.threats {
		if t.Score > maxScore {
			maxScore = t.Score
		}
	}
	return maxScore
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML SIGNALS (normalized)
// ═══════════════════════════════════════════════════════════════════════════════

func (d *AccessibilityAbuseDetector) GetMLSignals() *AccessibilityMLSignal {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()
	s := d.state

	signal := &AccessibilityMLSignal{
		// Raw flags
		HasAccessibilityService: s.hasAccessibilityService,
		HasInternetPermission:   s.hasInternetPermission,
		HasSMSPermissions:       s.hasSMSPermissions,
		HasSystemAlertWindow:    s.hasSystemAlertWindow,
		HasDeviceAdmin:          s.hasDeviceAdmin,
		HasNotificationAccess:   s.hasNotificationAccess,
		HasBootReceiver:         s.hasBootReceiver,
		HasInstallPackages:      s.hasInstallPackages,
		HasUsageStats:           s.hasUsageStats,
		HasFinancialKeywords:    s.hasFinancialKeywords,
		HasCryptoKeywords:       s.hasCryptoKeywords,
		HasCredentialPattern:    s.hasCredentialPattern,
		HasGeoTargeting:         s.hasGeoTargeting,

		// Raw counters
		AccessibilityAPICallCount: s.apiCalls,
		SuspiciousMethodCount:     s.suspiciousMethods,
		OverlayPatternCount:       s.overlayPatterns,
		ClickSimulationCount:      s.clickSimulations,
		ScreenScrapingCount:       s.screenScrapings,
		PackageMonitorCount:       s.packageMonitors,
		KeylogPatternCount:        s.keylogHits,
		NotificationCaptureCount:  s.notificationCaptures,
		GestureInjectionCount:     s.gestureInjections,
		FilesAnalyzed:             s.filesAnalyzed,
	}

	// ── Normalized features ──────────────────────────────────────
	files := float64(max(s.filesAnalyzed, 1))
	signal.NormalizedAPICalls = float64(s.apiCalls) / files
	signal.BehaviorDensity = float64(s.clickSimulations+s.screenScrapings+s.keylogHits) / files
	signal.PermissionRiskScore = s.permissionRiskNormalized()
	signal.ContextRiskScore = s.contextRiskNormalized()

	// ── Combos ───────────────────────────────────────────────────
	signal.DangerousCombos = s.calculateDangerousCombos()
	signal.ComboCount = len(signal.DangerousCombos)

	// ── Score & types ────────────────────────────────────────────
	signal.ThreatScore = s.calculateThreatScore()
	for threatType := range s.threats {
		signal.ThreatTypes = append(signal.ThreatTypes, threatType)
	}

	return signal
}

func (s *accessibilityState) calculateDangerousCombos() []string {
	if !s.hasAccessibilityService {
		return nil
	}

	type comboCheck struct {
		cond bool
		name string
	}

	checks := []comboCheck{
		{s.hasSystemAlertWindow, "accessibility+overlay"},
		{s.hasSMSPermissions, "accessibility+sms"},
		{s.hasDeviceAdmin, "accessibility+device_admin"},
		{s.hasNotificationAccess, "accessibility+notification"},
		{s.hasInternetPermission && s.screenScrapings > 0, "accessibility+internet+scraping"},
		{s.hasFinancialKeywords, "accessibility+financial"},
		{s.hasCryptoKeywords, "accessibility+crypto"},
		{s.hasBootReceiver, "accessibility+boot_persistence"},
		{s.hasInstallPackages, "accessibility+install"},
		{s.hasCamera && s.hasMicrophone, "accessibility+camera+mic"},
		{s.hasKeyguardDisable, "accessibility+keyguard_disable"},
		{s.hasSystemAlertWindow && s.hasFinancialKeywords, "banking_trojan_trifecta"},
		{s.hasSMSPermissions && s.hasNotificationAccess, "complete_2fa_bypass"},
		{s.hasDeviceAdmin && s.hasBootReceiver, "persistent_apt"},
	}

	var combos []string
	for _, c := range checks {
		if c.cond {
			combos = append(combos, c.name)
		}
	}
	return combos
}

// ═══════════════════════════════════════════════════════════════════════════════
// RISK SIGNALS (backward compatible)
// ═══════════════════════════════════════════════════════════════════════════════

func (d *AccessibilityAbuseDetector) GetRiskSignals() map[string]bool {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()
	s := d.state

	return map[string]bool{
		// ── Legacy (backward compatible) ─────────────────────────
		"has_accessibility_service":    s.hasAccessibilityService,
		"has_internet":                 s.hasInternetPermission,
		"has_sms_permissions":          s.hasSMSPermissions,
		"has_system_alert_window":      s.hasSystemAlertWindow,
		"accessibility_internet_combo": s.hasAccessibilityService && s.hasInternetPermission,
		"accessibility_sms_combo":      s.hasAccessibilityService && s.hasSMSPermissions,
		"accessibility_overlay_combo":  s.hasAccessibilityService && s.hasSystemAlertWindow,

		// ── New signals ─────────────────────────────────────────
		"has_device_admin":        s.hasDeviceAdmin,
		"has_notification_access": s.hasNotificationAccess,
		"has_boot_receiver":       s.hasBootReceiver,
		"has_install_packages":    s.hasInstallPackages,
		"has_usage_stats":         s.hasUsageStats,
		"has_camera":              s.hasCamera,
		"has_microphone":          s.hasMicrophone,
		"has_keyguard_disable":    s.hasKeyguardDisable,
		"has_financial_context":   s.hasFinancialKeywords,
		"has_crypto_context":      s.hasCryptoKeywords,
		"has_credential_pattern":  s.hasCredentialPattern,
		"has_geo_targeting":       s.hasGeoTargeting,

		// ── Behavioral ──────────────────────────────────────────
		"has_click_simulation":     s.clickSimulations > 0,
		"has_screen_scraping":      s.screenScrapings > 0,
		"has_keylogging":           s.keylogHits > 0,
		"has_package_monitoring":   s.packageMonitors > 0,
		"has_notification_capture": s.notificationCaptures > 0,
		"has_gesture_injection":    s.gestureInjections > 0,

		// ── Danger combos ───────────────────────────────────────
		"banking_trojan_risk":    s.hasAccessibilityService && s.hasSystemAlertWindow && s.hasFinancialKeywords,
		"complete_2fa_bypass":    s.hasAccessibilityService && s.hasSMSPermissions && s.hasNotificationAccess,
		"ransomware_risk":        s.hasAccessibilityService && s.hasDeviceAdmin && s.hasKeyguardDisable,
		"spyware_risk":           s.hasAccessibilityService && s.screenScrapings > 0 && s.hasInternetPermission,
		"credential_theft_risk":  s.hasAccessibilityService && s.hasCredentialPattern && s.keylogHits > 0,
		"security_killer_risk":   s.hasAccessibilityService && s.packageMonitors > 0,
		"persistent_threat_risk": s.hasAccessibilityService && s.hasBootReceiver && s.hasDeviceAdmin,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RESET
// ═══════════════════════════════════════════════════════════════════════════════

func (d *AccessibilityAbuseDetector) Reset() {
	d.state.mu.Lock()
	defer d.state.mu.Unlock()

	// Replace state contents in place rather than rewriting the struct
	// (which would also reset the mutex we currently hold). Keep the same
	// underlying mutex so the deferred Unlock above stays valid.
	d.state.threats = make(map[string]*AccessibilityThreat)
	d.state.hasAccessibilityService = false
	d.state.hasSystemAlertWindow = false
	d.state.hasDeviceAdmin = false
	d.state.hasSMSPermissions = false
	d.state.hasNotificationAccess = false
	d.state.hasInstallPackages = false
	d.state.hasBootReceiver = false
	d.state.hasKeyguardDisable = false
	d.state.hasInternetPermission = false
	d.state.hasUsageStats = false
	d.state.hasCamera = false
	d.state.hasMicrophone = false
	d.state.hasFinancialKeywords = false
	d.state.hasCryptoKeywords = false
	d.state.hasCredentialPattern = false
	d.state.hasGeoTargeting = false
	d.state.clickSimulations = 0
	d.state.screenScrapings = 0
	d.state.keylogHits = 0
	d.state.packageMonitors = 0
	d.state.gestureInjections = 0
	d.state.notificationCaptures = 0
	d.state.apiCalls = 0
	d.state.suspiciousMethods = 0
	d.state.overlayPatterns = 0
	d.state.filesAnalyzed = 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func findHitByTag(scan *preScanResult, tag string) *patternHit {
	for _, hit := range scan.hits {
		if hit.tp.tag == tag {
			return hit
		}
	}
	return nil
}

func safeSnippet(content []byte, start, length int) string {
	if start < 0 {
		start = 0
	}
	end := start + length
	if end > len(content) {
		end = len(content)
	}
	if start >= len(content) {
		return ""
	}
	snippet := string(content[start:end])
	snippet = strings.ReplaceAll(snippet, "\n", " | ")
	snippet = strings.ReplaceAll(snippet, "\r", "")
	return snippet
}
