// pkg/internal/types/categories.go
//
// # Mega-Analyzer — Category System (formerly "APK Vision v4.0")
//
// Архитектура:
//   - Category = string enum с O(1) lookup метаданных
//   - CategoryInfo = полные метаданные (приоритет, иконка, цвет, группа)
//   - Группы категорий для агрегации в отчётах
//   - Детерминированный порядок вывода (sort by Priority desc)
//   - Thread-safe: все данные immutable после init
package types

import "sort"

// ═══════════════════════════════════════════════════════════════════════════════
//
//	C A T E G O R Y   T Y P E
//
// ═══════════════════════════════════════════════════════════════════════════════

// Category — тип категории находки.
type Category string

// ═══════════════════════════════════════════════════════════════════════════════
//
//	G R O U P S
//
// ═══════════════════════════════════════════════════════════════════════════════

const (
	GroupLicense      = "License"
	GroupBilling      = "Billing"
	GroupPremium      = "Premium"
	GroupTrial        = "Trial"
	GroupSubscription = "Subscription"
	GroupAds          = "Ads"
	GroupAnalytics    = "Analytics"
	GroupCrashReport  = "Crash Reporting"
	GroupConfig       = "Config"
	GroupSecurity     = "Security"
	GroupThreatRules  = "Threat Rules"
	GroupObfuscation  = "Obfuscation"
	GroupNetwork      = "Network"
	GroupPiracy       = "Piracy"
	GroupTechnical    = "Technical"
	GroupResources    = "Resources"
	GroupOther        = "Other"
)

// GroupInfo описывает группу категорий.
type GroupInfo struct {
	Name        string
	Icon        string
	Description string
	SortOrder   int // меньше = выше в отчёте
}

// AllGroups — все группы в порядке отображения.
var AllGroups = []GroupInfo{
	{Name: GroupLicense, Icon: "🔐", Description: "License verification & validation", SortOrder: 1},
	{Name: GroupBilling, Icon: "💳", Description: "In-app purchases & billing", SortOrder: 2},
	{Name: GroupPremium, Icon: "⭐", Description: "Premium/Pro feature gates", SortOrder: 3},
	{Name: GroupSubscription, Icon: "🔄", Description: "Subscription management", SortOrder: 4},
	{Name: GroupTrial, Icon: "⏰", Description: "Trial periods & expiry", SortOrder: 5},
	{Name: GroupSecurity, Icon: "🛡️", Description: "Security & anti-tampering", SortOrder: 6},
	{Name: GroupPiracy, Icon: "🏴‍☠️", Description: "Piracy & cracking indicators", SortOrder: 7},
	{Name: GroupAds, Icon: "📺", Description: "Advertisement SDKs & logic", SortOrder: 8},
	{Name: GroupAnalytics, Icon: "📊", Description: "Analytics & tracking SDKs", SortOrder: 9},
	{Name: GroupCrashReport, Icon: "💥", Description: "Crash & error reporting SDKs", SortOrder: 10},
	{Name: GroupConfig, Icon: "☁️", Description: "Remote config & feature flags", SortOrder: 10},
	{Name: GroupObfuscation, Icon: "🔤", Description: "Code obfuscation & encryption", SortOrder: 11},
	{Name: GroupNetwork, Icon: "🌐", Description: "Network calls & API keys", SortOrder: 12},
	{Name: GroupTechnical, Icon: "🧩", Description: "Technical components", SortOrder: 13},
	{Name: GroupResources, Icon: "🗂️", Description: "Application resources", SortOrder: 14},
	{Name: GroupThreatRules, Icon: "⚠️", Description: "Rule-based threat detections", SortOrder: 15},
	{Name: GroupOther, Icon: "❓", Description: "Uncategorized findings", SortOrder: 99},
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//	C A T E G O R Y   C O N S T A N T S
//
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// ── License & Verification ───────────────────────────────────────────────
	CategoryLicenseCheck    Category = "license_check"
	CategoryGoogleLVL       Category = "GOOGLE_LVL"
	CategoryLicenseStorage  Category = "LICENSE_STORAGE"
	CategoryLicenseCallback Category = "LICENSE_CALLBACK"

	// ── Billing & Purchases ──────────────────────────────────────────────────
	CategoryBillingClient   Category = "BILLING_CLIENT"
	CategoryPurchaseVerify  Category = "PURCHASE_VERIFY"
	CategoryPurchaseToken   Category = "PURCHASE_TOKEN"
	CategoryBillingCallback Category = "BILLING_CALLBACK"
	CategoryDonation        Category = "donation"

	// ── Premium & Pro ────────────────────────────────────────────────────────
	CategoryPremiumCheck  Category = "PREMIUM_CHECK"
	CategoryPremiumUnlock Category = "PREMIUM_UNLOCK"
	CategoryProFeature    Category = "PRO_FEATURE"

	// ── Trial & Expiry ───────────────────────────────────────────────────────
	CategoryTrialCheck  Category = "TRIAL_CHECK"
	CategoryTrialExpiry Category = "TRIAL_EXPIRY"
	CategoryTimeCheck   Category = "TIME_CHECK"
	CategoryTiming      Category = CategoryTimeCheck // alias

	// ── Subscription ─────────────────────────────────────────────────────────
	CategorySubscription      Category = "SUBSCRIPTION"
	CategoryRecurringPay      Category = "RECURRING_PAY"
	CategorySubscriptionCheck Category = "subscription_check"

	// ── Advertisements — General ─────────────────────────────────────────────
	CategoryAdShow     Category = "ad_show"
	CategoryAdNetwork  Category = "ad_network"
	CategoryAdResource Category = "ad_resource"
	CategoryAdLoad     Category = "AD_LOAD"
	CategoryAdRemove   Category = "AD_REMOVE"
	CategoryAdCheck    Category = "AD_CHECK"
	CategoryAdInit     Category = "AD_INIT"

	// ── Advertisements — Networks ────────────────────────────────────────────
	CategoryAdMob       Category = "ADMOB"
	CategoryUnityAds    Category = "UNITY_ADS"
	CategoryFacebookAds Category = "FACEBOOK_ADS"
	CategoryIronSource  Category = "IRONSOURCE"
	CategoryAppLovin    Category = "APPLOVIN"
	CategoryAdColony    Category = "ADCOLONY"
	CategoryVungle      Category = "VUNGLE"
	CategoryChartboost  Category = "CHARTBOOST"
	CategoryStartApp    Category = "STARTAPP"
	CategoryMintegral   Category = "MINTEGRAL"
	CategoryPangle      Category = "PANGLE"

	// ── Analytics & Tracking ─────────────────────────────────────────────────
	CategoryAnalytics         Category = "ANALYTICS"
	CategoryFirebaseAnalytics Category = "FIREBASE_ANALYTICS"
	CategoryGoogleAnalytics   Category = "GOOGLE_ANALYTICS"
	CategoryFacebookAnalytics Category = "FACEBOOK_ANALYTICS"
	CategoryAmplitude         Category = "AMPLITUDE"
	CategoryMixpanel          Category = "MIXPANEL"
	CategoryAppsFlyer         Category = "APPSFLYER"
	CategoryAdjust            Category = "ADJUST"
	CategoryFlurry            Category = "FLURRY"
	CategoryCrashlytics       Category = "CRASHLYTICS"

	// ── Remote Config & Feature Flags ────────────────────────────────────────
	CategoryRemoteConfig Category = "REMOTE_CONFIG"
	CategoryFeatureFlags Category = "FEATURE_FLAGS"

	// ── Security — Signature & Integrity ─────────────────────────────────────
	CategorySecurity        Category = "SECURITY"
	CategorySignatureCheck  Category = "SIGNATURE_CHECK"
	CategoryIntegrityCheck  Category = "INTEGRITY_CHECK"
	CategoryTamperDetection Category = "TAMPER_DETECTION"
	CategoryHashCheck       Category = "HASH_CHECK"

	// ── Security — Device Detection ──────────────────────────────────────────
	CategoryRootDetection     Category = "ROOT_DETECTION"
	CategoryEmulatorDetection Category = "EMULATOR_DETECTION"
	CategoryDebugDetection    Category = "DEBUG_DETECTION"

	// ── Security — Advanced ──────────────────────────────────────────────────
	CategorySafetyNet     Category = "SAFETYNET"
	CategoryPlayIntegrity Category = "PLAY_INTEGRITY"
	CategorySSLPinning    Category = "SSL_PINNING"
	CategoryCertCheck     Category = "CERT_CHECK"
	CategoryAntiHook      Category = "ANTI_HOOK"
	CategoryAntiXposed    Category = "ANTI_XPOSED"

	// ── Threat Rules ─────────────────────────────────────────────────────────
	CategoryPermissionRule Category = "PERMISSION_RULE"
	CategoryMalwareCombo   Category = "MALWARE_COMBO"
	CategoryBankingThreat  Category = "BANKING_THREAT"

	// ── Obfuscation ──────────────────────────────────────────────────────────
	CategoryObfuscatedString Category = "OBFUSCATED_STRING"
	CategoryObfuscatedCode   Category = "OBFUSCATED_CODE"
	CategoryEncryptedData    Category = "ENCRYPTED_DATA"
	CategoryDynamicLoad      Category = "DYNAMIC_LOAD"
	CategoryPacker           Category = "packer"
	CategoryObfuscator       Category = "obfuscator"
	CategoryDexNetworkLoad   Category = "DEX_NETWORK_LOAD"

	// ── Network & API ────────────────────────────────────────────────────────
	CategoryNetwork         Category = "NETWORK"
	CategoryAPIKey          Category = "API_KEY"
	CategoryServerCheck     Category = "SERVER_CHECK"
	CategoryNetworkCall     Category = "NETWORK_CALL"
	CategoryNetworkEndpoint Category = "NETWORK_ENDPOINT"
	CategoryHardcodedIP     Category = "HARDCODED_IP"
	CategorySuspiciousURL   Category = "SUSPICIOUS_URL"

	// ── Manifest & Custom ────────────────────────────────────────────────────
	CategoryManifestInfo       Category = "MANIFEST_INFO"
	CategoryManifestPermission Category = "MANIFEST_PERMISSION"
	CategoryCustomKeyword      Category = "CUSTOM_KEYWORD"

	// ── Piracy & Cracking ────────────────────────────────────────────────────
	CategoryPiracy       Category = "PIRACY"
	CategoryPiracySite   Category = "PIRACY_SITE"
	CategoryModDetection Category = "MOD_DETECTION"
	CategoryCrackTool    Category = "CRACK_TOOL"
	CategoryPiracyTool   Category = "piracy_tool"

	// ── Technical ────────────────────────────────────────────────────────────
	CategoryCounter                 Category = "COUNTER"
	CategoryNative                  Category = "NATIVE"
	CategoryResource                Category = "RESOURCES"
	CategoryCrypto                  Category = "crypto"
	CategorySuspiciousNativePayload Category = "SUSPICIOUS_NATIVE_PAYLOAD"
	CategoryWebViewRemoteJS         Category = "WEBVIEW_REMOTE_JS"

	// ── Threat Indicators (cross-cutting) ────────────────────────────────────
	CategoryStealerIndicator Category = "STEALER_INDICATOR"
	CategoryAntiAnalysis     Category = "ANTI_ANALYSIS"

	// ── Security heuristics — new categories ─────────────────────────────────
	CategoryMalware       Category = "malware"
	CategoryVulnerability Category = "vulnerability"
	CategoryCredential    Category = "credential"
	CategoryPrivacy       Category = "privacy"
	CategoryRootBypass    Category = "root_bypass"

	// ── Vulnerability classes — new detectors (plan §3) ──────────────────────
	CategoryWeakCrypto           Category = "weak_crypto"
	CategoryHardcodedSecret      Category = "hardcoded_secret"
	CategoryCleartextTraffic     Category = "cleartext_traffic"
	CategoryInsecureTLS          Category = "insecure_tls"
	CategoryExportedComponent    Category = "exported_component"
	CategoryPendingIntentVuln    Category = "pending_intent_vuln"
	CategoryDeepLinkVuln         Category = "deep_link_vuln"
	CategoryJanusVuln            Category = "janus_vuln"
	CategoryStrandHogg           Category = "strand_hogg"
	CategoryZipSlip              Category = "zip_slip"
	CategoryDlopenObfuscation    Category = "dlopen_obfuscation"
	CategoryInsecureBackup       Category = "insecure_backup"
	CategoryPrivilegedPermission Category = "privileged_permission"
	CategoryWebViewFileAccess    Category = "webview_file_access"
	CategoryWebViewJSBridge      Category = "webview_js_bridge"
	CategoryResourceIntegrity    Category = "resource_integrity"
	CategoryStagingEndpoint      Category = "staging_endpoint"
	CategoryIl2cppMetadata       Category = "il2cpp_metadata"
	CategoryWeakSaveIntegrity    Category = "weak_save_integrity"
	CategoryDataPlaintextId      Category = "data_plaintext_id"
	CategoryModMenuInjection     Category = "mod_menu_injection"
	CategoryInsecureStorage      Category = "insecure_storage"

	// ── Low-noise informational categories ───────────────────────────────────
	// MediaAnomaly: a resource file (image/audio) shows a single weak forensic
	// signal (e.g. high entropy) without a second corroborating signal. Kept
	// informational so it never floods the Critical bucket — see plan §1.1.
	CategoryMediaAnomaly Category = "media_anomaly"
	// CrashReporting: error/crash monitoring SDK (Sentry, Bugsnag, …). These are
	// legitimate observability tools, not privacy trackers — see plan §1.3.
	CategoryCrashReporting Category = "crash_reporting"

	// ── Unknown ──────────────────────────────────────────────────────────────
	CategoryUnknown Category = "UNKNOWN"
)

// Aliases for the threat detector category vocabulary.
// Keep these as aliases to avoid duplicating registry entries for the same semantic bucket.
const (
	CategoryDynamicCodeLoad Category = CategoryDynamicLoad
)

// ═══════════════════════════════════════════════════════════════════════════════
//
//	C A T E G O R Y   I N F O
//
// ═══════════════════════════════════════════════════════════════════════════════

// CategoryInfo — полные метаданные категории.
type CategoryInfo struct {
	Name        string // человекочитаемое имя
	Description string // подробное описание
	Group       string // группа для агрегации
	Icon        string // emoji-иконка
	Color       string // цвет для UI (red/orange/yellow/blue/gray)
	Priority    int    // 1-10, выше = важнее
	IsCritical  bool   // требует внимания аналитика
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//	R E G I S T R Y — единый источник правды
//
// ═══════════════════════════════════════════════════════════════════════════════

// ci — сокращение для читаемости таблицы.
type ci = CategoryInfo

var categoryRegistry = map[Category]ci{
	// ┌─────────────────────────┬────────────────────────────────────────────────────────────┬────────────────────┬──────┬─────────┬──────┬──────┬────────┐
	// │ Category                │ Description                                                │ Group              │ Icon │ Color   │ Prio │ Crit │        │
	// ├─────────────────────────┼────────────────────────────────────────────────────────────┼────────────────────┼──────┼─────────┼──────┼──────┤        │
	// LICENSE
	CategoryLicenseCheck:    {"License Check", "License verification entry point", GroupLicense, "🔐", "red", 10, true},
	CategoryGoogleLVL:       {"Google LVL", "Google Play License Verification Library", GroupLicense, "🔐", "red", 10, true},
	CategoryLicenseStorage:  {"License Storage", "License state persistence", GroupLicense, "💾", "orange", 7, true},
	CategoryLicenseCallback: {"License Callback", "License check result handler", GroupLicense, "📞", "orange", 8, true},

	// BILLING
	CategoryBillingClient:   {"Billing Client", "Google Play Billing integration", GroupBilling, "💳", "red", 9, true},
	CategoryPurchaseVerify:  {"Purchase Verify", "Purchase validation logic", GroupBilling, "✅", "red", 9, true},
	CategoryPurchaseToken:   {"Purchase Token", "Purchase token handling", GroupBilling, "🎫", "orange", 8, true},
	CategoryBillingCallback: {"Billing Callback", "Billing result handler", GroupBilling, "🔔", "orange", 8, true},
	CategoryDonation:        {"Donation", "Donations / support payments", GroupBilling, "💝", "gray", 3, false},

	// PREMIUM
	CategoryPremiumCheck:  {"Premium Check", "Premium status verification", GroupPremium, "⭐", "red", 9, true},
	CategoryPremiumUnlock: {"Premium Unlock", "Premium feature unlock logic", GroupPremium, "🔓", "orange", 8, true},
	CategoryProFeature:    {"Pro Feature", "Pro-only feature gate", GroupPremium, "✨", "yellow", 7, false},

	// TRIAL
	CategoryTrialCheck:  {"Trial Check", "Trial period verification", GroupTrial, "⏰", "orange", 8, true},
	CategoryTrialExpiry: {"Trial Expiry", "Trial expiration handling", GroupTrial, "📅", "orange", 8, true},
	CategoryTimeCheck:   {"Time Check", "Time-based validation", GroupTrial, "🕐", "yellow", 6, false},

	// SUBSCRIPTION
	CategorySubscription:      {"Subscription", "Subscription status check", GroupSubscription, "🔄", "red", 9, true},
	CategoryRecurringPay:      {"Recurring Payment", "Recurring payment logic", GroupSubscription, "💰", "orange", 8, true},
	CategorySubscriptionCheck: {"Subscription Check", "Subscription state/verification checks", GroupSubscription, "🔄", "orange", 8, true},

	// ADS — GENERAL
	CategoryAdShow:     {"Ad Show", "Advertisement display", GroupAds, "📺", "yellow", 6, false},
	CategoryAdLoad:     {"Ad Load", "Advertisement loading", GroupAds, "📥", "yellow", 5, false},
	CategoryAdRemove:   {"Ad Remove", "Ad removal / ad-free logic", GroupAds, "🚫", "yellow", 7, false},
	CategoryAdCheck:    {"Ad Check", "Ad display condition", GroupAds, "❓", "yellow", 6, false},
	CategoryAdInit:     {"Ad Init", "Ad SDK initialization", GroupAds, "🎬", "yellow", 5, false},
	CategoryAdNetwork:  {"Ad Network", "Ad network SDK presence (class patterns)", GroupAds, "📡", "yellow", 6, false},
	CategoryAdResource: {"Ad Resource", "Advertisement-related resources/strings", GroupAds, "🗂️", "yellow", 5, false},

	// ADS — NETWORKS
	CategoryAdMob:       {"AdMob", "Google AdMob SDK", GroupAds, "📺", "yellow", 6, false},
	CategoryUnityAds:    {"Unity Ads", "Unity Ads SDK", GroupAds, "🎮", "yellow", 6, false},
	CategoryFacebookAds: {"Facebook Ads", "Meta Audience Network", GroupAds, "👤", "yellow", 6, false},
	CategoryIronSource:  {"IronSource", "IronSource/LevelPlay SDK", GroupAds, "🔩", "yellow", 6, false},
	CategoryAppLovin:    {"AppLovin", "AppLovin MAX SDK", GroupAds, "💜", "yellow", 6, false},
	CategoryAdColony:    {"AdColony", "AdColony SDK", GroupAds, "🏛️", "yellow", 6, false},
	CategoryVungle:      {"Vungle", "Vungle/Liftoff SDK", GroupAds, "🎯", "yellow", 6, false},
	CategoryChartboost:  {"Chartboost", "Chartboost SDK", GroupAds, "📊", "yellow", 6, false},
	CategoryStartApp:    {"StartApp", "StartApp SDK", GroupAds, "🚀", "yellow", 6, false},
	CategoryMintegral:   {"Mintegral", "Mintegral SDK", GroupAds, "🌐", "yellow", 6, false},
	CategoryPangle:      {"Pangle", "Pangle (TikTok) SDK", GroupAds, "🎵", "yellow", 6, false},

	// ANALYTICS
	CategoryAnalytics:         {"Analytics", "Generic analytics", GroupAnalytics, "📊", "gray", 3, false},
	CategoryFirebaseAnalytics: {"Firebase Analytics", "Google Firebase Analytics", GroupAnalytics, "🔥", "gray", 3, false},
	CategoryGoogleAnalytics:   {"Google Analytics", "Google Analytics 4", GroupAnalytics, "📈", "gray", 3, false},
	CategoryFacebookAnalytics: {"Facebook Analytics", "Meta App Events", GroupAnalytics, "👤", "gray", 3, false},
	CategoryAmplitude:         {"Amplitude", "Amplitude Analytics", GroupAnalytics, "📊", "gray", 3, false},
	CategoryMixpanel:          {"Mixpanel", "Mixpanel Analytics", GroupAnalytics, "🔀", "gray", 3, false},
	CategoryAppsFlyer:         {"AppsFlyer", "AppsFlyer Attribution", GroupAnalytics, "✈️", "gray", 3, false},
	CategoryAdjust:            {"Adjust", "Adjust Attribution", GroupAnalytics, "🎚️", "gray", 3, false},
	CategoryFlurry:            {"Flurry", "Yahoo Flurry Analytics", GroupAnalytics, "❄️", "gray", 3, false},

	// VULNERABILITY — new detector classes (plan §3)
	CategoryWeakCrypto:           {"Weak Crypto", "Weak or insecure cryptographic algorithm/config (ECB, static IV, MD5 for hashing passwords)", GroupSecurity, "🔓", "orange", 8, true},
	CategoryHardcodedSecret:      {"Hardcoded Secret", "API key, private key, or credential hardcoded in the APK", GroupSecurity, "🗝️", "red", 9, true},
	CategoryCleartextTraffic:     {"Cleartext Traffic", "HTTP (non-TLS) endpoint or usesCleartextTraffic=true", GroupNetwork, "🌐", "orange", 7, true},
	CategoryInsecureTLS:          {"Insecure TLS", "TrustManager/HostnameVerifier that accepts all certificates", GroupSecurity, "🔓", "red", 9, true},
	CategoryExportedComponent:    {"Exported Component", "Activity/Service/Provider exported without android:permission", GroupSecurity, "📤", "orange", 8, true},
	CategoryPendingIntentVuln:    {"Mutable PendingIntent", "PendingIntent created without FLAG_IMMUTABLE (API ≥ 23 intent-redirection)", GroupSecurity, "📬", "orange", 7, true},
	CategoryDeepLinkVuln:         {"Deep Link Hijack", "Unvalidated deep-link / implicit intent that could be hijacked", GroupSecurity, "🔗", "orange", 7, true},
	CategoryJanusVuln:            {"Janus Vuln", "APK likely signed with v1-only scheme (Janus bypass risk)", GroupSecurity, "⚠️", "red", 8, true},
	CategoryStrandHogg:           {"StrandHogg", "taskAffinity + allowTaskReparenting pattern (task-hijacking risk)", GroupSecurity, "🪝", "orange", 8, true},
	CategoryInsecureBackup:       {"Insecure Backup", "android:allowBackup=true — private app data extractable via adb backup (CWE-312/530)", GroupSecurity, "🔒", "yellow", 5, false},
	CategoryPrivilegedPermission: {"Privileged Permission", "Declares a signature/privileged permission (e.g. DUMP) not grantable to normal apps", GroupSecurity, "🔑", "yellow", 4, false},
	CategoryWebViewFileAccess:    {"WebView File Access", "WebView lets file:// pages read local files / any origin (CWE-200)", GroupSecurity, "🗂", "orange", 8, false},
	CategoryWebViewJSBridge:      {"WebView JS Bridge", "addJavascriptInterface exposes a native bridge to loaded pages", GroupSecurity, "🌉", "orange", 7, false},
	CategoryResourceIntegrity:    {"Resource Integrity", "Security-sensitive trust material shipped as a modifiable resource (repackaging enables MITM)", GroupSecurity, "🛡", "orange", 7, false},
	CategoryStagingEndpoint:      {"Staging Endpoint", "Non-production (staging/pre-prod/UAT) endpoint shipped in a release build (CWE-200 info exposure / widened attack surface)", GroupNetwork, "🧪", "yellow", 6, false},
	CategoryIl2cppMetadata:       {"Unencrypted IL2CPP Metadata", "IL2CPP global-metadata.dat shipped in cleartext (type/method/field names + string literals), enabling trivial reverse engineering, cheating and asset extraction", GroupSecurity, "🧩", "orange", 6, false},
	CategoryWeakSaveIntegrity:    {"Weak Save-File Integrity", "Save file stored in plaintext or reversibly obfuscated with no integrity protection (CWE-311/312) - trivially tampered to cheat or manipulate progress", GroupSecurity, "💾", "orange", 8, false},
	CategoryDataPlaintextId:      {"Plaintext Data Identifier", "Persistent device/user identifier stored in cleartext or analytics tracking enabled-by-default (privacy exposure, CWE-359)", GroupSecurity, "🕵️", "yellow", 4, false},
	CategoryModMenuInjection:     {"Injected Mod-Menu / Hook", "Injected native mod-menu or inline-hooking engine (e.g. Substrate/Dobby, FloatingModMenuService) not present in the original app - hallmark of a repacked cheat/mod build and an embedded-code-injection risk (CWE-506)", GroupSecurity, "🎛️", "red", 10, true},
	CategoryZipSlip:              {"Zip-Slip", "Zip entry extracted to a file path without traversal sanitization (../ path injection)", GroupSecurity, "🗜️", "red", 9, true},
	CategoryDlopenObfuscation:    {"Obfuscated Native Load", "Native library name assembled via string concatenation before dlopen/System.loadLibrary", GroupObfuscation, "🧵", "orange", 7, true},
	CategoryInsecureStorage:      {"Insecure Storage", "Data written to world-readable storage: MODE_WORLD_READABLE/WRITEABLE prefs or files on shared external storage (CWE-312/732)", GroupSecurity, "🗃️", "orange", 8, false},

	// CRASH REPORTING — legitimate observability, not privacy tracking (plan §1.3)
	CategoryCrashlytics:    {"Crashlytics", "Firebase Crashlytics", GroupCrashReport, "💥", "gray", 2, false},
	CategoryCrashReporting: {"Crash Reporting", "Crash/error reporting SDK (Sentry, Bugsnag, …)", GroupCrashReport, "💥", "gray", 2, false},

	// REMOTE CONFIG
	CategoryRemoteConfig: {"Remote Config", "Remote configuration service", GroupConfig, "☁️", "orange", 7, true},
	CategoryFeatureFlags: {"Feature Flags", "Feature flag management", GroupConfig, "🚩", "orange", 7, true},

	// SECURITY — SIGNATURE
	CategorySecurity:        {"Security", "Generic security indicator", GroupSecurity, "🛡️", "orange", 8, true},
	CategorySignatureCheck:  {"Signature Check", "APK signature verification", GroupSecurity, "✍️", "red", 9, true},
	CategoryIntegrityCheck:  {"Integrity Check", "App integrity verification", GroupSecurity, "🛡️", "red", 9, true},
	CategoryTamperDetection: {"Tamper Detection", "Tampering detection logic", GroupSecurity, "🔍", "red", 9, true},
	CategoryHashCheck:       {"Hash Check", "Hash/checksum verification", GroupSecurity, "🔢", "orange", 8, true},

	// SECURITY — DEVICE
	CategoryRootDetection:     {"Root Detection", "Root/jailbreak detection", GroupSecurity, "🌱", "orange", 8, true},
	CategoryEmulatorDetection: {"Emulator Detection", "Emulator environment check", GroupSecurity, "📱", "yellow", 7, false},
	CategoryDebugDetection:    {"Debug Detection", "Debugger attachment check", GroupSecurity, "🐛", "yellow", 7, false},

	// SECURITY — ADVANCED
	CategorySafetyNet:     {"SafetyNet", "Google SafetyNet Attestation", GroupSecurity, "🔒", "red", 10, true},
	CategoryPlayIntegrity: {"Play Integrity", "Play Integrity API", GroupSecurity, "🛡️", "red", 10, true},
	CategorySSLPinning:    {"SSL Pinning", "Certificate pinning", GroupSecurity, "📌", "orange", 8, true},
	CategoryCertCheck:     {"Cert Check", "Certificate validation", GroupSecurity, "📜", "orange", 8, true},
	CategoryAntiHook:      {"Anti-Hook", "Hook/injection detection", GroupSecurity, "🪝", "red", 9, true},
	CategoryAntiXposed:    {"Anti-Xposed", "Xposed framework detection", GroupSecurity, "⚔️", "red", 9, true},

	// THREAT RULES
	CategoryPermissionRule: {"Permission Risk", "Rule-based permission risk detection", GroupThreatRules, "⚠️", "orange", 8, true},
	CategoryMalwareCombo:   {"Malware Combo", "Rule-based malware combination detection", GroupThreatRules, "☣️", "red", 9, true},
	CategoryBankingThreat:  {"Banking Threat", "Rule-based banking threat detection", GroupThreatRules, "💳", "red", 9, true},

	// OBFUSCATION
	CategoryObfuscatedString: {"Obfuscated String", "String obfuscation detected", GroupObfuscation, "🔤", "blue", 5, false},
	CategoryObfuscatedCode:   {"Obfuscated Code", "Obfuscated/encoded payload indicators (e.g., Base64 decode)", GroupObfuscation, "🧩", "orange", 7, true},
	CategoryEncryptedData:    {"Encrypted Data", "Encrypted data storage", GroupObfuscation, "🔐", "blue", 6, false},
	CategoryDynamicLoad:      {"Dynamic Load", "Dynamic class/code loading", GroupObfuscation, "⚡", "orange", 7, true},
	CategoryDexNetworkLoad:   {"DEX From Network", "DEX download + dynamic loading indicators", GroupObfuscation, "⚡", "red", 9, true},
	CategoryPacker:           {"Packer", "Application packer/protector signature", GroupObfuscation, "📦", "red", 9, true},
	CategoryObfuscator:       {"Obfuscator", "Code obfuscator signature", GroupObfuscation, "🔤", "yellow", 5, false},

	// NETWORK
	CategoryNetwork:         {"Network", "Network operations / connectivity signals", GroupNetwork, "🌐", "gray", 4, false},
	CategoryAPIKey:          {"API Key", "Hardcoded API key", GroupNetwork, "🔑", "yellow", 6, false},
	CategoryServerCheck:     {"Server Check", "Server-side validation call", GroupNetwork, "🌐", "orange", 7, true},
	CategoryNetworkCall:     {"Network Call", "HTTP/network request", GroupNetwork, "📡", "gray", 4, false},
	CategoryNetworkEndpoint: {"Network Endpoint", "Hardcoded URL/endpoint (potential server)", GroupNetwork, "🔗", "yellow", 6, false},
	CategoryHardcodedIP:     {"Hardcoded IP", "Hardcoded IPv4 address (potential endpoint/C2)", GroupNetwork, "📍", "orange", 8, true},
	CategorySuspiciousURL:   {"Suspicious URL", "Suspicious URL/C2 indicator (TLD/webhook/etc.)", GroupNetwork, "🕸️", "red", 9, true},

	// MANIFEST & CUSTOM
	CategoryManifestInfo:       {"Manifest Info", "AndroidManifest package/name metadata", GroupTechnical, "🧾", "gray", 3, false},
	CategoryManifestPermission: {"Manifest Permission", "Declared Android permissions in manifest", GroupSecurity, "🛡️", "yellow", 6, false},
	CategoryCustomKeyword:      {"Custom Keyword", "User-specified keyword/IOC hit", GroupOther, "🔎", "yellow", 5, false},

	// PIRACY 🏴‍☠️
	CategoryPiracy:       {"Piracy", "General piracy indicator", GroupPiracy, "🏴‍☠️", "red", 10, true},
	CategoryPiracySite:   {"Piracy Site", "Known piracy site reference", GroupPiracy, "💀", "red", 10, true},
	CategoryModDetection: {"Mod Detection", "Modified/modded APK indicator", GroupPiracy, "🔧", "red", 9, true},
	CategoryCrackTool:    {"Crack Tool", "Known cracking tool reference", GroupPiracy, "⚠️", "red", 10, true},
	CategoryPiracyTool:   {"Piracy Tool", "Piracy/cracking tool reference (e.g., Lucky Patcher)", GroupPiracy, "🛠️", "red", 10, true},

	// TECHNICAL
	CategoryCounter:                 {"Counter", "Usage counter / limit", GroupTechnical, "🔢", "yellow", 5, false},
	CategoryNative:                  {"Native", "Native library (JNI/.so)", GroupTechnical, "🧩", "orange", 7, true},
	CategoryResource:                {"Resource", "Application resource", GroupResources, "🗂️", "gray", 2, false},
	CategoryMediaAnomaly:            {"Media Anomaly", "Resource file with a single weak forensic signal (e.g. high entropy); informational unless corroborated", GroupResources, "🖼️", "gray", 2, false},
	CategoryCrypto:                  {"Crypto", "Cryptocurrency-related keywords/APIs", GroupTechnical, "🪙", "gray", 3, false},
	CategorySuspiciousNativePayload: {"Suspicious Native", "Native payload indicators (network/dynamic-load strings)", GroupTechnical, "🧨", "orange", 8, true},
	CategoryWebViewRemoteJS:         {"WebView Remote JS", "WebView loads remote content/JS", GroupTechnical, "🕸️", "orange", 7, true},

	// THREAT (cross-cutting)
	CategoryStealerIndicator: {"Stealer Indicator", "High-risk data access / exfiltration indicators", GroupSecurity, "🕵️", "red", 9, true},
	CategoryAntiAnalysis:     {"Anti-Analysis", "Anti-debug/anti-hooking/anti-emulator techniques", GroupSecurity, "🛡️", "red", 9, true},

	// UNKNOWN
	CategoryUnknown: {"Unknown", "Uncategorized finding", GroupOther, "❓", "gray", 1, false},
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//	L O O K U P   A P I
//
// ═══════════════════════════════════════════════════════════════════════════════

// unknownInfo — fallback для неизвестных категорий.
var unknownInfo = CategoryInfo{
	Name: "Unknown", Description: "Unknown category",
	Group: GroupOther, Icon: "❓", Color: "gray",
	Priority: 1, IsCritical: false,
}

// GetCategoryInfo возвращает метаданные категории. O(1).
// Всегда возвращает валидный CategoryInfo (never nil-like).
func GetCategoryInfo(cat Category) CategoryInfo {
	if info, ok := categoryRegistry[cat]; ok {
		return info
	}
	// Для динамически созданных категорий — заполняем Name
	fallback := unknownInfo
	fallback.Name = string(cat)
	fallback.Description = string(cat)
	return fallback
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//	Q U E R Y   A P I
//
// ═══════════════════════════════════════════════════════════════════════════════

// GetAllCategories возвращает все зарегистрированные категории.
// Отсортированы по Priority (desc), затем по имени (asc) — детерминированный порядок.
func GetAllCategories() []Category {
	cats := make([]Category, 0, len(categoryRegistry))
	for cat := range categoryRegistry {
		cats = append(cats, cat)
	}
	sortCategories(cats)
	return cats
}

// GetCriticalCategories возвращает только критические категории.
// Отсортированы по Priority desc.
func GetCriticalCategories() []Category {
	cats := make([]Category, 0, 32)
	for cat, info := range categoryRegistry {
		if info.IsCritical {
			cats = append(cats, cat)
		}
	}
	sortCategories(cats)
	return cats
}

// GetCategoriesByGroup возвращает категории указанной группы.
// Отсортированы по Priority desc.
func GetCategoriesByGroup(group string) []Category {
	cats := make([]Category, 0, 16)
	for cat, info := range categoryRegistry {
		if info.Group == group {
			cats = append(cats, cat)
		}
	}
	sortCategories(cats)
	return cats
}

// GetCategoriesByColor возвращает категории по цвету (red/orange/yellow/blue/gray).
func GetCategoriesByColor(color string) []Category {
	cats := make([]Category, 0, 16)
	for cat, info := range categoryRegistry {
		if info.Color == color {
			cats = append(cats, cat)
		}
	}
	sortCategories(cats)
	return cats
}

// GetCategoryCount возвращает общее количество зарегистрированных категорий.
func GetCategoryCount() int {
	return len(categoryRegistry)
}

// IsCategoryRegistered проверяет, зарегистрирована ли категория.
func IsCategoryRegistered(cat Category) bool {
	_, ok := categoryRegistry[cat]
	return ok
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//	G R O U P   S T A T S
//
// ═══════════════════════════════════════════════════════════════════════════════

// GroupStats — статистика по группе для отчёта.
type GroupStats struct {
	Group         string
	Icon          string
	TotalCount    int
	CriticalCount int
	MaxPriority   int
	Categories    []Category
}

// GetGroupStats возвращает статистику по каждой группе из матчей.
// matches — map[Category]count из AnalysisResult.MatchesByCategory.
func GetGroupStats(matches map[Category]int) []GroupStats {
	groupMap := make(map[string]*GroupStats)

	for cat, count := range matches {
		info := GetCategoryInfo(cat)
		gs, ok := groupMap[info.Group]
		if !ok {
			gs = &GroupStats{
				Group: info.Group,
				Icon:  getGroupIcon(info.Group),
			}
			groupMap[info.Group] = gs
		}
		gs.TotalCount += count
		gs.Categories = append(gs.Categories, cat)
		if info.IsCritical {
			gs.CriticalCount += count
		}
		if info.Priority > gs.MaxPriority {
			gs.MaxPriority = info.Priority
		}
	}

	// Конвертируем в slice и сортируем
	result := make([]GroupStats, 0, len(groupMap))
	for _, gs := range groupMap {
		sortCategories(gs.Categories)
		result = append(result, *gs)
	}

	// Сортируем по GroupInfo.SortOrder
	sort.Slice(result, func(i, j int) bool {
		return getGroupSortOrder(result[i].Group) < getGroupSortOrder(result[j].Group)
	})

	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//	C A T E G O R Y   M E T H O D S
//
// ═══════════════════════════════════════════════════════════════════════════════

// String возвращает имя категории.
func (c Category) String() string {
	return GetCategoryInfo(c).Name
}

// Priority возвращает приоритет (1-10).
func (c Category) Priority() int {
	return GetCategoryInfo(c).Priority
}

// IsCritical проверяет, критическая ли категория.
func (c Category) IsCritical() bool {
	return GetCategoryInfo(c).IsCritical
}

// Icon возвращает emoji-иконку.
func (c Category) Icon() string {
	return GetCategoryInfo(c).Icon
}

// Color возвращает цвет для UI.
func (c Category) Color() string {
	return GetCategoryInfo(c).Color
}

// Group возвращает группу категории.
func (c Category) Group() string {
	return GetCategoryInfo(c).Group
}

// ═══════════════════════════════════════════════════════════════════════════════
//
//	I N T E R N A L   H E L P E R S
//
// ═══════════════════════════════════════════════════════════════════════════════

// sortCategories сортирует категории: Priority desc, Name asc.
func sortCategories(cats []Category) {
	sort.Slice(cats, func(i, j int) bool {
		pi := GetCategoryInfo(cats[i]).Priority
		pj := GetCategoryInfo(cats[j]).Priority
		if pi != pj {
			return pi > pj // higher priority first
		}
		return string(cats[i]) < string(cats[j]) // alphabetical
	})
}

// getGroupIcon находит иконку группы.
func getGroupIcon(group string) string {
	for _, g := range AllGroups {
		if g.Name == group {
			return g.Icon
		}
	}
	return "❓"
}

// getGroupSortOrder находит порядок сортировки группы.
func getGroupSortOrder(group string) int {
	for _, g := range AllGroups {
		if g.Name == group {
			return g.SortOrder
		}
	}
	return 99
}
