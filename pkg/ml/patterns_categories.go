package ml

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH PATTERNS — база знаний Assistant для поиска патч-точек
//
// 25 уязвимых паттернов + safe паттерны + scoring rules + patch templates
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH CATEGORY
// ═══════════════════════════════════════════════════════════════════════════════

type PatchCategory string

const (
	PatchCatLicense         PatchCategory = "license_check"
	PatchCatBilling         PatchCategory = "billing"
	PatchCatPremium         PatchCategory = "premium_check"
	PatchCatSubscription    PatchCategory = "subscription"
	PatchCatAds             PatchCategory = "ads"
	PatchCatAgeVerification PatchCategory = "age_verification"
	PatchCatRootDetect      PatchCategory = "root_detection"
	PatchCatEmulatorCheck   PatchCategory = "emulator_detection"
	PatchCatDebugDetect     PatchCategory = "debug_detection"
	PatchCatTamper          PatchCategory = "tamper_detection"
	PatchCatSignature       PatchCategory = "signature_check"
	PatchCatSSLPinning      PatchCategory = "ssl_pinning"
	PatchCatIntegrity       PatchCategory = "integrity_check"
	PatchCatTrialExpiry     PatchCategory = "trial_expiry"
	PatchCatFeatureGate     PatchCategory = "feature_gate"
	PatchCatHookDetect      PatchCategory = "hook_detection"
	PatchCatInstaller       PatchCategory = "installer_check"
	PatchCatServerAuth      PatchCategory = "server_auth"        // 🆕 Server authentication/token validation
	PatchCatDRM             PatchCategory = "drm"                // 🆕 DRM/content protection
	PatchCatCurrency        PatchCategory = "currency"           // 🆕 In-game currency/economy
	PatchCatCloudSave       PatchCategory = "cloud_save"         // Cloud save validation bypass
	PatchCatAntiCheat       PatchCategory = "anti_cheat"         // Anti-cheat SDK bypass
	PatchCatAnalytics       PatchCategory = "analytics"          // Attribution/analytics block
	PatchCatJWTForge        PatchCategory = "jwt_forge"          // JWT token verification bypass
	PatchCatBiometric       PatchCategory = "biometric_auth"     // BiometricPrompt / fingerprint gate
	PatchCatDeviceBinding   PatchCategory = "device_binding"     // Device ID / IMEI binding
	PatchCatHWAttestation   PatchCategory = "hw_attestation"     // TEE / StrongBox attestation
	PatchCatAppClone        PatchCategory = "app_clone"          // Clone app / dual-space
	PatchCatKernelSU        PatchCategory = "kernelsu_apatch"    // KernelSU / APatch root
	PatchCatLSPosed         PatchCategory = "lsposed_riru"       // LSPosed / Riru framework
	PatchCatCertCT          PatchCategory = "cert_transparency"  // Certificate Transparency
	PatchCatOAuth           PatchCategory = "oauth_token"        // OAuth2 / OIDC
	PatchCatGeoBlock        PatchCategory = "geo_block"          // Geographic restriction
	PatchCatDeviceFarm      PatchCategory = "device_farm"        // Device farm / automation
	PatchCatSpeedHack       PatchCategory = "speed_hack"         // Game speed hack
	PatchCatOverlay         PatchCategory = "screen_overlay"     // Screen overlay
	PatchCatVirtualSpace    PatchCategory = "virtual_space"      // VirtualApp / Island
	PatchCatNetSecPolicy    PatchCategory = "net_sec_policy"     // Network Security Config
	PatchCatObfuscKey       PatchCategory = "obfusc_license_key" // Obfuscated key check
	PatchCatMemoryScan      PatchCategory = "memory_scan"        // Memory integrity scan
	PatchCatFirebaseCheck   PatchCategory = "firebase_app_check" // Firebase App Check
)

// CategoryInfo — описание категории
type CategoryInfo struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"` // critical, high, medium
	Weight      float64 `json:"weight"`   // множитель для score
}

// AllCategories — информация о всех категориях
var AllCategories = map[PatchCategory]CategoryInfo{
	PatchCatLicense: {
		Name:        "License Check",
		Description: "Verifies if app is licensed/purchased",
		Severity:    "critical",
		Weight:      4.0,
	},
	PatchCatBilling: {
		Name:        "Billing/Purchase",
		Description: "In-app billing and purchase verification",
		Severity:    "critical",
		Weight:      4.0,
	},
	PatchCatPremium: {
		Name:        "Premium Check",
		Description: "Checks if user has premium/pro status",
		Severity:    "critical",
		Weight:      3.8,
	},
	PatchCatSubscription: {
		Name:        "Subscription",
		Description: "Subscription status verification",
		Severity:    "critical",
		Weight:      3.8,
	},
	PatchCatAds: {
		Name:        "Ad Control",
		Description: "Ad display and loading logic",
		Severity:    "high",
		Weight:      2.5,
	},
	PatchCatAgeVerification: {
		Name:        "Age Verification",
		Description: "Age, adult-content, and COPPA-style access gates",
		Severity:    "medium",
		Weight:      2.5,
	},
	PatchCatRootDetect: {
		Name:        "Root Detection",
		Description: "Checks if device is rooted",
		Severity:    "high",
		Weight:      3.0,
	},
	PatchCatEmulatorCheck: {
		Name:        "Emulator Detection",
		Description: "Checks if running on emulator",
		Severity:    "high",
		Weight:      3.0,
	},
	PatchCatDebugDetect: {
		Name:        "Debug Detection",
		Description: "Checks if debugger is attached",
		Severity:    "high",
		Weight:      2.8,
	},
	PatchCatTamper: {
		Name:        "Tamper Detection",
		Description: "Detects APK modification",
		Severity:    "high",
		Weight:      3.2,
	},
	PatchCatSignature: {
		Name:        "Signature Verification",
		Description: "Verifies APK signing certificate",
		Severity:    "critical",
		Weight:      3.5,
	},
	PatchCatSSLPinning: {
		Name:        "SSL Pinning",
		Description: "Certificate pinning for network security",
		Severity:    "high",
		Weight:      2.5,
	},
	PatchCatIntegrity: {
		Name:        "Integrity Check",
		Description: "Verifies app file integrity (CRC/hash)",
		Severity:    "high",
		Weight:      3.0,
	},
	PatchCatTrialExpiry: {
		Name:        "Trial Expiry",
		Description: "Time-based trial period check",
		Severity:    "critical",
		Weight:      3.5,
	},
	PatchCatFeatureGate: {
		Name:        "Feature Gate",
		Description: "Feature unlock/lock check",
		Severity:    "high",
		Weight:      3.0,
	},
	PatchCatHookDetect: {
		Name:        "Hook Detection",
		Description: "Detects Frida/Xposed/hooking frameworks",
		Severity:    "high",
		Weight:      3.0,
	},
	PatchCatInstaller: {
		Name:        "Installer Verification",
		Description: "Checks if installed from Play Store",
		Severity:    "medium",
		Weight:      2.0,
	},
	// 🆕 NEW CATEGORIES FOR MONEY/SERVER/DRM HACKING
	PatchCatServerAuth: {
		Name:        "Server Authentication",
		Description: "Server-side token/session validation",
		Severity:    "critical",
		Weight:      4.2,
	},
	PatchCatDRM: {
		Name:        "DRM/Content Protection",
		Description: "Digital rights management and content encryption",
		Severity:    "critical",
		Weight:      4.0,
	},
	PatchCatCurrency: {
		Name:        "Currency/Economy",
		Description: "In-game currency, coins, gems manipulation",
		Severity:    "critical",
		Weight:      3.9,
	},
	PatchCatCloudSave: {
		Name:        "Cloud Save",
		Description: "Cloud save validation and sync bypass",
		Severity:    "high",
		Weight:      2.8,
	},
	PatchCatAntiCheat: {
		Name:        "Anti-Cheat SDK",
		Description: "Anti-cheat engine detection bypass",
		Severity:    "high",
		Weight:      3.2,
	},
	PatchCatAnalytics: {
		Name:        "Analytics Block",
		Description: "Attribution and analytics event blocking",
		Severity:    "low",
		Weight:      0.5,
	},
	PatchCatJWTForge: {
		Name:        "JWT Forge",
		Description: "JWT token signature verification bypass",
		Severity:    "critical",
		Weight:      4.3,
	},
	PatchCatBiometric: {
		Name:        "Biometric Auth Bypass",
		Description: "BiometricPrompt / FingerprintManager authentication gate",
		Severity:    "high",
		Weight:      3.5,
	},
	PatchCatDeviceBinding: {
		Name:        "Device Binding Bypass",
		Description: "Device ID / IMEI hardware binding check",
		Severity:    "high",
		Weight:      3.8,
	},
	PatchCatHWAttestation: {
		Name:        "Hardware Attestation Bypass",
		Description: "TEE / StrongBox / Android Keystore attestation",
		Severity:    "critical",
		Weight:      4.5,
	},
	PatchCatAppClone: {
		Name:        "Clone App Detection Bypass",
		Description: "Dual-space / parallel space / clone app detection",
		Severity:    "medium",
		Weight:      2.5,
	},
	PatchCatKernelSU: {
		Name:        "KernelSU / APatch Bypass",
		Description: "KernelSU / APatch / Zygisk Next root detection",
		Severity:    "high",
		Weight:      3.2,
	},
	PatchCatLSPosed: {
		Name:        "LSPosed / Riru Bypass",
		Description: "LSPosed / Riru / EdXposed framework detection",
		Severity:    "high",
		Weight:      3.0,
	},
	PatchCatCertCT: {
		Name:        "Certificate Transparency Bypass",
		Description: "OkHttp CTPolicy / SCT validation bypass",
		Severity:    "high",
		Weight:      2.8,
	},
	PatchCatOAuth: {
		Name:        "OAuth2 Token Bypass",
		Description: "OAuth2 / OpenID Connect token validation bypass",
		Severity:    "critical",
		Weight:      4.2,
	},
	PatchCatGeoBlock: {
		Name:        "Geo-Block Bypass",
		Description: "Geographic region-lock / country restriction",
		Severity:    "medium",
		Weight:      2.0,
	},
	PatchCatDeviceFarm: {
		Name:        "Device Farm Detection Bypass",
		Description: "UIAutomator / device farm / automation detection",
		Severity:    "medium",
		Weight:      2.2,
	},
	PatchCatSpeedHack: {
		Name:        "Speed Hack Detection Bypass",
		Description: "Game speed-hack / frame-time manipulation detection",
		Severity:    "high",
		Weight:      3.0,
	},
	PatchCatOverlay: {
		Name:        "Screen Overlay Detection Bypass",
		Description: "canDrawOverlays / TYPE_APPLICATION_OVERLAY detection",
		Severity:    "medium",
		Weight:      2.3,
	},
	PatchCatVirtualSpace: {
		Name:        "Virtual Space Detection Bypass",
		Description: "VirtualApp / VirtualXposed / Island virtual space",
		Severity:    "high",
		Weight:      2.8,
	},
	PatchCatNetSecPolicy: {
		Name:        "Network Security Policy Bypass",
		Description: "Network Security Config CT / cleartext policy",
		Severity:    "high",
		Weight:      2.5,
	},
	PatchCatObfuscKey: {
		Name:        "Obfuscated License Key Bypass",
		Description: "Encrypted / obfuscated license key validation",
		Severity:    "critical",
		Weight:      4.0,
	},
	PatchCatMemoryScan: {
		Name:        "Memory Scan Bypass",
		Description: "In-process memory integrity / anti-cheat memory scan",
		Severity:    "high",
		Weight:      3.3,
	},
	PatchCatFirebaseCheck: {
		Name:        "Firebase App Check Bypass",
		Description: "Firebase App Check token validation",
		Severity:    "critical",
		Weight:      4.1,
	},
}
