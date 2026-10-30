package ml

// ═══════════════════════════════════════════════════════════════════════════════
// SDK PATTERN INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// ADVANCED THREAT PATTERNS (Phase 6)
// ═══════════════════════════════════════════════════════════════════════════════

var AdvancedPhase6Patterns = []VulnerablePattern{
	{
		ID:             "p43",
		Category:       PatchCatAnalytics,
		Description:    "Bypass Firebase Analytics initialization and event logging",
		MethodNames:    []string{"logEvent", "getInstance", "setAnalyticsCollectionEnabled"},
		ClassPatterns:  []string{"FirebaseAnalytics", "google/firebase/analytics"},
		RequiredCalls:  []string{},
		StringPatterns: []string{"firebase_analytics"},
		ReturnType:     "V",
		PatchType:      PatchReturnVoid,
		Weight:         1.0,
		MinMatchScore:  1.0,
	},
	{
		ID:             "p44",
		Category:       PatchCatAnalytics,
		Description:    "Block attribution SDKs (AppsFlyer/Adjust) from tracking",
		MethodNames:    []string{"start", "onCreate", "trackEvent", "logEvent"},
		ClassPatterns:  []string{"AppsFlyerLib", "Adjust", "appsflyer", "adjust/sdk"},
		RequiredCalls:  []string{},
		StringPatterns: []string{},
		ReturnType:     "V",
		PatchType:      PatchReturnVoid,
		Weight:         1.0,
		MinMatchScore:  1.0,
	},
	{
		ID:             "p45",
		Category:       PatchCatJWTForge,
		Description:    "Bypass JWT token signature validation to forge tokens locally",
		MethodNames:    []string{"verifySignature", "isSignatureValid", "verify"},
		ClassPatterns:  []string{"Signature", "JWT", "TokenValidator"},
		RequiredCalls:  []string{},
		StringPatterns: []string{"signature"},
		ReturnType:     "Z",
		PatchType:      PatchReturnTrue,
		Weight:         1.5,
		MinMatchScore:  1.0,
	},
	{
		ID:             "p46",
		Category:       PatchCatAntiCheat,
		Description:    "Prevent Anti-Cheat engines (e.g. Tencent, EAC, BattlEye) from initializing",
		MethodNames:    []string{"initAntiCheat", "startAntiCheatService", "init", "start"},
		ClassPatterns:  []string{"TssSdk", "AntiCheat", "EAC", "BattlEye"},
		RequiredCalls:  []string{},
		StringPatterns: []string{"anticheat", "tencent"},
		ReturnType:     "V",
		PatchType:      PatchReturnVoid,
		Weight:         1.5,
		MinMatchScore:  1.0,
	},
	{
		ID:             "p47",
		Category:       PatchCatAntiCheat,
		Description:    "Fake Anti-Cheat heartbeat pulses to avoid detection and bans",
		MethodNames:    []string{"sendHeartbeat", "onHeartbeatPulse", "checkConnectionStatus"},
		ClassPatterns:  []string{"Heartbeat", "AntiCheat", "TssSdk"},
		RequiredCalls:  []string{},
		StringPatterns: []string{"heartbeat"},
		ReturnType:     "Z",
		PatchType:      PatchReturnTrue,
		Weight:         1.2,
		MinMatchScore:  1.0,
	},
	{
		ID:             "p48",
		Category:       PatchCatCloudSave,
		Description:    "Bypass cloud save synchronization checks to allow local save modding",
		MethodNames:    []string{"syncWithCloud", "validateCloudSave", "isCloudSaveNewer", "isCloudSyncEnabled"},
		ClassPatterns:  []string{"CloudSave", "SyncManager", "SaveManager"},
		RequiredCalls:  []string{},
		StringPatterns: []string{"cloud_save"},
		ReturnType:     "Z",
		PatchType:      PatchReturnFalse,
		Weight:         1.0,
		MinMatchScore:  1.0,
	},
	{
		ID:             "p49",
		Category:       PatchCatSSLPinning,
		Description:    "Bypass SSL Pinning when enforced via network_security_config.xml",
		MethodNames:    []string{"checkServerTrusted", "getTrustAnchors"},
		ClassPatterns:  []string{"NetworkSecurityTrustManager", "NetworkSecurityConfig"},
		RequiredCalls:  []string{},
		StringPatterns: []string{},
		ReturnType:     "V",
		PatchType:      PatchReturnVoid,
		Weight:         1.5,
		MinMatchScore:  1.0,
	},
	{
		ID:             "p50",
		Category:       PatchCatRootDetect,
		Description:    "Bypass RootBeer library root detection checks",
		MethodNames:    []string{"isRooted", "isRootedWithoutBusyBoxCheck"},
		ClassPatterns:  []string{"RootBeer", "scottyab/rootbeer"},
		RequiredCalls:  []string{},
		StringPatterns: []string{"rootbeer"},
		ReturnType:     "Z",
		PatchType:      PatchReturnFalse,
		Weight:         1.0,
		MinMatchScore:  1.0,
	},
	{
		ID:             "p51",
		Category:       PatchCatEmulatorCheck,
		Description:    "Bypass generic emulator detection using Build.FINGERPRINT and Build.MODEL",
		MethodNames:    []string{"isEmulator", "checkEmulatorBuild", "isDeviceEmulator"},
		ClassPatterns:  []string{"EmulatorDetector", "DeviceUtils", "Build"},
		RequiredCalls:  []string{},
		StringPatterns: []string{"generic", "vbox", "qemu"},
		ReturnType:     "Z",
		PatchType:      PatchReturnFalse,
		Weight:         1.0,
		MinMatchScore:  1.0,
	},
	{
		ID:             "p52",
		Category:       PatchCatEmulatorCheck,
		Description:    "Bypass detection of emulator-specific files (e.g. qemu_trace, genymotion drivers)",
		MethodNames:    []string{"checkEmulatorFiles", "hasEmulatorFiles"},
		ClassPatterns:  []string{"EmulatorDetector", "DeviceUtils"},
		RequiredCalls:  []string{},
		StringPatterns: []string{"qemu_trace", "genymotion", "andy", "nox"},
		ReturnType:     "Z",
		PatchType:      PatchReturnFalse,
		Weight:         1.0,
		MinMatchScore:  1.0,
	},
}

// GetAllPatterns returns all patterns including SDK-specific patterns
func GetAllPatterns() []VulnerablePattern {
	allPatterns := make([]VulnerablePattern, 0, 200)

	// Core patterns
	allPatterns = append(allPatterns, VulnerablePatterns...)

	// Ad SDK patterns
	allPatterns = append(allPatterns, AdMobPatterns...)
	allPatterns = append(allPatterns, UnityAdsPatterns...)
	allPatterns = append(allPatterns, IronSourcePatterns...)
	allPatterns = append(allPatterns, AppLovinPatterns...)
	allPatterns = append(allPatterns, FacebookAudienceNetworkPatterns...)
	allPatterns = append(allPatterns, VunglePatterns...)
	allPatterns = append(allPatterns, AdColonyPatterns...)

	// Billing SDK patterns
	allPatterns = append(allPatterns, BillingV5Patterns...)
	allPatterns = append(allPatterns, BillingV6Patterns...)
	allPatterns = append(allPatterns, BillingV7Patterns...)
	allPatterns = append(allPatterns, AdvancedGatePatterns...)

	// Premium and subscription patterns
	allPatterns = append(allPatterns, PremiumFeaturePatterns...)

	// Currency and time-based restriction patterns (Task 9)
	allPatterns = append(allPatterns, CurrencyTimePatterns...)

	// Advanced Phase 6 patterns (Analytics, AntiCheat, Cloud Save, etc.)
	allPatterns = append(allPatterns, AdvancedPhase6Patterns...)

	// Extra modern-defense patterns (Play Integrity, HMAC, RootBeer, OkHttp pinner, JWT, App Check)
	allPatterns = append(allPatterns, ExtraVulnerablePatterns...)

	// Advanced extra defense patterns (Frida, Play Integrity verdict, CertPinner,
	// KernelSU/APatch, LSPosed, clone/dual-space, speedhack, geo, OAuth, biometric,
	// device-farm, Certificate Transparency) — см. patterns_extra_defense.go
	allPatterns = append(allPatterns, AdvancedExtraPatterns...)

	// Dynamic patterns loaded from API/JSON
	allPatterns = append(allPatterns, GetDynamicMLPatterns()...)

	return canonicalPatterns(allPatterns)
}

// DetectSDK checks which SDKs are present in the APK
func DetectSDK(classInfo *ClassInfo) []string {
	detectedSDKs := make([]string, 0, 10)

	// Ad SDKs
	if DetectAdMobSDK(classInfo) {
		detectedSDKs = append(detectedSDKs, "AdMob")
	}
	if DetectUnityAdsSDK(classInfo) {
		detectedSDKs = append(detectedSDKs, "Unity Ads")
	}
	if DetectIronSourceSDK(classInfo) {
		detectedSDKs = append(detectedSDKs, "IronSource")
	}
	if DetectAppLovinSDK(classInfo) {
		detectedSDKs = append(detectedSDKs, "AppLovin MAX")
	}
	if DetectFacebookAudienceNetworkSDK(classInfo) {
		detectedSDKs = append(detectedSDKs, "Facebook Audience Network")
	}
	if DetectVungleSDK(classInfo) {
		detectedSDKs = append(detectedSDKs, "Vungle")
	}
	if DetectAdColonySDK(classInfo) {
		detectedSDKs = append(detectedSDKs, "AdColony")
	}

	// Billing SDKs
	if DetectBillingV6SDK(classInfo) {
		detectedSDKs = append(detectedSDKs, "Google Play Billing v6")
	} else if DetectBillingV5SDK(classInfo) {
		detectedSDKs = append(detectedSDKs, "Google Play Billing v5")
	}

	return detectedSDKs
}
