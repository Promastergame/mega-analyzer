package report

import "mega-analyzer/pkg/internal/types"

// PythonPattern паттерн для Python скрипта
type PythonPattern struct {
	Description string            `json:"description"`
	Risk        string            `json:"risk"`
	Category    string            `json:"category"`
	Patterns    []string          `json:"patterns,omitempty"`
	ForceTrue   []string          `json:"force_true,omitempty"`
	ForceFalse  []string          `json:"force_false,omitempty"`
	ForceValue  map[string]string `json:"force_value,omitempty"`
	NopMethods  []string          `json:"nop_methods,omitempty"`
}

// GetPythonPatterns возвращает все паттерны
func GetPythonPatterns() map[string]PythonPattern {
	return map[string]PythonPattern{
		// ═══════════════════════════════════════════════════════════════════
		// LICENSE & VERIFICATION
		// ═══════════════════════════════════════════════════════════════════
		"license_check": {
			Description: "License verification methods",
			Risk:        "low",
			Category:    string(types.CategoryLicenseCheck),
			ForceTrue: []string{
				"isLicensed", "checkLicense", "verifyLicense", "isValidLicense",
				"hasLicense", "isLicenseValid", "validateLicense", "isRegistered",
				"isActivated", "hasValidLicense", "isLicenseOk", "licenseCheck",
				"isLicenseVerified", "checkLicenseStatus", "isLicenseActive",
			},
		},

		"google_lvl": {
			Description: "Google Play Licensing (LVL)",
			Risk:        "low",
			Category:    string(types.CategoryGoogleLVL),
			Patterns: []string{
				`(\.method[^\n]*dontAllow\(I\)V[\s\S]*?)(\.locals\s+\d+)`,
				`(\.method[^\n]*applicationError\(I\)V[\s\S]*?)(\.locals\s+\d+)`,
			},
			ForceTrue: []string{"checkAccess", "isAllowed", "allow"},
		},

		// ═══════════════════════════════════════════════════════════════════
		// IN-APP PURCHASES
		// ═══════════════════════════════════════════════════════════════════
		"purchase_check": {
			Description: "Purchase verification",
			Risk:        "low",
			Category:    string(types.CategoryPurchaseVerify),
			ForceTrue: []string{
				"isPurchased", "hasPurchased", "isProductPurchased", "checkPurchase",
				"verifyPurchase", "hasProduct", "isItemPurchased", "hasBought",
				"wasPurchased", "isOwned", "hasOwned", "ownsProduct", "hasItem",
				"isPurchaseValid", "isValidPurchase", "checkPurchaseStatus",
				"hasInAppPurchase", "isItemOwned", "hasPurchasedItem",
			},
		},

		"subscription": {
			Description: "Subscription status",
			Risk:        "low",
			Category:    string(types.CategorySubscription),
			ForceTrue: []string{
				"isSubscribed", "hasSubscription", "isSubscriptionActive",
				"checkSubscription", "isSubscriber", "hasActiveSubscription",
				"isSubActive", "hasValidSubscription", "isSubscriptionValid",
				"hasActivePlan", "isPlanActive", "isMonthlyActive", "isYearlyActive",
				"hasSubscriptionAccess", "isSubscriptionEnabled",
			},
			ForceFalse: []string{
				"isSubscriptionExpired", "hasSubscriptionExpired",
			},
		},

		// ═══════════════════════════════════════════════════════════════════
		// PREMIUM & PRO
		// ═══════════════════════════════════════════════════════════════════
		"premium_check": {
			Description: "Premium/Pro status",
			Risk:        "low",
			Category:    string(types.CategoryPremiumCheck),
			ForceTrue: []string{
				"isPremium", "isPro", "isProUser", "isPremiumUser", "hasPremium",
				"hasPro", "isVip", "isVipUser", "hasVip", "isGold", "isPlatinum",
				"isUnlocked", "isFullVersion", "hasFullVersion", "isPaid",
				"isPaidUser", "hasPaid", "isProVersion", "isPremiumVersion",
				"isElite", "isDonator", "isDonated", "hasLifetime", "isLifetime",
				"isPremiumActive", "isProActive", "hasProAccess", "hasPremiumAccess",
				"isUpgraded", "hasUpgrade", "checkPremium", "checkPro", "verifyPremium",
				"isPatron", "isSupporter", "hasDonated", "isPremiumMember",
			},
			ForceFalse: []string{
				"needsPremium", "requiresPremium", "requiresPro", "needsPro",
				"requiresUpgrade", "needsUpgrade", "isPremiumRequired",
			},
		},

		"feature_unlock": {
			Description: "Feature availability",
			Risk:        "low",
			Category:    string(types.CategoryPremiumUnlock),
			ForceTrue: []string{
				"isFeatureUnlocked", "isUnlocked", "hasFeature", "isEnabled",
				"isFeatureEnabled", "canUseFeature", "hasAccess", "isAccessible",
				"isAvailable", "isFeatureAvailable", "checkFeature", "canAccess",
				"hasPermission", "isAllowed", "isGranted", "canUse",
			},
			ForceFalse: []string{
				"isFeatureLocked", "isLocked", "isRestricted", "isDisabled",
				"isBlocked", "isFeatureBlocked", "isFeatureRestricted",
			},
		},

		// ═══════════════════════════════════════════════════════════════════
		// TRIAL & EXPIRY
		// ═══════════════════════════════════════════════════════════════════
		"trial_check": {
			Description: "Trial period",
			Risk:        "low",
			Category:    string(types.CategoryTrialCheck),
			ForceTrue: []string{
				"isTrialActive", "hasTrialLeft", "isInTrial", "checkTrial",
				"isTrialValid", "hasRemainingTrial", "isTrialPeriod",
			},
			ForceFalse: []string{
				"isTrialExpired", "hasTrialExpired", "isExpired", "checkExpiry",
				"isTrialEnded", "trialEnded", "isTrialOver", "hasExpired",
				"isLicenseExpired", "isKeyExpired", "isTimeExpired",
			},
			ForceValue: map[string]string{
				"getExpiryDate":    "0x7FFFFFFFFFFFFFFFL",
				"getExpiration":    "0x7FFFFFFFFFFFFFFFL",
				"getRemainingDays": "0x7FFFFFFF",
				"getDaysLeft":      "0x7FFFFFFF",
				"getTrialDaysLeft": "0x7FFFFFFF",
				"getRemainingTime": "0x7FFFFFFFFFFFFFFFL",
			},
		},

		// ═══════════════════════════════════════════════════════════════════
		// ADVERTISEMENTS
		// ═══════════════════════════════════════════════════════════════════
		"ad_boolean": {
			Description: "Ad-free status",
			Risk:        "low",
			Category:    string(types.CategoryAdRemove),
			ForceTrue: []string{
				"isAdFree", "hasNoAds", "isNoAds", "isPremiumNoAds", "hasRemoveAds",
				"isAdsRemoved", "hasAdsRemoved", "noAds", "adsRemoved", "adFree",
				"isAdRemoved", "hasAdRemoval", "isAdDisabled", "shouldHideAds",
				"shouldRemoveAds", "canRemoveAds", "hideAds", "disableAds",
				"isAdsFree", "hasAdsRemoval", "isAdvertFree",
			},
			ForceFalse: []string{
				"shouldShowAd", "shouldShowAds", "canShowAd", "canShowAds",
				"isAdEnabled", "hasAds", "showAds", "displayAds", "isAdsEnabled",
				"needsToShowAd", "shouldDisplayAd", "isTimeToShowAd",
				"shouldShowInterstitial", "shouldShowBanner", "shouldShowRewarded",
				"isAdReady", "hasAdLoaded", "isInterstitialReady",
			},
		},

		"ad_load": {
			Description: "Block ad loading",
			Risk:        "low",
			Category:    string(types.CategoryAdLoad),
			NopMethods: []string{
				"loadAd", "loadBanner", "loadInterstitial", "loadRewardedAd",
				"loadNativeAd", "fetchAd", "requestAd", "preloadAd", "cacheAd",
				"loadRewardedVideo", "loadFullScreenAd", "loadAdView",
				"requestBannerAd", "requestInterstitialAd", "requestRewardedAd",
			},
		},

		"ad_show": {
			Description: "Block ad display",
			Risk:        "low",
			Category:    string(types.CategoryAdShow),
			NopMethods: []string{
				"showAd", "showBanner", "showInterstitial", "showRewardedAd",
				"showNativeAd", "displayAd", "presentAd", "showFullScreenAd",
				"showRewardedVideo", "displayInterstitial", "displayBanner",
				"presentInterstitial", "presentRewarded",
			},
		},

		"ad_init": {
			Description: "Block ad SDK init",
			Risk:        "medium",
			Category:    string(types.CategoryAdInit),
			NopMethods: []string{
				"initialize", "init", "initSdk", "initializeSdk", "configure",
				"setup", "start", "onCreate", "initAds", "setupAds",
			},
		},

		// ═══════════════════════════════════════════════════════════════════
		// SECURITY BYPASS
		// ═══════════════════════════════════════════════════════════════════
		"signature_check": {
			Description: "Signature verification",
			Risk:        "medium",
			Category:    string(types.CategorySignatureCheck),
			ForceTrue: []string{
				"checkSignature", "verifySignature", "isSignatureValid",
				"validateSignature", "isOriginalSignature", "checkAppSignature",
				"isIntegrityOk", "checkIntegrity", "verifyIntegrity",
				"isSignatureMatching", "validateAppSignature",
			},
		},

		"root_detection": {
			Description: "Root detection",
			Risk:        "low",
			Category:    string(types.CategoryRootDetection),
			ForceFalse: []string{
				"isRooted", "isDeviceRooted", "checkRoot", "detectRoot",
				"hasRoot", "isRootAvailable", "checkRootAccess", "isSuAvailable",
				"checkSuBinary", "isRootedDevice", "rootCheck", "hasSuperuser",
				"isMagiskPresent", "checkMagisk", "hasMagisk", "detectMagisk",
				"isRootAccessGiven", "hasRootAccess",
			},
		},

		"emulator_detection": {
			Description: "Emulator detection",
			Risk:        "low",
			Category:    string(types.CategoryEmulatorDetection),
			ForceFalse: []string{
				"isEmulator", "isRunningOnEmulator", "detectEmulator",
				"checkEmulator", "isVirtualDevice", "isVM", "isGenymotion",
				"isBluestacks", "isNox", "isMemu", "isLDPlayer", "isAndroidStudio",
				"isSimulator", "isVirtualBox", "isQemu",
			},
		},

		"debug_detection": {
			Description: "Debug detection",
			Risk:        "low",
			Category:    string(types.CategoryDebugDetection),
			ForceFalse: []string{
				"isDebuggable", "isDebugBuild", "isDebugMode", "detectDebug",
				"checkDebugger", "isBeingDebugged", "isDebuggerAttached",
				"isDebugEnabled", "hasDebugger",
			},
		},

		"tamper_detection": {
			Description: "Tamper detection",
			Risk:        "medium",
			Category:    string(types.CategoryTamperDetection),
			ForceFalse: []string{
				"isTampered", "detectTampering", "checkTamper", "isModified",
				"isApkModified", "checkAppIntegrity", "isRepackaged", "detectRepackage",
				"hasBeenTampered", "isAppModified",
			},
			ForceTrue: []string{
				"isOriginal", "isAuthentic", "isGenuine", "isUnmodified",
			},
		},

		"hook_detection": {
			Description: "Hook detection",
			Risk:        "high",
			Category:    string(types.CategoryAntiHook),
			ForceFalse: []string{
				"isXposedActive", "detectXposed", "checkXposed", "hasXposed",
				"isHooked", "detectHook", "checkHook", "hasHook",
				"isSubstrateActive", "detectSubstrate",
			},
		},

		// ═══════════════════════════════════════════════════════════════════
		// ANALYTICS BLOCK
		// ═══════════════════════════════════════════════════════════════════
		"analytics": {
			Description: "Analytics tracking",
			Risk:        "low",
			Category:    string(types.CategoryFirebaseAnalytics),
			NopMethods: []string{
				"logEvent", "trackEvent", "sendEvent", "recordEvent",
				"track", "log", "send", "report", "setUserProperty",
				"setUserId", "setAnalyticsCollectionEnabled",
			},
		},

		"crashlytics": {
			Description: "Crash reporting",
			Risk:        "low",
			Category:    string(types.CategoryCrashlytics),
			NopMethods: []string{
				"recordException", "logException", "crash", "forceCrash",
				"log", "setCustomKey", "setUserId",
			},
		},
	}
}
