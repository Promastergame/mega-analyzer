package ml

// ═══════════════════════════════════════════════════════════════════════════════
// APPLOVIN MAX SDK PATTERN LIBRARY
//
// AppLovin MAX SDK patterns for rewarded ad callbacks
// Requirements: 2.4, 2.9, 19.6
// ═══════════════════════════════════════════════════════════════════════════════

// AppLovinPatterns — AppLovin MAX SDK specific vulnerability patterns
var AppLovinPatterns = []VulnerablePattern{
	// ═══════════════════════════════════════════════════════════════════════
	// APPLOVIN #1 — Initialization
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "APPLOVIN_INIT",
		Category:    PatchCatAds,
		Description: "AppLovin MAX initialization method",
		MethodNames: []string{
			"initialize", "init", "initializesdk",
			"setupapplovin", "startapplovin",
		},
		ClassPatterns: []string{
			"com/applovin",
			"applovin", "maxsdk", "applovinmax",
		},
		RequiredCalls: []string{
			"applovin;->initialize",
			"applovin;->initializesdk",
		},
		StringPatterns: []string{
			"com.applovin",
			"sdkkey",
			"applovin",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.9,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// APPLOVIN #2 — Load Rewarded Ad
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "APPLOVIN_LOAD_REWARDED",
		Category:    PatchCatAds,
		Description: "AppLovin MAX load rewarded ad",
		MethodNames: []string{
			"loadad", "loadrewardedad", "preloadad",
		},
		ClassPatterns: []string{
			"com/applovin",
			"maxrewardedad", "rewardedad",
		},
		RequiredCalls: []string{
			"maxrewardedad;->loadad",
			"maxrewardedad;->getinstance",
		},
		StringPatterns: []string{
			"adunitid", "rewarded",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.9,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// APPLOVIN #3 — Show Rewarded Ad
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "APPLOVIN_SHOW_REWARDED",
		Category:    PatchCatAds,
		Description: "AppLovin MAX show rewarded ad",
		MethodNames: []string{
			"showad", "showrewardedad", "displayad",
		},
		ClassPatterns: []string{
			"com/applovin",
			"maxrewardedad", "rewardedad",
		},
		RequiredCalls: []string{
			"maxrewardedad;->showad",
			"maxrewardedad;->isready",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.0,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// APPLOVIN #4 — MaxRewardedAdListener Callbacks (onUserRewarded)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "APPLOVIN_REWARD_CALLBACK",
		Category:    PatchCatAds,
		Description: "AppLovin MAX reward callback (onUserRewarded)",
		MethodNames: []string{
			"onuserrewarded", "onrewarded", "onrewardreceived",
			"onrewardedvideocompleted",
		},
		ClassPatterns: []string{
			"com/applovin",
			"maxrewardedadlistener", "rewardedadlistener",
		},
		RequiredCalls: []string{
			"maxreward;->getamount",
			"maxreward;->getlabel",
		},
		StringPatterns: []string{
			"reward", "maxreward",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.2,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// APPLOVIN #5 — MaxRewardedAdListener Other Callbacks
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "APPLOVIN_REWARDED_LISTENER",
		Category:    PatchCatAds,
		Description: "AppLovin MAX rewarded ad listener callbacks",
		MethodNames: []string{
			"onadloaded", "onadloadfailed", "onaddisplayed",
			"onaddisplayfailed", "onadclicked", "onadhidden",
		},
		ClassPatterns: []string{
			"com/applovin",
			"maxrewardedadlistener", "maxadlistener",
		},
		RequiredCalls: []string{
			"maxad", "maxerror",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.8,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// APPLOVIN #6 — Interstitial Ad Methods
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "APPLOVIN_INTERSTITIAL",
		Category:    PatchCatAds,
		Description: "AppLovin MAX interstitial ad methods",
		MethodNames: []string{
			"loadad", "showad", "isready",
		},
		ClassPatterns: []string{
			"com/applovin",
			"maxinterstitialad", "interstitialad",
		},
		RequiredCalls: []string{
			"maxinterstitialad;->loadad",
			"maxinterstitialad;->showad",
			"maxinterstitialad;->isready",
		},
		StringPatterns: []string{
			"interstitial", "adunitid",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.9,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// APPLOVIN #7 — Banner Ad Methods
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "APPLOVIN_BANNER",
		Category:    PatchCatAds,
		Description: "AppLovin MAX banner ad methods",
		MethodNames: []string{
			"loadad", "destroy", "startautorefresh",
			"stopautorefresh",
		},
		ClassPatterns: []string{
			"com/applovin",
			"maxadview", "bannerad",
		},
		RequiredCalls: []string{
			"maxadview;->loadad",
			"maxadview;->destroy",
		},
		StringPatterns: []string{
			"banner", "adunitid",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.8,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// APPLOVIN #8 — Is Ready Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "APPLOVIN_IS_READY",
		Category:    PatchCatAds,
		Description: "Checks if AppLovin ad is ready",
		MethodNames: []string{
			"isready", "isadready", "canadshow",
		},
		ClassPatterns: []string{
			"com/applovin",
			"maxrewardedad", "maxinterstitialad",
		},
		RequiredCalls: []string{
			"maxrewardedad;->isready",
			"maxinterstitialad;->isready",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        0.8,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// APPLOVIN #9 — Native Ad Methods
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "APPLOVIN_NATIVE",
		Category:    PatchCatAds,
		Description: "AppLovin MAX native ad methods",
		MethodNames: []string{
			"loadad", "destroy", "renderad",
		},
		ClassPatterns: []string{
			"com/applovin",
			"maxnativeadloader", "nativead",
		},
		RequiredCalls: []string{
			"maxnativeadloader;->loadad",
			"maxnativeadview",
		},
		StringPatterns: []string{
			"native", "adunitid",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.7,
		MinMatchScore: 10,
	},
}

// AppLovinSDKSignatures — detection signatures for AppLovin MAX SDK
var AppLovinSDKSignatures = SDKSignature{
	PackagePatterns: []string{
		"com/applovin",
	},
	ClassSignatures: []string{
		"AppLovinSdk",
		"MaxRewardedAd",
		"MaxInterstitialAd",
		"MaxAdView",
		"MaxRewardedAdListener",
		"MaxAdListener",
		"MaxReward",
		"MaxAd",
		"MaxError",
	},
	MethodSignatures: []string{
		"initialize",
		"loadAd",
		"showAd",
		"onUserRewarded",
		"isReady",
	},
}

// DetectAppLovinSDK checks if AppLovin MAX SDK is present in the APK
func DetectAppLovinSDK(classInfo *ClassInfo) bool {
	classLower := toLowerASCII(classInfo.ClassName)
	pathLower := toLowerASCII(classInfo.FilePath)

	// Check package patterns
	for _, pkg := range AppLovinSDKSignatures.PackagePatterns {
		pkgLower := toLowerASCII(pkg)
		if containsSubstring(pathLower, pkgLower) || containsSubstring(classLower, pkgLower) {
			return true
		}
	}

	// Check class signatures
	for _, cls := range AppLovinSDKSignatures.ClassSignatures {
		clsLower := toLowerASCII(cls)
		if containsSubstring(classLower, clsLower) {
			return true
		}
	}

	return false
}
