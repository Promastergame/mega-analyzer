package ml

// ═══════════════════════════════════════════════════════════════════════════════
// IRONSOURCE SDK PATTERN LIBRARY
//
// IronSource SDK patterns for mediation, banner, interstitial, and rewarded video
// Requirements: 2.3, 2.9, 19.5
// ═══════════════════════════════════════════════════════════════════════════════

// IronSourcePatterns — IronSource SDK specific vulnerability patterns
var IronSourcePatterns = []VulnerablePattern{
	// ═══════════════════════════════════════════════════════════════════════
	// IRONSOURCE #1 — Initialization
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "IRONSOURCE_INIT",
		Category:    PatchCatAds,
		Description: "IronSource initialization method",
		MethodNames: []string{
			"init", "initialize", "initironsource",
			"setupironsource", "startironsource",
		},
		ClassPatterns: []string{
			"com/ironsource",
			"ironsource", "mediationmanager",
		},
		RequiredCalls: []string{
			"ironsource;->init",
			"ironsource;->setadaptersdebuglevel",
		},
		StringPatterns: []string{
			"com.ironsource",
			"appkey",
			"ironsource",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.9,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// IRONSOURCE #2 — Show Interstitial
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "IRONSOURCE_SHOW_INTERSTITIAL",
		Category:    PatchCatAds,
		Description: "IronSource show interstitial ad",
		MethodNames: []string{
			"showinterstitial", "displayinterstitial",
			"showad", "displayad",
		},
		ClassPatterns: []string{
			"com/ironsource",
			"ironsource", "interstitial",
		},
		RequiredCalls: []string{
			"ironsource;->showinterstitial",
			"ironsource;->isinterstitialready",
		},
		StringPatterns: []string{
			"interstitial", "placementname",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.0,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// IRONSOURCE #3 — Show Rewarded Video
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "IRONSOURCE_SHOW_REWARDED",
		Category:    PatchCatAds,
		Description: "IronSource show rewarded video ad",
		MethodNames: []string{
			"showrewardedvideo", "showrewarded",
			"displayrewardedvideo", "playrewarded",
		},
		ClassPatterns: []string{
			"com/ironsource",
			"ironsource", "rewardedvideo",
		},
		RequiredCalls: []string{
			"ironsource;->showrewardedvideo",
			"ironsource;->isrewardedvideoa vailable",
		},
		StringPatterns: []string{
			"rewardedvideo", "rewarded", "placementname",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.0,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// IRONSOURCE #4 — Rewarded Video Callback (onRewardedVideoAdRewarded)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "IRONSOURCE_REWARD_CALLBACK",
		Category:    PatchCatAds,
		Description: "IronSource rewarded video callback (onRewardedVideoAdRewarded)",
		MethodNames: []string{
			"onrewardedvideoadrewarded", "onrewarded",
			"onrewardreceived", "onuserreward",
		},
		ClassPatterns: []string{
			"com/ironsource",
			"rewardedvideolistener", "rewardedlistener",
		},
		RequiredCalls: []string{
			"placement;->getrewardname",
			"placement;->getrewardamount",
		},
		StringPatterns: []string{
			"reward", "placement", "rewarded",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.2,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// IRONSOURCE #5 — RewardedVideoListener Callbacks
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "IRONSOURCE_REWARDED_LISTENER",
		Category:    PatchCatAds,
		Description: "IronSource rewarded video listener callbacks",
		MethodNames: []string{
			"onrewardedvideoavailabilitychanged",
			"onrewardedvideoadopened", "onrewardedvideoadclosed",
			"onrewardedvideoadstarted", "onrewardedvideoadended",
			"onrewardedvideoadshowfailed",
		},
		ClassPatterns: []string{
			"com/ironsource",
			"rewardedvideolistener",
		},
		RequiredCalls: []string{
			"ironsource",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.8,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// IRONSOURCE #6 — InterstitialListener Callbacks
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "IRONSOURCE_INTERSTITIAL_LISTENER",
		Category:    PatchCatAds,
		Description: "IronSource interstitial listener callbacks",
		MethodNames: []string{
			"oninterstitialadready", "oninterstitialadloadfailed",
			"oninterstitialadopened", "oninterstitialadclosed",
			"oninterstitialadshowsucceeded", "oninterstitialadshowfailed",
			"oninterstitialadclicked",
		},
		ClassPatterns: []string{
			"com/ironsource",
			"interstitiallistener",
		},
		RequiredCalls: []string{
			"ironsource",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.7,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// IRONSOURCE #7 — Banner Methods
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "IRONSOURCE_BANNER",
		Category:    PatchCatAds,
		Description: "IronSource banner ad methods",
		MethodNames: []string{
			"loadbanner", "destroybanner", "isbannerloa ded",
			"showbanner", "hidebanner",
		},
		ClassPatterns: []string{
			"com/ironsource",
			"ironsource", "banner",
		},
		RequiredCalls: []string{
			"ironsource;->loadbanner",
			"ironsource;->destroybanner",
			"isbannersize",
		},
		StringPatterns: []string{
			"banner", "bannerview",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.8,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// IRONSOURCE #8 — Is Available Checks
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "IRONSOURCE_IS_AVAILABLE",
		Category:    PatchCatAds,
		Description: "Checks if IronSource ad is available",
		MethodNames: []string{
			"isrewardedvideoavailable", "isinterstitialready",
			"isavailable", "isready", "canadshow",
		},
		ClassPatterns: []string{
			"com/ironsource",
			"ironsource",
		},
		RequiredCalls: []string{
			"ironsource;->isrewardedvideoavailable",
			"ironsource;->isinterstitialready",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        0.8,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// IRONSOURCE #9 — Mediation Methods
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "IRONSOURCE_MEDIATION",
		Category:    PatchCatAds,
		Description: "IronSource mediation methods",
		MethodNames: []string{
			"setmediation", "getmediation", "mediationinit",
			"setadaptersdebuglevel",
		},
		ClassPatterns: []string{
			"com/ironsource",
			"ironsource", "mediation",
		},
		RequiredCalls: []string{
			"ironsource;->setmediation",
		},
		StringPatterns: []string{
			"mediation", "adapter",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.7,
		MinMatchScore: 10,
	},
}

// IronSourceSDKSignatures — detection signatures for IronSource SDK
var IronSourceSDKSignatures = SDKSignature{
	PackagePatterns: []string{
		"com/ironsource",
	},
	ClassSignatures: []string{
		"IronSource",
		"RewardedVideoListener",
		"InterstitialListener",
		"BannerListener",
		"Placement",
		"IronSourceError",
		"ISBannerSize",
	},
	MethodSignatures: []string{
		"init",
		"showRewardedVideo",
		"showInterstitial",
		"onRewardedVideoAdRewarded",
		"isRewardedVideoAvailable",
	},
}

// DetectIronSourceSDK checks if IronSource SDK is present in the APK
func DetectIronSourceSDK(classInfo *ClassInfo) bool {
	classLower := toLowerASCII(classInfo.ClassName)
	pathLower := toLowerASCII(classInfo.FilePath)

	// Check package patterns
	for _, pkg := range IronSourceSDKSignatures.PackagePatterns {
		pkgLower := toLowerASCII(pkg)
		if containsSubstring(pathLower, pkgLower) || containsSubstring(classLower, pkgLower) {
			return true
		}
	}

	// Check class signatures
	for _, cls := range IronSourceSDKSignatures.ClassSignatures {
		clsLower := toLowerASCII(cls)
		if containsSubstring(classLower, clsLower) {
			return true
		}
	}

	return false
}
