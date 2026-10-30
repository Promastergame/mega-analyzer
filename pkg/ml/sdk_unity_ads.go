package ml

// ═══════════════════════════════════════════════════════════════════════════════
// UNITY ADS SDK PATTERN LIBRARY
//
// Unity Ads SDK patterns for initialization, show, and reward callbacks
// Requirements: 2.2, 2.9, 19.4
// ═══════════════════════════════════════════════════════════════════════════════

// UnityAdsPatterns — Unity Ads SDK specific vulnerability patterns
var UnityAdsPatterns = []VulnerablePattern{
	// ═══════════════════════════════════════════════════════════════════════
	// UNITY ADS #1 — Initialization
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "UNITY_ADS_INIT",
		Category:    PatchCatAds,
		Description: "Unity Ads initialization method",
		MethodNames: []string{
			"initialize", "init", "initializeads",
			"setupunityads", "startunityads",
		},
		ClassPatterns: []string{
			"com/unity3d/ads",
			"unityads", "adsmanager",
		},
		RequiredCalls: []string{
			"unityads;->initialize",
			"unityads;->setdebugmode",
		},
		StringPatterns: []string{
			"com.unity3d.ads",
			"unity_ads",
			"gameid",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.9,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// UNITY ADS #2 — Show Ad
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "UNITY_ADS_SHOW",
		Category:    PatchCatAds,
		Description: "Unity Ads show method",
		MethodNames: []string{
			"show", "showad", "displayad",
			"showvideo", "showrewarded",
		},
		ClassPatterns: []string{
			"com/unity3d/ads",
			"unityads",
		},
		RequiredCalls: []string{
			"unityads;->show",
			"iunityadsshowlistener",
		},
		StringPatterns: []string{
			"video", "rewarded", "interstitial",
			"placementid",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.0,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// UNITY ADS #3 — Load Ad
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "UNITY_ADS_LOAD",
		Category:    PatchCatAds,
		Description: "Unity Ads load method",
		MethodNames: []string{
			"load", "loadad", "preload",
			"loadplacement",
		},
		ClassPatterns: []string{
			"com/unity3d/ads",
			"unityads",
		},
		RequiredCalls: []string{
			"unityads;->load",
			"iunityadsloadlistener",
		},
		StringPatterns: []string{
			"placementid",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.9,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// UNITY ADS #4 — Reward Callback (onUnityAdsShowComplete)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "UNITY_ADS_REWARD_CALLBACK",
		Category:    PatchCatAds,
		Description: "Unity Ads reward callback (onUnityAdsShowComplete)",
		MethodNames: []string{
			"onunityadsshowcomplete", "onshowcomplete",
			"onvideocomplete", "onrewardcomplete",
		},
		ClassPatterns: []string{
			"com/unity3d/ads",
			"iunityadsshowlistener", "unityadslistener",
		},
		RequiredCalls: []string{
			"unityadsshowcompletionstate",
			"completed",
		},
		StringPatterns: []string{
			"completed", "skipped", "reward",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.2,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// UNITY ADS #5 — IUnityAdsShowListener Callbacks
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "UNITY_ADS_SHOW_LISTENER",
		Category:    PatchCatAds,
		Description: "Unity Ads show listener callbacks",
		MethodNames: []string{
			"onunityadsshowstart", "onunityadsshowclick",
			"onunityadsshowfailure", "onshowstart",
			"onshowfailure",
		},
		ClassPatterns: []string{
			"com/unity3d/ads",
			"iunityadsshowlistener",
		},
		RequiredCalls: []string{
			"unityads",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.8,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// UNITY ADS #6 — IUnityAdsLoadListener Callbacks
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "UNITY_ADS_LOAD_LISTENER",
		Category:    PatchCatAds,
		Description: "Unity Ads load listener callbacks",
		MethodNames: []string{
			"onunityadsadloaded", "onunityadsloadfailed",
			"onadloaded", "onloadfailed",
		},
		ClassPatterns: []string{
			"com/unity3d/ads",
			"iunityadsloadlistener",
		},
		RequiredCalls: []string{
			"unityads",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.7,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// UNITY ADS #7 — Is Ready Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "UNITY_ADS_IS_READY",
		Category:    PatchCatAds,
		Description: "Checks if Unity Ads is ready to show",
		MethodNames: []string{
			"isready", "isinitialized", "canadshow",
			"isavailable",
		},
		ClassPatterns: []string{
			"com/unity3d/ads",
			"unityads",
		},
		RequiredCalls: []string{
			"unityads;->isready",
			"unityads;->isinitialized",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        0.8,
		MinMatchScore: 10,
	},
}

// UnityAdsSDKSignatures — detection signatures for Unity Ads SDK
var UnityAdsSDKSignatures = SDKSignature{
	PackagePatterns: []string{
		"com/unity3d/ads",
		"com/unity3d/services",
	},
	ClassSignatures: []string{
		"UnityAds",
		"IUnityAdsShowListener",
		"IUnityAdsLoadListener",
		"IUnityAdsInitializationListener",
		"UnityAdsShowCompletionState",
		"UnityAdsLoadError",
		"UnityAdsShowError",
	},
	MethodSignatures: []string{
		"initialize",
		"show",
		"load",
		"onUnityAdsShowComplete",
		"isReady",
	},
}

// DetectUnityAdsSDK checks if Unity Ads SDK is present in the APK
func DetectUnityAdsSDK(classInfo *ClassInfo) bool {
	classLower := toLowerASCII(classInfo.ClassName)
	pathLower := toLowerASCII(classInfo.FilePath)

	// Check package patterns
	for _, pkg := range UnityAdsSDKSignatures.PackagePatterns {
		pkgLower := toLowerASCII(pkg)
		if containsSubstring(pathLower, pkgLower) || containsSubstring(classLower, pkgLower) {
			return true
		}
	}

	// Check class signatures
	for _, cls := range UnityAdsSDKSignatures.ClassSignatures {
		clsLower := toLowerASCII(cls)
		if containsSubstring(classLower, clsLower) {
			return true
		}
	}

	return false
}
