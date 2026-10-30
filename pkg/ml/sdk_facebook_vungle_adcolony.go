package ml

// ═══════════════════════════════════════════════════════════════════════════════
// FACEBOOK AUDIENCE NETWORK, VUNGLE, ADCOLONY SDK PATTERN LIBRARIES
//
// Additional ad SDK patterns for Facebook, Vungle, and AdColony
// Requirements: 2.5, 2.6, 2.7
// ═══════════════════════════════════════════════════════════════════════════════

// FacebookAudienceNetworkPatterns — Facebook Audience Network SDK patterns
var FacebookAudienceNetworkPatterns = []VulnerablePattern{
	// ═══════════════════════════════════════════════════════════════════════
	// FACEBOOK #1 — Rewarded Video Callback
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "FACEBOOK_REWARD_CALLBACK",
		Category:    PatchCatAds,
		Description: "Facebook Audience Network reward callback",
		MethodNames: []string{
			"onrewardedvideocompleted", "onrewarded",
			"onrewardedadcompleted",
		},
		ClassPatterns: []string{
			"com/facebook/ads",
			"rewardedvideoadlistener", "rewardedadlistener",
		},
		RequiredCalls: []string{
			"rewardedvideoad",
		},
		StringPatterns: []string{
			"reward", "completed",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.2,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// FACEBOOK #2 — Ad Loading
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "FACEBOOK_LOAD_AD",
		Category:    PatchCatAds,
		Description: "Facebook Audience Network ad loading",
		MethodNames: []string{
			"loadad", "load", "requestad",
		},
		ClassPatterns: []string{
			"com/facebook/ads",
			"rewardedvideoad", "interstitialad", "adview",
		},
		RequiredCalls: []string{
			"rewardedvideoad;->loadad",
			"interstitialad;->loadad",
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
	// FACEBOOK #3 — Ad Display
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "FACEBOOK_SHOW_AD",
		Category:    PatchCatAds,
		Description: "Facebook Audience Network ad display",
		MethodNames: []string{
			"show", "showad", "displayad",
		},
		ClassPatterns: []string{
			"com/facebook/ads",
			"rewardedvideoad", "interstitialad",
		},
		RequiredCalls: []string{
			"rewardedvideoad;->show",
			"interstitialad;->show",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.0,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// FACEBOOK #4 — Is Loaded Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "FACEBOOK_IS_LOADED",
		Category:    PatchCatAds,
		Description: "Facebook Audience Network ad loaded check",
		MethodNames: []string{
			"isadloaded", "isloaded", "isready",
		},
		ClassPatterns: []string{
			"com/facebook/ads",
			"rewardedvideoad", "interstitialad",
		},
		RequiredCalls: []string{
			"isadloaded",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        0.8,
		MinMatchScore: 10,
	},
}

// VunglePatterns — Vungle SDK patterns
var VunglePatterns = []VulnerablePattern{
	// ═══════════════════════════════════════════════════════════════════════
	// VUNGLE #1 — Initialization
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "VUNGLE_INIT",
		Category:    PatchCatAds,
		Description: "Vungle SDK initialization",
		MethodNames: []string{
			"init", "initialize", "initvungle",
		},
		ClassPatterns: []string{
			"com/vungle",
			"vungle", "vungleapi",
		},
		RequiredCalls: []string{
			"vungle;->init",
			"initcallback",
		},
		StringPatterns: []string{
			"com.vungle",
			"appid",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.9,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// VUNGLE #2 — Play Ad
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "VUNGLE_PLAY_AD",
		Category:    PatchCatAds,
		Description: "Vungle play ad method",
		MethodNames: []string{
			"playad", "play", "showad", "displayad",
		},
		ClassPatterns: []string{
			"com/vungle",
			"vungle", "banners",
		},
		RequiredCalls: []string{
			"vungle;->playad",
			"vungle;->canplayad",
		},
		StringPatterns: []string{
			"placementid",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.0,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// VUNGLE #3 — Reward Callback
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "VUNGLE_REWARD_CALLBACK",
		Category:    PatchCatAds,
		Description: "Vungle reward callback",
		MethodNames: []string{
			"onrewarded", "onrewardedadcompleted",
			"oncompleted",
		},
		ClassPatterns: []string{
			"com/vungle",
			"playadcallback", "rewardedcallback",
		},
		RequiredCalls: []string{
			"placementid",
		},
		StringPatterns: []string{
			"reward", "completed",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.2,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// VUNGLE #4 — Can Play Ad Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "VUNGLE_CAN_PLAY",
		Category:    PatchCatAds,
		Description: "Vungle can play ad check",
		MethodNames: []string{
			"canplayad", "isadplayable", "isready",
		},
		ClassPatterns: []string{
			"com/vungle",
			"vungle",
		},
		RequiredCalls: []string{
			"vungle;->canplayad",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        0.8,
		MinMatchScore: 10,
	},
}

// AdColonyPatterns — AdColony SDK patterns
var AdColonyPatterns = []VulnerablePattern{
	// ═══════════════════════════════════════════════════════════════════════
	// ADCOLONY #1 — Initialization
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ADCOLONY_INIT",
		Category:    PatchCatAds,
		Description: "AdColony SDK initialization",
		MethodNames: []string{
			"configure", "init", "initialize",
		},
		ClassPatterns: []string{
			"com/adcolony",
			"adcolony",
		},
		RequiredCalls: []string{
			"adcolony;->configure",
			"adcolonyappoptions",
		},
		StringPatterns: []string{
			"com.adcolony",
			"appid", "zoneid",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.9,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// ADCOLONY #2 — Request Interstitial
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ADCOLONY_REQUEST_AD",
		Category:    PatchCatAds,
		Description: "AdColony request interstitial ad",
		MethodNames: []string{
			"requestinterstitial", "requestad", "loadad",
		},
		ClassPatterns: []string{
			"com/adcolony",
			"adcolony", "interstitial",
		},
		RequiredCalls: []string{
			"adcolony;->requestinterstitial",
			"adcolonyinterstitiallistener",
		},
		StringPatterns: []string{
			"zoneid",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.9,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// ADCOLONY #3 — Show Ad
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ADCOLONY_SHOW_AD",
		Category:    PatchCatAds,
		Description: "AdColony show ad method",
		MethodNames: []string{
			"show", "showad", "displayad",
		},
		ClassPatterns: []string{
			"com/adcolony",
			"adcolonyinterstitial",
		},
		RequiredCalls: []string{
			"adcolonyinterstitial;->show",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        1.0,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// ADCOLONY #4 — Reward Callback
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ADCOLONY_REWARD_CALLBACK",
		Category:    PatchCatAds,
		Description: "AdColony reward callback",
		MethodNames: []string{
			"onreward", "onrewardreceived", "oncompleted",
		},
		ClassPatterns: []string{
			"com/adcolony",
			"adcolonyrewardlistener", "rewardlistener",
		},
		RequiredCalls: []string{
			"adcolonyzone reward",
		},
		StringPatterns: []string{
			"reward", "success",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.2,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// ADCOLONY #5 — Is Expired Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ADCOLONY_IS_EXPIRED",
		Category:    PatchCatAds,
		Description: "AdColony ad expiration check",
		MethodNames: []string{
			"isexpired", "isvalid", "isready",
		},
		ClassPatterns: []string{
			"com/adcolony",
			"adcolonyinterstitial",
		},
		RequiredCalls: []string{
			"adcolonyinterstitial;->isexpired",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnFalse,
		Weight:        0.8,
		MinMatchScore: 10,
	},
}

// SDK Signatures for detection
var FacebookAudienceNetworkSDKSignatures = SDKSignature{
	PackagePatterns: []string{
		"com/facebook/ads",
	},
	ClassSignatures: []string{
		"RewardedVideoAd",
		"InterstitialAd",
		"AdView",
		"RewardedVideoAdListener",
		"AdListener",
	},
	MethodSignatures: []string{
		"loadAd",
		"show",
		"onRewardedVideoCompleted",
	},
}

var VungleSDKSignatures = SDKSignature{
	PackagePatterns: []string{
		"com/vungle",
	},
	ClassSignatures: []string{
		"Vungle",
		"VungleApiClient",
		"PlayAdCallback",
		"InitCallback",
	},
	MethodSignatures: []string{
		"init",
		"playAd",
		"canPlayAd",
		"onRewarded",
	},
}

var AdColonySDKSignatures = SDKSignature{
	PackagePatterns: []string{
		"com/adcolony",
	},
	ClassSignatures: []string{
		"AdColony",
		"AdColonyInterstitial",
		"AdColonyInterstitialListener",
		"AdColonyRewardListener",
		"AdColonyZoneReward",
	},
	MethodSignatures: []string{
		"configure",
		"requestInterstitial",
		"show",
		"onReward",
	},
}

// Detection functions
func DetectFacebookAudienceNetworkSDK(classInfo *ClassInfo) bool {
	classLower := toLowerASCII(classInfo.ClassName)
	pathLower := toLowerASCII(classInfo.FilePath)

	for _, pkg := range FacebookAudienceNetworkSDKSignatures.PackagePatterns {
		pkgLower := toLowerASCII(pkg)
		if containsSubstring(pathLower, pkgLower) || containsSubstring(classLower, pkgLower) {
			return true
		}
	}

	for _, cls := range FacebookAudienceNetworkSDKSignatures.ClassSignatures {
		clsLower := toLowerASCII(cls)
		if containsSubstring(classLower, clsLower) {
			return true
		}
	}

	return false
}

func DetectVungleSDK(classInfo *ClassInfo) bool {
	classLower := toLowerASCII(classInfo.ClassName)
	pathLower := toLowerASCII(classInfo.FilePath)

	for _, pkg := range VungleSDKSignatures.PackagePatterns {
		pkgLower := toLowerASCII(pkg)
		if containsSubstring(pathLower, pkgLower) || containsSubstring(classLower, pkgLower) {
			return true
		}
	}

	for _, cls := range VungleSDKSignatures.ClassSignatures {
		clsLower := toLowerASCII(cls)
		if containsSubstring(classLower, clsLower) {
			return true
		}
	}

	return false
}

func DetectAdColonySDK(classInfo *ClassInfo) bool {
	classLower := toLowerASCII(classInfo.ClassName)
	pathLower := toLowerASCII(classInfo.FilePath)

	for _, pkg := range AdColonySDKSignatures.PackagePatterns {
		pkgLower := toLowerASCII(pkg)
		if containsSubstring(pathLower, pkgLower) || containsSubstring(classLower, pkgLower) {
			return true
		}
	}

	for _, cls := range AdColonySDKSignatures.ClassSignatures {
		clsLower := toLowerASCII(cls)
		if containsSubstring(classLower, clsLower) {
			return true
		}
	}

	return false
}
