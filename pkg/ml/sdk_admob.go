package ml

// ═══════════════════════════════════════════════════════════════════════════════
// ADMOB SDK PATTERN LIBRARY
//
// Google AdMob SDK patterns for ad loading, display, and reward callbacks
// Requirements: 2.1, 2.9, 19.3
// ═══════════════════════════════════════════════════════════════════════════════

// AdMobPatterns — AdMob SDK specific vulnerability patterns
var AdMobPatterns = []VulnerablePattern{
	// ═══════════════════════════════════════════════════════════════════════
	// ADMOB #1 — Ad Loading Methods
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ADMOB_LOAD_AD",
		Category:    PatchCatAds,
		Description: "AdMob ad loading method (loadAd, load)",
		MethodNames: []string{
			"loadad", "load", "requestad", "fetchad",
			"loadinterstitial", "loadrewarded", "loadbanner",
		},
		ClassPatterns: []string{
			"com/google/android/gms/ads",
			"adview", "interstitialad", "rewardedad",
			"adloader", "admanager",
		},
		RequiredCalls: []string{
			"adview;->loadad",
			"interstitialad;->load",
			"rewardedad;->load",
			"adloader;->loadad",
			"adrequest;->build",
		},
		StringPatterns: []string{
			"com.google.android.gms.ads",
			"ca-app-pub-",
			"adrequest",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.0,
		MinMatchScore: 15,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// ADMOB #2 — Ad Display Methods
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ADMOB_SHOW_AD",
		Category:    PatchCatAds,
		Description: "AdMob ad display method (show)",
		MethodNames: []string{
			"show", "showad", "displayad", "presentad",
			"showinterstitial", "showrewarded",
		},
		ClassPatterns: []string{
			"com/google/android/gms/ads",
			"interstitialad", "rewardedad",
			"admanager",
		},
		RequiredCalls: []string{
			"interstitialad;->show",
			"rewardedad;->show",
			"fullscreenad;->show",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.0,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// ADMOB #3 — Reward Video Callback (onUserEarnedReward)
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ADMOB_REWARD_CALLBACK",
		Category:    PatchCatAds,
		Description: "AdMob reward video callback (onUserEarnedReward)",
		MethodNames: []string{
			"onuserearned reward", "onrewarded", "onrewardearned",
			"onrewardedvideoadcompleted", "onrewarditem",
		},
		ClassPatterns: []string{
			"com/google/android/gms/ads",
			"onuserearned rewardlistener", "rewardedadcallback",
			"rewarditem",
		},
		RequiredCalls: []string{
			"rewarditem;->getamount",
			"rewarditem;->gettype",
			"onuserearned reward",
		},
		StringPatterns: []string{
			"reward", "earned", "rewarditem",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        1.2,
		MinMatchScore: 12,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// ADMOB #4 — Ad-Free Status Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ADMOB_AD_FREE_CHECK",
		Category:    PatchCatAds,
		Description: "Checks if ads should be shown (ad-free status)",
		MethodNames: []string{
			"shouldshowads", "isadsenabled", "canadshowad",
			"isadblocked", "hasremovedads", "isadfree",
		},
		ClassPatterns: []string{
			"admanager", "adcontroller", "adhelper",
			"adsettings", "adconfig",
		},
		RequiredCalls: []string{
			"getsharedpreferences",
			"getboolean",
		},
		StringPatterns: []string{
			"show_ads", "ads_enabled", "ad_free",
			"remove_ads", "no_ads",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnFalse,
		Weight:        1.1,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// ADMOB #5 — Ad Loaded Check
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ADMOB_IS_LOADED",
		Category:    PatchCatAds,
		Description: "Checks if ad is loaded and ready to show",
		MethodNames: []string{
			"isloaded", "isadloaded", "isready",
			"canadshow", "isavailable",
		},
		ClassPatterns: []string{
			"com/google/android/gms/ads",
			"interstitialad", "rewardedad",
		},
		RequiredCalls: []string{
			"interstitialad;->isloaded",
			"rewardedad;->isloaded",
		},
		ReturnType:    "Z",
		PatchType:     PatchReturnTrue,
		Weight:        0.8,
		MinMatchScore: 10,
	},

	// ═══════════════════════════════════════════════════════════════════════
	// ADMOB #6 — Ad Callback Listeners
	// ═══════════════════════════════════════════════════════════════════════
	{
		ID:          "ADMOB_AD_LISTENER",
		Category:    PatchCatAds,
		Description: "AdMob ad lifecycle callbacks",
		MethodNames: []string{
			"onadloaded", "onadfailed", "onadopened",
			"onadclosed", "onadclicked", "onadimpression",
		},
		ClassPatterns: []string{
			"com/google/android/gms/ads",
			"adlistener", "fullscreenadcallback",
			"rewardedadloadcallback",
		},
		RequiredCalls: []string{
			"adlistener",
			"loaderror",
		},
		ReturnType:    "V",
		PatchType:     PatchReturnVoid,
		Weight:        0.7,
		MinMatchScore: 10,
	},
}

// AdMobSDKSignatures — detection signatures for AdMob SDK
var AdMobSDKSignatures = SDKSignature{
	PackagePatterns: []string{
		"com/google/android/gms/ads",
		"com/google/ads",
	},
	ClassSignatures: []string{
		"AdView",
		"InterstitialAd",
		"RewardedAd",
		"AdLoader",
		"AdRequest",
		"MobileAds",
		"RewardItem",
		"OnUserEarnedRewardListener",
	},
	MethodSignatures: []string{
		"loadAd",
		"show",
		"onUserEarnedReward",
		"initialize",
	},
}

// SDKSignature — SDK detection signature
type SDKSignature struct {
	PackagePatterns  []string
	ClassSignatures  []string
	MethodSignatures []string
}

// DetectAdMobSDK checks if AdMob SDK is present in the APK
func DetectAdMobSDK(classInfo *ClassInfo) bool {
	classLower := toLowerASCII(classInfo.ClassName)
	pathLower := toLowerASCII(classInfo.FilePath)

	// Check package patterns
	for _, pkg := range AdMobSDKSignatures.PackagePatterns {
		pkgLower := toLowerASCII(pkg)
		if containsSubstring(pathLower, pkgLower) || containsSubstring(classLower, pkgLower) {
			return true
		}
	}

	// Check class signatures
	for _, cls := range AdMobSDKSignatures.ClassSignatures {
		clsLower := toLowerASCII(cls)
		if containsSubstring(classLower, clsLower) {
			return true
		}
	}

	return false
}

// Helper functions
func toLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func containsSubstring(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
