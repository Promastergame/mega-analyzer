package ml

import (
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CROSS-LANGUAGE PATTERN SUPPORT
// Detects patterns across Java, Kotlin, React Native, Flutter, Unity
// ═══════════════════════════════════════════════════════════════════════════════

// SourceLanguage represents the detected source language
type SourceLanguage string

const (
	LanguageJava        SourceLanguage = "Java"
	LanguageKotlin      SourceLanguage = "Kotlin"
	LanguageReactNative SourceLanguage = "React Native"
	LanguageFlutter     SourceLanguage = "Flutter"
	LanguageUnity       SourceLanguage = "Unity C#"
	LanguageUnknown     SourceLanguage = "Unknown"
)

// LanguageSignature defines patterns to detect source language
type LanguageSignature struct {
	Language       SourceLanguage
	ClassPatterns  []string
	MethodPatterns []string
	CallPatterns   []string
}

var LanguageSignatures = []LanguageSignature{
	{
		Language: LanguageKotlin,
		ClassPatterns: []string{
			"kotlin/", "kotlinx/",
			"$Companion", "$DefaultImpls",
		},
		MethodPatterns: []string{
			"get-", "set-", "is-",
			"component1", "component2", "component3",
			"$default", "$annotations",
			"invoke$",
		},
		CallPatterns: []string{
			"kotlin/jvm/internal/Intrinsics",
			"kotlin/coroutines/",
		},
	},
	{
		Language: LanguageReactNative,
		ClassPatterns: []string{
			"com/facebook/react/bridge/",
			"com/facebook/react/modules/",
		},
		MethodPatterns: []string{
			"@ReactMethod",
		},
		CallPatterns: []string{
			"ReactApplicationContext",
			"ReactContextBaseJavaModule",
			"WritableMap", "ReadableMap",
			"Promise;->resolve",
			"Promise;->reject",
		},
	},
	{
		Language: LanguageFlutter,
		ClassPatterns: []string{
			"io/flutter/plugin/",
			"io/flutter/embedding/",
		},
		MethodPatterns: []string{
			"onMethodCall",
			"onAttachedToEngine",
			"onDetachedFromEngine",
		},
		CallPatterns: []string{
			"MethodChannel",
			"EventChannel",
			"BasicMessageChannel",
			"MethodCall;->method",
			"Result;->success",
			"Result;->error",
		},
	},
	{
		Language: LanguageUnity,
		ClassPatterns: []string{
			"com/unity3d/player/",
			"UnityPlayer",
		},
		MethodPatterns: []string{
			"UnitySendMessage",
		},
		CallPatterns: []string{
			"UnityPlayer;->UnitySendMessage",
			"UnityPlayer;->currentActivity",
		},
	},
}

// CrossLanguagePattern defines security patterns for specific languages
type CrossLanguagePattern struct {
	Language    SourceLanguage
	Category    PatchCategory
	Description string
	Patterns    []string
	Weight      float64
}

var CrossLanguagePatterns = []CrossLanguagePattern{
	// ── Kotlin Property Accessors ────────────────────────────────────
	{
		Language:    LanguageKotlin,
		Category:    PatchCatPremium,
		Description: "Kotlin property accessor for premium status",
		Patterns: []string{
			"get-isPremium", "get-isPro", "get-isVip",
			"set-isPremium", "set-isPro", "set-isVip",
		},
		Weight: 4.0,
	},
	{
		Language:    LanguageKotlin,
		Category:    PatchCatLicense,
		Description: "Kotlin property accessor for license validation",
		Patterns: []string{
			"get-isLicensed", "get-isValid", "get-isActivated",
			"is-licensed", "is-valid", "is-activated",
		},
		Weight: 4.5,
	},
	{
		Language:    LanguageKotlin,
		Category:    PatchCatPremium,
		Description: "Kotlin property accessor for in-game currency",
		Patterns: []string{
			"get-coins", "get-gems", "get-diamonds",
			"set-coins", "set-gems", "set-diamonds",
		},
		Weight: 3.0,
	},

	// ── Kotlin Companion Objects ─────────────────────────────────────
	{
		Language:    LanguageKotlin,
		Category:    PatchCatPremium,
		Description: "Kotlin companion object singleton for premium checks",
		Patterns: []string{
			"$Companion;->isPremium",
			"$Companion;->checkPremium",
			"$Companion;->getPremiumStatus",
		},
		Weight: 4.0,
	},

	// ── React Native Bridge Methods ──────────────────────────────────
	{
		Language:    LanguageReactNative,
		Category:    PatchCatPremium,
		Description: "React Native bridge method for premium feature access",
		Patterns: []string{
			"checkPremiumStatus", "getPremiumFeatures",
			"unlockPremium", "verifyPremium",
		},
		Weight: 4.0,
	},
	{
		Language:    LanguageReactNative,
		Category:    PatchCatBilling,
		Description: "React Native bridge method for purchase verification",
		Patterns: []string{
			"verifyPurchase", "validateReceipt",
			"checkSubscription", "restorePurchases",
		},
		Weight: 4.5,
	},
	{
		Language:    LanguageReactNative,
		Category:    PatchCatAds,
		Description: "React Native bridge method for ad control",
		Patterns: []string{
			"showAd", "loadAd", "removeAds",
			"checkAdFree", "isAdFree",
		},
		Weight: 3.5,
	},

	// ── Flutter Platform Channels ────────────────────────────────────
	{
		Language:    LanguageFlutter,
		Category:    PatchCatPremium,
		Description: "Flutter platform channel for premium checks",
		Patterns: []string{
			"checkPremium", "getPremiumStatus",
			"verifyPremium", "unlockFeature",
		},
		Weight: 4.0,
	},
	{
		Language:    LanguageFlutter,
		Category:    PatchCatBilling,
		Description: "Flutter platform channel for billing operations",
		Patterns: []string{
			"verifyPurchase", "validateReceipt",
			"queryPurchases", "acknowledgePurchase",
		},
		Weight: 4.5,
	},
	{
		Language:    LanguageFlutter,
		Category:    PatchCatAds,
		Description: "Flutter platform channel for ad operations",
		Patterns: []string{
			"showAd", "loadAd", "hideAd",
			"checkAdStatus", "removeAds",
		},
		Weight: 3.5,
	},

	// ── Unity C# Bridge Methods ──────────────────────────────────────
	{
		Language:    LanguageUnity,
		Category:    PatchCatPremium,
		Description: "Unity bridge method for premium feature control",
		Patterns: []string{
			"CheckPremium", "GetPremiumStatus",
			"UnlockPremium", "IsPremiumUser",
		},
		Weight: 4.0,
	},
	{
		Language:    LanguageUnity,
		Category:    PatchCatBilling,
		Description: "Unity bridge method for IAP verification",
		Patterns: []string{
			"VerifyPurchase", "ValidateReceipt",
			"CheckPurchase", "RestorePurchases",
		},
		Weight: 4.5,
	},
	{
		Language:    LanguageUnity,
		Category:    PatchCatAds,
		Description: "Unity bridge method for ad control",
		Patterns: []string{
			"ShowAd", "LoadAd", "HideAd",
			"RemoveAds", "IsAdFree",
		},
		Weight: 3.5,
	},
	{
		Language:    LanguageUnity,
		Category:    PatchCatPremium,
		Description: "Unity bridge method for currency management",
		Patterns: []string{
			"GetCoins", "SetCoins", "AddCoins",
			"GetGems", "SetGems", "AddGems",
		},
		Weight: 3.0,
	},
}

// DetectSourceLanguage identifies the source language of a method
func DetectSourceLanguage(mi *MethodInfo) SourceLanguage {
	// Check class path first
	classPathLower := strings.ToLower(mi.ClassPath)

	for _, sig := range LanguageSignatures {
		// Check class patterns
		for _, pattern := range sig.ClassPatterns {
			if strings.Contains(classPathLower, strings.ToLower(pattern)) {
				return sig.Language
			}
		}

		// Check method name patterns
		for _, pattern := range sig.MethodPatterns {
			if strings.Contains(mi.NameLower, strings.ToLower(pattern)) {
				return sig.Language
			}
		}

		// Check API call patterns
		for _, call := range mi.Calls {
			for _, pattern := range sig.CallPatterns {
				if strings.Contains(call.FullCall, pattern) {
					return sig.Language
				}
			}
		}
	}

	// Default to Java if no specific language detected
	return LanguageJava
}

// MatchCrossLanguagePatterns checks if method matches cross-language patterns
func MatchCrossLanguagePatterns(mi *MethodInfo, language SourceLanguage) []CrossLanguagePattern {
	var matches []CrossLanguagePattern

	for _, pattern := range CrossLanguagePatterns {
		// Skip if language doesn't match
		if pattern.Language != language {
			continue
		}

		// Check if method name matches any pattern
		for _, p := range pattern.Patterns {
			pLower := strings.ToLower(p)
			if strings.Contains(mi.NameLower, pLower) {
				matches = append(matches, pattern)
				break
			}
		}
	}

	return matches
}

// GetLanguageDescription returns a human-readable description of the language
func GetLanguageDescription(lang SourceLanguage) string {
	switch lang {
	case LanguageKotlin:
		return "Kotlin (property accessors, companion objects)"
	case LanguageReactNative:
		return "React Native (bridge methods)"
	case LanguageFlutter:
		return "Flutter (platform channels)"
	case LanguageUnity:
		return "Unity C# (bridge methods)"
	case LanguageJava:
		return "Java"
	default:
		return "Unknown"
	}
}
