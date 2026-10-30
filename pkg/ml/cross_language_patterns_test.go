package ml

import (
	"testing"
)

func TestDetectSourceLanguage_Kotlin(t *testing.T) {
	tests := []struct {
		name     string
		mi       *MethodInfo
		expected SourceLanguage
	}{
		{
			name: "Kotlin property accessor",
			mi: &MethodInfo{
				Name:      "get-isPremium",
				NameLower: "get-ispremium",
				ClassPath: "Lcom/example/PremiumManager;",
			},
			expected: LanguageKotlin,
		},
		{
			name: "Kotlin companion object",
			mi: &MethodInfo{
				Name:      "isPremium",
				NameLower: "ispremium",
				ClassPath: "Lcom/example/PremiumManager$Companion;",
			},
			expected: LanguageKotlin,
		},
		{
			name: "Kotlin package",
			mi: &MethodInfo{
				Name:      "checkPremium",
				NameLower: "checkpremium",
				ClassPath: "Lkotlin/collections/List;",
			},
			expected: LanguageKotlin,
		},
		{
			name: "React Native bridge",
			mi: &MethodInfo{
				Name:      "checkPremiumStatus",
				NameLower: "checkpremiumstatus",
				ClassPath: "Lcom/facebook/react/bridge/ReactMethod;",
			},
			expected: LanguageReactNative,
		},
		{
			name: "Flutter platform channel",
			mi: &MethodInfo{
				Name:      "onMethodCall",
				NameLower: "onmethodcall",
				ClassPath: "Lio/flutter/plugin/common/MethodChannel;",
			},
			expected: LanguageFlutter,
		},
		{
			name: "Unity bridge",
			mi: &MethodInfo{
				Name:      "CheckPremium",
				NameLower: "checkpremium",
				ClassPath: "Lcom/unity3d/player/UnityPlayer;",
			},
			expected: LanguageUnity,
		},
		{
			name: "Regular Java",
			mi: &MethodInfo{
				Name:      "checkPremium",
				NameLower: "checkpremium",
				ClassPath: "Lcom/example/PremiumManager;",
			},
			expected: LanguageJava,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectSourceLanguage(tt.mi)
			if result != tt.expected {
				t.Errorf("DetectSourceLanguage() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMatchCrossLanguagePatterns_Kotlin(t *testing.T) {
	mi := &MethodInfo{
		Name:      "get-isPremium",
		NameLower: "get-ispremium",
		ClassPath: "Lcom/example/PremiumManager;",
	}

	matches := MatchCrossLanguagePatterns(mi, LanguageKotlin)

	if len(matches) == 0 {
		t.Fatal("Expected at least one match for Kotlin premium property accessor")
	}

	if matches[0].Category != PatchCatPremium {
		t.Errorf("Expected category %v, got %v", PatchCatPremium, matches[0].Category)
	}
}

func TestMatchCrossLanguagePatterns_ReactNative(t *testing.T) {
	mi := &MethodInfo{
		Name:      "verifyPurchase",
		NameLower: "verifypurchase",
		ClassPath: "Lcom/facebook/react/bridge/ReactMethod;",
	}

	matches := MatchCrossLanguagePatterns(mi, LanguageReactNative)

	if len(matches) == 0 {
		t.Fatal("Expected at least one match for React Native purchase verification")
	}

	if matches[0].Category != PatchCatBilling {
		t.Errorf("Expected category %v, got %v", PatchCatBilling, matches[0].Category)
	}
}

func TestMatchCrossLanguagePatterns_Flutter(t *testing.T) {
	mi := &MethodInfo{
		Name:      "showAd",
		NameLower: "showad",
		ClassPath: "Lio/flutter/plugin/common/MethodChannel;",
	}

	matches := MatchCrossLanguagePatterns(mi, LanguageFlutter)

	if len(matches) == 0 {
		t.Fatal("Expected at least one match for Flutter ad display")
	}

	if matches[0].Category != PatchCatAds {
		t.Errorf("Expected category %v, got %v", PatchCatAds, matches[0].Category)
	}
}

func TestMatchCrossLanguagePatterns_Unity(t *testing.T) {
	mi := &MethodInfo{
		Name:      "GetCoins",
		NameLower: "getcoins",
		ClassPath: "Lcom/unity3d/player/UnityPlayer;",
	}

	matches := MatchCrossLanguagePatterns(mi, LanguageUnity)

	if len(matches) == 0 {
		t.Fatal("Expected at least one match for Unity currency getter")
	}

	if matches[0].Category != PatchCatPremium {
		t.Errorf("Expected category %v, got %v", PatchCatPremium, matches[0].Category)
	}
}

func TestGetLanguageDescription(t *testing.T) {
	tests := []struct {
		lang     SourceLanguage
		expected string
	}{
		{LanguageKotlin, "Kotlin (property accessors, companion objects)"},
		{LanguageReactNative, "React Native (bridge methods)"},
		{LanguageFlutter, "Flutter (platform channels)"},
		{LanguageUnity, "Unity C# (bridge methods)"},
		{LanguageJava, "Java"},
		{LanguageUnknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(string(tt.lang), func(t *testing.T) {
			result := GetLanguageDescription(tt.lang)
			if result != tt.expected {
				t.Errorf("GetLanguageDescription(%v) = %v, want %v", tt.lang, result, tt.expected)
			}
		})
	}
}

func TestCrossLanguagePatterns_NotEmpty(t *testing.T) {
	if len(CrossLanguagePatterns) == 0 {
		t.Fatal("CrossLanguagePatterns should not be empty")
	}

	// Verify we have patterns for each language
	languageCounts := make(map[SourceLanguage]int)
	for _, pattern := range CrossLanguagePatterns {
		languageCounts[pattern.Language]++
	}

	expectedLanguages := []SourceLanguage{
		LanguageKotlin,
		LanguageReactNative,
		LanguageFlutter,
		LanguageUnity,
	}

	for _, lang := range expectedLanguages {
		if languageCounts[lang] == 0 {
			t.Errorf("No patterns found for language: %v", lang)
		}
	}
}

func TestCrossLanguagePatterns_ValidCategories(t *testing.T) {
	validCategories := map[PatchCategory]bool{
		PatchCatLicense:      true,
		PatchCatBilling:      true,
		PatchCatPremium:      true,
		PatchCatSubscription: true,
		PatchCatAds:          true,
	}

	for i, pattern := range CrossLanguagePatterns {
		if !validCategories[pattern.Category] {
			t.Errorf("Pattern #%d has invalid category: %v", i, pattern.Category)
		}
		if pattern.Weight <= 0 {
			t.Errorf("Pattern #%d has invalid weight: %f", i, pattern.Weight)
		}
		if len(pattern.Patterns) == 0 {
			t.Errorf("Pattern #%d has no patterns", i)
		}
	}
}
