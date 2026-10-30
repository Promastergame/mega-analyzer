package ml

import (
	"testing"
)

// TestPatternCounts verifies the number of patterns added
func TestPatternCounts(t *testing.T) {
	tests := []struct {
		name     string
		patterns []VulnerablePattern
		expected int
	}{
		{"Core Patterns", VulnerablePatterns, 90},
		{"AdMob Patterns", AdMobPatterns, 6},
		{"Unity Ads Patterns", UnityAdsPatterns, 7},
		{"IronSource Patterns", IronSourcePatterns, 9},
		{"AppLovin Patterns", AppLovinPatterns, 9},
		{"Facebook Audience Network Patterns", FacebookAudienceNetworkPatterns, 4},
		{"Vungle Patterns", VunglePatterns, 4},
		{"AdColony Patterns", AdColonyPatterns, 5},
		{"Billing v5 Patterns", BillingV5Patterns, 9},
		{"Billing v6 Patterns", BillingV6Patterns, 10},
		{"Billing v7 Patterns", BillingV7Patterns, 5},
		{"Advanced Gate Patterns", AdvancedGatePatterns, 4},
		{"Premium/Subscription Patterns", PremiumFeaturePatterns, 11},
		{"Currency/Time Patterns", CurrencyTimePatterns, 23}, // Task 9 + iter2 game economy (12 new)
	}

	totalExpected := 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := len(tt.patterns)
			if actual != tt.expected {
				t.Errorf("%s: expected %d patterns, got %d", tt.name, tt.expected, actual)
			}
			t.Logf("%s: %d patterns", tt.name, actual)
		})
		totalExpected += tt.expected
	}

	// Test GetAllPatterns
	t.Run("GetAllPatterns", func(t *testing.T) {
		allPatterns := GetAllPatterns()
		actual := len(allPatterns)
		minExpected := totalExpected + len(BillingV7Patterns) + len(AdvancedGatePatterns)
		if actual < minExpected {
			t.Errorf("GetAllPatterns: expected at least %d total patterns, got %d", minExpected, actual)
		}
		t.Logf("Total patterns: %d (min %d)", actual, minExpected)
	})
}

// TestSDKDetection verifies SDK detection functions work
func TestSDKDetection(t *testing.T) {
	tests := []struct {
		name      string
		className string
		filePath  string
		detector  func(*ClassInfo) bool
		expected  bool
	}{
		{
			name:      "AdMob Detection",
			className: "Lcom/google/android/gms/ads/AdView;",
			filePath:  "com/google/android/gms/ads/AdView.smali",
			detector:  DetectAdMobSDK,
			expected:  true,
		},
		{
			name:      "Unity Ads Detection",
			className: "Lcom/unity3d/ads/UnityAds;",
			filePath:  "com/unity3d/ads/UnityAds.smali",
			detector:  DetectUnityAdsSDK,
			expected:  true,
		},
		{
			name:      "IronSource Detection",
			className: "Lcom/ironsource/IronSource;",
			filePath:  "com/ironsource/IronSource.smali",
			detector:  DetectIronSourceSDK,
			expected:  true,
		},
		{
			name:      "AppLovin Detection",
			className: "Lcom/applovin/sdk/AppLovinSdk;",
			filePath:  "com/applovin/sdk/AppLovinSdk.smali",
			detector:  DetectAppLovinSDK,
			expected:  true,
		},
		{
			name:      "Billing v5 Detection",
			className: "Lcom/android/billingclient/api/BillingClient;",
			filePath:  "com/android/billingclient/api/BillingClient.smali",
			detector:  DetectBillingV5SDK,
			expected:  true,
		},
		{
			name:      "Non-SDK Class",
			className: "Lcom/myapp/MainActivity;",
			filePath:  "com/myapp/MainActivity.smali",
			detector:  DetectAdMobSDK,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classInfo := &ClassInfo{
				ClassName: tt.className,
				FilePath:  tt.filePath,
			}
			actual := tt.detector(classInfo)
			if actual != tt.expected {
				t.Errorf("%s: expected %v, got %v", tt.name, tt.expected, actual)
			}
		})
	}
}

// TestPatternIndexWithSDKPatterns verifies pattern index includes SDK patterns
func TestPatternIndexWithSDKPatterns(t *testing.T) {
	idx := BuildPatternIndex()
	stats := idx.Stats()

	t.Logf("Pattern Index Stats:")
	t.Logf("  Total Patterns: %d", stats.TotalPatterns)
	t.Logf("  Method Name Entries: %d", stats.MethodNameEntries)
	t.Logf("  Class Entries: %d", stats.ClassEntries)
	t.Logf("  Required Call Entries: %d", stats.RequiredCallEntries)
	t.Logf("  String Pattern Entries: %d", stats.StringPatternEntries)
	t.Logf("  Return Type Entries: %d", stats.ReturnTypeEntries)
	t.Logf("  Category Entries: %d", stats.CategoryEntries)

	// Verify we have more than just the core 32 patterns
	// Verify we have more than just the core 55 patterns
	if stats.TotalPatterns <= 55 {
		t.Errorf("Expected more than 55 patterns (including SDK patterns), got %d", stats.TotalPatterns)
	}

	// Verify we have patterns in the ads category
	adsPatterns := idx.FindByCategory(string(PatchCatAds))
	if len(adsPatterns) == 0 {
		t.Error("Expected ads patterns in index, got none")
	}
	t.Logf("  Ads Patterns: %d", len(adsPatterns))

	// Verify we have patterns in the billing category
	billingPatterns := idx.FindByCategory(string(PatchCatBilling))
	if len(billingPatterns) == 0 {
		t.Error("Expected billing patterns in index, got none")
	}
	t.Logf("  Billing Patterns: %d", len(billingPatterns))

	// Verify we have patterns in the subscription category
	subscriptionPatterns := idx.FindByCategory(string(PatchCatSubscription))
	if len(subscriptionPatterns) == 0 {
		t.Error("Expected subscription patterns in index, got none")
	}
	t.Logf("  Subscription Patterns: %d", len(subscriptionPatterns))
}
