package ml

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN DATABASE INTEGRITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestVulnerablePatternsNotEmpty(t *testing.T) {
	if len(VulnerablePatterns) == 0 {
		t.Fatal("VulnerablePatterns is empty")
	}
	if len(VulnerablePatterns) < 25 {
		t.Errorf("Expected at least 25 patterns, got %d", len(VulnerablePatterns))
	}
}

func TestAllPatternsHaveRequiredFields(t *testing.T) {
	for i, p := range VulnerablePatterns {
		if p.ID == "" {
			t.Errorf("Pattern #%d has empty ID", i)
		}
		if p.Category == "" {
			t.Errorf("Pattern %q has empty Category", p.ID)
		}
		if p.Description == "" {
			t.Errorf("Pattern %q has empty Description", p.ID)
		}
		if len(p.MethodNames) == 0 && len(p.ClassPatterns) == 0 && len(p.RequiredCalls) == 0 {
			t.Errorf("Pattern %q has no method names, class patterns, or required calls", p.ID)
		}
		if p.PatchType == "" {
			t.Errorf("Pattern %q has empty PatchType", p.ID)
		}
		if p.Weight <= 0 {
			t.Errorf("Pattern %q has invalid Weight: %f", p.ID, p.Weight)
		}
		if p.MinMatchScore <= 0 {
			t.Errorf("Pattern %q has invalid MinMatchScore: %f", p.ID, p.MinMatchScore)
		}
	}
}

func TestPatternIDsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range VulnerablePatterns {
		if seen[p.ID] {
			t.Errorf("Duplicate pattern ID: %q", p.ID)
		}
		seen[p.ID] = true
	}
}

func TestAllCategoriesHaveInfo(t *testing.T) {
	categoryUsed := make(map[PatchCategory]bool)
	for _, p := range VulnerablePatterns {
		categoryUsed[p.Category] = true
	}

	for cat := range categoryUsed {
		info, ok := GetCategoryInfo(cat)
		if !ok {
			t.Errorf("Category %q used in patterns but has no CategoryInfo", cat)
		}
		if info.Name == "" {
			t.Errorf("Category %q has empty Name", cat)
		}
		if info.Weight <= 0 {
			t.Errorf("Category %q has invalid Weight: %f", cat, info.Weight)
		}
		if info.Severity == "" {
			t.Errorf("Category %q has empty Severity", cat)
		}
	}
}

func TestAllPatchTypesHaveTemplates(t *testing.T) {
	usedTypes := make(map[PatchType]bool)
	for _, p := range VulnerablePatterns {
		usedTypes[p.PatchType] = true
	}

	for pt := range usedTypes {
		tmpl, ok := GetPatchTemplate(pt)
		if !ok {
			t.Errorf("PatchType %q used but has no template", pt)
		}
		if tmpl.Code == "" {
			t.Errorf("PatchType %q template has empty Code", pt)
		}
		if tmpl.Description == "" {
			t.Errorf("PatchType %q template has empty Description", pt)
		}
	}
}

func TestSafePatternsNotEmpty(t *testing.T) {
	if len(SafePatterns) == 0 {
		t.Fatal("SafePatterns is empty")
	}
}

func TestSafePatternsHaveFields(t *testing.T) {
	for i, sp := range SafePatterns {
		if sp.Name == "" {
			t.Errorf("SafePattern #%d has empty Name", i)
		}
		if len(sp.Indicators) == 0 {
			t.Errorf("SafePattern %q has no Indicators", sp.Name)
		}
		if sp.Penalty >= 0 {
			t.Errorf("SafePattern %q has non-negative Penalty: %f (should be negative)", sp.Name, sp.Penalty)
		}
	}
}

func TestLibraryExcludePathsNotEmpty(t *testing.T) {
	if len(LibraryExcludePaths) == 0 {
		t.Fatal("LibraryExcludePaths is empty")
	}
}

func TestLibraryExcludePathsFormat(t *testing.T) {
	for _, path := range LibraryExcludePaths {
		if strings.Contains(path, "\\") {
			t.Errorf("Library path %q contains backslash (should use forward slash)", path)
		}
		if !strings.HasSuffix(path, "/") {
			t.Errorf("Library path %q should end with /", path)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LIBRARY PATH DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsLibraryPath(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"com/google/android/gms/ads/AdView.smali", true},
		{"com/facebook/login/LoginManager.smali", true},
		{"androidx/core/app/ActivityCompat.smali", true},
		{"android/support/v4/app/Fragment.smali", true},
		{"com/squareup/okhttp/Call.smali", true},
		{"okhttp3/OkHttpClient.smali", true},
		{"kotlin/collections/ArraysKt.smali", true},
		{"com/crashlytics/android/Crashlytics.smali", true},
		{"com/unity3d/player/UnityPlayer.smali", true},
		{"com/mopub/mobileads/MoPubView.smali", true},

		// App code — NOT library
		{"com/myapp/MainActivity.smali", false},
		{"com/rovio/game/LicenseChecker.smali", false},
		{"com/halfbrick/mortar/BillingService.smali", false},
		{"LicenseChecker.smali", false},
	}

	for _, tt := range tests {
		result := IsLibraryPath(tt.path)
		if result != tt.expected {
			t.Errorf("IsLibraryPath(%q) = %v, want %v", tt.path, result, tt.expected)
		}
	}
}

func TestIsLibraryPathCaseInsensitive(t *testing.T) {
	tests := []string{
		"COM/GOOGLE/ANDROID/GMS/Ads.smali",
		"Com/Facebook/Login.smali",
		"ANDROIDX/Core/App.smali",
	}

	for _, path := range tests {
		if !IsLibraryPath(path) {
			t.Errorf("IsLibraryPath(%q) should be true (case insensitive)", path)
		}
	}
}

func TestIsLibraryPathBackslash(t *testing.T) {
	if !IsLibraryPath("com\\google\\android\\gms\\ads\\AdView.smali") {
		t.Error("IsLibraryPath should handle backslashes")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func TestGetPatternsByCategory(t *testing.T) {
	license := GetPatternsByCategory(PatchCatLicense)
	if len(license) == 0 {
		t.Error("No license patterns found")
	}
	for _, p := range license {
		if p.Category != PatchCatLicense {
			t.Errorf("Pattern %q has wrong category: %s", p.ID, p.Category)
		}
	}

	billing := GetPatternsByCategory(PatchCatBilling)
	if len(billing) == 0 {
		t.Error("No billing patterns found")
	}
}

func TestCountPatterns(t *testing.T) {
	count := CountPatterns()
	if count < 25 {
		t.Errorf("CountPatterns() = %d, want >= 25", count)
	}
}

func TestCountCategories(t *testing.T) {
	count := CountCategories()
	if count < 10 {
		t.Errorf("CountCategories() = %d, want >= 10", count)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN COVERAGE — проверяем что все категории покрыты
// ═══════════════════════════════════════════════════════════════════════════════

func TestAllCategoriesCovered(t *testing.T) {
	covered := make(map[PatchCategory]bool)
	for _, p := range VulnerablePatterns {
		covered[p.Category] = true
	}

	expectedCategories := []PatchCategory{
		PatchCatLicense, PatchCatBilling, PatchCatPremium,
		PatchCatSubscription, PatchCatAds, PatchCatRootDetect,
		PatchCatEmulatorCheck, PatchCatDebugDetect, PatchCatTamper,
		PatchCatSignature, PatchCatSSLPinning, PatchCatIntegrity,
		PatchCatTrialExpiry, PatchCatFeatureGate, PatchCatHookDetect,
		PatchCatInstaller,
	}

	for _, cat := range expectedCategories {
		if !covered[cat] {
			t.Errorf("Category %q has no patterns", cat)
		}
	}
}

func TestMethodNamesLowercase(t *testing.T) {
	for _, p := range VulnerablePatterns {
		for _, name := range p.MethodNames {
			if name != strings.ToLower(name) {
				t.Errorf("Pattern %q method name %q should be lowercase", p.ID, name)
			}
		}
	}
}

func TestGetAllPatterns(t *testing.T) {
	all := GetAllPatterns()
	if len(all) < len(VulnerablePatterns) {
		t.Errorf("GetAllPatterns count = %d, want at least %d", len(all), len(VulnerablePatterns))
	}
}

func TestDetectSDK_All(t *testing.T) {
	pa := NewPatchAnalyzer()

	tests := []struct {
		name     string
		smali    string
		expected string
	}{
		{"AdMob", ".class Lcom/google/android/gms/ads/AdActivity;", "AdMob"},
		{"Unity", ".class Lcom/unity3d/ads/UnityAds;", "Unity Ads"},
		{"AppLovin", ".class Lcom/applovin/sdk/AppLovinSdk;", "AppLovin MAX"},
		{"BillingV6", ".class Lcom/android/billingclient/api/ProxyBillingActivity;", "Google Play Billing v6"},
	}

	for _, tt := range tests {
		ci := pa.AnalyzeSmaliContent("test.smali", []byte(tt.smali))
		sdks := DetectSDK(ci)
		found := false
		for _, s := range sdks {
			if s == tt.expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DetectSDK did not find %s in %s", tt.expected, tt.name)
		}
	}
}
