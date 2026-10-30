package filter

import (
	"testing"
)

func TestFilter_IsStandardLibrary(t *testing.T) {
	f := NewFilter()

	tests := []struct {
		path     string
		expected bool
	}{
		// Стандартные библиотеки
		{"smali/android/app/Activity.smali", true},
		{"smali/androidx/core/app/CoreApp.smali", true},
		{"smali/kotlin/collections/List.smali", true},
		{"smali/com/google/gson/Gson.smali", true},
		{"smali/okhttp3/OkHttpClient.smali", true},

		// НЕ библиотеки
		{"smali/com/myapp/License.smali", false},
		{"smali/com/myapp/PremiumManager.smali", false},

		// High-value в библиотеке -> НЕ библиотека
		{"smali/com/android/billingclient/api/Purchase.smali", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := f.IsStandardLibrary(tt.path)
			if result != tt.expected {
				t.Errorf("IsStandardLibrary(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestFilter_GetImportance(t *testing.T) {
	f := NewFilter()

	tests := []struct {
		path        string
		minExpected int
		maxExpected int
	}{
		// Библиотеки
		{"smali/kotlin/Unit.smali", 0, 0},
		{"smali/android/os/Bundle.smali", 0, 0},

		// Высокоценные
		{"smali/com/app/LicenseManager.smali", 8, 10},
		{"smali/com/app/PremiumChecker.smali", 8, 10},
		{"smali/com/app/BillingHelper.smali", 8, 10},

		// Комбинации (аддитивный бонус)
		{"smali/com/app/LicenseVerifyManager.smali", 9, 10}, // license + verify + manager

		// Обфускация
		{"smali/a/b.smali", 5, 8},
		{"smali/x/y.smali", 5, 8},

		// Обычные
		{"smali/com/app/Utils.smali", 4, 6},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := f.GetImportance(tt.path)
			if result < tt.minExpected || result > tt.maxExpected {
				t.Errorf("GetImportance(%q) = %d, want [%d, %d]",
					tt.path, result, tt.minExpected, tt.maxExpected)
			}
		})
	}
}

func TestFilter_ClassifyWithReasons(t *testing.T) {
	f := NewFilter()

	result := f.Classify("smali/com/app/LicenseValidator.smali")

	if !result.IsAppCode {
		t.Error("Should be app code")
	}

	if len(result.Reasons) == 0 {
		t.Error("Should have reasons")
	}

	// Должен быть keyword "license"
	hasLicense := false
	for _, km := range result.MatchedKeywords {
		if km.Keyword == "license" {
			hasLicense = true
			break
		}
	}
	if !hasLicense {
		t.Error("Should match 'license' keyword")
	}

	// Должна быть категория "license"
	hasCategory := false
	for _, cat := range result.Categories {
		if cat == "license" {
			hasCategory = true
			break
		}
	}
	if !hasCategory {
		t.Error("Should have 'license' category")
	}
}

func TestFilter_KeywordCombinations(t *testing.T) {
	f := NewFilter()

	// license + check = больше бонус
	result1 := f.Classify("smali/com/app/License.smali")
	result2 := f.Classify("smali/com/app/LicenseChecker.smali")

	if result2.Importance <= result1.Importance {
		t.Errorf("LicenseChecker (%d) should have higher importance than License (%d)",
			result2.Importance, result1.Importance)
	}
}

func TestFilter_ObfuscationDetection(t *testing.T) {
	f := NewFilter()

	tests := []struct {
		path     string
		isObfusc bool
	}{
		{"smali/a.smali", true},
		{"smali/b/c.smali", true},
		{"smali/aa/bb.smali", true},
		{"smali/com/app/MainActivity.smali", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := f.Classify(tt.path)
			if (result.ObfuscationType != "") != tt.isObfusc {
				t.Errorf("Path %q: obfuscation=%q, want isObfusc=%v",
					tt.path, result.ObfuscationType, tt.isObfusc)
			}
		})
	}
}

func TestFilter_AppPackage(t *testing.T) {
	f := NewFilter()
	f.SetAppPackage("com.myapp")

	// Код приложения
	result := f.Classify("smali/com/myapp/MainActivity.smali")

	hasAppPackageReason := false
	for _, r := range result.Reasons {
		if r.Type == ReasonAppPackage {
			hasAppPackageReason = true
			break
		}
	}

	if !hasAppPackageReason {
		t.Error("Should have app_package reason")
	}
}

func TestFilter_Profiles(t *testing.T) {
	profiles := []ProfileType{ProfileStrict, ProfileBalanced, ProfileLoose, ProfileAudit}

	path := "smali/com/app/SomeClass.smali"

	var importances []int
	for _, profile := range profiles {
		f := NewFilterWithProfile(profile)
		result := f.Classify(path)
		importances = append(importances, result.Importance)
	}

	// Strict должен быть <= Balanced <= Loose <= Audit
	for i := 0; i < len(importances)-1; i++ {
		if importances[i] > importances[i+1] {
			t.Errorf("Profile ordering violated: %v", importances)
		}
	}
}

func TestFilter_CacheHitRate(t *testing.T) {
	f := NewFilter()

	paths := []string{
		"smali/a/b.smali",
		"smali/c/d.smali",
		"smali/e/f.smali",
	}

	// Первый проход - все misses
	for _, p := range paths {
		f.Classify(p)
	}

	// Второй проход - все hits
	for _, p := range paths {
		f.Classify(p)
	}

	stats := f.GetCacheStats()

	if stats.Hits != int64(len(paths)) {
		t.Errorf("Expected %d hits, got %d", len(paths), stats.Hits)
	}
	if stats.Misses != int64(len(paths)) {
		t.Errorf("Expected %d misses, got %d", len(paths), stats.Misses)
	}
	if stats.HitRate != 0.5 {
		t.Errorf("Expected 50%% hit rate, got %.2f", stats.HitRate)
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		baseName string
	}{
		{`smali\com\app\Test.smali`, "smali/com/app/Test.smali", "Test"},
		{"smali/com/app/Test.smali", "smali/com/app/Test.smali", "Test"},
		{`C:\path\to\file.smali`, "C:/path/to/file.smali", "file"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			info := NormalizePath(tt.input)
			if info.Normalized != tt.expected {
				t.Errorf("Normalized: got %q, want %q", info.Normalized, tt.expected)
			}
			if info.BaseName != tt.baseName {
				t.Errorf("BaseName: got %q, want %q", info.BaseName, tt.baseName)
			}
		})
	}
}

// Benchmark
func BenchmarkFilter_Classify(b *testing.B) {
	f := NewFilter()
	paths := []string{
		"smali/com/app/LicenseManager.smali",
		"smali/kotlin/collections/List.smali",
		"smali/a/b.smali",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Classify(paths[i%len(paths)])
	}
}

func BenchmarkFilter_ClassifyWithCache(b *testing.B) {
	f := NewFilter()
	path := "smali/com/app/LicenseManager.smali"

	// Прогрев кэша
	f.Classify(path)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Classify(path)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Additional tests to increase coverage to 80%
// ═══════════════════════════════════════════════════════════════════════════════

func TestMatchesPattern_Contains(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		pattern  string
		expected bool
	}{
		{"contains match", "check_license_now", "license", true},
		{"contains no match", "premium", "license", false},
		{"empty pattern", "test", "", true},
		{"empty string", "", "test", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchesPattern(tt.s, tt.pattern, MatchContains)
			if result != tt.expected {
				t.Errorf("MatchesPattern(%q, %q, MatchContains) = %v, want %v",
					tt.s, tt.pattern, result, tt.expected)
			}
		})
	}
}

func TestMatchesAny_Prefix(t *testing.T) {
	patterns := []string{"license", "premium", "billing"}

	tests := []struct {
		name     string
		s        string
		expected bool
	}{
		{"matches first", "license_check", true},
		{"matches second", "premium_user", true},
		{"matches third", "billing_api", true},
		{"no match", "analytics", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, _ := MatchesAny(tt.s, patterns, MatchPrefix)
			if matched != tt.expected {
				t.Errorf("MatchesAny(%q) = %v, want %v", tt.s, matched, tt.expected)
			}
		})
	}
}

func TestClamp(t *testing.T) {
	tests := []struct {
		value    int
		min      int
		max      int
		expected int
	}{
		{5, 0, 10, 5},
		{-5, 0, 10, 0},
		{15, 0, 10, 10},
		{0, 0, 10, 0},
		{10, 0, 10, 10},
	}

	for _, tt := range tests {
		result := Clamp(tt.value, tt.min, tt.max)
		if result != tt.expected {
			t.Errorf("Clamp(%d, %d, %d) = %d, want %d",
				tt.value, tt.min, tt.max, result, tt.expected)
		}
	}
}

func TestClampFloat(t *testing.T) {
	tests := []struct {
		value    float64
		min      float64
		max      float64
		expected float64
	}{
		{5.5, 0.0, 10.0, 5.5},
		{-5.5, 0.0, 10.0, 0.0},
		{15.5, 0.0, 10.0, 10.0},
		{0.0, 0.0, 10.0, 0.0},
		{10.0, 0.0, 10.0, 10.0},
	}

	for _, tt := range tests {
		result := ClampFloat(tt.value, tt.min, tt.max)
		if result != tt.expected {
			t.Errorf("ClampFloat(%.1f, %.1f, %.1f) = %.1f, want %.1f",
				tt.value, tt.min, tt.max, result, tt.expected)
		}
	}
}

func TestSignalStrength_String(t *testing.T) {
	tests := []struct {
		strength SignalStrength
		expected string
	}{
		{SignalWeak, "Weak"},
		{SignalMedium, "Medium"},
		{SignalStrong, "Strong"},
		{SignalCritical, "Critical"},
		{SignalStrength(99), "Unknown"},
	}

	for _, tt := range tests {
		result := tt.strength.String()
		if result != tt.expected {
			t.Errorf("SignalStrength(%d).String() = %q, want %q",
				tt.strength, result, tt.expected)
		}
	}
}

func TestStrengthFromScore(t *testing.T) {
	tests := []struct {
		score    int
		expected SignalStrength
	}{
		{0, SignalWeak},
		{1, SignalWeak},
		{3, SignalWeak},
		{4, SignalMedium},
		{6, SignalMedium},
		{7, SignalStrong},
		{8, SignalStrong},
		{9, SignalCritical},
		{10, SignalCritical},
		{15, SignalCritical},
	}

	for _, tt := range tests {
		result := strengthFromScore(tt.score)
		if result != tt.expected {
			t.Errorf("strengthFromScore(%d) = %v, want %v",
				tt.score, result, tt.expected)
		}
	}
}

func TestKeywordContext_String(t *testing.T) {
	tests := []struct {
		ctx      KeywordContext
		expected string
	}{
		{ContextUnknown, "Unknown"},
		{ContextFileName, "FileName"},
		{ContextPackagePath, "PackagePath"},
		{ContextLibraryPath, "LibraryPath"},
		{KeywordContext(99), "Unknown"},
	}

	for _, tt := range tests {
		result := tt.ctx.String()
		if result != tt.expected {
			t.Errorf("KeywordContext(%d).String() = %q, want %q",
				tt.ctx, result, tt.expected)
		}
	}
}

func TestAllProfiles(t *testing.T) {
	profiles := AllProfiles()

	if len(profiles) == 0 {
		t.Error("AllProfiles() should return at least one profile")
	}

	// Check that all profiles are valid
	for _, p := range profiles {
		desc := ProfileDescription(p)
		if desc == "" {
			t.Errorf("Profile %v has no description", p)
		}
	}
}

func TestProfileDescription(t *testing.T) {
	tests := []struct {
		profile  ProfileType
		expected string
	}{
		{ProfileStrict, "Strict: Minimum false positives, high-confidence findings only"},
		{ProfileBalanced, "Balanced: Trade-off between precision and recall (default)"},
		{ProfileLoose, "Loose: Maximum findings, including weak signals"},
		{ProfileParanoid, "Paranoid: For old/suspicious APKs, less dampening, more scrutiny"},
		{ProfileAudit, "Audit: Show everything including libraries, for manual review"},
		{ProfileType("invalid"), "Unknown profile"},
	}

	for _, tt := range tests {
		desc := ProfileDescription(tt.profile)
		if desc != tt.expected {
			t.Errorf("ProfileDescription(%v) = %q, want %q",
				tt.profile, desc, tt.expected)
		}
	}
}

func TestLRUCache_Basic(t *testing.T) {
	cache := NewLRUCache[string, int](3)

	// Put and Get
	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.Put("c", 3)

	if val, ok := cache.Get("a"); !ok || val != 1 {
		t.Errorf("Get(a) = %v, %v, want 1, true", val, ok)
	}

	// Eviction
	cache.Put("d", 4) // Should evict "b" (least recently used)

	if _, ok := cache.Get("b"); ok {
		t.Error("Get(b) should return false after eviction")
	}

	if val, ok := cache.Get("d"); !ok || val != 4 {
		t.Errorf("Get(d) = %v, %v, want 4, true", val, ok)
	}
}

func TestLRUCache_Clear(t *testing.T) {
	cache := NewLRUCache[string, int](3)

	cache.Put("a", 1)
	cache.Put("b", 2)

	cache.Clear()

	if _, ok := cache.Get("a"); ok {
		t.Error("Get(a) should return false after Clear()")
	}
	if _, ok := cache.Get("b"); ok {
		t.Error("Get(b) should return false after Clear()")
	}
}

func TestLRUCache_UpdateExisting(t *testing.T) {
	cache := NewLRUCache[string, int](2)

	cache.Put("a", 1)
	cache.Put("b", 2)
	cache.Put("a", 10) // Update existing

	if val, ok := cache.Get("a"); !ok || val != 10 {
		t.Errorf("Get(a) = %v, %v, want 10, true", val, ok)
	}

	// "a" was updated, so "b" should still be there
	if _, ok := cache.Get("b"); !ok {
		t.Error("Get(b) should return true")
	}
}

func TestClassificationResult_AddReason(t *testing.T) {
	result := &ClassificationResult{}

	result.addReason(ClassificationReason{
		Type:        ReasonKeyword,
		Description: "test reason",
		Impact:      5,
	})

	if len(result.Reasons) != 1 {
		t.Errorf("Expected 1 reason, got %d", len(result.Reasons))
	}

	if result.Reasons[0].Type != ReasonKeyword {
		t.Errorf("Expected ReasonKeyword, got %v", result.Reasons[0].Type)
	}
}

func TestClassificationResult_AddCategory(t *testing.T) {
	result := &ClassificationResult{}

	result.addCategory("license")
	result.addCategory("premium")
	result.addCategory("license") // Duplicate

	if len(result.Categories) != 2 {
		t.Errorf("Expected 2 unique categories, got %d", len(result.Categories))
	}
}

func TestFilter_SetAppPackage_Empty(t *testing.T) {
	f := NewFilter()
	f.SetAppPackage("")

	// Should not crash
	result := f.Classify("smali/com/app/Test.smali")
	if !result.IsAppCode {
		t.Error("Should still classify as app code")
	}
}

func TestFilter_Profile(t *testing.T) {
	f := NewFilterWithProfile(ProfileStrict)

	if f.Profile() != ProfileStrict {
		t.Errorf("Profile() = %v, want %v", f.Profile(), ProfileStrict)
	}
}

func TestLibraryPattern_GetDampening(t *testing.T) {
	dampVal := 0.5
	tests := []struct {
		name       string
		pattern    *LibraryPattern
		defaultVal float64
		expected   float64
	}{
		{
			name:       "has dampening",
			pattern:    &LibraryPattern{Dampening: &dampVal},
			defaultVal: 1.0,
			expected:   0.5,
		},
		{
			name:       "no dampening",
			pattern:    &LibraryPattern{},
			defaultVal: 0.8,
			expected:   0.8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.pattern.GetDampening(tt.defaultVal)
			if result != tt.expected {
				t.Errorf("GetDampening() = %f, want %f", result, tt.expected)
			}
		})
	}
}
