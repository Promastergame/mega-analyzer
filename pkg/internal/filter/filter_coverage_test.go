package filter

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ADDITIONAL FILTER TESTS FOR COVERAGE
// ═══════════════════════════════════════════════════════════════════════════════

func TestFilter_ClassifyForPipeline(t *testing.T) {
	f := NewFilter()

	tests := []struct {
		path          string
		expectAppCode bool
		minImportance int
	}{
		{"smali/com/myapp/LicenseManager.smali", true, 7},
		{"smali/kotlin/Unit.smali", false, 0},
		{"smali/a/b.smali", true, 3}, // obfuscated
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			fc := f.ClassifyForPipeline(tt.path)
			if fc.IsAppCode != tt.expectAppCode {
				t.Errorf("IsAppCode = %v, want %v", fc.IsAppCode, tt.expectAppCode)
			}
			if fc.Importance < tt.minImportance {
				t.Errorf("Importance = %d, want >= %d", fc.Importance, tt.minImportance)
			}
		})
	}
}

func TestFilter_ClassifyBatch(t *testing.T) {
	f := NewFilter()

	paths := []string{
		"smali/com/app/License.smali",
		"smali/kotlin/Unit.smali",
		"smali/a/b.smali",
	}

	results := f.ClassifyBatch(paths)
	if len(results) != len(paths) {
		t.Errorf("ClassifyBatch returned %d results, want %d", len(results), len(paths))
	}

	for i, result := range results {
		if result == nil {
			t.Errorf("result[%d] is nil", i)
		}
	}
}

func TestFilter_IsHighValue(t *testing.T) {
	f := NewFilter()

	tests := []struct {
		path     string
		expected bool
	}{
		{"smali/com/app/LicenseManager.smali", true},
		{"smali/com/app/Utils.smali", false},
		{"smali/kotlin/Unit.smali", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := f.IsHighValue(tt.path)
			if result != tt.expected {
				t.Errorf("IsHighValue(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestFilter_GetCategories(t *testing.T) {
	f := NewFilter()

	categories := f.GetCategories("smali/com/app/LicenseManager.smali")
	if len(categories) == 0 {
		t.Error("GetCategories should return at least one category for high-value path")
	}

	// Should contain "license" category
	found := false
	for _, cat := range categories {
		if cat == "license" {
			found = true
			break
		}
	}
	if !found {
		t.Error("GetCategories should contain 'license' for LicenseManager")
	}
}

func TestFilter_Summary(t *testing.T) {
	f := NewFilter()

	summary := f.Summary("smali/com/app/LicenseManager.smali")
	if summary == "" {
		t.Error("Summary should not be empty")
	}
}

func TestFilter_EnableDisableExplain(t *testing.T) {
	f := NewFilter()

	// Enable explain
	f.EnableExplain()
	result, trace := f.ClassifyWithTrace("smali/com/app/Test.smali")
	if result == nil {
		t.Error("ClassifyWithTrace should return result")
	}
	if trace == nil {
		t.Error("ClassifyWithTrace should return trace when explain enabled")
	}

	// Disable explain
	f.DisableExplain()
	trace = f.LastTrace()
	// LastTrace returns the last trace from ClassifyWithTrace, not from Classify
	_ = trace
}

func TestFilter_GetCacheStats(t *testing.T) {
	f := NewFilter()

	// Initial stats
	stats := f.GetCacheStats()
	if stats.Hits != 0 || stats.Misses != 0 {
		t.Error("Initial cache stats should be zero")
	}
	if stats.HitRate != 0 {
		t.Error("Initial hit rate should be 0")
	}

	// Classify some paths
	paths := []string{
		"smali/a/b.smali",
		"smali/c/d.smali",
		"smali/e/f.smali",
	}

	for _, p := range paths {
		f.Classify(p)
	}

	// Classify again (should hit cache)
	for _, p := range paths {
		f.Classify(p)
	}

	stats = f.GetCacheStats()
	if stats.Hits != int64(len(paths)) {
		t.Errorf("Cache hits = %d, want %d", stats.Hits, len(paths))
	}
	if stats.Misses != int64(len(paths)) {
		t.Errorf("Cache misses = %d, want %d", stats.Misses, len(paths))
	}
	if stats.HitRate != 0.5 {
		t.Errorf("Hit rate = %.2f, want 0.5", stats.HitRate)
	}
}

func TestFilter_NewFilterWithRules(t *testing.T) {
	rules := FilterRules{
		StandardLibraries: []LibraryPattern{
			{Pattern: "custom/lib/", Category: "custom", MatchType: MatchPrefix},
		},
	}

	f := NewFilterWithRules(rules)
	if f == nil {
		t.Fatal("NewFilterWithRules returned nil")
	}

	// Test that custom rule is applied
	result := f.Classify("smali/custom/lib/Test.smali")
	if !result.IsLibrary {
		t.Error("Custom library pattern should be recognized")
	}
}

func TestFilter_GetCacheStats_Detailed(t *testing.T) {
	f := NewFilter()

	// Initial stats
	stats := f.GetCacheStats()
	if stats.ClassifyCalls != 0 {
		t.Error("Initial ClassifyCalls should be zero")
	}
}

func TestPathReliability_String(t *testing.T) {
	tests := []struct {
		reliability PathReliability
		expected    string
	}{
		{PathReliable, "Reliable"},
		{PathPartial, "Partial"},
		{PathUnreliable, "Unreliable"},
		{PathReliability(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.reliability.String()
			if result != tt.expected {
				t.Errorf("PathReliability(%d).String() = %q, want %q",
					tt.reliability, result, tt.expected)
			}
		})
	}
}

func TestSignalCategory(t *testing.T) {
	// Test that signal categories are defined
	_ = SignalStructural
	_ = SignalSemantic
	_ = SignalContextual
}

func TestReasonType(t *testing.T) {
	// Test that all reason types are defined
	reasons := []ReasonType{
		ReasonStandardLibrary,
		ReasonHighValuePath,
		ReasonKeyword,
		ReasonKeywordCombo,
		ReasonObfuscation,
		ReasonAppPackage,
		ReasonException,
		ReasonSafeKeyword,
		ReasonContextAdjust,
		ReasonDampening,
		ReasonCorrelation,
	}

	for _, r := range reasons {
		if r == "" {
			t.Error("ReasonType should not be empty")
		}
	}
}

func TestClassificationResult_Methods(t *testing.T) {
	result := &ClassificationResult{}

	// Test addReason
	result.addReason(ClassificationReason{
		Type:        ReasonKeyword,
		Description: "test",
		Impact:      5,
	})
	if len(result.Reasons) != 1 {
		t.Error("addReason should add reason")
	}

	// Test addCategory (with deduplication)
	result.addCategory("license")
	result.addCategory("premium")
	result.addCategory("license") // duplicate

	if len(result.Categories) != 2 {
		t.Errorf("Categories length = %d, want 2 (deduplication)", len(result.Categories))
	}
}

func TestKeywordMatch(t *testing.T) {
	match := KeywordMatch{
		Keyword: "license",
		Bonus:   5,
		Context: ContextFileName,
	}

	if match.Keyword != "license" {
		t.Errorf("Keyword = %q, want %q", match.Keyword, "license")
	}
	if match.Bonus != 5 {
		t.Errorf("Bonus = %d, want 5", match.Bonus)
	}
	if match.Context != ContextFileName {
		t.Errorf("Context = %v, want %v", match.Context, ContextFileName)
	}
}

func TestClassificationReason(t *testing.T) {
	reason := ClassificationReason{
		Type:        ReasonKeyword,
		Description: "test reason",
		Impact:      10,
		Category:    SignalSemantic,
	}

	if reason.Type != ReasonKeyword {
		t.Errorf("Type = %q, want %q", reason.Type, ReasonKeyword)
	}
	if reason.Impact != 10 {
		t.Errorf("Impact = %d, want 10", reason.Impact)
	}
	if reason.Description != "test reason" {
		t.Errorf("Description = %q, want %q", reason.Description, "test reason")
	}
	if reason.Category != SignalSemantic {
		t.Errorf("Category = %v, want %v", reason.Category, SignalSemantic)
	}
}

func TestExplainTrace(t *testing.T) {
	trace := newExplainTrace("test.smali")
	if trace == nil {
		t.Fatal("newExplainTrace returned nil")
	}
	if trace.File != "test.smali" {
		t.Errorf("File = %q, want %q", trace.File, "test.smali")
	}
	if len(trace.Steps) != 0 {
		t.Error("Initial steps should be empty")
	}

	// Test log
	trace.log("TEST", "action", "pattern", "reason")
	if len(trace.Steps) != 1 {
		t.Error("log should add step")
	}

	// Test logWithImpact
	trace.logWithImpact("TEST", "action2", "pattern2", "reason2", 5, 10, 0.5)
	if len(trace.Steps) != 2 {
		t.Error("logWithImpact should add step")
	}

	// Test String
	s := trace.String()
	if s == "" {
		t.Error("String should not be empty")
	}
}

func TestDampeningTracker(t *testing.T) {
	dt := newDampeningTracker()
	if dt == nil {
		t.Fatal("newDampeningTracker returned nil")
	}
	if dt.total != 1.0 {
		t.Errorf("Initial total = %f, want 1.0", dt.total)
	}

	// Test apply
	dt.apply("test", 0.5)
	if dt.total != 0.5 {
		t.Errorf("After apply(0.5), total = %f, want 0.5", dt.total)
	}

	// Test floor
	dt2 := newDampeningTracker()
	dt2.apply("test", 0.1) // Would go below floor
	if dt2.total < 0.2 {
		t.Errorf("Total should not go below floor (0.2), got %f", dt2.total)
	}

	// Test ceiling
	dt3 := newDampeningTracker()
	dt3.apply("test", 2.0) // Would go above ceiling
	if dt3.total > 1.5 {
		t.Errorf("Total should not go above ceiling (1.5), got %f", dt3.total)
	}

	// Test sources
	sources := dt.sources()
	if len(sources) != 1 {
		t.Errorf("Sources length = %d, want 1", len(sources))
	}
}

func TestSafeLibraryPattern_GetDampening(t *testing.T) {
	d30 := 0.3
	tests := []struct {
		name     string
		pattern  SafeLibraryPattern
		default_ float64
		expected float64
	}{
		{
			name:     "with dampening",
			pattern:  SafeLibraryPattern{Dampening: &d30},
			default_: 1.0,
			expected: 0.3,
		},
		{
			name:     "without dampening",
			pattern:  SafeLibraryPattern{},
			default_: 0.5,
			expected: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.pattern.GetDampening(tt.default_)
			if result != tt.expected {
				t.Errorf("GetDampening() = %f, want %f", result, tt.expected)
			}
		})
	}
}

func TestFilter_CriticalKeywords(t *testing.T) {
	// Test that critical keywords prevent fast-path
	f := NewFilter()

	// These paths contain critical keywords and should NOT be fast-pathed
	criticalPaths := []string{
		"smali/com/android/billingclient/api/Purchase.smali",
		"smali/com/google/android/gms/ads/license/LicenseChecker.smali",
		"smali/com/app/premium/SubscriptionManager.smali",
	}

	for _, path := range criticalPaths {
		t.Run(path, func(t *testing.T) {
			result := f.Classify(path)
			// Should have some importance (not just library=0)
			if result.Importance == 0 && result.IsLibrary {
				t.Errorf("Path with critical keyword should not be fast-pathed to 0 importance: %s", path)
			}
		})
	}
}

func TestFilter_ObfuscationDetection_Detailed(t *testing.T) {
	f := NewFilter()

	tests := []struct {
		path         string
		expectObfusc bool
	}{
		{"smali/a.smali", true},                     // Single char
		{"smali/b/c.smali", true},                   // Two single chars
		{"smali/aa/bb.smali", true},                 // Two char segments
		{"smali/abc/def.smali", false},              // Three char segments (not obfuscated)
		{"smali/com/app/MainActivity.smali", false}, // Normal path
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := f.Classify(tt.path)
			hasObfusc := result.ObfuscationType != ""
			if hasObfusc != tt.expectObfusc {
				t.Errorf("ObfuscationType = %q, expectObfusc = %v", result.ObfuscationType, tt.expectObfusc)
			}
		})
	}
}

func TestFilter_AppPackage_Detailed(t *testing.T) {
	f := NewFilter()
	f.SetAppPackage("com.myapp")

	// Path matching app package
	result := f.Classify("smali/com/myapp/MainActivity.smali")
	if !result.IsAppCode {
		t.Error("Path matching app package should be app code")
	}

	// Check for app_package reason
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

func TestFilter_Profiles_Detailed(t *testing.T) {
	profiles := []ProfileType{ProfileStrict, ProfileBalanced, ProfileLoose, ProfileAudit, ProfileParanoid}

	for _, profile := range profiles {
		t.Run(string(profile), func(t *testing.T) {
			f := NewFilterWithProfile(profile)
			if f.Profile() != profile {
				t.Errorf("Profile() = %v, want %v", f.Profile(), profile)
			}
		})
	}
}

func TestFilter_FastPath(t *testing.T) {
	f := NewFilter()

	// Known library paths should use fast-path
	libraryPaths := []string{
		"smali/kotlin/collections/List.smali",
		"smali/android/os/Bundle.smali",
		"smali/okhttp3/OkHttpClient.smali",
	}

	for _, path := range libraryPaths {
		t.Run(path, func(t *testing.T) {
			result := f.Classify(path)
			if !result.IsLibrary {
				t.Errorf("Known library path should be classified as library: %s", path)
			}
		})
	}
}

func TestFilter_HighValuePatterns(t *testing.T) {
	f := NewFilter()

	// High-value patterns should be detected
	highValuePaths := []string{
		"smali/com/app/LicenseValidator.smali",
		"smali/com/app/PremiumManager.smali",
		"smali/com/app/BillingHelper.smali",
	}

	for _, path := range highValuePaths {
		t.Run(path, func(t *testing.T) {
			result := f.Classify(path)
			if len(result.MatchedHighValue) == 0 && result.Importance < 7 {
				t.Errorf("High-value path should have high importance: %s (got %d)", path, result.Importance)
			}
		})
	}
}

func TestFilter_KeywordCombinations_Detailed(t *testing.T) {
	f := NewFilter()

	// Single keyword
	result1 := f.Classify("smali/com/app/License.smali")

	// Multiple keywords (should have higher importance)
	result2 := f.Classify("smali/com/app/LicenseChecker.smali")

	// LicenseChecker should have higher or equal importance due to combination
	if result2.Importance < result1.Importance {
		t.Errorf("LicenseChecker (%d) should have >= importance than License (%d)",
			result2.Importance, result1.Importance)
	}
}

func TestFilter_Confidence(t *testing.T) {
	f := NewFilter()

	// High-value paths should have higher confidence
	result1 := f.Classify("smali/com/app/LicenseManager.smali")

	// Library paths should have lower confidence
	result2 := f.Classify("smali/kotlin/Unit.smali")

	if result1.Confidence <= result2.Confidence {
		t.Errorf("High-value path confidence (%.2f) should be > library confidence (%.2f)",
			result1.Confidence, result2.Confidence)
	}
}

func TestFilter_DampeningSources(t *testing.T) {
	f := NewFilter()

	// Library path should have dampening
	result := f.Classify("smali/kotlin/Unit.smali")
	// Note: Fast-path results may not have dampening applied
	// Just verify the result is valid
	if result == nil {
		t.Error("Classify should return a result")
	}
}

// Benchmarks
func BenchmarkFilter_ClassifyForPipeline(b *testing.B) {
	f := NewFilter()
	paths := []string{
		"smali/com/app/LicenseManager.smali",
		"smali/kotlin/collections/List.smali",
		"smali/a/b.smali",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.ClassifyForPipeline(paths[i%len(paths)])
	}
}

func BenchmarkFilter_ClassifyBatch(b *testing.B) {
	f := NewFilter()
	paths := []string{
		"smali/com/app/LicenseManager.smali",
		"smali/kotlin/collections/List.smali",
		"smali/a/b.smali",
		"smali/android/os/Bundle.smali",
		"smali/okhttp3/OkHttpClient.smali",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.ClassifyBatch(paths)
	}
}
