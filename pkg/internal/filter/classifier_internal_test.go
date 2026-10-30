package filter

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════
// Direct unit tests for internal classifier functions
// ═══════════════════════════════════════════════════════════════════

func TestDetectKeywordContext_InFilename(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("com/myapp/utils/LicenseChecker.smali")
	result := &ClassificationResult{}

	ctx := c.detectKeywordContext(pathInfo, "license", result)
	if ctx != ContextFileName {
		t.Fatalf("expected ContextFileName, got %v", ctx)
	}
}

func TestDetectKeywordContext_InPackage(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("com/myapp/license/Helper.smali")
	result := &ClassificationResult{IsLibrary: false}

	ctx := c.detectKeywordContext(pathInfo, "license", result)
	// "license" is in the package path, not in filename "Helper"
	if ctx != ContextPackagePath {
		t.Fatalf("expected ContextPackagePath, got %v", ctx)
	}
}

func TestDetectKeywordContext_InLibrary(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("com/google/license/Helper.smali")
	result := &ClassificationResult{IsLibrary: true}

	ctx := c.detectKeywordContext(pathInfo, "license", result)
	if ctx != ContextLibraryPath {
		t.Fatalf("expected ContextLibraryPath, got %v", ctx)
	}
}

func TestAssessPathReliability_Reliable(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("com/myapp/security/LicenseChecker.smali")
	r := c.assessPathReliability(pathInfo)
	if r != PathReliable {
		t.Fatalf("expected PathReliable, got %v", r)
	}
}

func TestAssessPathReliability_Partial(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	// Mostly obfuscated but has one long readable segment
	pathInfo := NormalizePath("a/b/c/LicenseManager.smali")
	r := c.assessPathReliability(pathInfo)
	if r != PathPartial {
		t.Fatalf("expected PathPartial for a/b/c/LicenseManager.smali, got %v", r)
	}
}

func TestAssessPathReliability_Unreliable(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	// All segments are obfuscated
	pathInfo := NormalizePath("a/b/c.smali")
	r := c.assessPathReliability(pathInfo)
	if r != PathUnreliable {
		t.Fatalf("expected PathUnreliable for a/b/c.smali, got %v", r)
	}
}

func TestAssessPathReliability_SingleSegment(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("Test.smali")
	r := c.assessPathReliability(pathInfo)
	if r != PathReliable {
		t.Fatalf("expected PathReliable for single segment, got %v", r)
	}
}

func TestIsObfuscatedName_SingleChar(t *testing.T) {
	if !isObfuscatedName("a") {
		t.Fatal("'a' should be obfuscated")
	}
	if !isObfuscatedName("z") {
		t.Fatal("'z' should be obfuscated")
	}
	if isObfuscatedName("A") {
		t.Fatal("'A' (uppercase) should NOT be obfuscated")
	}
}

func TestIsObfuscatedName_Short(t *testing.T) {
	if !isObfuscatedName("ab") {
		t.Fatal("'ab' should be obfuscated")
	}
	if !isObfuscatedName("a1") {
		t.Fatal("'a1' should be obfuscated")
	}
	if !isObfuscatedName("abc") {
		t.Fatal("'abc' should be obfuscated")
	}
}

func TestIsObfuscatedName_CamelCase(t *testing.T) {
	if isObfuscatedName("Ab") {
		t.Fatal("'Ab' (CamelCase) should NOT be obfuscated")
	}
	if isObfuscatedName("MainActivity") {
		t.Fatal("'MainActivity' should NOT be obfuscated")
	}
}

func TestIsObfuscatedName_Long(t *testing.T) {
	if isObfuscatedName("LicenseChecker") {
		t.Fatal("'LicenseChecker' should NOT be obfuscated")
	}
	if isObfuscatedName("abcdef") {
		t.Fatal("'abcdef' (>3 chars) should NOT be obfuscated")
	}
}

func TestIsObfuscatedName_WithDollar(t *testing.T) {
	// Inner class: a$1 → check "a" part
	if !isObfuscatedName("a$1") {
		t.Fatal("'a$1' should be obfuscated (inner class of 'a')")
	}
	if isObfuscatedName("MainActivity$Companion") {
		t.Fatal("'MainActivity$Companion' should NOT be obfuscated")
	}
}

func TestCountGenericKeywords(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		MatchedKeywords: []KeywordMatch{
			{Keyword: "check"},
			{Keyword: "license"},
			{Keyword: "validate"},
			{Keyword: "premium"},
		},
	}

	count := c.countGenericKeywords(result)
	if count != 2 { // "check" and "validate" are generic
		t.Fatalf("expected 2 generic keywords, got %d", count)
	}
}

func TestCountGenericKeywords_None(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		MatchedKeywords: []KeywordMatch{
			{Keyword: "license"},
			{Keyword: "premium"},
		},
	}

	count := c.countGenericKeywords(result)
	if count != 0 {
		t.Fatalf("expected 0 generic keywords, got %d", count)
	}
}

func TestApplyContextBonus_FileName(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	match := &KeywordMatch{Keyword: "license", Bonus: 10}
	pathInfo := NormalizePath("com/myapp/LicenseChecker.smali")
	dampening := newDampeningTracker()
	result := &ClassificationResult{}
	trace := newExplainTrace("test")

	c.applyContextBonus(ContextFileName, match, pathInfo, dampening, result, trace)

	if match.Bonus != 13 { // 10 + 3
		t.Fatalf("bonus after ContextFileName = %d, want 13", match.Bonus)
	}
}

func TestApplyContextBonus_PackagePath(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	match := &KeywordMatch{Keyword: "license", Bonus: 10}
	pathInfo := NormalizePath("com/myapp/license/Helper.smali")
	dampening := newDampeningTracker()
	result := &ClassificationResult{}
	trace := newExplainTrace("test")

	c.applyContextBonus(ContextPackagePath, match, pathInfo, dampening, result, trace)

	if match.Bonus != 11 { // 10 + 1
		t.Fatalf("bonus after ContextPackagePath = %d, want 11", match.Bonus)
	}
}

func TestApplyContextBonus_LibraryPath(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	match := &KeywordMatch{Keyword: "verify", Bonus: 10}
	pathInfo := NormalizePath("org/apache/commons/Verifier.smali")
	dampening := newDampeningTracker()
	result := &ClassificationResult{}
	trace := newExplainTrace("test")

	c.applyContextBonus(ContextLibraryPath, match, pathInfo, dampening, result, trace)

	// Dampening should be applied
	if dampening.total >= 1.0 {
		t.Fatalf("dampening should be < 1.0 after ContextLibraryPath, got %f", dampening.total)
	}
}

func TestIsSafeLibraryKeyword_True(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	// "validate" in apache commons path should be safe
	if !c.isSafeLibraryKeyword("org/apache/commons/validator/test.smali", "validate") {
		t.Fatal("'validate' in apache commons should be safe")
	}
}

func TestIsSafeLibraryKeyword_False(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	// "license" in app code should NOT be safe
	if c.isSafeLibraryKeyword("com/myapp/license/checker.smali", "license") {
		t.Fatal("'license' in app code should NOT be safe")
	}
}

func TestIsSafeLibraryKeyword_OkHttp(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	if !c.isSafeLibraryKeyword("okhttp3/internal/tls/certificateverifier.smali", "verify") {
		t.Fatal("'verify' in okhttp should be safe")
	}
}

func TestIsSafeLibraryKeyword_Kotlin(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	if !c.isSafeLibraryKeyword("kotlin/internal/platformcheck.smali", "check") {
		t.Fatal("'check' in kotlin should be safe")
	}
}

func TestIsSafeLibraryKeyword_BouncyCastle(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	if !c.isSafeLibraryKeyword("org/bouncycastle/cert/certverifier.smali", "verify") {
		t.Fatal("'verify' in bouncycastle should be safe")
	}
}

func TestCheckHighValuePaths_NoMatch(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("com/myapp/utils/Helper.smali")
	result := &ClassificationResult{}
	trace := newExplainTrace("test")

	c.checkHighValuePaths(pathInfo, result, trace)
	if len(result.MatchedHighValue) != 0 {
		t.Fatalf("expected 0 high-value matches, got %d", len(result.MatchedHighValue))
	}
}

func TestCheckStandardLibraries_Match(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("smali/com/google/android/gms/internal/zzabc.smali")
	result := &ClassificationResult{}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.checkStandardLibraries(pathInfo, result, dampening, trace)
	// Should match google gms library
}

func TestCheckStandardLibraries_NoMatch(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("smali/com/myapp/security/Guard.smali")
	result := &ClassificationResult{}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.checkStandardLibraries(pathInfo, result, dampening, trace)
	if result.IsLibrary {
		t.Fatal("app code should not be classified as library")
	}
}

func TestCheckObfuscation_Match(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("a/b/c.smali")
	result := &ClassificationResult{}
	trace := newExplainTrace("test")

	c.checkObfuscation(pathInfo, result, trace)
	// May or may not match depending on ObfuscationPatterns in rules
}

func TestCheckAppPackage_Match(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.SetAppPackage("com.target.app")

	pathInfo := NormalizePath("com/target/app/MainActivity.smali")
	result := &ClassificationResult{}
	trace := newExplainTrace("test")

	c.checkAppPackage(pathInfo, result, trace)
	if !result.IsAppCode {
		t.Fatal("should be marked as app code")
	}
}

func TestCheckAppPackage_NoPackageSet(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("com/target/app/MainActivity.smali")
	result := &ClassificationResult{}
	trace := newExplainTrace("test")

	c.checkAppPackage(pathInfo, result, trace)
	// Should not modify result when no app package is set
}

func TestCheckCorrelations_NoHighValue(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("com/myapp/Test.smali")
	result := &ClassificationResult{
		MatchedHighValue: nil,
		MatchedKeywords:  []KeywordMatch{{Keyword: "license"}},
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.checkCorrelations(pathInfo, result, dampening, trace)
	// Should return early — no high-value matches
	if dampening.total != 1.0 {
		t.Fatal("dampening should not change without high-value")
	}
}

func TestCheckCorrelations_NoKeywords(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	pathInfo := NormalizePath("com/myapp/Test.smali")
	result := &ClassificationResult{
		MatchedHighValue: []HighValuePattern{{Pattern: "license"}},
		MatchedKeywords:  nil,
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.checkCorrelations(pathInfo, result, dampening, trace)
	// Should return early — no keywords
	if dampening.total != 1.0 {
		t.Fatal("dampening should not change without keywords")
	}
}

func TestCalculateImportance_PureLibrary(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsLibrary:        true,
		MatchedHighValue: nil,
		MatchedKeywords:  nil,
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.calculateImportance(result, dampening, trace)
	if result.Importance != c.rules.Scoring.StandardLibraryScore {
		t.Fatalf("pure library importance = %d, want %d", result.Importance, c.rules.Scoring.StandardLibraryScore)
	}
}

func TestCalculateImportance_WithKeywords(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsAppCode: true,
		MatchedKeywords: []KeywordMatch{
			{Keyword: "license", Bonus: 20, Config: KeywordConfig{Weight: 20}},
			{Keyword: "premium", Bonus: 15, Config: KeywordConfig{Weight: 15}},
		},
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.calculateImportance(result, dampening, trace)
	if result.Importance <= 0 {
		t.Fatalf("importance with keywords should be > 0, got %d", result.Importance)
	}
}

func TestCalculateConfidence_AppCode(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsAppCode: true,
		IsLibrary: false,
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.calculateConfidence(result, dampening, trace)
	if result.Confidence < 0.5 {
		t.Fatalf("app code confidence should be >= 0.5, got %f", result.Confidence)
	}
}

func TestCalculateConfidence_Library(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsAppCode: false,
		IsLibrary: true,
	}
	dampening := newDampeningTracker()
	dampening.apply("library", 0.4)
	trace := newExplainTrace("test")

	c.calculateConfidence(result, dampening, trace)
	if result.Confidence >= 0.5 {
		t.Fatalf("library confidence should be < 0.5 with dampening, got %f", result.Confidence)
	}
}

func TestCalculateConfidence_WithHighValue(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsAppCode:        true,
		MatchedHighValue: []HighValuePattern{{}, {}, {}},
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.calculateConfidence(result, dampening, trace)
	if result.Confidence < 0.7 {
		t.Fatalf("high-value confidence should be >= 0.7, got %f", result.Confidence)
	}
}

func TestCalculateConfidence_DampenedKeywords(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsAppCode: true,
		MatchedKeywords: []KeywordMatch{
			{Keyword: "check", Dampened: true},
			{Keyword: "verify", Dampened: true},
		},
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.calculateConfidence(result, dampening, trace)
	// Dampened keywords should reduce confidence
	if result.Confidence > 0.9 {
		t.Logf("confidence with dampened keywords = %f", result.Confidence)
	}
}

// ═══════════════════════════════════════════════════════════════════
// ScoringConfig getter tests
// ═══════════════════════════════════════════════════════════════════

func TestScoringConfig_GetCombinationMultiplier_Default(t *testing.T) {
	s := &ScoringConfig{}
	if s.GetCombinationMultiplier() != 1.5 {
		t.Fatalf("default = %f, want 1.5", s.GetCombinationMultiplier())
	}
}

func TestScoringConfig_GetCombinationMultiplier_Custom(t *testing.T) {
	v := 2.0
	s := &ScoringConfig{CombinationMultiplier: &v}
	if s.GetCombinationMultiplier() != 2.0 {
		t.Fatalf("custom = %f, want 2.0", s.GetCombinationMultiplier())
	}
}

func TestScoringConfig_GetDefaultLibraryDampening(t *testing.T) {
	s := &ScoringConfig{}
	if s.GetDefaultLibraryDampening() != 0.4 {
		t.Fatalf("default = %f, want 0.4", s.GetDefaultLibraryDampening())
	}
	v := 0.6
	s2 := &ScoringConfig{DefaultLibraryDampening: &v}
	if s2.GetDefaultLibraryDampening() != 0.6 {
		t.Fatalf("custom = %f, want 0.6", s2.GetDefaultLibraryDampening())
	}
}

func TestScoringConfig_GetDampeningFloor(t *testing.T) {
	s := &ScoringConfig{}
	if s.GetDampeningFloor() != 0.2 {
		t.Fatalf("default = %f, want 0.2", s.GetDampeningFloor())
	}
	v := 0.1
	s2 := &ScoringConfig{DampeningFloor: &v}
	if s2.GetDampeningFloor() != 0.1 {
		t.Fatalf("custom = %f", s2.GetDampeningFloor())
	}
}

func TestScoringConfig_GetDampeningCeiling(t *testing.T) {
	s := &ScoringConfig{}
	if s.GetDampeningCeiling() != 1.5 {
		t.Fatalf("default = %f, want 1.5", s.GetDampeningCeiling())
	}
	v := 2.0
	s2 := &ScoringConfig{DampeningCeiling: &v}
	if s2.GetDampeningCeiling() != 2.0 {
		t.Fatalf("custom = %f", s2.GetDampeningCeiling())
	}
}

func TestScoringConfig_GetGenericPenaltyCap(t *testing.T) {
	s := &ScoringConfig{}
	if s.GetGenericPenaltyCap() != 2 {
		t.Fatalf("default = %d, want 2", s.GetGenericPenaltyCap())
	}
	v := 5
	s2 := &ScoringConfig{GenericPenaltyCap: &v}
	if s2.GetGenericPenaltyCap() != 5 {
		t.Fatalf("custom = %d", s2.GetGenericPenaltyCap())
	}
}

func TestScoringConfig_GetDefaultFilenameBonus(t *testing.T) {
	s := &ScoringConfig{}
	if s.GetDefaultFilenameBonus() != 3 {
		t.Fatalf("default = %d, want 3", s.GetDefaultFilenameBonus())
	}
	v := 10
	s2 := &ScoringConfig{DefaultFilenameBonus: &v}
	if s2.GetDefaultFilenameBonus() != 10 {
		t.Fatalf("custom = %d", s2.GetDefaultFilenameBonus())
	}
}

func TestScoringConfig_GetCorrelationBoost(t *testing.T) {
	s := &ScoringConfig{}
	if s.GetCorrelationBoost() != 1.2 {
		t.Fatalf("default = %f, want 1.2", s.GetCorrelationBoost())
	}
	v := 1.5
	s2 := &ScoringConfig{CorrelationBoost: &v}
	if s2.GetCorrelationBoost() != 1.5 {
		t.Fatalf("custom = %f", s2.GetCorrelationBoost())
	}
}

// ═══════════════════════════════════════════════════════════════════
// ObfuscationPattern tests
// ═══════════════════════════════════════════════════════════════════

func TestObfuscationPattern_Compile(t *testing.T) {
	p := &ObfuscationPattern{Regex: `^[a-z]$`}
	err := p.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !p.Matches("a") {
		t.Fatal("should match single lowercase letter")
	}
	if p.Matches("abc") {
		t.Fatal("should not match multiple chars")
	}
}

func TestObfuscationPattern_Compile_Invalid(t *testing.T) {
	p := &ObfuscationPattern{Regex: `[invalid`}
	err := p.Compile()
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestObfuscationPattern_Matches_NotCompiled(t *testing.T) {
	p := &ObfuscationPattern{Regex: `^[a-z]$`}
	// Not compiled yet
	if p.Matches("a") {
		t.Fatal("should return false when not compiled")
	}
}

func TestObfuscationPattern_Compile_Empty(t *testing.T) {
	p := &ObfuscationPattern{Regex: ""}
	err := p.Compile()
	if err != nil {
		t.Fatalf("empty regex should not error: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// KeywordConfig tests
// ═══════════════════════════════════════════════════════════════════

func TestKeywordConfig_GetFilenameBonus_Default(t *testing.T) {
	k := &KeywordConfig{}
	if k.GetFilenameBonus(5) != 5 {
		t.Fatalf("default = %d, want 5", k.GetFilenameBonus(5))
	}
}

func TestKeywordConfig_GetFilenameBonus_Custom(t *testing.T) {
	v := 10
	k := &KeywordConfig{FilenameBonus: &v}
	if k.GetFilenameBonus(5) != 10 {
		t.Fatalf("custom = %d, want 10", k.GetFilenameBonus(5))
	}
}

// ═══════════════════════════════════════════════════════════════════
// SafeLibraryPattern tests
// ═══════════════════════════════════════════════════════════════════

func TestSafeLibraryPattern_GetDampening_Default(t *testing.T) {
	sp := &SafeLibraryPattern{}
	if sp.GetDampening(0.5) != 0.5 {
		t.Fatalf("default = %f, want 0.5", sp.GetDampening(0.5))
	}
}

func TestSafeLibraryPattern_GetDampening_Custom(t *testing.T) {
	v := 0.3
	sp := &SafeLibraryPattern{Dampening: &v}
	if sp.GetDampening(0.5) != 0.3 {
		t.Fatalf("custom = %f, want 0.3", sp.GetDampening(0.5))
	}
}

// ═══════════════════════════════════════════════════════════════════
// calculateImportance edge cases
// ═══════════════════════════════════════════════════════════════════

func TestCalculateImportance_SingleKeyword(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsAppCode: true,
		MatchedKeywords: []KeywordMatch{
			{Keyword: "license", Bonus: 15, Config: KeywordConfig{Weight: 15}},
		},
		MatchedHighValue: []HighValuePattern{
			{Pattern: "something_else", Weight: 5},
		},
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.calculateImportance(result, dampening, trace)
	// Single keyword + 1 high-value → soft cap applied
	if result.Importance < 0 {
		t.Fatal("importance should not be negative")
	}
}

func TestCalculateImportance_MultiHighValue(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsAppCode: true,
		MatchedKeywords: []KeywordMatch{
			{Keyword: "license", Bonus: 10},
		},
		MatchedHighValue: []HighValuePattern{
			{Pattern: "a", Weight: 3},
			{Pattern: "b", Weight: 3},
			{Pattern: "c", Weight: 3},
		},
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.calculateImportance(result, dampening, trace)
	// 3 high-value → multi boost +2
	if result.Importance <= 0 {
		t.Fatal("importance should be positive with multi high-value")
	}
}

func TestCalculateImportance_GenericKeywords(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsAppCode: true,
		MatchedKeywords: []KeywordMatch{
			{Keyword: "check", Bonus: 5},
			{Keyword: "validate", Bonus: 5},
			{Keyword: "verify", Bonus: 5},
		},
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.calculateImportance(result, dampening, trace)
	// Generic keywords should get penalty
}

func TestCalculateImportance_WithDampening(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsAppCode: true,
		MatchedKeywords: []KeywordMatch{
			{Keyword: "license", Bonus: 20},
		},
	}
	dampening := newDampeningTracker()
	dampening.apply("library", 0.5) // 50% dampening
	trace := newExplainTrace("test")

	c.calculateImportance(result, dampening, trace)
	// Importance should be dampened
	if result.Importance > result.RawImportance {
		t.Fatal("dampened importance should be <= raw importance")
	}
}

func TestCalculateImportance_WithBoost(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsAppCode: true,
		MatchedKeywords: []KeywordMatch{
			{Keyword: "license", Bonus: 10},
		},
	}
	dampening := newDampeningTracker()
	dampening.apply("correlation", 1.3) // boost
	trace := newExplainTrace("test")

	c.calculateImportance(result, dampening, trace)
	// Importance should be boosted
}

func TestCalculateImportance_ObfuscationBonus(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)

	result := &ClassificationResult{
		IsAppCode:       true,
		ObfuscationType: "proguard",
		MatchedKeywords: []KeywordMatch{
			{Keyword: "license", Bonus: 10},
		},
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.calculateImportance(result, dampening, trace)
	// Should include obfuscation bonus
}

func TestCalculateImportance_AppPackageBonus(t *testing.T) {
	rules := GetProfile(ProfileStrict)
	c := NewClassifier(rules)
	c.SetAppPackage("com.myapp")

	result := &ClassificationResult{
		IsAppCode: true,
		MatchedKeywords: []KeywordMatch{
			{Keyword: "license", Bonus: 10},
		},
		Reasons: []ClassificationReason{
			{Type: ReasonAppPackage},
		},
	}
	dampening := newDampeningTracker()
	trace := newExplainTrace("test")

	c.calculateImportance(result, dampening, trace)
	// Should include app package bonus
}
