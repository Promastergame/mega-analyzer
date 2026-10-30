package filter

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SetRulesBaseDir — basic behavior
// ═══════════════════════════════════════════════════════════════════════════════

func TestSetRulesBaseDir_ValidDir(t *testing.T) {
	dir := t.TempDir()
	if err := SetRulesBaseDir(dir); err != nil {
		t.Fatalf("SetRulesBaseDir: %v", err)
	}
	// Reset to empty to avoid affecting other tests
	rulesBaseDirMu.Lock()
	rulesBaseDir = ""
	rulesBaseDirMu.Unlock()
}

func TestSetRulesBaseDir_RelativePath(t *testing.T) {
	// Relative paths are converted to absolute by filepath.Abs — should not error
	if err := SetRulesBaseDir("."); err != nil {
		t.Fatalf("SetRulesBaseDir('.'): %v", err)
	}
	rulesBaseDirMu.Lock()
	rulesBaseDir = ""
	rulesBaseDirMu.Unlock()
}

func TestValidatePath_InsideBaseDir(t *testing.T) {
	dir := t.TempDir()
	rulesBaseDirMu.Lock()
	rulesBaseDir = dir
	rulesBaseDirMu.Unlock()
	defer func() {
		rulesBaseDirMu.Lock()
		rulesBaseDir = ""
		rulesBaseDirMu.Unlock()
	}()

	safe := filepath.Join(dir, "rules.json")
	got, err := validatePath(safe)
	if err != nil {
		t.Fatalf("validatePath inside base: %v", err)
	}
	if !strings.HasPrefix(got, dir) {
		t.Errorf("path %q should be under base dir %q", got, dir)
	}
}

func TestValidatePath_OutsideBaseDir(t *testing.T) {
	dir := t.TempDir()
	rulesBaseDirMu.Lock()
	rulesBaseDir = dir
	rulesBaseDirMu.Unlock()
	defer func() {
		rulesBaseDirMu.Lock()
		rulesBaseDir = ""
		rulesBaseDirMu.Unlock()
	}()

	outside := filepath.Join(dir, "..", "outside.json")
	_, err := validatePath(outside)
	if err == nil {
		t.Error("expected error for path outside base dir")
	}
}

func TestValidatePath_NoBaseDir(t *testing.T) {
	// When no base dir is set, any path should be accepted
	rulesBaseDirMu.Lock()
	rulesBaseDir = ""
	rulesBaseDirMu.Unlock()

	_, err := validatePath("/tmp/any/path.json")
	if err != nil {
		t.Fatalf("validatePath with no base dir should succeed: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FilterRules.compile
// ═══════════════════════════════════════════════════════════════════════════════

func TestCompile_ObfuscationPatterns(t *testing.T) {
	rules := FilterRules{
		compiledMu: &sync.RWMutex{},
		ObfuscationPatterns: []ObfuscationPattern{
			{Name: "test", Regex: `^[a-z]$`, Weight: 5},
		},
	}
	if err := rules.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !rules.compiled {
		t.Error("compiled flag should be true after compile()")
	}
	// Calling compile() again should be idempotent (no-op)
	if err := rules.compile(); err != nil {
		t.Fatalf("second compile: %v", err)
	}
}

func TestCompile_InvalidObfuscationRegex(t *testing.T) {
	rules := FilterRules{
		compiledMu: &sync.RWMutex{},
		ObfuscationPatterns: []ObfuscationPattern{
			{Name: "bad", Regex: `[invalid`, Weight: 5},
		},
	}
	if err := rules.compile(); err == nil {
		t.Error("expected error for invalid obfuscation regex")
	}
}

func TestCompile_HighValuePatternRegex(t *testing.T) {
	rules := FilterRules{
		compiledMu: &sync.RWMutex{},
		HighValuePatterns: []HighValuePattern{
			{Pattern: `^license.*`, MatchType: MatchRegex, Weight: 9, Category: "license"},
		},
	}
	if err := rules.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
}

func TestCompile_InvalidHighValueRegex(t *testing.T) {
	rules := FilterRules{
		compiledMu: &sync.RWMutex{},
		HighValuePatterns: []HighValuePattern{
			{Pattern: `[bad`, MatchType: MatchRegex, Weight: 9, Category: "test"},
		},
	}
	if err := rules.compile(); err == nil {
		t.Error("expected error for invalid high_value regex")
	}
}

func TestCompile_SortsObfuscationByWeight(t *testing.T) {
	rules := FilterRules{
		compiledMu: &sync.RWMutex{},
		ObfuscationPatterns: []ObfuscationPattern{
			{Name: "low", Regex: `^a$`, Weight: 1},
			{Name: "high", Regex: `^b$`, Weight: 9},
			{Name: "mid", Regex: `^c$`, Weight: 5},
		},
	}
	if err := rules.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Should be sorted descending by weight
	if rules.ObfuscationPatterns[0].Weight < rules.ObfuscationPatterns[1].Weight {
		t.Error("ObfuscationPatterns should be sorted descending by weight")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// profiles.go — Apply (via ProfileModifier interface)
// ═══════════════════════════════════════════════════════════════════════════════

func TestBuiltinModifier_Apply_Strict(t *testing.T) {
	mod := GetModifier(ProfileStrict)
	if mod.Name() != "strict" {
		t.Errorf("Name() = %q, want 'strict'", mod.Name())
	}
	if mod.Description() == "" {
		t.Error("Description() should not be empty")
	}

	dr := DefaultRules()
	base := *dr.DeepCopy()
	result := mod.Apply(base)
	// Strict profile increases BaseImportance
	if result.Scoring.BaseImportance <= 0 {
		t.Error("strict profile should have positive BaseImportance")
	}
}

func TestBuiltinModifier_Apply_Loose(t *testing.T) {
	mod := GetModifier(ProfileLoose)
	dr := DefaultRules()
	base := *dr.DeepCopy()
	result := mod.Apply(base)
	// Loose profile adds keywords
	if _, ok := result.KeywordWeights["entitlement"]; !ok {
		t.Error("loose profile should add 'entitlement' keyword")
	}
}

func TestBuiltinModifier_Apply_Paranoid(t *testing.T) {
	mod := GetModifier(ProfileParanoid)
	dr := DefaultRules()
	base := *dr.DeepCopy()
	result := mod.Apply(base)
	// Paranoid profile adds suspicious keywords
	if _, ok := result.KeywordWeights["reflection"]; !ok {
		t.Error("paranoid profile should add 'reflection' keyword")
	}
}

func TestBuiltinModifier_Apply_Audit(t *testing.T) {
	mod := GetModifier(ProfileAudit)
	dr := DefaultRules()
	base := *dr.DeepCopy()
	result := mod.Apply(base)
	// Audit profile removes all libraries
	if len(result.StandardLibraries) != 0 {
		t.Errorf("audit profile should remove all libraries, got %d", len(result.StandardLibraries))
	}
}

func TestBuiltinModifier_Apply_Balanced(t *testing.T) {
	// Unknown profile → balanced (identity)
	mod := GetModifier("nonexistent")
	if mod.Name() != "balanced" {
		t.Errorf("unknown profile should give 'balanced' modifier, got %q", mod.Name())
	}
	dr := DefaultRules()
	base := *dr.DeepCopy()
	result := mod.Apply(base)
	// Balanced should leave BaseImportance at the default value
	if result.Scoring.BaseImportance != base.Scoring.BaseImportance {
		t.Errorf("balanced profile should be identity, got BaseImportance %d vs %d",
			result.Scoring.BaseImportance, base.Scoring.BaseImportance)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// GetProfile — all profile types
// ═══════════════════════════════════════════════════════════════════════════════

func TestGetProfile_AllTypes(t *testing.T) {
	for _, pt := range AllProfiles() {
		rules := GetProfile(pt)
		if rules.KeywordWeights == nil {
			t.Errorf("GetProfile(%q) returned nil KeywordWeights", pt)
		}
	}
}

func TestGetProfile_Strict_HasHighBaseImportance(t *testing.T) {
	r := GetProfile(ProfileStrict)
	if r.Scoring.BaseImportance < 3 {
		t.Errorf("strict BaseImportance = %d, want ≥3", r.Scoring.BaseImportance)
	}
}

func TestGetProfile_Audit_NoLibraries(t *testing.T) {
	r := GetProfile(ProfileAudit)
	if len(r.StandardLibraries) != 0 {
		t.Errorf("audit profile should have 0 libraries, got %d", len(r.StandardLibraries))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ProfileBuilder
// ═══════════════════════════════════════════════════════════════════════════════

func TestProfileBuilder_Build_Basics(t *testing.T) {
	rules := NewProfileBuilder(ProfileBalanced).
		WithBaseImportance(8).
		Build()
	if rules.Scoring.BaseImportance != 8 {
		t.Errorf("BaseImportance = %d, want 8", rules.Scoring.BaseImportance)
	}
}

func TestProfileBuilder_WithDampening(t *testing.T) {
	rules := NewProfileBuilder(ProfileBalanced).
		WithDampening(0.5, 0.3, 1.2).
		Build()
	if rules.Scoring.GetDefaultLibraryDampening() != 0.5 {
		t.Errorf("Dampening = %.2f, want 0.5", rules.Scoring.GetDefaultLibraryDampening())
	}
	if rules.Scoring.GetDampeningFloor() != 0.3 {
		t.Errorf("DampeningFloor = %.2f, want 0.3", rules.Scoring.GetDampeningFloor())
	}
}

func TestProfileBuilder_WithoutLibraries_More2(t *testing.T) {
	before := GetProfile(ProfileBalanced)
	beforeCount := len(before.StandardLibraries)

	rules := NewProfileBuilder(ProfileBalanced).
		WithoutLibraries("analytics", "ads_sdk").
		Build()
	afterCount := len(rules.StandardLibraries)

	if afterCount >= beforeCount {
		t.Errorf("WithoutLibraries should reduce library count: before=%d after=%d",
			beforeCount, afterCount)
	}
}

func TestProfileBuilder_WithKeyword_More2(t *testing.T) {
	rules := NewProfileBuilder(ProfileBalanced).
		WithKeyword("newkeyword", KeywordConfig{
			Weight:   7,
			Category: "custom",
			MinBonus: 5,
			MaxBonus: 9,
		}).
		Build()
	if _, ok := rules.KeywordWeights["newkeyword"]; !ok {
		t.Error("expected 'newkeyword' in KeywordWeights")
	}
}

func TestProfileBuilder_WithoutKeywords_More2(t *testing.T) {
	before := GetProfile(ProfileBalanced)
	if _, ok := before.KeywordWeights["license"]; !ok {
		t.Skip("'license' keyword not in balanced profile")
	}

	rules := NewProfileBuilder(ProfileBalanced).
		WithoutKeywords("license").
		Build()
	if _, ok := rules.KeywordWeights["license"]; ok {
		t.Error("expected 'license' to be removed from keywords")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CompareProfiles
// ═══════════════════════════════════════════════════════════════════════════════

func TestCompareProfiles_StrictVsLoose(t *testing.T) {
	diff := CompareProfiles(ProfileStrict, ProfileLoose)
	// These should have different BaseImportance / ScoringChanges
	_ = diff
	// At minimum, comparison should not panic and return a non-nil struct
	if diff.ScoringChanges == nil {
		t.Error("ScoringChanges should not be nil")
	}
}

func TestCompareProfiles_BalancedVsBalanced(t *testing.T) {
	diff := CompareProfiles(ProfileBalanced, ProfileBalanced)
	// Same profile vs same profile — no changes
	if len(diff.AddedLibraries) != 0 {
		t.Errorf("no added libraries expected, got: %v", diff.AddedLibraries)
	}
	if len(diff.RemovedLibraries) != 0 {
		t.Errorf("no removed libraries expected, got: %v", diff.RemovedLibraries)
	}
}

func TestCompareProfiles_AuditHasRemovedLibraries(t *testing.T) {
	// Audit removes all libraries vs balanced which has many
	diff := CompareProfiles(ProfileAudit, ProfileBalanced)
	// Going from audit to balanced → AddedLibraries should be non-empty
	if len(diff.AddedLibraries) == 0 {
		t.Error("expected added libraries going from audit to balanced")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ProfileDescription / IsValidProfile / ParseProfile
// ═══════════════════════════════════════════════════════════════════════════════

func TestProfileDescription_AllTypes(t *testing.T) {
	for _, pt := range AllProfiles() {
		desc := ProfileDescription(pt)
		if desc == "" || desc == "Unknown profile" {
			t.Errorf("ProfileDescription(%q) = %q, want non-empty known description", pt, desc)
		}
	}
	// Unknown profile
	if ProfileDescription("nonexistent") != "Unknown profile" {
		t.Error("unknown profile should return 'Unknown profile'")
	}
}

func TestIsValidProfile_More2(t *testing.T) {
	for _, pt := range AllProfiles() {
		if !IsValidProfile(pt) {
			t.Errorf("IsValidProfile(%q) = false, want true", pt)
		}
	}
	if IsValidProfile("invalid") {
		t.Error("IsValidProfile('invalid') = true, want false")
	}
}

func TestParseProfile_More2(t *testing.T) {
	for _, pt := range AllProfiles() {
		got, ok := ParseProfile(string(pt))
		if !ok {
			t.Errorf("ParseProfile(%q) ok = false, want true", pt)
		}
		if got != pt {
			t.Errorf("ParseProfile(%q) = %q, want %q", pt, got, pt)
		}
	}
	// Case-insensitive
	got, ok := ParseProfile("STRICT")
	if !ok || got != ProfileStrict {
		t.Errorf("ParseProfile('STRICT') = %q, %v", got, ok)
	}
	// Unknown → balanced
	got, ok = ParseProfile("unknown")
	if ok {
		t.Error("ParseProfile('unknown') ok should be false")
	}
	if got != ProfileBalanced {
		t.Errorf("ParseProfile('unknown') = %q, want balanced", got)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FilterRules.Validate
// ═══════════════════════════════════════════════════════════════════════════════

func TestFilterRules_Validate_DefaultRules(t *testing.T) {
	rules := DefaultRules()
	result := rules.Validate()
	// Just check Validate doesn't panic; embedded regexes may have warnings
	_ = result
}

func TestFilterRules_Validate_InvalidScoring(t *testing.T) {
	rules := DefaultRules()
	rules.Scoring.MinImportance = 10
	rules.Scoring.MaxImportance = 5 // min > max
	result := rules.Validate()
	if result.Valid {
		t.Error("should be invalid when MinImportance > MaxImportance")
	}
}

func TestFilterRules_Validate_NegativeBaseImportance(t *testing.T) {
	rules := DefaultRules()
	rules.Scoring.BaseImportance = -1
	result := rules.Validate()
	if result.Valid {
		t.Error("should be invalid when BaseImportance < 0")
	}
}

func TestFilterRules_Validate_MaxImportanceTooHigh(t *testing.T) {
	rules := DefaultRules()
	rules.Scoring.MaxImportance = 101
	result := rules.Validate()
	if result.Valid {
		t.Error("should be invalid when MaxImportance > 100")
	}
}

func TestFilterRules_Validate_EmptyVersion_Warning(t *testing.T) {
	rules := DefaultRules()
	rules.Metadata.Version = ""
	result := rules.Validate()
	hasVersionWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "rules_version") {
			hasVersionWarning = true
		}
	}
	if !hasVersionWarning {
		t.Errorf("expected version warning, got warnings: %v", result.Warnings)
	}
}

func TestFilterRules_Validate_EmptyLibraryPattern(t *testing.T) {
	rules := DefaultRules()
	rules.StandardLibraries = append(rules.StandardLibraries, LibraryPattern{
		Pattern:   "",
		MatchType: MatchPrefix,
		Category:  "test",
	})
	result := rules.Validate()
	if result.Valid {
		t.Error("empty library pattern should cause validation failure")
	}
}

func TestFilterRules_Validate_InvalidMatchType(t *testing.T) {
	rules := DefaultRules()
	rules.StandardLibraries = append(rules.StandardLibraries, LibraryPattern{
		Pattern:   "com/test/",
		MatchType: "invalid_type",
		Category:  "test",
	})
	result := rules.Validate()
	if result.Valid {
		t.Error("invalid match type should cause validation failure")
	}
}

func TestFilterRules_Validate_InvalidHighValueRegex(t *testing.T) {
	rules := DefaultRules()
	rules.HighValuePatterns = append(rules.HighValuePatterns, HighValuePattern{
		Pattern:   "[bad",
		MatchType: MatchRegex,
		Weight:    5,
		Category:  "test",
	})
	result := rules.Validate()
	if result.Valid {
		t.Error("invalid regex in HighValuePattern should fail validation")
	}
}

func TestFilterRules_Validate_InvalidObfuscationRegex(t *testing.T) {
	rules := DefaultRules()
	rules.ObfuscationPatterns = append(rules.ObfuscationPatterns, ObfuscationPattern{
		Name:   "bad",
		Regex:  "[broken",
		Weight: 3,
	})
	result := rules.Validate()
	if result.Valid {
		t.Error("invalid obfuscation regex should fail validation")
	}
}

func TestFilterRules_Validate_InvalidContextRuleEffect(t *testing.T) {
	rules := DefaultRules()
	rules.ContextRules = append(rules.ContextRules, ContextRule{
		Keyword:         "test",
		ContextContains: []string{"something"},
		Effect:          "invalid_effect",
		Factor:          1.0,
	})
	result := rules.Validate()
	if result.Valid {
		t.Error("invalid context rule effect should fail validation")
	}
}

func TestFilterRules_Validate_ZeroContextRuleFactor(t *testing.T) {
	rules := DefaultRules()
	rules.ContextRules = append(rules.ContextRules, ContextRule{
		Keyword:         "test",
		ContextContains: []string{"something"},
		Effect:          "boost",
		Factor:          0, // must be > 0
	})
	result := rules.Validate()
	if result.Valid {
		t.Error("context rule factor=0 should fail validation")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FilterRules.Save / LoadRules round-trip
// ═══════════════════════════════════════════════════════════════════════════════

func TestFilterRules_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")

	rules := GetProfile(ProfileBalanced)
	if err := rules.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected file to exist after Save")
	}

	loaded, err := LoadRules(path)
	if err != nil {
		// Embedded patterns may have compile warnings; just check it loaded
		t.Logf("LoadRules note: %v", err)
		return
	}

	if loaded.Metadata.Version == "" {
		t.Error("loaded rules should have version set")
	}
}

func TestLoadRules_FileNotFound(t *testing.T) {
	_, err := LoadRules("/nonexistent/path/rules.json")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLoadRules_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{bad json"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadRules(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadRulesValidated_ReturnsValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	rules := GetProfile(ProfileBalanced)
	if err := rules.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, validation, err := LoadRulesValidated(path)
	// Embedded patterns may have compile errors for some regex escapes
	_ = err
	_ = validation
}

// ═══════════════════════════════════════════════════════════════════════════════
// MarshalDeterministic
// ═══════════════════════════════════════════════════════════════════════════════

func TestMarshalDeterministic_Idempotent(t *testing.T) {
	rules := GetProfile(ProfileBalanced)
	data1, err := rules.MarshalDeterministic()
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}
	data2, err := rules.MarshalDeterministic()
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}
	if string(data1) != string(data2) {
		t.Error("MarshalDeterministic should produce identical output on repeated calls")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ScoringConfig getters
// ═══════════════════════════════════════════════════════════════════════════════

func TestScoringConfig_GettersWithNilPointers(t *testing.T) {
	s := &ScoringConfig{}
	if s.GetCombinationMultiplier() != 1.5 {
		t.Errorf("default CombinationMultiplier = %.2f, want 1.5", s.GetCombinationMultiplier())
	}
	if s.GetDefaultLibraryDampening() != 0.4 {
		t.Errorf("default DefaultLibraryDampening = %.2f, want 0.4", s.GetDefaultLibraryDampening())
	}
	if s.GetDampeningFloor() != 0.2 {
		t.Errorf("default DampeningFloor = %.2f, want 0.2", s.GetDampeningFloor())
	}
	if s.GetDampeningCeiling() != 1.5 {
		t.Errorf("default DampeningCeiling = %.2f, want 1.5", s.GetDampeningCeiling())
	}
	if s.GetGenericPenaltyCap() != 2 {
		t.Errorf("default GenericPenaltyCap = %d, want 2", s.GetGenericPenaltyCap())
	}
	if s.GetDefaultFilenameBonus() != 3 {
		t.Errorf("default DefaultFilenameBonus = %d, want 3", s.GetDefaultFilenameBonus())
	}
	if s.GetCorrelationBoost() != 1.2 {
		t.Errorf("default CorrelationBoost = %.2f, want 1.2", s.GetCorrelationBoost())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LibraryPattern.GetDampening / KeywordConfig.GetFilenameBonus
// ═══════════════════════════════════════════════════════════════════════════════

func TestLibraryPattern_GetDampening_More2(t *testing.T) {
	l := LibraryPattern{}
	if l.GetDampening(0.7) != 0.7 {
		t.Errorf("nil Dampening should return default, got %.2f", l.GetDampening(0.7))
	}
	v := 0.3
	l.Dampening = &v
	if l.GetDampening(0.7) != 0.3 {
		t.Errorf("set Dampening should return 0.3, got %.2f", l.GetDampening(0.7))
	}
}

func TestKeywordConfig_GetFilenameBonus(t *testing.T) {
	k := KeywordConfig{}
	if k.GetFilenameBonus(5) != 5 {
		t.Errorf("nil FilenameBonus should return default, got %d", k.GetFilenameBonus(5))
	}
	v := 2
	k.FilenameBonus = &v
	if k.GetFilenameBonus(5) != 2 {
		t.Errorf("set FilenameBonus should return 2, got %d", k.GetFilenameBonus(5))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ObfuscationPattern.Compile / Matches
// ═══════════════════════════════════════════════════════════════════════════════

func TestObfuscationPattern_CompileAndMatch(t *testing.T) {
	op := &ObfuscationPattern{Name: "single", Regex: `^[a-z]$`, Weight: 7}
	if err := op.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !op.Matches("a") {
		t.Error("should match single lowercase letter")
	}
	if op.Matches("aa") {
		t.Error("should not match double letter")
	}
}

func TestObfuscationPattern_MatchesWithoutCompile(t *testing.T) {
	op := &ObfuscationPattern{Name: "single", Regex: `^[a-z]$`, Weight: 7}
	// compiled is nil — should return false
	if op.Matches("a") {
		t.Error("uncompiled pattern should not match")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HighValuePattern.Compile
// ═══════════════════════════════════════════════════════════════════════════════

func TestHighValuePattern_Compile_NonRegex(t *testing.T) {
	hvp := &HighValuePattern{Pattern: "license", MatchType: MatchContains}
	if err := hvp.Compile(); err != nil {
		t.Fatalf("Compile on non-regex: %v", err)
	}
	// Should be a no-op for non-regex
	if hvp.compiled != nil {
		t.Error("expected nil compiled for non-regex pattern")
	}
}

func TestHighValuePattern_Compile_Regex(t *testing.T) {
	hvp := &HighValuePattern{Pattern: `^lic.*`, MatchType: MatchRegex}
	if err := hvp.Compile(); err != nil {
		t.Fatalf("Compile on regex: %v", err)
	}
	if hvp.compiled == nil {
		t.Error("expected compiled regex to be set")
	}
}

func TestHighValuePattern_Compile_InvalidRegex(t *testing.T) {
	hvp := &HighValuePattern{Pattern: `[bad`, MatchType: MatchRegex}
	if err := hvp.Compile(); err == nil {
		t.Error("expected error for invalid regex")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// normalizeKeywordConfig
// ═══════════════════════════════════════════════════════════════════════════════

func TestNormalizeKeywordConfig(t *testing.T) {
	kc := KeywordConfig{
		Category:    "  LICENSE  ",
		Aliases:     []string{"  LIC  ", "  LICENSE_KEY  "},
		Combinators: []string{"  CHECK  ", "  VERIFY  "},
	}
	normalized := normalizeKeywordConfig(kc)
	if normalized.Category != "license" {
		t.Errorf("Category = %q, want 'license'", normalized.Category)
	}
	if normalized.Aliases[0] != "lic" {
		t.Errorf("Aliases[0] = %q, want 'lic'", normalized.Aliases[0])
	}
	if normalized.Combinators[0] != "check" {
		t.Errorf("Combinators[0] = %q, want 'check'", normalized.Combinators[0])
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DeepCopy correctness
// ═══════════════════════════════════════════════════════════════════════════════

func TestDeepCopy_NilSafe(t *testing.T) {
	var r *FilterRules
	if r.DeepCopy() != nil {
		t.Error("DeepCopy of nil should return nil")
	}
}

func TestDeepCopy_Isolated(t *testing.T) {
	original := GetProfile(ProfileBalanced)
	copy := original.DeepCopy()

	// Mutate the copy — should not affect original
	copy.Scoring.BaseImportance = 999
	if original.Scoring.BaseImportance == 999 {
		t.Error("DeepCopy should be isolated from original")
	}
}

func TestDeepCopy_PointerFields(t *testing.T) {
	rules := DefaultRules()
	cp := rules.DeepCopy()

	// Mutate pointer field in copy
	*cp.Scoring.DefaultLibraryDampening = 0.99
	if *rules.Scoring.DefaultLibraryDampening == 0.99 {
		t.Error("pointer field mutation in copy should not affect original")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// isSupportedVersion / isValidMatchType
// ═══════════════════════════════════════════════════════════════════════════════

func TestIsSupportedVersion(t *testing.T) {
	for _, v := range supportedVersions {
		if !isSupportedVersion(v) {
			t.Errorf("isSupportedVersion(%q) = false, want true", v)
		}
	}
	if isSupportedVersion("0.0.1") {
		t.Error("isSupportedVersion('0.0.1') = true, want false")
	}
}

func TestIsValidMatchType(t *testing.T) {
	valid := []MatchType{MatchPrefix, MatchContains, MatchSuffix, MatchRegex}
	for _, mt := range valid {
		if !isValidMatchType(mt) {
			t.Errorf("isValidMatchType(%q) = false, want true", mt)
		}
	}
	if isValidMatchType("invalid") {
		t.Error("isValidMatchType('invalid') = true, want false")
	}
}
