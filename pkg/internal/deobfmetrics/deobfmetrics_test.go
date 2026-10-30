package deobfmetrics

import (
	"math"
	"strings"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input   string
		minBits float64
		maxBits float64
	}{
		{"", 0, 0},
		{"aaaa", 0, 0.01},      // all same char = 0 entropy
		{"ab", 0.99, 1.01},     // 2 chars = 1 bit
		{"abcd", 1.99, 2.01},   // 4 chars = 2 bits
		{"a", 0, 0.01},         // single char
		{"xK9mQ2pL", 2.5, 3.5}, // random-looking
		{"привет", 2.5, 3.0},   // Cyrillic unique runes
		{"🎉🚀💯", 1.5, 1.6},      // 3 unique emoji runes = log2(3) = 1.585
	}

	for _, tt := range tests {
		got := ShannonEntropy(tt.input)
		if got < tt.minBits || got > tt.maxBits {
			t.Errorf("ShannonEntropy(%q) = %f, want [%f, %f]", tt.input, got, tt.minBits, tt.maxBits)
		}
	}
}

func TestIsObfuscated(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"a", true},
		{"b", true},
		{"ab", true},
		{"x1", true},
		{"a1b2", true},
		{"xK9m", true},
		{"getName", false},
		{"isValid", false},
		{"onCreate", false},
		{"checkLicense", false},
		{"", false},
	}

	for _, tt := range tests {
		got := IsObfuscated(tt.name)
		if got != tt.expected {
			t.Errorf("IsObfuscated(%q) = %v, want %v", tt.name, got, tt.expected)
		}
	}
}

func TestIsMeaningful(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"getName", true},
		{"setPassword", true},
		{"isValid", true},
		{"hasPermission", true},
		{"onCreate", true},
		{"init_database", true},
		{"ISO", true},              // uppercase acronym
		{"URL", true},              // uppercase acronym
		{"HTTP", true},             // uppercase acronym
		{"JSON", true},             // uppercase acronym
		{"get_HTTPResponse", true}, // combined prefix and acronym with snake/camel
		{"island", false},          // false positive check: 'is' prefix followed by lower case
		{"issuance", false},        // false positive check
		{"a", false},
		{"xy", false},
		{"", false},
	}

	for _, tt := range tests {
		got := IsMeaningful(tt.name)
		if got != tt.expected {
			t.Errorf("IsMeaningful(%q) = %v, want %v", tt.name, got, tt.expected)
		}
	}
}

func TestIsHighEntropyString(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"hello world", false},
		{"short", false},
		{"xK9mQ2pLvR8nW5jTzA3bF7cD4eG6hIqYuXoS", true}, // truly random 38 chars
		{"Zx8Kp3Qm7Rv2Wn5Jt9Yb4Fd6Lg1Hs0EcUiOa", true}, // mixed case + digits 38 chars
		{"", false},
		{"abc", false},
		{"aaaaaaaaaa", false}, // low entropy despite length
	}

	for _, tt := range tests {
		got := IsHighEntropyString(tt.input)
		if got != tt.expected {
			entropy := ShannonEntropy(tt.input)
			t.Errorf("IsHighEntropyString(%q) = %v, want %v (entropy=%.2f)", tt.input, got, tt.expected, entropy)
		}
	}
}

func TestCalculatorCompute(t *testing.T) {
	calc := NewCalculator()

	before := DeobfState{
		AvgNameEntropy:    4.2,
		TotalIdentifiers:  100,
		ObfuscatedNames:   80,
		MeaningfulNames:   5,
		ReadableNames:     15,
		TotalBlocks:       200,
		DispatcherBlocks:  30,
		OpaquePredicates:  20,
		TotalStrings:      50,
		EncryptedStrings:  40,
		TotalReflection:   15,
		TotalInstructions: 1000,
		DeadInstructions:  100,
		CyclomaticTotal:   150,
	}

	after := DeobfState{
		AvgNameEntropy:     2.1,
		TotalIdentifiers:   100,
		ObfuscatedNames:    20,
		MeaningfulNames:    60,
		ReadableNames:      20,
		TotalBlocks:        180,
		DispatcherBlocks:   5,
		OpaquePredicates:   2,
		TotalStrings:       50,
		EncryptedStrings:   10,
		DecryptedStrings:   35,
		TotalReflection:    15,
		ResolvedReflection: 12,
		TotalInstructions:  850,
		DeadInstructions:   10,
		CyclomaticTotal:    90,
	}

	report, err := calc.Compute(before, after)
	if err != nil {
		t.Fatalf("Compute failed unexpectedly: %v", err)
	}

	// Entropy should be reduced
	if report.EntropyReduction < 0.4 {
		t.Errorf("EntropyReduction = %f, want > 0.4", report.EntropyReduction)
	}

	// Identifier recovery should be high (80 obfuscated → 20 = 75% recovered)
	if report.IdentifierRecoveryRate < 0.7 {
		t.Errorf("IdentifierRecoveryRate = %f, want > 0.7", report.IdentifierRecoveryRate)
	}

	// CFG flattening (30 dispatchers → 5 = 83% removed)
	if report.CFGFlatteningScore < 0.8 {
		t.Errorf("CFGFlatteningScore = %f, want > 0.8", report.CFGFlatteningScore)
	}

	// Opaque predicates (20 → 2 = 90% removed)
	if report.OpaquePredicateReduction < 0.85 {
		t.Errorf("OpaquePredicateReduction = %f, want > 0.85", report.OpaquePredicateReduction)
	}

	// String decryption (35 decrypted out of 40 encrypted = 87.5%)
	if report.StringDecryptionRate < 0.85 {
		t.Errorf("StringDecryptionRate = %f, want > 0.85", report.StringDecryptionRate)
	}

	// Reflection resolution (12/15 = 80%)
	if report.ReflectionResolutionRate < 0.75 {
		t.Errorf("ReflectionResolutionRate = %f, want > 0.75", report.ReflectionResolutionRate)
	}

	// Overall confidence should be high
	if report.OverallConfidence < 0.6 {
		t.Errorf("OverallConfidence = %f, want > 0.6", report.OverallConfidence)
	}

	// Grade should be good
	grade := report.Grade()
	if grade != "S" && grade != "A" && grade != "B" {
		t.Errorf("Grade = %s, want S/A/B", grade)
	}
}

func TestCalculatorZeroBefore(t *testing.T) {
	calc := NewCalculator()

	// Edge case: all zeros before (nothing to deobfuscate)
	before := DeobfState{}
	after := DeobfState{MeaningfulNames: 10}

	report, err := calc.Compute(before, after)
	if err != nil {
		t.Fatalf("Compute failed on zero before state: %v", err)
	}

	// Should not panic, all metrics should be 0
	if report.OverallConfidence != 0 {
		t.Errorf("OverallConfidence = %f, want 0 for zero before state", report.OverallConfidence)
	}
}

func TestCalculatorCompute_ValidationErrors(t *testing.T) {
	calc := NewCalculator()
	validBefore := DeobfState{TotalIdentifiers: 10, ObfuscatedNames: 5}
	validAfter := DeobfState{TotalIdentifiers: 10, ObfuscatedNames: 2}

	// 1. Negative fields in before state
	invalidBefore := validBefore
	invalidBefore.TotalIdentifiers = -1
	if _, err := calc.Compute(invalidBefore, validAfter); err == nil {
		t.Error("expected error for negative TotalIdentifiers in before state, got nil")
	}

	// 2. Transition violation: more obfuscated names after than before
	invalidAfterTransition := validAfter
	invalidAfterTransition.ObfuscatedNames = 15
	if _, err := calc.Compute(validBefore, invalidAfterTransition); err == nil {
		t.Error("expected error for after.ObfuscatedNames > before.ObfuscatedNames, got nil")
	}

	// 3. Transition violation: more decrypted strings than originally encrypted
	beforeStrings := DeobfState{TotalStrings: 20, EncryptedStrings: 5}
	afterStrings := DeobfState{TotalStrings: 20, DecryptedStrings: 10}
	if _, err := calc.Compute(beforeStrings, afterStrings); err == nil {
		t.Error("expected error for after.DecryptedStrings > before.EncryptedStrings, got nil")
	}

	// 4. Invalid weights (all zeros)
	zeroCalc := NewCalculatorWithWeights(MetricWeights{})
	if _, err := zeroCalc.Compute(validBefore, validAfter); err == nil {
		t.Error("expected error for zero weights, got nil")
	}
}

func TestExtractState(t *testing.T) {
	input := StateInput{
		Identifiers:        []string{"a", "b", "getName", "isValid", "x1y2", "processData"},
		Strings:            []string{"hello", "xK9mQ2pLvR8nW5jTzA3bF7cD", "world", "aGVsbG8gd29ybGQ9Kz0xMjM0NTY="},
		TotalBlocks:        50,
		TotalInstructions:  200,
		DeadInstructions:   20,
		CyclomaticTotal:    30,
		DispatcherBlocks:   5,
		OpaquePredicates:   3,
		ReflectionCalls:    10,
		ResolvedReflection: 7,
		RecoveredStrings:   2,
	}

	state := ExtractState(input)

	if state.TotalIdentifiers != 6 {
		t.Errorf("TotalIdentifiers = %d, want 6", state.TotalIdentifiers)
	}
	if state.ObfuscatedNames == 0 {
		t.Error("should detect obfuscated names")
	}
	if state.MeaningfulNames == 0 {
		t.Error("should detect meaningful names")
	}
	if state.EncryptedStrings == 0 {
		t.Error("should detect encrypted strings")
	}
	if state.DecryptedStrings != 2 {
		t.Errorf("DecryptedStrings = %d, want 2", state.DecryptedStrings)
	}
	if state.AvgNameEntropy <= 0 {
		t.Error("avg entropy should be > 0")
	}
	if state.ResolvedReflection != 7 {
		t.Errorf("ResolvedReflection = %d, want 7", state.ResolvedReflection)
	}
}

func TestClamp01(t *testing.T) {
	tests := []struct {
		input    float64
		expected float64
	}{
		{-0.5, 0},
		{0, 0},
		{0.5, 0.5},
		{1.0, 1.0},
		{1.5, 1.0},
		{math.Inf(1), 1.0},
		{-math.Inf(1), 0},
		{math.NaN(), 0},
	}

	for _, tt := range tests {
		got := clamp01(tt.input)
		if got != tt.expected {
			t.Errorf("clamp01(%f) = %f, want %f", tt.input, got, tt.expected)
		}
	}
}

func TestQualityReportSummary(t *testing.T) {
	report := &QualityReport{
		OverallConfidence:        0.82,
		EntropyReduction:         0.50,
		IdentifierRecoveryRate:   0.75,
		CFGFlatteningScore:       0.83,
		OpaquePredicateReduction: 0.90,
		CyclomaticDelta:          0.40,
		StringDecryptionRate:     0.87,
		ReflectionResolutionRate: 0.80,
		DeadCodeEliminationRate:  0.90,
	}

	summary := report.Summary()
	if summary == "" {
		t.Fatal("summary should not be empty")
	}

	// Should contain the confidence percentage
	if !strings.Contains(summary, "82%") {
		t.Errorf("summary should contain '82%%', got:\n%s", summary)
	}

	expectedGolden := `Deobfuscation Confidence: 82%
  Entropy Reduction:     50.0%
  Identifier Recovery:   75.0%
  CFG Deflattening:      83.0%
  Opaque Pred Removal:   90.0%
  Cyclomatic Reduction:  40.0%
  String Decryption:     87.0%
  Reflection Resolution: 80.0%
  Dead Code Elimination: 90.0%`
	if summary != expectedGolden {
		t.Errorf("Summary() mismatch with golden:\ngot:\n%s\nwant:\n%s", summary, expectedGolden)
	}
}

func TestGrade(t *testing.T) {
	tests := []struct {
		confidence float64
		want       string
	}{
		{0.95, "S"},
		{0.90, "S"},
		{0.8999, "A"},
		{0.80, "A"},
		{0.7999, "B"},
		{0.65, "B"},
		{0.6499, "C"},
		{0.50, "C"},
		{0.4999, "D"},
		{0.30, "D"},
		{0.2999, "F"},
		{0.00, "F"},
	}
	for _, tt := range tests {
		r := &QualityReport{OverallConfidence: tt.confidence}
		if got := r.Grade(); got != tt.want {
			t.Errorf("Grade(confidence=%v) = %s, want %s", tt.confidence, got, tt.want)
		}
	}
}

func TestCoverageEdgeCases(t *testing.T) {
	// 1. NameClass.String()
	if got := ClassObfuscated.String(); got != "obfuscated" {
		t.Errorf("ClassObfuscated.String() = %q, want 'obfuscated'", got)
	}
	if got := ClassMeaningful.String(); got != "meaningful" {
		t.Errorf("ClassMeaningful.String() = %q, want 'meaningful'", got)
	}
	if got := ClassReadable.String(); got != "readable" {
		t.Errorf("ClassReadable.String() = %q, want 'readable'", got)
	}

	// 2. ClassifyName with negative entropy (triggers on-demand computation)
	if got := ClassifyName("xK9mQ2pLvR8n", -1); got != ClassObfuscated {
		t.Errorf("ClassifyName on-demand entropy = %v, want ClassObfuscated", got)
	}

	// 3. DeobfState validation edge cases
	invalidStates := []DeobfState{
		{AvgNameEntropy: -1},
		{MaxNameEntropy: -1},
		{TotalReflection: 10, ResolvedReflection: 20},
		{TotalInstructions: 10, DeadInstructions: 20},
		{TotalIdentifiers: 10, ReadableNames: 5, ObfuscatedNames: 5, MeaningfulNames: 5},
		{TotalStrings: 10, EncryptedStrings: 8, DecryptedStrings: 5},
		{TotalBlocks: 10, DispatcherBlocks: 15},
	}
	for i, s := range invalidStates {
		if err := s.Validate(); err == nil {
			t.Errorf("invalidStates[%d].Validate() = nil, want error", i)
		}
	}

	// 4. MetricWeights validation & normalization
	badWeights := []MetricWeights{
		{Entropy: -1},
		{}, // sum = 0
	}
	for i, w := range badWeights {
		if err := w.Validate(); err == nil {
			t.Errorf("badWeights[%d].Validate() = nil, want error", i)
		}
	}

	zeroW := MetricWeights{}.Normalized()
	if zeroW.Sum() != 0 {
		t.Errorf("MetricWeights{}.Normalized().Sum() = %f, want 0", zeroW.Sum())
	}
}

// ---- BENCHMARKS -------------------------------------------------------------

func BenchmarkShannonEntropy(b *testing.B) {
	s := "xK9mQ2pLvR8nW5jTzA3bF7cD4eG6hIqYuXoS"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ShannonEntropy(s)
	}
}

func BenchmarkExtractState(b *testing.B) {
	input := StateInput{
		Identifiers:        []string{"a", "b", "getName", "isValid", "x1y2", "processData", "xK9mQ2pL", "hasPermission"},
		Strings:            []string{"hello", "xK9mQ2pLvR8nW5jTzA3bF7cD", "world", "aGVsbG8gd29ybGQ9Kz0xMjM0NTY="},
		TotalBlocks:        50,
		TotalInstructions:  200,
		DeadInstructions:   20,
		CyclomaticTotal:    30,
		DispatcherBlocks:   5,
		OpaquePredicates:   3,
		ReflectionCalls:    10,
		ResolvedReflection: 7,
		RecoveredStrings:   2,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractState(input)
	}
}

func BenchmarkCompute(b *testing.B) {
	calc := NewCalculator()
	before := DeobfState{
		AvgNameEntropy: 4.2, TotalIdentifiers: 100, ObfuscatedNames: 80,
		TotalBlocks: 200, DispatcherBlocks: 30, OpaquePredicates: 20,
		TotalStrings: 50, EncryptedStrings: 40, TotalReflection: 15,
		TotalInstructions: 1000, DeadInstructions: 100, CyclomaticTotal: 150,
	}
	after := DeobfState{
		AvgNameEntropy: 2.1, TotalIdentifiers: 100, ObfuscatedNames: 20, MeaningfulNames: 60, ReadableNames: 20,
		TotalBlocks: 180, DispatcherBlocks: 5, OpaquePredicates: 2,
		TotalStrings: 50, EncryptedStrings: 10, DecryptedStrings: 35,
		TotalReflection: 15, ResolvedReflection: 12,
		TotalInstructions: 850, DeadInstructions: 10, CyclomaticTotal: 90,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = calc.Compute(before, after)
	}
}

// ---- FUZZ TESTS -------------------------------------------------------------

func FuzzShannonEntropy(f *testing.F) {
	f.Add("hello world")
	f.Add("")
	f.Add("xK9mQ2pLvR8nW5jTzA3bF7cD")
	f.Add("Привет мир! 🎉")
	f.Fuzz(func(t *testing.T, s string) {
		e := ShannonEntropy(s)
		if e < 0 || math.IsNaN(e) || math.IsInf(e, 0) {
			t.Fatalf("ShannonEntropy(%q) = %v, must be finite non-negative", s, e)
		}
	})
}

func FuzzClassifyName(f *testing.F) {
	f.Add("getName", 0.0)
	f.Add("a", 0.0)
	f.Add("xK9mQ2pL", 0.0)
	f.Fuzz(func(t *testing.T, name string, entropy float64) {
		_ = ClassifyName(name, entropy)
	})
}
