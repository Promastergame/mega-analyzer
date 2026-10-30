package ml

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TEST HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func newTestHistory(t *testing.T) *AnalysisHistory {
	t.Helper()
	path := tempHistoryPath(t)
	h, err := LoadHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func populateHistory(h *AnalysisHistory, count int) {
	for i := 0; i < count; i++ {
		fb := &AnalysisFeedback{
			ID:            GenerateFeedbackID("app", time.Now()),
			APKName:       "app.apk",
			Timestamp:     time.Now(),
			Profile:       "balanced",
			TotalFiles:    1000,
			AnalyzedFiles: 800,
			TotalMatches:  100,
			CriticalCount: 5,
			FastPathHits:  200,
			SavedFromFP:   50,
			KeywordStats: map[string]*KeywordFeedback{
				"crypto": {
					Keyword:          "crypto",
					Triggered:        50,
					InAppCode:        10,
					InLibrary:        40,
					Dampened:         5,
					SumImportance:    100,
					SumRawImportance: 150,
					Contexts:         map[string]int{"body": 30, "filename": 20},
				},
				"license": {
					Keyword:          "license",
					Triggered:        30,
					InAppCode:        25,
					InLibrary:        5,
					Dampened:         0,
					SumImportance:    180,
					SumRawImportance: 200,
					Contexts:         map[string]int{"body": 30},
				},
			},
			LibraryStats: map[string]*LibraryFeedback{
				"com/google/ads/": {
					Prefix:          "com/google/ads/",
					TotalFiles:      50,
					MatchedFiles:    10,
					DampenedMatches: 10,
					HighValueFiles:  0,
					SumImportance:   5,
					Category:        "ads",
				},
			},
			CategoryStats: map[string]*CategoryFeedback{
				"crypto": {Category: "crypto", Files: 20, Matches: 50, Critical: 3},
			},
			TopFiles: []FileFeedback{
				{
					Path:            "com/app/CryptoHelper.smali",
					Importance:      8,
					MatchedKeywords: []string{"crypto", "encrypt", "key"},
					Categories:      []string{"crypto"},
				},
				{
					Path:            "com/app/License.smali",
					Importance:      6,
					MatchedKeywords: []string{"license", "check"},
					Categories:      []string{"licensing"},
				},
				{
					Path:            "com/app/Network.smali",
					Importance:      4,
					MatchedKeywords: []string{"crypto", "license"},
					Categories:      []string{"crypto", "licensing"},
				},
			},
		}
		h.Append(fb)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAFE MATH
// ═══════════════════════════════════════════════════════════════════════════════

func TestSafeRatio(t *testing.T) {
	tests := []struct {
		num, den int
		expected float64
	}{
		{10, 20, 0.5},
		{0, 10, 0},
		{10, 0, 0}, // division by zero → 0
		{5, 5, 1.0},
	}

	for _, tt := range tests {
		got := safeRatio(tt.num, tt.den)
		if got != tt.expected {
			t.Errorf("safeRatio(%d, %d) = %f, want %f", tt.num, tt.den, got, tt.expected)
		}
	}
}

func TestSafePercent(t *testing.T) {
	got := safePercent(1, 4)
	if got != 25.0 {
		t.Errorf("safePercent(1, 4) = %f, want 25.0", got)
	}

	got = safePercent(0, 0)
	if got != 0 {
		t.Errorf("safePercent(0, 0) = %f, want 0", got)
	}
}

func TestMaxInt(t *testing.T) {
	if maxInt(3, 5) != 5 {
		t.Error("maxInt(3,5) should be 5")
	}
	if maxInt(5, 3) != 5 {
		t.Error("maxInt(5,3) should be 5")
	}
	if maxInt(4, 4) != 4 {
		t.Error("maxInt(4,4) should be 4")
	}
}

func TestClamp01(t *testing.T) {
	tests := []struct {
		input    float64
		expected float64
	}{
		{0.5, 0.5},
		{0.0, 0.0},
		{1.0, 1.0},
		{-0.1, 0.0},
		{1.5, 1.0},
		{-100, 0.0},
		{100, 1.0},
	}

	for _, tt := range tests {
		got := clamp01(tt.input)
		if got != tt.expected {
			t.Errorf("clamp01(%f) = %f, want %f", tt.input, got, tt.expected)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUGGESTION TYPES
// ═══════════════════════════════════════════════════════════════════════════════

func TestSuggestionType_Risk(t *testing.T) {
	tests := []struct {
		st       SuggestionType
		expected RiskLevel
	}{
		{TypeScoring, RiskHigh},
		{TypeKeywordDampening, RiskMedium},
		{TypeLibraryFastpath, RiskMedium},
		{TypeKeywordWeight, RiskLow},
		{TypeLibraryDampening, RiskLow},
		{TypePerformance, RiskLow},
		{TypePattern, RiskLow},
	}

	for _, tt := range tests {
		got := tt.st.Risk()
		if got != tt.expected {
			t.Errorf("%s.Risk() = %s, want %s", tt.st, got, tt.expected)
		}
	}
}

func TestSuggestionType_Icon(t *testing.T) {
	tests := []struct {
		st       SuggestionType
		expected string
	}{
		{TypeKeywordDampening, "~"},
		{TypeKeywordWeight, "="},
		{TypeLibraryFastpath, ">"},
		{TypeScoring, "!"},
		{TypePattern, "&"},
		{SuggestionType("unknown"), "?"},
	}

	for _, tt := range tests {
		got := tt.st.Icon()
		if got != tt.expected {
			t.Errorf("%s.Icon() = %q, want %q", tt.st, got, tt.expected)
		}
	}
}

func TestClassifyConfidence(t *testing.T) {
	tests := []struct {
		value    float64
		expected ConfidenceLevel
	}{
		{0.95, ConfidenceStrong},
		{0.90, ConfidenceStrong},
		{0.85, ConfidenceHigh},
		{0.75, ConfidenceHigh},
		{0.65, ConfidenceModerate},
		{0.60, ConfidenceModerate},
		{0.55, ConfidenceWeak},
		{0.10, ConfidenceWeak},
		{0.0, ConfidenceWeak},
	}

	for _, tt := range tests {
		got := classifyConfidence(tt.value)
		if got != tt.expected {
			t.Errorf("classifyConfidence(%f) = %s, want %s", tt.value, got, tt.expected)
		}
	}
}

func TestConfidenceStability(t *testing.T) {
	tests := []struct {
		level   ConfidenceLevel
		samples int
		want    string
	}{
		{ConfidenceStrong, 100, "statistically robust"},
		{ConfidenceHigh, 100, "statistically stable"},
		{ConfidenceHigh, 10, "converging"},
		{ConfidenceModerate, 50, "requires more data"},
		{ConfidenceWeak, 5, "limited data"},
	}

	for _, tt := range tests {
		got := confidenceStability(tt.level, tt.samples)
		if got != tt.want {
			t.Errorf("confidenceStability(%s, %d) = %q, want %q",
				tt.level, tt.samples, got, tt.want)
		}
	}
}

func TestSuggestion_Weight(t *testing.T) {
	sg := Suggestion{
		Confidence: 0.8,
		Samples:    100,
		RiskImpact: RiskHigh,
	}

	w := sg.Weight()
	if w <= 0 {
		t.Error("weight should be positive")
	}

	// High risk multiplier
	sgLow := Suggestion{
		Confidence: 0.8,
		Samples:    100,
		RiskImpact: RiskLow,
	}

	if sgLow.Weight() >= sg.Weight() {
		t.Error("high risk should have higher weight than low risk")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIDENCE & MATURITY
// ═══════════════════════════════════════════════════════════════════════════════

func TestCalculateConfidence_Bounds(t *testing.T) {
	s := NewMLSuggester(newTestHistory(t))

	// Всегда в [0, 1]
	signals := []float64{-1.0, 0.0, 0.5, 1.0, 2.0, 100.0}
	samples := []int{0, 1, 10, 50, 100, 10000}

	for _, signal := range signals {
		for _, sample := range samples {
			got := s.calculateConfidence(signal, sample)
			if got < 0 || got > 1 {
				t.Errorf("calculateConfidence(%f, %d) = %f, out of [0,1]",
					signal, sample, got)
			}
		}
	}
}

func TestCalculateConfidence_MonotonicInSignal(t *testing.T) {
	s := NewMLSuggester(newTestHistory(t))
	samples := 50

	prev := s.calculateConfidence(0.1, samples)
	for signal := 0.2; signal <= 1.0; signal += 0.1 {
		curr := s.calculateConfidence(signal, samples)
		if curr < prev {
			t.Errorf("confidence should increase with signal: f(%f)=%f < f(%f)=%f",
				signal, curr, signal-0.1, prev)
		}
		prev = curr
	}
}

func TestCalculateConfidence_MonotonicInSamples(t *testing.T) {
	s := NewMLSuggester(newTestHistory(t))
	signal := 0.8

	prev := s.calculateConfidence(signal, 1)
	for samples := 5; samples <= 100; samples += 5 {
		curr := s.calculateConfidence(signal, samples)
		if curr < prev {
			t.Errorf("confidence should increase with samples: f(%d)=%f < f(%d)=%f",
				samples, curr, samples-5, prev)
		}
		prev = curr
	}
}

func TestCalculateMaturity(t *testing.T) {
	h := newTestHistory(t)
	s := NewMLSuggester(h)

	// Empty
	ctx := s.buildContext()
	if m := s.calculateMaturity(ctx); m != 0 {
		t.Errorf("empty history maturity = %f, want 0", m)
	}

	// 1 APK
	populateHistory(h, 1)
	ctx = s.buildContext()
	m1 := s.calculateMaturity(ctx)
	if m1 <= 0 || m1 >= 1 {
		t.Errorf("1 APK maturity = %f, should be in (0, 1)", m1)
	}

	// 50 APKs
	populateHistory(h, 49)
	ctx = s.buildContext()
	m50 := s.calculateMaturity(ctx)
	if m50 < 0.70 {
		t.Errorf("50 APK maturity = %f, should be near 0.74", m50)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INSIGHT STRENGTH & ENTROPY
// ═══════════════════════════════════════════════════════════════════════════════

func TestCalculateWeightedInsightStrength_Empty(t *testing.T) {
	got := calculateWeightedInsightStrength(nil)
	if got != 0 {
		t.Errorf("empty suggestions should give 0, got %f", got)
	}
}

func TestCalculateWeightedInsightStrength_SingleHigh(t *testing.T) {
	suggestions := []Suggestion{
		{Confidence: 0.9, Samples: 100, RiskImpact: RiskHigh},
	}

	got := calculateWeightedInsightStrength(suggestions)
	if got < 0.8 || got > 1.0 {
		t.Errorf("single high confidence should give high strength, got %f", got)
	}
}

func TestCalculateSignalEntropy_Empty(t *testing.T) {
	got := calculateSignalEntropy(nil)
	if got != 0 {
		t.Errorf("empty = 0, got %f", got)
	}
}

func TestCalculateSignalEntropy_SingleType(t *testing.T) {
	suggestions := []Suggestion{
		{Type: TypeKeywordDampening},
		{Type: TypeKeywordDampening},
		{Type: TypeKeywordDampening},
	}

	got := calculateSignalEntropy(suggestions)
	if got != 0 {
		t.Errorf("single type = 0 entropy, got %f", got)
	}
}

func TestCalculateSignalEntropy_Balanced(t *testing.T) {
	suggestions := []Suggestion{
		{Type: TypeKeywordDampening},
		{Type: TypeKeywordWeight},
		{Type: TypeLibraryFastpath},
		{Type: TypePattern},
	}

	got := calculateSignalEntropy(suggestions)
	if got < 0.9 {
		t.Errorf("4 equal types should give high entropy, got %f", got)
	}
}

func TestCalculateSignalEntropy_Skewed(t *testing.T) {
	suggestions := []Suggestion{
		{Type: TypeKeywordDampening},
		{Type: TypeKeywordDampening},
		{Type: TypeKeywordDampening},
		{Type: TypeKeywordDampening},
		{Type: TypePattern},
	}

	got := calculateSignalEntropy(suggestions)
	if got > 0.8 {
		t.Errorf("skewed distribution should give lower entropy, got %f", got)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYZE — FULL PIPELINE
// ═══════════════════════════════════════════════════════════════════════════════

func TestAnalyze_EmptyHistory(t *testing.T) {
	h := newTestHistory(t)
	s := NewMLSuggester(h)

	result := s.Analyze()

	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.TotalAPKs != 0 {
		t.Errorf("TotalAPKs = %d, want 0", result.TotalAPKs)
	}
	if len(result.Suggestions) != 0 {
		t.Errorf("empty history should have 0 suggestions, got %d", len(result.Suggestions))
	}
	if result.Maturity != 0 {
		t.Errorf("Maturity = %f, want 0", result.Maturity)
	}
	if result.InsightStrength != 0 {
		t.Errorf("InsightStrength = %f, want 0", result.InsightStrength)
	}
}

func TestAnalyze_WithData(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 10)
	s := NewMLSuggester(h)

	result := s.Analyze()

	if result.TotalAPKs != 10 {
		t.Errorf("TotalAPKs = %d, want 10", result.TotalAPKs)
	}
	if result.Maturity <= 0 {
		t.Error("Maturity should be > 0")
	}
	if result.Timestamp == "" {
		t.Error("Timestamp should not be empty")
	}
}

func TestAnalyze_ConfidenceFilter(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 10)

	// Low threshold — more suggestions
	low := NewMLSuggester(h, WithSuggesterConfig(SuggesterConfig{
		NoiseThreshold:        0.7,
		MinSampleSize:         1,
		ConfidenceThreshold:   0.1,
		LibraryMinAPKs:        1,
		LibraryMinFiles:       1,
		SigmoidSlope:          6.0,
		MaxDisplaySuggestions: 50,
		MaxCoOccurrences:      20,
		MaxWrappedWidth:       60,
	}))

	// High threshold — fewer suggestions
	high := NewMLSuggester(h, WithSuggesterConfig(SuggesterConfig{
		NoiseThreshold:        0.7,
		MinSampleSize:         1,
		ConfidenceThreshold:   0.95,
		LibraryMinAPKs:        1,
		LibraryMinFiles:       1,
		SigmoidSlope:          6.0,
		MaxDisplaySuggestions: 50,
		MaxCoOccurrences:      20,
		MaxWrappedWidth:       60,
	}))

	lowResult := low.Analyze()
	highResult := high.Analyze()

	if len(highResult.Suggestions) > len(lowResult.Suggestions) {
		t.Errorf("high threshold (%d) should have <= suggestions than low (%d)",
			len(highResult.Suggestions), len(lowResult.Suggestions))
	}
}

func TestAnalyze_SortedByConfidence(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 10)

	s := NewMLSuggester(h, WithSuggesterConfig(SuggesterConfig{
		NoiseThreshold:        0.3, // ловим больше
		MinSampleSize:         1,
		ConfidenceThreshold:   0.0,
		LibraryMinAPKs:        1,
		LibraryMinFiles:       1,
		SigmoidSlope:          6.0,
		MaxDisplaySuggestions: 50,
		MaxCoOccurrences:      20,
		MaxWrappedWidth:       60,
	}))

	result := s.Analyze()

	for i := 1; i < len(result.Suggestions); i++ {
		if result.Suggestions[i].Confidence > result.Suggestions[i-1].Confidence {
			t.Errorf("suggestions not sorted: [%d]=%f > [%d]=%f",
				i, result.Suggestions[i].Confidence,
				i-1, result.Suggestions[i-1].Confidence)
		}
	}
}

func TestAnalyze_SystemConfidence(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 10)

	s := NewMLSuggester(h)
	result := s.Analyze()

	expected := result.Maturity * result.InsightStrength
	if math.Abs(result.SystemConfidence-expected) > 0.001 {
		t.Errorf("SystemConfidence = %f, want Maturity*InsightStrength = %f",
			result.SystemConfidence, expected)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYZE KEYWORDS
// ═══════════════════════════════════════════════════════════════════════════════

func TestAnalyzeKeywords_HighNoise(t *testing.T) {
	h := newTestHistory(t)

	// Keyword with 80% noise
	fb := &AnalysisFeedback{
		ID:        GenerateFeedbackID("noisy", time.Now()),
		APKName:   "noisy.apk",
		Timestamp: time.Now(),
		KeywordStats: map[string]*KeywordFeedback{
			"noisy_kw": {
				Keyword:       "noisy_kw",
				Triggered:     100,
				InLibrary:     80,
				InAppCode:     20,
				SumImportance: 300,
			},
		},
		LibraryStats:  map[string]*LibraryFeedback{},
		CategoryStats: map[string]*CategoryFeedback{},
	}
	h.Append(fb)

	s := NewMLSuggester(h, WithSuggesterConfig(SuggesterConfig{
		NoiseThreshold:        0.7,
		MinSampleSize:         10,
		ConfidenceThreshold:   0.0,
		SigmoidSlope:          6.0,
		MaxDisplaySuggestions: 10,
		MaxCoOccurrences:      20,
		MaxWrappedWidth:       60,
	}))

	result := s.Analyze()

	found := false
	for _, sg := range result.Suggestions {
		if sg.Target == "noisy_kw" && sg.Type == TypeKeywordDampening {
			found = true
			if sg.RiskImpact != RiskMedium {
				t.Errorf("keyword_dampening risk = %s, want Medium", sg.RiskImpact)
			}
			break
		}
	}

	if !found {
		t.Error("should suggest dampening for noisy keyword")
	}
}

func TestAnalyzeKeywords_BelowMinSample(t *testing.T) {
	h := newTestHistory(t)

	fb := &AnalysisFeedback{
		ID:        GenerateFeedbackID("small", time.Now()),
		APKName:   "small.apk",
		Timestamp: time.Now(),
		KeywordStats: map[string]*KeywordFeedback{
			"rare": {
				Keyword:   "rare",
				Triggered: 3, // below default MinSampleSize=10
				InLibrary: 3,
			},
		},
		LibraryStats:  map[string]*LibraryFeedback{},
		CategoryStats: map[string]*CategoryFeedback{},
	}
	h.Append(fb)

	s := NewMLSuggester(h)
	result := s.Analyze()

	for _, sg := range result.Suggestions {
		if sg.Target == "rare" {
			t.Error("keyword below MinSampleSize should not generate suggestion")
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYZE LIBRARIES
// ═══════════════════════════════════════════════════════════════════════════════

func TestAnalyzeLibraries_AlwaysNoiseFastpath(t *testing.T) {
	h := newTestHistory(t)

	// 5 APKs, всегда noise
	for i := 0; i < 5; i++ {
		fb := &AnalysisFeedback{
			ID:            GenerateFeedbackID("lib_test", time.Now()),
			APKName:       "app.apk",
			Timestamp:     time.Now(),
			KeywordStats:  map[string]*KeywordFeedback{},
			CategoryStats: map[string]*CategoryFeedback{},
			LibraryStats: map[string]*LibraryFeedback{
				"com/ads/sdk/": {
					Prefix:          "com/ads/sdk/",
					TotalFiles:      30,
					MatchedFiles:    5,
					DampenedMatches: 5,
					HighValueFiles:  0, // always noise
					Category:        "ads",
				},
			},
		}
		h.Append(fb)
	}

	s := NewMLSuggester(h, WithSuggesterConfig(SuggesterConfig{
		NoiseThreshold:        0.7,
		MinSampleSize:         10,
		ConfidenceThreshold:   0.0,
		LibraryMinAPKs:        3,
		LibraryMinFiles:       20,
		SigmoidSlope:          6.0,
		MaxDisplaySuggestions: 10,
		MaxCoOccurrences:      20,
		MaxWrappedWidth:       60,
	}))

	result := s.Analyze()

	found := false
	for _, sg := range result.Suggestions {
		if sg.Type == TypeLibraryFastpath {
			found = true
			if sg.RiskImpact != RiskMedium {
				t.Errorf("library_fastpath risk = %s, want Medium", sg.RiskImpact)
			}
			break
		}
	}

	if !found {
		t.Error("should suggest fastpath for always-noise library")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYZE PERFORMANCE
// ═══════════════════════════════════════════════════════════════════════════════

func TestAnalyzePerformance_LowHitRate(t *testing.T) {
	h := newTestHistory(t)

	fb := &AnalysisFeedback{
		ID:            GenerateFeedbackID("perf", time.Now()),
		APKName:       "app.apk",
		Timestamp:     time.Now(),
		TotalFiles:    1000,
		AnalyzedFiles: 800,
		FastPathHits:  100, // 10% hit rate
		SavedFromFP:   50,
		KeywordStats:  map[string]*KeywordFeedback{},
		LibraryStats:  map[string]*LibraryFeedback{},
		CategoryStats: map[string]*CategoryFeedback{},
	}
	h.Append(fb)

	s := NewMLSuggester(h, WithSuggesterConfig(SuggesterConfig{
		ConfidenceThreshold:   0.0,
		SigmoidSlope:          6.0,
		MaxDisplaySuggestions: 10,
		MaxCoOccurrences:      20,
		MaxWrappedWidth:       60,
	}))

	result := s.Analyze()

	found := false
	for _, sg := range result.Suggestions {
		if sg.Type == TypePerformance {
			found = true
			break
		}
	}

	if !found {
		t.Error("should suggest performance optimization for low hit rate")
	}
}

func TestAnalyzePerformance_TooManyCritical(t *testing.T) {
	h := newTestHistory(t)

	fb := &AnalysisFeedback{
		ID:            GenerateFeedbackID("crit", time.Now()),
		APKName:       "app.apk",
		Timestamp:     time.Now(),
		TotalFiles:    1000,
		AnalyzedFiles: 800,
		CriticalCount: 200, // > 100
		KeywordStats:  map[string]*KeywordFeedback{},
		LibraryStats:  map[string]*LibraryFeedback{},
		CategoryStats: map[string]*CategoryFeedback{},
	}
	h.Append(fb)

	s := NewMLSuggester(h, WithSuggesterConfig(SuggesterConfig{
		ConfidenceThreshold:   0.0,
		SigmoidSlope:          6.0,
		MaxDisplaySuggestions: 10,
		MaxCoOccurrences:      20,
		MaxWrappedWidth:       60,
	}))

	result := s.Analyze()

	found := false
	for _, sg := range result.Suggestions {
		if sg.Type == TypeScoring {
			found = true
			if sg.RiskImpact != RiskHigh {
				t.Errorf("scoring risk = %s, want High", sg.RiskImpact)
			}
			break
		}
	}

	if !found {
		t.Error("should suggest recalibration for too many criticals")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CO-OCCURRENCE
// ═══════════════════════════════════════════════════════════════════════════════

func TestFindCoOccurrences_Empty(t *testing.T) {
	h := newTestHistory(t)
	s := NewMLSuggester(h)

	ctx := s.buildContext()
	result := s.findCoOccurrences(ctx)

	if result != nil {
		t.Errorf("empty history should give nil, got %v", result)
	}
}

func TestFindCoOccurrences_WithData(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 5)

	s := NewMLSuggester(h)
	ctx := s.buildContext()
	result := s.findCoOccurrences(ctx)

	if len(result) == 0 {
		t.Error("should find co-occurrences in populated history")
	}

	// Проверяем lift > 0
	for _, co := range result {
		if co.Lift < 0 {
			t.Errorf("lift should be >= 0, got %f for %s+%s",
				co.Lift, co.KeywordA, co.KeywordB)
		}
		if co.Support < 1 {
			t.Errorf("support should be >= 1, got %d", co.Support)
		}
	}
}

func TestFindCoOccurrences_Sorted(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 10)

	s := NewMLSuggester(h)
	ctx := s.buildContext()
	result := s.findCoOccurrences(ctx)

	if len(result) < 2 {
		t.Skip("not enough co-occurrences to test sorting")
	}

	for i := 1; i < len(result); i++ {
		scoreI := result[i].Lift * math.Log1p(float64(result[i].Support))
		scorePrev := result[i-1].Lift * math.Log1p(float64(result[i-1].Support))
		if scoreI > scorePrev {
			t.Errorf("co-occurrences not sorted: [%d] score %f > [%d] score %f",
				i, scoreI, i-1, scorePrev)
		}
	}
}

func TestFindCoOccurrences_MaxLimit(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 10)

	cfg := DefaultSuggesterConfig()
	cfg.MaxCoOccurrences = 3

	s := NewMLSuggester(h, WithSuggesterConfig(cfg))
	ctx := s.buildContext()
	result := s.findCoOccurrences(ctx)

	if len(result) > 3 {
		t.Errorf("should be capped at 3, got %d", len(result))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

func TestGenerateDampeningRule_ZeroTriggered(t *testing.T) {
	s := NewMLSuggester(newTestHistory(t))

	kw := &AggregatedKeywordStats{Keyword: "test", TotalTriggered: 0}
	result := s.generateDampeningRule(kw)

	if result != "{}" {
		t.Errorf("zero triggered should give empty rule, got %q", result)
	}
}

func TestGenerateDampeningRule_WithContexts(t *testing.T) {
	s := NewMLSuggester(newTestHistory(t))

	kw := &AggregatedKeywordStats{
		Keyword:         "test",
		TotalTriggered:  100,
		TotalInLibrary:  80,
		TotalInFileName: 40,
		NoiseRatio:      0.8,
	}

	result := s.generateDampeningRule(kw)

	if !strings.Contains(result, `"library"`) {
		t.Error("should include library context")
	}
	if !strings.Contains(result, `"filename"`) {
		t.Error("should include filename context")
	}
}

func TestGenerateWeightRule(t *testing.T) {
	s := NewMLSuggester(newTestHistory(t))

	kw := &AggregatedKeywordStats{
		Keyword:        "weak",
		TotalTriggered: 100,
		SumImportance:  50, // avg = 0.5 < 1.0 → weight=0
	}

	result := s.generateWeightRule(kw)

	if !strings.Contains(result, `"weight": 0`) {
		t.Error("low importance should suggest weight 0")
	}
}

func TestGenerateLibraryRule(t *testing.T) {
	s := NewMLSuggester(newTestHistory(t))

	lib := &AggregatedLibraryStats{
		Prefix:     "com/ads/",
		Category:   "ads",
		SeenInAPKs: 5,
		TotalFiles: 100,
	}

	result := s.generateLibraryRule(lib)

	if !strings.Contains(result, `"action": "skip"`) {
		t.Error("should suggest skip action")
	}
	if !strings.Contains(result, "com/ads/") {
		t.Error("should contain library prefix")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// REFLECTION
// ═══════════════════════════════════════════════════════════════════════════════

func TestBuildReflection_SignalDiversity(t *testing.T) {
	h := newTestHistory(t)
	s := NewMLSuggester(h)

	tests := []struct {
		entropy float64
		want    string
	}{
		{0.9, "well balanced"},
		{0.6, "moderate"},
		{0.3, "concentrated"},
		{0.1, "highly skewed"},
		{0.0, "no data"},
	}

	for _, tt := range tests {
		ctx := s.buildContext()
		stats := MLStats{AvgNoiseRatio: 0.5, TotalLibraries: 10}
		ref := s.buildReflection(ctx, stats, tt.entropy)

		if ref.SignalDiversity != tt.want {
			t.Errorf("entropy=%f → %q, want %q", tt.entropy, ref.SignalDiversity, tt.want)
		}
	}
}

func TestAssessSignalClarity_InsufficientData(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 2) // < 3

	s := NewMLSuggester(h)
	ctx := s.buildContext()

	got := s.assessSignalClarity(ctx)
	if got != "insufficient data" {
		t.Errorf("< 3 records should be insufficient, got %q", got)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERACTIVE OUTPUT
// ═══════════════════════════════════════════════════════════════════════════════

func TestInteractiveSuggest_EmptyHistory(t *testing.T) {
	h := newTestHistory(t)
	var buf bytes.Buffer

	s := NewMLSuggester(h, WithOutput(&buf))
	s.InteractiveSuggest()

	output := buf.String()

	if !strings.Contains(output, "INTELLIGENCE REPORT") {
		t.Error("should contain header")
	}
	if !strings.Contains(output, "No actionable suggestions") {
		t.Error("should say no suggestions for empty history")
	}
}

func TestInteractiveSuggest_WithData(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 10)
	var buf bytes.Buffer

	s := NewMLSuggester(h, WithOutput(&buf))
	s.InteractiveSuggest()

	output := buf.String()

	if !strings.Contains(output, "INTELLIGENCE REPORT") {
		t.Error("should contain header")
	}
	if !strings.Contains(output, "System State") {
		t.Error("should contain system state")
	}
	if !strings.Contains(output, "System Reflection") {
		t.Error("should contain reflection block")
	}
	if !strings.Contains(output, "Dataset size") {
		t.Error("should contain dataset size")
	}
}

func TestInteractiveSuggest_MaxDisplay(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 10)
	var buf bytes.Buffer

	cfg := DefaultSuggesterConfig()
	cfg.ConfidenceThreshold = 0.0
	cfg.MinSampleSize = 1
	cfg.NoiseThreshold = 0.1
	cfg.MaxDisplaySuggestions = 2

	s := NewMLSuggester(h, WithSuggesterConfig(cfg), WithOutput(&buf))
	s.InteractiveSuggest()

	output := buf.String()

	// Считаем suggestion headers (═══)
	count := strings.Count(output, "════════════════════════════════════════")
	// Reflection block тоже имеет ═══, но suggestion headers ≤ maxDisplay + 1 (reflection)
	// Проверяем что не слишком много suggestions показано
	if count > 5 { // 2 suggestions + reflection + немного буфера
		t.Errorf("too many separator lines (%d), MaxDisplaySuggestions=2", count)
	}
}

func TestPrintWrapped(t *testing.T) {
	var buf bytes.Buffer

	text := "This is a very long text that should be wrapped at some point because it exceeds the maximum width"
	printWrapped(&buf, text, 4, 30)

	output := buf.String()
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")

	for _, line := range lines {
		// Each line should start with indent
		if !strings.HasPrefix(line, "      ") { // 4+2 = 6 spaces
			t.Errorf("line should be indented: %q", line)
		}
	}

	if len(lines) < 2 {
		t.Error("text should be wrapped into multiple lines")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATELESS VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

func TestMLSuggester_Stateless(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 5)

	s := NewMLSuggester(h)

	// Вызываем Analyze() дважды — результаты должны быть консистентными
	r1 := s.Analyze()
	r2 := s.Analyze()

	if r1.TotalAPKs != r2.TotalAPKs {
		t.Error("Analyze() should be idempotent for same data")
	}
	if len(r1.Suggestions) != len(r2.Suggestions) {
		t.Error("same data should produce same number of suggestions")
	}
}

func TestMLSuggester_NoCacheLeaks(t *testing.T) {
	h := newTestHistory(t)
	populateHistory(h, 5)

	s := NewMLSuggester(h)
	_ = s.Analyze()

	// После Analyze() — внутренние кэши не должны остаться
	// (snapshot, aggKeywords, aggLibraries в analysisContext — локальные)
	// Проверяем что повторный вызов работает
	result := s.Analyze()
	if result == nil {
		t.Error("second Analyze() should work")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGGREGATION FROM RECORDS (чистые функции)
// ═══════════════════════════════════════════════════════════════════════════════

func TestAggregateKeywordsFromRecords_Empty(t *testing.T) {
	result := aggregateKeywordsFromRecords(nil)
	if len(result) != 0 {
		t.Errorf("empty records should give empty map, got %d", len(result))
	}
}

func TestAggregateLibrariesFromRecords_Empty(t *testing.T) {
	result := aggregateLibrariesFromRecords(nil)
	if len(result) != 0 {
		t.Errorf("empty records should give empty map, got %d", len(result))
	}
}

func TestAggregateKeywordsFromRecords_Merges(t *testing.T) {
	records := []*AnalysisFeedback{
		{KeywordStats: map[string]*KeywordFeedback{
			"test": {Keyword: "test", Triggered: 10, InLibrary: 5, SumImportance: 30},
		}},
		{KeywordStats: map[string]*KeywordFeedback{
			"test": {Keyword: "test", Triggered: 20, InLibrary: 15, SumImportance: 60},
		}},
	}

	result := aggregateKeywordsFromRecords(records)
	test := result["test"]

	if test == nil {
		t.Fatal("test keyword should exist")
	}
	if test.TotalTriggered != 30 {
		t.Errorf("TotalTriggered = %d, want 30", test.TotalTriggered)
	}
	if test.TotalInLibrary != 20 {
		t.Errorf("TotalInLibrary = %d, want 20", test.TotalInLibrary)
	}
	if test.SumImportance != 90 {
		t.Errorf("SumImportance = %f, want 90", test.SumImportance)
	}
	if test.SeenInAPKs != 2 {
		t.Errorf("SeenInAPKs = %d, want 2", test.SeenInAPKs)
	}
}

func TestAvgNoiseFromRecords_Empty(t *testing.T) {
	got := avgNoiseFromRecords(nil)
	if got != 0 {
		t.Errorf("empty = 0, got %f", got)
	}
}

func TestAvgNoiseFromRecords_WithData(t *testing.T) {
	records := []*AnalysisFeedback{
		{KeywordStats: map[string]*KeywordFeedback{
			"a": {Keyword: "a", Triggered: 10, InLibrary: 8, Dampened: 0},
			"b": {Keyword: "b", Triggered: 10, InLibrary: 2, Dampened: 0},
		}},
	}

	got := avgNoiseFromRecords(records)

	// a: noise = 0.8, b: noise = 0.2, avg = 0.5
	if math.Abs(got-0.5) > 0.001 {
		t.Errorf("avg noise = %f, want 0.5", got)
	}
}
