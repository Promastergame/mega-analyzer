package ml

import (
	"io"
	"path/filepath"
	"testing"
)

func TestMLSuggester_NormalizePattern(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Lcom/app/Test/", "com/app/test"},
		{"Lcom/app/Test/.*", "com/app/test"},
		{"com/app/Test", "com/app/test"},
	}
	for _, tt := range tests {
		if got := normalizePattern(tt.input); got != tt.want {
			t.Errorf("normalizePattern(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestMLSuggester_LibraryDampeningRule(t *testing.T) {
	s := &MLSuggester{}
	lib := &AggregatedLibraryStats{
		Prefix:     "Lcom/ads/",
		TotalFiles: 100,
	}
	// Note: AvgImportance depends on TotalMatched and cumulative weight,
	// which might be 0/0.
	rule := s.generateLibraryDampeningRule(lib)
	if rule == "" {
		t.Error("Should generate rule")
	}
}

func TestMLSuggester_FilterAlreadyApplied(t *testing.T) {
	s := &MLSuggester{}
	ctx := &analysisContext{
		snapshot: []*AnalysisFeedback{
			{
				UserOverrides: []UserOverride{
					{Path: "Lcom/app/AlreadyApplied/", Action: FeedbackNoise},
				},
			},
		},
	}
	suggestions := []Suggestion{
		{Target: "Lcom/app/AlreadyApplied/"},
		{Target: "Lcom/app/New/"},
	}

	filtered := s.filterAlreadyApplied(ctx, suggestions)
	if len(filtered) != 1 {
		t.Errorf("len(filtered) = %d, want 1", len(filtered))
	}
}

func TestMLSuggester_InteractiveSuggest_NoSuggestions(t *testing.T) {
	h, _ := LoadHistory(filepath.Join(testTempDir(t), "history.json"))
	s := NewMLSuggester(h, WithSuggesterConfig(DefaultSuggesterConfig()))
	s.output = io.Discard
	s.InteractiveSuggest()
}

func TestMLSuggester_CalculateStats_EdgeCases(t *testing.T) {
	s := &MLSuggester{}
	// Empty context
	ctx := &analysisContext{}
	stats := s.calculateStats(ctx)
	if stats.TotalKeywords != 0 {
		t.Errorf("TotalKeywords = %d", stats.TotalKeywords)
	}
}

func TestMLSuggester_AssessSignalClarity_Insufficient(t *testing.T) {
	s := &MLSuggester{}
	ctx := &analysisContext{
		snapshot: []*AnalysisFeedback{
			{}, // 1 record
		},
	}
	clarity := s.assessSignalClarity(ctx)
	if clarity != "insufficient data" {
		t.Errorf("clarity = %q", clarity)
	}
}
