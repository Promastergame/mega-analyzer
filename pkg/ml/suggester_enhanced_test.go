package ml

import (
	"testing"
)

func TestClusterPatterns(t *testing.T) {
	ctx := &analysisContext{}
	keywords := map[string]*AggregatedKeywordStats{
		"com/google/ads/a":  {Keyword: "com/google/ads/a", TotalTriggered: 10, SumImportance: 20},
		"com/google/ads/b":  {Keyword: "com/google/ads/b", TotalTriggered: 10, SumImportance: 20},
		"com/google/ads/c":  {Keyword: "com/google/ads/c", TotalTriggered: 10, SumImportance: 20},
		"org/apache/http/d": {Keyword: "org/apache/http/d", TotalTriggered: 10, SumImportance: 20},
		"org/apache/http/e": {Keyword: "org/apache/http/e", TotalTriggered: 10, SumImportance: 20},
	}

	clusters := ctx.clusterPatterns(keywords)

	// com/google/ads has 3 patterns -> should be a cluster
	// org/apache/http has 2 patterns -> should NOT be a cluster (min 3)

	if len(clusters) != 1 {
		t.Errorf("Expected 1 cluster, got %d", len(clusters))
	} else {
		if clusters[0].CommonPrefix != "com/google/ads" {
			t.Errorf("Expected cluster prefix com/google/ads, got %s", clusters[0].CommonPrefix)
		}
		if len(clusters[0].Patterns) != 3 {
			t.Errorf("Expected 3 patterns in cluster, got %d", len(clusters[0].Patterns))
		}
	}
}

func TestExtractPrefix(t *testing.T) {
	tests := []struct {
		pattern string
		prefix  string
	}{
		{"com/google/ads/Banner", "com/google/ads"},
		{"Lcom/google/ads/Banner", "com/google/ads"},
		{"simple", ""},
		{"Lno_slash", ""},
		{"a/b", ""}, // too short prefix
	}

	for _, tt := range tests {
		got := extractPrefix(tt.pattern)
		if got != tt.prefix {
			t.Errorf("extractPrefix(%q) = %q, want %q", tt.pattern, got, tt.prefix)
		}
	}
}

func TestIsCriticalContext(t *testing.T) {
	tests := []struct {
		ctx      string
		critical bool
	}{
		{"PREMIUM_CHECK", true},
		{"premium_check", true},
		{"normal_call", false},
		{"billing_client", true},
	}

	for _, tt := range tests {
		if isCriticalContext(tt.ctx) != tt.critical {
			t.Errorf("isCriticalContext(%q) = %v, want %v", tt.ctx, !tt.critical, tt.critical)
		}
	}
}

func TestGenerateClusterSuggestions(t *testing.T) {
	s := &MLSuggester{}
	ctx := &analysisContext{
		aggKeywords: map[string]*AggregatedKeywordStats{
			"p1": {Keyword: "p1", TotalTriggered: 10, SeenInAPKs: 10, TotalInLibrary: 9},
			"p2": {Keyword: "p2", TotalTriggered: 10, SeenInAPKs: 10, TotalInLibrary: 8},
		},
	}

	sugs := s.generateClusterSuggestions(ctx)
	// suggestions might be empty if confidence is low, but we check execution
	_ = sugs
}

func TestIsAntiPattern(t *testing.T) {
	ctx := &analysisContext{}
	kw := &AggregatedKeywordStats{Keyword: "test"}

	anti, _ := ctx.isAntiPattern(kw)
	if anti {
		t.Error("Empty context should not be anti-pattern")
	}
}
