package ml

import (
	"bytes"
	"strings"
	"testing"
)

func TestMLSuggester_InteractiveSuggest(t *testing.T) {
	buf := new(bytes.Buffer)
	h := &AnalysisHistory{}

	// Create some data to get suggestions
	fb := &AnalysisFeedback{
		TotalFiles: 100,
		KeywordStats: map[string]*KeywordFeedback{
			"test_keyword": {
				Keyword:   "test_keyword",
				Triggered: 10,
				InLibrary: 8,
			},
		},
	}
	h.Append(fb)

	s := NewMLSuggester(h, WithOutput(buf))
	s.InteractiveSuggest()

	out := buf.String()
	if !strings.Contains(out, "INTELLIGENCE REPORT") {
		t.Error("Header not found")
	}
}
