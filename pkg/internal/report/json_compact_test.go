package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// TestJSONCompactDropsSmaliBodies verifies the compact daily-view export:
// findings, matches and coverage stay, verbatim smali method bodies go. The
// 2026-11-03 corpus run measured smali_class at 128 of 153 MB of
// analysis.json, which made the full export unusable for routine review.
func TestJSONCompactDropsSmaliBodies(t *testing.T) {
	result := &types.AnalysisResult{
		Files: map[string]*types.FileAnalysis{
			"smali/app/A.smali": {
				Path:    "smali/app/A.smali",
				RelPath: "smali/app/A.smali",
				Matches: []types.Match{{Categorized: types.Categorized{Category: types.CategoryCrypto}, Line: 7}},
				SmaliClass: &types.SmaliClass{
					Name: "app.A",
					Methods: []types.SmaliMethod{{
						Name: "run",
						Body: []string{"invoke-virtual {v0}, Ljava/lang/Runtime;->exec", "return-void"},
					}},
				},
			},
		},
	}

	var compact bytes.Buffer
	if err := NewJSONReporter(result).WithCompact(true).GenerateStream(&compact); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(compact.String(), "smali_class") {
		t.Error("compact export must not embed smali_class bodies")
	}
	if !strings.Contains(compact.String(), `"category": "crypto"`) {
		t.Error("compact export must keep match evidence")
	}

	var full bytes.Buffer
	if err := NewJSONReporter(result).GenerateStream(&full); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(full.String(), "smali_class") {
		t.Error("full export must keep smali_class")
	}

	// The shared result must survive both exports untouched: the compact
	// writer shallow-copies per file instead of mutating the map.
	if result.Files["smali/app/A.smali"].SmaliClass == nil {
		t.Error("compact export mutated the caller's result")
	}
	var roundTrip types.AnalysisResult
	if err := json.Unmarshal(full.Bytes(), &roundTrip); err != nil {
		t.Fatal(err)
	}
}
