package main

import (
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestCollectCrackPointsByPath(t *testing.T) {
	extracted := filepath.Join(t.TempDir(), "extracted")
	smaliPath := filepath.Join(extracted, "smali", "com", "app", "Billing.smali")

	result := &types.AnalysisResult{
		TargetDir: extracted,
		CrackPoint: &types.CrackPointResult{
			Points: []types.CrackPoint{
				{
					Location: types.SourceLocation{
						File:   smaliPath,
						Method: "isPremium",
						Line:   42,
					},
					Method:     "isPremium",
					Category:   "premium",
					Confidence: 0.91,
					Impact:     7,
					Suggestion: "Force return true",
					PatchRisk:  "medium",
				},
				{
					Location: types.SourceLocation{
						File:   "smali/com/app/RootCheck.smali",
						Method: "isRooted",
					},
					Method:     "isRooted",
					Category:   "root",
					Confidence: 0.88,
					Suggestion: "Return false",
				},
			},
		},
	}

	got := collectCrackPointsByPath(result, extracted)

	if len(got[smaliPath]) != 1 {
		t.Fatalf("expected 1 crack point for %s, got %d", smaliPath, len(got[smaliPath]))
	}
	if !strings.Contains(got[smaliPath][0], "isPremium") {
		t.Errorf("summary = %q, want isPremium", got[smaliPath][0])
	}

	relPath := filepath.Join(extracted, "smali", "com", "app", "RootCheck.smali")
	if len(got[relPath]) != 1 {
		t.Fatalf("expected relative path resolved to %s, got keys: %v", relPath, mapKeys(got))
	}
}

func TestCollectCrackPointsByPath_Empty(t *testing.T) {
	if got := collectCrackPointsByPath(nil, ""); len(got) != 0 {
		t.Fatalf("expected empty map, got %v", got)
	}
	if got := collectCrackPointsByPath(&types.AnalysisResult{}, ""); len(got) != 0 {
		t.Fatalf("expected empty map, got %v", got)
	}
}

func mapKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
