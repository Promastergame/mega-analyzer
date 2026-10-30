package main

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestFormatCrackPointSummary_Full(t *testing.T) {
	pt := types.CrackPoint{
		Method:     "isPremium",
		Category:   "license",
		Confidence: 0.85,
		Impact:     3,
		PatchRisk:  "medium",
		Suggestion: "return true early",
	}
	got := formatCrackPointSummary(pt)
	if !strings.Contains(got, "isPremium") {
		t.Errorf("missing method: %q", got)
	}
	if !strings.Contains(got, "license") {
		t.Errorf("missing category: %q", got)
	}
	if !strings.Contains(got, "conf=0.85") {
		t.Errorf("missing confidence: %q", got)
	}
	if !strings.Contains(got, "impact=3") {
		t.Errorf("missing impact: %q", got)
	}
	if !strings.Contains(got, "risk=medium") {
		t.Errorf("missing risk: %q", got)
	}
	if !strings.Contains(got, "return true early") {
		t.Errorf("missing suggestion: %q", got)
	}
}

func TestFormatCrackPointSummary_Defaults(t *testing.T) {
	pt := types.CrackPoint{
		Location: types.SourceLocation{Method: "checkLicense"},
	}
	got := formatCrackPointSummary(pt)
	if !strings.Contains(got, "checkLicense") {
		t.Errorf("should use Location.Method when Method is empty: %q", got)
	}
	if !strings.Contains(got, "gate") {
		t.Errorf("should default category to 'gate': %q", got)
	}
}

func TestCollectCrackPointsByPath_NilResult(t *testing.T) {
	out := collectCrackPointsByPath(nil, "")
	if len(out) != 0 {
		t.Errorf("nil result should return empty map")
	}
}

func TestCollectCrackPointsByPath_NilCrackPoint(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.CrackPoint = nil
	out := collectCrackPointsByPath(result, "")
	if len(out) != 0 {
		t.Errorf("nil CrackPoint should return empty map")
	}
}

func TestCollectCrackPointsByPath_EmptyPoints(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.CrackPoint = &types.CrackPointResult{Points: nil}
	out := collectCrackPointsByPath(result, "")
	if len(out) != 0 {
		t.Errorf("empty Points should return empty map")
	}
}

func TestCollectCrackPointsByPath_WithPoints(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.CrackPoint = &types.CrackPointResult{
		Points: []types.CrackPoint{
			{
				Location:   types.SourceLocation{File: "/abs/path/to/License.smali"},
				Method:     "checkLicense",
				Confidence: 0.9,
			},
		},
	}
	out := collectCrackPointsByPath(result, "")
	if len(out) == 0 {
		t.Error("expected at least one entry for absolute path crackpoint")
	}
}

func TestResolveCrackPointPath_Empty(t *testing.T) {
	got := resolveCrackPointPath("", "", "")
	if got != "" {
		t.Errorf("empty filePath should return empty, got %q", got)
	}
}

func TestResolveCrackPointPath_Absolute(t *testing.T) {
	got := resolveCrackPointPath("/absolute/path.smali", "", "")
	if got == "" {
		t.Errorf("absolute path should not return empty: %q", got)
	}
}

func TestResolveCrackPointPath_Relative(t *testing.T) {
	got := resolveCrackPointPath("smali/com/app/Main.smali", "/extracted", "/target")
	_ = got // result depends on filesystem; just ensure no panic
}

func TestCrackPointsFromResult_Nil(t *testing.T) {
	pts := crackPointsFromResult(nil)
	if pts != nil {
		t.Errorf("nil result should return nil, got %v", pts)
	}
}

func TestCrackPointsFromResult_NilCrackPoint(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.CrackPoint = nil
	pts := crackPointsFromResult(result)
	if pts != nil {
		t.Errorf("nil CrackPoint should return nil")
	}
}

func TestCrackPointsFromResult_WithPoints(t *testing.T) {
	result := types.NewAnalysisResult("/tmp")
	result.CrackPoint = &types.CrackPointResult{
		Points: []types.CrackPoint{
			{Method: "isPremium", Confidence: 0.8},
		},
	}
	pts := crackPointsFromResult(result)
	if len(pts) != 1 {
		t.Errorf("expected 1 point, got %d", len(pts))
	}
}
