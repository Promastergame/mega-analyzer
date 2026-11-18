package pipeline

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
)

// TestTypedFindingFromDataFlowWeakSliceDowngrade locks the confidence-aware
// severity mapping: the backward slicer scores every path, and floor-level
// (speculative) flows must not carry HIGH severity into the verdict. Measured
// motivation: the clean markor baseline carried 93 HIGH data-flow findings,
// 34 of them at the 0.55 evidence floor (2026-11-04).
func TestTypedFindingFromDataFlowWeakSliceDowngrade(t *testing.T) {
	mk := func(confidence float64, severity string) finding.Finding {
		return typedFindingFromDataFlow(types.DataFlowFinding{
			Category:   "path_traversal",
			Severity:   severity,
			Confidence: confidence,
			Location:   types.SourceLocation{File: "smali/app/A.smali", Line: 12, Method: "Lapp/A;->run"},
		}, nil)
	}

	cases := []struct {
		confidence float64
		inSeverity string
		want       string
		wantWeak   bool
	}{
		{0.55, "high", "medium", true},   // evidence floor: speculative
		{0.55, "critical", "high", true}, // even critical needs a strong path
		{0.66, "high", "medium", true},
		{0.70, "high", "high", false}, // the gate is exclusive
		{0.86, "high", "high", false},
		{0.99, "high", "high", false},
		{0.55, "medium", "medium", true}, // medium and below keep their weight
	}
	for _, tc := range cases {
		item := mk(tc.confidence, tc.inSeverity)
		if item.Severity != tc.want {
			t.Errorf("confidence %.2f severity %s -> %s, want %s", tc.confidence, tc.inSeverity, item.Severity, tc.want)
		}
		weak := item.Explanation != nil && strings.Contains(item.Explanation.Status, "weak_slice")
		if weak != tc.wantWeak {
			t.Errorf("confidence %.2f: weak-slice status = %v, want %v", tc.confidence, weak, tc.wantWeak)
		}
	}
}
