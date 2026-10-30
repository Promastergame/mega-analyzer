package main

import (
	"testing"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ncer"
)

func TestFeedNcerConsequence_NilReportIsNoOp(t *testing.T) {
	c := ncer.NewCollector(time.Now())
	feedNcerConsequence(c, nil)
	res := &types.NcerCausalResult{}
	// scoreConsequence is unexported but ConsequenceScore(nil) == 0.0 is the
	// documented contract; verify indirectly via a fresh Reconcile pass.
	c.ObserveHTTP("GET", "https://example.com", "200", "example.com", "")
	got, err := c.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if got != nil && got.DConsequence != 0.0 {
		t.Errorf("DConsequence with no BehaviorAnalysis = %v, want 0.0", got.DConsequence)
	}
	_ = res
}

func TestFeedNcerConsequence_NoIndicatorsIsNoOp(t *testing.T) {
	c := ncer.NewCollector(time.Now())
	feedNcerConsequence(c, &sandbox.Report{BehaviorAnalysis: &sandbox.BehaviorAnalysis{}})
	c.ObserveHTTP("GET", "https://example.com", "200", "example.com", "")
	got, err := c.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if got != nil && got.DConsequence != 0.0 {
		t.Errorf("DConsequence with empty Indicators = %v, want 0.0", got.DConsequence)
	}
}

func TestFeedNcerConsequence_HighSeverityIndicatorRaisesDConsequence(t *testing.T) {
	c := ncer.NewCollector(time.Now())
	report := &sandbox.Report{
		BehaviorAnalysis: &sandbox.BehaviorAnalysis{
			Indicators: []sandbox.BehaviorIndicator{
				{Type: "ransomware_behavior", Description: "mass file encryption", Severity: 10},
			},
		},
	}
	feedNcerConsequence(c, report)
	c.ObserveHTTP("GET", "https://example.com", "200", "example.com", "")

	got, err := c.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if got == nil {
		t.Skip("native library not linked (stub path); skipping score assertion")
	}
	if got.DConsequence != 1.0 {
		t.Errorf("DConsequence with a severity-10 indicator = %v, want 1.0", got.DConsequence)
	}
}

func TestIndicatorSeverity_Mapping(t *testing.T) {
	cases := map[int]types.Severity{
		10: types.SeverityCritical,
		9:  types.SeverityCritical,
		8:  types.SeverityHigh,
		7:  types.SeverityHigh,
		6:  types.SeverityMedium,
		4:  types.SeverityMedium,
		3:  types.SeverityLow,
		1:  types.SeverityLow,
	}
	for in, want := range cases {
		if got := indicatorSeverity(in); got != want {
			t.Errorf("indicatorSeverity(%d) = %v, want %v", in, got, want)
		}
	}
}
