package ncer

import (
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestConsequenceScore_EmptyFindingsIsZero(t *testing.T) {
	if got := ConsequenceScore(nil); got != 0.0 {
		t.Errorf("ConsequenceScore(nil) = %v, want 0.0", got)
	}
	if got := ConsequenceScore([]types.AnomalyFinding{}); got != 0.0 {
		t.Errorf("ConsequenceScore([]) = %v, want 0.0", got)
	}
}

func TestConsequenceScore_SingleCriticalIsHigh(t *testing.T) {
	got := ConsequenceScore([]types.AnomalyFinding{{Severity: types.SeverityCritical}})
	if got != 1.0 {
		t.Errorf("single critical finding = %v, want 1.0", got)
	}
}

func TestConsequenceScore_SeverityOrdering(t *testing.T) {
	low := ConsequenceScore([]types.AnomalyFinding{{Severity: types.SeverityLow}})
	medium := ConsequenceScore([]types.AnomalyFinding{{Severity: types.SeverityMedium}})
	high := ConsequenceScore([]types.AnomalyFinding{{Severity: types.SeverityHigh}})
	critical := ConsequenceScore([]types.AnomalyFinding{{Severity: types.SeverityCritical}})

	if !(low < medium && medium < high && high < critical) {
		t.Errorf("expected strictly increasing severity weights, got low=%v medium=%v high=%v critical=%v",
			low, medium, high, critical)
	}
}

func TestConsequenceScore_ExplicitScoreCanDominateSeverity(t *testing.T) {
	got := ConsequenceScore([]types.AnomalyFinding{{Severity: types.SeverityLow, Score: 0.95}})
	if got != 0.95 {
		t.Errorf("explicit high Score should win over Low severity weight, got %v, want 0.95", got)
	}
}

func TestConsequenceScore_CriticalDominatesNoise(t *testing.T) {
	// A single critical finding buried in low-severity noise must keep the
	// score saturated at 1.0 (noisy-OR), not dilute toward the mean.
	findings := []types.AnomalyFinding{{Severity: types.SeverityCritical}}
	for i := 0; i < 50; i++ {
		findings = append(findings, types.AnomalyFinding{Severity: types.SeverityLow})
	}
	got := ConsequenceScore(findings)
	if got != 1.0 {
		t.Errorf("critical + 50 low findings = %v, want 1.0 (noisy-OR must not dilute a critical)", got)
	}
}

func TestConsequenceScore_NoisyOrAccumulates(t *testing.T) {
	// Two low findings (0.15 each) combine via noisy-OR: 1 - (0.85 * 0.85).
	got := ConsequenceScore([]types.AnomalyFinding{
		{Severity: types.SeverityLow},
		{Severity: types.SeverityLow},
	})
	want := float32(1.0 - (0.85 * 0.85))
	if abs32(got-want) > 1e-6 {
		t.Errorf("noisy-OR of low+low = %v, want %v", got, want)
	}
	// Adding a finding never lowers the score.
	single := ConsequenceScore([]types.AnomalyFinding{{Severity: types.SeverityLow}})
	if got < single {
		t.Errorf("adding a finding lowered the score: %v < %v", got, single)
	}
}

func TestConsequenceScore_ClampedToUnitInterval(t *testing.T) {
	got := ConsequenceScore([]types.AnomalyFinding{{Severity: types.SeverityCritical, Score: 5.0}})
	if got > 1.0 {
		t.Errorf("ConsequenceScore must clamp to 1.0, got %v", got)
	}
}

func TestCollector_ScoreConsequence_NoFindingsLeavesZero(t *testing.T) {
	c := &Collector{}
	result := &types.NcerCausalResult{}
	c.scoreConsequence(result)
	if result.DConsequence != 0.0 {
		t.Errorf("DConsequence with no findings attached = %v, want 0.0", result.DConsequence)
	}
}

func TestCollector_ScoreConsequence_UsesAttachedFindings(t *testing.T) {
	c := &Collector{}
	c.SetAnomalyFindings([]types.AnomalyFinding{{Severity: types.SeverityCritical}})
	result := &types.NcerCausalResult{}
	c.scoreConsequence(result)
	if result.DConsequence != 1.0 {
		t.Errorf("DConsequence with a critical finding attached = %v, want 1.0", result.DConsequence)
	}
}

func abs32(x float32) float32 {
	if x < 0 {
		return -x
	}
	return x
}
