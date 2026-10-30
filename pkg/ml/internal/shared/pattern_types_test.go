package shared

import (
	"testing"
)

func TestPatternEffectiveness_CalculateRates(t *testing.T) {
	pe := &PatternEffectiveness{
		TotalDetections: 10,
		TruePositives:   8,
		FalsePositives:  2,
		CrashCount:      1,
	}

	pe.CalculateRates()

	if pe.TruePositiveRate != 0.8 {
		t.Errorf("expected TPR 0.8, got %f", pe.TruePositiveRate)
	}
	if pe.FalsePositiveRate != 0.2 {
		t.Errorf("expected FPR 0.2, got %f", pe.FalsePositiveRate)
	}
	if pe.CrashRate != 0.1 {
		t.Errorf("expected CrashRate 0.1, got %f", pe.CrashRate)
	}

	// Test zero case
	peZero := &PatternEffectiveness{}
	peZero.CalculateRates()

	if peZero.TruePositiveRate != 0.0 || peZero.FalsePositiveRate != 0.0 || peZero.CrashRate != 0.0 {
		t.Errorf("expected zero rates, got TPR:%f FPR:%f CR:%f", peZero.TruePositiveRate, peZero.FalsePositiveRate, peZero.CrashRate)
	}
}
