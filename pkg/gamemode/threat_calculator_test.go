package gamemode

import (
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml"
	"testing"
)

// TestThreatCalculatorInterface verifies the interface is properly defined
func TestThreatCalculatorInterface(t *testing.T) {
	// This test ensures the interface compiles and is usable
	var _ ThreatCalculator = (*mockThreatCalculator)(nil)
}

// mockThreatCalculator is a mock implementation for testing
type mockThreatCalculator struct{}

func (m *mockThreatCalculator) CalculateThreatScore(patchPoints []ml.PatchPoint, result *types.AnalysisResult) ThreatResult {
	return ThreatResult{
		TotalScore:        0,
		ByCategory:        make(map[string]float64),
		CategoryBreakdown: []CategoryBreakdown{},
		DiversityBonus:    0,
	}
}

func (m *mockThreatCalculator) GetCategoryBreakdown(threatResult ThreatResult) []CategoryBreakdown {
	return threatResult.CategoryBreakdown
}

// TestPatchPointStructure verifies PatchPoint structure
func TestPatchPointStructure(t *testing.T) {
	pp := ml.PatchPoint{
		Category:      ml.PatchCatBilling,
		RiskLevel:     ml.RiskClassHigh,
		IsLibraryCode: false,
		Confidence:    0.85,
	}

	if pp.Category != ml.PatchCatBilling {
		t.Errorf("Expected category 'billing', got '%s'", pp.Category)
	}
	if pp.RiskLevel != ml.RiskClassHigh {
		t.Errorf("Expected risk level 'high', got '%s'", pp.RiskLevel)
	}
	if pp.IsLibraryCode {
		t.Error("Expected IsLibraryCode to be false")
	}
	if pp.Confidence != 0.85 {
		t.Errorf("Expected confidence 0.85, got %f", pp.Confidence)
	}
}

// TestThreatResultStructure verifies ThreatResult structure
func TestThreatResultStructure(t *testing.T) {
	tr := ThreatResult{
		TotalScore: 500.0,
		ByCategory: map[string]float64{
			"billing": 300.0,
			"license": 200.0,
		},
		CategoryBreakdown: []CategoryBreakdown{
			{Category: "billing", Points: 300.0, Weight: 3.0, Count: 2},
			{Category: "license", Points: 200.0, Weight: 2.0, Count: 1},
		},
		DiversityBonus: 50.0,
	}

	if tr.TotalScore != 500.0 {
		t.Errorf("Expected total score 500.0, got %f", tr.TotalScore)
	}

	// Use DiversityBonus to avoid unused field warning
	if tr.DiversityBonus != 50.0 {
		t.Errorf("Expected diversity bonus 50.0, got %f", tr.DiversityBonus)
	}
	if len(tr.ByCategory) != 2 {
		t.Errorf("Expected 2 categories, got %d", len(tr.ByCategory))
	}
	if len(tr.CategoryBreakdown) != 2 {
		t.Errorf("Expected 2 category breakdowns, got %d", len(tr.CategoryBreakdown))
	}
}
