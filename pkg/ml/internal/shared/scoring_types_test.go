package shared

import (
	"testing"
)

func TestRiskClass_Emoji(t *testing.T) {
	tests := []struct {
		risk     RiskClass
		expected string
	}{
		{RiskClassHigh, "🔴"},
		{RiskClassMedium, "🟡"},
		{RiskClassLow, "🟢"},
		{RiskClassNone, "⚪"},
		{RiskClass("UNKNOWN"), "⚪"},
	}

	for _, tt := range tests {
		if got := tt.risk.Emoji(); got != tt.expected {
			t.Errorf("RiskClass.Emoji(%q) = %v, want %v", tt.risk, got, tt.expected)
		}
	}
}

func TestScoreResult_Instantiate(t *testing.T) {
	sr := ScoreResult{
		FinalScore:     85.5,
		RiskLevel:      RiskClassHigh,
		Confidence:     0.9,
		BaseScore:      80.0,
		SuggestedPatch: PatchReturnTrue,
		PatchCategory:  PatchCatPremium,
	}

	if sr.RiskLevel.Emoji() != "🔴" {
		t.Errorf("expected 🔴, got %s", sr.RiskLevel.Emoji())
	}

	sm := ScoredMethod{
		Method:    MethodInfo{Name: "test"},
		Score:     sr,
		ClassName: "TestClass",
	}

	if sm.ClassName != "TestClass" {
		t.Errorf("expected TestClass")
	}
	if sm.Score.FinalScore != 85.5 {
		t.Errorf("expected 85.5, got %f", sm.Score.FinalScore)
	}
	if sm.Method.Name != "test" {
		t.Errorf("expected test")
	}
}
