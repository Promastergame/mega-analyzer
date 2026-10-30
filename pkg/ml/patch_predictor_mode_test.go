package ml

import (
	"bytes"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// MODE-SPECIFIC TERMINOLOGY TESTS (Task 7.8)
// ═══════════════════════════════════════════════════════════════════════════════

func TestPatchPredictor_GetPatchLabel_DefensiveMode(t *testing.T) {
	var buf bytes.Buffer
	config := DefaultPredictorConfig()
	config.Mode = PatchModeDefensive
	predictor := NewPatchPredictorWithConfig(&buf, config)

	tests := []struct {
		name       string
		isHighRisk bool
		expected   string
	}{
		{"high risk", true, "Impact"},
		{"low risk", false, "Weakness"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := predictor.getPatchLabel(tt.isHighRisk)
			if result != tt.expected {
				t.Errorf("getPatchLabel(%v) = %q, want %q", tt.isHighRisk, result, tt.expected)
			}
		})
	}
}

func TestPatchPredictor_GetPatchLabel_ResearchMode(t *testing.T) {
	var buf bytes.Buffer
	config := DefaultPredictorConfig()
	config.Mode = PatchModeResearch
	predictor := NewPatchPredictorWithConfig(&buf, config)

	tests := []struct {
		name       string
		isHighRisk bool
		expected   string
	}{
		{"high risk", true, "Bypass"},
		{"low risk", false, "Exploit suggestion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := predictor.getPatchLabel(tt.isHighRisk)
			if result != tt.expected {
				t.Errorf("getPatchLabel(%v) = %q, want %q", tt.isHighRisk, result, tt.expected)
			}
		})
	}
}

func TestPatchPredictor_PrintTerminologyLegend_DefensiveMode(t *testing.T) {
	var buf bytes.Buffer
	config := DefaultPredictorConfig()
	config.Mode = PatchModeDefensive
	predictor := NewPatchPredictorWithConfig(&buf, config)

	predictor.printTerminologyLegend(&buf)

	output := buf.String()

	expectedStrings := []string{
		"Terminology",
		"Defensive Mode",
		"Weakness",
		"Impact",
		"🛡️",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("printTerminologyLegend() output should contain %q", expected)
		}
	}
}

func TestPatchPredictor_PrintTerminologyLegend_ResearchMode(t *testing.T) {
	var buf bytes.Buffer
	config := DefaultPredictorConfig()
	config.Mode = PatchModeResearch
	predictor := NewPatchPredictorWithConfig(&buf, config)

	predictor.printTerminologyLegend(&buf)

	output := buf.String()

	expectedStrings := []string{
		"Terminology",
		"Research Mode",
		"Bypass",
		"Exploit suggestion",
		"⚔️",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("printTerminologyLegend() output should contain %q", expected)
		}
	}
}

func TestPatchPredictor_RenderToTerminal_IncludesTerminologyLegend(t *testing.T) {
	var buf bytes.Buffer
	config := DefaultPredictorConfig()
	config.Mode = PatchModeDefensive
	predictor := NewPatchPredictorWithConfig(&buf, config)

	prediction := &PatchPrediction{
		HighRisk:   []PatchPoint{},
		MediumRisk: []PatchPoint{},
		LowRisk:    []PatchPoint{},
		Mode:       PatchModeDefensive,
		Stats: PredictionStats{
			PatchPointsFound: 0,
		},
	}

	predictor.RenderToTerminal(prediction)

	output := buf.String()

	// Should include terminology legend
	if !strings.Contains(output, "Terminology") {
		t.Error("RenderToTerminal() should include terminology legend")
	}

	if !strings.Contains(output, "Defensive Mode") {
		t.Error("RenderToTerminal() should include mode name")
	}
}

func TestPatchPredictor_RenderPoint_UsesModeSpecificLabel(t *testing.T) {
	var buf bytes.Buffer
	config := DefaultPredictorConfig()
	config.Mode = PatchModeDefensive
	predictor := NewPatchPredictorWithConfig(&buf, config)

	point := PatchPoint{
		FilePath:      "com/example/Test.smali",
		MethodName:    "isRooted",
		ReturnType:    "Z",
		RiskScore:     85.0,
		Confidence:    0.9,
		CategoryName:  "Root Detection",
		PatchDesc:     "Return false to hide root",
		WhyVulnerable: []string{"Detects root access"},
		MatchedParts:  []string{"root", "su"},
	}

	predictor.renderPoint(&buf, 1, &point)

	output := buf.String()

	// Should use "Impact" for high-risk in defensive mode
	if !strings.Contains(output, "Impact") {
		t.Error("renderPoint() should use 'Impact' label in defensive mode for high-risk")
	}
}

func TestPatchPrediction_ModeField(t *testing.T) {
	prediction := &PatchPrediction{
		Mode:  PatchModeDefensive,
		Stats: PredictionStats{},
	}

	if prediction.Mode != PatchModeDefensive {
		t.Errorf("PatchPrediction.Mode = %q, want %q", prediction.Mode, PatchModeDefensive)
	}
}

func TestBuildPrediction_SetsModeField(t *testing.T) {
	var buf bytes.Buffer
	config := DefaultPredictorConfig()
	config.Mode = PatchModeResearch
	predictor := NewPatchPredictorWithConfig(&buf, config)

	scored := []ScoredMethod{}
	batch := &BatchAnalyzeResult{
		TotalFiles:      10,
		TotalMethods:    50,
		AnalyzedMethods: 50,
		SkippedMethods:  0,
	}

	prediction := predictor.buildPrediction(scored, batch)

	if prediction.Mode != PatchModeResearch {
		t.Errorf("buildPrediction() Mode = %q, want %q", prediction.Mode, PatchModeResearch)
	}
}

func TestEmptyPrediction_SetsModeField(t *testing.T) {
	var buf bytes.Buffer
	config := DefaultPredictorConfig()
	config.Mode = PatchModeDefensive
	predictor := NewPatchPredictorWithConfig(&buf, config)

	prediction := predictor.emptyPrediction()

	if prediction.Mode != PatchModeDefensive {
		t.Errorf("emptyPrediction() Mode = %q, want %q", prediction.Mode, PatchModeDefensive)
	}
}
