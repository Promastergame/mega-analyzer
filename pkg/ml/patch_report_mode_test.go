package ml

import (
	"bytes"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// MODE-SPECIFIC TERMINOLOGY TESTS FOR PATCH REPORT (Task 7.8)
// ═══════════════════════════════════════════════════════════════════════════════

func TestGetPatchLabelForReport_DefensiveMode(t *testing.T) {
	tests := []struct {
		name       string
		mode       PatchMode
		isHighRisk bool
		expected   string
	}{
		{"defensive high risk", PatchModeDefensive, true, "Impact"},
		{"defensive low risk", PatchModeDefensive, false, "Weakness"},
		{"research high risk", PatchModeResearch, true, "Bypass"},
		{"research low risk", PatchModeResearch, false, "Exploit suggestion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getPatchLabelForReport(tt.mode, tt.isHighRisk)
			if result != tt.expected {
				t.Errorf("getPatchLabelForReport(%q, %v) = %q, want %q", tt.mode, tt.isHighRisk, result, tt.expected)
			}
		})
	}
}

func TestPrintTerminologyLegendForReport_DefensiveMode(t *testing.T) {
	var buf bytes.Buffer

	printTerminologyLegendForReport(&buf, PatchModeDefensive)

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
			t.Errorf("printTerminologyLegendForReport() output should contain %q", expected)
		}
	}
}

func TestPrintTerminologyLegendForReport_ResearchMode(t *testing.T) {
	var buf bytes.Buffer

	printTerminologyLegendForReport(&buf, PatchModeResearch)

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
			t.Errorf("printTerminologyLegendForReport() output should contain %q", expected)
		}
	}
}

func TestRenderToTerminalWithFix_IncludesTerminologyLegend(t *testing.T) {
	var buf bytes.Buffer

	prediction := &PatchPrediction{
		HighRisk:   []PatchPoint{},
		MediumRisk: []PatchPoint{},
		LowRisk:    []PatchPoint{},
		Mode:       PatchModeDefensive,
		Stats: PredictionStats{
			PatchPointsFound: 0,
		},
	}

	RenderToTerminalWithFix(&buf, prediction)

	output := buf.String()

	// Should include terminology legend
	if !strings.Contains(output, "Terminology") {
		t.Error("RenderToTerminalWithFix() should include terminology legend")
	}

	if !strings.Contains(output, "Defensive Mode") {
		t.Error("RenderToTerminalWithFix() should include mode name")
	}
}

func TestRenderToTerminalWithFix_UsesModeSpecificLabel_HighRisk(t *testing.T) {
	var buf bytes.Buffer

	prediction := &PatchPrediction{
		HighRisk: []PatchPoint{
			{
				FilePath:        "com/example/Test.smali",
				ClassName:       "Test",
				MethodName:      "isRooted",
				MethodSignature: "()Z",
				ReturnType:      "Z",
				RiskScore:       85.0,
				RiskLevel:       RiskClassHigh,
				Confidence:      0.9,
				CategoryName:    "Root Detection",
				SuggestedPatch:  PatchReturnFalse,
				PatchDesc:       "Return false to hide root",
				WhyVulnerable:   []string{"Detects root access"},
				MethodBody:      []string{".method public isRooted()Z", ".end method"},
				MethodHeader:    ".method public isRooted()Z",
			},
		},
		MediumRisk: []PatchPoint{},
		LowRisk:    []PatchPoint{},
		Mode:       PatchModeDefensive,
		Stats: PredictionStats{
			PatchPointsFound: 1,
		},
	}

	RenderToTerminalWithFix(&buf, prediction)

	output := buf.String()

	// Should use "Impact" for high-risk in defensive mode
	if !strings.Contains(output, "Impact") {
		t.Error("RenderToTerminalWithFix() should use 'Impact' label in defensive mode for high-risk")
	}
}

func TestRenderToTerminalWithFix_UsesModeSpecificLabel_ResearchMode(t *testing.T) {
	var buf bytes.Buffer

	prediction := &PatchPrediction{
		HighRisk: []PatchPoint{
			{
				FilePath:        "com/example/Test.smali",
				ClassName:       "Test",
				MethodName:      "isRooted",
				MethodSignature: "()Z",
				ReturnType:      "Z",
				RiskScore:       85.0,
				RiskLevel:       RiskClassHigh,
				Confidence:      0.9,
				CategoryName:    "Root Detection",
				SuggestedPatch:  PatchReturnFalse,
				PatchDesc:       "Return false to hide root",
				WhyVulnerable:   []string{"Detects root access"},
				MethodBody:      []string{".method public isRooted()Z", ".end method"},
				MethodHeader:    ".method public isRooted()Z",
			},
		},
		MediumRisk: []PatchPoint{},
		LowRisk:    []PatchPoint{},
		Mode:       PatchModeResearch,
		Stats: PredictionStats{
			PatchPointsFound: 1,
		},
	}

	RenderToTerminalWithFix(&buf, prediction)

	output := buf.String()

	// Should use "Bypass" for high-risk in research mode
	if !strings.Contains(output, "Bypass") {
		t.Error("RenderToTerminalWithFix() should use 'Bypass' label in research mode for high-risk")
	}
}

func TestRenderToTerminalWithFix_UsesModeSpecificLabel_MediumRisk(t *testing.T) {
	var buf bytes.Buffer

	prediction := &PatchPrediction{
		HighRisk: []PatchPoint{},
		MediumRisk: []PatchPoint{
			{
				FilePath:        "com/example/Test.smali",
				ClassName:       "Test",
				MethodName:      "checkLicense",
				MethodSignature: "()Z",
				ReturnType:      "Z",
				RiskScore:       60.0,
				RiskLevel:       RiskClassMedium,
				Confidence:      0.7,
				CategoryName:    "License Check",
				SuggestedPatch:  PatchReturnTrue,
				PatchDesc:       "Return true to grant access",
				WhyVulnerable:   []string{"Checks license validity"},
				MethodBody:      []string{".method public checkLicense()Z", ".end method"},
				MethodHeader:    ".method public checkLicense()Z",
			},
		},
		LowRisk: []PatchPoint{},
		Mode:    PatchModeDefensive,
		Stats: PredictionStats{
			PatchPointsFound: 1,
		},
	}

	RenderToTerminalWithFix(&buf, prediction)

	output := buf.String()

	// Should use "Weakness" for medium-risk in defensive mode
	if !strings.Contains(output, "Weakness") {
		t.Error("RenderToTerminalWithFix() should use 'Weakness' label in defensive mode for medium-risk")
	}
}
