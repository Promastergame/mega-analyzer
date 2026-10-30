package ml

import (
	"strings"
	"testing"
)

// TestMarkdownExporter_Integration tests the Markdown exporter with real patch generation
func TestMarkdownExporter_Integration(t *testing.T) {
	// Create patch generator
	generator := NewPatchGenerator()

	// Create a sample patch point
	point := &PatchPoint{
		MethodName:      "isRooted",
		FilePath:        "com/example/security/RootCheck.smali",
		ClassName:       "RootCheck",
		MethodSignature: "()Z",
		SuggestedPatch:  PatchReturnFalse,
		PatchDesc:       "Return false to bypass root detection",
		Confidence:      0.85,
		RiskScore:       75.0,
		RiskLevel:       RiskClassHigh,
		Category:        PatchCatRootDetect,
		CategoryName:    "Root Detection",
		ReturnType:      "Z",
		MethodHeader:    ".method public isRooted()Z",
		MethodBody: []string{
			".method public isRooted()Z",
			"    .registers 2",
			"    invoke-static {}, Lcom/example/Utils;->checkRoot()Z",
			"    move-result v0",
			"    return v0",
			".end method",
		},
	}

	// Generate patch
	patch := generator.Generate(point)
	if patch == nil {
		t.Fatal("Failed to generate patch")
	}

	// Add mode and explanation
	patch.Mode = PatchModeResearch
	patch.Explanation = PatchExplanation{
		Reason:       "Method checks for root access",
		WhatItDoes:   "Detects if device is rooted",
		WhyThisPatch: "Return false to hide root status",
		Impact:       "App will not detect rooted device",
		Signals:      []string{"name:isRooted", "return:boolean"},
	}

	// Create exporter
	exporter := NewMarkdownExporter()

	// Export to string
	result := exporter.ExportToString([]*GeneratedPatch{patch}, []PatchPoint{*point})

	// Verify the output contains expected sections
	expectedSections := []string{
		"# ML Patcher Report",
		"## Summary",
		"**Total Patches:** 1",
		"## High Risk Patches",
		"⚔️", // Research mode icon
		"isRooted",
		"**Explanation:**",
		"**Original Code:**",
		"**Patched Code:**",
		"**Diff:**",
		"```smali",
		"```diff",
	}

	for _, section := range expectedSections {
		if !strings.Contains(result, section) {
			t.Errorf("Missing expected section: %s", section)
		}
	}

	// Verify patch content
	if !strings.Contains(result, "const/4 v0, 0x0") {
		t.Error("Missing patched instruction")
	}

	if !strings.Contains(result, "return v0") {
		t.Error("Missing return instruction")
	}
}

// TestMarkdownExporter_MultiplePatches tests exporting multiple patches with different modes
func TestMarkdownExporter_MultiplePatches(t *testing.T) {
	generator := NewPatchGenerator()

	// Create research mode patch
	researchPoint := &PatchPoint{
		MethodName:     "isPremium",
		FilePath:       "com/example/billing/License.smali",
		SuggestedPatch: PatchReturnTrue,
		Confidence:     0.92,
		RiskScore:      85.0,
		RiskLevel:      RiskClassHigh,
		Category:       PatchCatPremium,
		CategoryName:   "Premium Check",
		ReturnType:     "Z",
		MethodHeader:   ".method public isPremium()Z",
		MethodBody: []string{
			".method public isPremium()Z",
			"    .registers 1",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}

	researchPatch := generator.Generate(researchPoint)
	researchPatch.Mode = PatchModeResearch
	researchPatch.Explanation = PatchExplanation{
		Reason:       "Premium license check detected",
		WhatItDoes:   "Verifies premium license status",
		WhyThisPatch: "Bypass license check for testing",
		Impact:       "Premium features will be accessible",
	}

	// Create defensive mode patch
	defensivePoint := &PatchPoint{
		MethodName:     "validateSignature",
		FilePath:       "com/example/security/Validator.smali",
		SuggestedPatch: PatchReturnTrue,
		Confidence:     0.88,
		RiskScore:      80.0,
		RiskLevel:      RiskClassHigh,
		Category:       PatchCatSignature,
		CategoryName:   "Signature Check",
		ReturnType:     "Z",
		MethodHeader:   ".method public validateSignature()Z",
		MethodBody: []string{
			".method public validateSignature()Z",
			"    .registers 1",
			"    const/4 v0, 0x1",
			"    return v0",
			".end method",
		},
	}

	defensivePatch := generator.Generate(defensivePoint)
	defensivePatch.Mode = PatchModeDefensive
	defensivePatch.Explanation = PatchExplanation{
		Reason:       "Weak signature validation detected",
		WhatItDoes:   "Validates app signature",
		WhyThisPatch: "Enforce strict signature checking",
		Impact:       "Prevents tampering and repackaging",
	}

	// Export both patches
	exporter := NewMarkdownExporter()
	result := exporter.ExportToString(
		[]*GeneratedPatch{researchPatch, defensivePatch},
		[]PatchPoint{*researchPoint, *defensivePoint},
	)

	// Verify both modes are present
	if !strings.Contains(result, "⚔️") {
		t.Error("Missing research mode icon")
	}

	if !strings.Contains(result, "🛡️") {
		t.Error("Missing defensive mode icon")
	}

	// Verify mode summary
	if !strings.Contains(result, "### By Mode") {
		t.Error("Missing mode summary section")
	}

	// Verify both patches are present
	if !strings.Contains(result, "isPremium") {
		t.Error("Missing research mode patch")
	}

	if !strings.Contains(result, "validateSignature") {
		t.Error("Missing defensive mode patch")
	}

	// Verify total count
	if !strings.Contains(result, "**Total Patches:** 2") {
		t.Error("Incorrect total patches count")
	}
}

// TestMarkdownExporter_ConfidenceBreakdownIntegration tests confidence breakdown rendering
func TestMarkdownExporter_ConfidenceBreakdownIntegration(t *testing.T) {
	generator := NewPatchGenerator()

	point := &PatchPoint{
		MethodName:     "isDebugMode",
		FilePath:       "com/example/debug/DebugCheck.smali",
		SuggestedPatch: PatchReturnFalse,
		Confidence:     0.87,
		RiskScore:      70.0,
		RiskLevel:      RiskClassMedium,
		ReturnType:     "Z",
		MethodHeader:   ".method public isDebugMode()Z",
		MethodBody: []string{
			".method public isDebugMode()Z",
			"    .registers 1",
			"    const/4 v0, 0x1",
			"    return v0",
			".end method",
		},
	}

	patch := generator.Generate(point)
	patch.Mode = PatchModeResearch

	// Add detailed confidence breakdown
	patch.ConfidenceBreakdown = &ConfidenceBreakdown{
		BaseConfidence:    0.75,
		MultiSignalBonus:  0.08,
		ObfuscationAdjust: 0.04,
		FinalConfidence:   0.87,
		SignalContributions: []SignalContribution{
			{
				SignalType:   "name",
				Value:        "isDebugMode",
				Weight:       1.0,
				Confidence:   0.85,
				Contribution: 0.85,
			},
			{
				SignalType:   "api",
				Value:        "isDebuggerConnected",
				Weight:       1.1,
				Confidence:   0.9,
				Contribution: 0.99,
			},
		},
	}

	exporter := NewMarkdownExporter()
	result := exporter.ExportToString([]*GeneratedPatch{patch}, []PatchPoint{*point})

	// Verify confidence breakdown is rendered
	if !strings.Contains(result, "**Confidence Breakdown:**") {
		t.Error("Missing confidence breakdown section")
	}

	if !strings.Contains(result, "**Base Confidence:** 0.75") {
		t.Error("Missing base confidence")
	}

	if !strings.Contains(result, "**Multi-Signal Bonus:** +0.08") {
		t.Error("Missing multi-signal bonus")
	}

	if !strings.Contains(result, "**Obfuscation Adjustment:** +0.04") {
		t.Error("Missing obfuscation adjustment")
	}

	if !strings.Contains(result, "**Final Confidence:** 0.87") {
		t.Error("Missing final confidence")
	}

	// Verify signal contributions
	if !strings.Contains(result, "name: 0.85") {
		t.Error("Missing name signal contribution")
	}

	if !strings.Contains(result, "api: 0.99") {
		t.Error("Missing api signal contribution")
	}
}
