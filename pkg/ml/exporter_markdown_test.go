package ml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkdownExporter_ExportToString(t *testing.T) {
	exporter := NewMarkdownExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:   "isRooted",
			FilePath:     "com/example/security/RootCheck.smali",
			PatchType:    PatchReturnFalse,
			Description:  "Return false to bypass root detection",
			Mode:         PatchModeResearch,
			Confidence:   0.85,
			OriginalCode: ".method public isRooted()Z\n    # original code\n.end method",
			PatchedCode:  ".method public isRooted()Z\n    const/4 v0, 0x0\n    return v0\n.end method",
			DiffView:     "--- original\n+++ patched\n-    # original code\n+    const/4 v0, 0x0\n+    return v0",
			Explanation: PatchExplanation{
				Reason:       "Method checks for root access",
				WhatItDoes:   "Detects if device is rooted",
				WhyThisPatch: "Return false to hide root status",
				Impact:       "App will not detect rooted device",
				Signals:      []string{"name:isRooted", "return:boolean"},
			},
			ConfidenceBreakdown: &ConfidenceBreakdown{
				BaseConfidence:    0.75,
				MultiSignalBonus:  0.08,
				ObfuscationAdjust: 0.02,
				FinalConfidence:   0.85,
				SignalContributions: []SignalContribution{
					{
						SignalType:   "name",
						Value:        "isRooted",
						Weight:       1.0,
						Confidence:   0.9,
						Contribution: 0.9,
					},
				},
			},
		},
	}

	points := []PatchPoint{
		{
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
		},
	}

	result := exporter.ExportToString(patches, points)

	// Verify header
	if !strings.Contains(result, "# ML Patcher Report") {
		t.Error("Missing report header")
	}

	// Verify summary
	if !strings.Contains(result, "## Summary") {
		t.Error("Missing summary section")
	}

	if !strings.Contains(result, "**Total Patches:** 1") {
		t.Error("Missing total patches count")
	}

	// Verify mode icon
	if !strings.Contains(result, "⚔️") {
		t.Error("Missing research mode icon")
	}

	// Verify patch details
	if !strings.Contains(result, "isRooted") {
		t.Error("Missing method name")
	}

	if !strings.Contains(result, "**Confidence:** 0.85") {
		t.Error("Missing confidence")
	}

	// Verify explanation
	if !strings.Contains(result, "**Explanation:**") {
		t.Error("Missing explanation section")
	}

	if !strings.Contains(result, "Method checks for root access") {
		t.Error("Missing explanation reason")
	}

	// Verify confidence breakdown
	if !strings.Contains(result, "**Confidence Breakdown:**") {
		t.Error("Missing confidence breakdown")
	}

	if !strings.Contains(result, "**Base Confidence:** 0.75") {
		t.Error("Missing base confidence")
	}

	// Verify code blocks
	if !strings.Contains(result, "```smali") {
		t.Error("Missing Smali code blocks")
	}

	if !strings.Contains(result, "```diff") {
		t.Error("Missing diff block")
	}
}

func TestMarkdownExporter_ExportToFile(t *testing.T) {
	exporter := NewMarkdownExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:  "isPremium",
			FilePath:    "com/example/billing/License.smali",
			PatchType:   PatchReturnTrue,
			Description: "Return true to grant premium access",
			Mode:        PatchModeResearch,
			Confidence:  0.92,
		},
	}

	points := []PatchPoint{
		{
			MethodName:     "isPremium",
			FilePath:       "com/example/billing/License.smali",
			SuggestedPatch: PatchReturnTrue,
			Confidence:     0.92,
			RiskScore:      85.0,
			RiskLevel:      RiskClassHigh,
		},
	}

	// Create temp file
	tmpDir := testTempDir(t)
	outputPath := filepath.Join(tmpDir, "report.md")

	// Export to file
	err := exporter.ExportToFile(patches, points, outputPath)
	if err != nil {
		t.Fatalf("ExportToFile failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("Output file was not created")
	}

	// Read and verify content
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	contentStr := string(content)

	if !strings.Contains(contentStr, "# ML Patcher Report") {
		t.Error("File missing report header")
	}

	if !strings.Contains(contentStr, "isPremium") {
		t.Error("File missing method name")
	}
}

func TestMarkdownExporter_MultipleRiskLevels(t *testing.T) {
	exporter := NewMarkdownExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "highRiskMethod",
			FilePath:   "high.smali",
			Confidence: 0.9,
		},
		{
			MethodName: "mediumRiskMethod",
			FilePath:   "medium.smali",
			Confidence: 0.7,
		},
		{
			MethodName: "lowRiskMethod",
			FilePath:   "low.smali",
			Confidence: 0.4,
		},
	}

	points := []PatchPoint{
		{
			MethodName: "highRiskMethod",
			FilePath:   "high.smali",
			RiskLevel:  RiskClassHigh,
			RiskScore:  90.0,
			Confidence: 0.9,
		},
		{
			MethodName: "mediumRiskMethod",
			FilePath:   "medium.smali",
			RiskLevel:  RiskClassMedium,
			RiskScore:  60.0,
			Confidence: 0.7,
		},
		{
			MethodName: "lowRiskMethod",
			FilePath:   "low.smali",
			RiskLevel:  RiskClassLow,
			RiskScore:  30.0,
			Confidence: 0.4,
		},
	}

	result := exporter.ExportToString(patches, points)

	// Verify risk level sections
	if !strings.Contains(result, "## High Risk Patches") {
		t.Error("Missing high risk section")
	}

	if !strings.Contains(result, "## Medium Risk Patches") {
		t.Error("Missing medium risk section")
	}

	if !strings.Contains(result, "## Low Risk Patches") {
		t.Error("Missing low risk section")
	}

	// Verify summary counts
	if !strings.Contains(result, "🔴 **High Risk:** 1") {
		t.Error("Incorrect high risk count")
	}

	if !strings.Contains(result, "🟡 **Medium Risk:** 1") {
		t.Error("Incorrect medium risk count")
	}

	if !strings.Contains(result, "🟢 **Low Risk:** 1") {
		t.Error("Incorrect low risk count")
	}
}

func TestMarkdownExporter_DefensiveMode(t *testing.T) {
	exporter := NewMarkdownExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:  "validateSignature",
			FilePath:    "security.smali",
			Mode:        PatchModeDefensive,
			Confidence:  0.88,
			Description: "Strengthen signature validation",
		},
	}

	points := []PatchPoint{
		{
			MethodName: "validateSignature",
			FilePath:   "security.smali",
			RiskLevel:  RiskClassMedium,
			Confidence: 0.88,
		},
	}

	result := exporter.ExportToString(patches, points)

	// Verify defensive mode icon
	if !strings.Contains(result, "🛡️") {
		t.Error("Missing defensive mode icon")
	}

	// Verify mode in summary
	if !strings.Contains(result, "🛡️ **defensive:**") {
		t.Error("Missing defensive mode in summary")
	}
}

func TestMarkdownExporter_ConfidenceDistribution(t *testing.T) {
	exporter := NewMarkdownExporter()

	patches := []*GeneratedPatch{
		{MethodName: "high1", Confidence: 0.9},
		{MethodName: "high2", Confidence: 0.85},
		{MethodName: "medium1", Confidence: 0.7},
		{MethodName: "medium2", Confidence: 0.6},
		{MethodName: "low1", Confidence: 0.4},
	}

	points := []PatchPoint{
		{MethodName: "high1", FilePath: "a.smali", RiskLevel: RiskClassHigh, Confidence: 0.9},
		{MethodName: "high2", FilePath: "b.smali", RiskLevel: RiskClassHigh, Confidence: 0.85},
		{MethodName: "medium1", FilePath: "c.smali", RiskLevel: RiskClassMedium, Confidence: 0.7},
		{MethodName: "medium2", FilePath: "d.smali", RiskLevel: RiskClassMedium, Confidence: 0.6},
		{MethodName: "low1", FilePath: "e.smali", RiskLevel: RiskClassLow, Confidence: 0.4},
	}

	result := exporter.ExportToString(patches, points)

	// Verify confidence distribution
	if !strings.Contains(result, "### Confidence Distribution") {
		t.Error("Missing confidence distribution section")
	}

	if !strings.Contains(result, "**High (≥0.8):** 2") {
		t.Error("Incorrect high confidence count")
	}

	if !strings.Contains(result, "**Medium (0.5-0.8):** 2") {
		t.Error("Incorrect medium confidence count")
	}

	if !strings.Contains(result, "**Low (<0.5):** 1") {
		t.Error("Incorrect low confidence count")
	}

	// Verify average confidence (0.9 + 0.85 + 0.7 + 0.6 + 0.4) / 5 = 0.69
	if !strings.Contains(result, "**Average Confidence:** 0.69") {
		t.Error("Incorrect average confidence")
	}
}

func TestMarkdownExporter_EmptyPatches(t *testing.T) {
	exporter := NewMarkdownExporter()

	result := exporter.ExportToString([]*GeneratedPatch{}, []PatchPoint{})

	// Should still have header and summary
	if !strings.Contains(result, "# ML Patcher Report") {
		t.Error("Missing header for empty report")
	}

	if !strings.Contains(result, "## Summary") {
		t.Error("Missing summary for empty report")
	}

	if !strings.Contains(result, "**Total Patches:** 0") {
		t.Error("Incorrect total for empty report")
	}
}

func TestMarkdownExporter_ExplanationFields(t *testing.T) {
	exporter := NewMarkdownExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "checkLicense",
			FilePath:   "license.smali",
			Confidence: 0.8,
			Explanation: PatchExplanation{
				Reason:       "License validation check detected",
				WhatItDoes:   "Verifies premium license status",
				WhyThisPatch: "Bypass license check for testing",
				Impact:       "Premium features will be accessible",
				Signals:      []string{"name:checkLicense", "api:getLicenseStatus", "string:premium"},
			},
		},
	}

	points := []PatchPoint{
		{
			MethodName: "checkLicense",
			FilePath:   "license.smali",
			RiskLevel:  RiskClassHigh,
			Confidence: 0.8,
		},
	}

	result := exporter.ExportToString(patches, points)

	// Verify all explanation fields
	if !strings.Contains(result, "**Why Vulnerable:** License validation check detected") {
		t.Error("Missing reason field")
	}

	if !strings.Contains(result, "**Original Behavior:** Verifies premium license status") {
		t.Error("Missing what_it_does field")
	}

	if !strings.Contains(result, "**Patch Strategy:** Bypass license check for testing") {
		t.Error("Missing why_this_patch field")
	}

	if !strings.Contains(result, "**Expected Impact:** Premium features will be accessible") {
		t.Error("Missing impact field")
	}

	// Verify signals
	if !strings.Contains(result, "**Matched Signals:**") {
		t.Error("Missing signals section")
	}

	if !strings.Contains(result, "name:checkLicense") {
		t.Error("Missing signal: name:checkLicense")
	}

	if !strings.Contains(result, "api:getLicenseStatus") {
		t.Error("Missing signal: api:getLicenseStatus")
	}

	if !strings.Contains(result, "string:premium") {
		t.Error("Missing signal: string:premium")
	}
}

func TestMarkdownExporter_SignalContributions(t *testing.T) {
	exporter := NewMarkdownExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "isDebugMode",
			FilePath:   "debug.smali",
			Confidence: 0.87,
			ConfidenceBreakdown: &ConfidenceBreakdown{
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
			},
		},
	}

	points := []PatchPoint{
		{
			MethodName: "isDebugMode",
			FilePath:   "debug.smali",
			RiskLevel:  RiskClassMedium,
			Confidence: 0.87,
		},
	}

	result := exporter.ExportToString(patches, points)

	// Verify confidence breakdown
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
	if !strings.Contains(result, "name: 0.85 (weight: 1.00, confidence: 0.85)") {
		t.Error("Missing name signal contribution")
	}

	if !strings.Contains(result, "api: 0.99 (weight: 1.10, confidence: 0.90)") {
		t.Error("Missing api signal contribution")
	}
}

func TestMarkdownExporter_CategoryInformation(t *testing.T) {
	exporter := NewMarkdownExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "isEmulator",
			FilePath:   "emulator.smali",
			Confidence: 0.82,
		},
	}

	points := []PatchPoint{
		{
			MethodName:   "isEmulator",
			FilePath:     "emulator.smali",
			RiskLevel:    RiskClassHigh,
			Confidence:   0.82,
			Category:     PatchCatEmulatorCheck,
			CategoryName: "Emulator Detection",
		},
	}

	result := exporter.ExportToString(patches, points)

	// Verify category is displayed
	if !strings.Contains(result, "**Category:** Emulator Detection") {
		t.Error("Missing category information")
	}
}

func TestMarkdownExporter_NoExplanation(t *testing.T) {
	exporter := NewMarkdownExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:  "someMethod",
			FilePath:    "test.smali",
			Confidence:  0.5,
			Explanation: PatchExplanation{}, // Empty explanation
		},
	}

	points := []PatchPoint{
		{
			MethodName: "someMethod",
			FilePath:   "test.smali",
			RiskLevel:  RiskClassLow,
			Confidence: 0.5,
		},
	}

	result := exporter.ExportToString(patches, points)

	// Should not have explanation section if empty
	if strings.Contains(result, "**Explanation:**") {
		t.Error("Should not show empty explanation section")
	}
}
