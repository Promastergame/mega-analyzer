package ml

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNewJSONExporter tests exporter creation
func TestNewJSONExporter(t *testing.T) {
	exporter := NewJSONExporter()

	if exporter == nil {
		t.Fatal("NewJSONExporter returned nil")
	}

	if exporter.version == "" {
		t.Error("exporter version is empty")
	}
}

// TestExportToString tests string export
func TestExportToString(t *testing.T) {
	exporter := NewJSONExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:   "isLicensed",
			FilePath:     "com/example/License.smali",
			PatchType:    PatchReturnTrue,
			Description:  "Return true for license check",
			OriginalCode: ".method public isLicensed()Z\n    const/4 v0, 0x0\n    return v0\n.end method",
			PatchedCode:  ".method public isLicensed()Z\n    .registers 1\n\n    const/4 v0, 0x1\n    return v0\n.end method",
			DiffView:     "--- original\n+++ patched",
			Mode:         PatchModeResearch,
			Confidence:   0.85,
			Explanation: PatchExplanation{
				Reason:       "Method name matches license check pattern",
				WhatItDoes:   "Returns false, denying license",
				WhyThisPatch: "Return true to bypass license check",
				Impact:       "App will think it's licensed",
				Signals:      []string{"name_match", "return_type"},
			},
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/License.smali",
			ClassName:       "License",
			MethodName:      "isLicensed",
			MethodSignature: "()Z",
			RiskScore:       85.0,
			RiskLevel:       RiskClassHigh,
			Confidence:      0.85,
			Category:        PatchCatLicense,
			CategoryName:    "License Check",
			SuggestedPatch:  PatchReturnTrue,
			PatchDesc:       "Return true",
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	if result == "" {
		t.Fatal("ExportToString returned empty string")
	}

	// Verify it's valid JSON
	var export JSONExport
	if err := json.Unmarshal([]byte(result), &export); err != nil {
		t.Fatalf("Result is not valid JSON: %v", err)
	}

	// Verify metadata
	if export.Version == "" {
		t.Error("Version is empty")
	}

	if export.Timestamp.IsZero() {
		t.Error("Timestamp is zero")
	}

	if export.Generator != "ML Patcher" {
		t.Errorf("Generator = %q, want %q", export.Generator, "ML Patcher")
	}

	// Verify patches
	if len(export.Patches) != 1 {
		t.Fatalf("Patches count = %d, want 1", len(export.Patches))
	}

	patch := export.Patches[0]

	if patch.MethodName != "isLicensed" {
		t.Errorf("MethodName = %q, want %q", patch.MethodName, "isLicensed")
	}

	if patch.Mode != PatchModeResearch {
		t.Errorf("Mode = %q, want %q", patch.Mode, PatchModeResearch)
	}

	if patch.Confidence != 0.85 {
		t.Errorf("Confidence = %f, want 0.85", patch.Confidence)
	}

	// Verify explanation
	if patch.Explanation.Reason == "" {
		t.Error("Explanation.Reason is empty")
	}

	if patch.Explanation.WhatItDoes == "" {
		t.Error("Explanation.WhatItDoes is empty")
	}

	if patch.Explanation.WhyThisPatch == "" {
		t.Error("Explanation.WhyThisPatch is empty")
	}

	if patch.Explanation.Impact == "" {
		t.Error("Explanation.Impact is empty")
	}

	// Verify summary
	if export.Summary.TotalPatches != 1 {
		t.Errorf("Summary.TotalPatches = %d, want 1", export.Summary.TotalPatches)
	}

	if export.Summary.HighConfidence != 1 {
		t.Errorf("Summary.HighConfidence = %d, want 1", export.Summary.HighConfidence)
	}
}

// TestExportToFile tests file export
func TestExportToFile(t *testing.T) {
	exporter := NewJSONExporter()

	// Create temp directory
	tmpDir := testTempDir(t)
	filepath := filepath.Join(tmpDir, "export.json")

	patches := []*GeneratedPatch{
		{
			MethodName:  "isPremium",
			FilePath:    "com/example/Premium.smali",
			PatchType:   PatchReturnTrue,
			Description: "Return true for premium check",
			Mode:        PatchModeResearch,
			Confidence:  0.75,
			Explanation: PatchExplanation{
				Reason:       "Premium check detected",
				WhatItDoes:   "Checks premium status",
				WhyThisPatch: "Bypass premium check",
				Impact:       "Grant premium access",
			},
		},
	}

	points := []PatchPoint{
		{
			FilePath:       "com/example/Premium.smali",
			ClassName:      "Premium",
			MethodName:     "isPremium",
			RiskScore:      75.0,
			RiskLevel:      RiskClassMedium,
			Confidence:     0.75,
			Category:       PatchCatPremium,
			CategoryName:   "Premium Check",
			SuggestedPatch: PatchReturnTrue,
		},
	}

	err := exporter.ExportToFile(patches, points, filepath)
	if err != nil {
		t.Fatalf("ExportToFile failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		t.Fatal("Export file was not created")
	}

	// Read and verify content
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read export file: %v", err)
	}

	var export JSONExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("Export file is not valid JSON: %v", err)
	}

	if len(export.Patches) != 1 {
		t.Errorf("Patches count = %d, want 1", len(export.Patches))
	}
}

// TestExportMultiplePatches tests exporting multiple patches
func TestExportMultiplePatches(t *testing.T) {
	exporter := NewJSONExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "isLicensed",
			FilePath:   "com/example/License.smali",
			PatchType:  PatchReturnTrue,
			Mode:       PatchModeResearch,
			Confidence: 0.9,
			Explanation: PatchExplanation{
				Reason:       "License check",
				WhatItDoes:   "Checks license",
				WhyThisPatch: "Bypass",
				Impact:       "Grant access",
			},
		},
		{
			MethodName: "isPremium",
			FilePath:   "com/example/Premium.smali",
			PatchType:  PatchReturnTrue,
			Mode:       PatchModeResearch,
			Confidence: 0.7,
			Explanation: PatchExplanation{
				Reason:       "Premium check",
				WhatItDoes:   "Checks premium",
				WhyThisPatch: "Bypass",
				Impact:       "Grant premium",
			},
		},
		{
			MethodName: "isRooted",
			FilePath:   "com/example/Root.smali",
			PatchType:  PatchReturnFalse,
			Mode:       PatchModeResearch,
			Confidence: 0.4,
			Explanation: PatchExplanation{
				Reason:       "Root detection",
				WhatItDoes:   "Detects root",
				WhyThisPatch: "Hide root",
				Impact:       "Bypass root check",
			},
		},
	}

	points := []PatchPoint{
		{
			FilePath:       "com/example/License.smali",
			MethodName:     "isLicensed",
			RiskScore:      90.0,
			RiskLevel:      RiskClassHigh,
			Confidence:     0.9,
			Category:       PatchCatLicense,
			SuggestedPatch: PatchReturnTrue,
		},
		{
			FilePath:       "com/example/Premium.smali",
			MethodName:     "isPremium",
			RiskScore:      70.0,
			RiskLevel:      RiskClassMedium,
			Confidence:     0.7,
			Category:       PatchCatPremium,
			SuggestedPatch: PatchReturnTrue,
		},
		{
			FilePath:       "com/example/Root.smali",
			MethodName:     "isRooted",
			RiskScore:      40.0,
			RiskLevel:      RiskClassLow,
			Confidence:     0.4,
			Category:       PatchCatRootDetect,
			SuggestedPatch: PatchReturnFalse,
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	var export JSONExport
	if err := json.Unmarshal([]byte(result), &export); err != nil {
		t.Fatalf("Result is not valid JSON: %v", err)
	}

	// Verify patch count
	if len(export.Patches) != 3 {
		t.Fatalf("Patches count = %d, want 3", len(export.Patches))
	}

	// Verify summary
	if export.Summary.TotalPatches != 3 {
		t.Errorf("Summary.TotalPatches = %d, want 3", export.Summary.TotalPatches)
	}

	if export.Summary.HighConfidence != 1 {
		t.Errorf("Summary.HighConfidence = %d, want 1", export.Summary.HighConfidence)
	}

	if export.Summary.MediumConfidence != 1 {
		t.Errorf("Summary.MediumConfidence = %d, want 1", export.Summary.MediumConfidence)
	}

	if export.Summary.LowConfidence != 1 {
		t.Errorf("Summary.LowConfidence = %d, want 1", export.Summary.LowConfidence)
	}

	// Verify average confidence
	expectedAvg := (0.9 + 0.7 + 0.4) / 3.0
	if export.Summary.AvgConfidence != expectedAvg {
		t.Errorf("Summary.AvgConfidence = %f, want %f",
			export.Summary.AvgConfidence, expectedAvg)
	}

	// Verify risk level counts
	if export.Summary.ByRiskLevel[string(RiskClassHigh)] != 1 {
		t.Errorf("ByRiskLevel[high] = %d, want 1",
			export.Summary.ByRiskLevel[string(RiskClassHigh)])
	}

	if export.Summary.ByRiskLevel[string(RiskClassMedium)] != 1 {
		t.Errorf("ByRiskLevel[medium] = %d, want 1",
			export.Summary.ByRiskLevel[string(RiskClassMedium)])
	}

	if export.Summary.ByRiskLevel[string(RiskClassLow)] != 1 {
		t.Errorf("ByRiskLevel[low] = %d, want 1",
			export.Summary.ByRiskLevel[string(RiskClassLow)])
	}
}

// TestExportWithConfidenceBreakdown tests exporting with confidence breakdown
func TestExportWithConfidenceBreakdown(t *testing.T) {
	exporter := NewJSONExporter()

	breakdown := &ConfidenceBreakdown{
		BaseConfidence:    0.7,
		MultiSignalBonus:  0.08,
		ObfuscationAdjust: 0.02,
		FinalConfidence:   0.8,
		SignalContributions: []SignalContribution{
			{
				SignalType:   "name",
				Value:        "isLicensed",
				Weight:       1.0,
				Confidence:   0.8,
				Contribution: 0.8,
			},
			{
				SignalType:   "structure",
				Value:        "boolean_return",
				Weight:       0.9,
				Confidence:   0.7,
				Contribution: 0.63,
			},
		},
	}

	patches := []*GeneratedPatch{
		{
			MethodName:          "isLicensed",
			FilePath:            "com/example/License.smali",
			PatchType:           PatchReturnTrue,
			Mode:                PatchModeResearch,
			Confidence:          0.8,
			ConfidenceBreakdown: breakdown,
			Explanation: PatchExplanation{
				Reason:       "License check",
				WhatItDoes:   "Checks license",
				WhyThisPatch: "Bypass",
				Impact:       "Grant access",
			},
		},
	}

	points := []PatchPoint{
		{
			FilePath:       "com/example/License.smali",
			MethodName:     "isLicensed",
			RiskScore:      80.0,
			RiskLevel:      RiskClassHigh,
			Confidence:     0.8,
			Category:       PatchCatLicense,
			SuggestedPatch: PatchReturnTrue,
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	var export JSONExport
	if err := json.Unmarshal([]byte(result), &export); err != nil {
		t.Fatalf("Result is not valid JSON: %v", err)
	}

	patch := export.Patches[0]

	if patch.ConfidenceBreakdown == nil {
		t.Fatal("ConfidenceBreakdown is nil")
	}

	if patch.ConfidenceBreakdown.BaseConfidence != 0.7 {
		t.Errorf("BaseConfidence = %f, want 0.7",
			patch.ConfidenceBreakdown.BaseConfidence)
	}

	if patch.ConfidenceBreakdown.FinalConfidence != 0.8 {
		t.Errorf("FinalConfidence = %f, want 0.8",
			patch.ConfidenceBreakdown.FinalConfidence)
	}

	if len(patch.ConfidenceBreakdown.SignalContributions) != 2 {
		t.Errorf("SignalContributions count = %d, want 2",
			len(patch.ConfidenceBreakdown.SignalContributions))
	}
}

// TestValidation tests validation logic
func TestValidation(t *testing.T) {
	exporter := NewJSONExporter()

	tests := []struct {
		name    string
		patches []*GeneratedPatch
		points  []PatchPoint
		wantErr bool
		errMsg  string
	}{
		{
			name:    "empty patches",
			patches: []*GeneratedPatch{},
			points:  []PatchPoint{},
			wantErr: false,
		},
		{
			name: "invalid confidence",
			patches: []*GeneratedPatch{
				{
					MethodName: "test",
					FilePath:   "test.smali",
					PatchType:  PatchReturnTrue,
					Confidence: 1.5, // Invalid
					Explanation: PatchExplanation{
						Reason:       "test",
						WhatItDoes:   "test",
						WhyThisPatch: "test",
						Impact:       "test",
					},
				},
			},
			points: []PatchPoint{
				{
					FilePath:       "test.smali",
					MethodName:     "test",
					RiskScore:      50.0,
					RiskLevel:      RiskClassMedium,
					Confidence:     1.5,
					SuggestedPatch: PatchReturnTrue,
				},
			},
			wantErr: true,
			errMsg:  "confidence",
		},
		{
			name: "invalid risk score",
			patches: []*GeneratedPatch{
				{
					MethodName: "test",
					FilePath:   "test.smali",
					PatchType:  PatchReturnTrue,
					Confidence: 0.8,
					Explanation: PatchExplanation{
						Reason:       "test",
						WhatItDoes:   "test",
						WhyThisPatch: "test",
						Impact:       "test",
					},
				},
			},
			points: []PatchPoint{
				{
					FilePath:       "test.smali",
					MethodName:     "test",
					RiskScore:      150.0, // Invalid
					RiskLevel:      RiskClassHigh,
					Confidence:     0.8,
					SuggestedPatch: PatchReturnTrue,
				},
			},
			wantErr: true,
			errMsg:  "risk_score",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := exporter.ExportToString(tt.patches, tt.points)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Error message %q does not contain %q",
						err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestTimestampMetadata tests timestamp is included and recent
func TestTimestampMetadata(t *testing.T) {
	exporter := NewJSONExporter()

	before := time.Now().UTC()

	result, err := exporter.ExportToString([]*GeneratedPatch{}, []PatchPoint{})
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	after := time.Now().UTC()

	var export JSONExport
	if err := json.Unmarshal([]byte(result), &export); err != nil {
		t.Fatalf("Result is not valid JSON: %v", err)
	}

	// Verify timestamp is between before and after
	if export.Timestamp.Before(before) || export.Timestamp.After(after) {
		t.Errorf("Timestamp %v is not between %v and %v",
			export.Timestamp, before, after)
	}
}

// TestVersionMetadata tests version is included
func TestVersionMetadata(t *testing.T) {
	exporter := NewJSONExporter()

	result, err := exporter.ExportToString([]*GeneratedPatch{}, []PatchPoint{})
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	var export JSONExport
	if err := json.Unmarshal([]byte(result), &export); err != nil {
		t.Fatalf("Result is not valid JSON: %v", err)
	}

	if export.Version == "" {
		t.Error("Version is empty")
	}

	// Version should be in semver format
	parts := strings.Split(export.Version, ".")
	if len(parts) != 3 {
		t.Errorf("Version %q is not in semver format (x.y.z)", export.Version)
	}
}

// TestDiffViewIncluded tests diff view is included in export
func TestDiffViewIncluded(t *testing.T) {
	exporter := NewJSONExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:   "test",
			FilePath:     "test.smali",
			PatchType:    PatchReturnTrue,
			Mode:         PatchModeDefensive,
			OriginalCode: "original",
			PatchedCode:  "patched",
			DiffView:     "--- original\n+++ patched\n-original\n+patched",
			Confidence:   0.8,
			Explanation: PatchExplanation{
				Reason:       "test",
				WhatItDoes:   "test",
				WhyThisPatch: "test",
				Impact:       "test",
			},
		},
	}

	points := []PatchPoint{
		{
			FilePath:       "test.smali",
			MethodName:     "test",
			RiskScore:      50.0,
			RiskLevel:      RiskClassMedium,
			Confidence:     0.8,
			SuggestedPatch: PatchReturnTrue,
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	var export JSONExport
	if err := json.Unmarshal([]byte(result), &export); err != nil {
		t.Fatalf("Result is not valid JSON: %v", err)
	}

	patch := export.Patches[0]

	if patch.DiffView == "" {
		t.Error("DiffView is empty")
	}

	if !strings.Contains(patch.DiffView, "---") {
		t.Error("DiffView does not contain diff markers")
	}
}
