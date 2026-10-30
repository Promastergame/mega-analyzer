package ml

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestJSONExporter_ExportToStringWithThreshold tests JSON export with confidence filtering
func TestJSONExporter_ExportToStringWithThreshold(t *testing.T) {
	exporter := NewJSONExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:  "isRooted",
			FilePath:    "com/example/Root.smali",
			PatchType:   PatchReturnFalse,
			Description: "Bypass root detection",
			Mode:        PatchModeResearch,
			Confidence:  0.95,
		},
		{
			MethodName:  "isLicensed",
			FilePath:    "com/example/License.smali",
			PatchType:   PatchReturnTrue,
			Description: "Bypass license check",
			Mode:        PatchModeResearch,
			Confidence:  0.75,
		},
		{
			MethodName:  "isDebugger",
			FilePath:    "com/example/Debug.smali",
			PatchType:   PatchReturnFalse,
			Description: "Bypass debugger detection",
			Mode:        PatchModeResearch,
			Confidence:  0.45,
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Root.smali",
			ClassName:       "Root",
			MethodName:      "isRooted",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.95,
			RiskScore:       90.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatRootDetect,
		},
		{
			FilePath:        "com/example/License.smali",
			ClassName:       "License",
			MethodName:      "isLicensed",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.75,
			RiskScore:       70.0,
			RiskLevel:       RiskClassMedium,
			Category:        PatchCatLicense,
		},
		{
			FilePath:        "com/example/Debug.smali",
			ClassName:       "Debug",
			MethodName:      "isDebugger",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.45,
			RiskScore:       40.0,
			RiskLevel:       RiskClassLow,
			Category:        PatchCatDebugDetect,
		},
	}

	// Test with threshold 0.7 - should include only first two patches
	result, err := exporter.ExportToStringWithThreshold(patches, points, 0.7)
	if err != nil {
		t.Fatalf("ExportToStringWithThreshold failed: %v", err)
	}

	var export JSONExport
	if err := json.Unmarshal([]byte(result), &export); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Verify only 2 patches included
	if len(export.Patches) != 2 {
		t.Errorf("Expected 2 patches, got %d", len(export.Patches))
	}

	// Verify correct patches included
	if export.Patches[0].MethodName != "isRooted" {
		t.Errorf("Expected first patch to be isRooted, got %s", export.Patches[0].MethodName)
	}
	if export.Patches[1].MethodName != "isLicensed" {
		t.Errorf("Expected second patch to be isLicensed, got %s", export.Patches[1].MethodName)
	}

	// Verify summary reflects filtered count
	if export.Summary.TotalPatches != 2 {
		t.Errorf("Expected summary total 2, got %d", export.Summary.TotalPatches)
	}
}

// TestJSONExporter_ExportToFileWithThreshold tests JSON file export with confidence filtering
func TestJSONExporter_ExportToFileWithThreshold(t *testing.T) {
	exporter := NewJSONExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "isRooted",
			FilePath:   "com/example/Root.smali",
			PatchType:  PatchReturnFalse,
			Mode:       PatchModeDefensive,
			Confidence: 0.85,
		},
		{
			MethodName: "isDebugger",
			FilePath:   "com/example/Debug.smali",
			PatchType:  PatchReturnFalse,
			Mode:       PatchModeDefensive,
			Confidence: 0.40,
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Root.smali",
			MethodName:      "isRooted",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.85,
			RiskScore:       85.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatRootDetect,
		},
		{
			FilePath:        "com/example/Debug.smali",
			MethodName:      "isDebugger",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.40,
			RiskScore:       40.0,
			RiskLevel:       RiskClassLow,
			Category:        PatchCatDebugDetect,
		},
	}

	// Create temp file
	tmpDir := testTempDir(t)
	filepath := filepath.Join(tmpDir, "filtered.json")

	// Export with threshold 0.5
	if err := exporter.ExportToFileWithThreshold(patches, points, filepath, 0.5); err != nil {
		t.Fatalf("ExportToFileWithThreshold failed: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	var export JSONExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Should only include high-confidence patch
	if len(export.Patches) != 1 {
		t.Errorf("Expected 1 patch, got %d", len(export.Patches))
	}

	if export.Patches[0].MethodName != "isRooted" {
		t.Errorf("Expected isRooted, got %s", export.Patches[0].MethodName)
	}
}

// TestMarkdownExporter_ExportToStringWithThreshold tests Markdown export with confidence filtering
func TestMarkdownExporter_ExportToStringWithThreshold(t *testing.T) {
	exporter := NewMarkdownExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "isRooted",
			FilePath:   "com/example/Root.smali",
			PatchType:  PatchReturnFalse,
			Confidence: 0.90,
		},
		{
			MethodName: "isLicensed",
			FilePath:   "com/example/License.smali",
			PatchType:  PatchReturnTrue,
			Confidence: 0.60,
		},
		{
			MethodName: "isDebugger",
			FilePath:   "com/example/Debug.smali",
			PatchType:  PatchReturnFalse,
			Confidence: 0.35,
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Root.smali",
			MethodName:      "isRooted",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.90,
			RiskScore:       90.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatRootDetect,
		},
		{
			FilePath:        "com/example/License.smali",
			MethodName:      "isLicensed",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.60,
			RiskScore:       60.0,
			RiskLevel:       RiskClassMedium,
			Category:        PatchCatLicense,
		},
		{
			FilePath:        "com/example/Debug.smali",
			MethodName:      "isDebugger",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.35,
			RiskScore:       35.0,
			RiskLevel:       RiskClassLow,
			Category:        PatchCatDebugDetect,
		},
	}

	// Test with threshold 0.5 - should include first two patches
	result := exporter.ExportToStringWithThreshold(patches, points, 0.5)

	// Verify markdown contains expected patches
	if !strings.Contains(result, "isRooted") {
		t.Error("Expected isRooted in output")
	}
	if !strings.Contains(result, "isLicensed") {
		t.Error("Expected isLicensed in output")
	}
	if strings.Contains(result, "isDebugger") {
		t.Error("Did not expect isDebugger in output")
	}

	// Verify total patches count in summary
	if !strings.Contains(result, "**Total Patches:** 2") {
		t.Error("Expected total patches to be 2")
	}
}

// TestMarkdownExporter_ExportToFileWithThreshold tests Markdown file export with confidence filtering
func TestMarkdownExporter_ExportToFileWithThreshold(t *testing.T) {
	exporter := NewMarkdownExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "isRooted",
			FilePath:   "com/example/Root.smali",
			PatchType:  PatchReturnFalse,
			Confidence: 0.95,
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Root.smali",
			MethodName:      "isRooted",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.95,
			RiskScore:       95.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatRootDetect,
		},
	}

	// Create temp file
	tmpDir := testTempDir(t)
	filepath := filepath.Join(tmpDir, "filtered.md")

	// Export with threshold 0.9
	if err := exporter.ExportToFileWithThreshold(patches, points, filepath, 0.9); err != nil {
		t.Fatalf("ExportToFileWithThreshold failed: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "isRooted") {
		t.Error("Expected isRooted in output")
	}
}

// TestCSVExporter_ExportToStringWithThreshold tests CSV export with confidence filtering
func TestCSVExporter_ExportToStringWithThreshold(t *testing.T) {
	exporter := NewCSVExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "isRooted",
			FilePath:   "com/example/Root.smali",
			PatchType:  PatchReturnFalse,
			Confidence: 0.88,
		},
		{
			MethodName: "isLicensed",
			FilePath:   "com/example/License.smali",
			PatchType:  PatchReturnTrue,
			Confidence: 0.55,
		},
		{
			MethodName: "isDebugger",
			FilePath:   "com/example/Debug.smali",
			PatchType:  PatchReturnFalse,
			Confidence: 0.42,
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Root.smali",
			MethodName:      "isRooted",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.88,
			RiskScore:       88.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatRootDetect,
		},
		{
			FilePath:        "com/example/License.smali",
			MethodName:      "isLicensed",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.55,
			RiskScore:       55.0,
			RiskLevel:       RiskClassMedium,
			Category:        PatchCatLicense,
		},
		{
			FilePath:        "com/example/Debug.smali",
			MethodName:      "isDebugger",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.42,
			RiskScore:       42.0,
			RiskLevel:       RiskClassLow,
			Category:        PatchCatDebugDetect,
		},
	}

	// Test with threshold 0.5 - should include first two patches
	result, err := exporter.ExportToStringWithThreshold(patches, points, 0.5)
	if err != nil {
		t.Fatalf("ExportToStringWithThreshold failed: %v", err)
	}

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(result))
	reader.Comment = '#'

	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	// Should have header + 2 data rows
	if len(records) != 3 {
		t.Errorf("Expected 3 records (header + 2 data), got %d", len(records))
	}

	// Verify correct patches included
	if records[1][2] != "isRooted" {
		t.Errorf("Expected first data row to be isRooted, got %s", records[1][2])
	}
	if records[2][2] != "isLicensed" {
		t.Errorf("Expected second data row to be isLicensed, got %s", records[2][2])
	}

	// Verify total patches count in header
	if !strings.Contains(result, "# Total Patches: 2") {
		t.Error("Expected total patches to be 2 in header")
	}
}

// TestCSVExporter_ExportToFileWithThreshold tests CSV file export with confidence filtering
func TestCSVExporter_ExportToFileWithThreshold(t *testing.T) {
	exporter := NewCSVExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "isRooted",
			FilePath:   "com/example/Root.smali",
			PatchType:  PatchReturnFalse,
			Confidence: 0.92,
		},
		{
			MethodName: "isDebugger",
			FilePath:   "com/example/Debug.smali",
			PatchType:  PatchReturnFalse,
			Confidence: 0.38,
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Root.smali",
			MethodName:      "isRooted",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.92,
			RiskScore:       92.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatRootDetect,
		},
		{
			FilePath:        "com/example/Debug.smali",
			MethodName:      "isDebugger",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.38,
			RiskScore:       38.0,
			RiskLevel:       RiskClassLow,
			Category:        PatchCatDebugDetect,
		},
	}

	// Create temp file
	tmpDir := testTempDir(t)
	filepath := filepath.Join(tmpDir, "filtered.csv")

	// Export with threshold 0.9
	if err := exporter.ExportToFileWithThreshold(patches, points, filepath, 0.9); err != nil {
		t.Fatalf("ExportToFileWithThreshold failed: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(filepath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	content := string(data)

	// Parse CSV
	reader := csv.NewReader(strings.NewReader(content))
	reader.Comment = '#'

	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	// Should have header + 1 data row
	if len(records) != 2 {
		t.Errorf("Expected 2 records (header + 1 data), got %d", len(records))
	}

	if records[1][2] != "isRooted" {
		t.Errorf("Expected isRooted, got %s", records[1][2])
	}
}

// TestThresholdEdgeCases tests edge cases for threshold filtering
func TestThresholdEdgeCases(t *testing.T) {
	jsonExporter := NewJSONExporter()
	mdExporter := NewMarkdownExporter()
	csvExporter := NewCSVExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "method1",
			FilePath:   "com/example/Test.smali",
			PatchType:  PatchReturnTrue,
			Confidence: 0.50,
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Test.smali",
			MethodName:      "method1",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.50,
			RiskScore:       50.0,
			RiskLevel:       RiskClassMedium,
			Category:        PatchCatLicense,
		},
	}

	// Test threshold 0.0 - should include all
	t.Run("Threshold_0.0", func(t *testing.T) {
		result, err := jsonExporter.ExportToStringWithThreshold(patches, points, 0.0)
		if err != nil {
			t.Fatalf("Failed: %v", err)
		}
		var export JSONExport
		json.Unmarshal([]byte(result), &export)
		if len(export.Patches) != 1 {
			t.Errorf("Expected 1 patch with threshold 0.0, got %d", len(export.Patches))
		}
	})

	// Test threshold 0.5 - should include (confidence == threshold)
	t.Run("Threshold_0.5_Equal", func(t *testing.T) {
		result, err := jsonExporter.ExportToStringWithThreshold(patches, points, 0.5)
		if err != nil {
			t.Fatalf("Failed: %v", err)
		}
		var export JSONExport
		json.Unmarshal([]byte(result), &export)
		if len(export.Patches) != 1 {
			t.Errorf("Expected 1 patch with threshold 0.5 (equal), got %d", len(export.Patches))
		}
	})

	// Test threshold 1.0 - should exclude (confidence < threshold)
	t.Run("Threshold_1.0", func(t *testing.T) {
		result, err := jsonExporter.ExportToStringWithThreshold(patches, points, 1.0)
		if err != nil {
			t.Fatalf("Failed: %v", err)
		}
		var export JSONExport
		json.Unmarshal([]byte(result), &export)
		if len(export.Patches) != 0 {
			t.Errorf("Expected 0 patches with threshold 1.0, got %d", len(export.Patches))
		}
	})

	// Test threshold 1.5 (above max) - should exclude all
	t.Run("Threshold_1.5", func(t *testing.T) {
		result, err := jsonExporter.ExportToStringWithThreshold(patches, points, 1.5)
		if err != nil {
			t.Fatalf("Failed: %v", err)
		}
		var export JSONExport
		json.Unmarshal([]byte(result), &export)
		if len(export.Patches) != 0 {
			t.Errorf("Expected 0 patches with threshold 1.5, got %d", len(export.Patches))
		}
	})

	// Test Markdown exporter with various thresholds
	t.Run("Markdown_Threshold_0.7", func(t *testing.T) {
		result := mdExporter.ExportToStringWithThreshold(patches, points, 0.7)
		if !strings.Contains(result, "**Total Patches:** 0") {
			t.Error("Expected 0 patches with threshold 0.7")
		}
	})

	// Test CSV exporter with various thresholds
	t.Run("CSV_Threshold_0.5", func(t *testing.T) {
		result, err := csvExporter.ExportToStringWithThreshold(patches, points, 0.5)
		if err != nil {
			t.Fatalf("Failed: %v", err)
		}
		reader := csv.NewReader(strings.NewReader(result))
		reader.Comment = '#'
		records, _ := reader.ReadAll()
		// Header + 1 data row
		if len(records) != 2 {
			t.Errorf("Expected 2 records with threshold 0.5, got %d", len(records))
		}
	})
}

// TestMultipleThresholds tests filtering with various threshold values
func TestMultipleThresholds(t *testing.T) {
	exporter := NewJSONExporter()

	patches := []*GeneratedPatch{
		{MethodName: "m1", FilePath: "f1.smali", PatchType: PatchReturnTrue, Mode: PatchModeDefensive, Confidence: 0.95},
		{MethodName: "m2", FilePath: "f2.smali", PatchType: PatchReturnTrue, Mode: PatchModeDefensive, Confidence: 0.85},
		{MethodName: "m3", FilePath: "f3.smali", PatchType: PatchReturnTrue, Mode: PatchModeDefensive, Confidence: 0.75},
		{MethodName: "m4", FilePath: "f4.smali", PatchType: PatchReturnTrue, Mode: PatchModeDefensive, Confidence: 0.65},
		{MethodName: "m5", FilePath: "f5.smali", PatchType: PatchReturnTrue, Mode: PatchModeDefensive, Confidence: 0.55},
	}

	points := []PatchPoint{
		{FilePath: "f1.smali", MethodName: "m1", MethodSignature: "()Z", SuggestedPatch: PatchReturnTrue, Confidence: 0.95, RiskScore: 95.0, RiskLevel: RiskClassHigh, Category: PatchCatLicense},
		{FilePath: "f2.smali", MethodName: "m2", MethodSignature: "()Z", SuggestedPatch: PatchReturnTrue, Confidence: 0.85, RiskScore: 85.0, RiskLevel: RiskClassHigh, Category: PatchCatLicense},
		{FilePath: "f3.smali", MethodName: "m3", MethodSignature: "()Z", SuggestedPatch: PatchReturnTrue, Confidence: 0.75, RiskScore: 75.0, RiskLevel: RiskClassMedium, Category: PatchCatLicense},
		{FilePath: "f4.smali", MethodName: "m4", MethodSignature: "()Z", SuggestedPatch: PatchReturnTrue, Confidence: 0.65, RiskScore: 65.0, RiskLevel: RiskClassMedium, Category: PatchCatLicense},
		{FilePath: "f5.smali", MethodName: "m5", MethodSignature: "()Z", SuggestedPatch: PatchReturnTrue, Confidence: 0.55, RiskScore: 55.0, RiskLevel: RiskClassMedium, Category: PatchCatLicense},
	}

	testCases := []struct {
		threshold     float64
		expectedCount int
	}{
		{0.5, 5},
		{0.7, 3},
		{0.9, 1},
	}

	for _, tc := range testCases {
		t.Run(string(rune(tc.threshold*100)), func(t *testing.T) {
			result, err := exporter.ExportToStringWithThreshold(patches, points, tc.threshold)
			if err != nil {
				t.Fatalf("Failed with threshold %.2f: %v", tc.threshold, err)
			}

			var export JSONExport
			if err := json.Unmarshal([]byte(result), &export); err != nil {
				t.Fatalf("Failed to parse JSON: %v", err)
			}

			if len(export.Patches) != tc.expectedCount {
				t.Errorf("Threshold %.2f: expected %d patches, got %d",
					tc.threshold, tc.expectedCount, len(export.Patches))
			}

			// Verify all included patches meet threshold
			for _, patch := range export.Patches {
				if patch.Confidence < tc.threshold {
					t.Errorf("Patch %s has confidence %.2f below threshold %.2f",
						patch.MethodName, patch.Confidence, tc.threshold)
				}
			}
		})
	}
}
