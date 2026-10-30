package ml

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION TESTS FOR EXPORT FORMATS
//
// These tests verify that exported formats are valid and can be parsed by
// standard parsers (JSON parser, Markdown renderer, CSV parser).
//
// Requirements: 11.1, 11.2, 11.3
// Task: 7.9 Write integration tests for export formats
// ═══════════════════════════════════════════════════════════════════════════════

// TestJSONExporter_FormatValidity tests JSON export validity with standard parser
// Validates: Requirements 11.1
func TestJSONExporter_FormatValidity(t *testing.T) {
	// Create sample patches with complete metadata
	patches, points := createSamplePatchesForExport()

	// Create exporter
	exporter := NewJSONExporter()

	// Export to string
	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Verify JSON is valid by parsing with standard parser
	var export JSONExport
	if err := json.Unmarshal([]byte(result), &export); err != nil {
		t.Fatalf("Failed to parse JSON with standard parser: %v", err)
	}

	// Verify structure completeness
	if export.Version == "" {
		t.Error("Missing version in JSON export")
	}

	if export.Timestamp.IsZero() {
		t.Error("Missing timestamp in JSON export")
	}

	if export.Generator == "" {
		t.Error("Missing generator in JSON export")
	}

	if len(export.Patches) != len(points) {
		t.Errorf("Expected %d patches, got %d", len(points), len(export.Patches))
	}

	// Verify each patch has required fields
	for i, patch := range export.Patches {
		if patch.FilePath == "" {
			t.Errorf("Patch %d: missing file_path", i)
		}
		if patch.MethodName == "" {
			t.Errorf("Patch %d: missing method_name", i)
		}
		if patch.PatchType == "" {
			t.Errorf("Patch %d: missing patch_type", i)
		}
		if patch.Confidence < 0.0 || patch.Confidence > 1.0 {
			t.Errorf("Patch %d: confidence %f out of range", i, patch.Confidence)
		}
		if patch.RiskScore < 0.0 || patch.RiskScore > 100.0 {
			t.Errorf("Patch %d: risk_score %f out of range", i, patch.RiskScore)
		}
	}

	// Verify summary statistics
	if export.Summary.TotalPatches != len(points) {
		t.Errorf("Summary total_patches %d does not match actual %d",
			export.Summary.TotalPatches, len(points))
	}

	confidenceSum := export.Summary.HighConfidence +
		export.Summary.MediumConfidence +
		export.Summary.LowConfidence
	if confidenceSum != len(points) {
		t.Errorf("Confidence tier counts %d do not sum to total %d",
			confidenceSum, len(points))
	}
}

// TestJSONExporter_FileExportValidity tests JSON file export and parsing
// Validates: Requirements 11.1
func TestJSONExporter_FileExportValidity(t *testing.T) {
	patches, points := createSamplePatchesForExport()
	exporter := NewJSONExporter()

	// Create temporary file
	tmpFile := testTempDir(t) + "/export_test.json"

	// Export to file
	if err := exporter.ExportToFile(patches, points, tmpFile); err != nil {
		t.Fatalf("Export to file failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatal("Export file was not created")
	}

	// Read and parse file with standard JSON parser
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read export file: %v", err)
	}

	var export JSONExport
	if err := json.Unmarshal(data, &export); err != nil {
		t.Fatalf("Failed to parse exported JSON file: %v", err)
	}

	// Verify content
	if len(export.Patches) != len(points) {
		t.Errorf("Expected %d patches in file, got %d", len(points), len(export.Patches))
	}
}

// TestMarkdownExporter_FormatValidity tests Markdown export validity
// Validates: Requirements 11.2
func TestMarkdownExporter_FormatValidity(t *testing.T) {
	patches, points := createSamplePatchesForExport()
	exporter := NewMarkdownExporter()

	// Export to string
	result := exporter.ExportToString(patches, points)

	// Verify Markdown structure - check for required sections
	requiredSections := []string{
		"# ML Patcher Report",
		"## Summary",
		"**Total Patches:**",
		"### By Risk Level",
		"### By Mode",
		"### Confidence Distribution",
		"---",
	}

	for _, section := range requiredSections {
		if !strings.Contains(result, section) {
			t.Errorf("Missing required Markdown section: %s", section)
		}
	}

	// Verify code blocks are properly formatted
	if !strings.Contains(result, "```smali") {
		t.Error("Missing Smali code blocks")
	}

	if !strings.Contains(result, "```diff") {
		t.Error("Missing diff code blocks")
	}

	// Verify mode icons are present
	if !strings.Contains(result, "🛡️") && !strings.Contains(result, "⚔️") {
		t.Error("Missing mode icons in Markdown output")
	}

	// Verify all patches are included
	for _, point := range points {
		if !strings.Contains(result, point.MethodName) {
			t.Errorf("Missing method %s in Markdown output", point.MethodName)
		}
	}

	// Verify explanation sections are present
	if !strings.Contains(result, "**Explanation:**") {
		t.Error("Missing explanation sections")
	}

	// Verify confidence breakdown sections
	if !strings.Contains(result, "**Confidence Breakdown:**") {
		t.Error("Missing confidence breakdown sections")
	}
}

// TestMarkdownExporter_FileExportValidity tests Markdown file export
// Validates: Requirements 11.2
func TestMarkdownExporter_FileExportValidity(t *testing.T) {
	patches, points := createSamplePatchesForExport()
	exporter := NewMarkdownExporter()

	// Create temporary file
	tmpFile := testTempDir(t) + "/export_test.md"

	// Export to file
	if err := exporter.ExportToFile(patches, points, tmpFile); err != nil {
		t.Fatalf("Export to file failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatal("Export file was not created")
	}

	// Read file content
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read export file: %v", err)
	}

	content := string(data)

	// Verify content is valid Markdown
	if !strings.Contains(content, "# ML Patcher Report") {
		t.Error("Missing Markdown header in file")
	}

	if len(content) == 0 {
		t.Error("Export file is empty")
	}
}

// TestCSVExporter_FormatValidity tests CSV export validity with standard parser
// Validates: Requirements 11.3
func TestCSVExporter_FormatValidity(t *testing.T) {
	patches, points := createSamplePatchesForExport()
	exporter := NewCSVExporter()

	// Export to string
	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	// Parse CSV with standard parser
	reader := csv.NewReader(strings.NewReader(result))
	reader.Comment = '#' // Skip comment lines

	// Read all records
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV with standard parser: %v", err)
	}

	// Verify we have header + data rows
	if len(records) < 2 {
		t.Fatal("CSV should have at least header and one data row")
	}

	// Verify header row
	header := records[0]
	expectedColumns := []string{
		"File Path",
		"Class Name",
		"Method Name",
		"Method Signature",
		"Patch Type",
		"Mode",
		"Confidence",
		"Risk Score",
		"Risk Level",
		"Category",
		"Description",
	}

	if len(header) != len(expectedColumns) {
		t.Errorf("Expected %d columns, got %d", len(expectedColumns), len(header))
	}

	for i, expected := range expectedColumns {
		if i < len(header) && header[i] != expected {
			t.Errorf("Column %d: expected %s, got %s", i, expected, header[i])
		}
	}

	// Verify data rows
	dataRows := records[1:]
	if len(dataRows) != len(points) {
		t.Errorf("Expected %d data rows, got %d", len(points), len(dataRows))
	}

	// Verify each row has correct number of columns
	for i, row := range dataRows {
		if len(row) != len(expectedColumns) {
			t.Errorf("Row %d: expected %d columns, got %d", i, len(expectedColumns), len(row))
		}

		// Verify required fields are not empty
		if row[0] == "" { // File Path
			t.Errorf("Row %d: file path is empty", i)
		}
		if row[2] == "" { // Method Name
			t.Errorf("Row %d: method name is empty", i)
		}
		if row[4] == "" { // Patch Type
			t.Errorf("Row %d: patch type is empty", i)
		}
	}
}

// TestCSVExporter_FileExportValidity tests CSV file export and parsing
// Validates: Requirements 11.3
func TestCSVExporter_FileExportValidity(t *testing.T) {
	patches, points := createSamplePatchesForExport()
	exporter := NewCSVExporter()

	// Create temporary file
	tmpFile := testTempDir(t) + "/export_test.csv"

	// Export to file
	if err := exporter.ExportToFile(patches, points, tmpFile); err != nil {
		t.Fatalf("Export to file failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatal("Export file was not created")
	}

	// Open and parse file with standard CSV parser
	file, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("Failed to open export file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.Comment = '#' // Skip comment lines

	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse exported CSV file: %v", err)
	}

	// Verify content
	if len(records) < 2 {
		t.Error("CSV file should have at least header and one data row")
	}

	// Verify data rows match expected count
	dataRows := records[1:]
	if len(dataRows) != len(points) {
		t.Errorf("Expected %d data rows in file, got %d", len(points), len(dataRows))
	}
}

// TestAllExporters_CompleteMetadata tests that all exporters include complete metadata
// Validates: Requirements 11.4, 11.6
func TestAllExporters_CompleteMetadata(t *testing.T) {
	patches, points := createSamplePatchesForExport()

	t.Run("JSON_Metadata", func(t *testing.T) {
		exporter := NewJSONExporter()
		result, err := exporter.ExportToString(patches, points)
		if err != nil {
			t.Fatalf("Export failed: %v", err)
		}

		var export JSONExport
		json.Unmarshal([]byte(result), &export)

		// Verify metadata fields
		if export.Version == "" {
			t.Error("Missing version metadata")
		}
		if export.Timestamp.IsZero() {
			t.Error("Missing timestamp metadata")
		}
		if export.Generator == "" {
			t.Error("Missing generator metadata")
		}

		// Verify patch metadata
		for i, patch := range export.Patches {
			if patch.Mode == "" {
				t.Errorf("Patch %d: missing mode metadata", i)
			}
			if patch.OriginalCode == "" {
				t.Errorf("Patch %d: missing original code", i)
			}
			if patch.PatchedCode == "" {
				t.Errorf("Patch %d: missing patched code", i)
			}
			if patch.DiffView == "" {
				t.Errorf("Patch %d: missing diff view", i)
			}
		}
	})

	t.Run("Markdown_Metadata", func(t *testing.T) {
		exporter := NewMarkdownExporter()
		result := exporter.ExportToString(patches, points)

		// Verify metadata in Markdown
		if !strings.Contains(result, "**Generated:**") {
			t.Error("Missing timestamp metadata")
		}
		if !strings.Contains(result, "**Version:**") {
			t.Error("Missing version metadata")
		}

		// Verify patch content includes original, patched, and diff
		if !strings.Contains(result, "**Original Code:**") {
			t.Error("Missing original code section")
		}
		if !strings.Contains(result, "**Patched Code:**") {
			t.Error("Missing patched code section")
		}
		if !strings.Contains(result, "**Diff:**") {
			t.Error("Missing diff section")
		}
	})

	t.Run("CSV_Metadata", func(t *testing.T) {
		exporter := NewCSVExporter()
		result, _ := exporter.ExportToString(patches, points)

		// Verify metadata in CSV comments
		if !strings.Contains(result, "# Version:") {
			t.Error("Missing version metadata")
		}
		if !strings.Contains(result, "# Timestamp:") {
			t.Error("Missing timestamp metadata")
		}
		if !strings.Contains(result, "# Generator:") {
			t.Error("Missing generator metadata")
		}
		if !strings.Contains(result, "# Total Patches:") {
			t.Error("Missing total patches metadata")
		}
	})
}

// TestAllExporters_ConfidenceThresholdFiltering tests confidence-based filtering
// Validates: Requirements 11.5
func TestAllExporters_ConfidenceThresholdFiltering(t *testing.T) {
	patches, points := createSamplePatchesForExport()

	threshold := 0.8

	t.Run("JSON_Threshold", func(t *testing.T) {
		exporter := NewJSONExporter()
		result, err := exporter.ExportToStringWithThreshold(patches, points, threshold)
		if err != nil {
			t.Fatalf("Export failed: %v", err)
		}

		var export JSONExport
		json.Unmarshal([]byte(result), &export)

		// Verify all patches meet threshold
		for i, patch := range export.Patches {
			if patch.Confidence < threshold {
				t.Errorf("Patch %d: confidence %.2f below threshold %.2f",
					i, patch.Confidence, threshold)
			}
		}

		// Verify count matches filtered patches
		expectedCount := 0
		for _, point := range points {
			if point.Confidence >= threshold {
				expectedCount++
			}
		}

		if len(export.Patches) != expectedCount {
			t.Errorf("Expected %d filtered patches, got %d", expectedCount, len(export.Patches))
		}
	})

	t.Run("Markdown_Threshold", func(t *testing.T) {
		exporter := NewMarkdownExporter()
		result := exporter.ExportToStringWithThreshold(patches, points, threshold)

		// Count patches in output
		patchCount := strings.Count(result, "###") - 3 // Subtract summary subsections

		// Verify count matches filtered patches
		expectedCount := 0
		for _, point := range points {
			if point.Confidence >= threshold {
				expectedCount++
			}
		}

		if patchCount != expectedCount {
			t.Errorf("Expected %d filtered patches in Markdown, got %d",
				expectedCount, patchCount)
		}
	})

	t.Run("CSV_Threshold", func(t *testing.T) {
		exporter := NewCSVExporter()
		result, _ := exporter.ExportToStringWithThreshold(patches, points, threshold)

		reader := csv.NewReader(strings.NewReader(result))
		reader.Comment = '#'
		records, _ := reader.ReadAll()

		dataRows := records[1:] // Skip header

		// Verify count matches filtered patches
		expectedCount := 0
		for _, point := range points {
			if point.Confidence >= threshold {
				expectedCount++
			}
		}

		if len(dataRows) != expectedCount {
			t.Errorf("Expected %d filtered patches in CSV, got %d",
				expectedCount, len(dataRows))
		}
	})
}

// TestAllExporters_SpecialCharacterHandling tests handling of special characters
// Validates: Requirements 11.1, 11.2, 11.3
func TestAllExporters_SpecialCharacterHandling(t *testing.T) {
	// Create patches with special characters
	patches := []*GeneratedPatch{
		{
			MethodName:   "method\"WithQuotes",
			FilePath:     "com/example/Test.smali",
			PatchType:    PatchReturnTrue,
			Description:  "Description with, commas and \"quotes\"",
			Mode:         PatchModeResearch,
			Confidence:   0.85,
			OriginalCode: "original\ncode\nwith\nnewlines",
			PatchedCode:  "patched\ncode\nwith\nnewlines",
			DiffView:     "- old\n+ new",
			Explanation: PatchExplanation{
				Reason:       "Reason with special chars: <>&\"'",
				WhatItDoes:   "Does something with newlines\nand tabs\t",
				WhyThisPatch: "Because of \"reasons\"",
				Impact:       "Impact: 100%",
			},
		},
	}

	points := []PatchPoint{
		{
			MethodName:     "method\"WithQuotes",
			FilePath:       "com/example/Test.smali",
			SuggestedPatch: PatchReturnTrue,
			Confidence:     0.85,
			RiskScore:      75.0,
			RiskLevel:      RiskClassHigh,
		},
	}

	t.Run("JSON_SpecialChars", func(t *testing.T) {
		exporter := NewJSONExporter()
		result, err := exporter.ExportToString(patches, points)
		if err != nil {
			t.Fatalf("Export failed: %v", err)
		}

		// Verify JSON is still valid
		var export JSONExport
		if err := json.Unmarshal([]byte(result), &export); err != nil {
			t.Fatalf("Failed to parse JSON with special characters: %v", err)
		}

		// Verify special characters are preserved
		if !strings.Contains(export.Patches[0].MethodName, "\"") {
			t.Error("Quotes not preserved in JSON")
		}
	})

	t.Run("CSV_SpecialChars", func(t *testing.T) {
		exporter := NewCSVExporter()
		result, err := exporter.ExportToString(patches, points)
		if err != nil {
			t.Fatalf("Export failed: %v", err)
		}

		// Verify CSV is still valid
		reader := csv.NewReader(strings.NewReader(result))
		reader.Comment = '#'
		records, err := reader.ReadAll()
		if err != nil {
			t.Fatalf("Failed to parse CSV with special characters: %v", err)
		}

		// Verify we got the data
		if len(records) < 2 {
			t.Fatal("CSV should have header and data row")
		}
	})

	t.Run("Markdown_SpecialChars", func(t *testing.T) {
		exporter := NewMarkdownExporter()
		result := exporter.ExportToString(patches, points)

		// Verify Markdown is generated without errors
		if len(result) == 0 {
			t.Fatal("Markdown export is empty")
		}

		// Verify special characters don't break structure
		if !strings.Contains(result, "# ML Patcher Report") {
			t.Error("Markdown structure broken by special characters")
		}
	})
}

// createSamplePatchesForExport creates sample patches for export testing
func createSamplePatchesForExport() ([]*GeneratedPatch, []PatchPoint) {
	patches := []*GeneratedPatch{
		{
			MethodName:   "isRooted",
			FilePath:     "com/example/security/RootCheck.smali",
			PatchType:    PatchReturnFalse,
			Description:  "Bypass root detection",
			Mode:         PatchModeResearch,
			Confidence:   0.92,
			OriginalCode: ".method public isRooted()Z\n    .registers 2\n    const/4 v0, 0x1\n    return v0\n.end method",
			PatchedCode:  ".method public isRooted()Z\n    .registers 2\n    const/4 v0, 0x0\n    return v0\n.end method",
			DiffView:     "- const/4 v0, 0x1\n+ const/4 v0, 0x0",
			Explanation: PatchExplanation{
				Reason:       "Root detection method identified",
				WhatItDoes:   "Checks if device is rooted",
				WhyThisPatch: "Return false to hide root status",
				Impact:       "App will not detect rooted device",
				Signals:      []string{"name:isRooted", "return:boolean"},
			},
			ConfidenceBreakdown: &ConfidenceBreakdown{
				BaseConfidence:   0.85,
				MultiSignalBonus: 0.07,
				FinalConfidence:  0.92,
				SignalContributions: []SignalContribution{
					{SignalType: "name", Weight: 1.0, Confidence: 0.9, Contribution: 0.9},
					{SignalType: "structure", Weight: 0.9, Confidence: 0.8, Contribution: 0.72},
				},
			},
		},
		{
			MethodName:   "isPremium",
			FilePath:     "com/example/billing/License.smali",
			PatchType:    PatchReturnTrue,
			Description:  "Unlock premium features",
			Mode:         PatchModeResearch,
			Confidence:   0.88,
			OriginalCode: ".method public isPremium()Z\n    .registers 1\n    const/4 v0, 0x0\n    return v0\n.end method",
			PatchedCode:  ".method public isPremium()Z\n    .registers 1\n    const/4 v0, 0x1\n    return v0\n.end method",
			DiffView:     "- const/4 v0, 0x0\n+ const/4 v0, 0x1",
			Explanation: PatchExplanation{
				Reason:       "Premium license check detected",
				WhatItDoes:   "Verifies premium license status",
				WhyThisPatch: "Return true to grant premium access",
				Impact:       "Premium features will be accessible",
				Signals:      []string{"name:isPremium", "category:billing"},
			},
			ConfidenceBreakdown: &ConfidenceBreakdown{
				BaseConfidence:   0.82,
				MultiSignalBonus: 0.06,
				FinalConfidence:  0.88,
			},
		},
		{
			MethodName:   "validateSignature",
			FilePath:     "com/example/security/Validator.smali",
			PatchType:    PatchReturnTrue,
			Description:  "Enforce signature validation",
			Mode:         PatchModeDefensive,
			Confidence:   0.75,
			OriginalCode: ".method public validateSignature()Z\n    .registers 1\n    const/4 v0, 0x0\n    return v0\n.end method",
			PatchedCode:  ".method public validateSignature()Z\n    .registers 1\n    const/4 v0, 0x1\n    return v0\n.end method",
			DiffView:     "- const/4 v0, 0x0\n+ const/4 v0, 0x1",
			Explanation: PatchExplanation{
				Reason:       "Weak signature validation detected",
				WhatItDoes:   "Validates app signature",
				WhyThisPatch: "Enforce strict signature checking",
				Impact:       "Prevents tampering and repackaging",
			},
			ConfidenceBreakdown: &ConfidenceBreakdown{
				BaseConfidence:  0.75,
				FinalConfidence: 0.75,
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
			PatchDesc:       "Bypass root detection",
			Confidence:      0.92,
			RiskScore:       85.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatRootDetect,
			CategoryName:    "Root Detection",
		},
		{
			MethodName:      "isPremium",
			FilePath:        "com/example/billing/License.smali",
			ClassName:       "License",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			PatchDesc:       "Unlock premium features",
			Confidence:      0.88,
			RiskScore:       80.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatPremium,
			CategoryName:    "Premium Check",
		},
		{
			MethodName:      "validateSignature",
			FilePath:        "com/example/security/Validator.smali",
			ClassName:       "Validator",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			PatchDesc:       "Enforce signature validation",
			Confidence:      0.75,
			RiskScore:       70.0,
			RiskLevel:       RiskClassMedium,
			Category:        PatchCatSignature,
			CategoryName:    "Signature Check",
		},
	}

	return patches, points
}
