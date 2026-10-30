package ml

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewCSVExporter tests exporter creation
func TestNewCSVExporter(t *testing.T) {
	exporter := NewCSVExporter()

	if exporter == nil {
		t.Fatal("NewCSVExporter returned nil")
	}

	if exporter.version == "" {
		t.Error("exporter version is empty")
	}
}

// TestCSVExporter_ExportToString tests basic string export
func TestCSVExporter_ExportToString(t *testing.T) {
	exporter := NewCSVExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:  "isLicensed",
			FilePath:    "com/example/License.smali",
			PatchType:   PatchReturnTrue,
			Description: "Return true for license check",
			Mode:        PatchModeResearch,
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/License.smali",
			ClassName:       "License",
			MethodName:      "isLicensed",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.85,
			RiskScore:       85.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatLicense,
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

	// Verify header comments
	if !strings.Contains(result, "# ML Patcher CSV Export") {
		t.Error("Missing header comment")
	}

	if !strings.Contains(result, "# Version:") {
		t.Error("Missing version in header")
	}

	if !strings.Contains(result, "# Timestamp:") {
		t.Error("Missing timestamp in header")
	}

	// Verify CSV structure
	lines := strings.Split(result, "\n")

	// Find first non-comment line (header)
	headerLine := ""
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") && line != "" {
			headerLine = line
			break
		}
	}

	if headerLine == "" {
		t.Fatal("No CSV header found")
	}

	// Verify header columns
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

	for _, col := range expectedColumns {
		if !strings.Contains(headerLine, col) {
			t.Errorf("Header missing column: %s", col)
		}
	}

	// Verify data row exists
	if !strings.Contains(result, "isLicensed") {
		t.Error("Data row not found")
	}

	if !strings.Contains(result, "0.85") {
		t.Error("Confidence value not found")
	}

	if !strings.Contains(result, "85.00") {
		t.Error("Risk score not found")
	}
}

// TestCSVExporter_ExportToFile tests file export
func TestCSVExporter_ExportToFile(t *testing.T) {
	exporter := NewCSVExporter()

	// Create temp directory
	tmpDir := testTempDir(t)
	filepath := filepath.Join(tmpDir, "export.csv")

	patches := []*GeneratedPatch{
		{
			MethodName:  "isPremium",
			FilePath:    "com/example/Premium.smali",
			PatchType:   PatchReturnTrue,
			Description: "Return true for premium check",
			Mode:        PatchModeResearch,
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Premium.smali",
			ClassName:       "Premium",
			MethodName:      "isPremium",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.75,
			RiskScore:       75.0,
			RiskLevel:       RiskClassMedium,
			Category:        PatchCatPremium,
			PatchDesc:       "Return true",
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

	content := string(data)

	if !strings.Contains(content, "isPremium") {
		t.Error("Method name not found in file")
	}

	if !strings.Contains(content, "0.75") {
		t.Error("Confidence not found in file")
	}
}

// TestCSVExporter_MultiplePatches tests exporting multiple patches
func TestCSVExporter_MultiplePatches(t *testing.T) {
	exporter := NewCSVExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:  "isLicensed",
			FilePath:    "com/example/License.smali",
			PatchType:   PatchReturnTrue,
			Mode:        PatchModeResearch,
			Description: "Bypass license check",
		},
		{
			MethodName:  "isPremium",
			FilePath:    "com/example/Premium.smali",
			PatchType:   PatchReturnTrue,
			Mode:        PatchModeResearch,
			Description: "Bypass premium check",
		},
		{
			MethodName:  "isRooted",
			FilePath:    "com/example/Root.smali",
			PatchType:   PatchReturnFalse,
			Mode:        PatchModeResearch,
			Description: "Hide root detection",
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/License.smali",
			ClassName:       "License",
			MethodName:      "isLicensed",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.9,
			RiskScore:       90.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatLicense,
		},
		{
			FilePath:        "com/example/Premium.smali",
			ClassName:       "Premium",
			MethodName:      "isPremium",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.7,
			RiskScore:       70.0,
			RiskLevel:       RiskClassMedium,
			Category:        PatchCatPremium,
		},
		{
			FilePath:        "com/example/Root.smali",
			ClassName:       "Root",
			MethodName:      "isRooted",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnFalse,
			Confidence:      0.4,
			RiskScore:       40.0,
			RiskLevel:       RiskClassLow,
			Category:        PatchCatRootDetect,
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	// Verify all methods are present
	if !strings.Contains(result, "isLicensed") {
		t.Error("isLicensed not found")
	}

	if !strings.Contains(result, "isPremium") {
		t.Error("isPremium not found")
	}

	if !strings.Contains(result, "isRooted") {
		t.Error("isRooted not found")
	}

	// Count data rows (excluding header and comments)
	lines := strings.Split(result, "\n")
	dataRows := 0
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") && line != "" && !strings.Contains(line, "File Path") {
			dataRows++
		}
	}

	if dataRows != 3 {
		t.Errorf("Expected 3 data rows, got %d", dataRows)
	}
}

// TestCSVExporter_SpecialCharacters tests handling of special characters
func TestCSVExporter_SpecialCharacters(t *testing.T) {
	exporter := NewCSVExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:  "test,Method",
			FilePath:    "com/example/Test.smali",
			PatchType:   PatchReturnTrue,
			Mode:        PatchModeResearch,
			Description: "Description with \"quotes\" and, commas",
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Test.smali",
			ClassName:       "Test",
			MethodName:      "test,Method",
			MethodSignature: "(Ljava/lang/String;)Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.8,
			RiskScore:       80.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatLicense,
			PatchDesc:       "Description with \"quotes\" and, commas",
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	// Parse CSV to verify it's valid
	reader := csv.NewReader(strings.NewReader(result))
	reader.Comment = '#'

	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	// Should have header + 1 data row
	if len(records) < 2 {
		t.Fatalf("Expected at least 2 records (header + data), got %d", len(records))
	}

	// Verify data row
	dataRow := records[1]

	// Method name should contain comma
	if !strings.Contains(dataRow[2], ",") {
		t.Error("Comma in method name was not preserved")
	}

	// Description should contain quotes and commas
	descIdx := len(dataRow) - 1 // Description is last column
	if !strings.Contains(dataRow[descIdx], "quotes") {
		t.Error("Quotes in description were not preserved")
	}
}

// TestCSVExporter_NewlinesInFields tests handling of newlines
func TestCSVExporter_NewlinesInFields(t *testing.T) {
	exporter := NewCSVExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:  "testMethod",
			FilePath:    "com/example/Test.smali",
			PatchType:   PatchReturnTrue,
			Mode:        PatchModeResearch,
			Description: "Line 1\nLine 2\nLine 3",
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Test.smali",
			ClassName:       "Test",
			MethodName:      "testMethod",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.8,
			RiskScore:       80.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatLicense,
			PatchDesc:       "Line 1\nLine 2\nLine 3",
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	// Parse CSV to verify it's valid
	reader := csv.NewReader(strings.NewReader(result))
	reader.Comment = '#'

	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	// Verify newlines were replaced with spaces
	dataRow := records[1]
	descIdx := len(dataRow) - 1

	if strings.Contains(dataRow[descIdx], "\n") {
		t.Error("Newlines were not replaced in description")
	}

	if !strings.Contains(dataRow[descIdx], "Line 1") {
		t.Error("Description content was lost")
	}
}

// TestCSVExporter_EmptyFields tests handling of empty fields
func TestCSVExporter_EmptyFields(t *testing.T) {
	exporter := NewCSVExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "testMethod",
			FilePath:   "com/example/Test.smali",
			PatchType:  PatchReturnTrue,
			// Mode and Description are empty
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Test.smali",
			ClassName:       "", // Empty class name
			MethodName:      "testMethod",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.8,
			RiskScore:       80.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatLicense,
			PatchDesc:       "", // Empty description
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	// Parse CSV to verify it's valid
	reader := csv.NewReader(strings.NewReader(result))
	reader.Comment = '#'

	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	// Should have header + 1 data row
	if len(records) < 2 {
		t.Fatalf("Expected at least 2 records, got %d", len(records))
	}

	// Verify data row has correct number of fields
	dataRow := records[1]
	headerRow := records[0]

	if len(dataRow) != len(headerRow) {
		t.Errorf("Data row has %d fields, header has %d fields", len(dataRow), len(headerRow))
	}
}

// TestCSVExporter_FloatFormatting tests float formatting
func TestCSVExporter_FloatFormatting(t *testing.T) {
	exporter := NewCSVExporter()

	patches := []*GeneratedPatch{
		{
			MethodName: "testMethod",
			FilePath:   "com/example/Test.smali",
			PatchType:  PatchReturnTrue,
			Mode:       PatchModeResearch,
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Test.smali",
			ClassName:       "Test",
			MethodName:      "testMethod",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.856789,  // Should be formatted to 0.86
			RiskScore:       85.123456, // Should be formatted to 85.12
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatLicense,
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	// Verify float formatting
	if !strings.Contains(result, "0.86") {
		t.Error("Confidence not formatted to 2 decimal places")
	}

	if !strings.Contains(result, "85.12") {
		t.Error("Risk score not formatted to 2 decimal places")
	}
}

// TestCSVExporter_NoPatchesProvided tests export with only points (no patches)
func TestCSVExporter_NoPatchesProvided(t *testing.T) {
	exporter := NewCSVExporter()

	// No patches, only points
	patches := []*GeneratedPatch{}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Test.smali",
			ClassName:       "Test",
			MethodName:      "testMethod",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.8,
			RiskScore:       80.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatLicense,
			PatchDesc:       "Test description",
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	// Should still export with data from points
	if !strings.Contains(result, "testMethod") {
		t.Error("Method name not found")
	}

	if !strings.Contains(result, "Test description") {
		t.Error("Description from point not used")
	}

	// Mode should be empty
	reader := csv.NewReader(strings.NewReader(result))
	reader.Comment = '#'

	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to parse CSV: %v", err)
	}

	dataRow := records[1]
	modeIdx := 5 // Mode is 6th column (index 5)

	if dataRow[modeIdx] != "" {
		t.Errorf("Mode should be empty, got %q", dataRow[modeIdx])
	}
}

// TestCSVExporter_EmptyExport tests export with no patches or points
func TestCSVExporter_EmptyExport(t *testing.T) {
	exporter := NewCSVExporter()

	result, err := exporter.ExportToString([]*GeneratedPatch{}, []PatchPoint{})
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	// Should have header comments and CSV header
	if !strings.Contains(result, "# ML Patcher CSV Export") {
		t.Error("Missing header comment")
	}

	if !strings.Contains(result, "File Path") {
		t.Error("Missing CSV header")
	}

	// Should have 0 patches in metadata
	if !strings.Contains(result, "# Total Patches: 0") {
		t.Error("Total patches count incorrect")
	}
}

// TestCSVExporter_DefensiveMode tests defensive mode export
func TestCSVExporter_DefensiveMode(t *testing.T) {
	exporter := NewCSVExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:  "isRooted",
			FilePath:    "com/example/Root.smali",
			PatchType:   PatchReturnTrue,
			Mode:        PatchModeDefensive,
			Description: "Strengthen root detection",
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/Root.smali",
			ClassName:       "Root",
			MethodName:      "isRooted",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.85,
			RiskScore:       85.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatRootDetect,
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	// Verify defensive mode is present
	if !strings.Contains(result, "defensive") {
		t.Error("Defensive mode not found in export")
	}
}

// TestCSVExporter_AllCategories tests export with different categories
func TestCSVExporter_AllCategories(t *testing.T) {
	exporter := NewCSVExporter()

	categories := []PatchCategory{
		PatchCatLicense,
		PatchCatBilling,
		PatchCatPremium,
		PatchCatRootDetect,
		PatchCatEmulatorCheck,
	}

	patches := []*GeneratedPatch{}
	points := []PatchPoint{}

	for i, cat := range categories {
		patches = append(patches, &GeneratedPatch{
			MethodName: "method" + string(rune('A'+i)),
			FilePath:   "com/example/Test.smali",
			PatchType:  PatchReturnTrue,
			Mode:       PatchModeResearch,
		})

		points = append(points, PatchPoint{
			FilePath:        "com/example/Test.smali",
			ClassName:       "Test",
			MethodName:      "method" + string(rune('A'+i)),
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.8,
			RiskScore:       80.0,
			RiskLevel:       RiskClassHigh,
			Category:        cat,
		})
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	// Verify all categories are present
	for _, cat := range categories {
		if !strings.Contains(result, string(cat)) {
			t.Errorf("Category %s not found in export", cat)
		}
	}
}

// TestCSVExporter_ParseableByStandardTools tests CSV can be parsed by standard tools
func TestCSVExporter_ParseableByStandardTools(t *testing.T) {
	exporter := NewCSVExporter()

	patches := []*GeneratedPatch{
		{
			MethodName:  "isLicensed",
			FilePath:    "com/example/License.smali",
			PatchType:   PatchReturnTrue,
			Mode:        PatchModeResearch,
			Description: "Test description",
		},
	}

	points := []PatchPoint{
		{
			FilePath:        "com/example/License.smali",
			ClassName:       "License",
			MethodName:      "isLicensed",
			MethodSignature: "()Z",
			SuggestedPatch:  PatchReturnTrue,
			Confidence:      0.85,
			RiskScore:       85.0,
			RiskLevel:       RiskClassHigh,
			Category:        PatchCatLicense,
		},
	}

	result, err := exporter.ExportToString(patches, points)
	if err != nil {
		t.Fatalf("ExportToString failed: %v", err)
	}

	// Parse with standard csv.Reader
	reader := csv.NewReader(strings.NewReader(result))
	reader.Comment = '#'

	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Standard CSV parser failed: %v", err)
	}

	// Verify structure
	if len(records) < 2 {
		t.Fatalf("Expected at least 2 records, got %d", len(records))
	}

	// Verify header
	header := records[0]
	if len(header) != 11 {
		t.Errorf("Expected 11 columns, got %d", len(header))
	}

	// Verify data
	data := records[1]
	if len(data) != 11 {
		t.Errorf("Expected 11 data fields, got %d", len(data))
	}

	// Verify specific fields
	if data[2] != "isLicensed" {
		t.Errorf("Method name = %q, want %q", data[2], "isLicensed")
	}

	if data[6] != "0.85" {
		t.Errorf("Confidence = %q, want %q", data[6], "0.85")
	}
}
