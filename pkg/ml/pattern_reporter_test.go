package ml

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN REPORTER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestPatternEffectivenessReporter_DisplayReport_Empty(t *testing.T) {
	tracker := NewPatternTracker()
	var buf bytes.Buffer
	reporter := NewPatternEffectivenessReporter(tracker, &buf)

	err := reporter.DisplayReport()
	if err != nil {
		t.Fatalf("DisplayReport failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No pattern metrics found") {
		t.Errorf("Expected empty message, got: %s", output)
	}
}

func TestPatternEffectivenessReporter_DisplayReport_WithData(t *testing.T) {
	tracker := NewPatternTracker()

	// Add some test data
	tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	tracker.RecordOutcome("pattern1", OutcomeFalsePositive)

	tracker.RecordOutcome("pattern2", OutcomeTruePositive)
	tracker.RecordOutcome("pattern2", OutcomeFalseNegative)

	var buf bytes.Buffer
	reporter := NewPatternEffectivenessReporter(tracker, &buf)

	err := reporter.DisplayReport()
	if err != nil {
		t.Fatalf("DisplayReport failed: %v", err)
	}

	output := buf.String()

	// Check for expected content
	if !strings.Contains(output, "PATTERN EFFECTIVENESS REPORT") {
		t.Errorf("Missing report header")
	}
	if !strings.Contains(output, "Total patterns tracked: 2") {
		t.Errorf("Missing total patterns count")
	}
	if !strings.Contains(output, "pattern1") {
		t.Errorf("Missing pattern1 in output")
	}
	if !strings.Contains(output, "pattern2") {
		t.Errorf("Missing pattern2 in output")
	}
}

func TestPatternEffectivenessReporter_DisplayJSONReport(t *testing.T) {
	tracker := NewPatternTracker()

	// Add test data
	tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	tracker.RecordOutcome("pattern1", OutcomeFalsePositive)

	var buf bytes.Buffer
	reporter := NewPatternEffectivenessReporter(tracker, &buf)

	err := reporter.DisplayJSONReport()
	if err != nil {
		t.Fatalf("DisplayJSONReport failed: %v", err)
	}

	// Parse JSON output
	var result map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	if err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	// Verify structure
	if _, ok := result["generated_at"]; !ok {
		t.Errorf("Missing generated_at field")
	}
	if _, ok := result["total_patterns"]; !ok {
		t.Errorf("Missing total_patterns field")
	}
	if _, ok := result["patterns"]; !ok {
		t.Errorf("Missing patterns field")
	}

	// Verify total patterns
	totalPatterns := result["total_patterns"].(float64)
	if totalPatterns != 1 {
		t.Errorf("Expected 1 pattern, got %v", totalPatterns)
	}
}

func TestPatternEffectivenessReporter_ExportJSON(t *testing.T) {
	tracker := NewPatternTracker()

	// Add test data
	tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	tracker.RecordOutcome("pattern1", OutcomeFalsePositive)

	// Create temp file
	tmpFile := "test_pattern_export.json"
	defer os.Remove(tmpFile)

	var buf bytes.Buffer
	reporter := NewPatternEffectivenessReporter(tracker, &buf)

	err := reporter.ExportJSON(tmpFile)
	if err != nil {
		t.Fatalf("ExportJSON failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatalf("Export file was not created")
	}

	// Read and parse file
	data, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read export file: %v", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("Failed to parse export JSON: %v", err)
	}

	// Verify structure
	if _, ok := result["generated_at"]; !ok {
		t.Errorf("Missing generated_at field in export")
	}
	if _, ok := result["patterns"]; !ok {
		t.Errorf("Missing patterns field in export")
	}
}

func TestPatternEffectivenessReporter_LowPerformers(t *testing.T) {
	tracker := NewPatternTracker()

	// Add high-performing pattern
	for i := 0; i < 10; i++ {
		tracker.RecordOutcome("good_pattern", OutcomeTruePositive)
	}
	tracker.RecordOutcome("good_pattern", OutcomeFalsePositive)

	// Add low-performing pattern (< 70% precision)
	for i := 0; i < 5; i++ {
		tracker.RecordOutcome("bad_pattern", OutcomeTruePositive)
	}
	for i := 0; i < 10; i++ {
		tracker.RecordOutcome("bad_pattern", OutcomeFalsePositive)
	}

	var buf bytes.Buffer
	reporter := NewPatternEffectivenessReporter(tracker, &buf)

	err := reporter.DisplayReport()
	if err != nil {
		t.Fatalf("DisplayReport failed: %v", err)
	}

	output := buf.String()

	// Should show low performers section
	if !strings.Contains(output, "LOW PERFORMING PATTERNS") {
		t.Errorf("Missing low performers section")
	}
	if !strings.Contains(output, "bad_pattern") {
		t.Errorf("Missing bad_pattern in low performers")
	}
}

func TestPatternEffectivenessReporter_SortByF1(t *testing.T) {
	tracker := NewPatternTracker()

	// Pattern with high F1
	for i := 0; i < 10; i++ {
		tracker.RecordOutcome("high_f1", OutcomeTruePositive)
	}
	tracker.RecordOutcome("high_f1", OutcomeFalsePositive)

	// Pattern with low F1
	for i := 0; i < 3; i++ {
		tracker.RecordOutcome("low_f1", OutcomeTruePositive)
	}
	for i := 0; i < 7; i++ {
		tracker.RecordOutcome("low_f1", OutcomeFalsePositive)
	}

	var buf bytes.Buffer
	reporter := NewPatternEffectivenessReporter(tracker, &buf)

	metrics := tracker.GetAllMetrics()
	sorted := reporter.sortPatternsByF1(metrics)

	if len(sorted) != 2 {
		t.Fatalf("Expected 2 patterns, got %d", len(sorted))
	}

	// First should be high_f1
	if sorted[0].PatternID != "high_f1" {
		t.Errorf("Expected high_f1 first, got %s", sorted[0].PatternID)
	}

	// Second should be low_f1
	if sorted[1].PatternID != "low_f1" {
		t.Errorf("Expected low_f1 second, got %s", sorted[1].PatternID)
	}
}

func TestPatternEffectivenessReporter_Summary(t *testing.T) {
	tracker := NewPatternTracker()

	// Add multiple patterns
	for i := 0; i < 5; i++ {
		tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	}
	tracker.RecordOutcome("pattern1", OutcomeFalsePositive)

	for i := 0; i < 8; i++ {
		tracker.RecordOutcome("pattern2", OutcomeTruePositive)
	}
	tracker.RecordOutcome("pattern2", OutcomeFalsePositive)
	tracker.RecordOutcome("pattern2", OutcomeFalsePositive)

	var buf bytes.Buffer
	reporter := NewPatternEffectivenessReporter(tracker, &buf)

	metrics := tracker.GetAllMetrics()
	sorted := reporter.sortPatternsByF1(metrics)
	summary := reporter.calculateSummary(sorted)

	if summary.TotalPatterns != 2 {
		t.Errorf("Expected 2 patterns, got %d", summary.TotalPatterns)
	}

	if summary.TotalMatches != 16 {
		t.Errorf("Expected 16 total matches, got %d", summary.TotalMatches)
	}

	// Average precision should be between 0 and 1
	if summary.AvgPrecision < 0 || summary.AvgPrecision > 1 {
		t.Errorf("Invalid average precision: %f", summary.AvgPrecision)
	}
}

func TestDefaultPatternMetricsPath(t *testing.T) {
	path, err := DefaultPatternMetricsPath()
	if err != nil {
		t.Fatalf("DefaultPatternMetricsPath failed: %v", err)
	}

	if path == "" {
		t.Errorf("Expected non-empty path")
	}

	if !strings.Contains(path, PatternMetricsFileName) {
		t.Errorf("Path should contain %s, got: %s", PatternMetricsFileName, path)
	}
}

func TestPatternEffectivenessReporter_DisplayReport_Integration(t *testing.T) {
	tracker := NewPatternTracker()

	// Simulate realistic pattern data
	patterns := []struct {
		id string
		tp int
		fp int
		fn int
	}{
		{"root_detection_pattern", 45, 5, 2},
		{"premium_check_pattern", 38, 8, 4},
		{"emulator_detection", 52, 3, 1},
		{"billing_verification", 30, 15, 5},
		{"debug_check", 25, 20, 8},
	}

	for _, p := range patterns {
		for i := 0; i < p.tp; i++ {
			tracker.RecordOutcome(p.id, OutcomeTruePositive)
		}
		for i := 0; i < p.fp; i++ {
			tracker.RecordOutcome(p.id, OutcomeFalsePositive)
		}
		for i := 0; i < p.fn; i++ {
			tracker.RecordOutcome(p.id, OutcomeFalseNegative)
		}
	}

	var buf bytes.Buffer
	reporter := NewPatternEffectivenessReporter(tracker, &buf)

	err := reporter.DisplayReport()
	if err != nil {
		t.Fatalf("DisplayReport failed: %v", err)
	}

	output := buf.String()

	// Verify all patterns are present
	for _, p := range patterns {
		if !strings.Contains(output, p.id) {
			t.Errorf("Missing pattern %s in output", p.id)
		}
	}

	// Verify summary statistics
	if !strings.Contains(output, "Total patterns tracked: 5") {
		t.Errorf("Incorrect total patterns count")
	}

	// Verify low performers section (debug_check should be there)
	if !strings.Contains(output, "LOW PERFORMING PATTERNS") {
		t.Errorf("Missing low performers section")
	}
}

func TestPatternEffectivenessReporter_TruncateString(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly_ten", 11, "exactly_ten"},
		{"this_is_a_very_long_pattern_name", 20, "this_is_a_very_lo..."},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc"},
		{"abcdef", 5, "ab..."},
	}

	for _, tt := range tests {
		result := truncateString(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncateString(%q, %d) = %q, want %q",
				tt.input, tt.maxLen, result, tt.expected)
		}
	}
}
