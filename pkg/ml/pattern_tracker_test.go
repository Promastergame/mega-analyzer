package ml

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPatternTracker_SaveToFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "metrics.json")

	// Create tracker with some data
	tracker := NewPatternTracker()
	tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	tracker.RecordOutcome("pattern1", OutcomeFalsePositive)
	tracker.RecordOutcome("pattern2", OutcomeTruePositive)

	// Save to file
	err := tracker.SaveToFile(testFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Fatal("Metrics file was not created")
	}

	// Verify file is valid JSON
	data, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read metrics file: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("Metrics file is empty")
	}
}

func TestPatternTracker_LoadFromFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "metrics.json")

	// Create tracker with some data and save it
	tracker1 := NewPatternTracker()
	tracker1.RecordOutcome("pattern1", OutcomeTruePositive)
	tracker1.RecordOutcome("pattern1", OutcomeTruePositive)
	tracker1.RecordOutcome("pattern1", OutcomeFalsePositive)
	tracker1.RecordOutcome("pattern2", OutcomeTruePositive)
	tracker1.RecordOutcome("pattern2", OutcomeFalseNegative)

	err := tracker1.SaveToFile(testFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Create a new tracker and load the data
	tracker2 := NewPatternTracker()
	err = tracker2.LoadFromFile(testFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Verify pattern1 metrics
	metrics1 := tracker2.GetMetrics("pattern1")
	if metrics1 == nil {
		t.Fatal("pattern1 metrics not loaded")
	}
	if metrics1.TruePositives != 2 {
		t.Errorf("Expected 2 true positives for pattern1, got %d", metrics1.TruePositives)
	}
	if metrics1.FalsePositives != 1 {
		t.Errorf("Expected 1 false positive for pattern1, got %d", metrics1.FalsePositives)
	}
	if metrics1.TotalMatches != 3 {
		t.Errorf("Expected 3 total matches for pattern1, got %d", metrics1.TotalMatches)
	}

	// Verify pattern2 metrics
	metrics2 := tracker2.GetMetrics("pattern2")
	if metrics2 == nil {
		t.Fatal("pattern2 metrics not loaded")
	}
	if metrics2.TruePositives != 1 {
		t.Errorf("Expected 1 true positive for pattern2, got %d", metrics2.TruePositives)
	}
	if metrics2.FalseNegatives != 1 {
		t.Errorf("Expected 1 false negative for pattern2, got %d", metrics2.FalseNegatives)
	}
}

func TestPatternTracker_LoadFromFile_NonExistent(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "nonexistent.json")

	// Create a new tracker and try to load from non-existent file
	tracker := NewPatternTracker()
	err := tracker.LoadFromFile(testFile)

	// Should not return an error for non-existent file
	if err != nil {
		t.Errorf("LoadFromFile should not error on non-existent file, got: %v", err)
	}

	// Metrics should be empty
	allMetrics := tracker.GetAllMetrics()
	if len(allMetrics) != 0 {
		t.Errorf("Expected empty metrics, got %d entries", len(allMetrics))
	}
}

func TestPatternTracker_SaveAndLoad_PreservesMetrics(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "metrics.json")

	// Create tracker with comprehensive data
	tracker1 := NewPatternTracker()

	// Pattern with high precision
	for i := 0; i < 10; i++ {
		tracker1.RecordOutcome("high_precision", OutcomeTruePositive)
	}
	tracker1.RecordOutcome("high_precision", OutcomeFalsePositive)

	// Pattern with low precision
	for i := 0; i < 5; i++ {
		tracker1.RecordOutcome("low_precision", OutcomeFalsePositive)
	}
	tracker1.RecordOutcome("low_precision", OutcomeTruePositive)

	// Save to file
	err := tracker1.SaveToFile(testFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Load into new tracker
	tracker2 := NewPatternTracker()
	err = tracker2.LoadFromFile(testFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Verify high precision pattern
	highPrecision := tracker2.GetMetrics("high_precision")
	if highPrecision == nil {
		t.Fatal("high_precision metrics not loaded")
	}
	expectedPrecision := 10.0 / 11.0
	if abs(highPrecision.Precision-expectedPrecision) > 0.001 {
		t.Errorf("Expected precision %.3f, got %.3f", expectedPrecision, highPrecision.Precision)
	}

	// Verify low precision pattern
	lowPrecision := tracker2.GetMetrics("low_precision")
	if lowPrecision == nil {
		t.Fatal("low_precision metrics not loaded")
	}
	expectedLowPrecision := 1.0 / 6.0
	if abs(lowPrecision.Precision-expectedLowPrecision) > 0.001 {
		t.Errorf("Expected precision %.3f, got %.3f", expectedLowPrecision, lowPrecision.Precision)
	}
}

func TestPatternTracker_SaveAndLoad_PreservesTimestamps(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "metrics.json")

	// Create tracker with data
	tracker1 := NewPatternTracker()
	beforeTime := time.Now()
	tracker1.RecordOutcome("pattern1", OutcomeTruePositive)
	afterTime := time.Now()

	// Save to file
	err := tracker1.SaveToFile(testFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Load into new tracker
	tracker2 := NewPatternTracker()
	err = tracker2.LoadFromFile(testFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Verify timestamp is preserved
	metrics := tracker2.GetMetrics("pattern1")
	if metrics == nil {
		t.Fatal("pattern1 metrics not loaded")
	}

	if metrics.LastUpdated.Before(beforeTime) || metrics.LastUpdated.After(afterTime) {
		t.Errorf("Timestamp not preserved correctly: %v (expected between %v and %v)",
			metrics.LastUpdated, beforeTime, afterTime)
	}
}

func TestPatternTracker_LoadFromFile_InvalidJSON(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "invalid.json")

	// Write invalid JSON
	err := os.WriteFile(testFile, []byte("invalid json content"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Try to load
	tracker := NewPatternTracker()
	err = tracker.LoadFromFile(testFile)

	// Should return an error
	if err == nil {
		t.Error("LoadFromFile should error on invalid JSON")
	}
}

func TestPatternTracker_LoadFromFileRepairsDerivedMetrics(t *testing.T) {
	path := filepath.Join(testTempDir(t), "metrics.json")
	data := []byte(`{"rule":{"pattern_id":"","true_positives":3,"false_positives":1,"total_matches":999,"precision":0.01}}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	tracker := NewPatternTracker()
	if err := tracker.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	metrics := tracker.GetMetrics("rule")
	if metrics == nil || metrics.PatternID != "rule" || metrics.TotalMatches != 4 || metrics.Precision != 0.75 {
		t.Fatalf("derived metrics were not repaired: %+v", metrics)
	}
}

func TestPatternTracker_LoadNullCreatesUsableStore(t *testing.T) {
	path := filepath.Join(testTempDir(t), "metrics.json")
	if err := os.WriteFile(path, []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	tracker := NewPatternTracker()
	if err := tracker.LoadFromFile(path); err != nil {
		t.Fatal(err)
	}
	tracker.RecordOutcome("rule", OutcomeTruePositive)
	if metrics := tracker.GetMetrics("rule"); metrics == nil || metrics.TruePositives != 1 {
		t.Fatalf("loaded null store is not usable: %+v", metrics)
	}
}

// Helper function for floating point comparison
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
