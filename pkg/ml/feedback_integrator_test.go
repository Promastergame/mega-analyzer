package ml

import (
	"path/filepath"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FEEDBACK INTEGRATOR TESTS — Phase 4: Pattern Effectiveness Tracking
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewFeedbackIntegrator(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	if fi == nil {
		t.Fatal("NewFeedbackIntegrator returned nil")
	}

	if fi.tracker == nil {
		t.Error("tracker not set")
	}

	if fi.tracker != tracker {
		t.Error("tracker reference not preserved")
	}
}

func TestAdjustPatternWeights_LowPrecision(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	// Create pattern with low precision (40%)
	patternID := "low_precision_pattern"
	for i := 0; i < 4; i++ {
		tracker.RecordOutcome(patternID, OutcomeTruePositive)
	}
	for i := 0; i < 6; i++ {
		tracker.RecordOutcome(patternID, OutcomeFalsePositive)
	}

	patterns := []VulnerablePattern{
		{
			ID:     patternID,
			Weight: 1.0,
		},
	}

	fi.AdjustPatternWeights(patterns)

	expectedWeight := 1.0 * 0.8 // 0.8
	if patterns[0].Weight != expectedWeight {
		t.Errorf("expected weight=%f, got %f", expectedWeight, patterns[0].Weight)
	}
}

func TestAdjustPatternWeights_HighPrecision(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	// Create pattern with high precision (95%)
	patternID := "high_precision_pattern"
	for i := 0; i < 19; i++ {
		tracker.RecordOutcome(patternID, OutcomeTruePositive)
	}
	tracker.RecordOutcome(patternID, OutcomeFalsePositive)

	patterns := []VulnerablePattern{
		{
			ID:     patternID,
			Weight: 1.0,
		},
	}

	fi.AdjustPatternWeights(patterns)

	expectedWeight := 1.0 * 1.1 // 1.1
	if patterns[0].Weight != expectedWeight {
		t.Errorf("expected weight=%f, got %f", expectedWeight, patterns[0].Weight)
	}
}

func TestAdjustPatternWeights_MediumPrecision(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	// Create pattern with medium precision (80%) - no adjustment
	patternID := "medium_precision_pattern"
	for i := 0; i < 8; i++ {
		tracker.RecordOutcome(patternID, OutcomeTruePositive)
	}
	for i := 0; i < 2; i++ {
		tracker.RecordOutcome(patternID, OutcomeFalsePositive)
	}

	patterns := []VulnerablePattern{
		{
			ID:     patternID,
			Weight: 1.0,
		},
	}

	fi.AdjustPatternWeights(patterns)

	// Weight should remain unchanged (precision between 0.7 and 0.9)
	if patterns[0].Weight != 1.0 {
		t.Errorf("expected weight=1.0 (unchanged), got %f", patterns[0].Weight)
	}
}

func TestAdjustPatternWeights_ClampLowerBound(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	// Create pattern with low precision
	patternID := "very_low_precision"
	for i := 0; i < 2; i++ {
		tracker.RecordOutcome(patternID, OutcomeTruePositive)
	}
	for i := 0; i < 8; i++ {
		tracker.RecordOutcome(patternID, OutcomeFalsePositive)
	}

	patterns := []VulnerablePattern{
		{
			ID:     patternID,
			Weight: 0.35, // Start with low weight
		},
	}

	fi.AdjustPatternWeights(patterns)

	// 0.35 * 0.8 = 0.28, should be clamped to 0.3
	const epsilon = 0.0001
	if patterns[0].Weight < 0.3-epsilon || patterns[0].Weight > 0.3+epsilon {
		t.Errorf("expected weight=0.3 (clamped), got %f", patterns[0].Weight)
	}
}

func TestAdjustPatternWeights_ClampUpperBound(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	// Create pattern with high precision
	patternID := "very_high_precision"
	for i := 0; i < 19; i++ {
		tracker.RecordOutcome(patternID, OutcomeTruePositive)
	}
	tracker.RecordOutcome(patternID, OutcomeFalsePositive)

	patterns := []VulnerablePattern{
		{
			ID:     patternID,
			Weight: 1.9, // Start with high weight
		},
	}

	fi.AdjustPatternWeights(patterns)

	// 1.9 * 1.1 = 2.09, should be clamped to 2.0
	if patterns[0].Weight != 2.0 {
		t.Errorf("expected weight=2.0 (clamped), got %f", patterns[0].Weight)
	}
}

func TestAdjustPatternWeights_InsufficientData(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	// Create pattern with only 4 matches (< 5 threshold)
	patternID := "insufficient_data"
	for i := 0; i < 1; i++ {
		tracker.RecordOutcome(patternID, OutcomeTruePositive)
	}
	for i := 0; i < 3; i++ {
		tracker.RecordOutcome(patternID, OutcomeFalsePositive)
	}

	patterns := []VulnerablePattern{
		{
			ID:     patternID,
			Weight: 1.0,
		},
	}

	fi.AdjustPatternWeights(patterns)

	// Weight should remain unchanged (insufficient data)
	if patterns[0].Weight != 1.0 {
		t.Errorf("expected weight=1.0 (unchanged due to insufficient data), got %f", patterns[0].Weight)
	}
}

func TestAdjustPatternWeights_NoMetrics(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	// Pattern with no recorded outcomes
	patterns := []VulnerablePattern{
		{
			ID:     "no_metrics_pattern",
			Weight: 1.0,
		},
	}

	fi.AdjustPatternWeights(patterns)

	// Weight should remain unchanged (no metrics)
	if patterns[0].Weight != 1.0 {
		t.Errorf("expected weight=1.0 (unchanged due to no metrics), got %f", patterns[0].Weight)
	}
}

func TestAdjustPatternWeights_MultiplePatterns(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	// Pattern 1: Low precision (30%)
	for i := 0; i < 3; i++ {
		tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	}
	for i := 0; i < 7; i++ {
		tracker.RecordOutcome("pattern1", OutcomeFalsePositive)
	}

	// Pattern 2: High precision (95%)
	for i := 0; i < 19; i++ {
		tracker.RecordOutcome("pattern2", OutcomeTruePositive)
	}
	tracker.RecordOutcome("pattern2", OutcomeFalsePositive)

	// Pattern 3: Medium precision (80%)
	for i := 0; i < 8; i++ {
		tracker.RecordOutcome("pattern3", OutcomeTruePositive)
	}
	for i := 0; i < 2; i++ {
		tracker.RecordOutcome("pattern3", OutcomeFalsePositive)
	}

	// Pattern 4: Insufficient data
	for i := 0; i < 2; i++ {
		tracker.RecordOutcome("pattern4", OutcomeTruePositive)
	}

	patterns := []VulnerablePattern{
		{ID: "pattern1", Weight: 1.0},
		{ID: "pattern2", Weight: 1.0},
		{ID: "pattern3", Weight: 1.0},
		{ID: "pattern4", Weight: 1.0},
	}

	fi.AdjustPatternWeights(patterns)

	// Pattern 1: should be reduced
	if patterns[0].Weight != 0.8 {
		t.Errorf("pattern1: expected weight=0.8, got %f", patterns[0].Weight)
	}

	// Pattern 2: should be increased
	if patterns[1].Weight != 1.1 {
		t.Errorf("pattern2: expected weight=1.1, got %f", patterns[1].Weight)
	}

	// Pattern 3: should remain unchanged
	if patterns[2].Weight != 1.0 {
		t.Errorf("pattern3: expected weight=1.0, got %f", patterns[2].Weight)
	}

	// Pattern 4: should remain unchanged (insufficient data)
	if patterns[3].Weight != 1.0 {
		t.Errorf("pattern4: expected weight=1.0, got %f", patterns[3].Weight)
	}
}

func TestAdjustPatternWeights_ExactThresholds(t *testing.T) {
	tests := []struct {
		name           string
		tp             int
		fp             int
		initialWeight  float64
		expectedWeight float64
		description    string
	}{
		{
			name:           "exactly 0.7 precision",
			tp:             7,
			fp:             3,
			initialWeight:  1.0,
			expectedWeight: 1.0, // No adjustment at threshold
			description:    "precision = 0.7 should not trigger adjustment",
		},
		{
			name:           "just below 0.7 precision",
			tp:             6,
			fp:             4,
			initialWeight:  1.0,
			expectedWeight: 0.8, // Should reduce
			description:    "precision = 0.6 should reduce weight",
		},
		{
			name:           "exactly 0.9 precision",
			tp:             9,
			fp:             1,
			initialWeight:  1.0,
			expectedWeight: 1.0, // No adjustment at threshold
			description:    "precision = 0.9 should not trigger adjustment",
		},
		{
			name:           "just above 0.9 precision",
			tp:             19,
			fp:             1,
			initialWeight:  1.0,
			expectedWeight: 1.1, // Should increase
			description:    "precision = 0.95 should increase weight",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracker := NewPatternTracker()
			fi := NewFeedbackIntegrator(tracker)

			patternID := "test_pattern"
			for i := 0; i < tt.tp; i++ {
				tracker.RecordOutcome(patternID, OutcomeTruePositive)
			}
			for i := 0; i < tt.fp; i++ {
				tracker.RecordOutcome(patternID, OutcomeFalsePositive)
			}

			patterns := []VulnerablePattern{
				{
					ID:     patternID,
					Weight: tt.initialWeight,
				},
			}

			fi.AdjustPatternWeights(patterns)

			if patterns[0].Weight != tt.expectedWeight {
				t.Errorf("%s: expected weight=%f, got %f", tt.description, tt.expectedWeight, patterns[0].Weight)
			}
		})
	}
}

func TestAdjustPatternWeights_MultipleAdjustments(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	// Create pattern with low precision
	patternID := "iterative_pattern"
	for i := 0; i < 3; i++ {
		tracker.RecordOutcome(patternID, OutcomeTruePositive)
	}
	for i := 0; i < 7; i++ {
		tracker.RecordOutcome(patternID, OutcomeFalsePositive)
	}

	patterns := []VulnerablePattern{
		{
			ID:     patternID,
			Weight: 1.0,
		},
	}

	// First adjustment
	fi.AdjustPatternWeights(patterns)
	firstWeight := patterns[0].Weight // Should be 0.8

	// Second adjustment (without new data)
	fi.AdjustPatternWeights(patterns)
	secondWeight := patterns[0].Weight // Same evidence must not compound.

	const epsilon = 0.0001
	if firstWeight < 0.8-epsilon || firstWeight > 0.8+epsilon {
		t.Errorf("first adjustment: expected weight=0.8, got %f", firstWeight)
	}

	if secondWeight < 0.8-epsilon || secondWeight > 0.8+epsilon {
		t.Errorf("second adjustment: expected idempotent weight=0.8, got %f", secondWeight)
	}
}

func TestAdjustPatternWeights_EmptyPatternList(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	patterns := []VulnerablePattern{}

	// Should not panic
	fi.AdjustPatternWeights(patterns)

	if len(patterns) != 0 {
		t.Error("empty pattern list should remain empty")
	}
}

func TestAdjustPatternWeights_PreservesOtherFields(t *testing.T) {
	tracker := NewPatternTracker()
	fi := NewFeedbackIntegrator(tracker)

	// Create pattern with high precision
	patternID := "preserve_fields_pattern"
	for i := 0; i < 19; i++ {
		tracker.RecordOutcome(patternID, OutcomeTruePositive)
	}
	tracker.RecordOutcome(patternID, OutcomeFalsePositive)

	patterns := []VulnerablePattern{
		{
			ID:          patternID,
			Weight:      1.0,
			Description: "Test pattern",
			Category:    "test_category",
			PatchType:   "return_true",
		},
	}

	fi.AdjustPatternWeights(patterns)

	// Check that only Weight changed
	if patterns[0].ID != patternID {
		t.Error("ID should be preserved")
	}
	if patterns[0].Description != "Test pattern" {
		t.Error("Description should be preserved")
	}
	if patterns[0].Category != "test_category" {
		t.Error("Category should be preserved")
	}
	if patterns[0].PatchType != "return_true" {
		t.Error("PatchType should be preserved")
	}
	if patterns[0].Weight != 1.1 {
		t.Errorf("Weight should be adjusted to 1.1, got %f", patterns[0].Weight)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEEDBACK PERSISTENCE INTEGRATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestFeedbackIntegration_PersistenceRoundTrip(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "feedback_metrics.json")

	// Create tracker and record outcomes
	tracker := NewPatternTracker()
	for i := 0; i < 19; i++ {
		tracker.RecordOutcome("high_precision", OutcomeTruePositive)
	}
	tracker.RecordOutcome("high_precision", OutcomeFalsePositive)

	for i := 0; i < 3; i++ {
		tracker.RecordOutcome("low_precision", OutcomeTruePositive)
	}
	for i := 0; i < 7; i++ {
		tracker.RecordOutcome("low_precision", OutcomeFalsePositive)
	}

	// Save metrics
	err := tracker.SaveToFile(testFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Create new tracker and load metrics
	tracker2 := NewPatternTracker()
	err = tracker2.LoadFromFile(testFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Create FeedbackIntegrator with loaded tracker
	fi := NewFeedbackIntegrator(tracker2)

	patterns := []VulnerablePattern{
		{ID: "high_precision", Weight: 1.0},
		{ID: "low_precision", Weight: 1.0},
	}

	// Apply weight adjustments
	fi.AdjustPatternWeights(patterns)

	// Verify adjustments based on loaded metrics
	if patterns[0].Weight != 1.1 {
		t.Errorf("high_precision: expected weight=1.1, got %f", patterns[0].Weight)
	}
	if patterns[1].Weight != 0.8 {
		t.Errorf("low_precision: expected weight=0.8, got %f", patterns[1].Weight)
	}
}

func TestFeedbackIntegration_WeightAdjustmentsPersist(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "feedback_metrics.json")

	// Create tracker with pattern data
	tracker := NewPatternTracker()
	for i := 0; i < 9; i++ {
		tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	}
	tracker.RecordOutcome("pattern1", OutcomeFalsePositive)

	// Save initial metrics
	err := tracker.SaveToFile(testFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Load metrics in new tracker
	tracker2 := NewPatternTracker()
	err = tracker2.LoadFromFile(testFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Verify metrics persisted correctly
	metrics := tracker2.GetMetrics("pattern1")
	if metrics == nil {
		t.Fatal("pattern1 metrics not loaded")
	}

	expectedPrecision := 9.0 / 10.0
	const epsilon = 0.0001
	if abs(metrics.Precision-expectedPrecision) > epsilon {
		t.Errorf("Expected precision %.3f, got %.3f", expectedPrecision, metrics.Precision)
	}

	// Apply feedback integration
	fi := NewFeedbackIntegrator(tracker2)
	patterns := []VulnerablePattern{
		{ID: "pattern1", Weight: 1.0},
	}
	fi.AdjustPatternWeights(patterns)

	// Weight should remain unchanged (precision = 0.9, at threshold)
	if patterns[0].Weight != 1.0 {
		t.Errorf("Expected weight=1.0 (unchanged), got %f", patterns[0].Weight)
	}
}

func TestFeedbackIntegration_LoadAndAdjustMultiplePatterns(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "feedback_metrics.json")

	// Create tracker with multiple patterns
	tracker := NewPatternTracker()

	// Pattern 1: Very high precision (100%)
	for i := 0; i < 20; i++ {
		tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	}

	// Pattern 2: Low precision (30%)
	for i := 0; i < 3; i++ {
		tracker.RecordOutcome("pattern2", OutcomeTruePositive)
	}
	for i := 0; i < 7; i++ {
		tracker.RecordOutcome("pattern2", OutcomeFalsePositive)
	}

	// Pattern 3: Medium precision (75%)
	for i := 0; i < 15; i++ {
		tracker.RecordOutcome("pattern3", OutcomeTruePositive)
	}
	for i := 0; i < 5; i++ {
		tracker.RecordOutcome("pattern3", OutcomeFalsePositive)
	}

	// Pattern 4: Insufficient data
	for i := 0; i < 3; i++ {
		tracker.RecordOutcome("pattern4", OutcomeTruePositive)
	}

	// Save and reload
	err := tracker.SaveToFile(testFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	tracker2 := NewPatternTracker()
	err = tracker2.LoadFromFile(testFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Apply feedback integration
	fi := NewFeedbackIntegrator(tracker2)
	patterns := []VulnerablePattern{
		{ID: "pattern1", Weight: 1.0},
		{ID: "pattern2", Weight: 1.0},
		{ID: "pattern3", Weight: 1.0},
		{ID: "pattern4", Weight: 1.0},
	}
	fi.AdjustPatternWeights(patterns)

	// Verify adjustments
	if patterns[0].Weight != 1.1 {
		t.Errorf("pattern1: expected weight=1.1 (high precision), got %f", patterns[0].Weight)
	}
	if patterns[1].Weight != 0.8 {
		t.Errorf("pattern2: expected weight=0.8 (low precision), got %f", patterns[1].Weight)
	}
	if patterns[2].Weight != 1.0 {
		t.Errorf("pattern3: expected weight=1.0 (medium precision), got %f", patterns[2].Weight)
	}
	if patterns[3].Weight != 1.0 {
		t.Errorf("pattern4: expected weight=1.0 (insufficient data), got %f", patterns[3].Weight)
	}
}

func TestFeedbackIntegration_EmptyFileLoadsSuccessfully(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "empty_metrics.json")

	// Create empty tracker and save
	tracker := NewPatternTracker()
	err := tracker.SaveToFile(testFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Load into new tracker
	tracker2 := NewPatternTracker()
	err = tracker2.LoadFromFile(testFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Create FeedbackIntegrator
	fi := NewFeedbackIntegrator(tracker2)

	// Try to adjust patterns (should handle empty metrics gracefully)
	patterns := []VulnerablePattern{
		{ID: "nonexistent_pattern", Weight: 1.0},
	}
	fi.AdjustPatternWeights(patterns)

	// Weight should remain unchanged (no metrics)
	if patterns[0].Weight != 1.0 {
		t.Errorf("Expected weight=1.0 (no metrics), got %f", patterns[0].Weight)
	}
}

func TestFeedbackIntegration_IncrementalFeedback(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "incremental_metrics.json")

	// Phase 1: Initial feedback
	tracker := NewPatternTracker()
	for i := 0; i < 5; i++ {
		tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	}
	for i := 0; i < 5; i++ {
		tracker.RecordOutcome("pattern1", OutcomeFalsePositive)
	}
	err := tracker.SaveToFile(testFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Phase 2: Load and add more feedback
	tracker2 := NewPatternTracker()
	err = tracker2.LoadFromFile(testFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Add more positive outcomes
	for i := 0; i < 10; i++ {
		tracker2.RecordOutcome("pattern1", OutcomeTruePositive)
	}
	err = tracker2.SaveToFile(testFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Phase 3: Load final metrics and verify
	tracker3 := NewPatternTracker()
	err = tracker3.LoadFromFile(testFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	metrics := tracker3.GetMetrics("pattern1")
	if metrics == nil {
		t.Fatal("pattern1 metrics not loaded")
	}

	// Should have 15 TP, 5 FP = 75% precision
	if metrics.TruePositives != 15 {
		t.Errorf("Expected 15 true positives, got %d", metrics.TruePositives)
	}
	if metrics.FalsePositives != 5 {
		t.Errorf("Expected 5 false positives, got %d", metrics.FalsePositives)
	}

	expectedPrecision := 15.0 / 20.0
	const epsilon = 0.0001
	if abs(metrics.Precision-expectedPrecision) > epsilon {
		t.Errorf("Expected precision %.3f, got %.3f", expectedPrecision, metrics.Precision)
	}

	// Apply feedback integration
	fi := NewFeedbackIntegrator(tracker3)
	patterns := []VulnerablePattern{
		{ID: "pattern1", Weight: 1.0},
	}
	fi.AdjustPatternWeights(patterns)

	// Weight should remain unchanged (precision = 0.75, between thresholds)
	if patterns[0].Weight != 1.0 {
		t.Errorf("Expected weight=1.0 (medium precision), got %f", patterns[0].Weight)
	}
}

func TestFeedbackIntegration_ConcurrentAccess(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := testTempDir(t)
	testFile := filepath.Join(tmpDir, "concurrent_metrics.json")

	// Create tracker with initial data
	tracker := NewPatternTracker()
	for i := 0; i < 10; i++ {
		tracker.RecordOutcome("pattern1", OutcomeTruePositive)
	}
	err := tracker.SaveToFile(testFile)
	if err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}

	// Load tracker
	tracker2 := NewPatternTracker()
	err = tracker2.LoadFromFile(testFile)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	// Create FeedbackIntegrator
	fi := NewFeedbackIntegrator(tracker2)

	// Simulate concurrent weight adjustments
	done := make(chan bool, 2)

	go func() {
		patterns := []VulnerablePattern{
			{ID: "pattern1", Weight: 1.0},
		}
		fi.AdjustPatternWeights(patterns)
		done <- true
	}()

	go func() {
		patterns := []VulnerablePattern{
			{ID: "pattern1", Weight: 1.0},
		}
		fi.AdjustPatternWeights(patterns)
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done

	// Should not panic or cause data races
	metrics := tracker2.GetMetrics("pattern1")
	if metrics == nil {
		t.Fatal("pattern1 metrics should exist")
	}
}
