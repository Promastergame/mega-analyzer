package ml

import (
	"math"
	"testing"
	"testing/quick"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY-BASED TESTS — Pattern Metrics Calculation
// ═══════════════════════════════════════════════════════════════════════════════
//
// These tests verify that pattern metrics (precision, recall, F1 score) are
// calculated correctly according to their mathematical definitions.

// TestProperty_PatternMetricsCalculationCorrectness verifies that pattern metrics
// are calculated correctly according to their mathematical definitions.
//
// **Validates: Requirements 8.3**
//
// Property 16: Pattern Metrics Calculation Correctness
// For any pattern with recorded outcomes, the calculated metrics SHALL satisfy:
// - precision = TP/(TP+FP)
// - recall = TP/(TP+FN)
// - F1 = 2*(precision*recall)/(precision+recall)
func TestProperty_PatternMetricsCalculationCorrectness(t *testing.T) {
	config := &quick.Config{
		MaxCount: 100,
	}

	property := func(tp, fp, fn uint8) bool {
		// Skip cases where all values are zero (no data)
		if tp == 0 && fp == 0 && fn == 0 {
			return true
		}

		// Create a pattern tracker
		tracker := NewPatternTracker()
		patternID := "test_pattern"

		// Record outcomes
		for i := 0; i < int(tp); i++ {
			tracker.RecordOutcome(patternID, OutcomeTruePositive)
		}
		for i := 0; i < int(fp); i++ {
			tracker.RecordOutcome(patternID, OutcomeFalsePositive)
		}
		for i := 0; i < int(fn); i++ {
			tracker.RecordOutcome(patternID, OutcomeFalseNegative)
		}

		// Get metrics
		metrics := tracker.GetMetrics(patternID)
		if metrics == nil {
			t.Logf("Failed to get metrics for pattern %s", patternID)
			return false
		}

		// Calculate expected precision: TP / (TP + FP)
		var expectedPrecision float64
		totalMatches := int(tp) + int(fp)
		if totalMatches > 0 {
			expectedPrecision = float64(tp) / float64(totalMatches)
		} else {
			expectedPrecision = 0.0
		}

		// Calculate expected recall: TP / (TP + FN)
		var expectedRecall float64
		totalRelevant := int(tp) + int(fn)
		if totalRelevant > 0 {
			expectedRecall = float64(tp) / float64(totalRelevant)
		} else {
			expectedRecall = 0.0
		}

		// Calculate expected F1: 2 * (P * R) / (P + R)
		var expectedF1 float64
		if expectedPrecision+expectedRecall > 0 {
			expectedF1 = 2 * (expectedPrecision * expectedRecall) / (expectedPrecision + expectedRecall)
		} else {
			expectedF1 = 0.0
		}

		// Verify precision
		if !floatEquals(metrics.Precision, expectedPrecision, 1e-9) {
			t.Logf("Precision mismatch: TP=%d, FP=%d, FN=%d, expected=%.9f, got=%.9f",
				tp, fp, fn, expectedPrecision, metrics.Precision)
			return false
		}

		// Verify recall
		if !floatEquals(metrics.Recall, expectedRecall, 1e-9) {
			t.Logf("Recall mismatch: TP=%d, FP=%d, FN=%d, expected=%.9f, got=%.9f",
				tp, fp, fn, expectedRecall, metrics.Recall)
			return false
		}

		// Verify F1 score
		if !floatEquals(metrics.F1Score, expectedF1, 1e-9) {
			t.Logf("F1 mismatch: TP=%d, FP=%d, FN=%d, expected=%.9f, got=%.9f",
				tp, fp, fn, expectedF1, metrics.F1Score)
			return false
		}

		// Verify TotalMatches
		if metrics.TotalMatches != totalMatches {
			t.Logf("TotalMatches mismatch: expected=%d, got=%d", totalMatches, metrics.TotalMatches)
			return false
		}

		return true
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Property violated: %v", err)
	}
}

// TestProperty_PrecisionFormula verifies precision calculation in isolation
//
// **Validates: Requirements 8.3**
func TestProperty_PrecisionFormula(t *testing.T) {
	config := &quick.Config{
		MaxCount: 100,
	}

	property := func(tp, fp uint8) bool {
		// Skip case where both are zero
		if tp == 0 && fp == 0 {
			return true
		}

		tracker := NewPatternTracker()
		patternID := "precision_test"

		// Record outcomes
		for i := 0; i < int(tp); i++ {
			tracker.RecordOutcome(patternID, OutcomeTruePositive)
		}
		for i := 0; i < int(fp); i++ {
			tracker.RecordOutcome(patternID, OutcomeFalsePositive)
		}

		metrics := tracker.GetMetrics(patternID)
		if metrics == nil {
			return false
		}

		// Expected: TP / (TP + FP)
		totalMatches := int(tp) + int(fp)
		var expectedPrecision float64
		if totalMatches > 0 {
			expectedPrecision = float64(tp) / float64(totalMatches)
		}

		return floatEquals(metrics.Precision, expectedPrecision, 1e-9)
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Precision formula violated: %v", err)
	}
}

// TestProperty_RecallFormula verifies recall calculation in isolation
//
// **Validates: Requirements 8.3**
func TestProperty_RecallFormula(t *testing.T) {
	config := &quick.Config{
		MaxCount: 100,
	}

	property := func(tp, fn uint8) bool {
		// Skip case where both are zero
		if tp == 0 && fn == 0 {
			return true
		}

		tracker := NewPatternTracker()
		patternID := "recall_test"

		// Record outcomes
		for i := 0; i < int(tp); i++ {
			tracker.RecordOutcome(patternID, OutcomeTruePositive)
		}
		for i := 0; i < int(fn); i++ {
			tracker.RecordOutcome(patternID, OutcomeFalseNegative)
		}

		metrics := tracker.GetMetrics(patternID)
		if metrics == nil {
			return false
		}

		// Expected: TP / (TP + FN)
		totalRelevant := int(tp) + int(fn)
		var expectedRecall float64
		if totalRelevant > 0 {
			expectedRecall = float64(tp) / float64(totalRelevant)
		}

		return floatEquals(metrics.Recall, expectedRecall, 1e-9)
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Recall formula violated: %v", err)
	}
}

// TestProperty_F1Formula verifies F1 score calculation in isolation
//
// **Validates: Requirements 8.3**
func TestProperty_F1Formula(t *testing.T) {
	config := &quick.Config{
		MaxCount: 100,
	}

	property := func(tp, fp, fn uint8) bool {
		// Skip cases where all values are zero
		if tp == 0 && fp == 0 && fn == 0 {
			return true
		}

		tracker := NewPatternTracker()
		patternID := "f1_test"

		// Record outcomes
		for i := 0; i < int(tp); i++ {
			tracker.RecordOutcome(patternID, OutcomeTruePositive)
		}
		for i := 0; i < int(fp); i++ {
			tracker.RecordOutcome(patternID, OutcomeFalsePositive)
		}
		for i := 0; i < int(fn); i++ {
			tracker.RecordOutcome(patternID, OutcomeFalseNegative)
		}

		metrics := tracker.GetMetrics(patternID)
		if metrics == nil {
			return false
		}

		// Calculate expected F1: 2 * (P * R) / (P + R)
		var expectedF1 float64
		if metrics.Precision+metrics.Recall > 0 {
			expectedF1 = 2 * (metrics.Precision * metrics.Recall) / (metrics.Precision + metrics.Recall)
		}

		return floatEquals(metrics.F1Score, expectedF1, 1e-9)
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("F1 formula violated: %v", err)
	}
}

// TestProperty_MetricsRange verifies that all metrics are in valid ranges
//
// **Validates: Requirements 8.3**
func TestProperty_MetricsRange(t *testing.T) {
	config := &quick.Config{
		MaxCount: 100,
	}

	property := func(tp, fp, fn uint8) bool {
		// Skip cases where all values are zero
		if tp == 0 && fp == 0 && fn == 0 {
			return true
		}

		tracker := NewPatternTracker()
		patternID := "range_test"

		// Record outcomes
		for i := 0; i < int(tp); i++ {
			tracker.RecordOutcome(patternID, OutcomeTruePositive)
		}
		for i := 0; i < int(fp); i++ {
			tracker.RecordOutcome(patternID, OutcomeFalsePositive)
		}
		for i := 0; i < int(fn); i++ {
			tracker.RecordOutcome(patternID, OutcomeFalseNegative)
		}

		metrics := tracker.GetMetrics(patternID)
		if metrics == nil {
			return false
		}

		// All metrics should be in [0, 1] range
		if metrics.Precision < 0 || metrics.Precision > 1 {
			t.Logf("Precision out of range: %.9f", metrics.Precision)
			return false
		}
		if metrics.Recall < 0 || metrics.Recall > 1 {
			t.Logf("Recall out of range: %.9f", metrics.Recall)
			return false
		}
		if metrics.F1Score < 0 || metrics.F1Score > 1 {
			t.Logf("F1Score out of range: %.9f", metrics.F1Score)
			return false
		}

		return true
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Metrics range property violated: %v", err)
	}
}

// TestProperty_PerfectPrecision verifies that perfect precision (no false positives)
// results in precision = 1.0
//
// **Validates: Requirements 8.3**
func TestProperty_PerfectPrecision(t *testing.T) {
	config := &quick.Config{
		MaxCount: 100,
	}

	property := func(tp uint8) bool {
		// Skip zero case
		if tp == 0 {
			return true
		}

		tracker := NewPatternTracker()
		patternID := "perfect_precision_test"

		// Record only true positives (no false positives)
		for i := 0; i < int(tp); i++ {
			tracker.RecordOutcome(patternID, OutcomeTruePositive)
		}

		metrics := tracker.GetMetrics(patternID)
		if metrics == nil {
			return false
		}

		// Precision should be 1.0 when there are no false positives
		return floatEquals(metrics.Precision, 1.0, 1e-9)
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Perfect precision property violated: %v", err)
	}
}

// TestProperty_PerfectRecall verifies that perfect recall (no false negatives)
// results in recall = 1.0
//
// **Validates: Requirements 8.3**
func TestProperty_PerfectRecall(t *testing.T) {
	config := &quick.Config{
		MaxCount: 100,
	}

	property := func(tp uint8) bool {
		// Skip zero case
		if tp == 0 {
			return true
		}

		tracker := NewPatternTracker()
		patternID := "perfect_recall_test"

		// Record only true positives (no false negatives)
		for i := 0; i < int(tp); i++ {
			tracker.RecordOutcome(patternID, OutcomeTruePositive)
		}

		metrics := tracker.GetMetrics(patternID)
		if metrics == nil {
			return false
		}

		// Recall should be 1.0 when there are no false negatives
		return floatEquals(metrics.Recall, 1.0, 1e-9)
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Perfect recall property violated: %v", err)
	}
}

// TestProperty_ZeroPrecision verifies that zero precision (no true positives)
// results in precision = 0.0
//
// **Validates: Requirements 8.3**
func TestProperty_ZeroPrecision(t *testing.T) {
	config := &quick.Config{
		MaxCount: 100,
	}

	property := func(fp uint8) bool {
		// Skip zero case
		if fp == 0 {
			return true
		}

		tracker := NewPatternTracker()
		patternID := "zero_precision_test"

		// Record only false positives (no true positives)
		for i := 0; i < int(fp); i++ {
			tracker.RecordOutcome(patternID, OutcomeFalsePositive)
		}

		metrics := tracker.GetMetrics(patternID)
		if metrics == nil {
			return false
		}

		// Precision should be 0.0 when there are no true positives
		return floatEquals(metrics.Precision, 0.0, 1e-9)
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Zero precision property violated: %v", err)
	}
}

// TestProperty_ZeroRecall verifies that zero recall (no true positives)
// results in recall = 0.0
//
// **Validates: Requirements 8.3**
func TestProperty_ZeroRecall(t *testing.T) {
	config := &quick.Config{
		MaxCount: 100,
	}

	property := func(fn uint8) bool {
		// Skip zero case
		if fn == 0 {
			return true
		}

		tracker := NewPatternTracker()
		patternID := "zero_recall_test"

		// Record only false negatives (no true positives)
		for i := 0; i < int(fn); i++ {
			tracker.RecordOutcome(patternID, OutcomeFalseNegative)
		}

		metrics := tracker.GetMetrics(patternID)
		if metrics == nil {
			return false
		}

		// Recall should be 0.0 when there are no true positives
		return floatEquals(metrics.Recall, 0.0, 1e-9)
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Zero recall property violated: %v", err)
	}
}

// floatEquals checks if two floats are equal within a tolerance
func floatEquals(a, b, tolerance float64) bool {
	// Handle NaN cases
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.IsNaN(a) && math.IsNaN(b)
	}
	// Handle infinity cases
	if math.IsInf(a, 0) || math.IsInf(b, 0) {
		return a == b
	}
	// Normal comparison with tolerance
	return math.Abs(a-b) <= tolerance
}
