package ml

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN FEEDBACK TESTS — Task 20.1
// ═══════════════════════════════════════════════════════════════════════════════

func TestRecordPatternFeedback_Success(t *testing.T) {
	fc := NewFeedbackCollector()

	feedback := &PatternFeedback{
		PatternID:       "TEST_PATTERN_001",
		MethodPath:      "com/example/Test.method()V",
		APKHash:         "abc123",
		IsTruePositive:  true,
		IsFalsePositive: false,
		CausedCrash:     false,
		UserNotes:       "Correctly detected billing check",
	}

	err := fc.RecordPatternFeedback(feedback)
	if err != nil {
		t.Fatalf("RecordPatternFeedback failed: %v", err)
	}

	// Verify feedback was recorded
	agg := fc.GetPatternFeedback("TEST_PATTERN_001")
	if agg == nil {
		t.Fatal("Pattern feedback not found")
	}

	if agg.TotalDetections != 1 {
		t.Errorf("Expected 1 detection, got %d", agg.TotalDetections)
	}
	if agg.TruePositives != 1 {
		t.Errorf("Expected 1 true positive, got %d", agg.TruePositives)
	}
	if agg.FalsePositives != 0 {
		t.Errorf("Expected 0 false positives, got %d", agg.FalsePositives)
	}
}

func TestRecordPatternFeedback_NilFeedback(t *testing.T) {
	fc := NewFeedbackCollector()

	err := fc.RecordPatternFeedback(nil)
	if err == nil {
		t.Error("Expected error for nil feedback")
	}
}

func TestRecordPatternFeedback_EmptyPatternID(t *testing.T) {
	fc := NewFeedbackCollector()

	feedback := &PatternFeedback{
		PatternID:  "",
		MethodPath: "com/example/Test.method()V",
	}

	err := fc.RecordPatternFeedback(feedback)
	if err == nil {
		t.Error("Expected error for empty pattern ID")
	}
}

func TestRecordPatternFeedback_CrashTracking(t *testing.T) {
	fc := NewFeedbackCollector()

	// Record multiple feedbacks with crashes
	for i := 0; i < 5; i++ {
		feedback := &PatternFeedback{
			PatternID:   "CRASH_PATTERN",
			MethodPath:  "com/example/Test.method()V",
			APKHash:     "abc123",
			CausedCrash: i < 2, // First 2 cause crashes
		}
		fc.RecordPatternFeedback(feedback)
	}

	agg := fc.GetPatternFeedback("CRASH_PATTERN")
	if agg.CrashCount != 2 {
		t.Errorf("Expected 2 crashes, got %d", agg.CrashCount)
	}
	if agg.CrashRate != 0.4 { // 2/5 = 0.4
		t.Errorf("Expected crash rate 0.4, got %f", agg.CrashRate)
	}
}

func TestRecordPatternFeedback_UniqueAPKTracking(t *testing.T) {
	fc := NewFeedbackCollector()

	// Record feedbacks from same APK
	for i := 0; i < 3; i++ {
		feedback := &PatternFeedback{
			PatternID:  "TEST_PATTERN",
			MethodPath: "com/example/Test.method()V",
			APKHash:    "same_apk",
		}
		fc.RecordPatternFeedback(feedback)
	}

	// Record feedback from different APK
	feedback := &PatternFeedback{
		PatternID:  "TEST_PATTERN",
		MethodPath: "com/example/Test.method()V",
		APKHash:    "different_apk",
	}
	fc.RecordPatternFeedback(feedback)

	agg := fc.GetPatternFeedback("TEST_PATTERN")
	if agg.APKsSeenIn != 2 {
		t.Errorf("Expected 2 unique APKs, got %d", agg.APKsSeenIn)
	}
	if agg.TotalDetections != 4 {
		t.Errorf("Expected 4 total detections, got %d", agg.TotalDetections)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGGREGATED FEEDBACK TESTS — Task 20.2
// ═══════════════════════════════════════════════════════════════════════════════

func TestAggregatedPatternFeedback_CalculateRates(t *testing.T) {
	agg := &AggregatedPatternFeedback{
		TruePositives:   80,
		FalsePositives:  20,
		TotalDetections: 100,
		CrashCount:      5,
	}

	agg.CalculateRates()

	expectedTPRate := 0.8 // 80/100
	if agg.TruePositiveRate != expectedTPRate {
		t.Errorf("Expected TP rate %f, got %f", expectedTPRate, agg.TruePositiveRate)
	}

	expectedFPRate := 0.2 // 20/100
	if agg.FalsePositiveRate != expectedFPRate {
		t.Errorf("Expected FP rate %f, got %f", expectedFPRate, agg.FalsePositiveRate)
	}

	expectedCrashRate := 0.05 // 5/100
	if agg.CrashRate != expectedCrashRate {
		t.Errorf("Expected crash rate %f, got %f", expectedCrashRate, agg.CrashRate)
	}
}

func TestAggregatedPatternFeedback_CalculateRates_ZeroDetections(t *testing.T) {
	agg := &AggregatedPatternFeedback{
		TruePositives:   0,
		FalsePositives:  0,
		TotalDetections: 0,
		CrashCount:      0,
	}

	agg.CalculateRates()

	if agg.TruePositiveRate != 0.0 {
		t.Errorf("Expected TP rate 0.0, got %f", agg.TruePositiveRate)
	}
	if agg.FalsePositiveRate != 0.0 {
		t.Errorf("Expected FP rate 0.0, got %f", agg.FalsePositiveRate)
	}
	if agg.CrashRate != 0.0 {
		t.Errorf("Expected crash rate 0.0, got %f", agg.CrashRate)
	}
}

func TestGetPatternFeedback_NotFound(t *testing.T) {
	fc := NewFeedbackCollector()

	agg := fc.GetPatternFeedback("NONEXISTENT_PATTERN")
	if agg != nil {
		t.Error("Expected nil for nonexistent pattern")
	}
}

func TestPatternFlagging_MoreThan10FalsePositives(t *testing.T) {
	fc := NewFeedbackCollector()

	// Record 15 false positives
	for i := 0; i < 15; i++ {
		feedback := &PatternFeedback{
			PatternID:       "BAD_PATTERN",
			MethodPath:      "com/example/Test.method()V",
			APKHash:         "apk_" + string(rune(i)),
			IsFalsePositive: true,
		}
		fc.RecordPatternFeedback(feedback)
	}

	agg := fc.GetPatternFeedback("BAD_PATTERN")
	if !agg.IsFlagged {
		t.Error("Pattern should be flagged after >10 false positives")
	}
	if agg.FlagReason == "" {
		t.Error("Flag reason should be set")
	}
}

func TestPatternFlagging_LessThan10FalsePositives(t *testing.T) {
	fc := NewFeedbackCollector()

	// Record 5 false positives
	for i := 0; i < 5; i++ {
		feedback := &PatternFeedback{
			PatternID:       "OK_PATTERN",
			MethodPath:      "com/example/Test.method()V",
			IsFalsePositive: true,
		}
		fc.RecordPatternFeedback(feedback)
	}

	agg := fc.GetPatternFeedback("OK_PATTERN")
	if agg.IsFlagged {
		t.Error("Pattern should not be flagged with <10 false positives")
	}
}

func TestGetFlaggedPatterns(t *testing.T) {
	fc := NewFeedbackCollector()

	// Create one flagged pattern
	for i := 0; i < 15; i++ {
		feedback := &PatternFeedback{
			PatternID:       "FLAGGED_PATTERN",
			MethodPath:      "com/example/Test.method()V",
			IsFalsePositive: true,
		}
		fc.RecordPatternFeedback(feedback)
	}

	// Create one non-flagged pattern
	for i := 0; i < 5; i++ {
		feedback := &PatternFeedback{
			PatternID:      "OK_PATTERN",
			MethodPath:     "com/example/Test.method()V",
			IsTruePositive: true,
		}
		fc.RecordPatternFeedback(feedback)
	}

	flagged := fc.GetFlaggedPatterns()
	if len(flagged) != 1 {
		t.Errorf("Expected 1 flagged pattern, got %d", len(flagged))
	}
	if flagged[0].PatternID != "FLAGGED_PATTERN" {
		t.Errorf("Expected FLAGGED_PATTERN, got %s", flagged[0].PatternID)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTO-WEIGHT ADJUSTMENT TESTS — Task 20.3
// ═══════════════════════════════════════════════════════════════════════════════

func TestAutoAdjustWeights_InsufficientData(t *testing.T) {
	fc := NewFeedbackCollector()

	// Record only 10 feedbacks (less than minimum 20)
	for i := 0; i < 10; i++ {
		feedback := &PatternFeedback{
			PatternID:      "TEST_PATTERN",
			MethodPath:     "com/example/Test.method()V",
			IsTruePositive: true,
		}
		fc.RecordPatternFeedback(feedback)
	}

	adjustments := fc.AutoAdjustWeights()
	if len(adjustments) != 0 {
		t.Error("Should not adjust weights with insufficient data")
	}
}

func TestAutoAdjustWeights_HighTPRate(t *testing.T) {
	fc := NewFeedbackCollector()

	// Record 25 feedbacks with 85% TP rate (21 TP, 4 FP)
	for i := 0; i < 21; i++ {
		feedback := &PatternFeedback{
			PatternID:      "GOOD_PATTERN",
			MethodPath:     "com/example/Test.method()V",
			IsTruePositive: true,
		}
		fc.RecordPatternFeedback(feedback)
	}
	for i := 0; i < 4; i++ {
		feedback := &PatternFeedback{
			PatternID:       "GOOD_PATTERN",
			MethodPath:      "com/example/Test.method()V",
			IsFalsePositive: true,
		}
		fc.RecordPatternFeedback(feedback)
	}

	adjustments := fc.AutoAdjustWeights()
	adjustment, ok := adjustments["GOOD_PATTERN"]
	if !ok {
		t.Fatal("Expected adjustment for GOOD_PATTERN")
	}
	if adjustment <= 0 {
		t.Errorf("Expected positive adjustment, got %f", adjustment)
	}
}

func TestAutoAdjustWeights_LowTPRate(t *testing.T) {
	fc := NewFeedbackCollector()

	// Record 25 feedbacks with 40% TP rate (10 TP, 15 FP)
	for i := 0; i < 10; i++ {
		feedback := &PatternFeedback{
			PatternID:      "BAD_PATTERN",
			MethodPath:     "com/example/Test.method()V",
			IsTruePositive: true,
		}
		fc.RecordPatternFeedback(feedback)
	}
	for i := 0; i < 15; i++ {
		feedback := &PatternFeedback{
			PatternID:       "BAD_PATTERN",
			MethodPath:      "com/example/Test.method()V",
			IsFalsePositive: true,
		}
		fc.RecordPatternFeedback(feedback)
	}

	adjustments := fc.AutoAdjustWeights()
	adjustment, ok := adjustments["BAD_PATTERN"]
	if !ok {
		t.Fatal("Expected adjustment for BAD_PATTERN")
	}
	if adjustment >= 0 {
		t.Errorf("Expected negative adjustment, got %f", adjustment)
	}
}

func TestAutoAdjustWeights_HighCrashRate(t *testing.T) {
	fc := NewFeedbackCollector()

	// Record 25 feedbacks with 15% crash rate
	for i := 0; i < 25; i++ {
		feedback := &PatternFeedback{
			PatternID:      "CRASH_PATTERN",
			MethodPath:     "com/example/Test.method()V",
			IsTruePositive: true,
			CausedCrash:    i < 4, // 4 crashes out of 25 = 16%
		}
		fc.RecordPatternFeedback(feedback)
	}

	adjustments := fc.AutoAdjustWeights()
	adjustment, ok := adjustments["CRASH_PATTERN"]
	if !ok {
		t.Fatal("Expected adjustment for CRASH_PATTERN")
	}
	if adjustment >= 0 {
		t.Errorf("Expected negative adjustment for high crash rate, got %f", adjustment)
	}
}

func TestAutoAdjustWeights_MultiplePatterns(t *testing.T) {
	fc := NewFeedbackCollector()

	// Good pattern (85% TP rate)
	for i := 0; i < 21; i++ {
		fc.RecordPatternFeedback(&PatternFeedback{
			PatternID:      "GOOD_PATTERN",
			MethodPath:     "com/example/Test.method()V",
			IsTruePositive: true,
		})
	}
	for i := 0; i < 4; i++ {
		fc.RecordPatternFeedback(&PatternFeedback{
			PatternID:       "GOOD_PATTERN",
			MethodPath:      "com/example/Test.method()V",
			IsFalsePositive: true,
		})
	}

	// Bad pattern (40% TP rate)
	for i := 0; i < 10; i++ {
		fc.RecordPatternFeedback(&PatternFeedback{
			PatternID:      "BAD_PATTERN",
			MethodPath:     "com/example/Test.method()V",
			IsTruePositive: true,
		})
	}
	for i := 0; i < 15; i++ {
		fc.RecordPatternFeedback(&PatternFeedback{
			PatternID:       "BAD_PATTERN",
			MethodPath:      "com/example/Test.method()V",
			IsFalsePositive: true,
		})
	}

	adjustments := fc.AutoAdjustWeights()
	if len(adjustments) != 2 {
		t.Errorf("Expected 2 adjustments, got %d", len(adjustments))
	}

	goodAdj := adjustments["GOOD_PATTERN"]
	badAdj := adjustments["BAD_PATTERN"]

	if goodAdj <= 0 {
		t.Errorf("Expected positive adjustment for GOOD_PATTERN, got %f", goodAdj)
	}
	if badAdj >= 0 {
		t.Errorf("Expected negative adjustment for BAD_PATTERN, got %f", badAdj)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN LEARNING SYSTEM TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestPatternLearningSystem_RecordDetection(t *testing.T) {
	pls := NewPatternLearningSystem()

	err := pls.RecordDetection(
		"TEST_PATTERN",
		"com/example/Test.method()V",
		"abc123",
		true,  // true positive
		false, // not false positive
		false, // no crash
		"Test detection",
	)

	if err != nil {
		t.Fatalf("RecordDetection failed: %v", err)
	}

	_, feedback := pls.GetPatternEffectiveness("TEST_PATTERN")
	if feedback == nil {
		t.Fatal("Pattern feedback not found")
	}
	if feedback.TruePositives != 1 {
		t.Errorf("Expected 1 true positive, got %d", feedback.TruePositives)
	}
}

func TestPatternLearningSystem_GenerateLearningReport(t *testing.T) {
	pls := NewPatternLearningSystem()

	// Record some feedback
	for i := 0; i < 25; i++ {
		pls.RecordDetection(
			"TEST_PATTERN",
			"com/example/Test.method()V",
			"apk_"+string(rune(i)),
			i < 20, // 20 TP, 5 FP
			i >= 20,
			false,
			"",
		)
	}

	report := pls.GenerateLearningReport()
	if report == "" {
		t.Error("Report should not be empty")
	}

	// Report should contain key sections
	if !contains(report, "PATTERN LEARNING SYSTEM REPORT") {
		t.Error("Report should contain title")
	}
	if !contains(report, "PATTERN EFFECTIVENESS SUMMARY") {
		t.Error("Report should contain effectiveness summary")
	}
}

func TestPatternLearningSystem_ApplyWeightAdjustments(t *testing.T) {
	pls := NewPatternLearningSystem()

	// Find a real pattern to test with
	if len(VulnerablePatterns) == 0 {
		t.Skip("No patterns available for testing")
	}

	testPatternID := VulnerablePatterns[0].ID
	originalWeight := VulnerablePatterns[0].Weight
	defer func() { VulnerablePatterns[0].Weight = originalWeight }()

	// Record feedback that should increase weight (high TP rate)
	for i := 0; i < 25; i++ {
		pls.RecordDetection(
			testPatternID,
			"com/example/Test.method()V",
			"apk_"+string(rune(i)),
			i < 21, // 21 TP, 4 FP = 84% TP rate
			i >= 21,
			false,
			"",
		)
	}

	pls.ApplyWeightAdjustments()

	// Check if weight was adjusted
	newWeight := VulnerablePatterns[0].Weight
	if newWeight == originalWeight {
		t.Error("Weight should have been adjusted")
	}
}

func TestPatternLearningSystem_WeightClamping(t *testing.T) {
	pls := NewPatternLearningSystem()

	if len(VulnerablePatterns) == 0 {
		t.Skip("No patterns available for testing")
	}

	testPatternID := VulnerablePatterns[0].ID
	originalWeight := VulnerablePatterns[0].Weight
	defer func() { VulnerablePatterns[0].Weight = originalWeight }()

	// Set a very low weight
	VulnerablePatterns[0].Weight = 0.05

	// Record feedback that should decrease weight further
	for i := 0; i < 25; i++ {
		pls.RecordDetection(
			testPatternID,
			"com/example/Test.method()V",
			"apk_"+string(rune(i)),
			i < 5, // 5 TP, 20 FP = 20% TP rate (very bad)
			i >= 5,
			false,
			"",
		)
	}

	pls.ApplyWeightAdjustments()

	// Weight should be clamped to minimum 0.1
	if VulnerablePatterns[0].Weight < 0.1 {
		t.Errorf("Weight should be clamped to minimum 0.1, got %f", VulnerablePatterns[0].Weight)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
