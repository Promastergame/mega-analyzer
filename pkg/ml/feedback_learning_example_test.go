package ml

import (
	"fmt"
)

// Example demonstrates the complete feedback learning workflow
func ExamplePatternLearningSystem() {
	// Create a new pattern learning system
	pls := NewPatternLearningSystem()

	// Simulate pattern detections with user feedback
	// Pattern 1: High-quality pattern (80% TP rate)
	for i := 0; i < 20; i++ {
		pls.RecordDetection(
			"BILLING_CHECK_001",
			"com/example/billing/Validator.checkPurchase()Z",
			fmt.Sprintf("apk_%d", i),
			i < 16,  // 16 true positives
			i >= 16, // 4 false positives
			false,
			"Billing verification check",
		)
	}

	// Pattern 2: Low-quality pattern (40% TP rate)
	for i := 0; i < 20; i++ {
		pls.RecordDetection(
			"WEAK_PATTERN_002",
			"com/example/util/Helper.isValid()Z",
			fmt.Sprintf("apk_%d", i),
			i < 8,  // 8 true positives
			i >= 8, // 12 false positives
			false,
			"Generic validation check",
		)
	}

	// Get pattern effectiveness
	_, feedback1 := pls.GetPatternEffectiveness("BILLING_CHECK_001")
	fmt.Printf("Pattern 1 TP Rate: %.0f%%\n", feedback1.TruePositiveRate*100)

	_, feedback2 := pls.GetPatternEffectiveness("WEAK_PATTERN_002")
	fmt.Printf("Pattern 2 TP Rate: %.0f%%\n", feedback2.TruePositiveRate*100)

	// Check for flagged patterns
	flagged := pls.collector.GetFlaggedPatterns()
	fmt.Printf("Flagged patterns: %d\n", len(flagged))

	// Get weight adjustments
	adjustments := pls.collector.AutoAdjustWeights()

	// Sort pattern IDs for consistent output
	patternIDs := []string{"BILLING_CHECK_001", "WEAK_PATTERN_002"}
	for _, patternID := range patternIDs {
		if adj, ok := adjustments[patternID]; ok {
			direction := "increase"
			if adj < 0 {
				direction = "decrease"
			}
			fmt.Printf("%s: %s weight\n", patternID, direction)
		}
	}

	// Output:
	// Pattern 1 TP Rate: 80%
	// Pattern 2 TP Rate: 40%
	// Flagged patterns: 1
	// BILLING_CHECK_001: increase weight
	// WEAK_PATTERN_002: decrease weight
}

// Example demonstrates crash tracking
func ExampleFeedbackCollector_crashTracking() {
	fc := NewFeedbackCollector()

	// Record detections with some crashes
	for i := 0; i < 25; i++ {
		feedback := &PatternFeedback{
			PatternID:      "CRASH_PRONE_PATTERN",
			MethodPath:     "com/example/Test.method()V",
			APKHash:        fmt.Sprintf("apk_%d", i),
			IsTruePositive: true,
			CausedCrash:    i < 3, // 3 crashes out of 25 = 12%
		}
		fc.RecordPatternFeedback(feedback)
	}

	agg := fc.GetPatternFeedback("CRASH_PRONE_PATTERN")
	fmt.Printf("Crash rate: %.0f%%\n", agg.CrashRate*100)

	// Check if weight should be adjusted
	adjustments := fc.AutoAdjustWeights()
	if adj, ok := adjustments["CRASH_PRONE_PATTERN"]; ok {
		if adj < 0 {
			fmt.Println("Weight should be decreased due to high crash rate")
		}
	}

	// Output:
	// Crash rate: 12%
	// Weight should be decreased due to high crash rate
}

// Example demonstrates pattern flagging
func ExampleFeedbackCollector_patternFlagging() {
	fc := NewFeedbackCollector()

	// Record many false positives
	for i := 0; i < 15; i++ {
		feedback := &PatternFeedback{
			PatternID:       "NOISY_PATTERN",
			MethodPath:      "com/example/Test.method()V",
			APKHash:         fmt.Sprintf("apk_%d", i),
			IsFalsePositive: true,
		}
		fc.RecordPatternFeedback(feedback)
	}

	agg := fc.GetPatternFeedback("NOISY_PATTERN")
	if agg.IsFlagged {
		fmt.Println("Pattern is flagged for review")
		fmt.Printf("False positives: %d\n", agg.FalsePositives)
	}

	// Output:
	// Pattern is flagged for review
	// False positives: 15
}
