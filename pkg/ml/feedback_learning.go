package ml

import (
	"fmt"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FEEDBACK LEARNING SYSTEM — Task 20: Integration with Pattern Effectiveness
// ═══════════════════════════════════════════════════════════════════════════════
//
// This module integrates the feedback collection system with pattern effectiveness
// analysis to enable continuous learning and improvement of pattern weights.

// PatternLearningSystem combines feedback collection with pattern effectiveness
type PatternLearningSystem struct {
	collector *FeedbackCollector
	analyzer  *PatternEffectivenessAnalyzer
}

// NewPatternLearningSystem creates a new pattern learning system
func NewPatternLearningSystem() *PatternLearningSystem {
	collector := NewFeedbackCollector()
	return &PatternLearningSystem{
		collector: collector,
		analyzer:  NewPatternEffectivenessAnalyzer(collector),
	}
}

// RecordDetection records a pattern detection with user feedback
func (pls *PatternLearningSystem) RecordDetection(
	patternID string,
	methodPath string,
	apkHash string,
	isTruePositive bool,
	isFalsePositive bool,
	causedCrash bool,
	userNotes string,
) error {
	feedback := &PatternFeedback{
		PatternID:       patternID,
		MethodPath:      methodPath,
		APKHash:         apkHash,
		IsTruePositive:  isTruePositive,
		IsFalsePositive: isFalsePositive,
		CausedCrash:     causedCrash,
		UserNotes:       userNotes,
		Timestamp:       time.Now(),
	}

	return pls.collector.RecordPatternFeedback(feedback)
}

// GetPatternEffectiveness returns effectiveness metrics for a pattern
func (pls *PatternLearningSystem) GetPatternEffectiveness(patternID string) (*PatternEffectiveness, *AggregatedPatternFeedback) {
	// Get feedback-based metrics
	feedbackMetrics := pls.collector.GetPatternFeedback(patternID)

	// Get analyzer-based metrics
	allEffectiveness := pls.analyzer.AnalyzeAll()
	analyzerMetrics := allEffectiveness[patternID]

	return analyzerMetrics, feedbackMetrics
}

// SyncFeedbackToEffectiveness updates pattern effectiveness based on feedback
func (pls *PatternLearningSystem) SyncFeedbackToEffectiveness() {
	allFeedback := pls.collector.GetAllPatternFeedback()

	for patternID, feedback := range allFeedback {
		// Find the pattern
		var targetPattern *VulnerablePattern
		for i := range VulnerablePatterns {
			if VulnerablePatterns[i].ID == patternID {
				targetPattern = &VulnerablePatterns[i]
				break
			}
		}

		if targetPattern == nil {
			continue
		}

		// Update pattern effectiveness metadata if it exists
		if targetPattern.Effectiveness == nil {
			targetPattern.Effectiveness = &PatternEffectiveness{
				PatternID: patternID,
			}
		}

		// Sync feedback data to effectiveness
		targetPattern.Effectiveness.TruePositives = feedback.TruePositives
		targetPattern.Effectiveness.FalsePositives = feedback.FalsePositives
		targetPattern.Effectiveness.CrashCount = feedback.CrashCount
		targetPattern.Effectiveness.TotalDetections = feedback.TotalDetections
		targetPattern.Effectiveness.APKsSeenIn = feedback.APKsSeenIn
		targetPattern.Effectiveness.FirstSeen = feedback.FirstSeen
		targetPattern.Effectiveness.LastSeen = feedback.LastSeen
		targetPattern.Effectiveness.LastUpdated = time.Now()

		// Recalculate rates
		targetPattern.Effectiveness.CalculateRates()
	}
}

// ApplyWeightAdjustments applies auto-calculated weight adjustments to patterns
func (pls *PatternLearningSystem) ApplyWeightAdjustments() map[string]float64 {
	adjustments := pls.collector.AutoAdjustWeights()

	for patternID, adjustment := range adjustments {
		// Find the pattern
		for i := range VulnerablePatterns {
			if VulnerablePatterns[i].ID == patternID {
				// Apply adjustment (multiplicative)
				oldWeight := VulnerablePatterns[i].Weight
				newWeight := oldWeight * (1.0 + adjustment)

				// Clamp weight to reasonable range [0.1, 2.0]
				if newWeight < 0.1 {
					newWeight = 0.1
				}
				if newWeight > 2.0 {
					newWeight = 2.0
				}

				VulnerablePatterns[i].Weight = newWeight
				break
			}
		}
	}

	return adjustments
}

// GenerateLearningReport generates a report of learning system status
func (pls *PatternLearningSystem) GenerateLearningReport() string {
	var report string

	report += "═══════════════════════════════════════════════════════════════════════════════\n"
	report += "PATTERN LEARNING SYSTEM REPORT\n"
	report += "═══════════════════════════════════════════════════════════════════════════════\n\n"

	allFeedback := pls.collector.GetAllPatternFeedback()
	report += fmt.Sprintf("Total Patterns with Feedback: %d\n\n", len(allFeedback))

	// Flagged patterns
	flagged := pls.collector.GetFlaggedPatterns()
	if len(flagged) > 0 {
		report += "⚠️  FLAGGED PATTERNS (>10 False Positives):\n"
		for _, agg := range flagged {
			report += fmt.Sprintf("  - %s: %d false positives, %.1f%% FP rate\n",
				agg.PatternID, agg.FalsePositives, agg.FalsePositiveRate*100)
			report += fmt.Sprintf("    Reason: %s\n", agg.FlagReason)
		}
		report += "\n"
	}

	// Weight adjustments
	adjustments := pls.collector.AutoAdjustWeights()
	if len(adjustments) > 0 {
		report += "📊 RECOMMENDED WEIGHT ADJUSTMENTS:\n"
		for patternID, adjustment := range adjustments {
			direction := "increase"
			if adjustment < 0 {
				direction = "decrease"
			}
			report += fmt.Sprintf("  - %s: %s by %.1f%%\n",
				patternID, direction, adjustment*100)
		}
		report += "\n"
	}

	// Pattern effectiveness summary
	report += "PATTERN EFFECTIVENESS SUMMARY:\n"
	for patternID, agg := range allFeedback {
		if agg.TotalDetections >= 20 { // Only show patterns with sufficient data
			report += fmt.Sprintf("  %s:\n", patternID)
			report += fmt.Sprintf("    Detections: %d (across %d APKs)\n",
				agg.TotalDetections, agg.APKsSeenIn)
			report += fmt.Sprintf("    True Positive Rate: %.1f%%\n",
				agg.TruePositiveRate*100)
			report += fmt.Sprintf("    False Positive Rate: %.1f%%\n",
				agg.FalsePositiveRate*100)
			report += fmt.Sprintf("    Crash Rate: %.1f%%\n",
				agg.CrashRate*100)

			if agg.IsFlagged {
				report += "    ⚠️  FLAGGED FOR REVIEW\n"
			}
			report += "\n"
		}
	}

	report += "═══════════════════════════════════════════════════════════════════════════════\n"

	return report
}
