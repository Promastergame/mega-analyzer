package ml

import "time"

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN METRICS — Phase 4: Pattern Effectiveness Tracking
// ═══════════════════════════════════════════════════════════════════════════════
//
// This module implements pattern performance metrics tracking for the ML Patcher
// Improvements spec (Requirement 8.3).
//
// PatternMetrics tracks precision, recall, and F1 score for each pattern to
// measure pattern effectiveness and identify low-performing patterns.

// PatternMetrics tracks pattern performance metrics
type PatternMetrics struct {
	PatternID      string    `json:"pattern_id"`
	TruePositives  int       `json:"true_positives"`
	FalsePositives int       `json:"false_positives"`
	FalseNegatives int       `json:"false_negatives"`
	Precision      float64   `json:"precision"`
	Recall         float64   `json:"recall"`
	F1Score        float64   `json:"f1_score"`
	TotalMatches   int       `json:"total_matches"`
	LastUpdated    time.Time `json:"last_updated"`
}
