package ml

import (
	"math"
	"sync"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FEEDBACK INTEGRATOR — Phase 4: Pattern Effectiveness Tracking
// ═══════════════════════════════════════════════════════════════════════════════
//
// This module implements feedback integration for the ML Patcher Improvements
// spec (Requirements 8.6, 12.3, 12.4, 12.5).
//
// FeedbackIntegrator uses PatternTracker metrics to automatically adjust pattern
// weights based on performance - reducing weights for low-performing patterns and
// increasing weights for high-performing patterns.

// FeedbackIntegrator applies feedback to pattern weights
type FeedbackIntegrator struct {
	tracker *PatternTracker

	mu           sync.Mutex
	baseWeights  map[string]float64
	lastAdjusted map[string]float64
}

// NewFeedbackIntegrator creates a new FeedbackIntegrator instance
func NewFeedbackIntegrator(tracker *PatternTracker) *FeedbackIntegrator {
	return &FeedbackIntegrator{
		tracker:      tracker,
		baseWeights:  make(map[string]float64),
		lastAdjusted: make(map[string]float64),
	}
}

// AdjustPatternWeights adjusts pattern weights based on effectiveness metrics
// Requirements: 8.6, 12.3, 12.4, 12.5
//
// Weight adjustment rules:
// - Precision < 0.7: multiply weight by 0.8 (reduce weight for low-performing patterns)
// - Precision > 0.9: multiply weight by 1.1 (increase weight for high-performing patterns)
// - Weights are clamped to [0.3, 2.0] range
// - Only patterns with >= 5 total matches are adjusted (insufficient data otherwise)
func (fi *FeedbackIntegrator) AdjustPatternWeights(patterns []VulnerablePattern) {
	pointers := make([]*VulnerablePattern, 0, len(patterns))
	for i := range patterns {
		pointers = append(pointers, &patterns[i])
	}
	fi.AdjustIndexedPatternWeights(pointers)
}

// AdjustIndexedPatternWeights updates the live pattern snapshot owned by a
// PatchAnalyzer. The pattern index is built from copies of the embedded
// registry, so mutating the package-level VulnerablePatterns slice does not
// affect active scoring.
func (fi *FeedbackIntegrator) AdjustIndexedPatternWeights(patterns []*VulnerablePattern) {
	if fi == nil || fi.tracker == nil {
		return
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()

	for _, pattern := range patterns {
		if pattern == nil {
			continue
		}
		metrics := fi.tracker.GetMetrics(pattern.ID)
		if metrics == nil || metrics.TotalMatches < 5 {
			continue // Not enough data
		}

		// Always calculate from the unadjusted baseline. PredictFromCandidates can
		// be called repeatedly on one predictor; compounding the same evidence on
		// every call drives weights to a clamp even though no new label arrived.
		base, known := fi.baseWeights[pattern.ID]
		last, wasAdjusted := fi.lastAdjusted[pattern.ID]
		if !known || (wasAdjusted && math.Abs(pattern.Weight-last) > 1e-12) {
			base = pattern.Weight
			fi.baseWeights[pattern.ID] = base
		}

		multiplier := 1.0
		if metrics.Precision < 0.7 {
			multiplier = 0.8
		} else if metrics.Precision > 0.9 {
			multiplier = 1.1
		}

		// Clamp weight to reasonable range [0.3, 2.0]
		pattern.Weight = math.Max(0.3, math.Min(2.0, base*multiplier))
		fi.lastAdjusted[pattern.ID] = pattern.Weight
	}
}
