package ml

import (
	"math"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// STATIC SIGNAL CALIBRATION (v0 priors)
//
// Static-only evidence can never justify absolute certainty: every confidence
// emitted here is capped by the strength of its supporting evidence, not by
// how scary the matched name looks. A bare method-name hit ("isPro",
// "startsWith") must not report 100% Server Auth.
//
// Tiers (v0 priors — re-fit on a labeled APK corpus when one exists; the
// fitting machinery is already in the repo: Platt/Isotonic in calibration.go
// and PatchScorer.EnableTrainedCalibration):
//   - hard ceiling for any static signal: 0.95
//   - no evidence or only "method:" items, no call/literal: 0.80
//   - one distinct nonblank evidence item of any other kind: 0.85
//   - two or more distinct items (not all names): within the ceiling
//
// Repeated/blank evidence does not corroborate itself. These remain heuristic
// tiers, not empirically calibrated probabilities or proof of independence.
//
// CalibrateVulnSignals applies the tiers in place at the single aggregation
// choke point (AnalyzeVulnerabilitySignals), so ScoreBoost and every
// downstream consumer see calibrated values.
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// MaxStaticSignalConfidence is the hard ceiling: no static-only signal
	// may claim above it. Certainty requires runtime proof.
	MaxStaticSignalConfidence = 0.95
	// NameOnlyConfidenceCap applies to signals backed by nothing but
	// method names (one or more "method:" evidence items).
	NameOnlyConfidenceCap = 0.80
	// SingleEvidenceConfidenceCap applies to signals with exactly one
	// distinct, nonblank evidence item of any other kind.
	SingleEvidenceConfidenceCap = 0.85
)

// CalibrateVulnSignals clamps every signal's confidence to its evidence tier.
// It mutates the slice in place and returns it for chaining.
func CalibrateVulnSignals(signals []VulnSignal) []VulnSignal {
	for i := range signals {
		signals[i].Confidence = CalibratedSignalConfidence(
			signals[i].Confidence, signals[i].Evidence)
	}
	return signals
}

// CalibratedSignalConfidence maps a raw detector confidence to its evidence
// tier. Values already below the applicable cap pass through untouched.
func CalibratedSignalConfidence(raw float64, evidence []string) float64 {
	// Non-finite detector output is invalid, not strong evidence. In particular,
	// NaN evades ordinary comparisons and poisons aggregation/JSON encoding.
	if math.IsNaN(raw) || math.IsInf(raw, 0) {
		return 0
	}

	// Only the distinction 0 / 1 / 2+ is needed. Remembering the first item
	// avoids a map allocation on this hot path; evidence itself is not mutated.
	first := ""
	distinct := 0
	allNames := true
	for _, item := range evidence {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if distinct == 0 {
			first, distinct = item, 1
		} else if item != first {
			distinct = 2
		}
		if !strings.HasPrefix(item, "method:") {
			allNames = false
		}
	}

	cap := MaxStaticSignalConfidence
	switch {
	case distinct == 0 || allNames:
		cap = NameOnlyConfidenceCap
	case distinct == 1:
		cap = SingleEvidenceConfidenceCap
	}
	if raw > cap {
		return cap
	}
	if raw < 0 {
		return 0
	}
	return raw
}
