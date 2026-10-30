package vulnscan

import "math"

// Confidence signal identifiers. Each carries a signed weight; the aggregate
// (clamped to 0..1) becomes the finding's confidence score. This replaces the
// old binary "reported or not" model with graded Confirmed/Probable/Suspect
// tiers.
const (
	SigReflectedVerbatim   = "reflected_verbatim"    // payload echoed in HTML text
	SigExecutableContext   = "executable_context"    // payload in <script>/event handler
	SigDifferentialOnly    = "differential_only"     // response diverges only when injected
	SigMultiPayloadTrigger = "multi_payload_trigger" // several payloads of a class trigger
	SigOASTCallback        = "oast_callback"         // out-of-band interaction received
	SigSingleVariantOnly   = "single_variant_only"   // only one variant fired (maybe benign)
	SigErrorSignature      = "error_signature"       // backend error surfaced
	SigTimingAnomaly       = "timing_anomaly"        // statistically significant delay
)

var signalWeights = map[string]float64{
	SigReflectedVerbatim:   0.5,
	SigExecutableContext:   0.3,
	SigDifferentialOnly:    0.3,
	SigMultiPayloadTrigger: 0.15,
	SigOASTCallback:        0.6,
	SigErrorSignature:      0.4,
	SigTimingAnomaly:       0.35,
	SigSingleVariantOnly:   -0.2,
}

// ScoreConfidence aggregates weighted signals into a 0..1 confidence value.
func ScoreConfidence(signals []string) float64 {
	var score float64
	for _, s := range signals {
		score += signalWeights[s]
	}
	return math.Max(0, math.Min(score, 1.0))
}

// ApplyConfidence records signals on a finding and recomputes its score and
// tier from the FULL accumulated signal set. There is deliberately no floor
// or ratchet: negative signals (e.g. SigSingleVariantOnly) must be able to
// lower confidence, and a thin signal set must not inherit a high score from
// elsewhere. Signals accumulate on f.Signals, so repeated calls refine
// instead of resetting.
func ApplyConfidence(f *Finding, signals ...string) {
	if len(signals) > 0 {
		f.Signals = append(f.Signals, signals...)
	}
	f.Confidence = ScoreConfidence(f.Signals)
	f.Tier = TierForScore(f.Confidence)
}

// MeetsThreshold reports whether a finding's confidence clears the configured
// reporting threshold (used to tune signal-to-noise per scan).
func (f Finding) MeetsThreshold(threshold float64) bool {
	return f.Confidence >= threshold
}
