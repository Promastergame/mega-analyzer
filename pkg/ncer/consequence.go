package ncer

import "mega-analyzer/pkg/internal/types"

// consequenceWeight maps a types.Severity to the weight it contributes to
// ConsequenceScore. Weights climb steeply with severity so that a single
// critical finding dominates a session full of low-severity noise, matching
// how a human triaging a report would read it.
func consequenceWeight(sev types.Severity) float64 {
	switch sev {
	case types.SeverityCritical:
		return 1.0
	case types.SeverityHigh:
		return 0.75
	case types.SeverityMedium:
		return 0.4
	case types.SeverityLow:
		return 0.15
	default:
		return 0.0
	}
}

// ConsequenceScore computes the DConsequence discrepancy from a set of
// AnomalyFindings using a noisy-OR aggregation over per-finding weights,
// where each finding's weight is the maximum of its severity-derived weight
// and its own Score (already in [0, 1] — see types.AnomalyFinding). Returns
// 0.0 for an empty slice.
//
// Noisy-OR (1 - Π(1 - wᵢ)) is used deliberately instead of a mean: a session
// is "as bad as its worst finding, and a little worse for each additional
// one." A single critical finding (weight 1.0) drives the score to 1.0 and
// dominates any amount of low-severity noise — the mean would instead dilute
// it toward zero, which contradicts how a human triaging a report reads it
// (one critical hit is not made less serious by a hundred informational
// ones). The dimension answers "how bad were this session's other findings,"
// not "how bad was this specific NCER effect" — see the DConsequence field
// doc on types.NcerCausalResult for why no finer-grained binding is possible
// with today's data.
func ConsequenceScore(findings []types.AnomalyFinding) float32 {
	if len(findings) == 0 {
		return 0.0
	}

	// Noisy-OR: track the product of complements (1 - wᵢ); the score is its
	// complement. Any single wᵢ == 1.0 forces the product to 0, so the score
	// saturates at 1.0 regardless of the other findings.
	complement := 1.0
	for _, f := range findings {
		w := consequenceWeight(f.Severity)
		if f.Score > w {
			w = f.Score
		}
		if w < 0 {
			w = 0
		}
		if w > 1.0 {
			w = 1.0
		}
		complement *= (1.0 - w)
	}

	score := 1.0 - complement
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return float32(score)
}

// scoreConsequence fills in result.DConsequence, the DiscrepancyVector
// sub-dimension Rust never computes because it depends on AnomalyFinding
// data that never crosses the Go/Rust FFI boundary.
//
// Populated from findings attached via SetAnomalyFindings; if none were
// attached, DConsequence stays 0.0 (absent, not a genuine "no consequence"
// measurement — consistent with how Rust documents its own always-zero
// placeholder fields).
func (c *Collector) scoreConsequence(result *types.NcerCausalResult) {
	c.mu.Lock()
	findings := c.anomalyFindings
	c.mu.Unlock()

	result.DConsequence = ConsequenceScore(findings)
}
