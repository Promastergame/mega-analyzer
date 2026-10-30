package ml

import (
	"fmt"
	"math"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════════════
// CONCEPT DRIFT DETECTION
// ═══════════════════════════════════════════════════════════════════════════
//
// Models trained months ago drift silently as inputs evolve (new SDK
// versions, new attack patterns, new APK packing tricks). The cheapest
// reliable signal of drift is *input distribution change*: if the marginal
// of any feature shifts far enough from training, the model is operating
// out-of-domain even when it still emits confident scores.
//
// We provide two complementary detectors:
//
//   - PSI (Population Stability Index): a binned KL-divergence-like
//     summary of one feature's distribution shift relative to a reference.
//     Industry-standard threshold:  PSI < 0.1 → stable,
//     0.1 ≤ PSI < 0.25 → moderate, ≥ 0.25 → significant drift.
//   - PageHinkley: a sequential change-point detector for streaming
//     scalar metrics (e.g. mean prediction probability over a window).
//     Triggers an alert when cumulative deviation from the running mean
//     exceeds a threshold — the textbook "early warning" detector.
//
// Both are pure stdlib.

// ─── PSI: per-feature distribution shift ───────────────────────────────────

// FeatureBins describes a feature's reference distribution in fixed bins.
// Build once on training data, query on production batches.
type FeatureBins struct {
	Edges       []float64 // bin edges, ascending; length = nBins+1
	RefFraction []float64 // fraction of reference samples per bin; length = nBins
}

// BuildFeatureBins discretises `values` into equal-frequency bins and
// records the empirical fraction of samples per bin. We use quantile bins
// (instead of uniform) so PSI on heavy-tailed features (e.g. file sizes)
// remains stable.
//
// Quantile edges picked by index can collide when many samples share one
// value (e.g. a feature that is 0 for half the corpus). Duplicate edges make
// bin membership ambiguous and PSI unstable, so interior edges are deduped
// and, when the data cannot supply nBins-1 distinct cut points, the builder
// falls back to uniform bins spanning [min, max]. That keeps the bin count
// and the edges strictly ascending for every input.
func BuildFeatureBins(values []float64, nBins int) (*FeatureBins, error) {
	if nBins < 2 {
		return nil, fmt.Errorf("psi: nBins must be >= 2, got %d", nBins)
	}
	if len(values) < nBins {
		return nil, fmt.Errorf("psi: need at least %d samples, got %d", nBins, len(values))
	}
	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	// Candidate quantile cut points, deduped while preserving order.
	interior := make([]float64, 0, nBins-1)
	for i := 1; i < nBins; i++ {
		v := sorted[i*len(sorted)/nBins]
		if len(interior) == 0 || v > interior[len(interior)-1] {
			interior = append(interior, v)
		}
	}

	// Not enough distinct quantile cut points (heavy ties) → uniform bins.
	if len(interior) < nBins-1 {
		lo, hi := sorted[0], sorted[len(sorted)-1]
		if hi <= lo {
			// All values identical: pad a degenerate range so every sample
			// still lands in the middle bin deterministically.
			lo, hi = lo-0.5, hi+0.5
		}
		interior = interior[:0]
		for i := 1; i < nBins; i++ {
			interior = append(interior, lo+(hi-lo)*float64(i)/float64(nBins))
		}
	}

	edges := make([]float64, 0, nBins+1)
	edges = append(edges, math.Inf(-1))
	edges = append(edges, interior...)
	edges = append(edges, math.Inf(1))

	frac := make([]float64, len(edges)-1)
	for _, v := range values {
		b := findBin(edges, v)
		frac[b]++
	}
	for i := range frac {
		frac[i] /= float64(len(values))
	}
	return &FeatureBins{Edges: edges, RefFraction: frac}, nil
}

// MinPSIWindow is the smallest current-window size for which a PSI value is
// statistically meaningful. Below it the bin fractions are dominated by
// sampling noise, so PSI returns an error instead of a number callers could
// mistake for a drift signal.
const MinPSIWindow = 30

// PSI computes Population Stability Index of `values` against the reference
// distribution. Returns the divergence summed across bins.
//
// Formula: PSI = Σ (p_new − p_ref) × ln(p_new / p_ref).
//
// Tiny floor (1e-6) on bin fractions to avoid log(0) on empty bins —
// standard industry practice.
//
// The current window must hold at least MinPSIWindow samples; smaller
// windows return an error so downstream code never reports drift from a
// handful of observations.
func PSI(ref *FeatureBins, values []float64) (float64, error) {
	if ref == nil || len(ref.RefFraction) == 0 {
		return 0, fmt.Errorf("psi: nil reference")
	}
	if len(values) == 0 {
		return math.NaN(), nil
	}
	if len(values) < MinPSIWindow {
		return 0, fmt.Errorf("psi: current window too small: %d samples (min %d) — drift signal withheld", len(values), MinPSIWindow)
	}
	nBins := len(ref.RefFraction)
	newFrac := make([]float64, nBins)
	for _, v := range values {
		b := findBin(ref.Edges, v)
		newFrac[b]++
	}
	for i := range newFrac {
		newFrac[i] /= float64(len(values))
	}

	const eps = 1e-6
	var psi float64
	for i := 0; i < nBins; i++ {
		pRef := math.Max(eps, ref.RefFraction[i])
		pNew := math.Max(eps, newFrac[i])
		psi += (pNew - pRef) * math.Log(pNew/pRef)
	}
	return psi, nil
}

// PSIVerdict classifies a PSI value.
func PSIVerdict(psi float64) string {
	switch {
	case psi < 0.1:
		return "stable"
	case psi < 0.25:
		return "moderate_drift"
	default:
		return "significant_drift"
	}
}

func findBin(edges []float64, v float64) int {
	// Linear scan keeps things simple: edges count is small (≤ 20 typically).
	// Edges are sorted; first edge[i] strictly greater than v defines bin i-1.
	for i := 1; i < len(edges); i++ {
		if v < edges[i] {
			return i - 1
		}
	}
	return len(edges) - 2
}

// ─── Page-Hinkley: streaming mean shift ───────────────────────────────────

// PageHinkley tracks a running mean of a scalar metric and fires when the
// cumulative deviation passes `threshold`, in *either* direction.
//
// Use case: feed it the model's average predicted probability per scan
// batch. A sudden upward drift could mean the analyser started seeing many
// more "looks malicious" inputs (e.g. a new malware family); a downward
// drift could mean the model is becoming overly conservative.
//
// Two independent one-sided detectors run in parallel (the classic
// two-sided Page-Hinkley formulation):
//
//   - increase side: cumulates (x − mean − delta) and tracks its minimum;
//     alert when the cumulated sum rises above that minimum by threshold.
//   - decrease side: cumulates (mean − x − delta) — the sign-flipped
//     deviation — and references its own minimum; alert fires by the same
//     sum-minus-minimum rule, symmetric to the increase side.
//
// Parameters:
//
//   - delta: minimum change to register (insensitivity band).
//   - threshold: cumulative deviation that fires the alert.
//   - alpha: smoothing for the running mean (0 = uniform avg, 1 = forget all).
type PageHinkley struct {
	delta     float64
	threshold float64
	alpha     float64

	mean  float64
	count int
	upSum float64 // increase-side cumulative deviation
	upMin float64 // minimum of upSum so far
	dnSum float64 // decrease-side cumulative deviation (sign-flipped)
	dnMin float64 // minimum of dnSum so far

	Alerted     bool   // any alert fired (first fire returns true from Update)
	AlertedUp   bool   // an increase-side alert has fired
	AlertedDown bool   // a decrease-side alert has fired
	Direction   string // direction of the first alert: "increase" or "decrease"
}

// NewPageHinkley with sane defaults for predicted-probability streams.
func NewPageHinkley(delta, threshold float64) *PageHinkley {
	return &PageHinkley{
		delta:     delta,
		threshold: threshold,
		alpha:     0.0,
	}
}

// Reset clears state without losing config.
func (p *PageHinkley) Reset() {
	p.mean = 0
	p.count = 0
	p.upSum = 0
	p.upMin = 0
	p.dnSum = 0
	p.dnMin = 0
	p.Alerted = false
	p.AlertedUp = false
	p.AlertedDown = false
	p.Direction = ""
}

// Update folds a new scalar observation into the detector. Returns true
// when an alert is *first* triggered, in either direction. The direction of
// the shift is recorded in Direction (and AlertedUp / AlertedDown).
func (p *PageHinkley) Update(x float64) bool {
	p.count++
	if p.count == 1 {
		p.mean = x
		return false
	}
	if p.alpha > 0 {
		p.mean = (1-p.alpha)*p.mean + p.alpha*x
	} else {
		p.mean += (x - p.mean) / float64(p.count)
	}

	// Increase side: positive when x runs above the running mean.
	p.upSum += x - p.mean - p.delta
	if p.upSum < p.upMin {
		p.upMin = p.upSum
	}
	// Decrease side: the deviation is sign-flipped, so it grows positive
	// when x runs below the running mean. Both sides reference their own
	// historical minimum — the classic symmetric two-sided formulation.
	p.dnSum += p.mean - x - p.delta
	if p.dnSum < p.dnMin {
		p.dnMin = p.dnSum
	}

	if !p.AlertedUp && p.upSum-p.upMin > p.threshold {
		p.AlertedUp = true
		p.Alerted = true
		p.Direction = "increase"
		return true
	}
	if !p.AlertedDown && p.dnSum-p.dnMin > p.threshold {
		p.AlertedDown = true
		p.Alerted = true
		p.Direction = "decrease"
		return true
	}
	return false
}
