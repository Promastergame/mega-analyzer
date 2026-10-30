package ml

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════════════
// PROBABILITY CALIBRATION — Platt scaling and isotonic regression
// ═══════════════════════════════════════════════════════════════════════════
//
// Why we need this:
//
// Tree ensembles (RF, GBT) and even regularised logistic regression produce
// scores that are *order-correct* but not *calibrated*. A model claiming
// "p = 0.8" might really mean "in this region, ~60% of items are positive".
// Every downstream decision that thresholds at 0.5 — including the active-
// learning uncertainty band [0.4, 0.6] — relies on the score actually being
// a probability. Without calibration, "low confidence" becomes a guess.
//
// Two methods are provided:
//
//   - PlattCalibrator: fits a 1-parameter sigmoid (a*p + b) on a holdout
//     calibration set. Cheap, parametric, good when the miscalibration
//     curve is roughly sigmoidal.
//   - IsotonicCalibrator: fits a non-parametric monotonic step function
//     via the Pool Adjacent Violators (PAV) algorithm. Heavier (O(n log n)
//     per fit) but handles arbitrary monotonic miscalibrations including
//     the bowl-shaped distortions that GBT exhibits.
//
// Both implement Calibrator. Pure stdlib (math + sort).

// Calibrator maps a raw model score to a calibrated probability.
type Calibrator interface {
	// Fit learns the calibration on (rawScores, labels).
	Fit(rawScores []float64, labels []int) error
	// Calibrate maps a single raw score to a calibrated probability in [0, 1].
	Calibrate(rawScore float64) float64
}

// ─── Platt scaling ─────────────────────────────────────────────────────────

// PlattCalibrator learns scalars (a, b) such that
//
//	calibrated = sigmoid(a * raw + b)
//
// Equivalent to fitting a 1-feature LR on the model's raw outputs against
// the binary labels. The fit reuses the LogisticRegression in this package
// so the full early-stopping / regularisation logic is shared.
type PlattCalibrator struct {
	a       float64
	b       float64
	trained bool
}

// NewPlattCalibrator creates an unfit calibrator.
func NewPlattCalibrator() *PlattCalibrator { return &PlattCalibrator{} }

// Fit learns (a, b) from a calibration set. The caller is expected to use
// a *holdout* set the model never saw — fitting on training scores
// produces overconfident calibrators.
func (p *PlattCalibrator) Fit(rawScores []float64, labels []int) error {
	if len(rawScores) != len(labels) {
		return fmt.Errorf("platt: length mismatch %d vs %d", len(rawScores), len(labels))
	}
	if len(rawScores) < 2 {
		return errors.New("platt: need at least 2 samples")
	}

	X := make([][]float64, len(rawScores))
	for i, s := range rawScores {
		X[i] = []float64{s}
	}
	lr := NewLogisticRegression(0.5, 200, 0.001)
	lr.WithEarlyStopping(1e-6, 10)
	if err := lr.Fit(X, labels, []string{"raw"}); err != nil {
		return fmt.Errorf("platt: inner fit: %w", err)
	}
	p.a = lr.weights[0]
	p.b = lr.bias
	p.trained = true
	return nil
}

// Calibrate maps a raw score through the learned sigmoid.
func (p *PlattCalibrator) Calibrate(rawScore float64) float64 {
	if !p.trained {
		return rawScore
	}
	return sigmoid(p.a*rawScore + p.b)
}

// Coefficients returns the learned (a, b) — useful for diagnostics.
func (p *PlattCalibrator) Coefficients() (float64, float64) { return p.a, p.b }

// ─── Isotonic regression (Pool Adjacent Violators) ─────────────────────────

// IsotonicCalibrator fits a piecewise-constant non-decreasing step
// function via PAV. Constant inside each "block", monotonic across blocks.
//
// Lookup is O(log n) via binary search over breakpoints.
type IsotonicCalibrator struct {
	breakpoints []float64 // sorted ascending raw scores
	values      []float64 // calibrated probabilities, same length as breakpoints
	trained     bool
}

// NewIsotonicCalibrator creates an unfit calibrator.
func NewIsotonicCalibrator() *IsotonicCalibrator { return &IsotonicCalibrator{} }

// Fit runs Pool Adjacent Violators on (rawScores, labels).
//
// Algorithm sketch:
//
//  1. Sort by rawScore ascending.
//  2. Initialise each label as its own "block" with weight 1.
//  3. While any adjacent pair of blocks violates monotonicity (left.value >
//     right.value), merge them: weighted-mean of values, sum of weights.
//  4. Block boundaries become breakpoints; block values become outputs.
//
// Implementation uses an explicit stack to keep the inner loop O(n) on
// already-sorted input (each block is pushed once and merged at most once).
func (iso *IsotonicCalibrator) Fit(rawScores []float64, labels []int) error {
	if len(rawScores) != len(labels) {
		return fmt.Errorf("isotonic: length mismatch %d vs %d", len(rawScores), len(labels))
	}
	if len(rawScores) == 0 {
		return errors.New("isotonic: empty input")
	}

	// 1) sort by score
	idx := make([]int, len(rawScores))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return rawScores[idx[a]] < rawScores[idx[b]] })

	// 2) build the PAV stack: each entry is (sumValues, weight, scoreLow, scoreHigh)
	type block struct {
		sum    float64
		weight float64
		lo, hi float64 // raw-score range covered by this block
	}
	stack := make([]block, 0, len(rawScores))

	push := func(s float64, lbl int) {
		b := block{sum: float64(lbl), weight: 1, lo: s, hi: s}
		stack = append(stack, b)
		// Merge while monotonicity is violated: a "right" block with lower
		// average than the block to its left must be folded into it.
		for len(stack) >= 2 {
			top := &stack[len(stack)-1]
			prev := &stack[len(stack)-2]
			topAvg := top.sum / top.weight
			prevAvg := prev.sum / prev.weight
			if prevAvg <= topAvg {
				break
			}
			prev.sum += top.sum
			prev.weight += top.weight
			prev.hi = top.hi
			stack = stack[:len(stack)-1]
		}
	}
	for _, k := range idx {
		push(rawScores[k], labels[k])
	}

	// 3) emit breakpoints + values. Use the high end of each block as the
	//    breakpoint so a query at exactly `hi` lands in this block.
	iso.breakpoints = make([]float64, len(stack))
	iso.values = make([]float64, len(stack))
	for i, b := range stack {
		iso.breakpoints[i] = b.hi
		iso.values[i] = b.sum / b.weight
	}
	iso.trained = true
	return nil
}

// Calibrate maps a raw score to the value of its enclosing block.
//
// For raw scores below all breakpoints, returns the first block's value.
// For raw scores above all breakpoints, returns the last block's value.
// This is the standard "clip to nearest" extrapolation; it cannot be
// monotonic-broken because both endpoints are themselves block values.
func (iso *IsotonicCalibrator) Calibrate(rawScore float64) float64 {
	if !iso.trained || len(iso.breakpoints) == 0 {
		return rawScore
	}
	// Binary search for the smallest breakpoint >= rawScore.
	i := sort.SearchFloat64s(iso.breakpoints, rawScore)
	if i >= len(iso.breakpoints) {
		i = len(iso.breakpoints) - 1
	}
	v := iso.values[i]
	if v < 0 {
		v = 0
	} else if v > 1 {
		v = 1
	}
	return v
}

// Breakpoints returns a copy of the learned breakpoints (for diagnostics).
func (iso *IsotonicCalibrator) Breakpoints() ([]float64, []float64) {
	bp := make([]float64, len(iso.breakpoints))
	v := make([]float64, len(iso.values))
	copy(bp, iso.breakpoints)
	copy(v, iso.values)
	return bp, v
}

// ─── Reliability diagnostics ───────────────────────────────────────────────

// ReliabilityBin is one bucket on the calibration plot.
type ReliabilityBin struct {
	Lo, Hi      float64 // raw probability range covered
	Count       int     // number of predictions in this bucket
	MeanPredict float64 // average predicted probability
	Fraction    float64 // observed fraction of positives
}

// ReliabilityDiagram bins predictions by predicted probability and reports
// (avg predicted, observed positive rate) per bin. A perfectly calibrated
// model has MeanPredict ≈ Fraction in every bin.
//
// Used to *measure* miscalibration before/after fitting a Calibrator.
func ReliabilityDiagram(probs []float64, labels []int, nBins int) ([]ReliabilityBin, error) {
	if len(probs) != len(labels) {
		return nil, fmt.Errorf("reliability: length mismatch")
	}
	if nBins < 2 {
		nBins = 10
	}
	bins := make([]ReliabilityBin, nBins)
	for i := range bins {
		bins[i].Lo = float64(i) / float64(nBins)
		bins[i].Hi = float64(i+1) / float64(nBins)
	}
	for i, p := range probs {
		bin := int(p * float64(nBins))
		if bin >= nBins {
			bin = nBins - 1
		}
		if bin < 0 {
			bin = 0
		}
		bins[bin].Count++
		bins[bin].MeanPredict += p
		if labels[i] == 1 {
			bins[bin].Fraction++
		}
	}
	for i := range bins {
		if bins[i].Count > 0 {
			bins[i].MeanPredict /= float64(bins[i].Count)
			bins[i].Fraction /= float64(bins[i].Count)
		}
	}
	return bins, nil
}

// ExpectedCalibrationError computes the standard ECE: sum of bin-weighted
// |predicted − observed|. Lower is better; 0 = perfect calibration.
func ExpectedCalibrationError(probs []float64, labels []int, nBins int) (float64, error) {
	bins, err := ReliabilityDiagram(probs, labels, nBins)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, b := range bins {
		total += b.Count
	}
	if total == 0 {
		return math.NaN(), nil
	}
	var ece float64
	for _, b := range bins {
		if b.Count == 0 {
			continue
		}
		ece += float64(b.Count) / float64(total) * math.Abs(b.MeanPredict-b.Fraction)
	}
	return ece, nil
}

// ECEConfidenceInterval is a point estimate of ECE plus a bootstrap
// confidence interval. On small calibration sets the point estimate alone is
// misleading — two draws of 20 samples can differ by tens of ECE points —
// so every persisted metric should travel with its interval.
type ECEConfidenceInterval struct {
	ECE        float64 // point estimate on the full sample
	Lower      float64 // 2.5th percentile of bootstrap replicates
	Upper      float64 // 97.5th percentile of bootstrap replicates
	Samples    int     // number of samples the estimate is based on
	Replicates int     // bootstrap resamples actually used
}

// BootstrapECE computes ECE with a bootstrap confidence interval by
// resampling (probs, labels) pairs with replacement `replicates` times
// (deterministic for a given seed). A replicate can fail validation only in
// pathological cases; failed replicates are skipped, and if none succeed the
// interval is degenerate (Lower=Upper=ECE).
func BootstrapECE(probs []float64, labels []int, nBins, replicates int, seed int64) (ECEConfidenceInterval, error) {
	var out ECEConfidenceInterval
	point, err := ExpectedCalibrationError(probs, labels, nBins)
	if err != nil {
		return out, err
	}
	if math.IsNaN(point) {
		return out, fmt.Errorf("bootstrap ece: no valid point estimate")
	}
	out.ECE = point
	out.Samples = len(probs)
	if replicates < 1 {
		replicates = 1
	}
	out.Replicates = replicates

	rng := rand.New(rand.NewSource(seed))
	lows := make([]float64, 0, replicates)
	for r := 0; r < replicates; r++ {
		bp := make([]float64, len(probs))
		bl := make([]int, len(labels))
		for i := range probs {
			j := rng.Intn(len(probs))
			bp[i] = probs[j]
			bl[i] = labels[j]
		}
		e, err := ExpectedCalibrationError(bp, bl, nBins)
		if err != nil || math.IsNaN(e) {
			continue
		}
		lows = append(lows, e)
	}
	if len(lows) == 0 {
		out.Lower, out.Upper = point, point
		return out, nil
	}
	sort.Float64s(lows)
	out.Lower = lows[int(0.025*float64(len(lows)-1))]
	out.Upper = lows[int(0.975*float64(len(lows)-1))]
	return out, nil
}
