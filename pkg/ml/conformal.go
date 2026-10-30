package ml

import (
	"errors"
	"fmt"
	"math"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════════════
// CONFORMAL PREDICTION — distribution-free uncertainty quantification
// ═══════════════════════════════════════════════════════════════════════════
//
// Standard model output: "p = 0.85". Conformal output: "the true label is
// in the prediction set {1} with probability ≥ 0.9, and the score lies
// inside [0.78, 0.91]".
//
// The guarantee is *finite-sample* and *distribution-free*: as long as
// calibration data is exchangeable with test data, the prediction set
// covers the true label at the requested rate. There is no "if your
// model is well-specified" caveat — conformal works around the model.
//
// We implement *split conformal* (a.k.a. inductive conformal):
//
//   1. Split data into train + calibration.
//   2. Fit the model on train.
//   3. On calibration, score every example and compute non-conformity
//      scores: how "wrong" the model was on each label.
//   4. For a new input at significance α, the prediction set is every
//      label whose non-conformity score is below the (1−α) empirical
//      quantile of the calibration scores.
//
// For binary classification this collapses to one of:
//
//   - {0}        confident negative
//   - {1}        confident positive
//   - {0, 1}     ambiguous — analyst review required
//   - {}         out-of-distribution (model is so wrong nothing fits)
//
// The {0, 1} case is exactly the "uncertain" signal active learning needs,
// but with a coverage guarantee instead of an arbitrary [0.4, 0.6] band.

// ConformalPredictor holds calibration scores from a held-out set.
type ConformalPredictor struct {
	// Sorted ascending non-conformity scores from the calibration set.
	// Non-conformity score for an example with true label y and predicted
	// probability p_hat is `1 - p_hat[y]` — i.e. how much probability mass
	// the model put on the wrong class.
	calibScores []float64
}

// NewConformalPredictor constructs an unfit predictor.
func NewConformalPredictor() *ConformalPredictor { return &ConformalPredictor{} }

// Fit records non-conformity scores from the calibration set.
//
// `probs` are the model's predicted probabilities for class 1 on the
// calibration examples; `labels` are the true labels.
func (cp *ConformalPredictor) Fit(probs []float64, labels []int) error {
	if len(probs) != len(labels) {
		return fmt.Errorf("conformal: length mismatch %d vs %d", len(probs), len(labels))
	}
	if len(probs) < 10 {
		return errors.New("conformal: need at least 10 calibration samples for stable quantiles")
	}
	scores := make([]float64, len(probs))
	for i, p := range probs {
		if !validProbability(p) || (labels[i] != 0 && labels[i] != 1) {
			return fmt.Errorf("conformal: invalid probability or label at row %d", i)
		}
		// Probability mass on the *correct* class.
		var pCorrect float64
		if labels[i] == 1 {
			pCorrect = p
		} else {
			pCorrect = 1 - p
		}
		// Non-conformity = 1 − p_correct: higher means "more surprised the
		// label is what it is".
		scores[i] = 1 - pCorrect
	}
	sort.Float64s(scores)
	cp.calibScores = scores
	return nil
}

// PredictionSet is the result of a conformal query: which labels remain
// after thresholding non-conformity at the desired coverage level.
type PredictionSet struct {
	Includes0 bool    // class 0 is in the prediction set
	Includes1 bool    // class 1 is in the prediction set
	NonconfQ  float64 // the (1−α) quantile that defined the threshold

	// HeuristicFallback marks sets produced without any calibration data
	// (e.g. MondrianConformal's margin heuristic). These carry NO coverage
	// guarantee and must never be aggregated with calibrated sets in reports.
	HeuristicFallback bool
}

// IsCertain reports whether the set is a singleton.
func (s PredictionSet) IsCertain() bool {
	return s.Includes0 != s.Includes1 // exactly one of the two
}

// IsAmbiguous reports whether both classes survived → human review territory.
func (s PredictionSet) IsAmbiguous() bool { return s.Includes0 && s.Includes1 }

// IsEmpty reports an OOD prediction (no label fits).
func (s PredictionSet) IsEmpty() bool { return !s.Includes0 && !s.Includes1 }

// Predict returns the conformal prediction set at significance level α.
//
// Coverage guarantee: with probability ≥ 1−α (over the calibration draw),
// the set contains the true label. Typical α = 0.1 (90% coverage).
func (cp *ConformalPredictor) Predict(prob float64, alpha float64) (PredictionSet, error) {
	if len(cp.calibScores) == 0 {
		return PredictionSet{}, errors.New("conformal: not fit")
	}
	if !validProbability(prob) || !validSignificance(alpha) {
		return PredictionSet{}, fmt.Errorf("conformal: alpha must be in (0,1), got %f", alpha)
	}
	// Empirical (1−α) quantile of calibration scores.
	// Use the conformity-corrected index ceil((n+1)(1-α)) for the standard
	// finite-sample guarantee.
	q := conformalQuantile(cp.calibScores, alpha)

	// Non-conformity if the true label were 0 or 1.
	score0 := 1 - (1 - prob) // = prob
	score1 := 1 - prob
	return PredictionSet{
		Includes0: score0 <= q,
		Includes1: score1 <= q,
		NonconfQ:  q,
	}, nil
}

// UncertaintyGuarantee states what an UncertaintyBand actually guarantees,
// so downstream code cannot mistake a heuristic band for a statistical
// coverage interval.
type UncertaintyGuarantee string

const (
	// GuaranteeScoreBand: the band is built from the calibration set's
	// non-conformity quantile and reflects how surprised the model was on
	// calibration data. It is NOT a coverage interval for the true label or
	// the true probability — no coverage property holds.
	GuaranteeScoreBand UncertaintyGuarantee = "calibration_score_band"
	// GuaranteeFiniteCoverage: the distribution-free finite-sample (1−α)
	// coverage guarantee of split conformal prediction. Only PredictionSet
	// queries on calibrated scores carry this.
	GuaranteeFiniteCoverage UncertaintyGuarantee = "finite_sample_coverage"
	// GuaranteeNone: heuristic margin with no statistical meaning.
	GuaranteeNone UncertaintyGuarantee = "none"
)

// UncertaintyBand is an interval around a predicted probability together
// with an explicit statement of what it means. It deliberately does not
// masquerade as a probabilistic confidence interval: the only conformal
// quantity with a coverage guarantee is the PredictionSet.
type UncertaintyBand struct {
	Lo        float64              `json:"lo"`
	Hi        float64              `json:"hi"`
	Alpha     float64              `json:"alpha"`
	Guarantee UncertaintyGuarantee `json:"guarantee"`
}

// UncertaintyBand returns a band around `prob` derived from the calibration
// set's non-conformity quantile: lower = max(0, prob − q), upper =
// min(1, prob + q).
//
// The band carries GuaranteeScoreBand: it is a "model surprise" hint that
// callers can use to flag findings whose score lands near the calibration
// boundary. It is *not* a coverage interval for the true probability — for
// that, use Predict and the prediction set.
func (cp *ConformalPredictor) UncertaintyBand(prob float64, alpha float64) (UncertaintyBand, error) {
	if len(cp.calibScores) == 0 {
		return UncertaintyBand{}, errors.New("conformal: not fit")
	}
	if !validProbability(prob) || !validSignificance(alpha) {
		return UncertaintyBand{}, fmt.Errorf("conformal: alpha must be in (0,1), got %f", alpha)
	}
	q := conformalQuantile(cp.calibScores, alpha)
	return UncertaintyBand{
		Lo:        math.Max(0, prob-q),
		Hi:        math.Min(1, prob+q),
		Alpha:     alpha,
		Guarantee: GuaranteeScoreBand,
	}, nil
}

func validProbability(p float64) bool {
	return !math.IsNaN(p) && p >= 0 && p <= 1
}

func validSignificance(alpha float64) bool {
	return !math.IsNaN(alpha) && alpha > 0 && alpha < 1
}

// Scores are bounded by 1. When the corrected rank is n+1, using that
// upper bound includes both labels and remains JSON-serializable.
func conformalQuantile(sortedScores []float64, alpha float64) float64 {
	rank := int(math.Ceil(float64(len(sortedScores)+1) * (1 - alpha)))
	if rank > len(sortedScores) || rank < 1 || !validSignificance(alpha) {
		return 1
	}
	return sortedScores[rank-1]
}

// CategoryConformalConfidence is a lightweight per-category confidence band for
// reports. It is intentionally conservative when no calibration file is present:
// high-risk billing/integrity/license gates get narrower bands than noisy UI-ish
// categories, making overclaiming visible in exports.
//
// Method/Guarantee always describe how the band was produced. The heuristic
// path (fixed margins per category) never claims finite-sample coverage, so
// report consumers can filter it out instead of mixing it with calibrated
// conformal output.
type CategoryConformalConfidence struct {
	Category     PatchCategory `json:"category"`
	Coverage     float64       `json:"coverage,omitempty"` // absent without calibrated coverage
	Method       string        `json:"method"`             // "heuristic" | "conformal"
	Guarantee    string        `json:"guarantee"`          // GuaranteeNone | GuaranteeFiniteCoverage
	Lower        float64       `json:"lower"`
	Upper        float64       `json:"upper"`
	Label        string        `json:"label"`
	ReviewNeeded bool          `json:"review_needed"`
}

// EstimateCategoryConformalConfidence produces a deterministic conformal-style
// confidence interval per patch category from the calibrated confidence score.
//
// This is a heuristic margin, NOT conformal prediction: Method is "heuristic"
// and Guarantee is "none". It must stay visibly distinct from any genuinely
// calibrated output (Method "conformal", Guarantee "finite_sample_coverage")
// in reports and API responses.
func EstimateCategoryConformalConfidence(category PatchCategory, confidence float64) *CategoryConformalConfidence {
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}
	margin := 0.12
	switch category {
	case PatchCatBilling, PatchCatIntegrity, PatchCatLicense, PatchCatSignature, PatchCatPremium, PatchCatSubscription:
		margin = 0.08
	case PatchCatAds, PatchCatFeatureGate, PatchCatCurrency:
		margin = 0.14
	}
	lo := math.Max(0, confidence-margin)
	hi := math.Min(1, confidence+margin)
	label := "review"
	if lo >= 0.80 {
		label = "strong"
	} else if lo >= 0.60 {
		label = "moderate"
	} else if hi < 0.50 {
		label = "weak"
	}
	return &CategoryConformalConfidence{
		Category:     category,
		Method:       "heuristic",
		Guarantee:    string(GuaranteeNone),
		Lower:        math.Round(lo*100) / 100,
		Upper:        math.Round(hi*100) / 100,
		Label:        label,
		ReviewNeeded: label == "review" || label == "weak",
	}
}
