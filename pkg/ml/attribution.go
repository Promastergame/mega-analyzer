package ml

import (
	"math"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════════════
// FEATURE ATTRIBUTION — explain why the model predicted what it predicted
// ═══════════════════════════════════════════════════════════════════════════
//
// "The model says 0.85" is unactionable. "The model says 0.85, and 60% of
// the score came from `hdc.command_injection.jaccard`, 25% from
// `cyclomatic_complexity`, 10% from `string_density`, rest noise" lets the
// analyst either trust the finding or notice that it fired for the wrong
// reason.
//
// Two implementations:
//
//   - ExplainLR(): for LogisticRegression, the contribution of feature j
//     is exactly `weights[j] * x[j]` — Shapley value coincides with the
//     linear contribution under the linear-model assumption. Cheap,
//     mathematically clean, no approximation.
//
//   - ExplainGBT(): for tree ensembles, we use a *path-decomposition*
//     attribution: walk every tree from root to leaf for the input, and
//     credit each feature with the change-in-prediction caused by its
//     split. This is the same trick `xgboost`'s "predict-contrib" mode
//     uses, sometimes called "Saabas attribution". It's not the full
//     TreeSHAP algorithm (which is O(LD²) and ~150 more lines), but it's
//     consistent enough that aggregating across many predictions gives
//     stable global feature importance.

// Attribution is one feature's contribution to a single prediction.
type Attribution struct {
	FeatureIdx      int
	FeatureName     string
	Value           float64 // raw feature value
	Contribution    float64 // signed contribution to the score
	AbsContribution float64
}

// AttributionReport is the full breakdown for one prediction.
type AttributionReport struct {
	BaseScore     float64       // intercept / model prior
	RawScore      float64       // base + sum(contributions)
	Probability   float64       // sigmoid(RawScore) for log-odds models
	Contributions []Attribution // sorted by AbsContribution descending
}

// TopK returns up to k highest-magnitude contributions.
func (r *AttributionReport) TopK(k int) []Attribution {
	if k > len(r.Contributions) {
		k = len(r.Contributions)
	}
	out := make([]Attribution, k)
	copy(out, r.Contributions[:k])
	return out
}

// ─── Linear (LR) attribution ───────────────────────────────────────────────

// ExplainLR computes per-feature contributions for a logistic regression
// prediction. For LR this is exact: the model is linear in features, so
// the contribution of feature j to the logit is simply weights[j] * x[j].
func ExplainLR(lr *LogisticRegression, features []float64) (*AttributionReport, error) {
	if !lr.trained {
		return nil, errLR("model not trained yet")
	}
	if len(features) != len(lr.weights) {
		return nil, errLR("feature count mismatch")
	}

	contribs := make([]Attribution, len(features))
	rawSum := lr.bias
	for i, x := range features {
		c := lr.weights[i] * x
		rawSum += c
		name := "feature_" + itoa(i)
		if i < len(lr.featureNames) {
			name = lr.featureNames[i]
		}
		contribs[i] = Attribution{
			FeatureIdx:      i,
			FeatureName:     name,
			Value:           x,
			Contribution:    c,
			AbsContribution: math.Abs(c),
		}
	}
	sort.Slice(contribs, func(i, j int) bool {
		return contribs[i].AbsContribution > contribs[j].AbsContribution
	})
	return &AttributionReport{
		BaseScore:     lr.bias,
		RawScore:      rawSum,
		Probability:   sigmoid(rawSum),
		Contributions: contribs,
	}, nil
}

// ─── Tree-ensemble (GBT) attribution ───────────────────────────────────────

// ExplainGBT computes path-decomposition attributions for a GBT prediction.
//
// For each tree in the ensemble, we walk root → leaf for the input.
// At every internal node, we compute the *expected* prediction we would
// have made if the input had taken the *other* branch (using the
// subtree's average leaf value as a stand-in), and credit the difference
// to the splitting feature. This is the approximation `xgboost`'s
// `predict(pred_contribs=True)` uses and matches Saabas (2014).
//
// Limitations vs full TreeSHAP:
//   - Per-prediction attribution is consistent (sums to RawScore − base).
//   - Global aggregation (summing across many predictions) is biased toward
//     features used at shallow nodes. For pure ranking of "most important
//     features overall" use a held-out validation set, not training data.
func ExplainGBT(g *GradientBoostingClassifier, features []float64) (*AttributionReport, error) {
	if !g.trained {
		return nil, errGBT("model not trained yet")
	}
	if len(features) == 0 {
		return nil, errGBT("empty feature vector")
	}

	nFeatures := guessNumFeatures(g.featureNames, features)
	contribs := make([]float64, nFeatures)
	var baseShift float64

	for _, tree := range g.trees {
		// `walkAndAttribute` decomposes the tree's contribution into
		// per-feature deltas that telescope to (leaf_value − root_mean).
		// The missing root_mean piece is constant per tree and must be
		// folded back into the base score so contributions sum cleanly to
		// (raw_score − base).
		rootMean := subtreeMean(tree)
		baseShift += g.LearningRate * rootMean
		walkAndAttribute(tree, features, contribs, g.LearningRate)
	}

	rawSum := g.initLogit
	for _, c := range contribs {
		rawSum += c
	}
	rawSum += baseShift
	report := &AttributionReport{
		BaseScore:     g.initLogit + baseShift,
		RawScore:      rawSum,
		Probability:   sigmoid(rawSum),
		Contributions: make([]Attribution, len(contribs)),
	}
	for i, c := range contribs {
		name := "feature_" + itoa(i)
		if i < len(g.featureNames) {
			name = g.featureNames[i]
		}
		val := 0.0
		if i < len(features) {
			val = features[i]
		}
		report.Contributions[i] = Attribution{
			FeatureIdx:      i,
			FeatureName:     name,
			Value:           val,
			Contribution:    c,
			AbsContribution: math.Abs(c),
		}
	}
	sort.Slice(report.Contributions, func(i, j int) bool {
		return report.Contributions[i].AbsContribution > report.Contributions[j].AbsContribution
	})
	return report, nil
}

// walkAndAttribute walks the tree along the path the input takes. At each
// split, it credits the splitting feature with the change in subtree mean
// caused by going to the chosen branch. Saabas (2014) decomposition:
//
//	contribution(feature) = mean(taken subtree) − mean(current node)
//
// Summed across the path this telescopes to (leaf_value − root_mean), so
// across the whole ensemble the contributions add up to (raw_score −
// initLogit). That's the consistency check the test asserts.
//
// Multiplied by the GBT learning rate so contributions sum cleanly to the
// tree's contribution to the ensemble score.
func walkAndAttribute(node *regNode, features []float64, contribs []float64, lr float64) {
	if node.isLeaf {
		return
	}
	currentMean := subtreeMean(node)
	var taken *regNode
	if features[node.featureIdx] <= node.threshold {
		taken = node.left
	} else {
		taken = node.right
	}
	takenMean := subtreeMean(taken)
	contribs[node.featureIdx] += lr * (takenMean - currentMean)

	walkAndAttribute(taken, features, contribs, lr)
}

// subtreeMean computes the average leaf value across all leaves in the
// subtree rooted at `node`. Uses a small recursive helper; trees are
// shallow (typical maxDepth ≤ 6) so stack pressure is negligible.
func subtreeMean(node *regNode) float64 {
	if node.isLeaf {
		return node.value
	}
	sum, n := subtreeSum(node)
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

func subtreeSum(node *regNode) (float64, int) {
	if node.isLeaf {
		return node.value, 1
	}
	ls, ln := subtreeSum(node.left)
	rs, rn := subtreeSum(node.right)
	return ls + rs, ln + rn
}

// ─── Helpers ───────────────────────────────────────────────────────────────

func guessNumFeatures(names []string, vec []float64) int {
	if len(names) > 0 {
		return len(names)
	}
	return len(vec)
}

func errLR(msg string) error  { return fmtErr("logistic_regression: " + msg) }
func errGBT(msg string) error { return fmtErr("gradient_boosting: " + msg) }

// fmtErr is a tiny helper to keep package imports tidy without pulling in
// fmt.Errorf every time. Falls back to a plain string error.
func fmtErr(s string) error { return &smallError{s: s} }

type smallError struct{ s string }

func (e *smallError) Error() string { return e.s }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
