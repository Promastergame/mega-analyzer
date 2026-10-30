package ml

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════════════
// EVALUATION METRICS
// ═══════════════════════════════════════════════════════════════════════════
//
// Without metrics every "fix" to a classifier is faith-based. This file is
// dependency-free (math / sort / rand only) so it can run in CI alongside
// the existing analyzer build, and inside benchmarks where Cgo is off.
//
// All metrics treat label == 1 as the positive class, matching the
// LogisticRegression / RandomForest convention used elsewhere in pkg/ml.

// ConfusionMatrix is the 2×2 binary classification confusion table.
//
//	          predicted 0   predicted 1
//	actual 0      TN            FP
//	actual 1      FN            TP
type ConfusionMatrix struct {
	TP int
	FP int
	TN int
	FN int
}

// Total returns the number of samples that produced this confusion matrix.
func (c ConfusionMatrix) Total() int {
	return c.TP + c.FP + c.TN + c.FN
}

// Metrics is a snapshot of the standard binary classification scores.
//
// All values lie in [0, 1] (NaN when undefined for the given confusion
// matrix, e.g. precision when no positive predictions were made).
type Metrics struct {
	Accuracy         float64
	Precision        float64
	Recall           float64 // a.k.a. true-positive rate, sensitivity
	F1               float64
	Specificity      float64 // true-negative rate
	BalancedAcc      float64 // (TPR + TNR) / 2
	MatthewsCorrCoef float64

	// AUCROC requires probability predictions. Set to NaN when only labels
	// are available. Computed by AreaUnderROC().
	AUCROC float64

	Confusion ConfusionMatrix
}

// String renders the metrics as a compact one-line summary.
func (m Metrics) String() string {
	auc := "n/a"
	if !math.IsNaN(m.AUCROC) {
		auc = fmt.Sprintf("%.4f", m.AUCROC)
	}
	return fmt.Sprintf(
		"acc=%.4f prec=%.4f recall=%.4f f1=%.4f spec=%.4f mcc=%.4f auc=%s n=%d",
		m.Accuracy, m.Precision, m.Recall, m.F1, m.Specificity,
		m.MatthewsCorrCoef, auc, m.Confusion.Total(),
	)
}

// Confuse computes the confusion matrix from aligned predictions and labels.
// Predictions and labels must be 0 or 1.
func Confuse(yPred, yTrue []int) (ConfusionMatrix, error) {
	if len(yPred) != len(yTrue) {
		return ConfusionMatrix{}, fmt.Errorf("yPred (%d) and yTrue (%d) length mismatch", len(yPred), len(yTrue))
	}
	var c ConfusionMatrix
	for i, p := range yPred {
		t := yTrue[i]
		switch {
		case p == 1 && t == 1:
			c.TP++
		case p == 1 && t == 0:
			c.FP++
		case p == 0 && t == 0:
			c.TN++
		case p == 0 && t == 1:
			c.FN++
		default:
			return ConfusionMatrix{}, fmt.Errorf("expected 0/1 labels at idx %d, got pred=%d true=%d", i, p, t)
		}
	}
	return c, nil
}

// MetricsFromConfusion computes the scalar metrics from a confusion matrix.
// AUCROC is set to NaN; supply probabilities to AreaUnderROC for it.
func MetricsFromConfusion(c ConfusionMatrix) Metrics {
	total := c.Total()
	m := Metrics{Confusion: c, AUCROC: math.NaN()}
	if total == 0 {
		m.Accuracy = math.NaN()
		m.Precision = math.NaN()
		m.Recall = math.NaN()
		m.F1 = math.NaN()
		m.Specificity = math.NaN()
		m.BalancedAcc = math.NaN()
		m.MatthewsCorrCoef = math.NaN()
		return m
	}

	m.Accuracy = float64(c.TP+c.TN) / float64(total)

	if c.TP+c.FP > 0 {
		m.Precision = float64(c.TP) / float64(c.TP+c.FP)
	} else {
		m.Precision = math.NaN()
	}

	if c.TP+c.FN > 0 {
		m.Recall = float64(c.TP) / float64(c.TP+c.FN)
	} else {
		m.Recall = math.NaN()
	}

	if !math.IsNaN(m.Precision) && !math.IsNaN(m.Recall) && (m.Precision+m.Recall) > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	} else {
		m.F1 = math.NaN()
	}

	if c.TN+c.FP > 0 {
		m.Specificity = float64(c.TN) / float64(c.TN+c.FP)
	} else {
		m.Specificity = math.NaN()
	}

	if !math.IsNaN(m.Recall) && !math.IsNaN(m.Specificity) {
		m.BalancedAcc = (m.Recall + m.Specificity) / 2
	} else {
		m.BalancedAcc = math.NaN()
	}

	// MCC: numerically stable form using float math; denominator can
	// underflow to zero on degenerate matrices, in which case MCC = 0
	// per Matthews' original convention.
	tp := float64(c.TP)
	tn := float64(c.TN)
	fp := float64(c.FP)
	fn := float64(c.FN)
	num := tp*tn - fp*fn
	denom := math.Sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
	if denom == 0 {
		m.MatthewsCorrCoef = 0
	} else {
		m.MatthewsCorrCoef = num / denom
	}

	return m
}

// AreaUnderROC computes the AUC-ROC score from probability predictions.
//
// Implementation: rank-based formula equivalent to the Mann-Whitney U
// statistic, which avoids ROC-curve sweeping and handles ties correctly.
//
//	AUC = (sum_of_positive_ranks − n_pos*(n_pos+1)/2) / (n_pos * n_neg)
func AreaUnderROC(yProb []float64, yTrue []int) (float64, error) {
	if len(yProb) != len(yTrue) {
		return math.NaN(), fmt.Errorf("yProb (%d) and yTrue (%d) length mismatch", len(yProb), len(yTrue))
	}
	if len(yProb) == 0 {
		return math.NaN(), errors.New("empty input")
	}

	type item struct {
		score float64
		label int
		rank  float64
	}
	items := make([]item, len(yProb))
	for i := range yProb {
		items[i] = item{score: yProb[i], label: yTrue[i]}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].score < items[j].score })

	// Average ranks across ties so the U statistic is unbiased.
	i := 0
	for i < len(items) {
		j := i
		for j+1 < len(items) && items[j+1].score == items[i].score {
			j++
		}
		// Ranks are 1-indexed in the Mann-Whitney formula.
		avg := float64(i+j+2) / 2.0
		for k := i; k <= j; k++ {
			items[k].rank = avg
		}
		i = j + 1
	}

	var rankSumPos float64
	var nPos, nNeg int
	for _, it := range items {
		if it.label == 1 {
			rankSumPos += it.rank
			nPos++
		} else {
			nNeg++
		}
	}
	if nPos == 0 || nNeg == 0 {
		return math.NaN(), errors.New("AUC undefined: only one class present")
	}
	auc := (rankSumPos - float64(nPos)*float64(nPos+1)/2.0) / (float64(nPos) * float64(nNeg))
	return auc, nil
}

// AreaUnderPR computes average precision (the PR-AUC used for imbalanced
// datasets where ROC-AUC flatters a model that over-predicts the positive
// class): the precision at each positive example's threshold, averaged over
// positives.
//
//	AP = Σ_i (R_i − R_{i−1}) × P_i   over positives sorted by score desc,
//
// with R recall, P precision at that threshold. Undefined (NaN) when the
// input contains no positive or no negative example.
//
// Tied scores form a single threshold step (sklearn convention): a threshold
// cannot separate examples with equal scores, so per-item steps would make
// the result depend on input order within ties.
func AreaUnderPR(yProb []float64, yTrue []int) (float64, error) {
	if len(yProb) != len(yTrue) {
		return math.NaN(), fmt.Errorf("yProb (%d) and yTrue (%d) length mismatch", len(yProb), len(yTrue))
	}
	if len(yProb) == 0 {
		return math.NaN(), errors.New("empty input")
	}
	type item struct {
		score float64
		label int
	}
	items := make([]item, len(yProb))
	for i := range yProb {
		items[i] = item{score: yProb[i], label: yTrue[i]}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].score > items[j].score })

	var nPos, nNeg int
	for _, it := range items {
		if it.label == 1 {
			nPos++
		} else {
			nNeg++
		}
	}
	if nPos == 0 || nNeg == 0 {
		return math.NaN(), errors.New("PR-AUC undefined: only one class present")
	}

	var tp, fp int
	var ap float64
	var prevRecall float64
	for i := 0; i < len(items); {
		j := i + 1
		for j < len(items) && items[j].score == items[i].score {
			j++
		}
		for k := i; k < j; k++ {
			if items[k].label == 1 {
				tp++
			} else {
				fp++
			}
		}
		recall := float64(tp) / float64(nPos)
		precision := float64(tp) / float64(tp+fp)
		ap += (recall - prevRecall) * precision
		prevRecall = recall
		i = j
	}
	return ap, nil
}

// PrecisionAtK returns precision among the top-k highest-scoring predictions.
// Useful for security triage where analysts only inspect the top alerts.
func PrecisionAtK(yProb []float64, yTrue []int, k int) (float64, error) {
	if len(yProb) != len(yTrue) {
		return math.NaN(), fmt.Errorf("length mismatch")
	}
	if k <= 0 || k > len(yProb) {
		return math.NaN(), fmt.Errorf("k must be in (0, %d], got %d", len(yProb), k)
	}
	idx := make([]int, len(yProb))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return yProb[idx[a]] > yProb[idx[b]] })
	hits := 0
	for _, i := range idx[:k] {
		if yTrue[i] == 1 {
			hits++
		}
	}
	return float64(hits) / float64(k), nil
}

// ═══════════════════════════════════════════════════════════════════════════
// CROSS-VALIDATION
// ═══════════════════════════════════════════════════════════════════════════

// BinaryClassifier is the minimum surface a model must implement to be
// scored by k-fold CV. Both LogisticRegression and RandomForest already
// implement this; GradientBoostingClassifier (defined in gbt.go) does too.
//
// Note: only `PredictProbability` is required. The two existing models in
// this package use incompatible signatures for `Predict` (LR returns a
// probability, RF returns a class label), so EvaluateOn thresholds the
// probability itself at 0.5 to recover a class decision uniformly.
type BinaryClassifier interface {
	Fit(X [][]float64, y []int, featureNames []string) error
	PredictProbability(features []float64) (float64, error)
}

// PredictProbability is provided here as a shim so LogisticRegression
// satisfies BinaryClassifier without changing its existing public surface.
func (lr *LogisticRegression) PredictProbability(features []float64) (float64, error) {
	return lr.Predict(features)
}

// EvaluateOn runs the classifier on the given test set and returns Metrics
// including AUC-ROC. The classifier must already be fitted.
func EvaluateOn(model BinaryClassifier, X [][]float64, y []int) (Metrics, error) {
	if len(X) != len(y) {
		return Metrics{}, fmt.Errorf("X and y must have same length")
	}
	if len(X) == 0 {
		return Metrics{}, errors.New("empty test set")
	}
	yPred := make([]int, len(X))
	yProb := make([]float64, len(X))
	for i, row := range X {
		prob, err := model.PredictProbability(row)
		if err != nil {
			return Metrics{}, fmt.Errorf("predict[%d]: %w", i, err)
		}
		yProb[i] = prob
		if prob >= 0.5 {
			yPred[i] = 1
		}
	}
	c, err := Confuse(yPred, y)
	if err != nil {
		return Metrics{}, err
	}
	m := MetricsFromConfusion(c)
	if auc, err := AreaUnderROC(yProb, y); err == nil {
		m.AUCROC = auc
	}
	return m, nil
}

// CVFoldResult is a single k-fold CV outcome.
type CVFoldResult struct {
	Fold    int
	Train   int
	Test    int
	Metrics Metrics
}

// CVSummary aggregates per-fold metrics into mean ± std for each scalar.
type CVSummary struct {
	Folds []CVFoldResult
	Mean  Metrics
	Std   Metrics
}

// ModelFactory builds a fresh, untrained classifier for each CV fold.
// Required because most classifiers are stateful and refitting in place
// makes std-dev estimates correlated.
type ModelFactory func() BinaryClassifier

// KFoldCV runs stratified k-fold cross-validation. "Stratified" here means
// folds preserve the class ratio of the input — important when positives are
// rare (e.g. ~5% confirmed vulnerabilities).
//
// `featureNames` is forwarded to every Fit() call. `seed` controls the
// shuffle for reproducibility (pass 0 for non-deterministic).
func KFoldCV(factory ModelFactory, X [][]float64, y []int, featureNames []string, k int, seed int64) (*CVSummary, error) {
	if k < 2 {
		return nil, fmt.Errorf("k-fold CV needs k >= 2, got %d", k)
	}
	if len(X) != len(y) {
		return nil, fmt.Errorf("X and y must have same length")
	}
	if len(X) < k {
		return nil, fmt.Errorf("need at least k=%d samples, have %d", k, len(X))
	}

	// Stratify: bucket indices by label and round-robin into folds. This
	// keeps each fold's positive rate close to the global rate, which is
	// what users actually care about when classes are imbalanced.
	pos, neg := []int{}, []int{}
	for i, lbl := range y {
		if lbl == 1 {
			pos = append(pos, i)
		} else {
			neg = append(neg, i)
		}
	}

	var rng *rand.Rand
	if seed != 0 {
		rng = rand.New(rand.NewSource(seed))
	} else {
		rng = rand.New(rand.NewSource(rand.Int63()))
	}
	rng.Shuffle(len(pos), func(i, j int) { pos[i], pos[j] = pos[j], pos[i] })
	rng.Shuffle(len(neg), func(i, j int) { neg[i], neg[j] = neg[j], neg[i] })

	folds := make([][]int, k)
	for i, idx := range pos {
		folds[i%k] = append(folds[i%k], idx)
	}
	for i, idx := range neg {
		folds[i%k] = append(folds[i%k], idx)
	}

	summary := &CVSummary{Folds: make([]CVFoldResult, 0, k)}
	for fold := 0; fold < k; fold++ {
		testIdx := folds[fold]
		testSet := make(map[int]struct{}, len(testIdx))
		for _, i := range testIdx {
			testSet[i] = struct{}{}
		}
		var trainX [][]float64
		var trainY []int
		var testX [][]float64
		var testY []int
		for i, row := range X {
			if _, ok := testSet[i]; ok {
				testX = append(testX, row)
				testY = append(testY, y[i])
			} else {
				trainX = append(trainX, row)
				trainY = append(trainY, y[i])
			}
		}

		model := factory()
		if err := model.Fit(trainX, trainY, featureNames); err != nil {
			return nil, fmt.Errorf("fold %d: fit: %w", fold, err)
		}
		m, err := EvaluateOn(model, testX, testY)
		if err != nil {
			return nil, fmt.Errorf("fold %d: eval: %w", fold, err)
		}
		summary.Folds = append(summary.Folds, CVFoldResult{
			Fold:    fold,
			Train:   len(trainX),
			Test:    len(testX),
			Metrics: m,
		})
	}

	summary.Mean, summary.Std = aggregateCV(summary.Folds)
	return summary, nil
}

func aggregateCV(folds []CVFoldResult) (Metrics, Metrics) {
	n := float64(len(folds))
	if n == 0 {
		return Metrics{}, Metrics{}
	}
	var mean Metrics
	for _, f := range folds {
		mean.Accuracy += safeAdd(f.Metrics.Accuracy)
		mean.Precision += safeAdd(f.Metrics.Precision)
		mean.Recall += safeAdd(f.Metrics.Recall)
		mean.F1 += safeAdd(f.Metrics.F1)
		mean.Specificity += safeAdd(f.Metrics.Specificity)
		mean.BalancedAcc += safeAdd(f.Metrics.BalancedAcc)
		mean.MatthewsCorrCoef += safeAdd(f.Metrics.MatthewsCorrCoef)
		mean.AUCROC += safeAdd(f.Metrics.AUCROC)
	}
	mean.Accuracy /= n
	mean.Precision /= n
	mean.Recall /= n
	mean.F1 /= n
	mean.Specificity /= n
	mean.BalancedAcc /= n
	mean.MatthewsCorrCoef /= n
	mean.AUCROC /= n

	var std Metrics
	for _, f := range folds {
		std.Accuracy += sqDev(f.Metrics.Accuracy, mean.Accuracy)
		std.Precision += sqDev(f.Metrics.Precision, mean.Precision)
		std.Recall += sqDev(f.Metrics.Recall, mean.Recall)
		std.F1 += sqDev(f.Metrics.F1, mean.F1)
		std.Specificity += sqDev(f.Metrics.Specificity, mean.Specificity)
		std.BalancedAcc += sqDev(f.Metrics.BalancedAcc, mean.BalancedAcc)
		std.MatthewsCorrCoef += sqDev(f.Metrics.MatthewsCorrCoef, mean.MatthewsCorrCoef)
		std.AUCROC += sqDev(f.Metrics.AUCROC, mean.AUCROC)
	}
	std.Accuracy = math.Sqrt(std.Accuracy / n)
	std.Precision = math.Sqrt(std.Precision / n)
	std.Recall = math.Sqrt(std.Recall / n)
	std.F1 = math.Sqrt(std.F1 / n)
	std.Specificity = math.Sqrt(std.Specificity / n)
	std.BalancedAcc = math.Sqrt(std.BalancedAcc / n)
	std.MatthewsCorrCoef = math.Sqrt(std.MatthewsCorrCoef / n)
	std.AUCROC = math.Sqrt(std.AUCROC / n)
	return mean, std
}

func safeAdd(v float64) float64 {
	if math.IsNaN(v) {
		return 0
	}
	return v
}

func sqDev(v, m float64) float64 {
	if math.IsNaN(v) || math.IsNaN(m) {
		return 0
	}
	d := v - m
	return d * d
}
