package ml

import (
	"math"

	"mega-analyzer/pkg/ml/anomaly"
)

// AnomalyScorer is the small interface implemented by anomaly detectors used
// to re-rank methods. Keeping the interface local lets callers inject the
// existing pkg/ml/anomaly.Detector without coupling the hot path to a concrete
// model type.
type AnomalyScorer interface {
	Score([]float64) float64
}

// methodMLFeatures produces a stable, low-dimensional vector for an optional
// unsupervised model. Values are bounded where possible so a detector cannot
// dominate the heuristic scorer merely because one method is unusually large.
func methodMLFeatures(mi *MethodInfo, result *ScoreResult) []float64 {
	if mi == nil {
		return nil
	}
	calls := float64(len(mi.Calls))
	securityCalls := float64(len(mi.SecurityCalls))
	stringsCount := float64(len(mi.StringConsts))
	securityStrings := float64(len(mi.SecurityStrings))
	return []float64{
		math.Min(float64(mi.InstructionCount)/100.0, 1.0),
		math.Min(float64(mi.RegisterCount)/32.0, 1.0),
		math.Min(calls/32.0, 1.0),
		math.Min(securityCalls/16.0, 1.0),
		math.Min(stringsCount/32.0, 1.0),
		math.Min(securityStrings/16.0, 1.0),
		boolFloat(mi.ReturnsBoolean),
		boolFloat(mi.HasDualReturn),
		boolFloat(mi.IsObfuscated()),
		math.Min(result.BaseScore/100.0, 1.0),
	}
}

func boolFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

// IsObfuscated is intentionally tiny and defensive: MethodInfo has no direct
// obfuscation field, so use the same cheap indicators available to the scorer.
func (mi *MethodInfo) IsObfuscated() bool {
	if mi == nil {
		return false
	}
	return len(mi.Name) <= 2 && len(mi.ClassName) > 0
}

// ═══════════════════════════════════════════════════════════════════════════
// ISOLATION FOREST — runtime integration
// ═══════════════════════════════════════════════════════════════════════════

// BuildAnomalyTrainingMatrix materialises a feature matrix from paired methods
// and their score results, using the exact same bounded feature layout the hot
// path feeds to the detector at inference time. Rows with mismatched pairing
// or nil entries are skipped so training never sees ragged vectors.
func BuildAnomalyTrainingMatrix(methods []*MethodInfo, results []*ScoreResult) [][]float64 {
	n := len(methods)
	if len(results) < n {
		n = len(results)
	}
	out := make([][]float64, 0, n)
	for i := 0; i < n; i++ {
		if methods[i] == nil || results[i] == nil {
			continue
		}
		out = append(out, methodMLFeatures(methods[i], results[i]))
	}
	return out
}

// NewIsolationForestScorer trains an IsolationForest on the given matrix and
// returns it as an AnomalyScorer ready for PatchScorer.SetAnomalyScorer. The
// forest's Score already returns a [0,1] anomaly score, matching the interface.
func NewIsolationForestScorer(training [][]float64, cfg anomaly.IsolationForestConfig) (AnomalyScorer, error) {
	forest := anomaly.NewIsolationForest(cfg)
	if err := forest.Fit(training); err != nil {
		return nil, err
	}
	return forest, nil
}

// NewDefaultIsolationForestScorer is the one-call path: build the training
// matrix from scored methods and fit a forest with canonical hyperparameters.
func NewDefaultIsolationForestScorer(methods []*MethodInfo, results []*ScoreResult) (AnomalyScorer, error) {
	matrix := BuildAnomalyTrainingMatrix(methods, results)
	return NewIsolationForestScorer(matrix, anomaly.DefaultIsolationForestConfig())
}

// ═══════════════════════════════════════════════════════════════════════════
// STACKED META — training from real scored data
// ═══════════════════════════════════════════════════════════════════════════

// metaFeatureVector builds the 4-signal vector the scorer uses for meta
// re-ranking. Kept in one place so training and inference never drift apart.
func metaFeatureVector(result *ScoreResult, maxScore float64) []float64 {
	if maxScore < 1.0 {
		maxScore = 1.0
	}
	return []float64{
		result.FinalScore / maxScore,
		result.Confidence,
		math.Min(float64(len(result.MatchedSignals))/8.0, 1.0),
		result.AnomalyScore,
	}
}

// TrainStackedMeta fits a StackedMeta combiner on real scored results with
// {0,1} ground-truth labels (1 = truly patch-worthy). Returns nil when inputs
// are empty or misaligned so callers can fall back to heuristic confidence.
func TrainStackedMeta(results []*ScoreResult, labels []int, maxScore float64) *StackedMeta {
	if len(results) == 0 || len(results) != len(labels) {
		return nil
	}
	X := make([][]float64, len(results))
	for i, r := range results {
		if r == nil {
			return nil
		}
		X[i] = metaFeatureVector(r, maxScore)
	}
	meta := NewStackedMeta(4)
	meta.Fit(X, labels)
	return meta
}
