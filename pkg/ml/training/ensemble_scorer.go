package training

import (
	"fmt"
	"math"

	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/ml/ensemble"
)

// EnsembleModelScorer is the live-path wrapper around a trained ensemble risk model.
// It satisfies ml.TrainedRiskScorer. When no model file exists, IsLoaded() is false
// and Score returns (0, false), allowing seamless fallback to pure heuristics.
type EnsembleModelScorer struct {
	model  *EnsembleSavedModel
	scaler *ml.StandardScaler
	lr     *ml.LogisticRegression
}

// NewEnsembleModelScorer loads the ensemble model from the default path (~/.analyzer/models/ensemble_risk.json).
func NewEnsembleModelScorer() (*EnsembleModelScorer, error) {
	path, err := DefaultEnsembleModelPath()
	if err != nil {
		return &EnsembleModelScorer{}, err
	}
	return NewEnsembleModelScorerFromPath(path)
}

// NewEnsembleModelScorerFromPath loads the model from an explicit path. A missing
// file is not an error: the returned scorer reports IsLoaded()==false.
func NewEnsembleModelScorerFromPath(path string) (*EnsembleModelScorer, error) {
	m, err := LoadEnsembleModel(path)
	if err != nil {
		return &EnsembleModelScorer{}, err
	}
	if m == nil {
		return &EnsembleModelScorer{}, nil // no model on disk -> no-op scorer
	}
	return newEnsembleFromModel(m)
}

// NewEnsembleModelScorerFromModel builds a scorer from an in-memory model (used right
// after TrainEnsemble, e.g. to report or smoke-test before persisting).
func NewEnsembleModelScorerFromModel(m *EnsembleSavedModel) (*EnsembleModelScorer, error) {
	if m == nil {
		return &EnsembleModelScorer{}, nil
	}
	return newEnsembleFromModel(m)
}

func newEnsembleFromModel(m *EnsembleSavedModel) (*EnsembleModelScorer, error) {
	if err := validateEnsembleSchema(m); err != nil {
		return &EnsembleModelScorer{}, err
	}
	lr := ml.NewLogisticRegression(0.05, 1, 0.01)
	err := lr.LoadWeights(map[string]interface{}{
		"weights":  append([]float64(nil), m.LRWeights...),
		"bias":     m.LRBias,
		"features": append([]string(nil), m.FeatureNames...),
		"trained":  true,
	})
	if err != nil {
		return &EnsembleModelScorer{}, fmt.Errorf("rehydrate ensemble model: %w", err)
	}
	scaler := &ml.StandardScaler{
		Means:   append([]float64(nil), m.ScalerMeans...),
		StdDevs: append([]float64(nil), m.ScalerStdDevs...),
	}
	return &EnsembleModelScorer{model: m, scaler: scaler, lr: lr}, nil
}

// validateEnsembleSchema rejects corrupted or schema-drifted models before
// they can score. Score() applies weights positionally to Flatten() output,
// so a renamed, reordered or truncated schema silently shifts every
// prediction (measured ±0.5 on a single adjacent swap); a missing scaler
// degrades to unscaled passthrough in StandardScaler.Transform with the
// same effect. Refusing to load drops back to heuristics via IsLoaded(),
// which is the designed safe path — never a shifted model.
func validateEnsembleSchema(m *EnsembleSavedModel) error {
	if m == nil {
		return fmt.Errorf("ensemble model is nil")
	}
	want := ensemble.FeatureNames
	if len(m.FeatureNames) != len(want) {
		return fmt.Errorf("ensemble feature schema length mismatch: file=%d want=%d",
			len(m.FeatureNames), len(want))
	}
	for i, name := range want {
		if m.FeatureNames[i] != name {
			return fmt.Errorf("ensemble feature schema drift at position %d: file=%q want=%q",
				i, m.FeatureNames[i], name)
		}
	}
	n := len(want)
	if len(m.LRWeights) != n {
		return fmt.Errorf("ensemble weights length mismatch: file=%d want=%d",
			len(m.LRWeights), n)
	}
	if len(m.ScalerMeans) != n || len(m.ScalerStdDevs) != n {
		return fmt.Errorf("ensemble scaler length mismatch: means=%d stddevs=%d want=%d",
			len(m.ScalerMeans), len(m.ScalerStdDevs), n)
	}
	for i := 0; i < n; i++ {
		for value, what := range map[float64]string{
			m.LRWeights[i]:     fmt.Sprintf("weight[%d]", i),
			m.ScalerMeans[i]:   fmt.Sprintf("scaler mean[%d]", i),
			m.ScalerStdDevs[i]: fmt.Sprintf("scaler stddev[%d]", i),
		} {
			if math.IsNaN(value) || math.IsInf(value, 0) {
				return fmt.Errorf("ensemble %s is non-finite", what)
			}
		}
		if m.ScalerStdDevs[i] < 0 {
			return fmt.Errorf("ensemble scaler stddev[%d] is negative (%v): corrupt file",
				i, m.ScalerStdDevs[i])
		}
	}
	if math.IsNaN(m.LRBias) || math.IsInf(m.LRBias, 0) {
		return fmt.Errorf("ensemble bias is non-finite")
	}
	return nil
}
// IsLoaded reports whether a trained model backs this scorer.
func (s *EnsembleModelScorer) IsLoaded() bool { return s != nil && s.lr != nil && s.scaler != nil }

// Score computes the risk probability for given features using the trained model.
func (s *EnsembleModelScorer) Score(f ensemble.Features) (float64, bool) {
	if !s.IsLoaded() {
		return 0, false
	}
	x := f.Flatten()
	xScaled := s.scaler.Transform(x)
	raw, err := s.lr.Predict(xScaled)
	if err != nil {
		return 0, false
	}
	if s.model.CalibFitted {
		return sigmoid(s.model.CalibA*raw + s.model.CalibB), true
	}
	return raw, true
}

// Model exposes the underlying EnsembleSavedModel (nil when not loaded).
func (s *EnsembleModelScorer) Model() *EnsembleSavedModel {
	if !s.IsLoaded() {
		return nil
	}
	return s.model
}

// ModelInfo returns a one-line summary for CLI output.
func (s *EnsembleModelScorer) ModelInfo() string {
	if !s.IsLoaded() {
		return "no ensemble model (heuristics active)"
	}
	cal := ECESummary(s.model.CalibFitted, s.model.ECE, s.model.ECESamples, s.model.ECEReliable, s.model.ECELow, s.model.ECEHigh)
	return fmt.Sprintf("v%d trained=%s samples=%d (pos=%d neg=%d) %s",
		s.model.Version,
		s.model.TrainedAt.Format("2006-01-02"),
		s.model.SampleCount,
		s.model.Positives,
		s.model.Negatives,
		cal,
	)
}

// Compile-time assertion that EnsembleModelScorer satisfies the consumer interface.
var _ ml.TrainedRiskScorer = (*EnsembleModelScorer)(nil)
