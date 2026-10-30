package training

import (
	"fmt"

	"mega-analyzer/pkg/ml"
)

// KeywordScorer is the live-path wrapper around a trained relevance model. It
// satisfies ml.KeywordRelevanceScorer. Construct it once at startup and share
// it; after construction it is read-only and safe for concurrent use.
//
// When no model file exists, NewKeywordScorer returns a scorer whose IsLoaded()
// is false and whose ScoreKeyword always returns 0.5 (maximum uncertainty), so
// callers never need a nil check and the heuristic path stays in control.
type KeywordScorer struct {
	model *SavedModel
	lr    *ml.LogisticRegression
}

// NewKeywordScorer loads the model from the default path (~/.analyzer/models/).
func NewKeywordScorer() (*KeywordScorer, error) {
	path, err := DefaultModelPath()
	if err != nil {
		return &KeywordScorer{}, err
	}
	return NewKeywordScorerFromPath(path)
}

// NewKeywordScorerFromPath loads the model from an explicit path. A missing
// file is not an error: the returned scorer reports IsLoaded()==false.
func NewKeywordScorerFromPath(path string) (*KeywordScorer, error) {
	m, err := LoadModel(path)
	if err != nil {
		return &KeywordScorer{}, err
	}
	if m == nil {
		return &KeywordScorer{}, nil // no model on disk → no-op scorer
	}
	return newFromModel(m)
}

// NewKeywordScorerFromModel builds a scorer from an in-memory model (used right
// after Train, e.g. to report or smoke-test before persisting).
func NewKeywordScorerFromModel(m *SavedModel) (*KeywordScorer, error) {
	if m == nil {
		return &KeywordScorer{}, nil
	}
	return newFromModel(m)
}

func newFromModel(m *SavedModel) (*KeywordScorer, error) {
	lr := ml.NewLogisticRegression(0.05, 1, 0.01)
	// Reconstruct via LoadWeights with a Go-built map so the type assertions
	// inside LoadWeights ([]float64 / []string) succeed (a JSON-unmarshalled
	// map would carry []interface{} and fail).
	err := lr.LoadWeights(map[string]interface{}{
		"weights":  append([]float64(nil), m.LRWeights...),
		"bias":     m.LRBias,
		"features": append([]string(nil), m.FeatureNames...),
		"trained":  true,
	})
	if err != nil {
		return &KeywordScorer{}, fmt.Errorf("rehydrate model: %w", err)
	}
	return &KeywordScorer{model: m, lr: lr}, nil
}

// IsLoaded reports whether a trained model backs this scorer.
func (s *KeywordScorer) IsLoaded() bool { return s != nil && s.lr != nil }

// ScoreKeyword returns the calibrated probability in [0,1] that the keyword is
// relevant (not noise). Returns 0.5 when no model is loaded.
func (s *KeywordScorer) ScoreKeyword(kf *ml.KeywordFeedback) float64 {
	if !s.IsLoaded() || kf == nil {
		return 0.5
	}
	raw, err := s.lr.Predict(kf.ToFeatureVector())
	if err != nil {
		return 0.5
	}
	if s.model.CalibFitted {
		return sigmoid(s.model.CalibA*raw + s.model.CalibB)
	}
	return raw
}

// Model exposes the underlying SavedModel (nil when not loaded), for drift
// monitoring and diagnostics.
func (s *KeywordScorer) Model() *SavedModel {
	if !s.IsLoaded() {
		return nil
	}
	return s.model
}

// ModelInfo returns a one-line summary for CLI output.
func (s *KeywordScorer) ModelInfo() string {
	if !s.IsLoaded() {
		return "no model (heuristics active)"
	}
	cal := ECESummary(s.model.CalibFitted, s.model.ECE, s.model.ECESamples, s.model.ECEReliable, s.model.ECELow, s.model.ECEHigh)
	return fmt.Sprintf("v%d trained=%s samples=%d (hard=%d heuristic=%d) %s",
		s.model.Version,
		s.model.TrainedAt.Format("2006-01-02"),
		s.model.SampleCount,
		s.model.LabelCounts["hard"],
		s.model.LabelCounts["heuristic"],
		cal,
	)
}

// Compile-time assertion that KeywordScorer satisfies the consumer interface.
var _ ml.KeywordRelevanceScorer = (*KeywordScorer)(nil)
