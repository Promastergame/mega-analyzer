package ml

import (
	"errors"
	"fmt"
	"math"
)

// ═══════════════════════════════════════════════════════════════════════════
// MULTICLASS CLASSIFICATION via One-vs-Rest
// ═══════════════════════════════════════════════════════════════════════════
//
// The native binary GBT cannot tell "use_after_free" from "command_injection"
// when both are positive. For triage we need K binary models — one per
// vulnerability class — and pick the highest-probability class. This is
// the One-vs-Rest (OvR) reduction; it composes any binary classifier into
// a multiclass one without changing the underlying algorithm.
//
// Cost: K times slower training (and K models in memory). Benefit: a
// single ML pipeline that gives both "is this vulnerable?" (any class
// probability above threshold) and "if yes, which kind?" (argmax).

// MulticlassClassifier wraps K BinaryClassifier models, one per class.
type MulticlassClassifier struct {
	classes []string
	models  []BinaryClassifier
	factory ModelFactory
	trained bool
}

// NewMulticlassClassifier creates a classifier for the given classes.
//
// `factory` must produce a fresh, untrained binary classifier on each call;
// the returned classifier will fit one per class.
func NewMulticlassClassifier(classes []string, factory ModelFactory) (*MulticlassClassifier, error) {
	if len(classes) < 2 {
		return nil, errors.New("multiclass: need at least 2 classes")
	}
	if factory == nil {
		return nil, errors.New("multiclass: nil factory")
	}
	return &MulticlassClassifier{
		classes: append([]string(nil), classes...),
		factory: factory,
	}, nil
}

// Fit trains one binary classifier per class.
//
// `y` must contain integer labels in [0, len(classes)). For each class c,
// we synthesise binary labels (1 if y[i] == c, else 0) and fit a model.
func (m *MulticlassClassifier) Fit(X [][]float64, y []int, featureNames []string) error {
	if len(X) != len(y) {
		return fmt.Errorf("multiclass: X (%d) and y (%d) length mismatch", len(X), len(y))
	}
	for _, lbl := range y {
		if lbl < 0 || lbl >= len(m.classes) {
			return fmt.Errorf("multiclass: label %d out of range [0, %d)", lbl, len(m.classes))
		}
	}
	m.models = make([]BinaryClassifier, len(m.classes))
	for c := range m.classes {
		binY := make([]int, len(y))
		for i, lbl := range y {
			if lbl == c {
				binY[i] = 1
			}
		}
		mdl := m.factory()
		if err := mdl.Fit(X, binY, featureNames); err != nil {
			return fmt.Errorf("multiclass: fit class %d (%s): %w", c, m.classes[c], err)
		}
		m.models[c] = mdl
	}
	m.trained = true
	return nil
}

// PredictProbabilities returns a probability per class. The vector is
// *not* normalised to sum to 1 — OvR probabilities are independent
// estimates, and forcing them to sum can hide an "everything is unlikely"
// signal (useful for OOD detection). Pass the result through Softmax() if
// you need a proper distribution.
func (m *MulticlassClassifier) PredictProbabilities(features []float64) ([]float64, error) {
	if !m.trained {
		return nil, errors.New("multiclass: not trained")
	}
	out := make([]float64, len(m.classes))
	for c, mdl := range m.models {
		p, err := mdl.PredictProbability(features)
		if err != nil {
			return nil, fmt.Errorf("multiclass: predict class %d: %w", c, err)
		}
		out[c] = p
	}
	return out, nil
}

// Predict returns the most likely class index and its raw probability.
func (m *MulticlassClassifier) Predict(features []float64) (int, float64, error) {
	probs, err := m.PredictProbabilities(features)
	if err != nil {
		return 0, 0, err
	}
	bestIdx, bestP := 0, math.Inf(-1)
	for i, p := range probs {
		if p > bestP {
			bestIdx = i
			bestP = p
		}
	}
	return bestIdx, bestP, nil
}

// PredictName returns the human-readable class name.
func (m *MulticlassClassifier) PredictName(features []float64) (string, float64, error) {
	idx, p, err := m.Predict(features)
	if err != nil {
		return "", 0, err
	}
	return m.classes[idx], p, nil
}

// Classes exposes the registered class names in order.
func (m *MulticlassClassifier) Classes() []string {
	out := make([]string, len(m.classes))
	copy(out, m.classes)
	return out
}

// Softmax normalises a vector of independent OvR scores to a proper
// probability distribution. Use after PredictProbabilities() when callers
// need ranked ratios rather than raw confidences.
func Softmax(scores []float64) []float64 {
	out := make([]float64, len(scores))
	if len(scores) == 0 {
		return out
	}
	max := scores[0]
	for _, s := range scores {
		if s > max {
			max = s
		}
	}
	var sum float64
	for i, s := range scores {
		out[i] = math.Exp(s - max) // shifted for numerical stability
		sum += out[i]
	}
	if sum > 0 {
		for i := range out {
			out[i] /= sum
		}
	}
	return out
}
