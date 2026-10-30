package deobfmetrics

import (
	"errors"
	"fmt"
)

// MetricWeights controls the relative importance of each metric in the
// composite OverallConfidence score. Weights need not sum to 1; they are
// normalized at compute time.
type MetricWeights struct {
	Entropy          float64
	Identifiers      float64
	CFGFlattening    float64
	OpaquePredicates float64
	Cyclomatic       float64
	Strings          float64
	Reflection       float64
	DeadCode         float64
}

// ErrInvalidWeights is returned when weights are unusable (negative or all
// zero).
var ErrInvalidWeights = errors.New("deobfmetrics: invalid weights")

// DefaultWeights returns balanced, production-tuned weights.
func DefaultWeights() MetricWeights {
	return MetricWeights{
		Entropy:          0.15,
		Identifiers:      0.25,
		CFGFlattening:    0.15,
		OpaquePredicates: 0.10,
		Cyclomatic:       0.10,
		Strings:          0.10,
		Reflection:       0.10,
		DeadCode:         0.05,
	}
}

// Sum returns the total of all weights.
func (w MetricWeights) Sum() float64 {
	return w.Entropy + w.Identifiers + w.CFGFlattening + w.OpaquePredicates +
		w.Cyclomatic + w.Strings + w.Reflection + w.DeadCode
}

// Validate ensures no weight is negative and at least one is positive.
func (w MetricWeights) Validate() error {
	fields := []struct {
		name string
		val  float64
	}{
		{"entropy", w.Entropy},
		{"identifiers", w.Identifiers},
		{"cfg_flattening", w.CFGFlattening},
		{"opaque_predicates", w.OpaquePredicates},
		{"cyclomatic", w.Cyclomatic},
		{"strings", w.Strings},
		{"reflection", w.Reflection},
		{"dead_code", w.DeadCode},
	}
	for _, f := range fields {
		if f.val < 0 {
			return fmt.Errorf("%w: %s is negative (%g)", ErrInvalidWeights, f.name, f.val)
		}
	}
	if w.Sum() <= 0 {
		return fmt.Errorf("%w: total weight must be positive", ErrInvalidWeights)
	}
	return nil
}

// Normalized returns a copy of the weights scaled so they sum to 1.
// It assumes Validate has already passed.
func (w MetricWeights) Normalized() MetricWeights {
	sum := w.Sum()
	if sum <= 0 {
		return w
	}
	return MetricWeights{
		Entropy:          w.Entropy / sum,
		Identifiers:      w.Identifiers / sum,
		CFGFlattening:    w.CFGFlattening / sum,
		OpaquePredicates: w.OpaquePredicates / sum,
		Cyclomatic:       w.Cyclomatic / sum,
		Strings:          w.Strings / sum,
		Reflection:       w.Reflection / sum,
		DeadCode:         w.DeadCode / sum,
	}
}
