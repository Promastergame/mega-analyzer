package ml

import (
	"math/rand"
	"testing"
)

func TestConformalCoverageMeetsGuarantee(t *testing.T) {
	// Sanity check: with ~100 calibration samples + α=0.1, the prediction
	// set should contain the true label ≥ 90% of the time on a held-out
	// stream from the same distribution.
	rng := rand.New(rand.NewSource(99))

	// Calibration: 200 samples where p_pred = true positive rate.
	calProbs := make([]float64, 200)
	calLabels := make([]int, 200)
	for i := range calProbs {
		// Underlying: prob = 0.7 → 70% positives, model also says 0.7
		// (with small noise). Perfectly calibrated stream.
		p := 0.7 + 0.05*rng.NormFloat64()
		if p < 0 {
			p = 0
		}
		if p > 1 {
			p = 1
		}
		calProbs[i] = p
		if rng.Float64() < 0.7 {
			calLabels[i] = 1
		}
	}

	cp := NewConformalPredictor()
	if err := cp.Fit(calProbs, calLabels); err != nil {
		t.Fatal(err)
	}

	// Test: 1000 held-out items.
	hits := 0
	for i := 0; i < 1000; i++ {
		p := 0.7 + 0.05*rng.NormFloat64()
		if p < 0 {
			p = 0
		}
		if p > 1 {
			p = 1
		}
		var label int
		if rng.Float64() < 0.7 {
			label = 1
		}

		ps, err := cp.Predict(p, 0.1)
		if err != nil {
			t.Fatal(err)
		}
		if (label == 1 && ps.Includes1) || (label == 0 && ps.Includes0) {
			hits++
		}
	}
	coverage := float64(hits) / 1000.0
	// Allow some noise — guarantee is 1−α = 0.9 in expectation.
	if coverage < 0.85 {
		t.Errorf("conformal coverage %f below threshold 0.85", coverage)
	}
}

func TestConformalSetClassifications(t *testing.T) {
	cp := NewConformalPredictor()
	calProbs := make([]float64, 50)
	calLabels := make([]int, 50)
	for i := range calProbs {
		// Perfectly separable: low probs → negatives, high → positives.
		if i%2 == 0 {
			calProbs[i] = 0.05
			calLabels[i] = 0
		} else {
			calProbs[i] = 0.95
			calLabels[i] = 1
		}
	}
	if err := cp.Fit(calProbs, calLabels); err != nil {
		t.Fatal(err)
	}

	// Highly confident negative.
	ps, _ := cp.Predict(0.02, 0.1)
	if ps.IsAmbiguous() {
		t.Errorf("0.02 should not be ambiguous: %+v", ps)
	}
}
