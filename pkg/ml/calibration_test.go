package ml

import (
	"math"
	"math/rand"
	"testing"
)

func TestPlattCalibrationPullsTowardObservedRate(t *testing.T) {
	// Synthetic miscalibration: model overconfidently says 0.9 for items
	// that are positive only 60% of the time, and 0.1 for items that are
	// positive 30% of the time.
	rng := rand.New(rand.NewSource(7))
	var probs []float64
	var labels []int
	for i := 0; i < 400; i++ {
		if rng.Float64() < 0.5 {
			probs = append(probs, 0.9)
			if rng.Float64() < 0.6 {
				labels = append(labels, 1)
			} else {
				labels = append(labels, 0)
			}
		} else {
			probs = append(probs, 0.1)
			if rng.Float64() < 0.3 {
				labels = append(labels, 1)
			} else {
				labels = append(labels, 0)
			}
		}
	}

	beforeECE, _ := ExpectedCalibrationError(probs, labels, 10)

	calib := NewPlattCalibrator()
	if err := calib.Fit(probs, labels); err != nil {
		t.Fatal(err)
	}
	calibrated := make([]float64, len(probs))
	for i, p := range probs {
		calibrated[i] = calib.Calibrate(p)
	}
	afterECE, _ := ExpectedCalibrationError(calibrated, labels, 10)

	if afterECE >= beforeECE {
		t.Errorf("Platt should reduce ECE: before=%f after=%f", beforeECE, afterECE)
	}
}

func TestIsotonicHandlesNonMonotonicInput(t *testing.T) {
	// PAV must produce a monotonic output even from arbitrary scores.
	probs := []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9}
	labels := []int{1, 0, 1, 0, 1, 0, 1, 0, 1}

	iso := NewIsotonicCalibrator()
	if err := iso.Fit(probs, labels); err != nil {
		t.Fatal(err)
	}
	bp, vals := iso.Breakpoints()

	// Monotonicity check.
	for i := 1; i < len(vals); i++ {
		if vals[i] < vals[i-1]-1e-9 {
			t.Errorf("isotonic must be non-decreasing: bp=%v vals=%v", bp, vals)
		}
	}
}

func TestExpectedCalibrationErrorOnPerfectCalibration(t *testing.T) {
	// Model that says 0.5 always with 50% positives is perfectly calibrated.
	probs := make([]float64, 100)
	labels := make([]int, 100)
	for i := range probs {
		probs[i] = 0.5
		if i%2 == 0 {
			labels[i] = 1
		}
	}
	ece, err := ExpectedCalibrationError(probs, labels, 10)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(ece) > 1e-9 {
		t.Errorf("perfectly calibrated stream should have ECE=0, got %f", ece)
	}
}
