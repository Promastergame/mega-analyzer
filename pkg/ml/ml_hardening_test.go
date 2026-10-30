package ml

import (
	"math"
	"math/rand"
	"testing"
)

func TestBuildFeatureBinsHandlesDuplicateValues(t *testing.T) {
	// Half the corpus shares one value: quantile edges picked by index would
	// collide. The builder must dedupe (or fall back to uniform) so the bins
	// stay unambiguous.
	vals := make([]float64, 0, 200)
	for i := 0; i < 100; i++ {
		vals = append(vals, 0) // heavy tie
		vals = append(vals, float64(i)+0.5)
	}
	bins, err := BuildFeatureBins(vals, 5)
	if err != nil {
		t.Fatalf("BuildFeatureBins: %v", err)
	}
	for i := 1; i < len(bins.Edges); i++ {
		if bins.Edges[i] <= bins.Edges[i-1] {
			t.Fatalf("edges not strictly ascending: %v", bins.Edges)
		}
	}
	var sum float64
	for _, f := range bins.RefFraction {
		sum += f
	}
	if math.Abs(sum-1) > 1e-9 {
		t.Errorf("reference fractions sum to %f, want 1", sum)
	}

	// All values identical → degenerate range, uniform fallback must still
	// produce valid, strictly ascending bins.
	same := make([]float64, 50)
	bins, err = BuildFeatureBins(same, 4)
	if err != nil {
		t.Fatalf("BuildFeatureBins(identical): %v", err)
	}
	for i := 1; i < len(bins.Edges); i++ {
		if bins.Edges[i] <= bins.Edges[i-1] {
			t.Fatalf("identical values produced non-ascending edges: %v", bins.Edges)
		}
	}
}

func TestPSIWithholdsSignalOnSmallWindows(t *testing.T) {
	ref, err := BuildFeatureBins(make([]float64, 100), 5)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PSI(ref, make([]float64, MinPSIWindow-1)); err == nil {
		t.Fatal("PSI produced a drift value below the minimum window size")
	}
	// At the threshold the value must be computable.
	if _, err := PSI(ref, make([]float64, MinPSIWindow)); err != nil {
		t.Fatalf("PSI refused a valid window: %v", err)
	}
}

func TestPageHinkleyDetectsDecrease(t *testing.T) {
	ph := NewPageHinkley(0.005, 0.5)
	rng := rand.New(rand.NewSource(3))
	for i := 0; i < 100; i++ {
		if ph.Update(0.5 + 0.01*rng.NormFloat64()) {
			t.Fatalf("alert fired during stable phase at i=%d", i)
		}
	}
	fired := false
	for i := 0; i < 200; i++ {
		if ph.Update(0.1 + 0.01*rng.NormFloat64()) {
			fired = true
			break
		}
	}
	if !fired {
		t.Fatal("two-sided Page-Hinkley failed to detect a downward mean shift")
	}
	if ph.Direction != "decrease" || !ph.AlertedDown {
		t.Errorf("decrease not reported: direction=%q down=%v", ph.Direction, ph.AlertedDown)
	}
}

func TestPageHinkleyReportsIncreaseDirection(t *testing.T) {
	ph := NewPageHinkley(0.005, 0.5)
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 100; i++ {
		ph.Update(0.5 + 0.01*rng.NormFloat64())
	}
	fired := false
	for i := 0; i < 200; i++ {
		if ph.Update(0.9 + 0.01*rng.NormFloat64()) {
			fired = true
			break
		}
	}
	if !fired || ph.Direction != "increase" || !ph.AlertedUp {
		t.Errorf("increase not reported: fired=%v direction=%q up=%v", fired, ph.Direction, ph.AlertedUp)
	}
}

func TestBootstrapECEBracketsPointEstimate(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	probs := make([]float64, 120)
	labels := make([]int, 120)
	for i := range probs {
		p := rng.Float64()
		probs[i] = p
		if rng.Float64() < p {
			labels[i] = 1
		}
	}
	eci, err := BootstrapECE(probs, labels, 10, 200, 42)
	if err != nil {
		t.Fatalf("BootstrapECE: %v", err)
	}
	if eci.Samples != len(probs) {
		t.Errorf("samples=%d, want %d", eci.Samples, len(probs))
	}
	if eci.Lower > eci.ECE || eci.Upper < eci.ECE {
		t.Errorf("point ECE %.4f outside bootstrap CI [%.4f, %.4f]", eci.ECE, eci.Lower, eci.Upper)
	}

	// Perfect predictions: ECE collapses toward 0.
	perfectProbs := make([]float64, 60)
	perfectLabels := make([]int, 60)
	for i := 0; i < 30; i++ {
		perfectProbs[i], perfectLabels[i] = 0.99, 1
		perfectProbs[30+i], perfectLabels[30+i] = 0.01, 0
	}
	eci, err = BootstrapECE(perfectProbs, perfectLabels, 10, 100, 1)
	if err != nil {
		t.Fatalf("BootstrapECE(perfect): %v", err)
	}
	if eci.ECE > 0.02 {
		t.Errorf("perfect predictions gave ECE %.4f", eci.ECE)
	}
}

func TestUncertaintyBandCarriesGuarantee(t *testing.T) {
	cp := NewConformalPredictor()
	probs := make([]float64, 20)
	labels := make([]int, 20)
	for i := 0; i < 10; i++ {
		probs[i], labels[i] = 0.9, 1
		probs[10+i], labels[10+i] = 0.1, 0
	}
	if err := cp.Fit(probs, labels); err != nil {
		t.Fatalf("fit: %v", err)
	}
	band, err := cp.UncertaintyBand(0.8, 0.1)
	if err != nil {
		t.Fatalf("UncertaintyBand: %v", err)
	}
	if band.Guarantee != GuaranteeScoreBand {
		t.Errorf("guarantee = %q, want %q", band.Guarantee, GuaranteeScoreBand)
	}
	if band.Lo > band.Hi || band.Lo < 0 || band.Hi > 1 {
		t.Errorf("band out of order: [%f, %f]", band.Lo, band.Hi)
	}
}

func TestMondrianMarksHeuristicFallback(t *testing.T) {
	mc := NewMondrianConformal()
	set, err := mc.Predict("billing", 0.9, 0.1)
	if err != nil {
		t.Fatalf("predict: %v", err)
	}
	if !set.HeuristicFallback {
		t.Error("uncalibrated prediction must be flagged as heuristic fallback")
	}
	if err := mc.FitGlobal([]float64{0.9, 0.1, 0.8, 0.2, 0.85, 0.15, 0.95, 0.05, 0.7, 0.3}, []int{1, 0, 1, 0, 1, 0, 1, 0, 1, 0}); err != nil {
		t.Fatalf("fit global: %v", err)
	}
	set, err = mc.Predict("billing", 0.9, 0.1)
	if err != nil {
		t.Fatalf("predict after fit: %v", err)
	}
	if set.HeuristicFallback {
		t.Error("calibrated prediction must not be flagged as heuristic fallback")
	}
}

func TestCategoryConfidenceDeclaresHeuristicGuarantee(t *testing.T) {
	cc := EstimateCategoryConformalConfidence(PatchCatBilling, 0.9)
	if cc.Method != "heuristic" {
		t.Errorf("method = %q, want heuristic", cc.Method)
	}
	if cc.Guarantee != string(GuaranteeNone) {
		t.Errorf("guarantee = %q, want %q", cc.Guarantee, GuaranteeNone)
	}
}

func TestAreaUnderPRPerfectRanking(t *testing.T) {
	probs := []float64{0.95, 0.9, 0.85, 0.4, 0.3, 0.1}
	labels := []int{1, 1, 1, 0, 0, 0}
	ap, err := AreaUnderPR(probs, labels)
	if err != nil {
		t.Fatalf("AreaUnderPR: %v", err)
	}
	if math.Abs(ap-1) > 1e-9 {
		t.Errorf("perfect ranking AP = %f, want 1", ap)
	}
	if _, err := AreaUnderPR(probs[:3], labels[:3]); err == nil {
		t.Error("single-class input must be rejected")
	}
}

func TestAreaUnderPRTiesAreOrderIndependent(t *testing.T) {
	// Equal scores cannot be separated by any threshold: both orders must
	// give the grouped average precision (sklearn: 0.5 here), not 1 and 0.5
	// depending on input order.
	a, err := AreaUnderPR([]float64{0.5, 0.5}, []int{1, 0})
	if err != nil {
		t.Fatalf("AreaUnderPR: %v", err)
	}
	b, err := AreaUnderPR([]float64{0.5, 0.5}, []int{0, 1})
	if err != nil {
		t.Fatalf("AreaUnderPR: %v", err)
	}
	if math.Abs(a-0.5) > 1e-9 || math.Abs(b-0.5) > 1e-9 {
		t.Errorf("tied AP = (%f, %f), want (0.5, 0.5)", a, b)
	}

	// Larger tie group: 2 positives + 1 negative at 0.7 above a negative at
	// 0.2. Step 1: recall 1, precision 2/3 → AP = 2/3 regardless of order.
	for _, labels := range [][]int{{1, 1, 0, 0}, {1, 0, 1, 0}, {0, 1, 1, 0}} {
		ap, err := AreaUnderPR([]float64{0.7, 0.7, 0.7, 0.2}, labels)
		if err != nil {
			t.Fatalf("AreaUnderPR: %v", err)
		}
		if math.Abs(ap-2.0/3.0) > 1e-9 {
			t.Errorf("labels %v: AP = %f, want %f", labels, ap, 2.0/3.0)
		}
	}
}
