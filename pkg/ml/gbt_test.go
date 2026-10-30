package ml

import (
	"math"
	"math/rand"
	"testing"
)

// makeXORData generates a noisy XOR dataset that linear models cannot solve
// but tree ensembles can. Used to validate that GBT actually learns
// non-linear structure.
func makeXORData(n int, seed int64) ([][]float64, []int) {
	rng := rand.New(rand.NewSource(seed))
	X := make([][]float64, n)
	y := make([]int, n)
	for i := 0; i < n; i++ {
		x0 := rng.Float64()*2 - 1
		x1 := rng.Float64()*2 - 1
		X[i] = []float64{x0, x1}
		// XOR boundary with a small margin band ignored for clarity.
		if (x0 > 0 && x1 < 0) || (x0 < 0 && x1 > 0) {
			y[i] = 1
		} else {
			y[i] = 0
		}
	}
	return X, y
}

func TestGradientBoostingFitsXOR(t *testing.T) {
	X, y := makeXORData(400, 42)

	gbt := DefaultGradientBoosting()
	gbt.Seed = 42
	gbt.NEstimators = 100
	if err := gbt.Fit(X, y, []string{"x0", "x1"}); err != nil {
		t.Fatal(err)
	}

	// Evaluate on a held-out set generated from the same distribution.
	Xt, yt := makeXORData(200, 99)
	m, err := EvaluateOn(gbt, Xt, yt)
	if err != nil {
		t.Fatal(err)
	}
	if m.Accuracy < 0.85 {
		t.Errorf("XOR accuracy too low: %f (history train=%v val=%v)",
			m.Accuracy, gbt.TrainLossHistory, gbt.ValLossHistory)
	}
}

func TestGradientBoostingEarlyStopping(t *testing.T) {
	// Tiny noisy dataset where GBT will overfit quickly: train loss keeps
	// dropping but validation loss bottoms out, triggering early stop.
	rng := rand.New(rand.NewSource(7))
	n := 60
	X := make([][]float64, n)
	y := make([]int, n)
	for i := 0; i < n; i++ {
		x0 := rng.Float64()
		X[i] = []float64{x0, rng.Float64()}
		// Noisy label: flip 25% of the time so the model can't perfect-fit.
		if x0 > 0.5 {
			y[i] = 1
		}
		if rng.Float64() < 0.25 {
			y[i] ^= 1
		}
	}

	gbt := DefaultGradientBoosting()
	gbt.Seed = 7
	gbt.NEstimators = 500
	gbt.EarlyStoppingRounds = 5
	gbt.ValidationFraction = 0.3
	gbt.MaxDepth = 5
	gbt.LearningRate = 0.2

	if err := gbt.Fit(X, y, []string{"x0", "x1"}); err != nil {
		t.Fatal(err)
	}
	// Should stop well before NEstimators on this noisy dataset.
	if len(gbt.trees) >= gbt.NEstimators {
		t.Errorf("early stopping never triggered (trees=%d)", len(gbt.trees))
	}
	if len(gbt.ValLossHistory) == 0 {
		t.Errorf("expected ValLossHistory to be populated when early stopping is active")
	}
}

func TestLogisticRegressionEarlyStopping(t *testing.T) {
	// Linearly separable data, LR will converge fast.
	X := [][]float64{
		{1, 0}, {2, 0}, {3, 0}, {4, 0},
		{0, 1}, {0, 2}, {0, 3}, {0, 4},
	}
	y := []int{1, 1, 1, 1, 0, 0, 0, 0}
	lr := DefaultLogisticRegression()
	lr.epochs = 10000
	lr.WithEarlyStopping(1e-4, 5)
	if err := lr.Fit(X, y, []string{"x", "y"}); err != nil {
		t.Fatal(err)
	}
	if !lr.LastConverged {
		t.Errorf("LR should converge on linearly separable data")
	}
	if lr.LastEpochs >= lr.epochs {
		t.Errorf("LR ran the full %d epochs (no early stop?)", lr.epochs)
	}
	if len(lr.TrainingHistory) != lr.LastEpochs {
		t.Errorf("history size %d != epochs run %d", len(lr.TrainingHistory), lr.LastEpochs)
	}
}

func TestLogisticRegressionPartialFit(t *testing.T) {
	X := [][]float64{
		{1, 0}, {2, 0}, {0, 1}, {0, 2},
	}
	y := []int{1, 1, 0, 0}
	lr := DefaultLogisticRegression()
	if err := lr.Fit(X, y, []string{"x", "y"}); err != nil {
		t.Fatal(err)
	}

	// Snapshot weights, do PartialFit, ensure they moved.
	w0Before := lr.weights[0]
	if err := lr.PartialFit([][]float64{{5, 0}}, []int{1}, 3); err != nil {
		t.Fatal(err)
	}
	if math.Abs(lr.weights[0]-w0Before) < 1e-9 {
		t.Errorf("PartialFit didn't change weights; w0=%f", lr.weights[0])
	}
}

func TestRandomForestSeededIsReproducible(t *testing.T) {
	X, y := makeXORData(120, 3)

	rf1 := NewRandomForest(20, 6).WithSeed(123)
	rf2 := NewRandomForest(20, 6).WithSeed(123)
	if err := rf1.Fit(X, y, []string{"x0", "x1"}); err != nil {
		t.Fatal(err)
	}
	if err := rf2.Fit(X, y, []string{"x0", "x1"}); err != nil {
		t.Fatal(err)
	}

	// Two seeded fits on the same data must produce identical predictions.
	for _, x := range X[:30] {
		p1, _ := rf1.PredictProbability(x)
		p2, _ := rf2.PredictProbability(x)
		if math.Abs(p1-p2) > 1e-9 {
			t.Fatalf("seeded RFs disagree: p1=%f p2=%f x=%v", p1, p2, x)
		}
	}
}

func TestRandomForestHasDiverseTrees(t *testing.T) {
	// Sanity: with bootstrap+mtry working, two trees from the same forest
	// must NOT make identical predictions on every input. The original
	// implementation collapsed to one tree, which would fail this.
	X, y := makeXORData(200, 11)
	rf := NewRandomForest(10, 6).WithSeed(456)
	if err := rf.Fit(X, y, []string{"x0", "x1"}); err != nil {
		t.Fatal(err)
	}
	if len(rf.trees) < 2 {
		t.Skip("not enough trees to compare")
	}

	disagreements := 0
	for _, x := range X {
		p0 := rf.predictTree(rf.trees[0], x)
		p1 := rf.predictTree(rf.trees[1], x)
		if p0 != p1 {
			disagreements++
		}
	}
	if disagreements == 0 {
		t.Fatalf("trees never disagree → forest collapsed to single tree (RF bug regression!)")
	}
}
