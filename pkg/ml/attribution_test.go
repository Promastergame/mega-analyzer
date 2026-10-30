package ml

import (
	"math"
	"testing"
)

func TestExplainLRSumsToScore(t *testing.T) {
	X := [][]float64{
		{1, 0, 0},
		{0, 1, 0},
		{0, 0, 1},
		{1, 1, 0},
	}
	y := []int{1, 0, 1, 1}
	lr := DefaultLogisticRegression()
	if err := lr.Fit(X, y, []string{"a", "b", "c"}); err != nil {
		t.Fatal(err)
	}

	report, err := ExplainLR(lr, []float64{0.5, 0.7, 0.1})
	if err != nil {
		t.Fatal(err)
	}

	// Sum of contributions + base must equal raw score.
	var sum float64
	for _, c := range report.Contributions {
		sum += c.Contribution
	}
	if math.Abs(sum+report.BaseScore-report.RawScore) > 1e-9 {
		t.Errorf("contributions don't sum to raw score: sum=%f base=%f raw=%f",
			sum, report.BaseScore, report.RawScore)
	}
}

func TestExplainGBTConsistencyWithPrediction(t *testing.T) {
	X, y := makeXORData(300, 11)
	gbt := DefaultGradientBoosting()
	gbt.Seed = 11
	gbt.NEstimators = 50
	if err := gbt.Fit(X, y, []string{"x0", "x1"}); err != nil {
		t.Fatal(err)
	}

	probe := []float64{0.5, -0.3}
	wantP, _ := gbt.PredictProbability(probe)
	report, err := ExplainGBT(gbt, probe)
	if err != nil {
		t.Fatal(err)
	}

	// Attribution probability must agree with model probability up to
	// floating-point noise — both compute sigmoid(F(x)) where F is the
	// running sum of tree contributions.
	if math.Abs(report.Probability-wantP) > 1e-9 {
		t.Errorf("attribution prob (%f) != model prob (%f)", report.Probability, wantP)
	}
	if len(report.Contributions) != 2 {
		t.Errorf("expected 2 features in attribution, got %d", len(report.Contributions))
	}
}
