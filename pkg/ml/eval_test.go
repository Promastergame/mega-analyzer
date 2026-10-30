package ml

import (
	"math"
	"testing"
)

func TestConfuseAndMetrics(t *testing.T) {
	// 5 TP, 1 FP, 3 TN, 1 FN.
	yPred := []int{1, 1, 1, 1, 1, 1, 0, 0, 0, 0}
	yTrue := []int{1, 1, 1, 1, 1, 0, 0, 0, 0, 1}
	c, err := Confuse(yPred, yTrue)
	if err != nil {
		t.Fatalf("Confuse: %v", err)
	}
	if c.TP != 5 || c.FP != 1 || c.TN != 3 || c.FN != 1 {
		t.Fatalf("confusion mismatch: %+v", c)
	}

	m := MetricsFromConfusion(c)
	if math.Abs(m.Accuracy-0.8) > 1e-9 {
		t.Errorf("accuracy = %f, want 0.8", m.Accuracy)
	}
	wantPrec := 5.0 / 6.0
	if math.Abs(m.Precision-wantPrec) > 1e-9 {
		t.Errorf("precision = %f, want %f", m.Precision, wantPrec)
	}
	wantRec := 5.0 / 6.0
	if math.Abs(m.Recall-wantRec) > 1e-9 {
		t.Errorf("recall = %f, want %f", m.Recall, wantRec)
	}
	wantF1 := 2 * wantPrec * wantRec / (wantPrec + wantRec)
	if math.Abs(m.F1-wantF1) > 1e-9 {
		t.Errorf("f1 = %f, want %f", m.F1, wantF1)
	}
}

func TestMetricsHandlesAllZeroPredictions(t *testing.T) {
	yPred := []int{0, 0, 0, 0}
	yTrue := []int{1, 0, 1, 0}
	c, _ := Confuse(yPred, yTrue)
	m := MetricsFromConfusion(c)
	// Precision is undefined when no positives are predicted.
	if !math.IsNaN(m.Precision) {
		t.Errorf("precision should be NaN when no positives predicted, got %f", m.Precision)
	}
	if math.Abs(m.Recall-0) > 1e-9 {
		t.Errorf("recall should be 0 when no positives predicted, got %f", m.Recall)
	}
}

func TestAreaUnderROC_PerfectClassifier(t *testing.T) {
	// Probabilities perfectly separate classes → AUC = 1.
	yProb := []float64{0.1, 0.2, 0.3, 0.7, 0.8, 0.9}
	yTrue := []int{0, 0, 0, 1, 1, 1}
	auc, err := AreaUnderROC(yProb, yTrue)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(auc-1.0) > 1e-9 {
		t.Errorf("auc = %f, want 1.0", auc)
	}
}

func TestAreaUnderROC_RandomIsHalf(t *testing.T) {
	// All same probability → AUC = 0.5 (chance).
	yProb := []float64{0.5, 0.5, 0.5, 0.5}
	yTrue := []int{0, 1, 0, 1}
	auc, err := AreaUnderROC(yProb, yTrue)
	if err != nil {
		t.Fatal(err)
	}
	if math.Abs(auc-0.5) > 1e-9 {
		t.Errorf("auc = %f, want 0.5", auc)
	}
}

func TestPrecisionAtK(t *testing.T) {
	yProb := []float64{0.9, 0.8, 0.7, 0.6, 0.5, 0.4}
	yTrue := []int{1, 1, 0, 1, 0, 0}
	p, err := PrecisionAtK(yProb, yTrue, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Top-3 by prob: indices 0,1,2 → labels 1,1,0 → 2/3.
	want := 2.0 / 3.0
	if math.Abs(p-want) > 1e-9 {
		t.Errorf("p@3 = %f, want %f", p, want)
	}
}

func TestKFoldCV_LogisticRegression(t *testing.T) {
	// Linearly separable: y = 1 iff x0 > x1.
	X := [][]float64{
		{2, 1}, {3, 1}, {1, 0}, {4, 2}, {5, 1},
		{1, 2}, {1, 3}, {0, 1}, {2, 4}, {1, 5},
	}
	y := []int{1, 1, 1, 1, 1, 0, 0, 0, 0, 0}
	factory := func() BinaryClassifier {
		return DefaultLogisticRegression()
	}
	summary, err := KFoldCV(factory, X, y, []string{"x0", "x1"}, 5, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(summary.Folds) != 5 {
		t.Fatalf("expected 5 folds, got %d", len(summary.Folds))
	}
	// On linearly separable data 5-fold CV should land near perfect.
	if summary.Mean.Accuracy < 0.7 {
		t.Errorf("CV accuracy too low: %f", summary.Mean.Accuracy)
	}
}
