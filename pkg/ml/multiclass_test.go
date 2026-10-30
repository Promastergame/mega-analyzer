package ml

import (
	"math"
	"testing"
)

func TestMulticlassSeparates3Classes(t *testing.T) {
	// 3 classes, linearly separable centroids.
	X := [][]float64{
		{1, 0}, {1.1, 0.1}, {0.9, -0.1}, // class 0
		{0, 1}, {0.1, 1.1}, {-0.1, 0.9}, // class 1
		{-1, 0}, {-1.1, 0.1}, {-0.9, -0.1}, // class 2
	}
	y := []int{0, 0, 0, 1, 1, 1, 2, 2, 2}

	factory := func() BinaryClassifier {
		return DefaultLogisticRegression()
	}
	m, err := NewMulticlassClassifier([]string{"a", "b", "c"}, factory)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Fit(X, y, []string{"x0", "x1"}); err != nil {
		t.Fatal(err)
	}

	cases := map[string][]float64{
		"a": {1.05, 0},
		"b": {0, 1.05},
		"c": {-1.05, 0},
	}
	for want, vec := range cases {
		got, _, err := m.PredictName(vec)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("PredictName(%v) = %s, want %s", vec, got, want)
		}
	}
}

func TestSoftmaxNormalises(t *testing.T) {
	probs := Softmax([]float64{0.5, 0.7, 0.2})
	var sum float64
	for _, p := range probs {
		sum += p
	}
	if math.Abs(sum-1.0) > 1e-9 {
		t.Errorf("softmax should sum to 1, got %f", sum)
	}
}
