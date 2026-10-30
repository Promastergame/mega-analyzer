package ml

import (
	"testing"
)

func TestLogisticRegression(t *testing.T) {
	lr := DefaultLogisticRegression()

	X := [][]float64{
		{1.0, 0.0},
		{0.0, 1.0},
		{1.0, 1.0},
		{0.0, 0.0},
	}
	y := []int{1, 0, 1, 0}

	err := lr.Fit(X, y, []string{"f1", "f2"})
	if err != nil {
		t.Fatalf("Fit failed: %v", err)
	}

	prob, _ := lr.Predict([]float64{1.0, 0.0})
	if prob < 0.5 {
		t.Errorf("Predict(1,0) = %f, want > 0.5", prob)
	}

	cls, _ := lr.PredictClass([]float64{0.0, 1.0}, 0.5)
	if cls != 0 {
		t.Errorf("PredictClass(0,1) = %d, want 0", cls)
	}

	importance := lr.GetFeatureImportance()
	if len(importance) != 2 {
		t.Errorf("Importance len = %d", len(importance))
	}
}

func TestTFIDF(t *testing.T) {
	tfidf := NewTFIDF()
	docs := [][]string{
		{"apple", "banana", "apple"},
		{"banana", "cherry"},
		{"apple", "cherry"},
	}

	tfidf.Fit(docs)
	vectors := tfidf.Transform(docs)

	if len(vectors) != 3 {
		t.Errorf("Vectors len = %d", len(vectors))
	}

	sim := CosineSimilarity(vectors[0], vectors[1])
	if sim <= 0 {
		t.Errorf("Similarity = %f, want > 0", sim)
	}
}

func TestRandomForest(t *testing.T) {
	rf := NewRandomForest(20, 5).WithSeed(42)
	X := [][]float64{
		{1.0, 2.0},
		{2.0, 1.0},
		{10.0, 11.0},
		{11.0, 10.0},
	}
	y := []int{0, 0, 1, 1}

	err := rf.Fit(X, y, []string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}

	prob, _ := rf.PredictProbability([]float64{1.0, 1.0})
	if prob > 0.5 {
		t.Errorf("Prob(1,1) = %f, want < 0.5", prob)
	}

	cls, _ := rf.Predict([]float64{12.0, 12.0})
	if cls != 1 {
		t.Errorf("Cls(12,12) = %d, want 1", cls)
	}
}
