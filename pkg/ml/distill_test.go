package ml

import (
	"strings"
	"testing"
)

func TestDistillStudentMimicsTeacherOnLinearData(t *testing.T) {
	// Linearly separable data: student LR can match the teacher GBT
	// almost exactly.
	X := [][]float64{
		{1, 0}, {2, 0}, {3, 0}, {4, 0}, {5, 0},
		{0, 1}, {0, 2}, {0, 3}, {0, 4}, {0, 5},
	}
	y := []int{1, 1, 1, 1, 1, 0, 0, 0, 0, 0}

	teacher := DefaultGradientBoosting()
	teacher.Seed = 17
	teacher.NEstimators = 100
	if err := teacher.Fit(X, y, []string{"x", "y"}); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultDistillationConfig()
	cfg.Seed = 17
	cfg.SyntheticSamples = 1000
	student, err := Distill(teacher, X, []string{"x", "y"}, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Spot-check student vs teacher predictions.
	probes := [][]float64{{2, 0}, {0, 2}, {3, 1}, {1, 3}}
	disagreements := 0
	for _, p := range probes {
		t1, _ := teacher.PredictProbability(p)
		s1, _ := student.PredictProbability(p)
		// Allow a generous gap; LR can lag GBT in absolute prob, but the
		// classification should agree on linearly separable data.
		if (t1 > 0.5) != (s1 > 0.5) {
			disagreements++
		}
	}
	if disagreements > 0 {
		t.Errorf("student disagreed on %d/%d linearly separable probes", disagreements, len(probes))
	}
}

func TestDistillRefusesNonlinearConcept(t *testing.T) {
	// Interval concept: relevant iff |x| < 0.8. The teacher nails it, the
	// linear student cannot — Distill must fail loudly instead of shipping
	// a 0.60-accuracy student with 0 recall.
	var X [][]float64
	var y []int
	for i := 0; i < 200; i++ {
		x := -2 + 4*float64(i)/199
		label := 0
		if x > -0.8 && x < 0.8 {
			label = 1
		}
		X, y = append(X, []float64{x}), append(y, label)
	}

	teacher := DefaultGradientBoosting()
	teacher.Seed = 17
	if err := teacher.Fit(X, y, []string{"x"}); err != nil {
		t.Fatal(err)
	}
	teacherMetrics, err := EvaluateOn(teacher, X, y)
	if err != nil {
		t.Fatal(err)
	}
	if teacherMetrics.Accuracy < 0.95 {
		t.Fatalf("fixture teacher too weak (%.3f), cannot prove the gate", teacherMetrics.Accuracy)
	}

	cfg := DefaultDistillationConfig()
	cfg.Seed = 17
	if _, err := Distill(teacher, X, []string{"x"}, cfg); err == nil {
		t.Fatal("nonlinear concept must fail the fidelity gate, not ship a degraded student")
	} else if !strings.Contains(err.Error(), "reproduces the teacher") {
		t.Fatalf("unexpected error (want fidelity-gate refusal): %v", err)
	}
}
