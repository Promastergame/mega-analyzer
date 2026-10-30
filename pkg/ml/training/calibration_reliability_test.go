package training

import (
	"fmt"
	"testing"

	"mega-analyzer/pkg/ml"
)

// TestPseudoOnlyTrainingNeverReliable pins the honest-stamp rule: a corpus
// with zero human labels trains (bootstrap mode), but its ECE measures
// self-consistency against pseudo-labels — never quality. ECEReliable must
// stay false no matter how large the pseudo-only hold-out is.
func TestPseudoOnlyTrainingNeverReliable(t *testing.T) {
	records := groupedHistory(12) // no UserOverrides anywhere: pure heuristic
	opts := DefaultTrainOptions()
	opts.MinSamples = 10
	opts.MinPerClass = 5

	model, st, err := Train(records, opts)
	if err != nil {
		t.Fatalf("pseudo-only bootstrap training must still succeed: %v (stats=%+v)", err, st)
	}
	if st.HardLabeled != 0 {
		t.Fatalf("fixture leaked hard labels: %+v", st)
	}
	if model.EvalHard != nil {
		t.Fatalf("no human labels in, no hard hold-out out: %+v", model.EvalHard)
	}
	if model.PseudoFraction != 1 {
		t.Fatalf("PseudoFraction = %f, want 1", model.PseudoFraction)
	}
	if model.ECEReliable {
		t.Errorf("pseudo-only ECE (%.4f on %d rows) must not be stamped reliable",
			model.ECE, model.ECESamples)
	}
	if !model.CalibFitted {
		t.Error("calibration should still fit on a large hold-out (only the stamp changes)")
	}
}

// TestReliableImpliesHardEval guards the invariant in the other direction:
// whenever the stamp is on, human ground truth backed it. Overrides go on
// every group: the split holds out whole APK groups, so overrides on a
// single record would miss the hold-out whenever that group trains.
func TestReliableImpliesHardEval(t *testing.T) {
	records := groupedHistory(12)
	var overrides []ml.UserOverride
	for i := 0; i < 6; i++ {
		overrides = append(overrides,
			ml.UserOverride{Keyword: fmt.Sprintf("rel_%d", i), Action: ml.FeedbackRelevant},
			ml.UserOverride{Keyword: fmt.Sprintf("noise_%d", i), Action: ml.FeedbackNoise},
		)
	}
	for _, r := range records {
		r.UserOverrides = append([]ml.UserOverride(nil), overrides...)
	}

	opts := DefaultTrainOptions()
	opts.MinSamples = 10
	opts.MinPerClass = 5

	model, _, err := Train(records, opts)
	if err != nil {
		t.Fatalf("train: %v", err)
	}
	if model.EvalHard == nil {
		t.Fatal("human labels in, hard hold-out must come out")
	}
	if model.ECEReliable && model.EvalHard.Samples == 0 {
		t.Error("reliable stamp with an empty hard hold-out")
	}
}
