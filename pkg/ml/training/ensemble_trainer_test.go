package training

import (
	"fmt"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/ml/ensemble"
)

func TestTrainEnsemble_InsufficientSamples(t *testing.T) {
	records := []*ml.AnalysisFeedback{
		{
			UserOverrides: []ml.UserOverride{
				{
					Path:   "com/test/Foo",
					Action: "relevant",
					Features: &ensemble.Features{
						Cyclomatic: 10,
					},
				},
			},
		},
	}
	opts := DefaultEnsembleTrainOptions()
	opts.MinSamples = 5

	_, _, err := TrainEnsemble(records, opts)
	if err == nil {
		t.Fatalf("expected error for insufficient samples, got nil")
	}
}

func TestTrainEnsemble_SuccessAndPersistence(t *testing.T) {
	var overrides []ml.UserOverride
	for i := 0; i < 12; i++ {
		action := "noise"
		cyc := float64(1)
		if i%2 == 0 {
			action = "relevant"
			cyc = float64(20)
		}
		overrides = append(overrides, ml.UserOverride{
			Path:   fmt.Sprintf("com/test/Method%d", i),
			Action: action,
			Features: &ensemble.Features{
				Cyclomatic:    cyc,
				NestingDepth:  cyc / 2,
				BranchDensity: 0.1,
			},
		})
	}
	records := []*ml.AnalysisFeedback{
		{
			UserOverrides: overrides,
		},
	}
	opts := DefaultEnsembleTrainOptions()
	opts.MinSamples = 10

	model, st, err := TrainEnsemble(records, opts)
	if err != nil {
		t.Fatalf("TrainEnsemble failed: %v", err)
	}
	if st.LabeledSamples != 12 || st.Positives != 6 || st.Negatives != 6 {
		t.Errorf("unexpected stats: %+v", st)
	}
	if model.SampleCount != 12 {
		t.Errorf("expected 12 sample count, got %d", model.SampleCount)
	}

	tmpDir := t.TempDir()
	modelPath := filepath.Join(tmpDir, "ensemble_test.json")
	if err := SaveEnsembleModel(model, modelPath); err != nil {
		t.Fatalf("SaveEnsembleModel failed: %v", err)
	}

	loaded, err := LoadEnsembleModel(modelPath)
	if err != nil {
		t.Fatalf("LoadEnsembleModel failed: %v", err)
	}
	if loaded == nil {
		t.Fatalf("expected model, got nil")
	}
	if loaded.Version != EnsembleModelVersion {
		t.Errorf("version mismatch: %d vs %d", loaded.Version, EnsembleModelVersion)
	}
	if len(loaded.LRWeights) != len(ensemble.FeatureNames) {
		t.Errorf("weights mismatch")
	}
}

func TestTrainEnsemble_DeterministicSameSeed(t *testing.T) {
	build := func() *EnsembleSavedModel {
		var overrides []ml.UserOverride
		for apk := 0; apk < 3; apk++ {
			for i := 0; i < 16; i++ {
				action := "noise"
				cyc := 2.0
				if (i+apk)%2 == 0 {
					action = "relevant"
					cyc = 22.0
				}
				overrides = append(overrides, ml.UserOverride{
					Path:     fmt.Sprintf("com/det/apk%d/Method%d", apk, i),
					Action:   action,
					APKName:  fmt.Sprintf("det-apk%d", apk),
					Features: &ensemble.Features{Cyclomatic: cyc, NestingDepth: cyc / 4, BranchDensity: 0.1},
				})
			}
		}
		records := []*ml.AnalysisFeedback{{
			ID:            "det",
			APKName:       "det",
			UserOverrides: overrides,
		}}
		opts := DefaultEnsembleTrainOptions()
		opts.Seed = 17
		opts.MinSamples = 20
		model, _, err := TrainEnsemble(records, opts)
		if err != nil {
			t.Fatalf("TrainEnsemble failed: %v", err)
		}
		return model
	}
	a, b := build(), build()
	if a.LRBias != b.LRBias {
		t.Errorf("bias differs across same-seed retrains: %v vs %v", a.LRBias, b.LRBias)
	}
	if len(a.LRWeights) != len(b.LRWeights) {
		t.Fatalf("weight length differs: %d vs %d", len(a.LRWeights), len(b.LRWeights))
	}
	for i := range a.LRWeights {
		if a.LRWeights[i] != b.LRWeights[i] {
			t.Fatalf("weight[%d] differs across same-seed retrains: %v vs %v", i, a.LRWeights[i], b.LRWeights[i])
		}
	}
	for i := range a.ScalerMeans {
		if a.ScalerMeans[i] != b.ScalerMeans[i] || a.ScalerStdDevs[i] != b.ScalerStdDevs[i] {
			t.Fatalf("scaler[%d] differs across same-seed retrains", i)
		}
	}
}
