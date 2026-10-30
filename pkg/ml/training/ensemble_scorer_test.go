package training

import (
	"fmt"
	"math"
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/ml/ensemble"
)

func TestEnsembleScorer_FallbackWithoutFile(t *testing.T) {
	tmpDir := t.TempDir()
	scorer, err := NewEnsembleModelScorerFromPath(filepath.Join(tmpDir, "nonexistent.json"))
	if err != nil {
		t.Fatalf("expected nil error for nonexistent file, got: %v", err)
	}
	if scorer.IsLoaded() {
		t.Errorf("expected IsLoaded() == false")
	}
	if prob, ok := scorer.Score(ensemble.Features{}); ok || prob != 0 {
		t.Errorf("expected (0, false), got (%v, %v)", prob, ok)
	}
	if info := scorer.ModelInfo(); info != "no ensemble model (heuristics active)" {
		t.Errorf("unexpected info string: %s", info)
	}
}

func TestEnsembleScorer_ScaleAndPredict(t *testing.T) {
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
				Cyclomatic: cyc,
			},
		})
	}
	opts := DefaultEnsembleTrainOptions()
	opts.MinSamples = 12 // legacy scorer test: deliberately small corpus
	model, _, err := TrainEnsemble([]*ml.AnalysisFeedback{{UserOverrides: overrides}}, opts)
	if err != nil {
		t.Fatalf("TrainEnsemble failed: %v", err)
	}

	scorer, err := NewEnsembleModelScorerFromModel(model)
	if err != nil {
		t.Fatalf("NewEnsembleModelScorerFromModel failed: %v", err)
	}
	if !scorer.IsLoaded() {
		t.Errorf("expected IsLoaded() == true")
	}

	prob, ok := scorer.Score(ensemble.Features{Cyclomatic: 20})
	if !ok {
		t.Errorf("expected ok == true")
	}
	if math.IsNaN(prob) || prob < 0 || prob > 1 {
		t.Errorf("invalid probability: %v", prob)
	}
}

func trainTinyEnsemble(t *testing.T) *EnsembleSavedModel {
	t.Helper()
	var overrides []ml.UserOverride
	for i := 0; i < 12; i++ {
		action := "noise"
		cyc := float64(1)
		if i%2 == 0 {
			action = "relevant"
			cyc = float64(20)
		}
		overrides = append(overrides, ml.UserOverride{
			Path:     fmt.Sprintf("com/test/Method%d", i),
			Action:   action,
			Features: &ensemble.Features{Cyclomatic: cyc},
		})
	}
	opts := DefaultEnsembleTrainOptions()
	opts.MinSamples = 12
	model, _, err := TrainEnsemble([]*ml.AnalysisFeedback{{UserOverrides: overrides}}, opts)
	if err != nil {
		t.Fatalf("TrainEnsemble failed: %v", err)
	}
	return model
}

func TestEnsembleScorer_RejectsCorruptModels(t *testing.T) {
	good := trainTinyEnsemble(t)
	if _, err := NewEnsembleModelScorerFromModel(good); err != nil {
		t.Fatalf("valid model must load: %v", err)
	}

	cases := map[string]func(*EnsembleSavedModel){
		"swapped schema": func(m *EnsembleSavedModel) {
			m.FeatureNames[0], m.FeatureNames[1] = m.FeatureNames[1], m.FeatureNames[0]
		},
		"renamed feature": func(m *EnsembleSavedModel) {
			m.FeatureNames[0] = "cyclomatic_typo"
		},
		"truncated names": func(m *EnsembleSavedModel) {
			m.FeatureNames = m.FeatureNames[:5]
		},
		"missing scaler": func(m *EnsembleSavedModel) {
			m.ScalerMeans, m.ScalerStdDevs = nil, nil
		},
		"short scaler": func(m *EnsembleSavedModel) {
			m.ScalerMeans = m.ScalerMeans[:5]
		},
		"truncated weights": func(m *EnsembleSavedModel) {
			m.LRWeights = m.LRWeights[:5]
		},
		"NaN weight": func(m *EnsembleSavedModel) {
			m.LRWeights[3] = math.NaN()
		},
		"infinite bias": func(m *EnsembleSavedModel) {
			m.LRBias = math.Inf(1)
		},
		"negative stddev": func(m *EnsembleSavedModel) {
			m.ScalerStdDevs[2] = -0.5
		},
	}
	for name, mutate := range cases {
		bad := *good
		bad.FeatureNames = append([]string(nil), good.FeatureNames...)
		bad.LRWeights = append([]float64(nil), good.LRWeights...)
		bad.ScalerMeans = append([]float64(nil), good.ScalerMeans...)
		bad.ScalerStdDevs = append([]float64(nil), good.ScalerStdDevs...)
		mutate(&bad)
		scorer, err := NewEnsembleModelScorerFromModel(&bad)
		if err == nil {
			t.Errorf("%s: corrupt model must be rejected", name)
		}
		if scorer.IsLoaded() {
			t.Errorf("%s: corrupt model must report IsLoaded()==false", name)
		}
		if _, ok := scorer.Score(ensemble.Features{Cyclomatic: 20}); ok {
			t.Errorf("%s: corrupt model must not score", name)
		}
	}
}

func TestEnsembleScorer_RoundTripThroughDisk(t *testing.T) {
	good := trainTinyEnsemble(t)
	path := filepath.Join(t.TempDir(), "ensemble.json")
	if err := SaveEnsembleModel(good, path); err != nil {
		t.Fatalf("SaveEnsembleModel: %v", err)
	}
	scorer, err := NewEnsembleModelScorerFromPath(path)
	if err != nil {
		t.Fatalf("valid saved model must load: %v", err)
	}
	if !scorer.IsLoaded() {
		t.Fatal("valid saved model must report IsLoaded()==true")
	}
	if _, ok := scorer.Score(ensemble.Features{Cyclomatic: 20}); !ok {
		t.Fatal("valid saved model must score")
	}
}
