package training

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"mega-analyzer/pkg/ml"
)

// makeRecord builds one synthetic APK feedback record from a keyword spec.
func makeRecord(id string, kws map[string]*ml.KeywordFeedback) *ml.AnalysisFeedback {
	cp := make(map[string]*ml.KeywordFeedback, len(kws))
	for k, v := range kws {
		c := *v
		c.Keyword = k
		cp[k] = &c
	}
	return &ml.AnalysisFeedback{ID: id, KeywordStats: cp}
}

// syntheticHistory creates a corpus with a clear relevant/noise separation plus
// a couple of hard human labels, spread across several records so APKsSeenIn
// accumulates.
func syntheticHistory() []*ml.AnalysisFeedback {
	var records []*ml.AnalysisFeedback
	const nRecords = 10
	for r := 0; r < nRecords; r++ {
		kws := map[string]*ml.KeywordFeedback{}
		// 12 relevant keywords: high importance, app code, no library noise.
		for i := 0; i < 12; i++ {
			kws[fmt.Sprintf("relevant_%d", i)] = &ml.KeywordFeedback{
				Triggered: 3, InAppCode: 3, InLibrary: 0,
				SumImportance: 21 + float64(i), // avg ~7
			}
		}
		// 12 noise keywords: low importance, library-dominated.
		for i := 0; i < 12; i++ {
			kws[fmt.Sprintf("noise_%d", i)] = &ml.KeywordFeedback{
				Triggered: 5, InAppCode: 0, InLibrary: 5,
				SumImportance: 0.4, // avg ~0.08
			}
		}
		// One hard-labeled relevant and one hard-labeled noise.
		kws["hard_relevant"] = &ml.KeywordFeedback{
			Triggered: 2, InAppCode: 2, SumImportance: 6, MarkedRelevant: 1,
		}
		kws["hard_noise"] = &ml.KeywordFeedback{
			Triggered: 2, InLibrary: 2, SumImportance: 1, MarkedNoise: 1,
		}
		records = append(records, makeRecord(fmt.Sprintf("apk_%d", r), kws))
	}
	return records
}

func TestExtractSamplesTiers(t *testing.T) {
	records := syntheticHistory()
	samples, st := ExtractSamples(records, DefaultTrainOptions())

	if st.HardLabeled != 2 {
		t.Errorf("expected 2 hard labels, got %d", st.HardLabeled)
	}
	if st.Positives == 0 || st.Negatives == 0 {
		t.Fatalf("expected both classes, got pos=%d neg=%d", st.Positives, st.Negatives)
	}
	if len(samples) != st.HardLabeled+st.HeuristicLabeled {
		t.Errorf("sample count %d != hard+heuristic %d", len(samples), st.HardLabeled+st.HeuristicLabeled)
	}
	// Every feature vector must have the contracted length.
	for _, s := range samples {
		if len(s.Features) != len(ml.KeywordRelevanceFeatureNames) {
			t.Fatalf("feature length %d != %d", len(s.Features), len(ml.KeywordRelevanceFeatureNames))
		}
	}
}

func TestTrainAndScoreSeparation(t *testing.T) {
	records := syntheticHistory()
	opts := DefaultTrainOptions()
	opts.MinSamples = 10

	model, st, err := Train(records, opts)
	if err != nil {
		t.Fatalf("train failed: %v (stats=%+v)", err, st)
	}
	if !model.CalibFitted {
		t.Errorf("expected calibration to fit on synthetic data")
	}
	if len(model.LRWeights) != len(ml.KeywordRelevanceFeatureNames) {
		t.Fatalf("weight count mismatch")
	}

	scorer, err := NewKeywordScorerFromModel(model)
	if err != nil {
		t.Fatalf("scorer build: %v", err)
	}
	if !scorer.IsLoaded() {
		t.Fatal("scorer should be loaded")
	}

	relProb := scorer.ScoreKeyword(&ml.KeywordFeedback{
		Triggered: 30, InAppCode: 30, InLibrary: 0, SumImportance: 210, APKsSeenIn: 10,
	})
	noiseProb := scorer.ScoreKeyword(&ml.KeywordFeedback{
		Triggered: 50, InAppCode: 0, InLibrary: 50, SumImportance: 4, APKsSeenIn: 10,
	})

	if !(relProb > noiseProb) {
		t.Errorf("model failed to separate classes: relevant=%.3f noise=%.3f", relProb, noiseProb)
	}
	if relProb < 0.5 {
		t.Errorf("relevant keyword scored too low: %.3f", relProb)
	}
	if noiseProb > 0.5 {
		t.Errorf("noise keyword scored too high: %.3f", noiseProb)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	records := syntheticHistory()
	opts := DefaultTrainOptions()
	opts.MinSamples = 10
	model, _, err := Train(records, opts)
	if err != nil {
		t.Fatalf("train: %v", err)
	}

	path := filepath.Join(t.TempDir(), "model.json")
	if err := SaveModel(model, path); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadModel(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded == nil {
		t.Fatal("loaded model is nil")
	}
	if loaded.SampleCount != model.SampleCount || loaded.CalibA != model.CalibA {
		t.Errorf("round-trip mismatch: %+v vs %+v", loaded, model)
	}

	// Scores must match between the in-memory and the reloaded model.
	kf := &ml.KeywordFeedback{Triggered: 30, InAppCode: 30, SumImportance: 210, APKsSeenIn: 10}
	s1, _ := NewKeywordScorerFromModel(model)
	s2, _ := NewKeywordScorerFromModel(loaded)
	if d := s1.ScoreKeyword(kf) - s2.ScoreKeyword(kf); d > 1e-9 || d < -1e-9 {
		t.Errorf("scores diverged after round-trip: %.12f", d)
	}
}

func TestScorerNoModelIsNoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	scorer, err := NewKeywordScorerFromPath(path)
	if err != nil {
		t.Fatalf("expected no error for missing model, got %v", err)
	}
	if scorer.IsLoaded() {
		t.Error("scorer should not be loaded when file is absent")
	}
	if p := scorer.ScoreKeyword(&ml.KeywordFeedback{Triggered: 1}); p != 0.5 {
		t.Errorf("no-op scorer should return 0.5, got %.3f", p)
	}
}

func TestInsufficientSamplesAborts(t *testing.T) {
	// Single tiny record → far below MinSamples.
	records := []*ml.AnalysisFeedback{
		makeRecord("x", map[string]*ml.KeywordFeedback{
			"a": {Triggered: 1, InAppCode: 1, SumImportance: 7},
		}),
	}
	_, _, err := Train(records, DefaultTrainOptions())
	if err == nil {
		t.Error("expected error on insufficient samples")
	}
}

func TestExtractSamplesLatestOverrideWins(t *testing.T) {
	t0 := time.Date(2026, 7, 23, 1, 0, 0, 0, time.UTC)
	records := []*ml.AnalysisFeedback{
		{
			KeywordStats: map[string]*ml.KeywordFeedback{
				"crypto": {Keyword: "crypto", Triggered: 10, InAppCode: 10, SumImportance: 70, MarkedNoise: 1},
			},
			UserOverrides: []ml.UserOverride{{Keyword: "crypto", Action: ml.FeedbackNoise, Timestamp: t0}},
		},
		{
			UserOverrides: []ml.UserOverride{{Keyword: "CRYPTO", Action: ml.FeedbackRelevant, Timestamp: t0.Add(time.Hour)}},
		},
	}
	opts := DefaultTrainOptions()
	opts.UseHeuristicLabels = false
	samples, stats := ExtractSamples(records, opts)
	if len(samples) != 1 || samples[0].Label != 1 || samples[0].Source != "hard" {
		t.Fatalf("latest correction must be the only hard label, samples=%+v stats=%+v", samples, stats)
	}
}
