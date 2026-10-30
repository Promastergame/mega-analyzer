package training

import (
	"fmt"
	"testing"
	"time"

	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/ml/ensemble"
)

// groupedHistory builds records whose APKHash groups them: each group carries
// its own keyword vocabulary so a group-wise split can be observed in the
// trained model.
func groupedHistory(nGroups int) []*ml.AnalysisFeedback {
	var records []*ml.AnalysisFeedback
	for g := 0; g < nGroups; g++ {
		kws := map[string]*ml.KeywordFeedback{}
		for i := 0; i < 6; i++ {
			kws[fmt.Sprintf("rel_%d", i)] = &ml.KeywordFeedback{
				Triggered: 4, InAppCode: 4, InLibrary: 0, SumImportance: 28,
			}
			kws[fmt.Sprintf("noise_%d", i)] = &ml.KeywordFeedback{
				Triggered: 6, InAppCode: 0, InLibrary: 6, SumImportance: 0.3,
			}
			// A second vocabulary tier no override ever touches, so every
			// split side also produces heuristic pseudo-labels.
			kws[fmt.Sprintf("relb_%d", i)] = &ml.KeywordFeedback{
				Triggered: 4, InAppCode: 4, InLibrary: 0, SumImportance: 28,
			}
			kws[fmt.Sprintf("noiseb_%d", i)] = &ml.KeywordFeedback{
				Triggered: 6, InAppCode: 0, InLibrary: 6, SumImportance: 0.3,
			}
		}
		records = append(records, &ml.AnalysisFeedback{
			ID:           fmt.Sprintf("apk_g%d", g),
			APKHash:      fmt.Sprintf("hash_g%d", g),
			KeywordStats: kws,
		})
	}
	return records
}

func TestTrainGroupSplitByAPK(t *testing.T) {
	records := groupedHistory(12)
	opts := DefaultTrainOptions()
	opts.MinSamples = 10
	opts.MinPerClass = 5

	model, st, err := Train(records, opts)
	if err != nil {
		t.Fatalf("train: %v (stats=%+v)", err, st)
	}
	if st.Groups != 12 {
		t.Errorf("groups=%d, want 12", st.Groups)
	}
	if !model.GroupSplit {
		t.Fatal("expected group-wise split with 12 APK groups")
	}
	// With 12 groups at CalibFraction 0.2, calibration must hold out whole
	// groups — so the hold-out is smaller than the training side but not
	// empty, and ECE carries its sample count and interval.
	if model.CalibFitted && model.ECESamples == 0 {
		t.Error("fitted calibration without recorded ECESamples")
	}
	if model.CalibFitted && model.ECEHigh < model.ECELow {
		t.Error("ECE interval inverted")
	}
	// Per-source hold-out evaluation must be present.
	if model.EvalPseudo == nil || model.EvalPseudo.Samples == 0 {
		t.Error("expected pseudo-label hold-out metrics")
	}
}

func TestTrainRejectsSingleClassCorpus(t *testing.T) {
	// Plenty of samples, but every one of them positive.
	var records []*ml.AnalysisFeedback
	for g := 0; g < 10; g++ {
		kws := map[string]*ml.KeywordFeedback{}
		for i := 0; i < 4; i++ {
			kws[fmt.Sprintf("rel_%d_%d", g, i)] = &ml.KeywordFeedback{
				Triggered: 4, InAppCode: 4, SumImportance: 28,
			}
		}
		records = append(records, &ml.AnalysisFeedback{ID: fmt.Sprintf("a%d", g), APKHash: fmt.Sprintf("h%d", g), KeywordStats: kws})
	}
	opts := DefaultTrainOptions()
	opts.MinSamples = 10
	_, _, err := Train(records, opts)
	if err == nil {
		t.Fatal("expected per-class rejection for an all-positive corpus")
	}
}

func TestTrainPseudoLabelCap(t *testing.T) {
	records := groupedHistory(12)
	// Anchor the cap with hard human labels: without them the pseudo share
	// is 1 by definition and the cap has nothing to protect.
	overrides := make([]ml.UserOverride, 0, 12)
	for i := 0; i < 6; i++ { // relb_/noiseb_ keywords stay pseudo-labeled

		overrides = append(overrides,
			ml.UserOverride{Keyword: fmt.Sprintf("rel_%d", i), Action: ml.FeedbackRelevant},
			ml.UserOverride{Keyword: fmt.Sprintf("noise_%d", i), Action: ml.FeedbackNoise},
		)
	}
	records[0].UserOverrides = overrides

	opts := DefaultTrainOptions()
	opts.MinSamples = 10
	opts.MaxPseudoFraction = 0.5

	model, _, err := Train(records, opts)
	if err != nil {
		t.Fatalf("train: %v", err)
	}
	if model.PseudoFraction > 0.5+1e-9 {
		t.Errorf("pseudo share %.3f exceeded the 0.5 cap", model.PseudoFraction)
	}
	if model.PseudoFraction == 0 {
		t.Error("cap removed every pseudo label instead of capping them")
	}
}

func TestTrainSingleGroupFallsBackToSampleSplit(t *testing.T) {
	// syntheticHistory has 10 distinct record IDs → simulate one APK only.
	records := syntheticHistory()
	for _, r := range records {
		r.APKHash = "same-apk"
	}
	opts := DefaultTrainOptions()
	opts.MinSamples = 10
	model, st, err := Train(records, opts)
	if err != nil {
		t.Fatalf("train: %v", err)
	}
	if model.GroupSplit {
		t.Error("single-APK history must fall back to sample-level split")
	}
	if st.Groups != 1 {
		t.Errorf("groups=%d, want 1", st.Groups)
	}
}

func TestEnsembleTrainGroupSplitByAPK(t *testing.T) {
	// Overrides spread over 6 APKs: group-wise split must engage, and the
	// hold-out must be big enough (>= 20 rows) for calibration to fit.
	var records []*ml.AnalysisFeedback
	for apk := 0; apk < 2; apk++ {
		var overrides []ml.UserOverride
		for i := 0; i < 24; i++ {
			action := "noise"
			cyc := 2.0
			if i%2 == 0 {
				action = "relevant"
				cyc = 22.0
			}
			overrides = append(overrides, ml.UserOverride{
				Path:     fmt.Sprintf("com/apk%d/Method%d", apk, i),
				Action:   action,
				APKName:  fmt.Sprintf("apk%d", apk),
				Features: &ensemble.Features{Cyclomatic: cyc, NestingDepth: cyc / 4, BranchDensity: 0.1},
			})
		}
		records = append(records, &ml.AnalysisFeedback{
			ID:            fmt.Sprintf("apk%d", apk),
			APKName:       fmt.Sprintf("apk%d", apk),
			Timestamp:     time.Now(),
			UserOverrides: overrides,
		})
	}
	opts := DefaultEnsembleTrainOptions()
	opts.MinSamples = 20

	model, st, err := TrainEnsemble(records, opts)
	if err != nil {
		t.Fatalf("ensemble train: %v (stats=%+v)", err, st)
	}
	if st.Groups != 2 {
		t.Errorf("groups=%d, want 2", st.Groups)
	}
	if !model.GroupSplit {
		t.Fatal("expected group-wise split with 2 APK groups")
	}
	if !model.CalibFitted {
		t.Fatal("expected calibration with a >=20-row group-wise hold-out")
	}
	if model.ECESamples == 0 {
		t.Error("calibration fitted without recording the hold-out size")
	}
	if model.ECEReliable && model.ECESamples < ECEReliableMinSamples {
		t.Error("ECEReliable=true below the reliability floor")
	}
}

// ensembleHistory builds 24 labeled overrides across 4 APK groups so the
// ensemble trainer exercises the group-wise split path.
func ensembleHistory(t *testing.T) []*ml.AnalysisFeedback {
	t.Helper()
	var records []*ml.AnalysisFeedback
	for apk := 0; apk < 4; apk++ {
		var overrides []ml.UserOverride
		for i := 0; i < 6; i++ {
			action := "noise"
			cyc := 2.0
			if i%2 == 0 {
				action = "relevant"
				cyc = 22.0
			}
			overrides = append(overrides, ml.UserOverride{
				Path:     fmt.Sprintf("com/bench/apk%d/Method%d", apk, i),
				Action:   action,
				APKName:  fmt.Sprintf("apk%d", apk),
				Features: &ensemble.Features{Cyclomatic: cyc, NestingDepth: cyc / 4, BranchDensity: 0.1},
			})
		}
		records = append(records, &ml.AnalysisFeedback{
			ID:            fmt.Sprintf("apk%d", apk),
			APKName:       fmt.Sprintf("apk%d", apk),
			Timestamp:     time.Now(),
			UserOverrides: overrides,
		})
	}
	return records
}

func TestEnsembleTrainRejectsOneSidedCorpus(t *testing.T) {
	var records []*ml.AnalysisFeedback
	var overrides []ml.UserOverride
	for i := 0; i < 12; i++ {
		overrides = append(overrides, ml.UserOverride{
			Path:     fmt.Sprintf("com/test/Rel%d", i),
			Action:   "relevant",
			Features: &ensemble.Features{Cyclomatic: 20},
		})
	}
	records = append(records, &ml.AnalysisFeedback{UserOverrides: overrides})
	_, _, err := TrainEnsemble(records, DefaultEnsembleTrainOptions())
	if err == nil {
		t.Fatal("expected per-class rejection for an all-relevant corpus")
	}
}

func TestECESummaryDisplaysReliability(t *testing.T) {
	if got := ECESummary(false, 0, 0, false, 0, 0); got != "uncalibrated" {
		t.Errorf("uncalibrated summary = %q", got)
	}
	got := ECESummary(true, 0.12, 40, true, 0.08, 0.17)
	if got != "calibrated ECE=0.120 [0.080–0.170]" {
		t.Errorf("reliable summary = %q", got)
	}
	got = ECESummary(true, 0.05, 8, false, 0.0, 0.2)
	if got != "calibrated ECE=0.050 (n=8, unreliable — CI 0.000–0.200)" {
		t.Errorf("unreliable summary = %q", got)
	}
}
