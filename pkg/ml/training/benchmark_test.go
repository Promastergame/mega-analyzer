package training

import (
	"path/filepath"
	"testing"

	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/ml/ensemble"
)

func TestBenchmarkCorpusHashIsStable(t *testing.T) {
	corpus, err := LoadBenchmarkCorpus(filepath.Join("testdata", "benchmark_corpus.json"))
	if err != nil {
		t.Fatalf("load seed corpus: %v", err)
	}
	h1, h2 := corpus.Hash(), corpus.Hash()
	if h1 != h2 || len(h1) != 16 {
		t.Fatalf("corpus hash not stable: %q vs %q", h1, h2)
	}
	// Any content change must change the hash — that is the whole point.
	modified := *corpus
	modified.Entries[0].Label = 1 - modified.Entries[0].Label
	if modified.Hash() == h1 {
		t.Fatal("hash ignored a label change")
	}
}

func TestBenchmarkCorpusValidation(t *testing.T) {
	base := func() *BenchmarkCorpus {
		return &BenchmarkCorpus{Version: 1, Entries: []BenchmarkEntry{
			{Kind: BenchmarkKindKeyword, Key: "a", Label: 1, Keyword: &ml.KeywordFeedback{Triggered: 1}},
			{Kind: BenchmarkKindMethod, Key: "b", Label: 0, Features: &ensemble.Features{}},
		}}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("valid corpus rejected: %v", err)
	}

	dup := base()
	dup.Entries = append(dup.Entries, BenchmarkEntry{Kind: BenchmarkKindKeyword, Key: "a", Label: 0, Keyword: &ml.KeywordFeedback{}})
	if err := dup.Validate(); err == nil {
		t.Error("duplicate key accepted")
	}

	badKind := base()
	badKind.Entries[0].Kind = "magic"
	if err := badKind.Validate(); err == nil {
		t.Error("unknown kind accepted")
	}

	missingPayload := base()
	missingPayload.Entries[1].Features = nil
	if err := missingPayload.Validate(); err == nil {
		t.Error("method entry without features accepted")
	}
}

func TestRunBenchmarkEndToEnd(t *testing.T) {
	corpus, err := LoadBenchmarkCorpus(filepath.Join("testdata", "benchmark_corpus.json"))
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	// Train real models on synthetic history so both scorers are loaded.
	opts := DefaultTrainOptions()
	opts.MinSamples = 10
	kwModel, _, err := Train(syntheticHistory(), opts)
	if err != nil {
		t.Fatalf("keyword train: %v", err)
	}
	kwScorer, err := NewKeywordScorerFromModel(kwModel)
	if err != nil {
		t.Fatalf("keyword scorer: %v", err)
	}
	ensModel, _, err := TrainEnsemble(ensembleHistory(t), DefaultEnsembleTrainOptions())
	if err != nil {
		t.Fatalf("ensemble train: %v", err)
	}
	ensScorer, err := NewEnsembleModelScorerFromModel(ensModel)
	if err != nil {
		t.Fatalf("ensemble scorer: %v", err)
	}

	report, err := RunBenchmark(corpus, kwScorer, ensScorer)
	if err != nil {
		t.Fatalf("run benchmark: %v", err)
	}
	if report.Skipped != 0 {
		t.Errorf("expected every entry scored, skipped=%d", report.Skipped)
	}
	if report.Overall.N != len(corpus.Entries) {
		t.Errorf("overall n=%d, want %d", report.Overall.N, len(corpus.Entries))
	}
	if len(report.ByCategory) == 0 {
		t.Fatal("expected per-category breakdown")
	}
	// Metrics must be sane and the bootstrap interval must bracket the point.
	o := report.Overall
	if o.ECELow > o.ECE || o.ECEHigh < o.ECE {
		t.Errorf("ECE %.4f outside CI [%.4f, %.4f]", o.ECE, o.ECELow, o.ECEHigh)
	}
	if o.Precision < 0 || o.Precision > 1 || o.Recall < 0 || o.Recall > 1 || o.FPR < 0 || o.FPR > 1 {
		t.Errorf("metric out of range: %+v", o)
	}
	if o.PRAUC != o.PRAUC { // NaN check
		t.Error("PR-AUC is NaN on a two-class corpus")
	}

	// Determinism: same corpus + models → identical metric block.
	report2, err := RunBenchmark(corpus, kwScorer, ensScorer)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if report2.Overall != report.Overall {
		t.Errorf("benchmark not deterministic:\n %+v\n %+v", report.Overall, report2.Overall)
	}

	// Nil scorers must skip, not crash.
	if _, err := RunBenchmark(corpus, nil, nil); err == nil {
		t.Error("expected error when no model is loaded")
	}
}
