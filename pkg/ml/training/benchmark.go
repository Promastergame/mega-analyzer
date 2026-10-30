package training

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"time"

	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/ml/ensemble"
)

// ═══════════════════════════════════════════════════════════════════════════
// FIXED-CORPUS ML BENCHMARK
// ═══════════════════════════════════════════════════════════════════════════
//
// Unit tests prove correctness; only a fixed labeled corpus proves the ML
// got *better*. This file defines the regression benchmark:
//
//   - a versioned, hash-stamped corpus of labeled keyword and method
//     entries (BenchmarkCorpus), checked into version control;
//   - one deterministic run of the *deployed* scoring path over the whole
//     corpus (RunBenchmark), no training, no splits, no randomness;
//   - a JSON report with precision / recall / F1 / FPR / PR-AUC / Brier /
//     ECE (+ bootstrap CI) overall and per category, keyed by the corpus
//     hash so runs are comparable across commits.
//
// A report saved next to the corpus becomes the baseline: a metric that
// moved between runs is either a code change or a model change, and the
// corpus hash says which corpus measured it.

// Benchmark entry kinds. Each kind is scored by its own deployed model.
const (
	BenchmarkKindKeyword = "keyword" // scored by the keyword relevance model
	BenchmarkKindMethod  = "method"  // scored by the ensemble risk model
)

// BenchmarkEntry is one labeled corpus item.
type BenchmarkEntry struct {
	Kind     string              `json:"kind"`               // keyword | method
	Key      string              `json:"key"`                // unique within the corpus
	Category string              `json:"category,omitempty"` // report grouping (e.g. "billing")
	Label    int                 `json:"label"`              // 1 = relevant/gate, 0 = noise/non-gate
	Keyword  *ml.KeywordFeedback `json:"keyword_stats,omitempty"`
	Features *ensemble.Features  `json:"features,omitempty"`
}

// BenchmarkCorpus is the fixed labeled set the benchmark runs against.
type BenchmarkCorpus struct {
	Version     int              `json:"version"`
	Description string           `json:"description"`
	Entries     []BenchmarkEntry `json:"entries"`
}

// LoadBenchmarkCorpus reads and validates a corpus file.
func LoadBenchmarkCorpus(path string) (*BenchmarkCorpus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("benchmark corpus: %w", err)
	}
	var c BenchmarkCorpus
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("benchmark corpus: parse: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("benchmark corpus %s: %w", path, err)
	}
	return &c, nil
}

// Validate enforces the invariants the benchmark relies on: known kinds,
// unique keys, both a label and the payload the kind's scorer needs.
func (c *BenchmarkCorpus) Validate() error {
	seen := make(map[string]bool, len(c.Entries))
	for i, e := range c.Entries {
		if e.Key == "" {
			return fmt.Errorf("entry %d has no key", i)
		}
		if seen[e.Key] {
			return fmt.Errorf("duplicate entry key %q", e.Key)
		}
		seen[e.Key] = true
		if e.Label != 0 && e.Label != 1 {
			return fmt.Errorf("entry %q has invalid label %d (want 0 or 1)", e.Key, e.Label)
		}
		switch e.Kind {
		case BenchmarkKindKeyword:
			if e.Keyword == nil {
				return fmt.Errorf("keyword entry %q lacks keyword_stats", e.Key)
			}
		case BenchmarkKindMethod:
			if e.Features == nil {
				return fmt.Errorf("method entry %q lacks features", e.Key)
			}
		default:
			return fmt.Errorf("entry %q has unknown kind %q", e.Key, e.Kind)
		}
	}
	return nil
}

// Hash returns a stable digest of the corpus contents (description and
// entry order included), so a report records exactly which corpus produced
// its numbers.
func (c *BenchmarkCorpus) Hash() string {
	data, err := json.Marshal(c)
	if err != nil {
		return "unmarshalable"
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:8])
}

// BenchmarkMetrics is the metric block for one slice of the corpus.
type BenchmarkMetrics struct {
	N         int     `json:"n"`
	Positives int     `json:"positives"`
	Negatives int     `json:"negatives"`
	Accuracy  float64 `json:"accuracy"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	FPR       float64 `json:"fpr"`
	PRAUC     float64 `json:"pr_auc"`
	Brier     float64 `json:"brier"`
	ECE       float64 `json:"ece"`
	ECELow    float64 `json:"ece_low"`
	ECEHigh   float64 `json:"ece_high"`
}

// BenchmarkCategoryReport is one category's slice of the corpus.
type BenchmarkCategoryReport struct {
	Category string           `json:"category"`
	Metrics  BenchmarkMetrics `json:"metrics"`
}

// BenchmarkReport is the full benchmark output for one corpus + model pair.
type BenchmarkReport struct {
	CorpusHash    string                    `json:"corpus_hash"`
	CorpusDesc    string                    `json:"corpus_description"`
	GeneratedAt   time.Time                 `json:"generated_at"`
	KeywordModel  string                    `json:"keyword_model"`
	EnsembleModel string                    `json:"ensemble_model"`
	Overall       BenchmarkMetrics          `json:"overall"`
	ByCategory    []BenchmarkCategoryReport `json:"by_category"`
	Skipped       int                       `json:"skipped_entries"` // no scorer for their kind
	Summary       string                    `json:"summary"`
}

// RunBenchmark scores the whole corpus with the deployed models and produces
// the regression report. Both scorers are optional: a nil scorer skips its
// entries (counted in Skipped), so the benchmark runs against whatever
// models are loaded — the report names them. Determinism: no training, no
// shuffling, fixed bootstrap seed.
func RunBenchmark(corpus *BenchmarkCorpus, kw *KeywordScorer, ens *EnsembleModelScorer) (*BenchmarkReport, error) {
	if corpus == nil {
		return nil, fmt.Errorf("benchmark: nil corpus")
	}
	if err := corpus.Validate(); err != nil {
		return nil, fmt.Errorf("benchmark: %w", err)
	}

	var all []benchScored
	skipped := 0
	for _, e := range corpus.Entries {
		switch e.Kind {
		case BenchmarkKindKeyword:
			if kw == nil || !kw.IsLoaded() {
				skipped++
				continue
			}
			all = append(all, benchScored{e.Category, kw.ScoreKeyword(e.Keyword), e.Label})
		case BenchmarkKindMethod:
			if ens == nil || !ens.IsLoaded() {
				skipped++
				continue
			}
			p, ok := ens.Score(*e.Features)
			if !ok {
				skipped++
				continue
			}
			all = append(all, benchScored{e.Category, p, e.Label})
		}
	}
	if len(all) == 0 {
		return nil, fmt.Errorf("benchmark: no entries were scoreable (load the models the corpus targets)")
	}

	byCat := make(map[string][]benchScored)
	for _, s := range all {
		byCat[s.category] = append(byCat[s.category], s)
	}

	cats := make([]string, 0, len(byCat))
	for cat := range byCat {
		cats = append(cats, cat)
	}
	sort.Strings(cats)

	report := &BenchmarkReport{
		CorpusHash:    corpus.Hash(),
		CorpusDesc:    corpus.Description,
		GeneratedAt:   time.Now(),
		KeywordModel:  modelInfoOrNone(kw != nil && kw.IsLoaded(), kw),
		EnsembleModel: modelInfoEnsOrNone(ens != nil && ens.IsLoaded(), ens),
	}
	report.Overall = benchmarkMetrics(all)
	for _, cat := range cats {
		report.ByCategory = append(report.ByCategory, BenchmarkCategoryReport{
			Category: cat,
			Metrics:  benchmarkMetrics(byCat[cat]),
		})
	}
	report.Skipped = skipped

	if len(report.ByCategory) > 0 {
		report.Summary = fmt.Sprintf(
			"n=%d acc=%.3f prec=%.3f rec=%.3f f1=%.3f fpr=%.3f pr_auc=%.3f brier=%.3f ece=%.3f [%.3f–%.3f] categories=%d skipped=%d",
			report.Overall.N, report.Overall.Accuracy, report.Overall.Precision, report.Overall.Recall,
			report.Overall.F1, report.Overall.FPR, report.Overall.PRAUC, report.Overall.Brier,
			report.Overall.ECE, report.Overall.ECELow, report.Overall.ECEHigh,
			len(report.ByCategory), report.Skipped)
	}
	return report, nil
}

func modelInfoOrNone(loaded bool, kw *KeywordScorer) string {
	if !loaded {
		return "not loaded"
	}
	return kw.ModelInfo()
}

func modelInfoEnsOrNone(loaded bool, ens *EnsembleModelScorer) string {
	if !loaded {
		return "not loaded"
	}
	return ens.ModelInfo()
}

// benchScored is one corpus entry after scoring by its model.
type benchScored struct {
	category string
	prob     float64
	label    int
}

// benchmarkMetrics computes the full metric block at the 0.5 threshold.
func benchmarkMetrics(entries []benchScored) BenchmarkMetrics {
	m := BenchmarkMetrics{N: len(entries)}
	if m.N == 0 {
		return m
	}
	probs := make([]float64, m.N)
	labels := make([]int, m.N)
	var tp, fp, tn, fn int
	var brier float64
	for i, e := range entries {
		probs[i], labels[i] = e.prob, e.label
		pred := 0
		if e.prob >= 0.5 {
			pred = 1
		}
		switch {
		case pred == 1 && e.label == 1:
			tp++
		case pred == 1 && e.label == 0:
			fp++
		case pred == 0 && e.label == 0:
			tn++
		default:
			fn++
		}
		diff := e.prob - float64(e.label)
		brier += diff * diff
	}
	m.Positives = tp + fn
	m.Negatives = tn + fp
	m.Accuracy = float64(tp+tn) / float64(m.N)
	if tp+fp > 0 {
		m.Precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		m.Recall = float64(tp) / float64(tp+fn)
	}
	if m.Precision+m.Recall > 0 {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
	if fp+tn > 0 {
		m.FPR = float64(fp) / float64(fp+tn)
	}
	if ap, err := ml.AreaUnderPR(probs, labels); err == nil {
		m.PRAUC = ap
	} else {
		m.PRAUC = math.NaN()
	}
	m.Brier = brier / float64(m.N)
	if ece, err := ml.BootstrapECE(probs, labels, 10, bootstrapReplicates, 1); err == nil {
		m.ECE, m.ECELow, m.ECEHigh = ece.ECE, ece.Lower, ece.Upper
	}
	return m
}

// SaveBenchmarkReport writes the report atomically for diffing across runs.
func SaveBenchmarkReport(r *BenchmarkReport, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("benchmark report mkdir: %w", err)
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("benchmark report marshal: %w", err)
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("benchmark report write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("benchmark report rename: %w", err)
	}
	return nil
}
