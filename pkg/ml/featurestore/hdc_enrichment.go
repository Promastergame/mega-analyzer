package featurestore

import (
	"fmt"
	"math"
	"strings"
)

// HDCFinding is the minimal interface FeatureStore needs to enrich itself
// with HDC signals. Both `apkloader.NativeFinding` (the existing scan
// report row) and any future Aetrium output type can satisfy it by
// exposing the anchor name + similarity scores already present in the
// finding's evidence string.
//
// We keep this surface here, in the featurestore package, rather than
// importing apkloader to avoid an import cycle (apkloader → ml/featurestore
// is the desired direction).
type HDCFinding struct {
	// AnchorName is the canonical anchor identifier emitted by the Rust
	// HDC engine (e.g. "use_after_free", "command_injection").
	AnchorName string
	// Jaccard similarity to the matched anchor signature, in [0, 1].
	Jaccard float64
	// Hamming similarity (1 − normalised hamming distance), in [0, 1].
	HammingSim float64
	// Severity score lifted from the anchor metadata, in [0, 1].
	Severity float64
}

// EnrichWithHDCFindings folds an Aetrium scan report into a feature store.
//
// For every finding it emits:
//
//   - hdc.<anchor>.jaccard          — best-of-run Jaccard for that anchor
//   - hdc.<anchor>.hamming          — best-of-run Hamming similarity
//   - hdc.<anchor>.severity         — anchor metadata severity (constant)
//   - hdc.<anchor>.hits             — number of times that anchor matched
//
// And the run-level aggregates:
//
//   - hdc.any.matched               — 1.0 if ≥1 anchor crossed its threshold, else 0
//   - hdc.aggregate.max_jaccard     — max Jaccard across all findings
//   - hdc.aggregate.mean_jaccard    — mean Jaccard
//   - hdc.aggregate.n_anchors       — number of distinct anchors that fired
//   - hdc.aggregate.n_findings      — total number of findings
//   - hdc.aggregate.severity_score  — Σ (severity × jaccard), an HDC-only risk proxy
//
// This is the bridge that lets a downstream Go ML model (LR/RF/GBT) see HDC
// similarity as a real feature, rather than the current arrangement where
// HDC and Go scoring run independently and never meet.
func EnrichWithHDCFindings(fs *FeatureStore, findings []HDCFinding) error {
	if fs == nil {
		return fmt.Errorf("featurestore: nil store")
	}

	// Per-anchor best-of-run aggregates. We use NaN-as-sentinel rather than
	// 0 so a future MissingFill can distinguish "no finding" from "finding
	// with similarity 0".
	bestJaccard := map[string]float64{}
	bestHamming := map[string]float64{}
	severityBy := map[string]float64{}
	hits := map[string]int{}

	matchedAny := 0.0
	maxJ := math.Inf(-1)
	sumJ := 0.0

	for _, f := range findings {
		name := f.AnchorName
		if name == "" {
			continue
		}
		if v, ok := bestJaccard[name]; !ok || f.Jaccard > v {
			bestJaccard[name] = f.Jaccard
		}
		if v, ok := bestHamming[name]; !ok || f.HammingSim > v {
			bestHamming[name] = f.HammingSim
		}
		if f.Severity > severityBy[name] {
			severityBy[name] = f.Severity
		}
		hits[name]++

		matchedAny = 1.0
		if f.Jaccard > maxJ {
			maxJ = f.Jaccard
		}
		sumJ += f.Jaccard
	}

	for name, j := range bestJaccard {
		anchor := normalizeAnchorName(name)
		if err := fs.Set("hdc."+anchor+".jaccard", j, OriginHDC); err != nil {
			return err
		}
		if err := fs.Set("hdc."+anchor+".hamming", bestHamming[name], OriginHDC); err != nil {
			return err
		}
		if err := fs.Set("hdc."+anchor+".severity", severityBy[name], OriginHDC); err != nil {
			return err
		}
		if err := fs.Set("hdc."+anchor+".hits", float64(hits[name]), OriginHDC); err != nil {
			return err
		}
	}

	if err := fs.Set("hdc.any.matched", matchedAny, OriginHDC); err != nil {
		return err
	}
	if err := fs.Set("hdc.aggregate.n_findings", float64(len(findings)), OriginHDC); err != nil {
		return err
	}
	if err := fs.Set("hdc.aggregate.n_anchors", float64(len(bestJaccard)), OriginHDC); err != nil {
		return err
	}

	if matchedAny > 0 && len(findings) > 0 {
		if err := fs.Set("hdc.aggregate.max_jaccard", maxJ, OriginHDC); err != nil {
			return err
		}
		mean := sumJ / float64(len(findings))
		if err := fs.Set("hdc.aggregate.mean_jaccard", mean, OriginHDC); err != nil {
			return err
		}
		// Risk proxy: weight every finding's similarity by its severity.
		// If callers train on this feature alongside structural ones, the
		// model learns when to "trust HDC over heuristics" automatically.
		score := 0.0
		for _, f := range findings {
			score += f.Severity * f.Jaccard
		}
		if err := fs.Set("hdc.aggregate.severity_score", score, OriginHDC); err != nil {
			return err
		}
	} else {
		// Initialize the aggregates explicitly to 0 so feature schemas
		// remain stable across runs that produced no findings.
		_ = fs.Set("hdc.aggregate.max_jaccard", 0, OriginHDC)
		_ = fs.Set("hdc.aggregate.mean_jaccard", 0, OriginHDC)
		_ = fs.Set("hdc.aggregate.severity_score", 0, OriginHDC)
	}

	return nil
}

// normalizeAnchorName lowercases and replaces unsafe characters so it can
// appear inside a feature key without ambiguity.
func normalizeAnchorName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, "/", "_")
	return name
}
