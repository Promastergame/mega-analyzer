// Package training learns a keyword-relevance model from the analyzer's own
// run history (~/.analyzer/history.json) and persists it for use on the live
// scoring path. It is pure Go / stdlib-only and degrades gracefully: when no
// model file exists the analyzer keeps its hand-tuned heuristics unchanged.
//
// Labelling strategy (tiered, to survive label sparsity):
//
//	Tier 1 — hard labels:  MarkedRelevant>MarkedNoise → relevant(1),
//	                        MarkedNoise>MarkedRelevant → noise(0). High weight.
//	Tier 3 — heuristic pseudo-labels: reproduce the existing recalculateWeights
//	         thresholds so the model generalises them smoothly. Low weight.
//
// (A Tier-2 soft-label tier based on ThreatRelevance was intentionally dropped:
// that field is all-zero across the current corpus and would add no signal.)
package training

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"time"

	"mega-analyzer/pkg/ml"
)

const (
	// ModelVersion is bumped when the on-disk format or feature contract
	// changes incompatibly. LoadModel rejects mismatched versions.
	ModelVersion = 1

	modelDir      = "models"
	modelFileName = "keyword_relevance.json"

	// hardLabelWeight makes the (scarce) human labels dominate the (plentiful)
	// heuristic pseudo-labels during training.
	hardLabelWeight   = 8.0
	pseudoLabelWeight = 1.0

	// MinCalibSamples is the smallest hold-out that Platt scaling is allowed
	// to fit on. Below it the sigmoid parameters are noise (a 2-sample
	// "calibration" once produced confident nonsense), so calibration and
	// ECE are skipped entirely.
	MinCalibSamples = 20

	// ECEReliableMinSamples is the hold-out size at which a stored ECE point
	// estimate is reported as reliable. Below it the bootstrap interval is
	// wide and consumers must treat ECE as indicative only.
	ECEReliableMinSamples = 30

	// bootstrapReplicates controls the ECE confidence interval resolution.
	bootstrapReplicates = 500

	// finiteInf replaces ±Inf bin edges before JSON serialization (encoding/json
	// cannot represent Inf/NaN). All real feature values fall well inside.
	finiteInf = 1e18
)

// DefaultModelPath returns ~/.analyzer/models/keyword_relevance.json.
func DefaultModelPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ml.DefaultHistoryDir, modelDir, modelFileName), nil
}

// LabeledSample is one training example extracted from aggregated keyword stats.
type LabeledSample struct {
	Keyword  string
	Features []float64
	Label    int     // 1 = relevant, 0 = noise
	Weight   float64 // sample weight (hard labels weigh more)
	Source   string  // "hard" | "heuristic"
}

// LabelStats summarises what ExtractSamples produced.
type LabelStats struct {
	UniqueKeywords   int
	HardLabeled      int
	HeuristicLabeled int
	Positives        int
	Negatives        int
	// HardPositives/HardNegatives and HeuristicPositives/HeuristicNegatives
	// decompose the class balance by label source, so the pseudo-label share
	// of each class is visible instead of folded into one number.
	HardPositives      int
	HardNegatives      int
	HeuristicPositives int
	HeuristicNegatives int
	// Coverage is the share of the aggregated keyword vocabulary that
	// received any label (hard or pseudo).
	Coverage float64
	// PseudoFraction is the heuristic-labeled share of all labeled samples.
	PseudoFraction float64
	// Groups is the number of distinct APK/project groups the records came
	// from; GroupSplit reports whether the train/calib split was performed
	// group-wise (false means a within-sample fallback was used).
	Groups     int
	GroupSplit bool
}

// TrainOptions configures Train. Use DefaultTrainOptions for sensible values.
type TrainOptions struct {
	LR                 float64 // logistic learning rate
	Epochs             int     // max epochs (early stopping still applies)
	Lambda             float64 // L2 regularization
	CalibFraction      float64 // hold-out fraction for Platt calibration
	MinSamples         int     // abort below this many labeled rows
	MinPerClass        int     // abort when either class has fewer labeled rows
	MaxPseudoFraction  float64 // cap on heuristic-labeled share of training rows (0..1; 1 = uncapped)
	MinCalibSamples    int     // Platt calibration needs at least this many hold-out rows (0 = package default)
	MinHardEvalSamples int     // hard-label quality gate arms at this many hard hold-out rows (0 = default)
	MinHardQuality     float64 // abort when hard-label hold-out accuracy is below this (0 = default 0.6)
	UseHeuristicLabels bool    // include Tier-3 pseudo-labels
	Seed               int64   // deterministic shuffle seed
}

// DefaultTrainOptions returns tuned defaults. Heuristic labels are ON because
// the human-labeled corpus is tiny; without them there is not enough data.
func DefaultTrainOptions() TrainOptions {
	return TrainOptions{
		LR:                 0.05,
		Epochs:             500,
		Lambda:             0.01,
		CalibFraction:      0.2,
		MinSamples:         40,
		MinPerClass:        5,
		MaxPseudoFraction:  0.8,
		MinCalibSamples:    MinCalibSamples,
		MinHardEvalSamples: 10,
		MinHardQuality:     0.6,
		UseHeuristicLabels: true,
		Seed:               1,
	}
}

// SideMetrics is evaluation quality on one subset of the hold-out (hard vs
// pseudo labels), thresholded at 0.5.
type SideMetrics struct {
	Samples   int     `json:"samples"`
	Positives int     `json:"positives"`
	Negatives int     `json:"negatives"`
	Accuracy  float64 `json:"accuracy"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// SavedModel is the serializable artifact written to disk.
type SavedModel struct {
	Version      int            `json:"version"`
	TrainedAt    time.Time      `json:"trained_at"`
	SampleCount  int            `json:"sample_count"`
	LabelCounts  map[string]int `json:"label_counts"`
	Positives    int            `json:"positives"`
	Negatives    int            `json:"negatives"`
	FeatureNames []string       `json:"feature_names"`

	// Splits & label provenance, so instability has a visible cause.
	Groups         int          `json:"groups"`
	GroupSplit     bool         `json:"group_split"`
	Coverage       float64      `json:"coverage"`
	PseudoFraction float64      `json:"pseudo_fraction"`
	EvalHard       *SideMetrics `json:"eval_hard,omitempty"`
	EvalPseudo     *SideMetrics `json:"eval_pseudo,omitempty"`

	// Logistic regression parameters (stored as explicit slices, NOT via
	// SaveWeights(), so the JSON round-trip preserves []float64/[]string types).
	LRWeights []float64 `json:"lr_weights"`
	LRBias    float64   `json:"lr_bias"`

	// Platt calibration: calibrated = sigmoid(CalibA*raw + CalibB).
	CalibFitted bool    `json:"calib_fitted"`
	CalibA      float64 `json:"calib_a"`
	CalibB      float64 `json:"calib_b"`

	// ECE on the calibration hold-out with a bootstrap confidence interval,
	// measured over the SERVED (Platt-scaled) probabilities.
	// ECEReliable is false when the hold-out is too small for the point
	// estimate to be trusted, or when the hold-out holds no human labels at
	// all (a pseudo-only hold-out measures self-consistency, not quality) —
	// consumers must then display the interval or nothing at all, never the
	// bare number.
	ECE         float64 `json:"ece"`
	ECESamples  int     `json:"ece_samples"`
	ECELow      float64 `json:"ece_low,omitempty"`
	ECEHigh     float64 `json:"ece_high,omitempty"`
	ECEReliable bool    `json:"ece_reliable"`

	DriftBins map[string]*ml.FeatureBins `json:"drift_bins,omitempty"`
}

// ── Feature / label extraction ──────────────────────────────────────────────

// aggregate folds all per-record keyword stats into one KeywordFeedback per
// unique keyword, mirroring the AggregatedKeyword representation used at serving
// time (APKsSeenIn becomes the number of records the keyword appears in).
func aggregate(records []*ml.AnalysisFeedback) map[string]*ml.KeywordFeedback {
	agg := make(map[string]*ml.KeywordFeedback)
	for _, r := range records {
		if r == nil {
			continue
		}
		for kw, kf := range r.KeywordStats {
			if kf == nil {
				continue
			}
			a := agg[kw]
			if a == nil {
				a = &ml.KeywordFeedback{Keyword: kw}
				agg[kw] = a
			}
			a.Triggered += kf.Triggered
			a.InAppCode += kf.InAppCode
			a.InLibrary += kf.InLibrary
			a.Dampened += kf.Dampened
			a.SumImportance += kf.SumImportance
			a.MarkedRelevant += kf.MarkedRelevant
			a.MarkedNoise += kf.MarkedNoise
			a.APKsSeenIn++
		}
	}

	// MarkedRelevant/MarkedNoise in old history files are counters, while user
	// overrides are corrective decisions. Apply the reconciled latest decision
	// after aggregation so copied records and label flips cannot create a tie or
	// overweight one human action.
	byNormalizedKeyword := make(map[string]*ml.KeywordFeedback, len(agg))
	for keyword, feedback := range agg {
		byNormalizedKeyword[ml.NormalizeFeedbackTarget(keyword)] = feedback
	}
	for _, decision := range ml.ResolveUserOverrideDecisions(records) {
		if decision.Keyword == "" {
			continue
		}
		feedback := byNormalizedKeyword[ml.NormalizeFeedbackTarget(decision.Keyword)]
		if feedback == nil {
			continue
		}
		feedback.MarkedRelevant = 0
		feedback.MarkedNoise = 0
		switch decision.Action {
		case ml.FeedbackRelevant:
			feedback.MarkedRelevant = 1
		case ml.FeedbackNoise:
			feedback.MarkedNoise = 1
		}
	}
	return agg
}

// labelFor applies the tiered labelling strategy. source=="" means "skip".
func labelFor(kf *ml.KeywordFeedback, opts TrainOptions) (label int, weight float64, source string) {
	// Tier 1 — hard human labels.
	if kf.MarkedRelevant > 0 || kf.MarkedNoise > 0 {
		switch {
		case kf.MarkedRelevant > kf.MarkedNoise:
			return 1, hardLabelWeight, "hard"
		case kf.MarkedNoise > kf.MarkedRelevant:
			return 0, hardLabelWeight, "hard"
		default:
			return 0, 0, "" // tie → ambiguous, skip
		}
	}
	if !opts.UseHeuristicLabels {
		return 0, 0, ""
	}
	// Tier 3 — heuristic pseudo-labels. The goal of the model is false-positive
	// suppression, so we label NOISE generously (that's what we want to catch)
	// and RELEVANT conservatively (strong, repeated, app-code evidence only).
	// This avoids flooding the positive class with weak single-hit keywords.
	avg := kf.AvgImportance()
	noise := kf.NoiseRatio()
	switch {
	// Strong, repeated, high-importance, app-dominant signal → relevant.
	case avg > 5.0 && noise < 0.2 && kf.APKsSeenIn >= 2:
		return 1, pseudoLabelWeight, "heuristic"
	// Persistent low-value or library-dominated keyword → noise.
	case avg < 0.5 && kf.APKsSeenIn >= 2:
		return 0, pseudoLabelWeight, "heuristic"
	case avg < 1.0 && noise > 0.5:
		return 0, pseudoLabelWeight, "heuristic"
	case kf.Triggered >= 5 && avg < 1.5 && noise > 0.4:
		return 0, pseudoLabelWeight, "heuristic"
	default:
		return 0, 0, "" // uncertain middle band → skip
	}
}

// ExtractSamples aggregates history and builds the labeled training set.
func ExtractSamples(records []*ml.AnalysisFeedback, opts TrainOptions) ([]LabeledSample, LabelStats) {
	agg := aggregate(records)
	var st LabelStats
	st.UniqueKeywords = len(agg)
	samples := make([]LabeledSample, 0, len(agg))
	for kw, kf := range agg {
		if kf.Triggered == 0 {
			continue
		}
		label, weight, src := labelFor(kf, opts)
		if src == "" {
			continue
		}
		samples = append(samples, LabeledSample{
			Keyword:  kw,
			Features: kf.ToFeatureVector(),
			Label:    label,
			Weight:   weight,
			Source:   src,
		})
		switch src {
		case "hard":
			st.HardLabeled++
			if label == 1 {
				st.HardPositives++
			} else {
				st.HardNegatives++
			}
		case "heuristic":
			st.HeuristicLabeled++
			if label == 1 {
				st.HeuristicPositives++
			} else {
				st.HeuristicNegatives++
			}
		}
		if label == 1 {
			st.Positives++
		} else {
			st.Negatives++
		}
	}
	if st.UniqueKeywords > 0 {
		st.Coverage = float64(len(samples)) / float64(st.UniqueKeywords)
	}
	if total := st.HardLabeled + st.HeuristicLabeled; total > 0 {
		st.PseudoFraction = float64(st.HeuristicLabeled) / float64(total)
	}
	return samples, st
}

// ── Training ────────────────────────────────────────────────────────────────

func sigmoid(z float64) float64 { return 1.0 / (1.0 + math.Exp(-z)) }

// recordGroupKey is the leakage unit: one APK/project. Re-scans of the same
// application share the key, so they always land on the same side of the
// train/calib split. APKHash is the strongest identity; name+package is the
// fallback; the record ID is the last resort for anonymous history entries.
func recordGroupKey(r *ml.AnalysisFeedback) string {
	switch {
	case r == nil:
		return ""
	case r.APKHash != "":
		return "hash:" + r.APKHash
	case r.APKName != "" || r.Package != "":
		return "name:" + r.APKName + "|" + r.Package
	default:
		return "id:" + r.ID
	}
}

// groupRecords buckets records by APK/project and returns group keys in a
// deterministic (sorted) order.
func groupRecords(records []*ml.AnalysisFeedback) (map[string][]*ml.AnalysisFeedback, []string) {
	groups := make(map[string][]*ml.AnalysisFeedback)
	for _, r := range records {
		if r == nil {
			continue
		}
		key := recordGroupKey(r)
		groups[key] = append(groups[key], r)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return groups, keys
}

// capPseudoLabels enforces MaxPseudoFraction on the training rows: hard labels
// always stay, excess heuristic labels are dropped deterministically. Without
// the cap, a flood of pseudo-labels can outvote the few reliable ones even at
// an 8:1 weight disadvantage.
func capPseudoLabels(samples []LabeledSample, maxPseudoFraction float64, seed int64) []LabeledSample {
	if maxPseudoFraction >= 1.0 || maxPseudoFraction < 0 {
		return samples
	}
	var hardIdx, pseudoIdx []int
	for i, s := range samples {
		if s.Source == "hard" {
			hardIdx = append(hardIdx, i)
		} else {
			pseudoIdx = append(pseudoIdx, i)
		}
	}
	if len(hardIdx) == 0 {
		// No hard anchors — the cap formula degenerates; the caller's class
		// and count minimums govern whether training is meaningful at all.
		return samples
	}
	// P/(H+P) <= f  =>  P <= f*H/(1-f)
	maxPseudo := int(float64(len(hardIdx)) * maxPseudoFraction / (1 - maxPseudoFraction))
	if len(pseudoIdx) <= maxPseudo {
		return samples
	}
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(len(pseudoIdx), func(i, j int) { pseudoIdx[i], pseudoIdx[j] = pseudoIdx[j], pseudoIdx[i] })
	keep := make(map[int]bool, maxPseudo)
	for _, i := range pseudoIdx[:maxPseudo] {
		keep[i] = true
	}
	out := make([]LabeledSample, 0, len(hardIdx)+maxPseudo)
	for i, s := range samples {
		if s.Source == "hard" || keep[i] {
			out = append(out, s)
		}
	}
	return out
}

// splitBySource partitions hold-out samples for per-source evaluation.
func splitBySource(samples []LabeledSample) (hard, pseudo []LabeledSample) {
	for _, s := range samples {
		if s.Source == "hard" {
			hard = append(hard, s)
		} else {
			pseudo = append(pseudo, s)
		}
	}
	return hard, pseudo
}

// evaluateSide scores one hold-out subset at the 0.5 threshold. Nil when the
// subset is empty.
func evaluateSide(lr *ml.LogisticRegression, samples []LabeledSample) *SideMetrics {
	if len(samples) == 0 {
		return nil
	}
	sm := &SideMetrics{Samples: len(samples)}
	var tp, fp, tn, fn int
	for _, s := range samples {
		p, err := lr.Predict(s.Features)
		if err != nil {
			continue
		}
		pred := 0
		if p >= 0.5 {
			pred = 1
		}
		switch {
		case pred == 1 && s.Label == 1:
			tp++
		case pred == 1 && s.Label == 0:
			fp++
		case pred == 0 && s.Label == 0:
			tn++
		default:
			fn++
		}
	}
	sm.Positives = tp + fn
	sm.Negatives = tn + fp
	sm.Accuracy = float64(tp+tn) / float64(sm.Samples)
	if tp+fp > 0 {
		sm.Precision = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		sm.Recall = float64(tp) / float64(tp+fn)
	}
	if sm.Precision+sm.Recall > 0 {
		sm.F1 = 2 * sm.Precision * sm.Recall / (sm.Precision + sm.Recall)
	}
	return sm
}

// Train runs the full pipeline: group split → extract → fit → quality gate →
// calibrate → drift bins.
//
// The train/calibration split is performed over APK/project *groups*, before
// any aggregation, so a keyword's feature vector on one side never includes
// scans from the other side (re-scans of one app can no longer leak). Within
// a single-group history the split degenerates to the old sample-level
// hold-out — there is no cross-APK leakage to prevent there.
func Train(records []*ml.AnalysisFeedback, opts TrainOptions) (*SavedModel, LabelStats, error) {
	if opts.MinCalibSamples <= 0 {
		opts.MinCalibSamples = MinCalibSamples
	}
	if opts.MinHardEvalSamples <= 0 {
		opts.MinHardEvalSamples = 10
	}
	if opts.MinHardQuality <= 0 {
		opts.MinHardQuality = 0.6
	}

	samples, st := ExtractSamples(records, opts)
	if len(samples) < opts.MinSamples {
		return nil, st, fmt.Errorf("insufficient labeled samples: %d < %d (run more analyses or mark feedback)", len(samples), opts.MinSamples)
	}
	if st.Positives == 0 || st.Negatives == 0 {
		return nil, st, fmt.Errorf("training needs both classes: positives=%d negatives=%d", st.Positives, st.Negatives)
	}
	if opts.MinPerClass > 0 && (st.Positives < opts.MinPerClass || st.Negatives < opts.MinPerClass) {
		return nil, st, fmt.Errorf("per-class minimum not met: positives=%d negatives=%d, need >= %d per class", st.Positives, st.Negatives, opts.MinPerClass)
	}

	groups, keys := groupRecords(records)
	st.Groups = len(keys)

	// ── Group-wise train/calib split (leakage protection) ──
	var trainSamples, calibSamples []LabeledSample
	if len(keys) >= 2 {
		rng := rand.New(rand.NewSource(opts.Seed))
		rng.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
		nCalibGroups := int(float64(len(keys)) * opts.CalibFraction)
		if nCalibGroups < 1 {
			nCalibGroups = 1
		}
		if nCalibGroups > len(keys)-1 {
			nCalibGroups = len(keys) - 1
		}
		var calibRecords, trainRecords []*ml.AnalysisFeedback
		for i, k := range keys {
			if i < nCalibGroups {
				calibRecords = append(calibRecords, groups[k]...)
			} else {
				trainRecords = append(trainRecords, groups[k]...)
			}
		}
		trainSamples, _ = ExtractSamples(trainRecords, opts)
		calibSamples, _ = ExtractSamples(calibRecords, opts)
		st.GroupSplit = true
	}

	// Single-group fallback: hold out individual samples. With one APK there
	// is no cross-app leakage, only the weaker within-app generalisation.
	if len(trainSamples) == 0 || len(calibSamples) == 0 {
		rng := rand.New(rand.NewSource(opts.Seed))
		rng.Shuffle(len(samples), func(i, j int) { samples[i], samples[j] = samples[j], samples[i] })
		nCalib := int(float64(len(samples)) * opts.CalibFraction)
		if nCalib > len(samples)-2 {
			nCalib = len(samples) - 2
		}
		if nCalib < 0 {
			nCalib = 0
		}
		calibSamples = samples[:nCalib]
		trainSamples = samples[nCalib:]
		st.GroupSplit = false
	}

	// Cap the pseudo-label share of the *training* rows only.
	trainSamples = capPseudoLabels(trainSamples, opts.MaxPseudoFraction, opts.Seed)

	var trainHard, trainPseudo int
	for _, s := range trainSamples {
		if s.Source == "hard" {
			trainHard++
		} else {
			trainPseudo++
		}
	}
	trainPseudoShare := 0.0
	if total := trainHard + trainPseudo; total > 0 {
		trainPseudoShare = float64(trainPseudo) / float64(total)
	}

	var trainPos, trainNeg int
	for _, s := range trainSamples {
		if s.Label == 1 {
			trainPos++
		} else {
			trainNeg++
		}
	}
	if trainPos == 0 || trainNeg == 0 {
		return nil, st, fmt.Errorf("training split lost a class: train positives=%d negatives=%d", trainPos, trainNeg)
	}

	X, y, w := matrices(trainSamples)
	lr := ml.NewLogisticRegression(opts.LR, opts.Epochs, opts.Lambda)
	if err := lr.FitWeighted(X, y, w, ml.KeywordRelevanceFeatureNames); err != nil {
		return nil, st, fmt.Errorf("logistic fit: %w", err)
	}

	sw := lr.SaveWeights()
	weights, _ := sw["weights"].([]float64)
	bias, _ := sw["bias"].(float64)

	model := &SavedModel{
		Version:        ModelVersion,
		TrainedAt:      time.Now(),
		SampleCount:    len(trainSamples) + len(calibSamples),
		LabelCounts:    map[string]int{"hard": st.HardLabeled, "heuristic": st.HeuristicLabeled},
		Positives:      st.Positives,
		Negatives:      st.Negatives,
		FeatureNames:   append([]string(nil), ml.KeywordRelevanceFeatureNames...),
		Groups:         st.Groups,
		GroupSplit:     st.GroupSplit,
		Coverage:       st.Coverage,
		PseudoFraction: trainPseudoShare,
		LRWeights:      weights,
		LRBias:         bias,
	}

	// ── Per-source hold-out evaluation + hard-label quality gate ──
	hardEval, pseudoEval := splitBySource(calibSamples)
	model.EvalHard = evaluateSide(lr, hardEval)
	model.EvalPseudo = evaluateSide(lr, pseudoEval)
	if model.EvalHard != nil && model.EvalHard.Samples >= opts.MinHardEvalSamples && model.EvalHard.Accuracy < opts.MinHardQuality {
		return nil, st, fmt.Errorf(
			"hard-label quality gate failed: hold-out accuracy %.3f < %.3f on %d hard labels (pseudo-labels may be teaching the model to ignore human corrections)",
			model.EvalHard.Accuracy, opts.MinHardQuality, model.EvalHard.Samples)
	}

	// ── Calibration on the group-held-out set ──
	var calibProbs []float64
	var calibLabels []int
	for _, s := range calibSamples {
		p, err := lr.Predict(s.Features)
		if err != nil {
			continue
		}
		calibProbs = append(calibProbs, p)
		calibLabels = append(calibLabels, s.Label)
	}
	var calibPos, calibNeg int
	for _, l := range calibLabels {
		if l == 1 {
			calibPos++
		} else {
			calibNeg++
		}
	}
	if len(calibProbs) >= opts.MinCalibSamples && calibPos > 0 && calibNeg > 0 {
		platt := ml.NewPlattCalibrator()
		if err := platt.Fit(calibProbs, calibLabels); err == nil {
			a, b := platt.Coefficients()
			model.CalibA, model.CalibB, model.CalibFitted = a, b, true
			// ECE over the SERVED (Platt-scaled) distribution, not the raw
			// one: the runtime applies CalibA/CalibB before reporting, so an
			// ECE measured on raw probabilities understates the served error
			// (observed 0.018 raw vs 0.062 served on the same rows).
			served := make([]float64, len(calibProbs))
			for i, p := range calibProbs {
				served[i] = sigmoid(a*p + b)
			}
			ecal, err := ml.BootstrapECE(served, calibLabels, 10, bootstrapReplicates, opts.Seed)
			if err == nil {
				model.ECE = ecal.ECE
				model.ECESamples = ecal.Samples
				model.ECELow, model.ECEHigh = ecal.Lower, ecal.Upper
				// A reliability stamp needs human ground truth: a pseudo-only
				// hold-out measures self-consistency, not quality. Without a
				// single hard-label hold-out row (EvalHard == nil) the model
				// trains fine but must not advertise reliability.
				model.ECEReliable = ecal.Samples >= ECEReliableMinSamples && model.EvalHard != nil
			}
		}
	}

	model.DriftBins = buildDriftBins(trainSamples)
	return model, st, nil
}

func matrices(s []LabeledSample) (X [][]float64, y []int, w []float64) {
	X = make([][]float64, len(s))
	y = make([]int, len(s))
	w = make([]float64, len(s))
	for i, sm := range s {
		X[i] = sm.Features
		y[i] = sm.Label
		w[i] = sm.Weight
	}
	return X, y, w
}

// buildDriftBins computes a per-feature reference distribution for PSI drift
// monitoring. ±Inf edges are replaced with finite sentinels so the bins can be
// JSON-serialized; binning is unaffected since all real values lie within.
func buildDriftBins(samples []LabeledSample) map[string]*ml.FeatureBins {
	const nBins = 5
	if len(samples) < nBins {
		return nil
	}
	out := make(map[string]*ml.FeatureBins, len(ml.KeywordRelevanceFeatureNames))
	for fi, name := range ml.KeywordRelevanceFeatureNames {
		vals := make([]float64, len(samples))
		for i, s := range samples {
			if fi < len(s.Features) {
				vals[i] = s.Features[fi]
			}
		}
		bins, err := ml.BuildFeatureBins(vals, nBins)
		if err != nil {
			continue
		}
		for i, e := range bins.Edges {
			if math.IsInf(e, -1) {
				bins.Edges[i] = -finiteInf
			} else if math.IsInf(e, 1) {
				bins.Edges[i] = finiteInf
			}
		}
		out[name] = bins
	}
	return out
}

// ── Persistence ─────────────────────────────────────────────────────────────

// ECESummary renders the calibration line for CLI output. A bare ECE number
// is only shown when the hold-out is large enough to trust it; below
// ECEReliableMinSamples the summary says so explicitly instead of printing a
// deceptively precise value.
func ECESummary(calibFitted bool, ece float64, samples int, reliable bool, low, high float64) string {
	if !calibFitted {
		return "uncalibrated"
	}
	if reliable {
		return fmt.Sprintf("calibrated ECE=%.3f [%.3f–%.3f]", ece, low, high)
	}
	return fmt.Sprintf("calibrated ECE=%.3f (n=%d, unreliable — CI %.3f–%.3f)", ece, samples, low, high)
}

// SaveModel writes the model atomically (temp file + rename) with mode 0644.
func SaveModel(m *SavedModel, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("model mkdir: %w", err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("model marshal: %w", err)
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("model write: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("model rename: %w", err)
	}
	return nil
}

// LoadModel reads and validates a SavedModel. It returns (nil, nil) when the
// file does not exist, so callers can treat "no model" as the heuristic default.
func LoadModel(path string) (*SavedModel, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var m SavedModel
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("corrupt model file: %w", err)
	}
	if m.Version != ModelVersion {
		return nil, fmt.Errorf("model version mismatch: file=%d want=%d", m.Version, ModelVersion)
	}
	if len(m.LRWeights) != len(ml.KeywordRelevanceFeatureNames) {
		return nil, fmt.Errorf("model feature count mismatch: %d weights vs %d features", len(m.LRWeights), len(ml.KeywordRelevanceFeatureNames))
	}
	return &m, nil
}
