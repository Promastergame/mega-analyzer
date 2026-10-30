package ml

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Eval Harness — offline evaluation for pkg/ml predictions
// ─────────────────────────────────────────────────────────────────────────────
// Проблема: до этого pkg/ml тестировался только unit-тестами на синтетике.
// Нет единого места, где можно ответить: "precision High = 0.91 после
// последнего коммита или 0.73?" — регрессии не ловились.
//
// Решение: лёгкий, детерминированный eval, который:
//   • на golden-наборе (demo/vulnerable-app + анонимизированные APK) считает
//     per-category precision/recall/F1, ROC-AUC, PR-AUC, ECE, PSI drift
//   • пишет единый EvalReport в analysis.json и REPORT.html
//   • фейлит CI если High precision < порога или ECE > 0.15
//
// Все метрики — чистый stdlib, без внешних зависимостей, чтобы работать
// offline на 2012-era potato (требование проекта).
//
// Использование:
//   pred := predictor.PredictFromDirectory("demo/vulnerable-app")
//   labeled := loadGoldenLabels("testdata/golden.json") // map[methodSig]bool
//   report := Evaluate(pred, labeled)
//   if report.Overall.ECE > 0.15 { log.warn("miscalibrated") }

// GoldenLabel — истина для метода
type GoldenLabel struct {
	MethodSig string `json:"method_sig"`
	Category  string `json:"category"`
	Label     int    `json:"label"` // 1 = gate, 0 = non-gate
}

// CategoryMetrics — precision/recall/F1 per category
type CategoryMetrics struct {
	Category  string  `json:"category"`
	Support   int     `json:"support"` // total labeled in category
	TP        int     `json:"tp"`
	FP        int     `json:"fp"`
	TN        int     `json:"tn"`
	FN        int     `json:"fn"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	AUC       float64 `json:"auc,omitempty"` // ROC-AUC when probs available
}

// OverallMetrics — агрегат
type OverallMetrics struct {
	ProbabilitySamples int `json:"probability_samples"`
	CalibrationStatus string `json:"calibration_status"`
	Total     int     `json:"total"`
	Accuracy  float64 `json:"accuracy"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	ECE       float64 `json:"ece,omitempty"` // Meaningful only when CalibrationStatus is measured.
	Brier     float64 `json:"brier,omitempty"`
	PSI       float64 `json:"psi,omitempty"` // PSI vs reference distribution
}

// EvalReport — полный отчёт eval
type EvalReport struct {
	HighPrecision float64 `json:"high_precision"`
	HighPredictions int `json:"high_predictions"`
	Overall    OverallMetrics    `json:"overall"`
	ByCategory []CategoryMetrics `json:"by_category"`
	Thresholds ThresholdSweep     `json:"thresholds,omitempty"`
	Drift      *DriftReport      `json:"drift,omitempty"`
	Passed     bool              `json:"passed"`
	Failures   []string          `json:"failures,omitempty"`
}

// ThresholdSweep — sweep по порогу для PR/ROC кривой
type ThresholdSweep struct {
	Thresholds []float64 `json:"thresholds"`
	Precisions []float64 `json:"precisions"`
	Recalls    []float64 `json:"recalls"`
	F1s        []float64 `json:"f1s"`
	BestF1     float64   `json:"best_f1"`
	BestThresh float64   `json:"best_thresh"`
}

// DriftReport — PSI per feature + PageHinkley
type DriftReport struct {
	PerFeature map[string]float64 `json:"per_feature_psi"`
	WorstFeature string            `json:"worst_feature"`
	WorstPSI     float64           `json:"worst_psi"`
	Verdict      string            `json:"verdict"` // stable / moderate_drift / significant_drift
}

// EvalConfig — пороги для pass/fail
type EvalConfig struct {
	AllowMissingProbabilities bool // Explicit classification-only evaluation.
	MinPrecisionHigh float64
	MaxECE           float64
	MaxPSI           float64
	MinF1            float64
}

func DefaultEvalConfig() EvalConfig {
	return EvalConfig{
		MinPrecisionHigh: 0.75,
		MaxECE:           0.15,
		MaxPSI:           0.25,
		MinF1:            0.70,
	}
}

// Evaluate — главный вход: prediction + golden → report
func Evaluate(pred *PatchPrediction, labels []GoldenLabel, probs map[string]float64, cfg EvalConfig) EvalReport {
	if cfg.MinPrecisionHigh == 0 {
		cfg = DefaultEvalConfig()
	}
	// index prediction: methodSig → predicted positive?
	predSet := make(map[string]bool)
	predCat := make(map[string]string)
	highSet := make(map[string]bool)
	if pred != nil {
		for _, pt := range pred.HighRisk { highSet[pt.MethodSignature] = true }
		for _, bucket := range [][]PatchPoint{pred.HighRisk, pred.MediumRisk, pred.LowRisk} {
			for _, pt := range bucket {
				if !predSet[pt.MethodSignature] { predCat[pt.MethodSignature] = string(pt.Category) }
				predSet[pt.MethodSignature] = true
			}
		}
		// library/malware buckets are not gates — ignore for eval
	}

	// overall counts
	var tp, fp, tn, fn int
	byCat := make(map[string]*CategoryMetrics)
	// for ECE/Brier we need probs and labels aligned
	var evalProbs []float64
	var evalLabels []int
	var brierSum float64
	var highTP, highFP int
	getCategory := func(category string) *CategoryMetrics {
		if byCat[category] == nil { byCat[category] = &CategoryMetrics{Category: category} }
		return byCat[category]
	}

	for _, gl := range labels {
		predPos := predSet[gl.MethodSig]
		truePos := gl.Label == 1
		if highSet[gl.MethodSig] {
			if truePos { highTP++ } else { highFP++ }
		}
		switch {
		case truePos && predPos:
			tp++
		case !truePos && predPos:
			fp++
		case !truePos && !predPos:
			tn++
		case truePos && !predPos:
			fn++
		}
		// per category
		cm := getCategory(gl.Category)
		cm.Support++
		categoryMatch := predPos && predCat[gl.MethodSig] == gl.Category
		switch {
		case truePos && categoryMatch:
			cm.TP++
		case !truePos && categoryMatch:
			cm.FP++
		case !truePos && !categoryMatch:
			cm.TN++
		case truePos && !categoryMatch:
			cm.FN++
		}
		if predPos && !categoryMatch { getCategory(predCat[gl.MethodSig]).FP++ }
		// ECE/Brier if probs available
		if p, ok := probs[gl.MethodSig]; ok && validEvalProbability(p) {
			evalProbs = append(evalProbs, p)
			evalLabels = append(evalLabels, gl.Label)
			diff := p - float64(gl.Label)
			brierSum += diff * diff
		}
	}

	total := len(labels)
	overall := OverallMetrics{Total: total, ProbabilitySamples: len(evalProbs), CalibrationStatus: "not_evaluated"}
	if len(evalProbs) > 0 {
		overall.CalibrationStatus = "partial"
		if len(evalProbs) == total { overall.CalibrationStatus = "measured" }
	}
	if total > 0 {
		overall.Accuracy = float64(tp+tn) / float64(total)
		if tp+fp > 0 {
			overall.Precision = float64(tp) / float64(tp+fp)
		}
		if tp+fn > 0 {
			overall.Recall = float64(tp) / float64(tp+fn)
		}
		if overall.Precision+overall.Recall > 0 {
			overall.F1 = 2 * overall.Precision * overall.Recall / (overall.Precision + overall.Recall)
		}
		if len(evalLabels) > 0 {
			overall.Brier = brierSum / float64(len(evalLabels))
			if ece, err := ExpectedCalibrationError(evalProbs, evalLabels, 10); err == nil {
				overall.ECE = ece
			}
		}
	}

	// per-category finalize
	var byCatSlice []CategoryMetrics
	for _, cm := range byCat {
		if cm.TP+cm.FP > 0 {
			cm.Precision = float64(cm.TP) / float64(cm.TP+cm.FP)
		}
		if cm.TP+cm.FN > 0 {
			cm.Recall = float64(cm.TP) / float64(cm.TP+cm.FN)
		}
		if cm.Precision+cm.Recall > 0 {
			cm.F1 = 2 * cm.Precision * cm.Recall / (cm.Precision + cm.Recall)
		}
		// AUC per category if probs available for that category
		var catProbs []float64
		var catLabels []int
		for _, gl := range labels {
			if gl.Category != cm.Category {
				continue
			}
			if p, ok := probs[gl.MethodSig]; ok && validEvalProbability(p) {
				catProbs = append(catProbs, p)
				catLabels = append(catLabels, gl.Label)
			}
		}
		if len(catProbs) >= 4 {
			cm.AUC = rocAUC(catProbs, catLabels)
		}
		byCatSlice = append(byCatSlice, *cm)
	}
	sort.Slice(byCatSlice, func(i, j int) bool { return byCatSlice[i].Category < byCatSlice[j].Category })

	// threshold sweep for PR curve
	var sweep ThresholdSweep
	if len(evalProbs) >= 10 {
		sweep = sweepThresholds(evalProbs, evalLabels)
	}

	// pass/fail
	passed := true
	var failures []string
	highPrecision := 0.0
	if highTP+highFP > 0 { highPrecision = float64(highTP)/float64(highTP+highFP) }
	if highTP+highFP > 0 && highPrecision < cfg.MinPrecisionHigh {
		passed = false
		failures = append(failures, fmt.Sprintf("High precision %.3f < %.3f", highPrecision, cfg.MinPrecisionHigh))
	}
	if !cfg.AllowMissingProbabilities && overall.CalibrationStatus != "measured" {
		passed = false
		failures = append(failures, "calibration not fully evaluated: missing or invalid probabilities")
	}
	if total == 0 { passed = false; failures = append(failures, "no labeled samples") }
	if overall.ECE > cfg.MaxECE && len(evalProbs) >= 20 {
		passed = false
		failures = append(failures, fmt.Sprintf("ECE %.3f > %.3f (miscalibrated)", overall.ECE, cfg.MaxECE))
	}
	if overall.F1 < cfg.MinF1 && total >= 20 {
		passed = false
		failures = append(failures, fmt.Sprintf("F1 %.3f < %.3f", overall.F1, cfg.MinF1))
	}

	return EvalReport{
		HighPrecision: highPrecision,
		HighPredictions: highTP+highFP,
		Overall:    overall,
		ByCategory: byCatSlice,
		Thresholds: sweep,
		Passed:     passed,
		Failures:   failures,
	}
}

func validEvalProbability(p float64) bool {
	return !math.IsNaN(p) && !math.IsInf(p, 0) && p >= 0 && p <= 1
}

// EvaluateWithDrift — Evaluate + PSI drift vs reference feature bins
func EvaluateWithDrift(pred *PatchPrediction, labels []GoldenLabel, probs map[string]float64, refBins map[string]*FeatureBins, curFeatures map[string][]float64) EvalReport {
	report := Evaluate(pred, labels, probs, DefaultEvalConfig())
	if len(refBins) == 0 || len(curFeatures) == 0 {
		return report
	}
	dr := &DriftReport{
		PerFeature: make(map[string]float64),
	}
	var worstPSI float64
	var worstFeat string
	for feat, bins := range refBins {
		vals, ok := curFeatures[feat]
		if !ok || len(vals) == 0 {
			continue
		}
		psi, err := PSI(bins, vals)
		if err != nil || math.IsNaN(psi) {
			continue
		}
		dr.PerFeature[feat] = psi
		if psi > worstPSI {
			worstPSI = psi
			worstFeat = feat
		}
	}
	dr.WorstPSI = worstPSI
	dr.WorstFeature = worstFeat
	dr.Verdict = PSIVerdict(worstPSI)
	report.Drift = dr
	if dr.Verdict == "significant_drift" {
		report.Passed = false
		report.Failures = append(report.Failures, fmt.Sprintf("drift %s PSI %.3f on %s", dr.Verdict, dr.WorstPSI, dr.WorstFeature))
	}
	return report
}

// ── helpers ──────────────────────────────────────────────────────────────────

func rocAUC(probs []float64, labels []int) float64 {
	auc, err := AreaUnderROC(probs, labels)
	if err != nil {
		return 0.5
	}
	return auc
}

func sweepThresholds(probs []float64, labels []int) ThresholdSweep {
	thresholds := []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9}
	var precisions, recalls, f1s []float64
	var bestF1, bestThresh float64
	for _, thresh := range thresholds {
		var tp, fp, fn int
		for i, p := range probs {
			pred := 0
			if p >= thresh {
				pred = 1
			}
			if labels[i] == 1 && pred == 1 {
				tp++
			} else if labels[i] == 0 && pred == 1 {
				fp++
			} else if labels[i] == 1 && pred == 0 {
				fn++
			}
		}
		prec := 0.0
		if tp+fp > 0 {
			prec = float64(tp) / float64(tp+fp)
		}
		rec := 0.0
		if tp+fn > 0 {
			rec = float64(tp) / float64(tp+fn)
		}
		f1 := 0.0
		if prec+rec > 0 {
			f1 = 2 * prec * rec / (prec + rec)
		}
		precisions = append(precisions, math.Round(prec*1000)/1000)
		recalls = append(recalls, math.Round(rec*1000)/1000)
		f1s = append(f1s, math.Round(f1*1000)/1000)
		if f1 > bestF1 {
			bestF1 = f1
			bestThresh = thresh
		}
	}
	return ThresholdSweep{
		Thresholds: thresholds,
		Precisions: precisions,
		Recalls:    recalls,
		F1s:        f1s,
		BestF1:     math.Round(bestF1*1000) / 1000,
		BestThresh: bestThresh,
	}
}

// Summary returns compact human-readable summary for logs
func (r EvalReport) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Eval overall: acc=%.3f prec=%.3f rec=%.3f F1=%.3f ECE=%.3f Brier=%.3f",
		r.Overall.Accuracy, r.Overall.Precision, r.Overall.Recall, r.Overall.F1, r.Overall.ECE, r.Overall.Brier))
	if r.Thresholds.BestF1 > 0 {
		sb.WriteString(fmt.Sprintf(" bestF1=%.3f@%.2f", r.Thresholds.BestF1, r.Thresholds.BestThresh))
	}
	if r.Drift != nil && r.Drift.WorstFeature != "" {
		sb.WriteString(fmt.Sprintf(" drift=%s PSI=%.3f on %s", r.Drift.Verdict, r.Drift.WorstPSI, r.Drift.WorstFeature))
	}
	if !r.Passed {
		sb.WriteString(" FAIL: " + strings.Join(r.Failures, "; "))
	} else {
		sb.WriteString(" PASS")
	}
	return sb.String()
}
