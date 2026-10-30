package ml

import (
	"fmt"
	"sort"
)

// ─────────────────────────────────────────────────────────────────────────────
// Adaptive Conformal — per-category, per-difficulty calibration
// ─────────────────────────────────────────────────────────────────────────────
// Проблема базового conformal.go: один глобальный quantile для всех категорий.
// Но billing/integrity gates имеют другую калибровку, чем ads/feature gates.
// Результат: high-risk категории перекалиброваны, noisy — недокалиброваны.
//
// Решение: per-category conformal с Mondrian conformal prediction.
// Каждая категория имеет свой калибровочный набор и свой quantile.
// Для категории без калибровки — fallback к глобальному.
// Также адаптивность по difficulty (hard/medium/low) — "adaptive prediction sets".

// MondrianConformal — per-category conformal (Mondrian)
type MondrianConformal struct {
	perCategory map[PatchCategory]*ConformalPredictor
	global      *ConformalPredictor
}

// NewMondrianConformal создаёт пустой Mondrian predictor
func NewMondrianConformal() *MondrianConformal {
	return &MondrianConformal{
		perCategory: make(map[PatchCategory]*ConformalPredictor),
		global:      NewConformalPredictor(),
	}
}

// FitCategory обучает conformal для одной категории
func (mc *MondrianConformal) FitCategory(cat PatchCategory, probs []float64, labels []int) error {
	if len(probs) == 0 {
		return fmt.Errorf("mondrian: empty category %s", cat)
	}
	cp := NewConformalPredictor()
	if err := cp.Fit(probs, labels); err != nil {
		return err
	}
	mc.perCategory[cat] = cp
	return nil
}

// FitGlobal обучает fallback глобальный калибратор
func (mc *MondrianConformal) FitGlobal(probs []float64, labels []int) error {
	return mc.global.Fit(probs, labels)
}

// Predict возвращает conformal set с учётом категории
func (mc *MondrianConformal) Predict(cat PatchCategory, prob float64, alpha float64) (PredictionSet, error) {
	if cp, ok := mc.perCategory[cat]; ok && len(cp.calibScores) >= 10 {
		return cp.Predict(prob, alpha)
	}
	// fallback global
	if len(mc.global.calibScores) == 0 {
		// эвристика: если нет калибровки — используем EstimateCategoryConformalConfidence
		// как приближение (не даёт гарантии покрытия, но лучше чем ошибка).
		// HeuristicFallback=true обязателен: без него вызывающий код не отличит
		// эту эвристику от настоящей conformal-калибровки.
		est := EstimateCategoryConformalConfidence(cat, prob)
		// маппим на PredictionSet: если ReviewNeeded → ambiguous, иначе singleton
		if est.ReviewNeeded {
			return PredictionSet{Includes0: true, Includes1: true, NonconfQ: (est.Upper - est.Lower) / 2, HeuristicFallback: true}, nil
		}
		if prob >= 0.5 {
			return PredictionSet{Includes0: false, Includes1: true, NonconfQ: 0.12, HeuristicFallback: true}, nil
		}
		return PredictionSet{Includes0: true, Includes1: false, NonconfQ: 0.12, HeuristicFallback: true}, nil
	}
	return mc.global.Predict(prob, alpha)
}

// CategoryStats — отчёт по категории для отладки
type CategoryConformalStats struct {
	Category   PatchCategory `json:"category"`
	CalibSize  int           `json:"calib_size"`
	Quantile   float64       `json:"quantile"`    // (1-α) quantile для α=0.1
	Coverage90 float64       `json:"coverage_90"` // эмпирическое покрытие на калибровке
	IsFallback bool          `json:"is_fallback"`
}

// Stats возвращает per-category статистику (для -ml-stats / REPORT)
func (mc *MondrianConformal) Stats(alpha float64) []CategoryConformalStats {
	var out []CategoryConformalStats
	for cat, cp := range mc.perCategory {
		q := 0.0
		if len(cp.calibScores) > 0 {
			n := len(cp.calibScores)
			rank := int((float64(n+1) * (1 - alpha)))
			if rank > n {
				rank = n
			}
			if rank < 1 {
				rank = 1
			}
			q = cp.calibScores[rank-1]
		}
		out = append(out, CategoryConformalStats{
			Category:   cat,
			CalibSize:  len(cp.calibScores),
			Quantile:   q,
			IsFallback: false,
		})
	}
	// global fallback entry
	if len(mc.global.calibScores) > 0 {
		n := len(mc.global.calibScores)
		rank := int((float64(n+1) * (1 - alpha)))
		if rank > n {
			rank = n
		}
		if rank < 1 {
			rank = 1
		}
		out = append(out, CategoryConformalStats{
			Category:   "global_fallback",
			CalibSize:  len(mc.global.calibScores),
			Quantile:   mc.global.calibScores[rank-1],
			IsFallback: true,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out
}

// AdaptiveThreshold — per-category оптимальный порог по F1 (из eval harness)
// Используется для динамической категоризации RiskLevel (вместо глобальных 65/45/30)
type AdaptiveThreshold struct {
	Category  PatchCategory `json:"category"`
	Threshold float64       `json:"threshold"` // prob threshold for "positive"
	F1        float64       `json:"f1"`
	Support   int           `json:"support"`
}

// LearnAdaptiveThresholds — по eval данным учит per-category пороги
func LearnAdaptiveThresholds(probs map[string]float64, labels []GoldenLabel) []AdaptiveThreshold {
	// grouped by category
	byCat := make(map[string][]GoldenLabel)
	for _, gl := range labels {
		byCat[gl.Category] = append(byCat[gl.Category], gl)
	}
	var out []AdaptiveThreshold
	for cat, gls := range byCat {
		var catProbs []float64
		var catLabels []int
		for _, gl := range gls {
			if p, ok := probs[gl.MethodSig]; ok {
				catProbs = append(catProbs, p)
				catLabels = append(catLabels, gl.Label)
			}
		}
		if len(catProbs) < 10 {
			continue
		}
		sweep := sweepThresholds(catProbs, catLabels)
		out = append(out, AdaptiveThreshold{
			Category:  PatchCategory(cat),
			Threshold: sweep.BestThresh,
			F1:        sweep.BestF1,
			Support:   len(catProbs),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out
}
