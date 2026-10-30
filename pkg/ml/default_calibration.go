package ml

import "math"

// ═══════════════════════════════════════════════════════════════════════════════
// DEFAULT CALIBRATION — калибровка/гейт «по умолчанию»
// ═══════════════════════════════════════════════════════════════════════════════
//
// Сырой confidence — это НЕ вероятность, и применять патч «вслепую» по нему
// опасно. Здесь мы:
//   1) включаем консервативный conformal-гейт review по умолчанию (без обучения,
//      данные не нужны) — патчи с низкой уверенностью уходят на ревью;
//   2) даём bootstrap-хелперы, чтобы, когда появятся размеченные (score,label)
//      пары, обучить полноценный Platt-скейлер + conformal-гейт и мета-модель.
//
// Важно: DefaultReviewGate НЕ трогает численное значение Confidence (передаём
// nil-скейлер в SetConfidenceCalibration), поэтому существующее поведение и
// тесты, проверяющие точные значения confidence, не ломаются — добавляется лишь
// решение needs_review на уже посчитанной вероятности.

// defaultReviewThreshold — нонконформити-порог гейта по умолчанию: если
// (1 - p) > threshold, патч уходит на ревью. 0.4 ⇒ p < 0.6 → needs_review.
// Это осознанная дефолтная ПОЛИТИКА, а не обученный на данных порог.
const defaultReviewThreshold = 0.4

// DefaultReviewGate возвращает conformal-гейт с разумным дефолтным порогом.
// NewConformalGate без Calibrate() ставит threshold=1.0 (гейт молчит всегда) —
// мы задаём консервативный дефолт, чтобы гейт реально работал из коробки.
func DefaultReviewGate() *ConformalGate {
	g := NewConformalGate(0.1)
	g.threshold = defaultReviewThreshold
	return g
}

// BootstrapCalibration обучает Platt-скейлер и conformal-гейт на реальных
// (score,label) парах, где label∈{0,1} (1 = патч действительно корректен).
// Возвращает (nil,nil) при недостатке/рассогласовании данных, чтобы вызывающий
// откатился на DefaultReviewGate.
func BootstrapCalibration(scores []float64, labels []int) (*PlattScaler, *ConformalGate) {
	if len(scores) == 0 || len(scores) != len(labels) {
		return nil, nil
	}
	// Stratified, disjoint folds. Call BootstrapCalibrationSplit when source
	// groups (e.g. APK families) are available and should stay in one fold.
	var fitScores, gateScores []float64
	var fitLabels, gateLabels []int
	counts := [2]int{}
	for i, score := range scores {
		label := labels[i]
		if label < 0 || label > 1 || math.IsNaN(score) || math.IsInf(score, 0) {
			return nil, nil
		}
		if counts[label]%2 == 0 {
			fitScores, fitLabels = append(fitScores, score), append(fitLabels, label)
		} else {
			gateScores, gateLabels = append(gateScores, score), append(gateLabels, label)
		}
		counts[label]++
	}
	return BootstrapCalibrationSplit(fitScores, fitLabels, gateScores, gateLabels)
}

// BootstrapCalibrationSplit fits probabilities and the conformal threshold on
// independent folds. Callers must keep related sources in the same fold.
func BootstrapCalibrationSplit(scores []float64, labels []int, gateScores []float64, gateLabels []int) (*PlattScaler, *ConformalGate) {
	valid := func(x []float64, y []int) bool {
		if len(x) != len(y) { return false }
		counts := [2]int{}
		for i, v := range x {
			if math.IsNaN(v) || math.IsInf(v, 0) || y[i] < 0 || y[i] > 1 { return false }
			counts[y[i]]++
		}
		return counts[0] >= 5 && counts[1] >= 5
	}
	if !valid(scores, labels) || !valid(gateScores, gateLabels) { return nil, nil }
	ps := NewPlattScaler()
	ps.Fit(scores, labels)

	gate := NewConformalGate(0.1)
	probs := make([]float64, len(gateScores))
	for i, s := range gateScores {
		p := ps.Probability(s)
		if gateLabels[i] == 1 {
			probs[i] = p // вероятность истинного класса (позитив)
		} else {
			probs[i] = 1 - p // вероятность истинного класса (негатив)
		}
	}
	gate.Calibrate(probs)
	return ps, gate
}

// EnableDefaultCalibration включает дефолтный review-гейт на скорере, не
// искажая значения Confidence (scaler=nil). Удобный one-call для интеграций,
// собирающих PatchScorer вручную.
func (ps *PatchScorer) EnableDefaultCalibration() {
	if ps != nil {
		ps.SetConfidenceCalibration(nil, DefaultReviewGate())
	}
}

// EnableTrainedCalibration обучает и включает Platt+gate из размеченных данных.
// При недостатке данных откатывается на дефолтный review-гейт.
func (ps *PatchScorer) EnableTrainedCalibration(scores []float64, labels []int) {
	if ps == nil {
		return
	}
	scaler, gate := BootstrapCalibration(scores, labels)
	if scaler == nil || gate == nil {
		ps.EnableDefaultCalibration()
		return
	}
	ps.SetConfidenceCalibration(scaler, gate)
}
