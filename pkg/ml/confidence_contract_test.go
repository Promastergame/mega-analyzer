package ml

import (
	"testing"
)

// TestFinalizePreservesMetaModel — P1#3: противоположные предсказания
// метамодели обязаны давать разную финальную уверенность (раньше оба
// превращались в одинаковые 0.95 эвристикой).
func TestFinalizePreservesMetaModel(t *testing.T) {
	mk := func(bias float64) *PatchScorer {
		ps := NewPatchScorer(nil)
		ps.SetMetaModel(&StackedMeta{Bias: bias})
		return ps
	}
	point := func() (*PatchPoint, *ScoredMethod) {
		return &PatchPoint{RiskScore: 95}, &ScoredMethod{}
	}
	pHi, sHi := point()
	mk(10).FinalizeConfidence(pHi, sHi)
	pLo, sLo := point()
	mk(-10).FinalizeConfidence(pLo, sLo)

	if pHi.Confidence-pLo.Confidence < 0.9 {
		t.Errorf("metaModel outputs collapsed: hi=%v lo=%v", pHi.Confidence, pLo.Confidence)
	}
	if pLo.Confidence > 0.5 {
		t.Errorf("near-zero metaModel prediction became confidence %v", pLo.Confidence)
	}
}

// TestFinalizeDecidesOnCalibratedProbability — P1#3: решение использует
// калиброванную вероятность, а не исходные 0.95. Калибратор σ(s−0.103)
// отображает 0.95 → 0.70: итог обязан быть needs_review, не auto_patch.
func TestFinalizeDecidesOnCalibratedProbability(t *testing.T) {
	ps := NewPatchScorer(nil)
	ps.SetConfidenceCalibration(&PlattScaler{A: 1.0, B: -0.103}, nil)
	point := &PatchPoint{RiskScore: 95}
	ps.FinalizeConfidence(point, &ScoredMethod{})

	if point.Confidence < 0.69 || point.Confidence > 0.71 {
		t.Errorf("Confidence = %v, want ~0.70 (calibrated)", point.Confidence)
	}
	if point.RuntimeDecision != "needs_review" {
		t.Errorf("decision = %s, want needs_review (0.70 < 0.85)", point.RuntimeDecision)
	}
	if point.RuntimeConfidence == nil || point.RuntimeConfidence.Probability != point.Confidence {
		t.Error("published confidence diverges from RuntimeConfidence.Probability")
	}
}

// TestBootstrapCalibrationSplitContract — сплит требует независимые фолды:
// мало данных → отказ (nil), достаточно сбалансированных → scaler+gate.
func TestBootstrapCalibrationSplitContract(t *testing.T) {
	smallScores := []float64{0.1, 0.2, 0.8, 0.9, 0.15, 0.25, 0.75, 0.85, 0.3, 0.7}
	smallLabels := []int{0, 0, 1, 1, 0, 0, 1, 1, 0, 1}
	if ps, gate := BootstrapCalibration(smallScores, smallLabels); ps != nil || gate != nil {
		t.Error("10 samples must be insufficient for disjoint fit/gate folds")
	}
	var bigScores []float64
	var bigLabels []int
	for i := 0; i < 12; i++ {
		bigScores = append(bigScores, 0.1+0.01*float64(i))
		bigLabels = append(bigLabels, 0)
		bigScores = append(bigScores, 0.8+0.01*float64(i))
		bigLabels = append(bigLabels, 1)
	}
	ps, gate := BootstrapCalibration(bigScores, bigLabels)
	if ps == nil || gate == nil {
		t.Fatal("24 balanced samples must yield scaler+gate on disjoint folds")
	}
	if p := ps.Probability(0.9); p <= 0.5 {
		t.Errorf("calibrated P(0.9) = %v, want > 0.5", p)
	}
}
