package ml

import "math"

// ═══════════════════════════════════════════════════════════════════════════════
// RUNTIME INTELLIGENCE — калиброванная уверенность и гейт «needs_review»
// ═══════════════════════════════════════════════════════════════════════════════
//
// Задача: не применять патч «вслепую». Сырой score модели плохо интерпретируется
// как вероятность. Здесь:
//
//   • PlattScaler         — калибрует сырой score в вероятность (Platt scaling).
//   • ConformalGate       — split-conformal порог: если 1-p выше порога значимости,
//                           помечает результат как неопределённый (needs_review).
//   • RuntimeConfidence   — объединяет калиброванную вероятность, строгий smali-lint
//                           и conformal-гейт в одно решение: применять / на ревью.
//   • StackedMeta         — обучаемый лог-регрессионный мета-комбайнер сигналов
//                           вместо захардкоженных весов ансамбля.
//
// Всё аддитивно и самодостаточно — не меняет существующий hot-path, но готово к
// интеграции в patch_scorer/patch_generator.

// PlattScaler калибрует сырой score s в вероятность через σ(a·s + b).
type PlattScaler struct {
	A float64 `json:"a"`
	B float64 `json:"b"`
}

// NewPlattScaler возвращает единичный (identity-подобный) калибратор.
func NewPlattScaler() *PlattScaler { return &PlattScaler{A: 1.0, B: 0.0} }

// Probability отображает сырой score в [0,1].
func (p *PlattScaler) Probability(score float64) float64 {
	return 1.0 / (1.0 + math.Exp(-(p.A*score + p.B)))
}

// Fit подбирает A,B методом Ньютона на парах (score, label∈{0,1}).
// Детерминированный, без внешних зависимостей.
func (p *PlattScaler) Fit(scores []float64, labels []int) {
	if len(scores) == 0 || len(scores) != len(labels) {
		return
	}
	a, b := 1.0, 0.0
	for iter := 0; iter < 100; iter++ {
		var g0, g1 float64          // градиент по a,b
		var h00, h01, h11 float64   // гессиан
		for i, s := range scores {
			z := a*s + b
			pr := 1.0 / (1.0 + math.Exp(-z))
			y := float64(labels[i])
			d := pr - y
			g0 += d * s
			g1 += d
			w := pr * (1 - pr)
			h00 += w * s * s
			h01 += w * s
			h11 += w
		}
		// регуляризация диагонали для устойчивости
		h00 += 1e-6
		h11 += 1e-6
		det := h00*h11 - h01*h01
		if math.Abs(det) < 1e-12 {
			break
		}
		da := (h11*g0 - h01*g1) / det
		db := (h00*g1 - h01*g0) / det
		a -= da
		b -= db
		if math.Abs(da) < 1e-9 && math.Abs(db) < 1e-9 {
			break
		}
	}
	if !math.IsNaN(a) && !math.IsInf(a, 0) && !math.IsNaN(b) && !math.IsInf(b, 0) {
		p.A, p.B = a, b
	}
}

// ConformalGate реализует split-conformal порог значимости. Калибруется на
// нонконформити-скорах (1 - p_истинного_класса) валидационного набора.
type ConformalGate struct {
	Alpha     float64   `json:"alpha"`     // уровень значимости (напр. 0.1 = 90% покрытие)
	threshold float64   // квантиль нонконформити
	scores    []float64 // отсортированные калибровочные нонконформити
}

// NewConformalGate создаёт гейт с уровнем значимости alpha.
func NewConformalGate(alpha float64) *ConformalGate {
	if alpha <= 0 || alpha >= 1 {
		alpha = 0.1
	}
	return &ConformalGate{Alpha: alpha, threshold: 1.0}
}

// Calibrate задаёт порог по калибровочным вероятностям истинного класса.
func (c *ConformalGate) Calibrate(trueClassProbs []float64) {
	if len(trueClassProbs) == 0 {
		return
	}
	nc := make([]float64, len(trueClassProbs))
	for i, p := range trueClassProbs {
		nc[i] = 1.0 - p
	}
	// вставочная сортировка (детерминированно, малые наборы)
	for i := 1; i < len(nc); i++ {
		v := nc[i]
		j := i - 1
		for j >= 0 && nc[j] > v {
			nc[j+1] = nc[j]
			j--
		}
		nc[j+1] = v
	}
	c.scores = nc
	// индекс квантиля (1-alpha) с поправкой конформного предиктора
	q := math.Ceil((float64(len(nc))+1)*(1-c.Alpha)) - 1
	if q < 0 {
		q = 0
	}
	if int(q) >= len(nc) {
		q = float64(len(nc) - 1)
	}
	c.threshold = nc[int(q)]
}

// Uncertain возвращает true, если вероятность p недостаточно уверенная (патч
// следует отправить на ревью, а не применять автоматически).
func (c *ConformalGate) Uncertain(p float64) bool {
	return (1.0 - p) > c.threshold
}

// RuntimeConfidence — итоговое решение по патчу.
type RuntimeConfidence struct {
	Probability float64  `json:"probability"`  // калиброванная вероятность корректности
	NeedsReview bool     `json:"needs_review"` // требуется ручная проверка
	Reasons     []string `json:"reasons,omitempty"`
}

// AssessPatch объединяет калиброванную вероятность, строгий smali-lint и
// conformal-гейт в одно решение. smaliCode может быть пустым (пропустить lint).
func AssessPatch(scaler *PlattScaler, gate *ConformalGate, rawScore float64, smaliCode string) RuntimeConfidence {
	rc := RuntimeConfidence{}
	p := rawScore
	if scaler != nil {
		p = scaler.Probability(rawScore)
	}
	if math.IsNaN(p) || math.IsInf(p, 0) {
		p = 0
	}
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	rc.Probability = p

	if gate != nil && gate.Uncertain(p) {
		rc.NeedsReview = true
		rc.Reasons = append(rc.Reasons, "conformal: insufficient confidence")
	}
	if smaliCode != "" {
		if issues := LintSmaliStrict(smaliCode); len(issues) > 0 {
			rc.NeedsReview = true
			for _, is := range issues {
				rc.Reasons = append(rc.Reasons, "smali-lint: "+is)
			}
		}
	}
	return rc
}

// StackedMeta — обучаемый лог-регрессионный мета-комбайнер сигналов ансамбля
// (замена захардкоженным весам). Детерминированный градиентный спуск.
type StackedMeta struct {
	Weights []float64 `json:"weights"`
	Bias    float64   `json:"bias"`
	LR      float64   `json:"lr"`
	Epochs  int       `json:"epochs"`
}

// NewStackedMeta создаёт мета-модель на n сигналов.
func NewStackedMeta(n int) *StackedMeta {
	return &StackedMeta{Weights: make([]float64, n), LR: 0.1, Epochs: 200}
}

// Predict возвращает вероятность из вектора сигналов.
func (m *StackedMeta) Predict(x []float64) float64 {
	z := m.Bias
	for i := 0; i < len(x) && i < len(m.Weights); i++ {
		z += m.Weights[i] * x[i]
	}
	return 1.0 / (1.0 + math.Exp(-z))
}

// Fit обучает мета-модель на матрице сигналов X и метках y∈{0,1}.
func (m *StackedMeta) Fit(X [][]float64, y []int) {
	if len(X) == 0 || len(X) != len(y) {
		return
	}
	n := len(m.Weights)
	for e := 0; e < m.Epochs; e++ {
		gW := make([]float64, n)
		gB := 0.0
		for i, x := range X {
			pr := m.Predict(x)
			d := pr - float64(y[i])
			for j := 0; j < n && j < len(x); j++ {
				gW[j] += d * x[j]
			}
			gB += d
		}
		inv := m.LR / float64(len(X))
		for j := 0; j < n; j++ {
			m.Weights[j] -= inv * gW[j]
		}
		m.Bias -= inv * gB
	}
}
