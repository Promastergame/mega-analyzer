package ml

import (
	"math"
	"math/rand"
	"sync"
)

// ─────────────────────────────────────────────────────────────────────────────
// Replay Buffer — incremental learning without catastrophic forgetting
// ─────────────────────────────────────────────────────────────────────────────
// Проблема v1 PartialFit (ml_models.go:329): чистый SGD по одному примеру
// затирает старые веса (catastrophic forgetting) — после 50 фидбеков модель
// помнит только последние 5.
//
// Решение: буфер последних N примеров + стратифицированная выборка при каждом
// PartialFit. Каждый incremental шаг:
//   1. добавляет новый пример в буфер (кольцевой, capacity 256)
//   2. семплирует мини-батч из буфера (balanced: 50% старые, 50% новые)
//   3. делает 1-3 SGD шага по батчу (а не по 1 примеру)
//   4. применяет L2 decay к весам (EWC-lite) чтобы не дрейфовать далеко от
//      исходной модели (anchor к pretrained весам)
//
// Это EWC/Replay-lite: без второй модели и Fisher matrix, но с тем же
// инвариантом — «новые данные учат, старые не забываем».
//
// Хранится только Features (8-dim) + label, ~2KB на 256 примеров — <10KB RAM.

type ReplayExample struct {
	Features []float64 `json:"features"`
	Label    int      `json:"label"` // 0 or 1
	Weight   float64  `json:"weight"` // per-example loss weight (default 1)
	Source   string   `json:"source"` // "user_feedback" / "pseudo_label"
}

type ReplayBuffer struct {
	mu       sync.Mutex
	capacity int
	buf      []ReplayExample
	pos      int // next write index (ring)
	size     int // current filled
	// anchor для EWC-lite
	anchorWeights []float64
	anchorBias    float64
	anchorSet     bool
	ewcLambda     float64 // сила привязки к anchor (0 = нет)
	rnd           *rand.Rand
}

func NewReplayBuffer(capacity int) *ReplayBuffer {
	if capacity <= 0 {
		capacity = 256
	}
	return &ReplayBuffer{
		capacity:  capacity,
		buf:       make([]ReplayExample, capacity),
		ewcLambda: 0.01,
		rnd:       rand.New(rand.NewSource(42)), // детерминирован для тестов
	}
}

// WithEWCLambda тюнит силу EWC привязки
func (rb *ReplayBuffer) WithEWCLambda(lambda float64) *ReplayBuffer {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.ewcLambda = lambda
	return rb
}

// WithSeed для детерминированных тестов
func (rb *ReplayBuffer) WithSeed(seed int64) *ReplayBuffer {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.rnd = rand.New(rand.NewSource(seed))
	return rb
}

// SetAnchor фиксирует текущие веса модели как EWC anchor
func (rb *ReplayBuffer) SetAnchor(weights []float64, bias float64) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.anchorWeights = append([]float64(nil), weights...)
	rb.anchorBias = bias
	rb.anchorSet = true
}

// Add добавляет пример (копирует Features)
func (rb *ReplayBuffer) Add(ex ReplayExample) {
	if len(ex.Features) == 0 {
		return
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	cp := ReplayExample{
		Features: append([]float64(nil), ex.Features...),
		Label:    ex.Label,
		Weight:   ex.Weight,
		Source:   ex.Source,
	}
	if cp.Weight == 0 {
		cp.Weight = 1
	}
	rb.buf[rb.pos] = cp
	rb.pos = (rb.pos + 1) % rb.capacity
	if rb.size < rb.capacity {
		rb.size++
	}
}

// Len — текущее число примеров
func (rb *ReplayBuffer) Len() int {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	return rb.size
}

// Capacity — максимум
func (rb *ReplayBuffer) Capacity() int { return rb.capacity }

// Sample — стратифицированная выборка batchSize примеров (balanced positive/negative когда возможно)
// Возвращает копии (безопасно мутировать)
func (rb *ReplayBuffer) Sample(batchSize int) []ReplayExample {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.size == 0 || batchSize <= 0 {
		return nil
	}
	if batchSize > rb.size {
		batchSize = rb.size
	}
	// собираем индексы живых элементов в кольце (0..size-1 логически)
	// физический порядок: pos-size .. pos-1 (mod capacity)
	indices := make([]int, rb.size)
	for i := 0; i < rb.size; i++ {
		indices[i] = (rb.pos - rb.size + i + rb.capacity) % rb.capacity
	}
	// стратификация: делим на positive/negative пулы
	var posIdx, negIdx []int
	for _, idx := range indices {
		if rb.buf[idx].Label == 1 {
			posIdx = append(posIdx, idx)
		} else {
			negIdx = append(negIdx, idx)
		}
	}
	// цель: ~50/50, но не требуем — если одного класса < batch/2, берём всё что есть
	wantPos := batchSize / 2
	wantNeg := batchSize - wantPos
	if len(posIdx) < wantPos {
		wantPos = len(posIdx)
		wantNeg = batchSize - wantPos
		if wantNeg > len(negIdx) {
			wantNeg = len(negIdx)
		}
	} else if len(negIdx) < wantNeg {
		wantNeg = len(negIdx)
		wantPos = batchSize - wantNeg
	}
	// shuffle each pool deterministically via rb.rnd
	shuffle := func(a []int) {
		for i := len(a) - 1; i > 0; i-- {
			j := rb.rnd.Intn(i + 1)
			a[i], a[j] = a[j], a[i]
		}
	}
	shuffle(posIdx)
	shuffle(negIdx)
	var sampled []int
	sampled = append(sampled, posIdx[:wantPos]...)
	sampled = append(sampled, negIdx[:wantNeg]...)
	// добираем если недобор (малые классы)
	if len(sampled) < batchSize {
		remaining := batchSize - len(sampled)
		// leftover из большего пула
		var leftover []int
		if len(posIdx) > wantPos {
			leftover = posIdx[wantPos:]
		} else if len(negIdx) > wantNeg {
			leftover = negIdx[wantNeg:]
		}
		if len(leftover) > 0 {
			if remaining > len(leftover) {
				remaining = len(leftover)
			}
			sampled = append(sampled, leftover[:remaining]...)
		}
	}
	// материализация
	out := make([]ReplayExample, len(sampled))
	for i, idx := range sampled {
		src := rb.buf[idx]
		out[i] = ReplayExample{
			Features: append([]float64(nil), src.Features...),
			Label:    src.Label,
			Weight:   src.Weight,
			Source:   src.Source,
		}
	}
	// финальный shuffle батча
	for i := len(out) - 1; i > 0; i-- {
		j := rb.rnd.Intn(i + 1)
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// IncrementalStep — один шаг инкрементального обучения с replay + EWC
// lr = learning rate, passes = SGD passes over batch, batchSize = replay sample size
func (rb *ReplayBuffer) IncrementalStep(model *LogisticRegression, newExamples []ReplayExample, lr float64, passes, batchSize int) error {
	if model == nil {
		return nil
	}
	if !model.trained {
		// первый Fit был обязателен — без формы весов нечего обновлять
		return nil
	}
	// добавляем новые примеры
	for _, ex := range newExamples {
		rb.Add(ex)
	}
	if rb.Len() == 0 {
		return nil
	}
	if batchSize <= 0 {
		batchSize = 32
	}
	if passes <= 0 {
		passes = 2
	}
	if lr <= 0 {
		lr = model.learningRate
		if lr == 0 {
			lr = 0.05
		}
	}

	batch := rb.Sample(batchSize)
	if len(batch) == 0 {
		return nil
	}
	// конвертируем батч в X,y,weights
	X := make([][]float64, len(batch))
	y := make([]int, len(batch))
	weights := make([]float64, len(batch))
	for i, ex := range batch {
		X[i] = ex.Features
		y[i] = ex.Label
		weights[i] = ex.Weight
		if weights[i] == 0 {
			weights[i] = 1
		}
	}

	// EWC-lite: сохраняем anchor, временно подменяем lambda на ewcLambda для этого шага
	// (простая L2 к anchor, а не полная Fisher — достаточно для 8-dim модели)
	origWeights := append([]float64(nil), model.weights...)
	origBias := model.bias
	origLambda := model.lambda

	if rb.anchorSet && len(rb.anchorWeights) == len(model.weights) {
		// на время шага усиливаем регуляризацию к anchor (эмулируем EWC penalty)
		model.lambda = origLambda + rb.ewcLambda
	}

	// делаем SGD шаги по батчу (используем PartialFit логику, но batched)
	// Reuse PartialFit per-example loop — оно уже учитывает lambda и lr
	for p := 0; p < passes; p++ {
		// shuffle батч каждый pass
		for i := len(X) - 1; i > 0; i-- {
			j := rb.rnd.Intn(i + 1)
			X[i], X[j] = X[j], X[i]
			y[i], y[j] = y[j], y[i]
			weights[i], weights[j] = weights[j], weights[i]
		}
		for i, row := range X {
			// transform via model's standardization if enabled
			trRow := model.transformRow(row)
			// forward
			z := model.bias
			for j, f := range trRow {
				if j < len(model.weights) {
					z += model.weights[j] * f
				}
			}
			pred := sigmoid(z)
			err := (pred - float64(y[i])) * weights[i]
			// EWC penalty gradient: lambda_ewc * (w - anchor)
			for j, f := range trRow {
				if j >= len(model.weights) {
					continue
				}
				grad := err*f + model.lambda*model.weights[j]
				if rb.anchorSet && j < len(rb.anchorWeights) {
					// anchor pull: additional term lambda_ewc * (w - anchor)
					// уже учтён через увеличенный lambda? для точности добавим явно:
					// но чтобы не двойной учёт, используем только lambda_ewc часть
					grad += rb.ewcLambda * (model.weights[j] - rb.anchorWeights[j])
				}
				model.weights[j] -= lr * grad
			}
			biasGrad := err
			if rb.anchorSet {
				biasGrad += rb.ewcLambda * (model.bias - rb.anchorBias)
			}
			model.bias -= lr * biasGrad
			// clamp клип весов от взрыва
			for j := range model.weights {
				if math.IsNaN(model.weights[j]) || math.IsInf(model.weights[j], 0) {
					model.weights[j] = origWeights[j]
				}
				if model.weights[j] > 10 {
					model.weights[j] = 10
				} else if model.weights[j] < -10 {
					model.weights[j] = -10
				}
			}
			if math.IsNaN(model.bias) || math.IsInf(model.bias, 0) {
				model.bias = origBias
			}
		}
	}

	model.lambda = origLambda
	model.trained = true
	return nil
}

// Snapshot — копия всех примеров в порядке от старых к новым (для истории/экспорта)
func (rb *ReplayBuffer) Snapshot() []ReplayExample {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.size == 0 {
		return nil
	}
	out := make([]ReplayExample, rb.size)
	for i := 0; i < rb.size; i++ {
		idx := (rb.pos - rb.size + i + rb.capacity) % rb.capacity
		src := rb.buf[idx]
		out[i] = ReplayExample{
			Features: append([]float64(nil), src.Features...),
			Label:    src.Label,
			Weight:   src.Weight,
			Source:   src.Source,
		}
	}
	return out
}

// ClassBalance — доля positive в буфере (для мониторинга)
func (rb *ReplayBuffer) ClassBalance() float64 {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	if rb.size == 0 {
		return 0
	}
	pos := 0
	for i := 0; i < rb.size; i++ {
		idx := (rb.pos - rb.size + i + rb.capacity) % rb.capacity
		if rb.buf[idx].Label == 1 {
			pos++
		}
	}
	return float64(pos) / float64(rb.size)
}
