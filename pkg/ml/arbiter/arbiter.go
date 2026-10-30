package arbiter

import (
	"sort"

	"mega-analyzer/pkg/ml/arbiter/hdc"
)

// Anchor — одна "прецедентная" сигнатура: заранее закодированный вектор
// известного вредоносного паттерна плюс человекочитаемая метка и вес.
// Анкоры не обучаются — это просто маленькая курируемая база знаний,
// закодированная через тот же feature-encoding, что и реальные находки.
type Anchor struct {
	Label  string
	Vector hdc.Vector
	Weight float64
}

// Match — результат сравнения одной находки с одним анкором.
type Match struct {
	Label string
	Sim   float32
}

// Arbiter — "precedent similarity" сигнал: сравнивает HDC-вектор находки
// с маленьким in-memory anchor store известно-плохих сигнатур через
// Sim() (косинусоподобная близость по Хэммингу). Дёшево, объяснимо,
// работает на CPU, не требует переобучения.
type Arbiter struct {
	anchors []Anchor
}

// simThreshold — минимальная похожесть, чтобы анкор считался "совпавшим"
// и попал в объяснение (matched []string).
const simThreshold = 0.62

// New создаёт Arbiter с дефолтным набором сидированных анкоров.
func New() *Arbiter {
	return &Arbiter{anchors: defaultAnchors()}
}

// NewWithAnchors создаёт Arbiter с произвольным набором анкоров (для тестов).
func NewWithAnchors(anchors []Anchor) *Arbiter {
	return &Arbiter{anchors: anchors}
}

// Score кодирует набор фич (см. BlockFeatures) в hypervector и сравнивает
// его с каждым анкором. Возвращает максимальную похожесть как score в
// [0,1] и список меток анкоров, превысивших simThreshold (по убыванию
// похожести), объясняющих, на что конкретно похожа находка.
func (a *Arbiter) Score(feats map[string]string) (float32, []Match) {
	if len(feats) == 0 || len(a.anchors) == 0 {
		return 0, nil
	}

	vec := hdc.EncodeFeatures(feats)

	var best float32
	matches := make([]Match, 0, 4)
	for _, anc := range a.anchors {
		sim := vec.Sim(anc.Vector) * float32(anc.Weight)
		if sim > best {
			best = sim
		}
		if sim >= simThreshold {
			matches = append(matches, Match{Label: anc.Label, Sim: sim})
		}
	}

	sort.Slice(matches, func(i, j int) bool { return matches[i].Sim > matches[j].Sim })
	return best, matches
}

// defaultAnchors — курируемые сигнатуры известно-плохих паттернов,
// закодированные через ту же feature-схему, что и BlockFeatures.
// Веса >1.0 у самых однозначных индикаторов (высокая энтропия +
// прямой путь к sink), <1.0 у более "шумных"/неоднозначных паттернов.
func defaultAnchors() []Anchor {
	defs := []struct {
		label  string
		weight float64
		feats  map[string]string
	}{
		{
			label:  "packed_payload_dropper",
			weight: 1.1,
			feats: map[string]string{
				"entropy":      "high",
				"crypto_ratio": "high",
				"taint_dist":   "0",
			},
		},
		{
			label:  "obfuscated_dynamic_loader",
			weight: 1.0,
			feats: map[string]string{
				"entropy":       "high",
				"network_ratio": "low",
				"taint_dist":    "1",
			},
		},
		{
			label:  "network_exfil_direct",
			weight: 1.0,
			feats: map[string]string{
				"entropy":       "medium",
				"network_ratio": "high",
				"taint_dist":    "0",
			},
		},
		{
			label:  "network_exfil_relayed",
			weight: 0.9,
			feats: map[string]string{
				"entropy":       "medium",
				"network_ratio": "high",
				"taint_dist":    "1",
			},
		},
		{
			label:  "weak_crypto_wrapper",
			weight: 0.85,
			feats: map[string]string{
				"entropy":      "medium",
				"crypto_ratio": "medium",
				"taint_dist":   "none",
			},
		},
		{
			label:  "credential_harvest_sink",
			weight: 1.05,
			feats: map[string]string{
				"entropy":       "low",
				"network_ratio": "medium",
				"taint_dist":    "0",
			},
		},
		{
			label:  "native_bridge_obfuscated",
			weight: 0.95,
			feats: map[string]string{
				"entropy":      "high",
				"crypto_ratio": "low",
				"taint_dist":   "2",
			},
		},
		{
			label:  "staged_download_execute",
			weight: 1.05,
			feats: map[string]string{
				"entropy":       "medium",
				"network_ratio": "high",
				"taint_dist":    "1",
			},
		},
		{
			label:  "benign_crypto_utility",
			weight: 0.4,
			feats: map[string]string{
				"entropy":      "high",
				"crypto_ratio": "high",
				"taint_dist":   "none",
			},
		},
		{
			label:  "reflective_api_indirection",
			weight: 0.9,
			feats: map[string]string{
				"entropy":       "medium",
				"network_ratio": "low",
				"crypto_ratio":  "low",
				"taint_dist":    "3+",
			},
		},
	}

	anchors := make([]Anchor, 0, len(defs))
	for _, d := range defs {
		anchors = append(anchors, Anchor{
			Label:  d.label,
			Weight: d.weight,
			Vector: hdc.EncodeFeatures(d.feats),
		})
	}
	return anchors
}
