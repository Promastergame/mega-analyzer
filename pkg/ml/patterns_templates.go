package ml

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH TEMPLATES — шаблоны готовых патчей
// ═══════════════════════════════════════════════════════════════════════════════

type PatchTemplate struct {
	Type        PatchType `json:"type"`
	Description string    `json:"description"`
	Code        string    `json:"code"`
	Registers   int       `json:"registers"` // минимум регистров
}

var PatchTemplates = mustLoadPatchTemplates()

// ═══════════════════════════════════════════════════════════════════════════════
// SCORING THRESHOLDS
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// Минимальный score чтобы считать патч-точкой
	MinPatchScore = 30.0

	// Пороги для классификации
	HighRiskThreshold   = 65.0
	MediumRiskThreshold = 45.0
	LowRiskThreshold    = 30.0

	// Максимум результатов каждого уровня
	MaxHighRiskResults   = 15
	MaxMediumRiskResults = 15
	MaxLowRiskResults    = 10
)
