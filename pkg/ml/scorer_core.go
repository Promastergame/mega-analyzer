package ml

import "fmt"

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH SCORER
// ═══════════════════════════════════════════════════════════════════════════════

// PatchScorer считает risk score для методов
type PatchScorer struct {
	analyzer *PatchAnalyzer
	config   ScorerConfig

	// Optional learned components. Nil means legacy heuristic-only behavior.
	anomalyScorer  AnomalyScorer
	confidenceCal  *PlattScaler
	confidenceGate *ConformalGate
	metaModel      *StackedMeta
}

// ScorerConfig — настройки скоринга
type ScorerConfig struct {
	// Пороги
	HighThreshold   float64
	MediumThreshold float64
	LowThreshold    float64

	// Множители
	NameMatchWeight   float64
	CallMatchWeight   float64
	StringMatchWeight float64
	StructuralWeight  float64
	ContextWeight     float64

	// Лимиты
	MaxScore      float64
	MinConfidence float64

	// Penalty control
	LibraryPenaltyScale float64
	SafePatternScale    float64
}

// DefaultScorerConfig — настройки по умолчанию
func DefaultScorerConfig() ScorerConfig {
	return ScorerConfig{
		HighThreshold:       HighRiskThreshold,
		MediumThreshold:     MediumRiskThreshold,
		LowThreshold:        LowRiskThreshold,
		NameMatchWeight:     1.0,
		CallMatchWeight:     1.0,
		StringMatchWeight:   1.0,
		StructuralWeight:    1.0,
		ContextWeight:       1.0,
		MaxScore:            100.0,
		MinConfidence:       0.3,
		LibraryPenaltyScale: 1.0,
		SafePatternScale:    1.0,
	}
}

// Validate performs validation on the ScorerConfig and returns an error if invalid.
func (sc *ScorerConfig) Validate() error {
	if sc.HighThreshold < 0 || sc.HighThreshold > 100 {
		return fmt.Errorf("HighThreshold must be between 0 and 100, got %f", sc.HighThreshold)
	}
	if sc.MediumThreshold < 0 || sc.MediumThreshold > 100 {
		return fmt.Errorf("MediumThreshold must be between 0 and 100, got %f", sc.MediumThreshold)
	}
	if sc.LowThreshold < 0 || sc.LowThreshold > 100 {
		return fmt.Errorf("LowThreshold must be between 0 and 100, got %f", sc.LowThreshold)
	}
	if sc.MaxScore < 0 || sc.MaxScore > 1000 {
		return fmt.Errorf("MaxScore must be between 0 and 1000, got %f", sc.MaxScore)
	}
	if sc.MinConfidence < 0 || sc.MinConfidence > 1 {
		return fmt.Errorf("MinConfidence must be between 0 and 1, got %f", sc.MinConfidence)
	}
	if sc.NameMatchWeight < 0 {
		return fmt.Errorf("NameMatchWeight must be non-negative, got %f", sc.NameMatchWeight)
	}
	if sc.CallMatchWeight < 0 {
		return fmt.Errorf("CallMatchWeight must be non-negative, got %f", sc.CallMatchWeight)
	}
	if sc.StringMatchWeight < 0 {
		return fmt.Errorf("StringMatchWeight must be non-negative, got %f", sc.StringMatchWeight)
	}
	if sc.StructuralWeight < 0 {
		return fmt.Errorf("StructuralWeight must be non-negative, got %f", sc.StructuralWeight)
	}
	if sc.ContextWeight < 0 {
		return fmt.Errorf("ContextWeight must be non-negative, got %f", sc.ContextWeight)
	}
	if sc.LibraryPenaltyScale < 0 {
		return fmt.Errorf("LibraryPenaltyScale must be non-negative, got %f", sc.LibraryPenaltyScale)
	}
	if sc.SafePatternScale < 0 {
		return fmt.Errorf("SafePatternScale must be non-negative, got %f", sc.SafePatternScale)
	}

	// Validate threshold ordering
	if sc.HighThreshold <= sc.MediumThreshold {
		return fmt.Errorf("HighThreshold must be greater than MediumThreshold")
	}
	if sc.MediumThreshold <= sc.LowThreshold {
		return fmt.Errorf("MediumThreshold must be greater than LowThreshold")
	}

	return nil
}

// NewPatchScorer создаёт скорер
func NewPatchScorer(analyzer *PatchAnalyzer) *PatchScorer {
	return &PatchScorer{
		analyzer: analyzer,
		config:   DefaultScorerConfig(),
	}
}

// NewPatchScorerWithConfig создаёт скорер с конфигурацией
func NewPatchScorerWithConfig(analyzer *PatchAnalyzer, config ScorerConfig) *PatchScorer {
	return &PatchScorer{
		analyzer: analyzer,
		config:   config,
	}
}

// SetAnomalyScorer injects an optional unsupervised detector used as a bounded
// re-ranking signal. Passing nil disables the component.
func (ps *PatchScorer) SetAnomalyScorer(model AnomalyScorer) {
	if ps != nil {
		ps.anomalyScorer = model
	}
}

// SetConfidenceCalibration enables calibrated confidence and needs_review
// reporting for scored methods.
func (ps *PatchScorer) SetConfidenceCalibration(scaler *PlattScaler, gate *ConformalGate) {
	if ps != nil {
		ps.confidenceCal = scaler
		ps.confidenceGate = gate
	}
}

// SetMetaModel injects an optional learned stacker for confidence re-ranking.
func (ps *PatchScorer) SetMetaModel(model *StackedMeta) {
	if ps != nil {
		ps.metaModel = model
	}
}
