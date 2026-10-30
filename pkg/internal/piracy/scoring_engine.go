// Package piracy — scoring_engine.go
// Explainable multi-signal scoring engine
package piracy

import (
	"fmt"
	"math"
	"sort"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SCORING RESULT
// ═══════════════════════════════════════════════════════════════════════════════

type ScoringResult struct {
	FinalConfidence float64                `json:"final_confidence"`
	BaseConfidence  float64                `json:"base_confidence"`
	Boost           float64                `json:"boost"`
	RiskLevel       RiskLevel              `json:"risk_level"`
	EvidenceCount   int                    `json:"evidence_count"`
	Explanations    []string               `json:"explanations"`
	TopEvidence     []Evidence             `json:"top_evidence"`
	SignalBreakdown map[SignalType]float64 `json:"signal_breakdown"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORING ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

type ScoringEngine struct {
	cfg ScoringConfig
}

// NewScoringEngine создаёт движок с конфигом по умолчанию.
func NewScoringEngine() *ScoringEngine {
	return &ScoringEngine{cfg: DefaultScoringConfig()}
}

// NewScoringEngineWithConfig создаёт движок с пользовательским конфигом.
// Возвращает ошибку при невалидной конфигурации.
func NewScoringEngineWithConfig(cfg ScoringConfig) (*ScoringEngine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid scoring config: %w", err)
	}
	return &ScoringEngine{cfg: cfg}, nil
}

// Config возвращает текущую конфигурацию (для инспекции/тестов).
func (se *ScoringEngine) Config() ScoringConfig {
	return se.cfg
}

// ═══════════════════════════════════════════════════════════════════════════════
// CALCULATE SCORE — главная точка входа
// ═══════════════════════════════════════════════════════════════════════════════

func (se *ScoringEngine) CalculateScore(findings []Finding) *ScoringResult {
	if len(findings) == 0 {
		return &ScoringResult{
			FinalConfidence: 0,
			RiskLevel:       RiskNone,
			Explanations:    []string{"No suspicious indicators found"},
			SignalBreakdown: map[SignalType]float64{},
		}
	}

	evidence := se.findingsToEvidence(findings)
	signalGroups := groupBySignal(evidence)

	baseConf := se.calculateBaseConfidence(evidence, signalGroups)
	boost := se.calculateCombinationBoost(signalGroups)
	finalConf := math.Min(baseConf*boost, 1.0)
	riskLevel := se.getRiskLevel(finalConf)

	explanations := se.generateExplanations(evidence, signalGroups, boost)
	topEvidence := se.getTopEvidence(evidence, 5)
	breakdown := se.getSignalBreakdown(signalGroups)

	return &ScoringResult{
		FinalConfidence: finalConf,
		BaseConfidence:  baseConf,
		Boost:           boost,
		RiskLevel:       riskLevel,
		EvidenceCount:   len(evidence),
		Explanations:    explanations,
		TopEvidence:     topEvidence,
		SignalBreakdown: breakdown,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BASE CONFIDENCE с decay для дубликатов
// ═══════════════════════════════════════════════════════════════════════════════

func (se *ScoringEngine) calculateBaseConfidence(
	evidence []Evidence,
	groups map[SignalType][]Evidence,
) float64 {
	if len(evidence) == 0 {
		return 0
	}

	var maxConf float64
	var typeAvg float64
	typeCount := 0

	for _, evList := range groups {
		if len(evList) == 0 {
			continue
		}

		// Сортируем по effective score (убывание)
		sort.Slice(evList, func(i, j int) bool {
			swI := se.cfg.SignalWeights[evList[i].Strength]
			swJ := se.cfg.SignalWeights[evList[j].Strength]
			return evList[i].effectiveScore(swI) > evList[j].effectiveScore(swJ)
		})

		// Лучший элемент группы (decay^0 = 1.0) — кандидат на maxConf
		bestSW := se.cfg.SignalWeights[evList[0].Strength]
		bestScore := evList[0].effectiveScore(bestSW)
		if bestScore > maxConf {
			maxConf = bestScore
		}

		// Сумма по группе с decay
		var groupSum float64
		for idx, ev := range evList {
			sw := se.cfg.SignalWeights[ev.Strength]
			decay := math.Pow(se.cfg.DuplicateDecay, float64(idx))
			groupSum += ev.effectiveScore(sw) * decay
		}

		typeAvg += groupSum / float64(len(evList))
		typeCount++
	}

	if typeCount > 0 {
		typeAvg /= float64(typeCount)
	}

	diversityFactor := math.Min(
		float64(len(evidence))/se.cfg.DiversityCap, 1.0,
	)

	baseConf := (maxConf * se.cfg.BlendMax) +
		(typeAvg * se.cfg.BlendAvg) +
		(diversityFactor * se.cfg.BlendDiversity)

	return math.Min(baseConf, 1.0)
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMBINATION BOOST — типобезопасный
// ═══════════════════════════════════════════════════════════════════════════════

func (se *ScoringEngine) calculateCombinationBoost(
	groups map[SignalType][]Evidence,
) float64 {
	boost := 1.0

	for combo, mult := range se.cfg.CombinationBoosts {
		if combo == ComboMultipleCritical {
			continue // обрабатывается отдельно ниже
		}
		if se.comboMatches(combo, groups) {
			boost *= mult
		}
	}

	// Multiple critical signals
	if mult, ok := se.cfg.CombinationBoosts[ComboMultipleCritical]; ok {
		criticalCount := 0
		for _, evList := range groups {
			for _, ev := range evList {
				if ev.Strength == StrengthCritical {
					criticalCount++
				}
			}
		}
		if criticalCount >= se.cfg.MultipleCriticalThreshold {
			boost *= mult
		}
	}

	return math.Min(boost, se.cfg.MaxBoost)
}

// comboMatches проверяет, присутствует ли комбинация сигналов в группах.
func (se *ScoringEngine) comboMatches(
	combo CombinationKey,
	groups map[SignalType][]Evidence,
) bool {
	if len(groups[combo.First]) == 0 {
		return false
	}

	// Wildcard: Second == "" → «first + хотя бы ещё один любой тип»
	if combo.Second == "" {
		for st, evs := range groups {
			if st != combo.First && len(evs) > 0 {
				return true
			}
		}
		return false
	}

	return len(groups[combo.Second]) > 0
}

// ═══════════════════════════════════════════════════════════════════════════════
// RISK LEVEL — определение по порогам из конфига
// ═══════════════════════════════════════════════════════════════════════════════

func (se *ScoringEngine) getRiskLevel(confidence float64) RiskLevel {
	for _, t := range se.cfg.RiskThresholds {
		if confidence >= t.MinConfidence {
			return t.Level
		}
	}
	return RiskMinimal
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPLAINABILITY
// ═══════════════════════════════════════════════════════════════════════════════

func (se *ScoringEngine) generateExplanations(
	evidence []Evidence,
	groups map[SignalType][]Evidence,
	boost float64,
) []string {
	var explanations []string

	// Топовые находки
	top := se.getTopEvidence(evidence, 3)
	for i, ev := range top {
		explanations = append(explanations,
			fmt.Sprintf("%d. Found %s: %s (confidence: %.0f%%, strength: %s)",
				i+1, ev.Type, ev.Pattern, ev.Confidence*100, ev.Strength))
	}

	// Суммарно по типам
	for signalType, evList := range groups {
		if len(evList) > 0 {
			explanations = append(explanations,
				fmt.Sprintf("Detected %d %s signal(s)", len(evList), signalType))
		}
	}

	// Буст
	if boost > 1.0 {
		explanations = append(explanations,
			fmt.Sprintf("Confidence boosted by %.0f%% due to signal combination",
				(boost-1.0)*100))
	}

	// Конкретные предупреждения по комбинациям
	if len(groups[SignalWatermark]) > 0 && len(groups[SignalCrack]) > 0 {
		explanations = append(explanations,
			"⚠️ High risk: Watermark + Crack pattern combination detected")
	}
	if len(groups[SignalMalware]) > 0 {
		explanations = append(explanations,
			"🚨 CRITICAL: Malware signatures detected")
	}
	if len(groups[SignalCrackTool]) > 0 {
		explanations = append(explanations,
			"🔓 Cracking tool signatures found")
	}

	return explanations
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func (se *ScoringEngine) findingsToEvidence(findings []Finding) []Evidence {
	evidence := make([]Evidence, 0, len(findings))
	for _, f := range findings {
		evidence = append(evidence, Evidence{
			Type:        mapFindingTypeToSignal(f.Type),
			Strength:    se.inferStrength(f),
			Source:      f.Source,
			Pattern:     f.Pattern,
			Location:    f.Location,
			Confidence:  f.Confidence,
			Weight:      f.Weight,
			Description: f.Description,
		})
	}
	return evidence
}

func mapFindingTypeToSignal(findingType string) SignalType {
	switch findingType {
	case "site", "path":
		return SignalSource
	case "mod", "path_mod":
		return SignalBehavior
	case "crack":
		return SignalCrack
	case "watermark":
		return SignalWatermark
	case "encrypted", "obfuscated":
		return SignalObfuscation
	case "framework":
		return SignalFramework
	case "crack_tool":
		return SignalCrackTool
	case "malware":
		return SignalMalware
	default:
		return SignalBehavior
	}
}

func (se *ScoringEngine) inferStrength(f Finding) SignalStrength {
	// Явно заданная сила
	if f.Strength.Valid() {
		return f.Strength
	}

	// По risk-тегам
	for _, tag := range f.RiskTags {
		switch tag {
		case "malware":
			return StrengthCritical
		case "crack", "bypass":
			return StrengthStrong
		}
	}

	// По типу сигнала
	switch mapFindingTypeToSignal(f.Type) {
	case SignalMalware, SignalCrackTool:
		return StrengthCritical
	case SignalCrack:
		return StrengthStrong
	case SignalFramework, SignalSource, SignalWatermark:
		return StrengthMedium
	case SignalObfuscation, SignalBehavior:
		return StrengthWeak
	default:
		return StrengthMinimal
	}
}

func groupBySignal(evidence []Evidence) map[SignalType][]Evidence {
	groups := make(map[SignalType][]Evidence)
	for _, ev := range evidence {
		groups[ev.Type] = append(groups[ev.Type], ev)
	}
	return groups
}

func (se *ScoringEngine) getTopEvidence(evidence []Evidence, n int) []Evidence {
	sorted := make([]Evidence, len(evidence))
	copy(sorted, evidence)

	sort.Slice(sorted, func(i, j int) bool {
		swI := se.cfg.SignalWeights[sorted[i].Strength]
		swJ := se.cfg.SignalWeights[sorted[j].Strength]
		return sorted[i].effectiveScore(swI) > sorted[j].effectiveScore(swJ)
	})

	if len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

func (se *ScoringEngine) getSignalBreakdown(
	groups map[SignalType][]Evidence,
) map[SignalType]float64 {
	breakdown := make(map[SignalType]float64, len(groups))
	for st, evList := range groups {
		if len(evList) == 0 {
			continue
		}
		var total float64
		for _, ev := range evList {
			total += ev.Confidence * ev.Weight
		}
		breakdown[st] = total / float64(len(evList))
	}
	return breakdown
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTEGRATION WITH DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════

func (se *ScoringEngine) EnhanceResultWithScoring(result *Result) {
	sr := se.CalculateScore(result.Findings)
	result.Confidence = sr.FinalConfidence
	result.RiskLevel = string(sr.RiskLevel)
}
