package ml

import (
	"fmt"
	"math"
	"strings"
)


// ═══════════════════════════════════════════════════════════════════════════════
// STEP 7: CALCULATE FINAL SCORE
// ═══════════════════════════════════════════════════════════════════════════════

func (ps *PatchScorer) calculateFinal(mi *MethodInfo, result *ScoreResult, reputation *ReputationVerdict) {
	// Raw score
	rawScore := result.BaseScore +
		result.StructuralBonus +
		result.SafePenalty +
		result.LibraryPenalty +
		result.ContextBonus

	// Apply category weight
	if result.CategoryWeight > 0 {
		rawScore *= (0.5 + result.CategoryWeight*0.125) // масштабируем мягко
	}

	// ── Phase 6: Library Reputation penalty ──────────────────────
	// Проверяем reputation DB ПОСЛЕ всех бонусов/штрафов, но ДО clamp.
	// Это самый мощный фильтр: trusted frameworks получают ÷5..÷20.
	if reputation != nil && reputation.IsTrusted {
		rawScore *= reputation.PenaltyFactor
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("REPUTATION: %s [%s] — score ×%.2f",
				reputation.Framework, reputation.Domain, reputation.PenaltyFactor))
		if reputation.Reason != "" {
			result.Reasons = append(result.Reasons, "⚠ "+reputation.Reason)
		}
	}

	// ── Phase 6: String false-positive suppression ───────────────
	// Если security strings триггернули, но они в safe context — убираем бонус.
	if mi.HasSecurityStrings && reputation == nil {
		suppressedCount := 0
		for _, s := range mi.SecurityStrings {
			if CheckStringFalsePositive(s, mi) {
				suppressedCount++
			}
		}
		if suppressedCount > 0 && suppressedCount >= len(mi.SecurityStrings) {
			// ВСЕ security strings — false positives
			rawScore *= 0.3
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("REPUTATION: all %d security strings are safe-context (MIME/codec/infra)",
					suppressedCount))
		}
	}

	// Clamp to [0, MaxScore]
	if rawScore < 0 {
		rawScore = 0
	}
	if rawScore > ps.config.MaxScore {
		rawScore = ps.config.MaxScore
	}

	result.FinalScore = math.Round(rawScore*10) / 10 // 1 decimal

	// ── Risk level classification ────────────────────────────────
	switch {
	case result.FinalScore >= ps.config.HighThreshold:
		result.RiskLevel = RiskClassHigh
	case result.FinalScore >= ps.config.MediumThreshold:
		result.RiskLevel = RiskClassMedium
	case result.FinalScore >= ps.config.LowThreshold:
		result.RiskLevel = RiskClassLow
	default:
		result.RiskLevel = RiskClassNone
	}

	// ── Collect matched signals first ────────────────────────────
	// Populate MatchedSignals before confidence calculation
	result.MatchedSignals = ps.collectMatchSignals(mi, result)

	// ── Confidence calculation with breakdown ────────────────────
	// Use CalculateConfidenceWithBreakdown for detailed confidence analysis
	// (Requirements: 2.7, 4.4, 4.5)
	breakdown := ps.CalculateConfidenceWithBreakdown(mi, result)
	result.Confidence = breakdown.FinalConfidence
	result.ConfidenceBreakdown = &breakdown

	if ps.metaModel != nil {
		// Same 4-signal layout the meta model was trained on (see
		// metaFeatureVector) so training and inference never drift apart.
		result.Confidence = ps.metaModel.Predict(metaFeatureVector(result, ps.config.MaxScore))
	}
	if ps.confidenceCal != nil || ps.confidenceGate != nil {
		rc := AssessPatch(ps.confidenceCal, ps.confidenceGate, result.Confidence, "")
		result.RuntimeConfidence = &rc
	}
}

// FinalizeConfidence — единая финальная калибровка confidence ПОСЛЕ всех
// сигналов (ensemble, entry-point, interesting, DFG, structural, crack-point,
// decoy, vuln). ScoreBatch считает confidence до этих бонусов; здесь
// пересчитываем её от финального risk score и применяем штрафы warnings/
// library/obfuscation, которые раньше жили только в неиспользуемом
// calculateConfidence. Заполняет RuntimeConfidence (калиброванный + conformal
// gate) и RuntimeDecision: auto_patch / needs_review / reject.
func (ps *PatchScorer) FinalizeConfidence(point *PatchPoint, sm *ScoredMethod) {
	if point == nil || sm == nil {
		return
	}
	maxScore := ps.config.MaxScore
	if maxScore <= 0 {
		maxScore = 100
	}
	conf := point.RiskScore / maxScore
	if conf < 0 {
		conf = 0
	}
	if conf > 1 {
		conf = 1
	}

	// Штрафы: warnings (до 0.2), библиотека (0.15), обфускация (0.05).
	conf -= math.Min(float64(len(point.Warnings))*0.05, 0.2)
	if point.IsLibraryCode {
		conf -= 0.15
	}
	if sm.Score.ObfuscationInfo != nil && sm.Score.ObfuscationInfo.IsObfuscated {
		conf -= 0.05
	}
	if conf < ps.config.MinConfidence {
		conf = ps.config.MinConfidence
	}
	if conf > 1 {
		conf = 1
	}
	conf = math.Round(conf*100) / 100
	if ps.metaModel != nil {
		// Build the same feature layout as training, using the final evidence.
		features := sm.Score
		features.FinalScore = point.RiskScore
		features.Confidence = conf
		conf = ps.metaModel.Predict(metaFeatureVector(&features, maxScore))
	}
	// ConfidenceBreakdown фиксирует сигнальный уровень; финальная калибровка
	// отражается в RuntimeConfidence и RuntimeDecision.
	rc := AssessPatch(ps.confidenceCal, ps.confidenceGate, conf, "")
	point.RuntimeConfidence = &rc
	point.Confidence = rc.Probability
	switch {
	case rc.NeedsReview:
		point.RuntimeDecision = "needs_review"
	case rc.Probability >= 0.85:
		point.RuntimeDecision = "auto_patch"
	case rc.Probability >= 0.6:
		point.RuntimeDecision = "needs_review"
	default:
		point.RuntimeDecision = "reject"
	}
	point.CategoryConfidence = EstimateCategoryConformalConfidence(point.Category, point.Confidence)
}

// calculateConfidence оценивает уверенность в результате (Task 13.1, 13.2)
func (ps *PatchScorer) calculateConfidence(mi *MethodInfo, result *ScoreResult) float64 {
	// Collect all matching signals
	signals := ps.collectMatchSignals(mi, result)
	result.MatchedSignals = signals

	// Calculate base confidence from signals
	var confidence float64
	signalCount := len(signals)

	if signalCount == 0 {
		confidence = ps.config.MinConfidence
	} else {
		// Aggregate signal confidences with diminishing returns
		totalWeight := 0.0
		weightedConfidence := 0.0

		for _, signal := range signals {
			totalWeight += signal.Weight
			weightedConfidence += signal.Confidence * signal.Weight
		}

		if totalWeight > 0 {
			confidence = weightedConfidence / totalWeight
		}

		// Bonus for multiple signals (multi-signal confidence boost)
		multiSignalBonus := ps.calculateMultiSignalBonus(signalCount)
		confidence += multiSignalBonus
	}

	// Apply obfuscation-aware confidence adjustment (Task 13.2)
	if result.ObfuscationInfo != nil && result.ObfuscationInfo.IsObfuscated {
		confidence = ps.applyObfuscationConfidenceAdjustment(confidence, result, signalCount)
	}

	// Штраф за warnings (safe patterns)
	warningPenalty := float64(len(result.Warnings)) * 0.05
	confidence -= math.Min(warningPenalty, 0.2)

	// Штраф за библиотеку
	if mi.IsLibrary {
		confidence -= 0.15
	}

	// Clamp to valid range
	if confidence < ps.config.MinConfidence {
		confidence = ps.config.MinConfidence
	}
	if confidence > 1.0 {
		confidence = 1.0
	}

	return math.Round(confidence*100) / 100
}

// calculateMultiSignalBonus calculates the bonus for methods with multiple matched signals
// Formula: min((N-1) * 0.08, 0.25) where N is the number of matched signals
// This rewards methods that match multiple signals, with a maximum bonus of 0.25
// Examples: 2 signals = 0.08 bonus, 3 signals = 0.16 bonus, 4+ signals = 0.25 bonus (capped)
func (ps *PatchScorer) calculateMultiSignalBonus(signalCount int) float64 {
	if signalCount < 2 {
		return 0.0
	}
	return math.Min(float64(signalCount-1)*0.08, 0.25)
}

// collectMatchSignals collects all matching signals from the method (Task 13.1)
func (ps *PatchScorer) collectMatchSignals(mi *MethodInfo, result *ScoreResult) []MatchSignal {
	signals := make([]MatchSignal, 0, 5)

	// Signal 1: Name matching
	if mi.HasSecurityName || mi.HasCheckPrefix || (result.BestPattern != nil && len(result.BestPattern.MethodNames) > 0) {
		nameConfidence := 0.7
		if mi.HasSecurityName && mi.HasCheckPrefix {
			nameConfidence = 0.85
		}
		signals = append(signals, MatchSignal{
			Type:       SignalName,
			Value:      mi.Name,
			Weight:     SignalWeights[SignalName],
			Confidence: nameConfidence,
		})
	}

	// Signal 2: Structure matching
	if mi.ReturnsBoolean || mi.HasDualReturn || mi.HasIfWithReturn {
		structureConfidence := 0.6
		if mi.ReturnsBoolean && mi.HasDualReturn {
			structureConfidence = 0.8
		}
		signals = append(signals, MatchSignal{
			Type:       SignalStructure,
			Value:      fmt.Sprintf("boolean=%v,dual_return=%v,if_return=%v", mi.ReturnsBoolean, mi.HasDualReturn, mi.HasIfWithReturn),
			Weight:     SignalWeights[SignalStructure],
			Confidence: structureConfidence,
		})
	}

	// Signal 3: API call matching
	if mi.HasSecurityAPI || len(mi.SecurityCalls) > 0 {
		apiConfidence := 0.75
		if len(mi.SecurityCalls) >= 2 {
			apiConfidence = 0.9
		}
		apiValue := "security_api"
		if len(mi.SecurityCalls) > 0 {
			apiValue = strings.Join(mi.SecurityCalls, ",")
			if len(apiValue) > 100 {
				apiValue = apiValue[:100] + "..."
			}
		}
		signals = append(signals, MatchSignal{
			Type:       SignalAPICall,
			Value:      apiValue,
			Weight:     SignalWeights[SignalAPICall],
			Confidence: apiConfidence,
		})
	}

	// Signal 4: String constant matching
	if mi.HasSecurityStrings || len(mi.SecurityStrings) > 0 {
		stringConfidence := 0.65
		if len(mi.SecurityStrings) >= 2 {
			stringConfidence = 0.8
		}
		stringValue := "security_strings"
		if len(mi.SecurityStrings) > 0 {
			stringValue = strings.Join(mi.SecurityStrings, ",")
			if len(stringValue) > 100 {
				stringValue = stringValue[:100] + "..."
			}
		}
		signals = append(signals, MatchSignal{
			Type:       SignalString,
			Value:      stringValue,
			Weight:     SignalWeights[SignalString],
			Confidence: stringConfidence,
		})
	}

	// Signal 5: Return type matching
	if mi.ReturnsBoolean {
		signals = append(signals, MatchSignal{
			Type:       SignalReturnType,
			Value:      "Z",
			Weight:     SignalWeights[SignalReturnType],
			Confidence: 0.7,
		})
	}

	vs := result.VulnerabilitySignals
	if vs == nil {
		vs = AnalyzeVulnerabilitySignals(mi)
	}
	if vs != nil && vs.HasAny() {
		maxConf := 0.0
		values := make([]string, 0, len(vs.Signals))
		for _, signal := range vs.Signals {
			if signal.Confidence > maxConf {
				maxConf = signal.Confidence
			}
			values = append(values, string(signal.Kind))
		}
		signals = append(signals, MatchSignal{
			Type:       SignalVulnSignal,
			Value:      strings.Join(values, ","),
			Weight:     SignalWeights[SignalVulnSignal],
			Confidence: maxConf,
		})
	}

	return signals
}

// calculateSignalContributions calculates weighted contributions for all matched signals
// This method implements multi-signal aggregation as specified in Task 4.2
// Returns a list of SignalContribution structs with calculated contributions (weight * confidence)
func (ps *PatchScorer) calculateSignalContributions(signals []MatchSignal) []SignalContribution {
	contributions := make([]SignalContribution, 0, len(signals))

	for _, signal := range signals {
		contribution := SignalContribution{
			SignalType:   string(signal.Type),
			Value:        signal.Value,
			Weight:       signal.Weight,
			Confidence:   signal.Confidence,
			Contribution: signal.Weight * signal.Confidence,
		}
		contributions = append(contributions, contribution)
	}

	return contributions
}

// CalculateConfidenceWithBreakdown calculates confidence with detailed breakdown (Task 4.5)
// This method integrates all confidence calculation components:
// 1. Collect all matched signals (Task 4.2)
// 2. Calculate weighted aggregation using SignalWeights (Task 4.2)
// 3. Calculate signal contributions (weight * confidence) (Task 4.2)
// 4. Add multi-signal bonus (Task 4.3)
// 5. Apply obfuscation adjustment (Task 4.4)
// 6. Normalize final confidence to [0.3, 1.0] range
// 7. Return ConfidenceBreakdown struct with all details
func (ps *PatchScorer) CalculateConfidenceWithBreakdown(mi *MethodInfo, result *ScoreResult) ConfidenceBreakdown {
	breakdown := ConfidenceBreakdown{
		SignalContributions: []SignalContribution{},
	}

	// Step 1: Collect all matched signals
	signals := ps.collectMatchSignals(mi, result)

	// Step 2 & 3: Calculate weighted aggregation and signal contributions
	totalWeight := 0.0
	weightedSum := 0.0

	for _, signal := range signals {
		contribution := signal.Weight * signal.Confidence
		totalWeight += signal.Weight
		weightedSum += contribution

		breakdown.SignalContributions = append(breakdown.SignalContributions, SignalContribution{
			SignalType:   string(signal.Type),
			Value:        signal.Value,
			Weight:       signal.Weight,
			Confidence:   signal.Confidence,
			Contribution: contribution,
		})
	}

	// Calculate base confidence from weighted average
	if totalWeight > 0 {
		breakdown.BaseConfidence = weightedSum / totalWeight
	} else {
		breakdown.BaseConfidence = ps.config.MinConfidence // Minimum threshold
	}

	// Step 4: Add multi-signal bonus
	if len(signals) >= 2 {
		breakdown.MultiSignalBonus = ps.calculateMultiSignalBonus(len(signals))
	}

	// Step 5: Apply obfuscation adjustment
	if result.ObfuscationInfo != nil && result.ObfuscationInfo.IsObfuscated {
		// Calculate adjustment as the difference from base confidence
		adjustedConfidence := ps.applyObfuscationConfidenceAdjustmentWithSignals(
			breakdown.BaseConfidence+breakdown.MultiSignalBonus,
			result,
			signals,
		)
		breakdown.ObfuscationAdjust = adjustedConfidence - (breakdown.BaseConfidence + breakdown.MultiSignalBonus)
	}

	// Step 6: Calculate final confidence
	breakdown.FinalConfidence = breakdown.BaseConfidence +
		breakdown.MultiSignalBonus +
		breakdown.ObfuscationAdjust

	// Step 7: Normalize to [0.3, 1.0] range
	if breakdown.FinalConfidence < ps.config.MinConfidence {
		breakdown.FinalConfidence = ps.config.MinConfidence
	}
	if breakdown.FinalConfidence > 1.0 {
		breakdown.FinalConfidence = 1.0
	}

	// Round to 2 decimal places
	breakdown.FinalConfidence = math.Round(breakdown.FinalConfidence*100) / 100

	return breakdown
}

// applyObfuscationConfidenceAdjustment adjusts confidence based on obfuscation (Task 4.4)
// Detects obfuscation from ObfuscationInfo and applies confidence ranges:
// - structure + API = [0.6, 0.8]
// - structure-only = [0.3, 0.6]
// Prioritizes structural signals over name signals when obfuscated.
// applyObfuscationConfidenceAdjustment adjusts confidence based on obfuscation (Task 4.4)
// Detects obfuscation from ObfuscationInfo and applies confidence ranges:
// - structure + API = [0.6, 0.8]
func (ps *PatchScorer) applyObfuscationConfidenceAdjustment(baseConfidence float64, result *ScoreResult, _ int) float64 {
	return ps.applyObfuscationConfidenceAdjustmentWithSignals(baseConfidence, result, result.MatchedSignals)
}

// applyObfuscationConfidenceAdjustmentWithSignals adjusts confidence with explicit signals
func (ps *PatchScorer) applyObfuscationConfidenceAdjustmentWithSignals(baseConfidence float64, result *ScoreResult, signals []MatchSignal) float64 {
	obfInfo := result.ObfuscationInfo

	// Detect signal composition
	hasName := false
	hasStructure := false
	hasAPI := false
	hasString := false

	for _, signal := range signals {
		switch signal.Type {
		case SignalName:
			hasName = true
		case SignalStructure:
			hasStructure = true
		case SignalAPICall:
			hasAPI = true
		case SignalString:
			hasString = true
		}
	}

	// Prioritize structural signals over name signals when obfuscated
	// If obfuscation is detected with high confidence, deprioritize name signals
	if obfInfo.Confidence >= 0.6 && hasName && (hasStructure || hasAPI) {
		// Recalculate confidence without name signal to prioritize structural signals
		totalWeight := 0.0
		weightedSum := 0.0

		for _, signal := range signals {
			// Skip name signals for obfuscated code
			if signal.Type == SignalName {
				continue
			}
			totalWeight += signal.Weight
			weightedSum += signal.Confidence * signal.Weight
		}

		if totalWeight > 0 {
			baseConfidence = weightedSum / totalWeight
		}
	}

	// Apply confidence range clamping based on signal composition
	switch {
	case hasStructure && hasAPI:
		// Structure + API signals: clamp to [0.6, 0.8]
		// This is the expected case for obfuscated code with reliable signals
		if baseConfidence < 0.6 {
			baseConfidence = 0.6
		}
		if baseConfidence > 0.8 {
			baseConfidence = 0.8
		}

	case hasStructure && !hasAPI:
		// Structure-only signals: clamp to [0.3, 0.6]
		// Lower confidence due to lack of API confirmation
		if baseConfidence < 0.3 {
			baseConfidence = 0.3
		}
		if baseConfidence > 0.6 {
			baseConfidence = 0.6
		}

	case hasAPI && !hasStructure:
		// API-only signals: clamp to [0.3, 0.6]
		// Lower confidence due to lack of structural confirmation
		if baseConfidence < 0.3 {
			baseConfidence = 0.3
		}
		if baseConfidence > 0.6 {
			baseConfidence = 0.6
		}

	case hasString && (hasStructure || hasAPI):
		// String + structure/API: clamp to [0.5, 0.7]
		// Moderate confidence with string constants
		if baseConfidence < 0.5 {
			baseConfidence = 0.5
		}
		if baseConfidence > 0.7 {
			baseConfidence = 0.7
		}

	default:
		// Very low confidence: no strong structural or API signals
		// Clamp to maximum of 0.4
		if baseConfidence > 0.4 {
			baseConfidence = 0.4
		}
	}

	// Additional boost for high-confidence obfuscation detection with structural signals
	// This rewards structural matches in confirmed obfuscated code
	if obfInfo.Confidence >= 0.7 && hasStructure {
		baseConfidence += 0.05
		// Ensure we don't exceed the upper bound of the range
		if hasAPI && baseConfidence > 0.8 {
			baseConfidence = 0.8
		} else if !hasAPI && baseConfidence > 0.6 {
			baseConfidence = 0.6
		}
	}

	return baseConfidence
}
