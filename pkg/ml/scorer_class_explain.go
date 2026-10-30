package ml

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"mega-analyzer/pkg/ml/ensemble"
)

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH SCORING
// ═══════════════════════════════════════════════════════════════════════════════

// ScoredMethod — метод с score
type ScoredMethod struct {
	Method      MethodInfo        `json:"method"`
	Score       ScoreResult       `json:"score"`
	ClassPath   string            `json:"class_path"`
	ClassName   string            `json:"class_name"`
	Interesting *InterestingScore `json:"-"`
	EntryPoint  *EntryPointInfo   `json:"-"`
	Ensemble    *ensemble.Score   `json:"-"`
}

// ScoreClass скорит все методы класса
func (ps *PatchScorer) ScoreClass(classInfo *ClassInfo) []ScoredMethod {
	results := make([]ScoredMethod, 0, len(classInfo.Methods))

	for i := range classInfo.Methods {
		mi := &classInfo.Methods[i]
		scoreResult := ps.scoreMethodInClassContext(mi, classInfo)

		// Пропускаем методы с score ниже минимума
		if scoreResult.FinalScore < MinPatchScore {
			continue
		}

		results = append(results, ScoredMethod{
			Method:    *mi,
			Score:     *scoreResult,
			ClassPath: classInfo.FilePath,
			ClassName: classInfo.ClassName,
		})
	}

	// Сортируем по score
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score.FinalScore > results[j].Score.FinalScore
	})

	return results
}

// recalculateFinal пересчитывает финальный score после модификации компонентов
func (ps *PatchScorer) recalculateFinal(result *ScoreResult) {
	rawScore := result.BaseScore +
		result.StructuralBonus +
		result.SafePenalty +
		result.LibraryPenalty +
		result.ContextBonus

	if result.CategoryWeight > 0 {
		rawScore *= (0.5 + result.CategoryWeight*0.125)
	}

	if rawScore < 0 {
		rawScore = 0
	}
	if rawScore > ps.config.MaxScore {
		rawScore = ps.config.MaxScore
	}

	result.FinalScore = math.Round(rawScore*10) / 10

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
}

// ScoreBatch скорит результат пакетного анализа
func (ps *PatchScorer) ScoreBatch(batchResult *BatchAnalyzeResult) []ScoredMethod {
	allScored := make([]ScoredMethod, 0, 64)

	for _, classInfo := range batchResult.Classes {
		scored := ps.ScoreClass(classInfo)
		allScored = append(allScored, scored...)
	}

	// Глобальная сортировка по score
	sort.Slice(allScored, func(i, j int) bool {
		if allScored[i].Score.FinalScore != allScored[j].Score.FinalScore {
			return allScored[i].Score.FinalScore > allScored[j].Score.FinalScore
		}
		// При равном score — app code важнее
		if allScored[i].Method.IsAppCode != allScored[j].Method.IsAppCode {
			return allScored[i].Method.IsAppCode
		}
		return allScored[i].Score.Confidence > allScored[j].Score.Confidence
	})

	return allScored
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORE EXPLANATION — человекочитаемое объяснение
// ═══════════════════════════════════════════════════════════════════════════════

// ExplainScore создаёт человекочитаемое объяснение
func ExplainScore(sm *ScoredMethod) string {
	var b strings.Builder

	s := &sm.Score
	m := &sm.Method

	// Header
	b.WriteString(fmt.Sprintf("Score: %.1f%% (%s)\n", s.FinalScore, s.RiskLevel))
	b.WriteString(fmt.Sprintf("Method: %s\n", MethodSignatureShort(m)))
	b.WriteString(fmt.Sprintf("Class: %s\n", ShortClassName(m.ClassName)))

	if s.BestPattern != nil {
		b.WriteString(fmt.Sprintf("Pattern: %s (%s)\n", s.BestPattern.ID, s.BestPattern.Description))
	}

	// Breakdown
	b.WriteString("\nScore breakdown:\n")
	b.WriteString(fmt.Sprintf("  Base score:       %+.1f\n", s.BaseScore))
	b.WriteString(fmt.Sprintf("  Structural:       %+.1f\n", s.StructuralBonus))
	if s.SafePenalty != 0 {
		b.WriteString(fmt.Sprintf("  Safe penalty:     %+.1f\n", s.SafePenalty))
	}
	if s.LibraryPenalty != 0 {
		b.WriteString(fmt.Sprintf("  Library penalty:  %+.1f\n", s.LibraryPenalty))
	}
	if s.ContextBonus != 0 {
		b.WriteString(fmt.Sprintf("  Context bonus:    %+.1f\n", s.ContextBonus))
	}
	if s.CategoryWeight != 1.0 {
		b.WriteString(fmt.Sprintf("  Category weight:  x%.1f\n", s.CategoryWeight))
	}

	// Reasons
	if len(s.Reasons) > 0 {
		b.WriteString("\nWhy vulnerable:\n")
		for _, r := range s.Reasons {
			b.WriteString(fmt.Sprintf("  • %s\n", r))
		}
	}

	// Warnings
	if len(s.Warnings) > 0 {
		b.WriteString("\nWarnings:\n")
		for _, w := range s.Warnings {
			b.WriteString(fmt.Sprintf("  ⚠ %s\n", w))
		}
	}

	return b.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIDENCE BREAKDOWN API METHODS
// ═══════════════════════════════════════════════════════════════════════════════

// ExplainConfidence creates a human-readable explanation of confidence calculation
// Requirements: 2.7, 4.5
func (ps *PatchScorer) ExplainConfidence(mi *MethodInfo, result *ScoreResult) string {
	var b strings.Builder

	if result.ConfidenceBreakdown == nil {
		return "No confidence breakdown available"
	}

	breakdown := result.ConfidenceBreakdown

	b.WriteString(fmt.Sprintf("Confidence: %.2f (%.0f%%)\n", breakdown.FinalConfidence, breakdown.FinalConfidence*100))
	b.WriteString("\nBreakdown:\n")
	b.WriteString(fmt.Sprintf("  Base confidence:      %.2f\n", breakdown.BaseConfidence))

	if len(breakdown.SignalContributions) > 0 {
		b.WriteString("\n  Signal contributions:\n")
		for _, contrib := range breakdown.SignalContributions {
			b.WriteString(fmt.Sprintf("    • %s: %.2f (weight: %.1f, confidence: %.2f)\n",
				contrib.SignalType, contrib.Contribution, contrib.Weight, contrib.Confidence))
		}
	}

	if breakdown.MultiSignalBonus > 0 {
		b.WriteString(fmt.Sprintf("\n  Multi-signal bonus:   +%.2f\n", breakdown.MultiSignalBonus))
	}

	if breakdown.ObfuscationAdjust != 0 {
		b.WriteString(fmt.Sprintf("  Obfuscation adjust:   %+.2f\n", breakdown.ObfuscationAdjust))
	}

	b.WriteString(fmt.Sprintf("\n  Final confidence:     %.2f\n", breakdown.FinalConfidence))

	// Add warnings for low confidence
	if breakdown.FinalConfidence < 0.5 {
		b.WriteString("\n⚠ Warning: Low confidence - manual review recommended\n")
	}

	return b.String()
}

// GetConfidenceBreakdown returns the confidence breakdown for a scored method
// Requirements: 2.7, 4.5
func (ps *PatchScorer) GetConfidenceBreakdown(result *ScoreResult) *ConfidenceBreakdown {
	return result.ConfidenceBreakdown
}

// scoreMethodInClassContext is shared by legacy ScoreClass and the live
// predictor pipeline. The latter defers the presentation cutoff until after
// model, feedback and structural evidence have been applied.
func (ps *PatchScorer) scoreMethodInClassContext(mi *MethodInfo, classInfo *ClassInfo) *ScoreResult {
	result := ps.ScoreMethod(mi)
	if classInfo != nil && classInfo.HasSecurityContext && classInfo.SecurityMethodCount >= 2 {
		result.ContextBonus += 5
		result.Reasons = append(result.Reasons, fmt.Sprintf("Class has %d security-related methods", classInfo.SecurityMethodCount))
		ps.recalculateFinal(result)
	}
	return result
}
