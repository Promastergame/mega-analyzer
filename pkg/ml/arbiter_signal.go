package ml

import (
	"fmt"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/ml/arbiter"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ARBITER SIGNAL — "precedent similarity" (HDC) как дополнительный сигнал
// в ContextScorer breakdown, плюс confidence fusion (HDC + pattern-matcher).
// ═══════════════════════════════════════════════════════════════════════════════

const arbiterSignalName = "precedent_similarity"

// arbiterMaxPoints — верхняя граница вклада arbiter-сигнала в SignalScore.
// Сигнал дополняет, а не доминирует над rule-based скорингом.
const arbiterMaxPoints = 20

var defaultArbiter = arbiter.New()

// ScoreWithArbiter — обёртка над Score(), дополняющая обычный
// rule-based результат сигналом "precedent similarity": HDC-фичи блока
// сравниваются с анкор-стором известно-плохих сигнатур (см.
// pkg/ml/arbiter), и похожесть конвертируется в SignalBreakdownItem с
// объяснением, какие именно прецеденты совпали. Это же — точка
// confidence fusion между HDC и pattern-matcher/GNN сигналами: очки
// от статических правил (pattern-matcher) и от HDC-арбитра складываются
// в единый TotalScore, а совпавшие анкоры логируются как отдельное
// голосующее объяснение.
func (cs *ContextScorer) ScoreWithArbiter(ctx *AppContext, node *cfg.CFGNode) *ContextScoringResult {
	result := cs.Score(ctx)
	if node == nil {
		return result
	}

	feats := arbiter.BlockFeatures(node)
	if len(feats) == 0 {
		return result
	}

	sim, matches := defaultArbiter.Score(feats)
	points := int(sim * float32(arbiterMaxPoints))
	if points <= 0 {
		return result
	}

	desc := "HDC precedent similarity to known-bad signatures"
	reason := ""
	if len(matches) > 0 {
		reason = fmt.Sprintf("closest precedent: %s (sim=%.2f)", matches[0].Label, matches[0].Sim)
	}

	item := SignalBreakdownItem{
		Signal:      arbiterSignalName,
		Description: desc,
		BasePoints:  points,
		ContextMod:  0,
		FinalPoints: points,
		Category:    "ml_precedent",
		Reason:      reason,
	}

	result.SignalBreakdown = append(result.SignalBreakdown, item)
	result.SignalScore += points
	result.TotalScore += points
	if result.TotalScore < 0 {
		result.TotalScore = 0
	}

	result.ThreatLevel = cs.rules.Thresholds.GetLevel(result.TotalScore)
	result.ThreatLevelInfo = GetThreatLevelInfo(result.ThreatLevel)

	if len(matches) > 0 {
		explain := fmt.Sprintf("🧬 precedent_similarity: matched %d known-bad pattern(s), top=%s (%.0f%% sim, %+d points)",
			len(matches), matches[0].Label, matches[0].Sim*100, points)
		result.Explanations = append(result.Explanations, explain)
	}

	result.Summary = cs.generateSummary(result)

	return result
}
