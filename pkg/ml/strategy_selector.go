package ml

import (
	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// STRATEGY SELECTOR
//
// Chooses the best patch strategy for a given method based on applicability
// and priority. Integrates with ContextAnalyzer for context-aware selection.
//
// Requirements: 1.4, 6.6
// ═══════════════════════════════════════════════════════════════════════════════

// StrategySelector chooses the best strategy for a method
type StrategySelector struct {
	strategies      []PatchStrategy
	contextAnalyzer *ContextAnalyzer
}

// defaultPatchStrategies returns the canonical strategy set. Both constructors
// share it so a new strategy cannot be added to one and forgotten in the other.
func defaultPatchStrategies() []PatchStrategy {
	return []PatchStrategy{
		NewReturnTrueStrategy(),
		NewReturnFalseStrategy(),
		NewConstantInjectionStrategy(),
		NewConditionInversionStrategy(),
		NewPartialBypassStrategy(),
		NewNopInjectionStrategy(),
		NewNumericMaxInjectionStrategy(),
		NewPriceZeroInjectionStrategy(),
		NewResourceMaxInjectionStrategy(),
		NewCooldownResetInjectionStrategy(),
		NewWideMaxInjectionStrategy(),
		NewObjectReturnInjectionStrategy(),
		NewInvokeResultHijackStrategy(),
		NewEntryGateStrategy(),
		NewConstReplaceStrategy(),
	}
}

// NewStrategySelector creates a new StrategySelector with default strategies
func NewStrategySelector() *StrategySelector {
	return &StrategySelector{
		strategies:      defaultPatchStrategies(),
		contextAnalyzer: NewContextAnalyzer(),
	}
}

// NewStrategySelectorWithAnalyzer creates a StrategySelector with a custom ContextAnalyzer
func NewStrategySelectorWithAnalyzer(ca *ContextAnalyzer) *StrategySelector {
	return &StrategySelector{
		strategies:      defaultPatchStrategies(),
		contextAnalyzer: ca,
	}
}

// SelectStrategy chooses the best strategy for the given method and mode
//
// Algorithm:
//  1. Filter strategies by applicability (CanApply)
//  2. Sort by priority (highest first)
//  3. Return highest priority strategy
//  4. Return nil if no strategies are applicable
//
// Parameters:
//   - mi: Method information containing structure, calls, and context
//   - mode: Operational mode (defensive for fixes, research for bypasses)
//
// Returns:
//   - Best applicable strategy, or nil if none are applicable
func (ss *StrategySelector) SelectStrategy(
	mi *shared.MethodInfo,
	mode PatchMode,
) PatchStrategy {
	return ss.SelectStrategyWithSignals(mi, mode, nil)
}

// SelectStrategyWithSignals chooses the best strategy for the given method
// and mode, honouring confirmed vulnerability signals: the strategy whose
// patch type matches the signal's desired outcome gets a priority boost, so
// audit signals are never overridden by name-pattern heuristics.
func (ss *StrategySelector) SelectStrategyWithSignals(
	mi *shared.MethodInfo,
	mode PatchMode,
	signals []VulnSignal,
) PatchStrategy {
	ranked := ss.RankStrategies(mi, mode, signals)
	if len(ranked) == 0 {
		return nil
	}
	return ranked[0].Strategy
}

// GetContextAnalyzer returns the ContextAnalyzer used by this selector
func (ss *StrategySelector) GetContextAnalyzer() *ContextAnalyzer {
	return ss.contextAnalyzer
}

// GetStrategies returns all registered strategies
func (ss *StrategySelector) GetStrategies() []PatchStrategy {
	return ss.strategies
}

// AddStrategy adds a custom strategy to the selector
func (ss *StrategySelector) AddStrategy(strategy PatchStrategy) {
	ss.strategies = append(ss.strategies, strategy)
}

// RankedStrategy — стратегия с оценкой и причиной, для fallback-цепочки.
type RankedStrategy struct {
	Strategy   PatchStrategy
	Assessment StrategyAssessment
	Score      float64
}

// RankStrategies возвращает ВСЕ применимые стратегии по убыванию скора
// (signal-буст +100 уже применен). Детерминировано: стабильная сортировка.
func (ss *StrategySelector) RankStrategies(
	mi *shared.MethodInfo,
	mode PatchMode,
	signals []VulnSignal,
) []RankedStrategy {
	req, err := BuildChangeRequest(mi, mode, signals)
	if err != nil {
		return nil
	}
	return ss.RankStrategiesWithRequest(req)
}

// GenerateBest пробует стратегии по рангу до первой валидной.
// Реализация переехала в patch_planner.go: единый путь планировщика
// (кандидаты → генерация → контракт → структура → выбор).

func isPartialForcedPatch(p *GeneratedPatch) bool {
	if p == nil {
		return false
	}
	if p.ReturnCoverage != nil {
		c := p.ReturnCoverage
		return c.TotalSites <= 0 || c.HandledSites <= 0 || c.HandledSites != c.TotalSites
	}
	// Backward compatibility for external strategies without typed coverage.
	// Built-in return injectors do not depend on Description wording anymore.
	// overrideReturnsSafe кладет note вида "N return site(s) left unforced"
	return len(p.Description) > 0 &&
		(containsFold(p.Description, "left unforced") ||
			containsFold(p.Description, "swapOnly") ||
			containsFold(p.Description, "cannot be safely"))
}

func containsFold(haystack, needle string) bool {
	if len(needle) == 0 {
		return false
	}
	h, n := haystack, needle
	// ASCII case-fold достаточно для наших маркеров
	if len(h) < len(n) {
		return false
	}
	lh := make([]byte, len(h))
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lh[i] = c
	}
	ln := make([]byte, len(n))
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		ln[i] = c
	}
	hs, ns := string(lh), string(ln)
	for i := 0; i+len(ns) <= len(hs); i++ {
		if hs[i:i+len(ns)] == ns {
			return true
		}
	}
	return false
}
