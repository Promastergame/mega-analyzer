package ml

import (
	"fmt"

	"mega-analyzer/pkg/internal/cfg"
)

// ═══════════════════════════════════════════════════════════════════════════════
// STRUCTURAL SIGNALS — Phase 2
//
// Извлекает path-sensitive сигналы из CFG (доминаторы, guards, funnels) и
// конвертирует их в дополнительный bonus к RiskScore.
//
// Эти данные ВСЕГДА строятся в pkg/internal/cfg (PatternAnalyzer.FindGuards/
// FindFunnels + DominatorAnalyzer), но раньше **никогда не читались** в ml-
// слое. Phase 2 закрывает этот gap: guard-доминирование и AND-funnel дают
// конкретный bonus и попадают в WhyVulnerable/Reasons для аудита.
//
// ВАЖНО: side-effect мутирует node.IsGuard / GuardInfo / IsFunnel / FunnelInfo
// у узлов CFG. Поскольку CFG кешируется (cfgCache), повторный вызов на тот же
// CFG идемпотентен (PatternAnalyzer проверяет node.Type перед обработкой).
// ═══════════════════════════════════════════════════════════════════════════════

// StructuralSignals — агрегат path-sensitive сигналов CFG.
type StructuralSignals struct {
	// Guards — if-условия которые доминируют достижимый exit.
	// Это сильнейший индикатор «проверка решает судьбу метода».
	GuardCount      int     `json:"guard_count"`
	HardGateCount   int     `json:"hard_gate_count"`  // guards с ExitPostDoms = реально 100%
	DominationRatio float64 `json:"domination_ratio"` // % CFG-узлов под доминированием guard'а

	// Funnels — точки сходимости где несколько проверок встречаются у одного return.
	FunnelCount  int  `json:"funnel_count"`
	HasAndFunnel bool `json:"has_and_funnel"` // RequiresAllTrue: 3 проверки и все должны пройти
	HasOrFunnel  bool `json:"has_or_funnel"`  // RequiresAnyFalse: достаточно одной чтобы провалить
}

// ComputeStructuralSignals прогоняет dominators + PatternAnalyzer и собирает агрегат.
// Безопасно вызывать на одном и том же CFG несколько раз (idempotent).
func ComputeStructuralSignals(controlFlowGraph *cfg.ControlFlowGraph) *StructuralSignals {
	if controlFlowGraph == nil || controlFlowGraph.NodeCount() == 0 {
		return nil
	}

	// DominatorAnalyzer — prerequisite для FindGuards (проверяет PostDominates).
	// Используем флаги CFG чтобы не делать двойную работу при cache hit.
	if !controlFlowGraph.DominatorTree || !controlFlowGraph.PostDomTree {
		dom := cfg.NewDominatorAnalyzer(controlFlowGraph)
		if !controlFlowGraph.DominatorTree {
			dom.ComputeDominators()
		}
		if !controlFlowGraph.PostDomTree {
			dom.ComputePostDominators()
		}
	}

	patternAnalyzer := cfg.NewPatternAnalyzer(controlFlowGraph)
	guards := patternAnalyzer.FindGuards()
	funnels := patternAnalyzer.FindFunnels()

	sig := &StructuralSignals{
		GuardCount:  len(guards),
		FunnelCount: len(funnels),
	}

	// HARD GATE: guard для которого exit постдоминирует условие — то есть
	// какой бы edge ни был выбран, мы ВСЁ РАВНО придём к этому exit.
	// Самый сильный structural-сигнал: «эта проверка решает 100% судьбу метода».
	for _, g := range guards {
		if g != nil && g.ExitPostDoms {
			sig.HardGateCount++
		}
	}

	// Funnel-семантика: AND (все должны быть true) против OR (любой провалит).
	for _, f := range funnels {
		if f == nil {
			continue
		}
		if f.RequiresAllTrue {
			sig.HasAndFunnel = true
		}
		if f.RequiresAnyFalse {
			sig.HasOrFunnel = true
		}
	}

	// Domination ratio: упрощённая метрика — % узлов где ImmediateDom (вверх по
	// дереву доминаторов) хотя бы один guard. Это «насколько весь метод
	// зависит от защитных проверок».
	if sig.GuardCount > 0 {
		guardIDs := make(map[int]bool, sig.GuardCount)
		for _, n := range controlFlowGraph.Nodes {
			if n != nil && n.IsGuard {
				guardIDs[n.ID] = true
			}
		}
		dominated := 0
		for _, n := range controlFlowGraph.Nodes {
			if n == nil {
				continue
			}
			// Идём вверх по dominator tree, ищем guard.
			for d := n.ImmediateDom; d != nil; d = d.ImmediateDom {
				if guardIDs[d.ID] {
					dominated++
					break
				}
			}
		}
		total := float64(controlFlowGraph.NodeCount())
		if total > 0 {
			sig.DominationRatio = float64(dominated) / total
		}
	}

	return sig
}

// ScoreContribution считает вклад в RiskScore и возвращает читаемые reasons.
// Cap по компонентам, чтобы один pathological метод с 50 guard'ами не
// взорвал скор.
func (s *StructuralSignals) ScoreContribution() (float64, []string) {
	if s == nil {
		return 0, nil
	}

	var bonus float64
	var reasons []string

	// Guard bonus: +5 за каждый guard, cap 15. Это значит max 3 guard'а
	// дают полный сигнал — больше = diminishing returns (метод-перегруженный
	// проверками часто = decoy).
	if s.GuardCount > 0 {
		gb := float64(s.GuardCount) * 5.0
		if gb > 15.0 {
			gb = 15.0
		}
		bonus += gb
		reasons = append(reasons,
			fmt.Sprintf("STRUCT: %d guard(s) detected (path-sensitive, +%.1f)",
				s.GuardCount, gb))
	}

	// Hard gate (ExitPostDoms): дополнительные +3 за каждый, cap 10.
	// Это самый сильный сигнал — guard полностью контролирует exit.
	if s.HardGateCount > 0 {
		hgb := float64(s.HardGateCount) * 3.0
		if hgb > 10.0 {
			hgb = 10.0
		}
		bonus += hgb
		reasons = append(reasons,
			fmt.Sprintf("STRUCT: %d HARD GATE(s) — guards post-dominate exit (+%.1f)",
				s.HardGateCount, hgb))
	}

	// Domination ratio: чем больше % метода под guard'ом — тем больше «вес»
	// этой проверки в логике метода. Активируется только если ratio > 0.3
	// (иначе это случайный if в большом методе).
	if s.DominationRatio > 0.3 {
		df := s.DominationRatio * 8.0
		bonus += df
		reasons = append(reasons,
			fmt.Sprintf("STRUCT: guards dominate %.0f%% of method body (+%.1f)",
				s.DominationRatio*100, df))
	}

	// AND-funnel: цепочка проверок-AND. В патч-стратегии это значит «один
	// entry-патч может сломать всю цепь» → ценный сигнал.
	if s.HasAndFunnel {
		bonus += 4.0
		reasons = append(reasons,
			"STRUCT: AND-funnel detected — single entry-patch may break chain (+4.0)")
	}

	// OR-funnel: слабее (множество путей провала), но всё равно индикатор
	// сложной защитной логики.
	if s.HasOrFunnel && !s.HasAndFunnel {
		bonus += 2.0
		reasons = append(reasons,
			"STRUCT: OR-funnel detected — multiple failure paths (+2.0)")
	}

	return bonus, reasons
}
