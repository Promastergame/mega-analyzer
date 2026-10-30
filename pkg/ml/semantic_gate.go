package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/ml/stringutils"
)

// ─────────────────────────────────────────────────────────────────────────────
// Semantic Gate Detector v2 — path-sensitive, CFG-aware
// ─────────────────────────────────────────────────────────────────────────────
// Проблема v1 (patch_predictor.go:1027-1300): 250+ строк
//   strings.Contains(nameLower, "equals") || strings.Contains(nameLower, "show")
// — хрупко, ломается на любом rename, не понимает семантику.
//
// Решение v2: семантика = CFG + DFG + структурные сигналы + call graph depth
// вместо имён. Имя — лишь слабый prior (weight 0.2), а не hard filter.
//
// Сигналы (все уже считаются в cfg/structural):
//   • guardCount (DominatesExit) — метод контролирует достижения exit
//   • hardGateCount (ExitPostDominates) — gate пост-доминирует выход (самый сильный)
//   • funnelDetected — AND-funnel (один патч ломает цепочку)
//   • DFG license check confidence — data-flow доказывает проверку лицензии
//   • crackPointConfirmed — CFG подтвердил точку взлома извне
//   • isSyntheticAccessor — синтетика компилятора (access$, lambda$, Dsl)
//   • callChain depth — реальный граф вызовов
//
// Результат: gateScore ∈ [0,1] + verdict (REAL_GATE | WEAK_GATE | NON_GATE)
// с объяснением. PatchPredictor использует gateScore как множитель к PatchValue.

// GateVerdict — итоговый вердикт семантического детектора
type GateVerdict int

const (
	GateNonGate GateVerdict = iota // точно не gate (accessor, synthetic, Math wrapper)
	GateWeakGate                    // есть структура, но слабый сигнал
	GateRealGate                    // сильная gate-семантика
)

func (v GateVerdict) String() string {
	switch v {
	case GateRealGate:
		return "REAL_GATE"
	case GateWeakGate:
		return "WEAK_GATE"
	default:
		return "NON_GATE"
	}
}

// SemanticGateResult — выход v2 детектора
type SemanticGateResult struct {
	Verdict    GateVerdict `json:"verdict"`
	Score      float64     `json:"score"`       // 0..1, 1 = точно gate
	Confidence float64     `json:"confidence"`  // калиброванная уверенность
	Reasons    []string    `json:"reasons"`     // почему так решили
	// сигналы, вошедшие в скор
	GuardCount       int     `json:"guard_count"`
	HardGateCount    int     `json:"hard_gate_count"`
	Funnel           bool    `json:"funnel"`
	DFGConf          float64 `json:"dfg_conf"`
	CrackConfirmed   bool    `json:"crack_confirmed"`
	IsSynthetic      bool    `json:"is_synthetic"`
	NamePriorPenalty float64 `json:"name_prior_penalty"` // 0..1, 0 = no penalty
}

// SemanticGateDetector — CFG-aware detector (stateless, потокобезопасен)
type SemanticGateDetector struct {
	// пороги, тюнятся без перестройки пайплайна
	hardGateWeight float64
	guardWeight    float64
	funnelBonus    float64
	dfgWeight      float64
	crackBonus     float64
	synthPenalty   float64
}

func NewSemanticGateDetector() *SemanticGateDetector {
	return &SemanticGateDetector{
		hardGateWeight: 0.35,
		guardWeight:    0.25,
		funnelBonus:    0.15,
		dfgWeight:      0.30,
		crackBonus:     0.25,
		synthPenalty:   0.50,
	}
}

// Analyze — главный метод: MethodInfo + CFG/DFG/структура → verdict
func (d *SemanticGateDetector) Analyze(mi *MethodInfo, cg *cfg.ControlFlowGraph, structSigs *StructuralSignals, dfg *DFGInfo, crackConfirmed bool) *SemanticGateResult {
	res := &SemanticGateResult{
		Verdict:  GateNonGate,
		Score:    0,
		Reasons:  []string{},
		CrackConfirmed: crackConfirmed,
	}
	if mi == nil {
		res.Reasons = append(res.Reasons, "nil method")
		return res
	}

	// 1. Synthetic / accessor — hard NON_GATE (семантика, а не имя)
	res.IsSynthetic = isSyntheticMethod(mi)
	if res.IsSynthetic {
		res.Reasons = append(res.Reasons, "synthetic/compiler-generated (access$, lambda$, Dsl, clear/has)")
		res.Score = 0.05
		res.Confidence = 0.95
		res.Verdict = GateNonGate
		return res
	}

	// 2. Собираем сигналы из CFG/структуры
	if cg != nil {
		// guard/hardGate из structural уже, но можем и напрямую из CFG если есть
		_ = cg
	}
	if structSigs != nil {
		res.GuardCount = structSigs.GuardCount
		res.HardGateCount = structSigs.HardGateCount
		res.Funnel = structSigs.HasAndFunnel || structSigs.HasOrFunnel || structSigs.FunnelCount > 0
	}
	if dfg != nil && dfg.Available {
		res.DFGConf = dfg.Confidence
	}

	// 3. Инварианты: data-class accessor без веток — точно не gate
	if isDataAccessorHeuristic(mi) && !hasRealBranching(mi, structSigs) {
		res.Reasons = append(res.Reasons, "data accessor without branching (getter/setter/equals)")
		res.Score = 0.10
		res.Confidence = 0.85
		res.Verdict = GateNonGate
		return res
	}

	// 4. Считаем семантический скор [0,1]
	score := 0.0
	if res.HardGateCount > 0 {
		// каждый hard gate — сильный сигнал, но с убывающей отдачей
		for i := 0; i < res.HardGateCount && i < 3; i++ {
			add := d.hardGateWeight / float64(i+1) // 0.35, 0.17, 0.11
			score += add
			res.Reasons = append(res.Reasons, describeHardGate(i, add))
		}
	}
	if res.GuardCount > 0 {
		guardScore := float64(res.GuardCount) * 0.08 // 1 guard=0.08, 5 guards=0.40 (cap 0.30)
		if guardScore > 0.30 {
			guardScore = 0.30
		}
		score += guardScore * d.guardWeight / 0.25 // нормализуем к весу
		res.Reasons = append(res.Reasons, describeGuards(res.GuardCount, guardScore))
	}
	if res.Funnel {
		score += d.funnelBonus
		res.Reasons = append(res.Reasons, "AND-funnel detected (+0.15) — single patch breaks chain")
	}
	if res.DFGConf > 0 {
		dfgContrib := res.DFGConf * d.dfgWeight // conf 0..1 → 0..0.30
		score += dfgContrib
		res.Reasons = append(res.Reasons, describeDFG(res.DFGConf, dfgContrib))
	}
	if res.CrackConfirmed {
		score += d.crackBonus
		res.Reasons = append(res.Reasons, "CFG crack-point confirmed (+0.25)")
	}

	// 5. Name prior — слабый штраф, а не hard filter (в отличие от v1)
	res.NamePriorPenalty = namePriorPenalty(mi.Name)
	if res.NamePriorPenalty > 0 {
		score *= (1 - res.NamePriorPenalty)
		if res.NamePriorPenalty >= 0.3 {
			res.Reasons = append(res.Reasons, describeNamePenalty(mi.Name, res.NamePriorPenalty))
		}
	}

	// 6. Branching requirement: без веток даже с DFG — не gate (кроме crackConfirmed)
	if !hasRealBranching(mi, structSigs) && !res.CrackConfirmed && res.DFGConf < 0.5 {
		score *= 0.40
		res.Reasons = append(res.Reasons, "no real branching (single path) — score ×0.40")
	}

	if score > 1.0 {
		score = 1.0
	}
	if score < 0 {
		score = 0
	}
	res.Score = score

	// 7. Калибровка confidence: чем больше подтверждений, тем выше
	confirmations := 0
	if res.HardGateCount > 0 {
		confirmations++
	}
	if res.GuardCount > 1 {
		confirmations++
	}
	if res.Funnel {
		confirmations++
	}
	if res.DFGConf >= 0.6 {
		confirmations++
	}
	if res.CrackConfirmed {
		confirmations++
	}
	switch confirmations {
	case 0:
		res.Confidence = 0.35
	case 1:
		res.Confidence = 0.60
	case 2:
		res.Confidence = 0.80
	default:
		res.Confidence = 0.92
	}

	// 8. Verdict threshold (тюнится по eval harness, см. eval_harness.go)
	switch {
	case res.Score >= 0.55:
		res.Verdict = GateRealGate
	case res.Score >= 0.25:
		res.Verdict = GateWeakGate
	default:
		res.Verdict = GateNonGate
	}

	return res
}

// ── helpers ──────────────────────────────────────────────────────────────────

func isSyntheticMethod(mi *MethodInfo) bool {
	if mi.IsSynthetic {
		return true
	}
	n := stringutils.ToLowerIfEmpty(mi.Name, mi.NameLower)
	// компиляторная синтетика — точные признаки, а не "contains"
	if strings.Contains(n, "$lambda$") || strings.Contains(n, "lambda$") {
		return true
	}
	classLower := stringutils.ToLowerIfEmpty(mi.ClassName, mi.ClassNameLower)
	if strings.Contains(classLower, "kt$dsl") || strings.Contains(classLower, "kt$android") {
		return true
	}
	// protobuf generated: hasXxx / clearXxx / getXxx где класс — protobuf
	if mi.IsAccessor && (strings.HasPrefix(n, "has") || strings.HasPrefix(n, "clear")) {
		return true
	}
	// access$000 — synthetic accessor
	if strings.HasPrefix(n, "access$") {
		return true
	}
	return false
}

func isDataAccessorHeuristic(mi *MethodInfo) bool {
	n := stringutils.ToLowerIfEmpty(mi.Name, mi.NameLower)
	for _, dataMethod := range DataClassMethodNames {
		if n == dataMethod {
			return true
		}
	}
	// Additional common data accessor methods
	additionalDataMethods := []string{"iterator", "size", "clear", "isempty"}
	for _, method := range additionalDataMethods {
		if n == method {
			return true
		}
	}
	// intrinsic getter — Drawable / protobuf без логики
	if stringutils.ContainsAny(n, IntrinsicPatterns) {
		return true
	}
	// getInt/getLong без веток — likely primitive getter
	if (n == "getint" || n == "getlong" || n == "getshort" || n == "getbyte") && mi.IfCheckCount == 0 {
		return true
	}
	return false
}

func hasRealBranching(mi *MethodInfo, sigs *StructuralSignals) bool {
	if sigs != nil && (sigs.HardGateCount > 0 || sigs.GuardCount > 0 || sigs.HasAndFunnel || sigs.HasOrFunnel || sigs.FunnelCount > 0) {
		return true
	}
	// fallback: эвристика по счётчикам
	return mi.IfCheckCount > 0 && mi.ReturnCount > 1 || mi.HasDualReturn
}

func namePriorPenalty(name string) float64 {
	n := strings.ToLower(name)
	for _, h := range UILifecycleHints {
		if strings.Contains(n, h) {
			if semanticContainsAny(n, SecurityNameKeywords) {
				return 0
			}
			return 0.30
		}
	}
	for _, p := range UIPatternsForPenalty {
		if strings.Contains(n, p) {
			return 0.50
		}
	}
	return 0
}

func semanticContainsAny(s string, keywords []string) bool {
	return stringutils.ContainsAny(s, keywords)
}

func describeHardGate(i int, add float64) string {
	if i == 0 {
		return fmt.Sprintf("1 HARD GATE (post-dominates exit) (+%.2f) — strongest signal", add)
	}
	return fmt.Sprintf("additional hard gate #%d (+%.2f) — diminishing return", i+1, add)
}

func describeGuards(count int, contrib float64) string {
	return fmt.Sprintf("%d guard(s) DominatesExit (total +%.2f)", count, contrib)
}

func describeDFG(conf, contrib float64) string {
	return fmt.Sprintf("DFG license check conf=%.2f (+%.2f)", conf, contrib)
}

func describeNamePenalty(name string, penalty float64) string {
	return fmt.Sprintf("name prior penalty for %s (-%.0f%%, UI/lifecycle hint)", name, penalty*100)
}
