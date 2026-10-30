package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// WIDE MAX INJECTION — хирургический MAX для long/double геттеров (J/D)
//
// NumericMaxInjection покрывает только 32-бит (I/S/B/C). Но игровая экономика
// часто long: getCoins()J, getBalance()J. Whole-body стаб выкидывает телеметрию,
// а const-wide требует ПАРУ регистров vX:vX+1.
//
// Стратегия:
//   (a) size-neutral swap: `const-wide/16 v0, 0x0` → `const-wide v0, max`
//       невозможен без resize (2u → 5u), поэтому swap только если const-wide
//       уже широкий и держит другое значение — меняем литерал на месте.
//   (b) single-def: регистр пишется одним const-wide и читается только
//       return-wide — флипаем деф.
//   (c) branchless insert: `const-wide vX, max` перед каждым return-wide.
//       Если есть numeric branches или hazard (switch/try) — НЕ вставляем,
//       а отдаем валидный whole-body стаб через BuildTypedReturnPatch
//       (регистро-корректный, wide-пары учтены).
//
// Приоритет 88 — как у NumericMax (та же семья, широкий фланг).
// ═══════════════════════════════════════════════════════════════════════════════

// WideMaxInjectionStrategy форсит long/double возврат в MAX, сохраняя тело.
type WideMaxInjectionStrategy struct {
	priority int
}

// NewWideMaxInjectionStrategy создаёт стратегию.
func NewWideMaxInjectionStrategy() *WideMaxInjectionStrategy {
	return &WideMaxInjectionStrategy{priority: 88}
}

// CanApply: research, wide-примитив J/D, экономическое/ресурсное имя,
// есть хотя бы один return-wide.
func (s *WideMaxInjectionStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	if mi == nil || isConstructorMethod(mi) {
		return false
	}
	if mode != PatchModeResearch {
		return false
	}
	rt := strings.TrimSpace(mi.ReturnType)
	if rt != "J" && rt != "D" {
		return false
	}
	if maxRefusesEconomy(mi) {
		return false
	}
	if !isEconomyGetterName(mi.NameLower) && !isCombatResourceGetterName(mi.NameLower) && !isCooldownGetterName(mi.NameLower) && !isPriceGetterName(mi.NameLower) {
		// wide без экономического имени — не трогаем (слишком агрессивно)
		return false
	}
	return hasReturnWide(mi.RawBody)
}

// Generate внедряет const-wide MAX перед каждым return-wide или стабит метод.
func (s *WideMaxInjectionStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}
	// Integer MAX bits reinterpreted as double are NaN: a double balance
	// needs Double.MAX_VALUE bits instead of Long.MAX_VALUE.
	maxBits := int64(0x7fffffffffffffff)
	if strings.TrimSpace(mi.ReturnType) == "D" {
		maxBits = int64(0x7fefffffffffffff)
	}
	smaliCode, count, note := overrideWideReturnsSafe(mi.RawBody, maxBits)
	if count == 0 {
		// surgical невозможен — валидный стаб (не ошибка: селектор попробует дальше,
		// а GenerateBest отфильтрует по ValidateStrict)
		header := mi.MethodHeader
		if header == "" {
			header = shared.ReconstructStubHeader(mi)
		}
		rt := effectiveReturnType(mi.ReturnType, mi.FullSignature, header)
		smaliCode = buildStubMethodSmart(header, mi.FullSignature, rt, kindMaxInt)
		count = 1
		note = "surgical wide override refused layout; emitted validated stub"
	}
	desc := fmt.Sprintf("Force wide getter %s to MAX at %d return-wide site(s)", mi.Name, count)
	if note != "" {
		desc += "; " + note
	}
	patch := &GeneratedPatch{
		OriginalCode: strings.Join(mi.RawBody, "\n"),
		PatchedCode:  smaliCode,
		PatchType:    PatchReturnMaxInt,
		Description:  desc,
		MethodName:   mi.Name,
		FilePath:     mi.FilePath,
		Mode:         mode,
		Explanation: PatchExplanation{
			Reason:       fmt.Sprintf("%s looks like a wide (J/D) resource getter.", mi.Name),
			WhatItDoes:   "Keeps the body when layout allows; otherwise emits a register-correct wide stub (const-wide + return-wide with pair budget).",
			WhyThisPatch: "Wide economy (long coins) can't be forced with 32-bit const; const-wide needs a register pair.",
			Impact:       "Reported wide amount becomes effectively unlimited.",
			Signals:      []string{fmt.Sprintf("Wide getter name: %s", mi.Name)},
		},
	}
	patch.ReturnCoverage = returnSiteCoverage(mi.RawBody, "return-wide", count)
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)
	return patch, nil
}

// GetPriority returns the strategy priority.
func (s *WideMaxInjectionStrategy) GetPriority() int { return s.priority }

// PatchType returns the patch type produced by this strategy.
func (s *WideMaxInjectionStrategy) PatchType() PatchType { return PatchReturnMaxInt }

// GetDescription returns a human-readable description.
func (s *WideMaxInjectionStrategy) GetDescription() string {
	return "Surgically force wide (J/D) economy/resource getters to MAX before each return-wide, preserving side effects; stub fallback when layout is unsafe."
}

func (s *WideMaxInjectionStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "wide_max_injection",
		SupportedRoles:       []MethodRole{MethodRoleValueProvider},
		SupportedReturns:     []string{"J", "D"},
		PreservesControlFlow: true,
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func hasReturnWide(body []string) bool {
	for _, line := range body {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) == 2 && fields[0] == "return-wide" {
			return true
		}
	}
	return false
}

// overrideWideReturnsSafe — упрощенный аналог overrideReturnsSafe для wide.
// Безопасная политика:
//   - swap литерала const-wide/const-wide-16/32 feeding return-wide (resize via
//     const-wide, т.к. MAX не лезет в 16 бит) — только если нет hazard;
//   - branchless insert const-wide перед return-wide;
//   - при branches/hazard — только swap, остальное скипаем с note.
// Возвращает (smali, forced, note).
func overrideWideReturnsSafe(body []string, value int64) (string, int, string) {
	sites := []int{} // lineIdx return-wide
	for i, line := range body {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) == 2 && fields[0] == "return-wide" {
			sites = append(sites, i)
		}
	}
	if len(sites) == 0 {
		return strings.Join(body, "\n") + "\n", 0, ""
	}
	if hasRelayoutHazard(body) || hasNumericBranch(body) {
		// Только size-neutral swap const-wide (тот же опкод, тот же размер).
		out := make([]string, len(body))
		copy(out, body)
		forced := 0
		predecessors := straightLinePredecessors(body)
		for _, si := range sites {
			reg := wideReturnReg(body[si])
			j := predecessors[si]
			if j < 0 {
				continue
			}
			t := smaliCodeLine(body[j])
			if dreg, ok := constWideDestRegister(t); ok && dreg == reg && strings.HasPrefix(t, "const-wide ") {
				out[j] = swapWideLiteral(body[j], value)
				forced++
			}
		}
		if forced == len(sites) {
			return strings.Join(out, "\n") + "\n", forced, ""
		}
		note := fmt.Sprintf("%d wide return site(s) left unforced: branches/hazard need relayout", len(sites)-forced)
		return strings.Join(out, "\n") + "\n", forced, note
	}
	// Branchless, no hazard — вставляем const-wide перед каждым return-wide.
	var b strings.Builder
	forced := 0
	for _, line := range body {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		isSite := len(fields) == 2 && fields[0] == "return-wide"
		if isSite {
			reg := fields[1]
			indent := indentLike(line)
			b.WriteString(indent)
			b.WriteString(fmt.Sprintf("const-wide %s, 0x%xL", reg, uint64(value)))
			b.WriteByte('\n')
			forced++
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String(), forced, ""
}

func wideReturnReg(line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 2 {
		return fields[1]
	}
	return "v0"
}

func constWideDestRegister(trimmed string) (string, bool) {
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return "", false
	}
	if fields[0] != "const-wide" && fields[0] != "const-wide/16" && fields[0] != "const-wide/32" && fields[0] != "const-wide/high16" {
		return "", false
	}
	reg := strings.TrimSuffix(fields[1], ",")
	if strings.HasPrefix(reg, "v") || strings.HasPrefix(reg, "p") {
		return reg, true
	}
	return "", false
}

func swapWideLiteral(line string, value int64) string {
	indent := indentLike(line)
	fields := strings.Fields(strings.TrimSpace(line))
	reg := strings.TrimSuffix(fields[1], ",")
	return fmt.Sprintf("%s%s %s, 0x%xL", indent, fields[0], reg, uint64(value))
}
