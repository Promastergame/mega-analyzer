package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ENTRY GATE STRATEGY — size-neutral нопинг первого security-гейта
//
// Проблема: в методах с switch/try/catch (hasRelayoutHazard) вставка const
// перед return запрещена — overrideReturnsSafe сдается (swapOnlyFallback).
// Whole-body стаб в таких методах опасен: режет try-границы и switch-payload.
//
// Решение: НЕ трогаем returns вообще. Вместо этого нопим ПЕРВЫЙ security
// conditional (if-* 2u → 2×nop 1u+1u, размер тот же!). Ветка исчезает,
// метод падает в fall-through — для OR-gated детекта это "not detected".
// Для AND-funnel (if>=3) — тоже entry-gate, как в PartialBypass.
//
// Всегда offset-safe: ни один code unit не сдвигается. Работает везде.
//
// Приоритет 75 — выше partial (70, тоже точечный) и ниже стабов (80)?
// Нет: выше partial, но ниже constant (90) и hijack (89): если можно форсить
// результат — форсим, gate-нопинг только когда returns недоступны.
// Итог: 75 > 70 partial, < 80 return-стабы? Стабы 80 выше — но стабы режут
// сайд-эффекты. Gate-нопинг сохраняет тело, поэтому ставим 78: выше стабов,
// ниже всей surgical-семьи (86+). Компромисс: тело живо + безопасно.
// ═══════════════════════════════════════════════════════════════════════════════

// EntryGateStrategy нопит первый security-conditional.
type EntryGateStrategy struct {
	priority int
}

// NewEntryGateStrategy создаёт стратегию.
func NewEntryGateStrategy() *EntryGateStrategy {
	return &EntryGateStrategy{priority: 78}
}

// CanApply: boolean, ≥1 if, security-контекст, есть инвертируемый conditional
// в security-контексте (3 строки после security-line).
func (s *EntryGateStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	if mi == nil || isConstructorMethod(mi) {
		return false
	}
	if mode == PatchModeDefensive {
		return false
	}
	if !mi.ReturnsBoolean {
		return false
	}
	if mi.IfCheckCount == 0 {
		return false
	}
	if !mi.HasSecurityAPI && !mi.HasSecurityStrings && !mi.HasSecurityName {
		return false
	}
	return s.findEntryGate(mi) >= 0
}

// Generate нопит entry-gate (size-neutral).
func (s *EntryGateStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}
	gateIdx := s.findEntryGate(mi)
	if gateIdx < 0 {
		return nil, fmt.Errorf("no entry gate found")
	}
	var b strings.Builder
	for i, line := range mi.RawBody {
		if i == gateIdx {
			trimmed := strings.TrimSpace(line)
			mnem, _ := insnLine(trimmed)
			units, known := smaliUnits(mnem)
			if !known {
				units = 2 // if-* всегда 2u
			}
			// size-neutral: N юнитов → N nop'ов
			for k := 0; k < units; k++ {
				b.WriteString("    nop\n")
			}
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	smaliCode := strings.TrimRight(b.String(), "\n")
	patch := &GeneratedPatch{
		OriginalCode: strings.Join(mi.RawBody, "\n"),
		PatchedCode:  smaliCode,
		PatchType:    PatchNop,
		Description:  "Nop entry security gate (size-neutral, control flow falls through to clean path)",
		MethodName:   mi.Name,
		FilePath:     mi.FilePath,
		Mode:         mode,
		Explanation: PatchExplanation{
			Reason:       fmt.Sprintf("Method %s opens with a security gate; neutralising it preserves the body.", mi.Name),
			WhatItDoes:   "Replaces the first security conditional with size-equal nops — no layout shift, no relayout needed.",
			WhyThisPatch: "Safest edit for switch/try-catch methods where return-override is refused: zero offset drift by construction.",
			Impact:       "Security branch never taken; method falls through to the clean path.",
			Signals:      []string{fmt.Sprintf("Entry gate in %s", mi.Name)},
		},
	}
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)
	return patch, nil
}

// GetPriority returns the strategy priority.
func (s *EntryGateStrategy) GetPriority() int { return s.priority }

// PatchType returns the patch type produced by this strategy.
func (s *EntryGateStrategy) PatchType() PatchType { return PatchNop }

// GetDescription returns a human-readable description.
func (s *EntryGateStrategy) GetDescription() string {
	return "Size-neutral nop of the first security conditional (entry gate) — offset-safe even for switch/try-catch methods."
}

func (s *EntryGateStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "entry_gate",
		SupportedRoles:       []MethodRole{MethodRoleBooleanGate, MethodRoleWrapper},
		SupportedReturns:     []string{"Z"},
		PreservesControlFlow: true,
		RequiresCFG:          true,
	}
}

// findEntryGate ищет первый conditional в security-контексте.
// Primary: CFG (FindEntryGateCFG) — первый гейт на пути к желаемому возврату.
// Fallback: текстовая эвристика (security-line в окне 4 строк + первый if).
func (s *EntryGateStrategy) findEntryGate(mi *shared.MethodInfo) int {
	// Desired для research-bypass boolean-гейта: форсим "чистый" исход.
	// Детекты (isRooted) → 0, positive-gates (isLicensed) → 1.
	desired := int32(nopFillValue(mi, PatchModeResearch))
	if gate := FindEntryGateCFG(mi.RawBody, desired); gate >= 0 {
		// CFG не знает про security-контекст — проверяем, что гейт рядом
		// с security (или метод целиком security-контекстный).
		if s.gateInSecurityContext(mi, gate) {
			return gate
		}
	}
	return s.findEntryGateTextual(mi)
}

func (s *EntryGateStrategy) gateInSecurityContext(mi *shared.MethodInfo, gateIdx int) bool {
	for j := gateIdx - 1; j >= 0 && j >= gateIdx-4; j-- {
		if s.isSecurityLine(strings.TrimSpace(mi.RawBody[j]), mi) {
			return true
		}
	}
	// Метод с security-именем/API целиком контекстный — любой первый гейт ок.
	return mi.HasSecurityAPI || mi.HasSecurityStrings || mi.HasSecurityName
}

func (s *EntryGateStrategy) findEntryGateTextual(mi *shared.MethodInfo) int {
	securityLines := map[int]bool{}
	for i, line := range mi.RawBody {
		trimmed := strings.TrimSpace(line)
		if s.isSecurityLine(trimmed, mi) {
			securityLines[i] = true
		}
	}
	for i, line := range mi.RawBody {
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) == 0 || !IsConditionalOpcode(fields[0]) {
			continue
		}
		for j := i - 1; j >= 0 && j >= i-4; j-- {
			if securityLines[j] {
				return i
			}
		}
		// Gate без явного security выше, но метод security-контекстный:
		// первый conditional — тоже gate (OR-funnel).
		if i < 12 {
			return i
		}
	}
	return -1
}

func (s *EntryGateStrategy) isSecurityLine(line string, mi *shared.MethodInfo) bool {
	if strings.Contains(line, "invoke-") {
		for _, c := range mi.SecurityCalls {
			if c != "" && strings.Contains(line, c) {
				return true
			}
		}
		lower := strings.ToLower(line)
		for _, p := range securityAPIs {
			if strings.Contains(lower, strings.ToLower(p)) {
				return true
			}
		}
	}
	if strings.Contains(line, "const-string") {
		for _, str := range mi.SecurityStrings {
			if str != "" && strings.Contains(line, str) {
				return true
			}
		}
	}
	return false
}
