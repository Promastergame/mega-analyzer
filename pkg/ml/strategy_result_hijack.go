package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// INVOKE RESULT HIJACK — стелс-перехват результата вызова
//
// NopInjection выпиливает security-invoke целиком (3u → 3×nop). Это заметно:
// пропадают сайд-эффекты (логи/телеметрия/инициализация), а антитампер может
// палить отсутствие вызова.
//
// Hijack хитрее: invoke ОСТАЕТСЯ (все сайд-эффекты живы), а следующий
// move-result* заменяется на size-neutral const:
//   move-result v0            → const/4 v0, 0x1  (оба 1u!)
//   move-result-object v0     → const/4 v0, 0x0  (null, 1u)
// move-result-wide НЕ трогаем (нет 1u wide-const) — отказ.
//
// Это всегда offset-safe: размер не меняется ни на юнит. Работает даже в
// методах с switch/try/catch, где overrideReturnsSafe сдается.
//
// Приоритет 89 — как у price-zero: точечнее nop (60), сохраняет вызов.
// ═══════════════════════════════════════════════════════════════════════════════

// InvokeResultHijackStrategy перехватывает результат security-вызова.
type InvokeResultHijackStrategy struct {
	contextAnalyzer *ContextAnalyzer
	priority        int
}

// NewInvokeResultHijackStrategy создаёт стратегию.
func NewInvokeResultHijackStrategy() *InvokeResultHijackStrategy {
	return &InvokeResultHijackStrategy{
		contextAnalyzer: NewContextAnalyzer(),
		priority:        89,
	}
}

// CanApply: есть security-invoke + сразу за ним move-result (не wide,
// регистр ≤ v15), метод не конструктор, ≥2 инструкций.
func (s *InvokeResultHijackStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	if mi == nil || isConstructorMethod(mi) {
		return false
	}
	if len(mi.RawBody) < 2 {
		return false
	}
	if !mi.HasSecurityAPI && !mi.HasSecurityStrings && !mi.HasSecurityName {
		// Без security-контекста перехват результата — слишком агрессивно.
		return false
	}
	for i, line := range mi.RawBody {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "invoke-") || !s.matchesSecurityCall(trimmed, mi) {
			continue
		}
		if i+1 >= len(mi.RawBody) {
			continue
		}
		next := strings.TrimSpace(mi.RawBody[i+1])
		fields := strings.Fields(next)
		if len(fields) != 2 || !strings.HasPrefix(fields[0], "move-result") {
			continue
		}
		if fields[0] == "move-result-wide" {
			continue // нет 1u wide-const
		}
		if !strings.HasPrefix(fields[1], "v") || !regIndexLE15(fields[1]) {
			continue // const/4 не кодирует v16+
		}
		return true
	}
	return false
}

// Generate заменяет move-result на полярно-правильный const, invoke жив.
func (s *InvokeResultHijackStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}
	checkType := s.contextAnalyzer.DetermineCheckType(mi)
	fill := 0
	if v := nopFillValue(mi, mode); v == 1 {
		fill = 1
	}
	smaliCode, count := s.generateSmaliCode(mi, fill)
	if count == 0 {
		return nil, fmt.Errorf("no hijackable move-result found")
	}
	desc := fmt.Sprintf("Hijack %d invoke result(s) to 0x%x, keeping security calls for stealth", count, fill)
	patch := &GeneratedPatch{
		OriginalCode: strings.Join(mi.RawBody, "\n"),
		PatchedCode:  smaliCode,
		PatchType:    PatchNop,
		Description:  desc,
		MethodName:   mi.Name,
		FilePath:     mi.FilePath,
		Mode:         mode,
		Explanation: PatchExplanation{
			Reason:       fmt.Sprintf("Security check %q result intercepted at move-result.", checkType),
			WhatItDoes:   fmt.Sprintf("Keeps every invoke (side effects alive) and forces the consumed result to 0x%x.", fill),
			WhyThisPatch: "Stealthier than nop: logs/telemetry still run, only the decision value is overridden — harder to detect by call-presence checks.",
			Impact:       "Check logic executes but its verdict is neutralised.",
			Signals:      []string{fmt.Sprintf("Hijacked calls in %s", mi.Name)},
		},
	}
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)
	return patch, nil
}

// GetPriority returns the strategy priority.
func (s *InvokeResultHijackStrategy) GetPriority() int { return s.priority }

// PatchType returns the patch type produced by this strategy.
func (s *InvokeResultHijackStrategy) PatchType() PatchType { return PatchNop }

// GetDescription returns a human-readable description.
func (s *InvokeResultHijackStrategy) GetDescription() string {
	return "Keeps security invokes (stealth) and replaces the consuming move-result with a polarity-correct const (size-neutral, offset-safe)."
}

func (s *InvokeResultHijackStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "invoke_result_hijack",
		SupportedRoles:       []MethodRole{MethodRoleBooleanGate, MethodRoleWrapper, MethodRoleValueProvider},
		PreservesControlFlow: true,
		RequiresDFG:          true,
	}
}

func (s *InvokeResultHijackStrategy) generateSmaliCode(mi *shared.MethodInfo, fill int) (string, int) {
	var b strings.Builder
	header := mi.MethodHeader
	if header == "" {
		header = shared.ReconstructStubHeader(mi)
	}
	b.WriteString(header)
	b.WriteByte('\n')
	if mi.HasLocalsDirective {
		locals := mi.RegisterCount
		if locals < 0 {
			locals = 0
		}
		b.WriteString(fmt.Sprintf("    .locals %d\n\n", locals))
	} else {
		regs := mi.RegisterCount
		if regs == 0 {
			regs = 2
		}
		b.WriteString(fmt.Sprintf("    .registers %d\n\n", regs))
	}
	count := 0
	for i, line := range mi.RawBody {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ".method") || strings.HasPrefix(trimmed, ".end method") ||
			strings.HasPrefix(trimmed, ".registers") || strings.HasPrefix(trimmed, ".locals") {
			continue
		}
		// move-result сразу за security-invoke → const (size-neutral 1u→1u)
		if i > 0 && isMoveResultNarrow(trimmed) {
			prev := strings.TrimSpace(mi.RawBody[i-1])
			if strings.Contains(prev, "invoke-") && s.matchesSecurityCall(prev, mi) {
				dst := strings.Fields(trimmed)[1]
				if strings.HasPrefix(dst, "v") && regIndexLE15(dst) {
					b.WriteString(fmt.Sprintf("    const/4 %s, 0x%x\n", dst, fill))
					count++
					continue
				}
			}
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString(".end method")
	return b.String(), count
}

func isMoveResultNarrow(trimmed string) bool {
	fields := strings.Fields(trimmed)
	return len(fields) == 2 && (fields[0] == "move-result" || fields[0] == "move-result-object")
}

func (s *InvokeResultHijackStrategy) matchesSecurityCall(line string, mi *shared.MethodInfo) bool {
	for _, secCall := range mi.SecurityCalls {
		if secCall != "" && strings.Contains(line, secCall) {
			return true
		}
	}
	// fallback: эвристика по securityAPIs именам
	lower := strings.ToLower(line)
	for _, p := range securityAPIs {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
