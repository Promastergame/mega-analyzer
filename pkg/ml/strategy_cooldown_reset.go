package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// CooldownResetInjectionStrategy — хирургическая стратегия для геттеров ОСТАВШЕГОСЯ
// времени кулдауна/ожидания (getCooldownRemaining, timeLeft, nextClaim…). Тело
// метода сохраняется целиком (античит-телеметрия, логи, ленивая инициализация),
// а перед каждым 32-битным `return vX` внедряется const 0 через overrideReturnsSafe.
// Ноль здесь однозначно означает «готово сейчас». Приоритет 87 — ниже ценового
// нуля (89) и экономического MAX (88), чтобы на неоднозначных именах побеждали
// более специфичные стратегии. Wide-возвраты (J/D) не трогаются: const-wide
// несовместим с точечной инъекцией.
type CooldownResetInjectionStrategy struct {
	priority int
}

// NewCooldownResetInjectionStrategy создаёт стратегию с приоритетом 87.
func NewCooldownResetInjectionStrategy() *CooldownResetInjectionStrategy {
	return &CooldownResetInjectionStrategy{priority: 87}
}

// cooldownGetterTokens — маркеры имени геттера остаточного времени. Узкие, чтобы
// ноль был однозначно «готово», а не «истёк триал».
var cooldownGetterTokens = []string{
	"cooldown", "recharge", "remainingtime", "timeremaining", "timeleft",
	"waittime", "nextspin", "nextclaim", "nextreward", "regentime",
	"refilltime", "respawntime", "reloadtime",
}

// CanApply: research-режим, числовой примитив (I/S/B/C, НЕ boolean, НЕ wide),
// имя выглядит как геттер остатка кулдауна, и есть хотя бы один 32-битный return.
func (s *CooldownResetInjectionStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	if mi == nil || isConstructorMethod(mi) {
		return false
	}
	if mode != PatchModeResearch {
		return false
	}
	if mi.ReturnsBoolean || !isIntFamilyReturn(mi.ReturnType) {
		return false
	}
	if !isCooldownGetterName(mi.NameLower) {
		return false
	}
	_, ok := findReturnRegisters(mi.RawBody)
	return ok
}

// Generate внедряет const-0 перед каждым 32-битным return, сохраняя тело.
func (s *CooldownResetInjectionStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}
	smaliCode, count, note := overrideReturnsSafe(mi.RawBody, 0)
	if count == 0 {
		return nil, fmt.Errorf("no 32-bit return instruction found to override")
	}

	desc := fmt.Sprintf(
		"Force cooldown getter %s to 0 at %d return site(s), preserving side effects",
		mi.Name, count)
	if note != "" {
		desc += "; " + note
	}

	patch := &GeneratedPatch{
		OriginalCode: strings.Join(mi.RawBody, "\n"),
		PatchedCode:  smaliCode,
		PatchType:    PatchReturnZero,
		Description:  desc,
		MethodName:   mi.Name,
		FilePath:     mi.FilePath,
		Mode:         mode,
		Explanation: PatchExplanation{
			Reason:       fmt.Sprintf("%s looks like a cooldown/wait-timer getter (remaining time).", mi.Name),
			WhatItDoes:   "Keeps every original instruction and only overrides the returned remaining time to 0 before returning.",
			WhyThisPatch: "A zero remaining cooldown makes every readiness check pass immediately; surgical injection preserves anti-cheat/telemetry side effects a whole-body stub would drop.",
			Impact:       "Cooldowns/timers become effectively instant; control flow unchanged.",
			Signals:      []string{fmt.Sprintf("Cooldown getter name: %s", mi.Name)},
		},
	}
	patch.ReturnCoverage = returnSiteCoverage(mi.RawBody, "return", count)
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)
	return patch, nil
}

// GetPriority returns the strategy priority.
func (s *CooldownResetInjectionStrategy) GetPriority() int { return s.priority }

// PatchType returns the patch type produced by this strategy.
func (s *CooldownResetInjectionStrategy) PatchType() PatchType { return PatchReturnZero }

// GetDescription returns a human-readable description.
func (s *CooldownResetInjectionStrategy) GetDescription() string {
	return "Surgically force cooldown/timer getters to 0 before each 32-bit return (instant cooldowns), preserving side effects."
}

// Metadata exposes the strategy contract used by the assessment layer.
func (s *CooldownResetInjectionStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "cooldown_reset_injection",
		SupportedRoles:       []MethodRole{MethodRoleValueProvider},
		SupportedReturns:     []string{"I", "S", "B", "C"},
		PreservesControlFlow: true,
	}
}

// isCooldownGetterName reports whether the (already lower-cased) method name looks
// like a remaining-cooldown/wait-timer getter.
func isCooldownGetterName(nameLower string) bool {
	if nameLower == "" {
		return false
	}
	for _, tok := range cooldownGetterTokens {
		if strings.Contains(nameLower, tok) {
			return true
		}
	}
	return false
}
