package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ResourceMaxInjectionStrategy — хирургический аналог NumericMaxInjectionStrategy,
// но для НЕэкономических ресурсов, где «больше — лучше»: здоровье, мана, боезапас,
// броня, кислород и т.п. Тело метода сохраняется целиком, а перед каждым 32-битным
// `return vX` форсится MAX_INT через overrideReturnsSafe. Токены имени сознательно
// НЕ пересекаются с economyGetterTokens, чтобы не дублировать экономический геттер.
// Приоритет 86 — ниже экономического MAX (88) и ценового нуля (89): на
// неоднозначных именах побеждают более специфичные стратегии. Wide-возвраты (J/D)
// не трогаются: const-wide несовместим с точечной инъекцией.
type ResourceMaxInjectionStrategy struct {
	priority int
}

// NewResourceMaxInjectionStrategy создаёт стратегию с приоритетом 86.
func NewResourceMaxInjectionStrategy() *ResourceMaxInjectionStrategy {
	return &ResourceMaxInjectionStrategy{priority: 86}
}

// combatResourceGetterTokens — маркеры имени боевого/выживальческого ресурса.
// Специально узкие и без пересечения с economyGetterTokens.
var combatResourceGetterTokens = []string{
	"health", "hitpoint", "mana", "ammo", "ammunition", "durability",
	"armor", "armour", "shield", "oxygen", "boost",
}

// CanApply: research-режим, числовой примитив (I/S/B/C, НЕ boolean, НЕ wide),
// имя выглядит как геттер боевого ресурса, и есть хотя бы один 32-битный return.
func (s *ResourceMaxInjectionStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	if mi == nil || isConstructorMethod(mi) {
		return false
	}
	if mode != PatchModeResearch {
		return false
	}
	if mi.ReturnsBoolean || !isIntFamilyReturn(mi.ReturnType) {
		return false
	}
	if !isCombatResourceGetterName(mi.NameLower) {
		return false
	}
	_, ok := findReturnRegisters(mi.RawBody)
	return ok
}

// Generate внедряет const-MAX_INT перед каждым 32-битным return, сохраняя тело.
func (s *ResourceMaxInjectionStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}
	smaliCode, count, note := overrideReturnsSafe(mi.RawBody, 0x7fffffff)
	if count == 0 {
		return nil, fmt.Errorf("no 32-bit return instruction found to override")
	}

	desc := fmt.Sprintf(
		"Force resource getter %s to MAX_INT at %d return site(s), preserving side effects",
		mi.Name, count)
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
			Reason:       fmt.Sprintf("%s looks like a combat/survival resource getter (health/mana/ammo/armor).", mi.Name),
			WhatItDoes:   "Keeps every original instruction and only overrides the returned amount to MAX_INT before returning.",
			WhyThisPatch: "Surgical override preserves anti-cheat/telemetry side effects that a whole-body stub would drop — harder to detect.",
			Impact:       "Reported resource amount becomes effectively unlimited; control flow unchanged.",
			Signals:      []string{fmt.Sprintf("Resource getter name: %s", mi.Name)},
		},
	}
	patch.ReturnCoverage = returnSiteCoverage(mi.RawBody, "return", count)
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)
	return patch, nil
}

// GetPriority returns the strategy priority.
func (s *ResourceMaxInjectionStrategy) GetPriority() int { return s.priority }

// PatchType returns the patch type produced by this strategy.
func (s *ResourceMaxInjectionStrategy) PatchType() PatchType { return PatchReturnMaxInt }

// GetDescription returns a human-readable description.
func (s *ResourceMaxInjectionStrategy) GetDescription() string {
	return "Surgically force combat/survival resource getters (health/mana/ammo/armor) to MAX_INT before each 32-bit return, preserving side effects."
}

// Metadata exposes the strategy contract used by the assessment layer.
func (s *ResourceMaxInjectionStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "resource_max_injection",
		SupportedRoles:       []MethodRole{MethodRoleValueProvider},
		SupportedReturns:     []string{"I", "S", "B", "C"},
		PreservesControlFlow: true,
	}
}

// isCombatResourceGetterName reports whether the (already lower-cased) method name
// looks like a combat/survival resource getter (non-economy).
func isCombatResourceGetterName(nameLower string) bool {
	if nameLower == "" {
		return false
	}
	for _, tok := range combatResourceGetterTokens {
		if strings.Contains(nameLower, tok) {
			return true
		}
	}
	return false
}
