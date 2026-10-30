package ml

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// NUMERIC MAX INJECTION STRATEGY (surgical) — игровая экономика
// ═══════════════════════════════════════════════════════════════════════════════
//
// Хирургический аналог ConstantInjectionStrategy, но для ЧИСЛОВЫХ геттеров
// игровой экономики (coins/gems/gold/energy/…). Вместо замены всего тела
// (что выкидывает античит-телеметрию, логи, ленивую инициализацию — а значит
// повышает шанс детекта модификации) стратегия сохраняет каждую инструкцию и
// лишь форсит возвращаемый регистр в MAX_INT (0x7fffffff) прямо перед каждым
// 32-битным `return vX`.
//
// Пример — исходный подсчёт баланса всё ещё выполняется, меняется лишь итог:
//
//	iget v0, p0, L.../Wallet;->coins:I
//	# ← const v0, 0x7fffffff  (внедрено здесь)
//	return v0
//
// Wide-возвраты (J/D) СОЗНАТЕЛЬНО не трогаются: они требуют пары регистров и
// const-wide, что несовместимо с точечной инъекцией — для них остаётся
// whole-body стаб через patch_smali_builder (регистро-корректный).

// NumericMaxInjectionStrategy форсит числовой возврат в MAX_INT, сохраняя тело.
type NumericMaxInjectionStrategy struct {
	priority int
}

// NewNumericMaxInjectionStrategy создаёт стратегию. Приоритет 88 — ниже
// булевой хирургической инъекции (90), но выше whole-body стабов, чтобы
// экономические геттеры патчились наименее разрушительным способом.
func NewNumericMaxInjectionStrategy() *NumericMaxInjectionStrategy {
	return &NumericMaxInjectionStrategy{priority: 88}
}

// CanApply: research-режим, числовой примитив (I/S/B/C, НЕ boolean, НЕ wide),
// имя выглядит как экономический геттер, и есть хотя бы один 32-битный return.
func (s *NumericMaxInjectionStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	if mi == nil || isConstructorMethod(mi) {
		return false
	}
	// Разблокировка ресурсов — исследовательская задача, не оборонительная.
	if mode != PatchModeResearch {
		return false
	}
	if mi.ReturnsBoolean || !isIntFamilyReturn(mi.ReturnType) {
		return false
	}
	if maxRefusesEconomy(mi) {
		return false
	}
	if !isEconomyGetterName(mi.NameLower) {
		return false
	}
	_, ok := findReturnRegisters(mi.RawBody)
	return ok
}

// Generate внедряет const-MAX_INT перед каждым 32-битным return.
func (s *NumericMaxInjectionStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}
	smaliCode, count, note := overrideReturnsSafe(mi.RawBody, 0x7fffffff)
	if count == 0 {
		return nil, fmt.Errorf("no 32-bit return instruction found to override")
	}

	desc := fmt.Sprintf(
		"Force economy getter %s to MAX_INT at %d return site(s), preserving side effects",
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
			Reason: fmt.Sprintf(
				"%s looks like an in-game resource getter (coins/gems/gold/energy).", mi.Name),
			WhatItDoes:   "Keeps every original instruction and only overrides the returned amount to MAX_INT before returning.",
			WhyThisPatch: "Surgical override preserves anti-cheat/telemetry side effects that a whole-body stub would drop — harder to detect.",
			Impact:       "Reported resource amount becomes effectively unlimited; control flow unchanged.",
			Signals:      []string{fmt.Sprintf("Economy getter name: %s", mi.Name)},
		},
	}
	patch.ReturnCoverage = returnSiteCoverage(mi.RawBody, "return", count)
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)
	return patch, nil
}

// GetPriority returns the strategy priority.
func (s *NumericMaxInjectionStrategy) GetPriority() int { return s.priority }

// PatchType returns the patch type produced by this strategy.
func (s *NumericMaxInjectionStrategy) PatchType() PatchType { return PatchReturnMaxInt }

// GetDescription returns a human-readable description.
func (s *NumericMaxInjectionStrategy) GetDescription() string {
	return "Surgically force numeric economy getters (coins/gems/gold/energy) to MAX_INT before each 32-bit return, preserving side effects."
}

func (s *NumericMaxInjectionStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "numeric_max_injection",
		SupportedRoles:       []MethodRole{MethodRoleValueProvider},
		SupportedReturns:     []string{"I", "S", "B", "C"},
		PreservesControlFlow: true,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// isIntFamilyReturn — тип возврата помещается в один 32-битный регистр (I/S/B/C).
// J/D (wide) исключены сознательно: пара регистров + const-wide несовместимы с
// точечной инъекцией.
func isIntFamilyReturn(rt string) bool {
	switch strings.TrimSpace(rt) {
	case "I", "S", "B", "C":
		return true
	}
	return false
}

// economyGetterTokens — маркеры имени экономического геттера. Специально узкие,
// чтобы не хватать нейтральные getX. Синхронизированы с currency_time_patterns.go.
// adfree покрывает флаги снятия рекламы (0/1): форсированный MAX читается
// проверками как "реклама отключена".
var economyGetterTokens = []string{
	"coin", "gold", "gem", "crystal", "diamond", "ruby", "cash", "money",
	"currency", "balance", "credit", "token", "ticket", "spin", "shard",
	"fragment", "star", "energy", "stamina", "fuel", "life", "lives",
	"heart", "silver", "reward", "wallet", "adfree",
}

// isEconomyGetterName reports whether the (already lower-cased) method name looks
// like an in-game resource/currency getter.
func isEconomyGetterName(nameLower string) bool {
	if nameLower == "" {
		return false
	}
	for _, tok := range economyGetterTokens {
		if strings.Contains(nameLower, tok) {
			return true
		}
	}
	return false
}
