package ml

import (
	"fmt"
	"strings"
	"unicode"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PRICE ZERO INJECTION STRATEGY (surgical) — покупки за ноль
// ═══════════════════════════════════════════════════════════════════════════════
//
// Хирургическая стратегия для геттеров ЦЕНЫ/СТОИМОСТИ (getGemCost, getPrice,
// itemCost, upgradeCost…). Родственный NumericMaxInjectionStrategy приём:
// тело сохраняется целиком (античит-телеметрия, логи, ленивая инициализация —
// всё остаётся), а перед каждым 32-битным `return vX` внедряется `const/4 0x0`.
//
// Почему отдельная стратегия, а не MAX_INT: для БАЛАНСА игрока MAX_INT даёт
// «бесконечные ресурсы», но ЦЕНА товара с MAX_INT делает покупку недоступной.
// Семантически корректное значение цены в research-режиме — ноль: любая
// проверка `if (price <= coins)` проходит без трогания баланса.
//
// Приоритет 89 — выше NumericMaxInjectionStrategy (88): на неоднозначных
// именах вида getGemCost ("gem" тянет экономический маркер баланса,
// "cost" — ценовой) побеждает обнуление цены как единственно осмысленный
// вариант. Широкие возвраты (J/D), как и в NumericMax, сознательно не
// трогаются: const-wide несовместим с точечной инъекцией.
//
// Отбор по имени — НЕ подстрочный. Имя разбивается на токены
// (getGemCost → get/gem/cost, PRICE_PER_UNIT → price/per/unit), и стратегия
// срабатывает только если один из токенов — маркер цены И ни один токен не
// указывает на «не-сумму» (getCostumeId, getPriceTier, getPriceListSize,
// comparePrice…). Обнуление индекса/ID/размера не даёт бесплатной покупки,
// зато даёт ArrayIndexOutOfBounds.

const priceZeroInjectionPriority = 89

// PriceZeroInjectionStrategy форсит цену в 0, сохраняя тело метода.
type PriceZeroInjectionStrategy struct {
	priority int
}

// NewPriceZeroInjectionStrategy создаёт стратегию.
func NewPriceZeroInjectionStrategy() *PriceZeroInjectionStrategy {
	return &PriceZeroInjectionStrategy{priority: priceZeroInjectionPriority}
}

// priceNameTokens — маркеры ценового геттера (сравнение по целому токену).
// Специально узкие, чтобы не хватать нейтральные getX; пересечение с
// economyGetterTokens разрешается приоритетом селектора.
var priceNameTokens = map[string]struct{}{
	"price": {}, "prices": {},
	"cost": {}, "costs": {},
}

// priceNameStopTokens — токены, при которых возвращаемое int почти наверняка
// НЕ является суммой: идентификаторы, индексы, размеры, коды ресурсов,
// компараторы. Любое совпадение отключает стратегию для метода.
var priceNameStopTokens = map[string]struct{}{
	// идентификаторы / индексация
	"id": {}, "ids": {}, "uid": {}, "index": {}, "idx": {}, "position": {}, "pos": {},
	"slot": {}, "ordinal": {}, "offset": {}, "key": {},
	// классификация
	"type": {}, "kind": {}, "tier": {}, "level": {}, "lvl": {}, "category": {},
	"mode": {}, "state": {}, "status": {}, "flag": {}, "flags": {}, "version": {},
	// размеры / счётчики (не суммы)
	"size": {}, "count": {}, "len": {}, "length": {}, "num": {}, "number": {},
	// android-ресурсы / отображение
	"res": {}, "resource": {}, "resid": {}, "icon": {}, "color": {}, "colour": {},
	"layout": {}, "view": {}, "string": {}, "text": {}, "label": {}, "format": {},
	// операции, возвращающие int, но не значение
	"compare": {}, "compareto": {}, "hash": {}, "hashcode": {}, "code": {},
	"find": {}, "indexof": {}, "error": {}, "err": {},
}

// CanApply: research-режим, числовой примитив (I/S/B/C, НЕ boolean, НЕ wide),
// имя выглядит как ценовой геттер, и есть хотя бы один 32-битный return.
//
// Имя матчим по mi.Name (оригинальный camelCase: getGemCost → get/gem/cost),
// с фолбэком на NameLower для уже-нижнего регистра и обфусцированных имен.
func (s *PriceZeroInjectionStrategy) CanApply(mi *shared.MethodInfo, mode PatchMode) bool {
	if mi == nil || isConstructorMethod(mi) {
		return false
	}
	// Бесплатная покупка — исследовательская задача, не оборонительная.
	if mode != PatchModeResearch {
		return false
	}
	if mi.ReturnsBoolean || !isIntFamilyReturn(mi.ReturnType) {
		return false
	}
	if _, ok := matchPriceGetterForMethod(mi); !ok {
		return false
	}
	_, ok := findReturnRegisters(mi.RawBody)
	return ok
}

// Generate внедряет const-0 перед каждым 32-битным return, сохраняя тело.
func (s *PriceZeroInjectionStrategy) Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error) {
	if mi == nil {
		return nil, fmt.Errorf("method info is nil")
	}
	smaliCode, count, note := overrideReturnsSafe(mi.RawBody, 0)
	if count == 0 {
		return nil, fmt.Errorf("no 32-bit return instruction found to override in %s", mi.Name)
	}

	desc := fmt.Sprintf(
		"Force price getter %s to 0 at %d return site(s), preserving side effects",
		mi.Name, count)
	if note != "" {
		desc += "; " + note
	}

	signals := []string{fmt.Sprintf("Price getter name: %s", mi.Name)}
	if token, ok := matchPriceGetterForMethod(mi); ok {
		signals = append(signals, fmt.Sprintf("Matched price token: %q", token))
	}
	signals = append(signals, fmt.Sprintf("Return type: %s, %d return site(s)", mi.ReturnType, count))

	patch := &GeneratedPatch{
		OriginalCode: strings.Join(mi.RawBody, "\n"),
		PatchedCode:  smaliCode,
		PatchType:    PatchReturnZero,
		Description:  desc,
		MethodName:   mi.Name,
		FilePath:     mi.FilePath,
		Mode:         mode,
		Explanation: PatchExplanation{
			Reason: fmt.Sprintf(
				"%s looks like a purchase-price getter (whole-token match on price/cost, no id/index/size markers).", mi.Name),
			WhatItDoes:   "Keeps every original instruction and only overrides the returned amount to 0 immediately before each 32-bit return.",
			WhyThisPatch: "A zero price makes every affordability check pass without touching the player's balance; surgical injection preserves anti-cheat side effects a whole-body stub would drop.",
			Impact:       "Purchases become free of charge; control flow unchanged. If the value is ever used as a divisor or array bound, the game may throw at runtime — verify with the caller list.",
			Signals:      signals,
		},
	}
	patch.ReturnCoverage = returnSiteCoverage(mi.RawBody, "return", count)
	patch.OriginalLines = len(mi.RawBody)
	patch.PatchedLines = countLines(smaliCode)
	return patch, nil
}

// GetPriority returns the strategy priority.
func (s *PriceZeroInjectionStrategy) GetPriority() int { return s.priority }

// PatchType returns the patch type produced by this strategy.
func (s *PriceZeroInjectionStrategy) PatchType() PatchType { return PatchReturnZero }

// GetDescription returns a human-readable description.
func (s *PriceZeroInjectionStrategy) GetDescription() string {
	return "Surgically force price/cost getters to 0 before each 32-bit return (free purchases), preserving side effects."
}

// Metadata describes the strategy for the selector/registry.
func (s *PriceZeroInjectionStrategy) Metadata() StrategyMetadata {
	return StrategyMetadata{
		ID:                   "price_zero_injection",
		SupportedRoles:       []MethodRole{MethodRoleValueProvider},
		SupportedReturns:     []string{"I", "S", "B", "C"},
		PreservesControlFlow: true,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// isPriceGetterName reports whether the method name looks like a
// purchase-price/cost getter rather than a balance/id/index getter.
func isPriceGetterName(name string) bool {
	_, ok := matchPriceGetterName(name)
	if ok {
		return true
	}
	// Фолбэк для уже-нижнего регистра без границ слов (getgemcost):
	// подстрочный матч цены без стоп-фильтра тут нельзя (costume FP),
	// поэтому только склеенные price/cost без стоп-подстрок id/index/size.
	return matchPriceGetterConcatenated(name)
}

// matchPriceGetterForMethod матчит по оригинальному Name (camelCase дает
// границы токенов), с фолбэком на NameLower.
func matchPriceGetterForMethod(mi *shared.MethodInfo) (string, bool) {
	if mi == nil {
		return "", false
	}
	if tok, ok := matchPriceGetterName(mi.Name); ok {
		return tok, true
	}
	if mi.NameLower != "" && mi.NameLower != mi.Name {
		if tok, ok := matchPriceGetterName(mi.NameLower); ok {
			return tok, true
		}
		if isPriceGetterName(mi.NameLower) {
			// concatenated fallback уже проверен внутри isPriceGetterName
			for _, tok := range []string{"price", "prices", "cost", "costs"} {
				if containsLower(mi.NameLower, tok) {
					return tok, true
				}
			}
		}
	}
	return "", false
}

// matchPriceGetterConcatenated — фолбэк для склеенного нижнего регистра
// вида "getgemcost": целых токенов нет, ищем price/cost как подстроку,
// но отказываем при подстроках-идентификаторах (costumeid содержит id).
func matchPriceGetterConcatenated(lower string) bool {
	l := lower
	has := containsLower(l, "price") || containsLower(l, "cost")
	if !has {
		return false
	}
	// Стоп-подстроки только однозначные для склеенного регистра:
	// id в конце (costumeid, priceid), index, size, tier, count.
	for _, stop := range []string{"id", "index", "size", "tier", "count", "position"} {
		if containsLower(l, stop) {
			return false
		}
	}
	// "costume" без id (getcostume) — тоже не сумма.
	if containsLower(l, "costume") {
		return false
	}
	return true
}

// matchPriceGetterName tokenizes the identifier and returns the matched price
// token. It rejects names containing any stop-token (id, index, size, tier,
// compare…) because zeroing those does not produce a free purchase.
func matchPriceGetterName(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	tokens := splitIdentifierTokens(name)
	if len(tokens) == 0 {
		return "", false
	}

	matched := ""
	for _, t := range tokens {
		if _, stop := priceNameStopTokens[t]; stop {
			return "", false
		}
		if _, ok := priceNameTokens[t]; ok && matched == "" {
			matched = t
		}
	}
	return matched, matched != ""
}

// splitIdentifierTokens splits a Java/Kotlin identifier into lower-cased tokens:
//
//	getGemCost      → [get gem cost]
//	PRICE_PER_UNIT  → [price per unit]
//	getHTTPCost     → [get http cost]
//	item2Price      → [item price]
//	getCostumeId    → [get costume id]
//
// Digits and non-letters act as separators; acronym runs (HTTPCost) are split
// at the last upper-case letter before a lower-case one. Works for both
// original-case and already lower-cased input (the latter simply yields
// underscore-separated tokens, which is enough for snake_case and the common
// getXxx prefix which we do not rely on).
func splitIdentifierTokens(name string) []string {
	runes := []rune(name)
	tokens := make([]string, 0, 4)
	var cur strings.Builder

	flush := func() {
		if cur.Len() > 0 {
			tokens = append(tokens, cur.String())
			cur.Reset()
		}
	}

	for i, r := range runes {
		if !unicode.IsLetter(r) {
			flush()
			continue
		}
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			nextLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			// lower→Upper boundary (gemCost) or end of acronym run (HTTPCost).
			if unicode.IsLower(prev) || (unicode.IsUpper(prev) && nextLower) {
				flush()
			}
		}
		cur.WriteRune(unicode.ToLower(r))
	}
	flush()
	return tokens
}