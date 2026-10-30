package ml

import (
	"strings"

	"mega-analyzer/pkg/ml/internal/shared"
)

func currencyPattern(p *VulnerablePattern) bool {
	return p != nil && (p.Category == PatchCatCurrency || strings.Contains(p.ID, "CURRENCY") || p.ID == "ENERGY_LIVES_SYSTEM")
}

// Last definition wins scalar settings; built-in aliases are merged so an
// extension does not silently discard working names from the core catalog.
func canonicalPatterns(patterns []VulnerablePattern) []VulnerablePattern {
	out := make([]VulnerablePattern, 0, len(patterns))
	byID := make(map[string]int, len(patterns))
	merge := func(a, b []string) []string {
		result := append([]string(nil), a...)
		for _, value := range b { found := false; for _, old := range result { if strings.EqualFold(old, value) { found = true; break } }; if !found { result = append(result, value) } }
		return result
	}
	for _, p := range patterns {
		if currencyPattern(&p) { p.Category = PatchCatCurrency }
		if p.ID == "ITEM_PRICE_GETTER" { p.PatchType = PatchReturnZero }
		if index, exists := byID[p.ID]; exists && p.ID != "" {
			old := out[index]
			p.MethodNames = merge(old.MethodNames, p.MethodNames)
			p.ClassPatterns = merge(old.ClassPatterns, p.ClassPatterns)
			p.RequiredCalls = merge(old.RequiredCalls, p.RequiredCalls)
			p.StringPatterns = merge(old.StringPatterns, p.StringPatterns)
			out[index] = p
		} else { byID[p.ID] = len(out); out = append(out, p) }
	}
	return out
}
func patternReturnCompatible(pattern *VulnerablePattern, rt string) bool {
	if pattern.ReturnType == "" || pattern.ReturnType == rt { return true }
	return currencyPattern(pattern) && pattern.ReturnType == "I" && isEconomyNumber(rt) && (pattern.PatchType == PatchReturnMaxInt || pattern.PatchType == PatchReturnZero)
}

// maxRefusesEconomy keeps MAX strategies off prices and display values. A price
// forced to MAX_INT becomes unaffordable instead of free; a UI frame is not an
// amount at all. When flow analysis already classified the operation, trust it;
// otherwise fall back to the price-name tokens (they carry stop-token logic for
// IDs, sizes and comparators).
func maxRefusesEconomy(mi *shared.MethodInfo) bool {
	if mi == nil { return true }
	if mi.Economy != nil {
		switch mi.Economy.Operation {
		case EconomyPrice, EconomyDisplay:
			return true
		}
		return false
	}
	return isPriceGetterName(mi.NameLower)
}

func economyPatternFits(mi *MethodInfo, pattern *VulnerablePattern) bool {
	if !currencyPattern(pattern) { return true }
	info := economyForMethod(mi)
	if info == nil { return false }
	if !isEconomyCandidate(info) { return false }
	switch pattern.PatchType {
	case PatchReturnMaxInt:
		return info.Operation == EconomyBalanceRead || (info.Operation == EconomyReward && isEconomyNumber(mi.ReturnType))
	case PatchReturnZero, PatchReturnFalse:
		return info.Operation == EconomyPrice
	case PatchReturnVoid:
		return info.Operation == EconomyBalanceWrite || info.Operation == EconomySpend || info.Operation == EconomyReward
	case PatchReturnTrue:
		return info.Operation == EconomyAfford || info.Operation == EconomyValidation
	}
	return true
}

func onlyGenericPatternCalls(parts []string) bool {
	any := false
	for _, part := range parts {
		if !strings.HasPrefix(part, "call:") { continue }
		any = true
		call := strings.ToLower(strings.TrimPrefix(part, "call:"))
		switch call {
		case "getint", "getlong", "getfloat", "getdouble", "getstring", "getboolean", "putint", "putlong", "putfloat", "putstring", "putboolean", "sharedpreferences", "getsharedpreferences", "edit", "apply", "commit", "equals", "hashmap;->get", "hashmap;->containskey", "list;->contains", "list;->size":
		default: return false
		}
	}
	return any
}
