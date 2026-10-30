package ml

import (
	"fmt"
	"math"
	"strings"
)

func (ps *PatchScorer) scoreEconomyEvidence(mi *MethodInfo, result *ScoreResult) {
	info := economyForMethod(mi)
	if !isEconomyCandidate(info) { return }
	result.PatchCategory = PatchCatCurrency
	if category, ok := GetCategoryInfo(PatchCatCurrency); ok { result.CategoryWeight = category.Weight }
	score := 48.0
	if info.ValueLinked { score += 16 }
	if info.Storage == "preferences" || info.Storage == "json" || info.Storage == "sqlite" { score += 4 }
	result.BaseScore = math.Max(result.BaseScore, score)
	result.Reasons = append(result.Reasons, fmt.Sprintf("Resource %s: %s (%s); source of authority: %s", strings.Join(info.Resources, ", "), info.Operation, info.Storage, info.Authority))
	for _, evidence := range info.Evidence { result.MatchedParts = append(result.MatchedParts, "economy:"+evidence.Kind+":"+evidence.Reference) }
	if mi.IsSynthetic || mi.IsAccessor {
		// Compiler-generated forwarders are discovery context, not rewrite
		// targets: patch the real getter the accessor delegates to.
		result.SuggestedPatch = ""
		return
	}
	if info.Authority == "server_related" {
		// A server-side copy is audit evidence, never a rewrite target.
		result.SuggestedPatch = ""
		return
	}
	if !info.ValueResolved {
		// The resource is only named (method/class), the value source is
		// unknown: admit for audit, do not suggest a rewrite yet.
		result.SuggestedPatch = ""
		return
	}
	switch info.Operation {
	case EconomyBalanceRead:
		result.SuggestedPatch = PatchReturnMaxInt
	case EconomyPrice:
		result.SuggestedPatch = PatchReturnZero
	case EconomyAfford:
		result.SuggestedPatch = PatchReturnTrue
	default:
		// Writers and validators need a transaction-specific request. Do not
		// silently replace an entire purchase/reward with return-void/true.
		result.SuggestedPatch = ""
	}
}

func onlyEconomySignals(vs *VulnerabilitySignals) bool {
	if !vs.HasAny() { return false }
	for _, signal := range vs.Signals { if signal.Kind != VulnClientSideCurrency { return false } }
	return true
}

func economyNeedsTransactionReview(info *EconomyInfo) bool {
	if !isEconomyCandidate(info) { return false }
	if info.Authority == "server_related" { return true }
	if !info.ValueResolved { return true }
	return info.Operation != EconomyBalanceRead && info.Operation != EconomyPrice && info.Operation != EconomyAfford
}

func economyPatternBonus(matches []PatternMatch) float64 {
	// Several patterns fed by the same API/name do not constitute independent
	// evidence. Reward only new semantic evidence, never repeated return/shape.
	seen := make(map[string]bool)
	additional := 0
	for i, match := range matches {
		for _, part := range match.MatchedParts {
			if strings.HasPrefix(part, "return_type:") || strings.HasPrefix(part, "structure:") { continue }
			if !seen[part] { seen[part] = true; if i > 0 { additional++ } }
		}
	}
	return math.Min(float64(additional)*2, 8)
}
