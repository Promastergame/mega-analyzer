package fpfilter

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// VerdictRefiner performs cross-finding correlation to refine verdicts.
type VerdictRefiner struct{}

func NewVerdictRefiner() *VerdictRefiner {
	return &VerdictRefiner{}
}

// Refine takes all classified findings and refines their verdicts based on context.
func (r *VerdictRefiner) Refine(findings []types.ClassifiedFinding) []types.ClassifiedFinding {
	// 1. Duplicate detection: Identical patterns in same file logic
	refined := r.deduplicate(findings)

	// 2. Cross-finding correlation
	hasAppRisks := false
	for _, cf := range refined {
		if cf.Verdict == types.VerdictConfirmedAppRisk {
			hasAppRisks = true
			break
		}
	}

	// If there are confirmed app risks, maybe upgrade some SDK noise that might be related
	if hasAppRisks {
		for i, cf := range refined {
			if cf.Verdict == types.VerdictSDKNoiseSuppressed && cf.SDKInfo != nil {
				// E.g. if SDK has file operations and App has file operations, upgrade SDK to interesting
				// For now, a simplified approach
				if isCorrelatableCategory(cf.Original.Category) {
					refined[i].Verdict = types.VerdictSDKInteresting
					refined[i].SuppressionReason = "Upgraded: Potentially correlates with app risk"
				}
			}
		}
	}

	// 3. Behavior Chains — upgrade only meaningful multi-signal chains
	refined = r.upgradeBehaviorChains(refined)

	return refined
}

func (r *VerdictRefiner) upgradeBehaviorChains(findings []types.ClassifiedFinding) []types.ClassifiedFinding {
	needsContext := make([]int, 0, len(findings))
	hasAppRisk := false
	hasStrongInChain := false
	securityCategories := make(map[string]struct{})

	for i, cf := range findings {
		if cf.Verdict == types.VerdictConfirmedAppRisk {
			hasAppRisk = true
		}
		if cf.Verdict != types.VerdictNeedsContext {
			continue
		}
		needsContext = append(needsContext, i)
		if len(cf.StrongSignals) > 0 {
			hasStrongInChain = true
		}
		if cf.Original != nil && isSecurityChainCategory(cf.Original.Category) {
			securityCategories[string(cf.Original.Category)] = struct{}{}
		}
		if cf.Verdict == types.VerdictNeedsContext && cf.SDKInfo == nil && cf.Original != nil && isAppCodePath(cf.Original.File) {
			hasAppRisk = true
		}
	}

	if len(needsContext) < 3 {
		return findings
	}

	// Require corroboration: app code involvement, a strong signal, or 2+ security categories.
	if !hasAppRisk && !hasStrongInChain && len(securityCategories) < 2 {
		return findings
	}

	for _, i := range needsContext {
		findings[i].Verdict = types.VerdictConfirmedAppRisk
		findings[i].SuppressionReason = "Upgraded: Correlated suspicious behavior chain"
	}
	return findings
}

func isAppCodePath(file string) bool {
	if file == "" {
		return false
	}
	lower := strings.ToLower(file)
	sdkHints := []string{
		"/com/google/", "/androidx/", "/kotlin/", "/okhttp",
		"/firebase/", "/facebook/", "/unity3d/", "/applovin/",
	}
	for _, hint := range sdkHints {
		if strings.Contains(lower, hint) {
			return false
		}
	}
	return strings.Contains(lower, "smali/")
}

func isSecurityChainCategory(c types.Category) bool {
	switch c {
	case types.CategoryPremiumCheck, types.CategoryPurchaseVerify, types.CategoryBillingClient,
		types.CategorySubscription, types.CategoryLicenseCheck, types.CategoryRootDetection,
		types.CategoryTamperDetection, types.CategoryIntegrityCheck, types.CategorySignatureCheck,
		types.CategoryPlayIntegrity, types.CategorySafetyNet, types.CategorySSLPinning,
		types.CategoryAntiHook, types.CategoryAntiXposed, types.CategoryStealerIndicator,
		types.CategoryBankingThreat, types.CategoryMalwareCombo,
		types.CategoryDynamicLoad, types.CategoryWebViewRemoteJS:
		return true
	default:
		return false
	}
}

func (r *VerdictRefiner) deduplicate(findings []types.ClassifiedFinding) []types.ClassifiedFinding {
	seen := make(map[string]int) // hash -> index
	var result []types.ClassifiedFinding

	for _, cf := range findings {
		if cf.Original == nil {
			result = append(result, cf)
			continue
		}

		// Deduplicate only exact same evidence in the same file/line.
		// The same vulnerable API pattern in two SDKs or two files is not noise:
		// libraries can carry real vulnerabilities, so file location is part of the key.
		hash := fmt.Sprintf("%s|%s|%s|%d", cf.Original.File, cf.Original.Category, cf.Original.Pattern, cf.Original.Line)

		if idx, exists := seen[hash]; exists {
			existing := result[idx]
			// Keep the one with higher score
			if cf.FinalScore > existing.FinalScore {
				// Mark existing as duplicate
				result[idx].Verdict = types.VerdictGenericNoiseSuppressed
				result[idx].ScoreBreakdown.DuplicatePatternScore -= 5.0
				result[idx].FinalScore -= 5.0
				result[idx].SuppressionReason = "Duplicate pattern"
				// Add new one
				seen[hash] = len(result)
				result = append(result, cf)
			} else {
				// Mark new as duplicate
				cf.Verdict = types.VerdictGenericNoiseSuppressed
				cf.ScoreBreakdown.DuplicatePatternScore -= 5.0
				cf.FinalScore -= 5.0
				cf.SuppressionReason = "Duplicate pattern"
				result = append(result, cf)
			}
		} else {
			seen[hash] = len(result)
			result = append(result, cf)
		}
	}

	return result
}

func isCorrelatableCategory(c types.Category) bool {
	switch c {
	case "FILE_ACCESS", "NETWORK_CLEARTEXT", "DYNAMIC_CODE_LOADING", "CRYPTO_WEAK":
		return true
	}
	return false
}
