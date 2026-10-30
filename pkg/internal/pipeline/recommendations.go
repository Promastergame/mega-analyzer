// pkg/internal/pipeline/recommendations.go
package pipeline

import "mega-analyzer/pkg/internal/types"

// generateRecommendations создаёт рекомендации на основе результатов.
func generateRecommendations(result *types.AnalysisResult) []types.Recommendation {
	recs := make([]types.Recommendation, 0, 8)

	// Собираем критические категории
	critCats := make(map[types.Category]int)
	for cat, count := range result.MatchesByCategory {
		if types.GetCategoryInfo(cat).IsCritical {
			critCats[cat] = count
		}
	}

	// Table-driven rules
	rules := []recRule{
		{
			cats:  []types.Category{types.CategoryGoogleLVL, types.CategoryLicenseCheck},
			prio:  types.PriorityCritical,
			title: "🔴 License Verification Review",
			desc:  "License verification logic detected",
			steps: []string{
				"1. Locate LicenseCheckerCallback implementations",
				"2. Trace dontAllow()/applicationError() paths",
				"3. Identify server-side validation",
				"4. Document decision points and gated features",
			},
		},
		{
			cats:  []types.Category{types.CategoryBillingClient, types.CategoryPurchaseVerify},
			prio:  types.PriorityCritical,
			title: "🔴 In-App Purchase Review",
			desc:  "Purchase verification logic detected",
			steps: []string{
				"1. Locate isPurchased() decision points",
				"2. Identify purchase token validation",
				"3. Trace server-side verification",
				"4. Map purchase-gated features",
			},
		},
		{
			cats:  []types.Category{types.CategoryPremiumCheck, types.CategoryPremiumUnlock},
			prio:  types.PriorityHigh,
			title: "🟠 Premium/Pro Review",
			desc:  "Premium status checks detected",
			steps: []string{
				"1. Locate isPremium()/isPro() checks",
				"2. Identify SharedPreferences/DB keys",
				"3. Map premium-gated UI/features",
			},
		},
		{
			cats:  []types.Category{types.CategorySubscription},
			prio:  types.PriorityHigh,
			title: "🟠 Subscription Review",
			desc:  "Subscription verification detected",
			steps: []string{
				"1. Locate isSubscribed() decision points",
				"2. Review expiry date handling",
				"3. Trace server-side validation",
			},
		},
		{
			cats:  []types.Category{types.CategoryAdRemove, types.CategoryAdShow},
			prio:  types.PriorityHigh,
			title: "🟠 Advertisement Review",
			desc:  "Ad logic detected",
			steps: []string{
				"1. Identify ad initialization paths",
				"2. List ad network SDKs",
				"3. Map ad-free conditions",
			},
		},
		{
			cats:  []types.Category{types.CategorySignatureCheck, types.CategoryTamperDetection, types.CategoryIntegrityCheck},
			prio:  types.PriorityCritical,
			title: "🔴 Security Checks Review",
			desc:  "Anti-tampering/integrity checks detected",
			steps: []string{
				"1. Identify signature/integrity check entry points",
				"2. Trace SafetyNet/Play Integrity usage",
				"3. Review tamper/root/debug detection",
				"4. Document enforcement points",
			},
		},
	}

	for _, rule := range rules {
		if rule.matches(critCats) {
			files := filesForCategories(result, rule.cats...)
			recs = append(recs, types.Recommendation{
				Priority:    rule.prio,
				Title:       rule.title,
				Description: rule.desc,
				Steps:       rule.steps,
				Files:       files,
			})
		}
	}

	// Always-present general recommendation
	recs = append(recs, types.Recommendation{
		Priority:    types.PriorityInfo,
		Title:       "📋 Review Order",
		Description: "Recommended analysis sequence",
		Steps: []string{
			"1. Security checks (signature, root, tamper)",
			"2. License verification",
			"3. Purchase verification",
			"4. Subscription checks",
			"5. Premium/Pro flags",
			"6. Trial/expiry checks",
			"7. Ad logic and monetization",
		},
	})

	return recs
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

type recRule struct {
	cats  []types.Category
	prio  types.Priority
	title string
	desc  string
	steps []string
}

func (r recRule) matches(critCats map[types.Category]int) bool {
	for _, cat := range r.cats {
		if critCats[cat] > 0 {
			return true
		}
	}
	return false
}

func filesForCategories(result *types.AnalysisResult, cats ...types.Category) []string {
	files := make([]string, 0, 10)
	seen := make(map[string]struct{})

	catSet := make(map[types.Category]struct{}, len(cats))
	for _, c := range cats {
		catSet[c] = struct{}{}
	}

	for path, analysis := range result.Files {
		if !analysis.IsAppCode {
			continue
		}
		for _, match := range analysis.Matches {
			if _, ok := catSet[match.Category]; ok {
				if _, exists := seen[path]; !exists {
					files = append(files, path)
					seen[path] = struct{}{}
				}
				break
			}
		}
		if len(files) >= 10 {
			break
		}
	}

	return files
}
