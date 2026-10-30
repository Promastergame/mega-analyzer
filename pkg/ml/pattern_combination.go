package ml

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN COMBINATION DETECTION (Task 16)
// Requirements: 18.1-18.4
// ═══════════════════════════════════════════════════════════════════════════════

// PatternCombination represents a detected combination of related patterns
type PatternCombination struct {
	Patterns        []string        `json:"patterns"`         // Pattern IDs
	Categories      []PatchCategory `json:"categories"`       // Pattern categories
	CombinationType string          `json:"combination_type"` // e.g., "license+signature", "premium+server"
	ScoreBoost      float64         `json:"score_boost"`      // 15-25% boost
	Explanation     string          `json:"explanation"`      // Why this combination is significant
}

// Common pattern combinations that indicate multi-layered security
var KnownCombinations = []struct {
	Categories  []PatchCategory
	Type        string
	Boost       float64
	Explanation string
}{
	{
		Categories:  []PatchCategory{PatchCatLicense, PatchCatSignature},
		Type:        "license+signature",
		Boost:       0.25, // 25% boost
		Explanation: "Multi-layer protection: license check with signature verification",
	},
	{
		Categories:  []PatchCategory{PatchCatPremium, PatchCatBilling},
		Type:        "premium+billing",
		Boost:       0.20, // 20% boost
		Explanation: "Multi-layer protection: premium status with billing verification",
	},
	{
		Categories:  []PatchCategory{PatchCatSubscription, PatchCatBilling},
		Type:        "subscription+billing",
		Boost:       0.20, // 20% boost
		Explanation: "Multi-layer protection: subscription with billing verification",
	},
	{
		Categories:  []PatchCategory{PatchCatRootDetect, PatchCatEmulatorCheck},
		Type:        "root+emulator",
		Boost:       0.18, // 18% boost
		Explanation: "Multi-layer detection: root and emulator checks combined",
	},
	{
		Categories:  []PatchCategory{PatchCatRootDetect, PatchCatHookDetect},
		Type:        "root+hook",
		Boost:       0.18, // 18% boost
		Explanation: "Multi-layer detection: root and hooking framework checks",
	},
	{
		Categories:  []PatchCategory{PatchCatTamper, PatchCatSignature},
		Type:        "tamper+signature",
		Boost:       0.22, // 22% boost
		Explanation: "Multi-layer integrity: tamper detection with signature verification",
	},
	{
		Categories:  []PatchCategory{PatchCatTamper, PatchCatIntegrity},
		Type:        "tamper+integrity",
		Boost:       0.20, // 20% boost
		Explanation: "Multi-layer integrity: tamper and integrity checks combined",
	},
	{
		Categories:  []PatchCategory{PatchCatDebugDetect, PatchCatHookDetect},
		Type:        "debug+hook",
		Boost:       0.17, // 17% boost
		Explanation: "Multi-layer detection: debug and hooking checks combined",
	},
	{
		Categories:  []PatchCategory{PatchCatPremium, PatchCatTrialExpiry},
		Type:        "premium+trial",
		Boost:       0.18, // 18% boost
		Explanation: "Multi-layer access control: premium status with trial expiry",
	},
	{
		Categories:  []PatchCategory{PatchCatFeatureGate, PatchCatPremium},
		Type:        "feature+premium",
		Boost:       0.15, // 15% boost
		Explanation: "Multi-layer access control: feature gate with premium check",
	},
}

// DetectPatternCombinations detects pattern combinations in a class
func DetectPatternCombinations(classInfo *ClassInfo, scoredMethods []ScoredMethod) []PatternCombination {
	combinations := []PatternCombination{}

	// Group patterns by category
	categoryPatterns := make(map[PatchCategory][]string)

	for _, sm := range scoredMethods {
		if sm.Score.BestPattern != nil {
			category := sm.Score.BestPattern.Category
			patternID := sm.Score.BestPattern.ID
			categoryPatterns[category] = append(categoryPatterns[category], patternID)
		}
	}

	// Check for known combinations
	for _, combo := range KnownCombinations {
		if hasAllCategories(categoryPatterns, combo.Categories) {
			// Collect pattern IDs for this combination
			patterns := []string{}
			for _, cat := range combo.Categories {
				patterns = append(patterns, categoryPatterns[cat]...)
			}

			combination := PatternCombination{
				Patterns:        patterns,
				Categories:      combo.Categories,
				CombinationType: combo.Type,
				ScoreBoost:      combo.Boost,
				Explanation:     combo.Explanation,
			}

			combinations = append(combinations, combination)
		}
	}

	// Check for same-category combinations (multiple patterns in same category)
	for category, patterns := range categoryPatterns {
		if len(patterns) >= 2 {
			// Multiple patterns in same category indicates thorough checking
			combination := PatternCombination{
				Patterns:        patterns,
				Categories:      []PatchCategory{category},
				CombinationType: fmt.Sprintf("multiple_%s", category),
				ScoreBoost:      0.15, // 15% boost for redundant checks
				Explanation:     fmt.Sprintf("Multiple %s patterns detected (redundant security checks)", getCategoryName(category)),
			}

			combinations = append(combinations, combination)
		}
	}

	return combinations
}

// hasAllCategories checks if all required categories are present
func hasAllCategories(categoryPatterns map[PatchCategory][]string, required []PatchCategory) bool {
	for _, cat := range required {
		if _, exists := categoryPatterns[cat]; !exists {
			return false
		}
	}
	return true
}

// getCategoryName returns a human-readable category name
func getCategoryName(category PatchCategory) string {
	if info, ok := AllCategories[category]; ok {
		return strings.ToLower(info.Name)
	}
	return string(category)
}

// ApplyPatternCombinationBoost applies score boost for detected combinations
func ApplyPatternCombinationBoost(scoredMethods []ScoredMethod, combinations []PatternCombination) []ScoredMethod {
	if len(combinations) == 0 {
		return scoredMethods
	}

	// Build a map of pattern IDs that are part of combinations
	combinationPatterns := make(map[string]float64) // pattern ID -> max boost

	for _, combo := range combinations {
		for _, patternID := range combo.Patterns {
			if existing, ok := combinationPatterns[patternID]; !ok || combo.ScoreBoost > existing {
				combinationPatterns[patternID] = combo.ScoreBoost
			}
		}
	}

	// Apply boost to scored methods
	for i := range scoredMethods {
		sm := &scoredMethods[i]
		if sm.Score.BestPattern != nil {
			if boost, ok := combinationPatterns[sm.Score.BestPattern.ID]; ok {
				// Calculate boost amount
				boostAmount := sm.Score.FinalScore * boost

				// Apply boost
				sm.Score.FinalScore += boostAmount

				// Add explanation
				sm.Score.Reasons = append(sm.Score.Reasons,
					fmt.Sprintf("Pattern combination boost: +%.1f%% (+%.1f points)",
						boost*100, boostAmount))

				// Update risk level if needed
				if sm.Score.FinalScore >= HighRiskThreshold && sm.Score.RiskLevel != RiskClassHigh {
					sm.Score.RiskLevel = RiskClassHigh
				} else if sm.Score.FinalScore >= MediumRiskThreshold && sm.Score.RiskLevel == RiskClassLow {
					sm.Score.RiskLevel = RiskClassMedium
				}
			}
		}
	}

	return scoredMethods
}

// FormatPatternCombinations creates a human-readable report of combinations
func FormatPatternCombinations(combinations []PatternCombination) string {
	if len(combinations) == 0 {
		return ""
	}

	var b strings.Builder

	b.WriteString("\n═══════════════════════════════════════════════════════════════════════════════\n")
	b.WriteString("PATTERN COMBINATIONS DETECTED\n")
	b.WriteString("═══════════════════════════════════════════════════════════════════════════════\n\n")

	for i, combo := range combinations {
		b.WriteString(fmt.Sprintf("%d. %s\n", i+1, combo.CombinationType))
		b.WriteString(fmt.Sprintf("   Patterns: %s\n", strings.Join(combo.Patterns, ", ")))
		b.WriteString(fmt.Sprintf("   Score Boost: +%.0f%%\n", combo.ScoreBoost*100))
		b.WriteString(fmt.Sprintf("   Explanation: %s\n\n", combo.Explanation))
	}

	return b.String()
}
