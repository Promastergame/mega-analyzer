package ml

import (
	"fmt"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN PRIORITY SYSTEM (Task 17)
// Requirements: 22.1-22.4
// ═══════════════════════════════════════════════════════════════════════════════

// PatternPriority represents the priority level of a pattern
type PatternPriority string

const (
	PriorityCritical PatternPriority = "CRITICAL" // Billing, purchase, subscription
	PriorityHigh     PatternPriority = "HIGH"     // Premium, ads, license
	PriorityMedium   PatternPriority = "MEDIUM"   // Detection (root, emulator, debug)
	PriorityLow      PatternPriority = "LOW"      // Utility, installer, logging
)

// GetPatternPriority returns the priority level for a pattern category
func GetPatternPriority(category PatchCategory) PatternPriority {
	switch category {
	// Critical: Billing and purchase-related
	case PatchCatBilling, PatchCatSubscription:
		return PriorityCritical

	// High: Premium features, ads, license
	case PatchCatPremium, PatchCatAds, PatchCatLicense, PatchCatTrialExpiry:
		return PriorityHigh

	// Medium: Detection and security checks
	case PatchCatRootDetect, PatchCatEmulatorCheck, PatchCatDebugDetect,
		PatchCatTamper, PatchCatSignature, PatchCatIntegrity,
		PatchCatHookDetect, PatchCatSSLPinning:
		return PriorityMedium

	// Low: Utility and less critical checks
	case PatchCatFeatureGate, PatchCatInstaller:
		return PriorityLow

	default:
		return PriorityMedium
	}
}

// GetPriorityScore returns a numeric score for sorting (higher = more important)
func GetPriorityScore(priority PatternPriority) int {
	switch priority {
	case PriorityCritical:
		return 4
	case PriorityHigh:
		return 3
	case PriorityMedium:
		return 2
	case PriorityLow:
		return 1
	default:
		return 0
	}
}

// SortByPriority sorts scored methods by priority first, then by risk score
func SortByPriority(scoredMethods []ScoredMethod) []ScoredMethod {
	sort.Slice(scoredMethods, func(i, j int) bool {
		// Get priorities
		priI := PriorityMedium
		priJ := PriorityMedium

		if scoredMethods[i].Score.BestPattern != nil {
			priI = GetPatternPriority(scoredMethods[i].Score.BestPattern.Category)
		}
		if scoredMethods[j].Score.BestPattern != nil {
			priJ = GetPatternPriority(scoredMethods[j].Score.BestPattern.Category)
		}

		// Sort by priority first
		scoreI := GetPriorityScore(priI)
		scoreJ := GetPriorityScore(priJ)

		if scoreI != scoreJ {
			return scoreI > scoreJ
		}

		// If same priority, sort by risk score
		if scoredMethods[i].Score.FinalScore != scoredMethods[j].Score.FinalScore {
			return scoredMethods[i].Score.FinalScore > scoredMethods[j].Score.FinalScore
		}

		// If same score, prefer app code over library code
		if scoredMethods[i].Method.IsAppCode != scoredMethods[j].Method.IsAppCode {
			return scoredMethods[i].Method.IsAppCode
		}

		// If same app code status, prefer higher confidence
		return scoredMethods[i].Score.Confidence > scoredMethods[j].Score.Confidence
	})

	return scoredMethods
}

// GroupByPriority groups scored methods by priority level
func GroupByPriority(scoredMethods []ScoredMethod) map[PatternPriority][]ScoredMethod {
	groups := make(map[PatternPriority][]ScoredMethod)

	// Initialize groups
	groups[PriorityCritical] = []ScoredMethod{}
	groups[PriorityHigh] = []ScoredMethod{}
	groups[PriorityMedium] = []ScoredMethod{}
	groups[PriorityLow] = []ScoredMethod{}

	// Group methods
	for _, sm := range scoredMethods {
		priority := PriorityMedium
		if sm.Score.BestPattern != nil {
			priority = GetPatternPriority(sm.Score.BestPattern.Category)
		}
		groups[priority] = append(groups[priority], sm)
	}

	return groups
}

// FormatByPriority creates a human-readable report grouped by priority
func FormatByPriority(scoredMethods []ScoredMethod) string {
	if len(scoredMethods) == 0 {
		return "No patch points detected.\n"
	}

	// Sort by priority
	sorted := SortByPriority(scoredMethods)

	// Group by priority
	groups := GroupByPriority(sorted)

	var b strings.Builder

	b.WriteString("═══════════════════════════════════════════════════════════════════════════════\n")
	b.WriteString("PATCH POINTS BY PRIORITY\n")
	b.WriteString("═══════════════════════════════════════════════════════════════════════════════\n\n")

	// Format each priority group
	priorities := []PatternPriority{PriorityCritical, PriorityHigh, PriorityMedium, PriorityLow}

	for _, priority := range priorities {
		methods := groups[priority]
		if len(methods) == 0 {
			continue
		}

		// Priority header
		emoji := getPriorityEmoji(priority)
		b.WriteString(fmt.Sprintf("%s %s PRIORITY (%d methods)\n", emoji, priority, len(methods)))
		b.WriteString(strings.Repeat("─", 79))
		b.WriteString("\n\n")

		// List methods
		for i, sm := range methods {
			if i >= 10 {
				b.WriteString(fmt.Sprintf("   ... and %d more\n\n", len(methods)-10))
				break
			}

			b.WriteString(fmt.Sprintf("%d. Score: %.1f%% (%s) | Confidence: %.2f\n",
				i+1, sm.Score.FinalScore, sm.Score.RiskLevel, sm.Score.Confidence))
			b.WriteString(fmt.Sprintf("   Method: %s\n", MethodSignatureShort(&sm.Method)))
			b.WriteString(fmt.Sprintf("   Class: %s\n", ShortClassName(sm.Method.ClassName)))

			if sm.Score.BestPattern != nil {
				b.WriteString(fmt.Sprintf("   Pattern: %s\n", sm.Score.BestPattern.ID))
			}

			b.WriteString("\n")
		}

		b.WriteString("\n")
	}

	return b.String()
}

// getPriorityEmoji returns an emoji for the priority level
func getPriorityEmoji(priority PatternPriority) string {
	switch priority {
	case PriorityCritical:
		return "🔴"
	case PriorityHigh:
		return "🟠"
	case PriorityMedium:
		return "🟡"
	case PriorityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

// GetPriorityDescription returns a description of what the priority means
func GetPriorityDescription(priority PatternPriority) string {
	switch priority {
	case PriorityCritical:
		return "Critical revenue-impacting patterns (billing, purchases, subscriptions)"
	case PriorityHigh:
		return "High-value patterns (premium features, ads, license checks)"
	case PriorityMedium:
		return "Security and detection patterns (root, emulator, debug, tamper)"
	case PriorityLow:
		return "Utility and less critical patterns (feature gates, installer checks)"
	default:
		return "Unknown priority"
	}
}

// FilterByPriority filters scored methods to only include specified priorities
func FilterByPriority(scoredMethods []ScoredMethod, priorities ...PatternPriority) []ScoredMethod {
	if len(priorities) == 0 {
		return scoredMethods
	}

	// Build priority set
	prioritySet := make(map[PatternPriority]bool)
	for _, p := range priorities {
		prioritySet[p] = true
	}

	// Filter methods
	filtered := []ScoredMethod{}
	for _, sm := range scoredMethods {
		priority := PriorityMedium
		if sm.Score.BestPattern != nil {
			priority = GetPatternPriority(sm.Score.BestPattern.Category)
		}

		if prioritySet[priority] {
			filtered = append(filtered, sm)
		}
	}

	return filtered
}

// GetPriorityStats returns statistics about priority distribution
func GetPriorityStats(scoredMethods []ScoredMethod) map[PatternPriority]int {
	stats := make(map[PatternPriority]int)

	for _, sm := range scoredMethods {
		priority := PriorityMedium
		if sm.Score.BestPattern != nil {
			priority = GetPatternPriority(sm.Score.BestPattern.Category)
		}
		stats[priority]++
	}

	return stats
}
