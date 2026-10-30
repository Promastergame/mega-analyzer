package ml

import (
	"fmt"
	"os"
	"path/filepath"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CLI COMMANDS FOR PATTERN EFFECTIVENESS ANALYSIS — Task 2
// ═══════════════════════════════════════════════════════════════════════════════

// RunEffectivenessAnalysis runs the full effectiveness analysis and generates report
// This implements Task 2: Analyze existing 32 patterns and classify by effectiveness
func RunEffectivenessAnalysis(outputPath string, stores ...FeedbackStore) error {
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")
	fmt.Println("PATTERN EFFECTIVENESS ANALYSIS")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")
	fmt.Println()

	// Create analyzer
	analyzer := NewPatternEffectivenessAnalyzer(stores...)

	// Step 1: Analyze all patterns (Requirements 1.1)
	fmt.Printf("Step 1: Analyzing %d patterns...\n", len(VulnerablePatterns))
	allEffectiveness := analyzer.AnalyzeAll()
	fmt.Printf("✓ Analyzed %d patterns\n\n", len(allEffectiveness))

	// Step 2: Generate report (Requirements 1.4)
	fmt.Println("Step 2: Generating effectiveness report...")
	report := analyzer.GenerateReport()
	fmt.Printf("✓ Report generated\n\n")

	// Step 3: Display summary
	fmt.Println("SUMMARY:")
	fmt.Printf("  Total Patterns: %d\n", report.TotalPatterns)
	fmt.Printf("  Unknown / insufficient observations: %d\n", report.UnknownCount)
	fmt.Printf("  IMBA:            %d patterns (%.1f%%)\n", report.IMBACount, float64(report.IMBACount)/float64(report.TotalPatterns)*100)
	fmt.Printf("  NORMAL:         %d patterns (%.1f%%)\n", report.NormalCount, float64(report.NormalCount)/float64(report.TotalPatterns)*100)
	fmt.Printf("  TRASH:           %d patterns (%.1f%%)\n\n", report.TrashCount, float64(report.TrashCount)/float64(report.TotalPatterns)*100)

	// Step 4: Identify trash patterns for removal (Requirements 16.1)
	fmt.Println("Step 3: Identifying patterns recommended for removal...")
	trashPatterns := analyzer.RecommendRemoval()
	fmt.Printf("✓ Found %d patterns recommended for removal\n\n", len(trashPatterns))

	if len(trashPatterns) > 0 {
		fmt.Println("PATTERNS RECOMMENDED FOR REMOVAL:")
		for i, pattern := range trashPatterns {
			effectiveness := allEffectiveness[pattern.ID]
			fmt.Printf("  %d. %s\n", i+1, pattern.ID)
			fmt.Printf("     Category: %s\n", pattern.Category)
			fmt.Printf("     Success Rate: %.1f%% | False Positive: %.1f%% | Crash: %.1f%%\n",
				effectiveness.TruePositiveRate*100, effectiveness.FalsePositiveRate*100, effectiveness.CrashRate*100)
			fmt.Printf("     Reason: %s\n\n", effectiveness.TierReason)
		}
	}

	// Step 5: Format and save full report
	fmt.Println("Step 4: Generating detailed report...")
	formattedReport := FormatReport(report)

	// Save to file if output path provided
	if outputPath != "" {
		// Create directory if it doesn't exist
		dir := filepath.Dir(outputPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		if err := os.WriteFile(outputPath, []byte(formattedReport), 0644); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
		fmt.Printf("✓ Full report saved to: %s\n\n", outputPath)
	}

	// Display full report to console
	fmt.Println(formattedReport)

	return nil
}

// AnalyzePatternByID analyzes a specific pattern by ID
func AnalyzePatternByID(patternID string) (*PatternEffectiveness, error) {
	analyzer := NewPatternEffectivenessAnalyzer()

	// Find the pattern
	var targetPattern *VulnerablePattern
	for _, pattern := range analyzer.patterns {
		if pattern.ID == patternID {
			targetPattern = pattern
			break
		}
	}

	if targetPattern == nil {
		return nil, fmt.Errorf("pattern not found: %s", patternID)
	}

	// Analyze it
	effectiveness := analyzer.analyzePattern(targetPattern)
	return effectiveness, nil
}

// ListAllPatterns lists all patterns with their basic info
func ListAllPatterns() {
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")
	fmt.Println("ALL VULNERABILITY PATTERNS")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")
	fmt.Println()

	// Group by category
	categoryMap := make(map[PatchCategory][]*VulnerablePattern)
	for i := range VulnerablePatterns {
		pattern := &VulnerablePatterns[i]
		categoryMap[pattern.Category] = append(categoryMap[pattern.Category], pattern)
	}

	// Display by category
	for category, info := range AllCategories {
		patterns := categoryMap[category]
		if len(patterns) == 0 {
			continue
		}

		fmt.Printf("Category: %s (%s)\n", info.Name, category)
		fmt.Printf("Severity: %s | Weight: %.1f\n", info.Severity, info.Weight)
		fmt.Printf("Patterns: %d\n\n", len(patterns))

		for i, pattern := range patterns {
			fmt.Printf("  %d. %s\n", i+1, pattern.ID)
			fmt.Printf("     Description: %s\n", pattern.Description)
			fmt.Printf("     Method Names: %d | Required Calls: %d | String Patterns: %d\n",
				len(pattern.MethodNames), len(pattern.RequiredCalls), len(pattern.StringPatterns))
			fmt.Printf("     Return Type: %s | Patch Type: %s\n\n", pattern.ReturnType, pattern.PatchType)
		}
	}

	fmt.Printf("Total: %d patterns across %d categories\n", len(VulnerablePatterns), len(AllCategories))
}

// ComparePatternTiers compares patterns across tiers
func ComparePatternTiers() {
	analyzer := NewPatternEffectivenessAnalyzer()
	report := analyzer.GenerateReport()

	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")
	fmt.Println("PATTERN TIER COMPARISON")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")
	fmt.Println()

	// IMBA tier
	if len(report.IMBAPatterns) > 0 {
		fmt.Printf("🔥 IMBA TIER (%d patterns)\n", len(report.IMBAPatterns))
		fmt.Println("─────────────────────────────────────────────────────────────────────────────")
		avgTP := 0.0
		avgFP := 0.0
		for _, pe := range report.IMBAPatterns {
			avgTP += pe.TruePositiveRate
			avgFP += pe.FalsePositiveRate
		}
		avgTP /= float64(len(report.IMBAPatterns))
		avgFP /= float64(len(report.IMBAPatterns))
		fmt.Printf("Average Success Rate: %.1f%%\n", avgTP*100)
		fmt.Printf("Average False Positive: %.1f%%\n\n", avgFP*100)
	}

	// Normal tier
	if len(report.NormalPatterns) > 0 {
		fmt.Printf("✅ NORMAL TIER (%d patterns)\n", len(report.NormalPatterns))
		fmt.Println("─────────────────────────────────────────────────────────────────────────────")
		avgTP := 0.0
		avgFP := 0.0
		for _, pe := range report.NormalPatterns {
			avgTP += pe.TruePositiveRate
			avgFP += pe.FalsePositiveRate
		}
		avgTP /= float64(len(report.NormalPatterns))
		avgFP /= float64(len(report.NormalPatterns))
		fmt.Printf("Average Success Rate: %.1f%%\n", avgTP*100)
		fmt.Printf("Average False Positive: %.1f%%\n\n", avgFP*100)
	}

	// Trash tier
	if len(report.TrashPatterns) > 0 {
		fmt.Printf("🗑️  TRASH TIER (%d patterns)\n", len(report.TrashPatterns))
		fmt.Println("─────────────────────────────────────────────────────────────────────────────")
		avgTP := 0.0
		avgFP := 0.0
		for _, pe := range report.TrashPatterns {
			avgTP += pe.TruePositiveRate
			avgFP += pe.FalsePositiveRate
		}
		avgTP /= float64(len(report.TrashPatterns))
		avgFP /= float64(len(report.TrashPatterns))
		fmt.Printf("Average Success Rate: %.1f%%\n", avgTP*100)
		fmt.Printf("Average False Positive: %.1f%%\n\n", avgFP*100)
	}

	fmt.Println("═══════════════════════════════════════════════════════════════════════════════")
}
