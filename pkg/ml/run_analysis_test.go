package ml

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRunFullAnalysis runs the complete pattern effectiveness analysis (Task 2)
// This test generates the effectiveness report for all 32 patterns
func TestRunFullAnalysis(t *testing.T) {
	// Skip in short mode
	if testing.Short() {
		t.Skip("Skipping full analysis in short mode")
	}

	outputPath := filepath.Join(testTempDir(t), "pattern_effectiveness_report.txt")

	err := RunEffectivenessAnalysis(outputPath)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	// Verify report was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("Report file was not created")
	}

	t.Logf("Analysis complete. Report saved to: %s", outputPath)
}

// TestListPatterns tests the pattern listing functionality
func TestListPatterns(t *testing.T) {
	// This just verifies the function doesn't panic
	ListAllPatterns()
}

// TestComparePatternTiers tests the tier comparison functionality
func TestComparePatternTiers(t *testing.T) {
	// This just verifies the function doesn't panic
	ComparePatternTiers()
}

// TestAnalyzeSpecificPattern tests analyzing a specific pattern
func TestAnalyzeSpecificPattern(t *testing.T) {
	effectiveness, err := AnalyzePatternByID("LICENSE_BOOL_CHECK")
	if err != nil {
		t.Fatalf("Failed to analyze pattern: %v", err)
	}

	if effectiveness.PatternID != "LICENSE_BOOL_CHECK" {
		t.Errorf("Wrong pattern ID: %s", effectiveness.PatternID)
	}

	if effectiveness.Tier == "" {
		t.Error("Tier not set")
	}

	t.Logf("Pattern: %s, Tier: %s, Success: %.1f%%",
		effectiveness.PatternID, effectiveness.Tier, effectiveness.TruePositiveRate*100)
}
