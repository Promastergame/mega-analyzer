package ml

import (
	"strings"
	"testing"
)

func TestDetectPatternCombinations(t *testing.T) {
	// Create a mock class with multiple security patterns
	classInfo := &ClassInfo{
		ClassName: "Lcom/example/SecurityChecker;",
		FilePath:  "com/example/SecurityChecker.smali",
	}

	// Create scored methods with different patterns
	scoredMethods := []ScoredMethod{
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{
					ID:       "LICENSE_BOOL_CHECK",
					Category: PatchCatLicense,
				},
				FinalScore: 70.0,
			},
		},
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{
					ID:       "SIGNATURE_VERIFY",
					Category: PatchCatSignature,
				},
				FinalScore: 65.0,
			},
		},
	}

	// Detect combinations
	combinations := DetectPatternCombinations(classInfo, scoredMethods)

	// Should detect license+signature combination
	if len(combinations) == 0 {
		t.Fatal("Expected to detect pattern combinations")
	}

	found := false
	for _, combo := range combinations {
		if combo.CombinationType == "license+signature" {
			found = true
			if combo.ScoreBoost != 0.25 {
				t.Errorf("Expected 25%% boost, got %.0f%%", combo.ScoreBoost*100)
			}
			if len(combo.Patterns) != 2 {
				t.Errorf("Expected 2 patterns, got %d", len(combo.Patterns))
			}
		}
	}

	if !found {
		t.Error("Expected to find license+signature combination")
	}
}

func TestDetectPatternCombinations_SameCategory(t *testing.T) {
	classInfo := &ClassInfo{
		ClassName: "Lcom/example/RootChecker;",
		FilePath:  "com/example/RootChecker.smali",
	}

	// Multiple root detection patterns
	scoredMethods := []ScoredMethod{
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{
					ID:       "ROOT_DETECT",
					Category: PatchCatRootDetect,
				},
				FinalScore: 60.0,
			},
		},
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{
					ID:       "MAGISK_DETECT",
					Category: PatchCatRootDetect,
				},
				FinalScore: 55.0,
			},
		},
	}

	combinations := DetectPatternCombinations(classInfo, scoredMethods)

	// Should detect multiple root detection patterns
	found := false
	for _, combo := range combinations {
		if combo.CombinationType == "multiple_root_detection" {
			found = true
			if combo.ScoreBoost != 0.15 {
				t.Errorf("Expected 15%% boost, got %.0f%%", combo.ScoreBoost*100)
			}
		}
	}

	if !found {
		t.Error("Expected to find multiple root detection combination")
	}
}

func TestApplyPatternCombinationBoost(t *testing.T) {
	scoredMethods := []ScoredMethod{
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{
					ID:       "LICENSE_BOOL_CHECK",
					Category: PatchCatLicense,
				},
				FinalScore: 60.0,
				RiskLevel:  RiskClassMedium,
				Reasons:    []string{"Matches license pattern"},
			},
		},
	}

	combinations := []PatternCombination{
		{
			Patterns:        []string{"LICENSE_BOOL_CHECK"},
			CombinationType: "license+signature",
			ScoreBoost:      0.25, // 25% boost
			Explanation:     "Multi-layer protection",
		},
	}

	// Apply boost
	boosted := ApplyPatternCombinationBoost(scoredMethods, combinations)

	// Check that score was boosted
	expectedScore := 60.0 * 1.25 // 75.0
	if boosted[0].Score.FinalScore != expectedScore {
		t.Errorf("Expected score %.1f, got %.1f", expectedScore, boosted[0].Score.FinalScore)
	}

	// Check that risk level was updated
	if boosted[0].Score.RiskLevel != RiskClassHigh {
		t.Errorf("Expected HIGH risk level, got %s", boosted[0].Score.RiskLevel)
	}

	// Check that reason was added
	foundReason := false
	for _, reason := range boosted[0].Score.Reasons {
		if strings.Contains(reason, "Pattern combination") || strings.Contains(reason, "combination boost") {
			foundReason = true
			break
		}
	}
	if !foundReason {
		t.Error("Expected combination boost reason to be added")
	}
}

func TestFormatPatternCombinations(t *testing.T) {
	combinations := []PatternCombination{
		{
			Patterns:        []string{"LICENSE_BOOL_CHECK", "SIGNATURE_VERIFY"},
			CombinationType: "license+signature",
			ScoreBoost:      0.25,
			Explanation:     "Multi-layer protection: license check with signature verification",
		},
	}

	output := FormatPatternCombinations(combinations)

	if output == "" {
		t.Error("Expected non-empty output")
	}

	// Check that output contains key information
	if !strings.Contains(output, "license+signature") {
		t.Error("Output should contain combination type")
	}
	if !strings.Contains(output, "25%") {
		t.Error("Output should contain boost percentage")
	}
}

func TestDetectPatternCombinations_NoCombinations(t *testing.T) {
	classInfo := &ClassInfo{
		ClassName: "Lcom/example/SimpleChecker;",
		FilePath:  "com/example/SimpleChecker.smali",
	}

	// Single pattern, no combinations
	scoredMethods := []ScoredMethod{
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{
					ID:       "LICENSE_BOOL_CHECK",
					Category: PatchCatLicense,
				},
				FinalScore: 60.0,
			},
		},
	}

	combinations := DetectPatternCombinations(classInfo, scoredMethods)

	// Should not detect any combinations (single pattern)
	if len(combinations) != 0 {
		t.Errorf("Expected no combinations, got %d", len(combinations))
	}
}

func TestKnownCombinations_Coverage(t *testing.T) {
	// Verify that all known combinations have valid data
	for i, combo := range KnownCombinations {
		if len(combo.Categories) < 2 {
			t.Errorf("Combination %d should have at least 2 categories", i)
		}
		if combo.Type == "" {
			t.Errorf("Combination %d missing type", i)
		}
		if combo.Boost < 0.15 || combo.Boost > 0.25 {
			t.Errorf("Combination %d boost %.2f outside expected range [0.15, 0.25]", i, combo.Boost)
		}
		if combo.Explanation == "" {
			t.Errorf("Combination %d missing explanation", i)
		}
	}
}
