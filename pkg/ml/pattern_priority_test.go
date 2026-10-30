package ml

import (
	"strings"
	"testing"
)

func TestGetPatternPriority(t *testing.T) {
	tests := []struct {
		category PatchCategory
		expected PatternPriority
	}{
		{PatchCatBilling, PriorityCritical},
		{PatchCatSubscription, PriorityCritical},
		{PatchCatPremium, PriorityHigh},
		{PatchCatAds, PriorityHigh},
		{PatchCatLicense, PriorityHigh},
		{PatchCatRootDetect, PriorityMedium},
		{PatchCatEmulatorCheck, PriorityMedium},
		{PatchCatFeatureGate, PriorityLow},
		{PatchCatInstaller, PriorityLow},
	}

	for _, tt := range tests {
		got := GetPatternPriority(tt.category)
		if got != tt.expected {
			t.Errorf("GetPatternPriority(%s) = %s, want %s", tt.category, got, tt.expected)
		}
	}
}

func TestGetPriorityScore(t *testing.T) {
	tests := []struct {
		priority PatternPriority
		expected int
	}{
		{PriorityCritical, 4},
		{PriorityHigh, 3},
		{PriorityMedium, 2},
		{PriorityLow, 1},
	}

	for _, tt := range tests {
		got := GetPriorityScore(tt.priority)
		if got != tt.expected {
			t.Errorf("GetPriorityScore(%s) = %d, want %d", tt.priority, got, tt.expected)
		}
	}
}

func TestSortByPriority(t *testing.T) {
	methods := []ScoredMethod{
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{Category: PatchCatFeatureGate}, // Low
				FinalScore:  80.0,
			},
		},
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{Category: PatchCatBilling}, // Critical
				FinalScore:  60.0,
			},
		},
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{Category: PatchCatPremium}, // High
				FinalScore:  70.0,
			},
		},
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{Category: PatchCatRootDetect}, // Medium
				FinalScore:  75.0,
			},
		},
	}

	sorted := SortByPriority(methods)

	// Check order: Critical > High > Medium > Low (regardless of score)
	expectedOrder := []PatchCategory{
		PatchCatBilling,     // Critical (score 60)
		PatchCatPremium,     // High (score 70)
		PatchCatRootDetect,  // Medium (score 75)
		PatchCatFeatureGate, // Low (score 80)
	}

	for i, expected := range expectedOrder {
		if sorted[i].Score.BestPattern.Category != expected {
			t.Errorf("Position %d: got %s, want %s", i, sorted[i].Score.BestPattern.Category, expected)
		}
	}
}

func TestSortByPriority_SamePriority(t *testing.T) {
	methods := []ScoredMethod{
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{Category: PatchCatBilling},
				FinalScore:  60.0,
			},
		},
		{
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{Category: PatchCatSubscription},
				FinalScore:  80.0,
			},
		},
	}

	sorted := SortByPriority(methods)

	// Both are critical, so should be sorted by score (80 > 60)
	if sorted[0].Score.FinalScore != 80.0 {
		t.Errorf("First method should have score 80.0, got %.1f", sorted[0].Score.FinalScore)
	}
	if sorted[1].Score.FinalScore != 60.0 {
		t.Errorf("Second method should have score 60.0, got %.1f", sorted[1].Score.FinalScore)
	}
}

func TestGroupByPriority(t *testing.T) {
	methods := []ScoredMethod{
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatBilling}}},
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatSubscription}}},
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatPremium}}},
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatRootDetect}}},
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatFeatureGate}}},
	}

	groups := GroupByPriority(methods)

	if len(groups[PriorityCritical]) != 2 {
		t.Errorf("Expected 2 critical methods, got %d", len(groups[PriorityCritical]))
	}
	if len(groups[PriorityHigh]) != 1 {
		t.Errorf("Expected 1 high method, got %d", len(groups[PriorityHigh]))
	}
	if len(groups[PriorityMedium]) != 1 {
		t.Errorf("Expected 1 medium method, got %d", len(groups[PriorityMedium]))
	}
	if len(groups[PriorityLow]) != 1 {
		t.Errorf("Expected 1 low method, got %d", len(groups[PriorityLow]))
	}
}

func TestFormatByPriority(t *testing.T) {
	methods := []ScoredMethod{
		{
			Method: MethodInfo{
				Name:      "checkBilling",
				ClassName: "Lcom/example/BillingChecker;",
			},
			Score: ScoreResult{
				BestPattern: &VulnerablePattern{
					ID:       "BILLING_SUPPORTED",
					Category: PatchCatBilling,
				},
				FinalScore: 75.0,
				RiskLevel:  RiskClassHigh,
				Confidence: 0.85,
			},
		},
	}

	output := FormatByPriority(methods)

	if output == "" {
		t.Error("Expected non-empty output")
	}

	// Check that output contains priority information
	if !strings.Contains(output, "CRITICAL") {
		t.Error("Output should contain CRITICAL priority")
	}
	if !strings.Contains(output, "checkBilling") {
		t.Error("Output should contain method name")
	}
}

func TestFilterByPriority(t *testing.T) {
	methods := []ScoredMethod{
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatBilling}}},
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatPremium}}},
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatRootDetect}}},
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatFeatureGate}}},
	}

	// Filter for critical and high only
	filtered := FilterByPriority(methods, PriorityCritical, PriorityHigh)

	if len(filtered) != 2 {
		t.Errorf("Expected 2 filtered methods, got %d", len(filtered))
	}

	// Verify filtered methods are correct priorities
	for _, sm := range filtered {
		priority := GetPatternPriority(sm.Score.BestPattern.Category)
		if priority != PriorityCritical && priority != PriorityHigh {
			t.Errorf("Filtered method has wrong priority: %s", priority)
		}
	}
}

func TestGetPriorityStats(t *testing.T) {
	methods := []ScoredMethod{
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatBilling}}},
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatSubscription}}},
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatPremium}}},
		{Score: ScoreResult{BestPattern: &VulnerablePattern{Category: PatchCatRootDetect}}},
	}

	stats := GetPriorityStats(methods)

	if stats[PriorityCritical] != 2 {
		t.Errorf("Expected 2 critical, got %d", stats[PriorityCritical])
	}
	if stats[PriorityHigh] != 1 {
		t.Errorf("Expected 1 high, got %d", stats[PriorityHigh])
	}
	if stats[PriorityMedium] != 1 {
		t.Errorf("Expected 1 medium, got %d", stats[PriorityMedium])
	}
}

func TestGetPriorityDescription(t *testing.T) {
	priorities := []PatternPriority{
		PriorityCritical,
		PriorityHigh,
		PriorityMedium,
		PriorityLow,
	}

	for _, priority := range priorities {
		desc := GetPriorityDescription(priority)
		if desc == "" || desc == "Unknown priority" {
			t.Errorf("Priority %s should have a valid description", priority)
		}
	}
}
