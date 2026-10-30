package gamemode

import (
	"math/rand"
	"testing"

	"mega-analyzer/pkg/ml"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PROPERTY-BASED TESTS FOR THREAT CALCULATOR
// ═══════════════════════════════════════════════════════════════════════════════

// TestThreatScoreRangeConstraint tests Property 1: Threat Score Range Constraint
// Feature: analyzer-gamemode-upgrade, Property 1: Threat Score Range Constraint
// Validates: Requirements 2.5
//
// Property: For any set of patch points with valid risk scores and categories,
// the threat calculator SHALL produce a final threat score in the range 0-1000
func TestThreatScoreRangeConstraint(t *testing.T) {
	calculator := NewThreatCalculator()

	// Run property test with multiple iterations
	for i := 0; i < 100; i++ {
		// Generate random patch points
		patchPoints := generateRandomPatchPoints(i)

		// Calculate threat score
		result := calculator.CalculateThreatScore(patchPoints, nil)

		// Property 1: Score must be in range 0-1000
		if result.TotalScore < 0 {
			t.Errorf("Iteration %d: Threat score below minimum: %.2f < 0", i, result.TotalScore)
		}

		if result.TotalScore > 1000 {
			t.Errorf("Iteration %d: Threat score above maximum: %.2f > 1000", i, result.TotalScore)
		}

		// Score should be 0 for empty patch points
		if len(patchPoints) == 0 && result.TotalScore != 0 {
			t.Errorf("Iteration %d: Expected 0 score for empty patch points, got %.2f", i, result.TotalScore)
		}

		// Score should be positive for non-empty patch points with positive risk scores
		if len(patchPoints) > 0 {
			hasPositiveRisk := false
			for _, point := range patchPoints {
				if point.RiskScore > 0 {
					hasPositiveRisk = true
					break
				}
			}

			if hasPositiveRisk && result.TotalScore <= 0 {
				t.Errorf("Iteration %d: Expected positive score for patch points with positive risk, got %.2f",
					i, result.TotalScore)
			}
		}
	}
}

// TestRiskWeightingHierarchy tests Property 2: Risk Weighting Hierarchy
// Feature: analyzer-gamemode-upgrade, Property 2: Risk Weighting Hierarchy
// Validates: Requirements 2.2, 2.3
//
// Property: For any threat calculation, high-risk findings SHALL be weighted at least 3x more
// than medium-risk findings, and medium-risk findings SHALL be weighted at least 2x more than low-risk findings
func TestRiskWeightingHierarchy(t *testing.T) {
	calculator := NewThreatCalculator()

	baseScore := 50.0

	// Test high vs medium risk weighting
	for i := 0; i < 50; i++ {
		highRiskPoints := []ml.PatchPoint{
			{
				RiskScore:     baseScore,
				RiskLevel:     ml.RiskClassHigh,
				Category:      ml.PatchCatBilling,
				IsLibraryCode: false,
			},
		}

		mediumRiskPoints := []ml.PatchPoint{
			{
				RiskScore:     baseScore,
				RiskLevel:     ml.RiskClassMedium,
				Category:      ml.PatchCatBilling,
				IsLibraryCode: false,
			},
		}

		highResult := calculator.CalculateThreatScore(highRiskPoints, nil)
		mediumResult := calculator.CalculateThreatScore(mediumRiskPoints, nil)

		// Property 2a: High risk should be weighted at least 3x more than medium risk
		ratio := highResult.TotalScore / mediumResult.TotalScore
		if ratio < 2.9 { // Allow small tolerance for floating point
			t.Errorf("Iteration %d: High risk not weighted enough vs medium: ratio=%.2f, expected>=3.0", i, ratio)
		}
	}

	// Test medium vs low risk weighting
	for i := 0; i < 50; i++ {
		mediumRiskPoints := []ml.PatchPoint{
			{
				RiskScore:     baseScore,
				RiskLevel:     ml.RiskClassMedium,
				Category:      ml.PatchCatBilling,
				IsLibraryCode: false,
			},
		}

		lowRiskPoints := []ml.PatchPoint{
			{
				RiskScore:     baseScore,
				RiskLevel:     ml.RiskClassLow,
				Category:      ml.PatchCatBilling,
				IsLibraryCode: false,
			},
		}

		mediumResult := calculator.CalculateThreatScore(mediumRiskPoints, nil)
		lowResult := calculator.CalculateThreatScore(lowRiskPoints, nil)

		// Property 2b: Medium risk should be weighted at least 2x more than low risk
		ratio := mediumResult.TotalScore / lowResult.TotalScore
		if ratio < 1.9 { // Allow small tolerance for floating point
			t.Errorf("Iteration %d: Medium risk not weighted enough vs low: ratio=%.2f, expected>=2.0", i, ratio)
		}
	}
}

// TestLibraryCodeWeightMultiplier tests Property 3: Library Code Weight Multiplier
// Feature: analyzer-gamemode-upgrade, Property 3: Library Code Weight Multiplier
// Validates: Requirements 2.4
//
// Property: For any threat calculation involving library code findings,
// the threat calculator SHALL apply a 0.25x weight multiplier to reflect their lower priority
func TestLibraryCodeWeightMultiplier(t *testing.T) {
	calculator := NewThreatCalculator()

	baseScore := 100.0

	for i := 0; i < 50; i++ {
		// App code patch point
		appCodePoints := []ml.PatchPoint{
			{
				RiskScore:     baseScore,
				RiskLevel:     ml.RiskClassHigh,
				Category:      ml.PatchCatBilling,
				IsLibraryCode: false,
			},
		}

		// Library code patch point (same everything except IsLibraryCode)
		libraryCodePoints := []ml.PatchPoint{
			{
				RiskScore:     baseScore,
				RiskLevel:     ml.RiskClassHigh,
				Category:      ml.PatchCatBilling,
				IsLibraryCode: true,
			},
		}

		appResult := calculator.CalculateThreatScore(appCodePoints, nil)
		libraryResult := calculator.CalculateThreatScore(libraryCodePoints, nil)

		// Property 3: Library code should get 0.25x multiplier
		expectedRatio := 0.25
		actualRatio := libraryResult.TotalScore / appResult.TotalScore

		tolerance := 0.05 // 5% tolerance
		if actualRatio < expectedRatio-tolerance || actualRatio > expectedRatio+tolerance {
			t.Errorf("Iteration %d: Library code multiplier incorrect: ratio=%.3f, expected=%.3f±%.3f",
				i, actualRatio, expectedRatio, tolerance)
		}
	}
}

// TestThreatCalculatorConsistency tests that threat calculation is deterministic
func TestThreatCalculatorConsistency(t *testing.T) {
	calculator := NewThreatCalculator()

	// Create test patch points
	patchPoints := []ml.PatchPoint{
		{
			RiskScore:     80.0,
			RiskLevel:     ml.RiskClassHigh,
			Category:      ml.PatchCatBilling,
			IsLibraryCode: false,
		},
		{
			RiskScore:     60.0,
			RiskLevel:     ml.RiskClassMedium,
			Category:      ml.PatchCatLicense,
			IsLibraryCode: false,
		},
		{
			RiskScore:     40.0,
			RiskLevel:     ml.RiskClassLow,
			Category:      ml.PatchCatAds,
			IsLibraryCode: true,
		},
	}

	// Calculate multiple times - should get same result
	var firstResult ThreatResult
	for i := 0; i < 10; i++ {
		result := calculator.CalculateThreatScore(patchPoints, nil)

		if i == 0 {
			firstResult = result
		} else {
			// Results should be identical
			if result.TotalScore != firstResult.TotalScore {
				t.Errorf("Inconsistent threat calculation: iteration %d got %.2f, expected %.2f",
					i, result.TotalScore, firstResult.TotalScore)
			}

			if len(result.CategoryBreakdown) != len(firstResult.CategoryBreakdown) {
				t.Errorf("Inconsistent category breakdown count: iteration %d got %d, expected %d",
					i, len(result.CategoryBreakdown), len(firstResult.CategoryBreakdown))
			}
		}
	}
}

// TestDiversityBonus tests that diversity bonus is applied correctly
func TestDiversityBonus(t *testing.T) {
	calculator := NewThreatCalculator()

	baseScore := 50.0

	// Single category
	singleCategoryPoints := []ml.PatchPoint{
		{
			RiskScore:     baseScore,
			RiskLevel:     ml.RiskClassHigh,
			Category:      ml.PatchCatBilling,
			IsLibraryCode: false,
		},
	}

	// Multiple categories
	multiCategoryPoints := []ml.PatchPoint{
		{
			RiskScore:     baseScore,
			RiskLevel:     ml.RiskClassHigh,
			Category:      ml.PatchCatBilling,
			IsLibraryCode: false,
		},
		{
			RiskScore:     baseScore,
			RiskLevel:     ml.RiskClassHigh,
			Category:      ml.PatchCatLicense,
			IsLibraryCode: false,
		},
	}

	singleResult := calculator.CalculateThreatScore(singleCategoryPoints, nil)
	multiResult := calculator.CalculateThreatScore(multiCategoryPoints, nil)

	// Multi-category should have higher score due to diversity bonus
	if multiResult.TotalScore <= singleResult.TotalScore*2 {
		t.Errorf("Expected diversity bonus to increase score: single=%.2f, multi=%.2f",
			singleResult.TotalScore, multiResult.TotalScore)
	}

	// Diversity bonus should be recorded
	if multiResult.DiversityBonus <= 0 {
		t.Errorf("Expected positive diversity bonus for multiple categories, got %.3f",
			multiResult.DiversityBonus)
	}
}

// generateRandomPatchPoints creates random patch points for property testing
func generateRandomPatchPoints(seed int) []ml.PatchPoint {

	count := rand.Intn(10) // 0-9 patch points
	points := make([]ml.PatchPoint, count)

	categories := []ml.PatchCategory{
		ml.PatchCatBilling, ml.PatchCatLicense, ml.PatchCatPremium,
		ml.PatchCatSubscription, ml.PatchCatTamper, ml.PatchCatAds,
	}

	riskLevels := []ml.RiskClass{
		ml.RiskClassHigh, ml.RiskClassMedium, ml.RiskClassLow,
	}

	for i := 0; i < count; i++ {
		points[i] = ml.PatchPoint{
			RiskScore:     rand.Float64() * 100, // 0-100
			RiskLevel:     riskLevels[rand.Intn(len(riskLevels))],
			Category:      categories[rand.Intn(len(categories))],
			IsLibraryCode: rand.Float64() < 0.3, // 30% chance of library code
		}
	}

	return points
}
