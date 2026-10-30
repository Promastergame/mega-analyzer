package gamemode

import (
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml"
)

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT CALCULATOR IMPLEMENTATION
// ═══════════════════════════════════════════════════════════════════════════════

type DefaultThreatCalculator struct {
	// Risk weights for different risk levels
	highRiskWeight   float64
	mediumRiskWeight float64
	lowRiskWeight    float64
	libraryWeight    float64
}

func NewThreatCalculator() ThreatCalculator {
	return &DefaultThreatCalculator{
		highRiskWeight:   6.0,  // High risk weighted 3x more than medium (3 * 2.0 = 6.0)
		mediumRiskWeight: 2.0,  // Medium risk weighted 2x more than low (2 * 1.0 = 2.0)
		lowRiskWeight:    1.0,  // Base weight
		libraryWeight:    0.25, // Library code gets 0.25x multiplier
	}
}

func (tc *DefaultThreatCalculator) CalculateThreatScore(patchPoints []ml.PatchPoint, analysisRes *types.AnalysisResult) ThreatResult {
	result := ThreatResult{
		ByCategory:        make(map[string]float64),
		CategoryBreakdown: make([]CategoryBreakdown, 0),
	}

	categoryPoints := make(map[string]float64)
	categoryCounts := make(map[string]int)
	uniqueCategories := make(map[string]bool)

	totalScore := 0.0

	// 1. Calculate score from patch points
	for _, point := range patchPoints {
		// Calculate base points based on risk level
		var basePoints float64
		switch point.RiskLevel {
		case ml.RiskClassHigh:
			basePoints = point.RiskScore * tc.highRiskWeight
		case ml.RiskClassMedium:
			basePoints = point.RiskScore * tc.mediumRiskWeight
		case ml.RiskClassLow:
			basePoints = point.RiskScore * tc.lowRiskWeight
		default:
			basePoints = point.RiskScore
		}

		// Apply library code penalty
		if point.IsLibraryCode {
			basePoints *= tc.libraryWeight
		}

		categoryName := string(point.Category)
		if categoryName == "" {
			categoryName = "unknown"
		}

		categoryPoints[categoryName] += basePoints
		categoryCounts[categoryName]++
		uniqueCategories[categoryName] = true
		totalScore += basePoints
	}

	// 2. Add score from standard rule matches (SAST/vulnerabilities)
	if analysisRes != nil && analysisRes.Stats.TotalMatches > 0 {
		criticalPoints := float64(analysisRes.Stats.CriticalMatches) * 5.0
		nonCriticalPoints := float64(analysisRes.Stats.TotalMatches-analysisRes.Stats.CriticalMatches) * 0.5
		sastScore := criticalPoints + nonCriticalPoints

		if sastScore > 0 {
			categoryName := "sast"
			categoryPoints[categoryName] = sastScore
			categoryCounts[categoryName] = analysisRes.Stats.TotalMatches
			uniqueCategories[categoryName] = true
			totalScore += sastScore
		}
	}

	// Calculate diversity bonus (more categories = higher bonus)
	diversityCount := len(uniqueCategories)
	diversityBonus := 0.0
	if diversityCount > 1 {
		diversityBonus = float64(diversityCount-1) * 0.1 // 10% bonus per additional category
		totalScore *= (1.0 + diversityBonus)
	}

	// Build category breakdown
	for category, points := range categoryPoints {
		weight := tc.getCategoryWeight(category)
		breakdown := CategoryBreakdown{
			Category: category,
			Points:   points,
			Weight:   weight,
			Count:    categoryCounts[category],
		}
		result.CategoryBreakdown = append(result.CategoryBreakdown, breakdown)
	}

	// Normalize to 0-1000 range
	if totalScore > 1000 {
		totalScore = 1000
	}

	result.TotalScore = totalScore
	result.ByCategory = categoryPoints
	result.DiversityBonus = diversityBonus

	return result
}

func (tc *DefaultThreatCalculator) GetCategoryBreakdown(threatResult ThreatResult) []CategoryBreakdown {
	return threatResult.CategoryBreakdown
}

func (tc *DefaultThreatCalculator) getCategoryWeight(category string) float64 {
	// Category-specific weights based on severity
	weights := map[string]float64{
		"billing":      3.0,
		"license":      2.8,
		"premium":      2.5,
		"subscription": 2.5,
		"tamper":       2.2,
		"drm":          2.0,
		"currency":     1.8,
		"server_auth":  1.5,
		"ads":          1.2,
		"feature_gate": 1.0,
		"installer":    0.8,
	}

	if weight, exists := weights[category]; exists {
		return weight
	}
	return 1.0 // Default weight
}
