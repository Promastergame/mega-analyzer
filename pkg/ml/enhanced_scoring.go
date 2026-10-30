package ml

// ═══════════════════════════════════════════════════════════════════════════════
// ENHANCED SCORING ENGINE (Task 26 - Requirement 20)
//
// Intelligent scoring with:
// - Confidence weighting
// - Structural similarity boosting
// - Superficial match penalties
// - Decoy detection integration
// - Advanced threat detection integration
// ═══════════════════════════════════════════════════════════════════════════════

// EnhancedScore contains comprehensive scoring information
type EnhancedScore struct {
	BaseScore        float64                 `json:"base_score"`
	ConfidenceScore  float64                 `json:"confidence_score"`
	StructuralBonus  float64                 `json:"structural_bonus"`
	DecoyPenalty     float64                 `json:"decoy_penalty"`
	ThreatBonus      float64                 `json:"threat_bonus"`
	FinalScore       float64                 `json:"final_score"`
	Confidence       float64                 `json:"confidence"`         // 0.0-1.0
	IsHighConfidence bool                    `json:"is_high_confidence"` // >= 0.6
	MatchedPatterns  []string                `json:"matched_patterns"`
	DecoyAnalysis    *DecoyBasicAnalysis     `json:"decoy_analysis,omitempty"`
	ThreatAnalysis   *AdvancedThreatAnalysis `json:"threat_analysis,omitempty"`
}

// CalculateEnhancedScore computes an intelligent score with confidence weighting
func CalculateEnhancedScore(mi *MethodInfo, patternMatches []PatternMatch) *EnhancedScore {
	score := &EnhancedScore{
		MatchedPatterns: make([]string, 0, len(patternMatches)),
	}

	// 1. Calculate base score from pattern matches
	score.BaseScore = calculateBaseScore(mi, patternMatches, score)

	// 2. Calculate confidence based on evidence quality
	score.Confidence = calculateConfidence(mi, patternMatches)
	score.IsHighConfidence = score.Confidence >= 0.6

	// 3. Apply confidence weighting to base score
	score.ConfidenceScore = score.BaseScore * score.Confidence

	// 4. Calculate structural similarity bonus (Requirement 20.3)
	score.StructuralBonus = calculateStructuralBonus(mi, patternMatches)

	// 5. Detect and penalize decoy code (Requirement 16.1, 16.2)
	score.DecoyAnalysis = AnalyzeDecoyCharacteristics(mi)
	score.DecoyPenalty = score.DecoyAnalysis.TotalPenalty

	// 6. Detect advanced threats and apply bonus (Requirements 17, 19, 21, 22)
	score.ThreatAnalysis = DetectAdvancedThreats(mi)
	score.ThreatBonus = calculateThreatBonus(score.ThreatAnalysis)

	// 7. Calculate final score
	score.FinalScore = score.ConfidenceScore + score.StructuralBonus + score.DecoyPenalty + score.ThreatBonus

	// 8. Apply minimum confidence threshold (Requirement 20.5)
	if score.Confidence < 0.6 {
		score.FinalScore *= 0.5 // 50% penalty for low confidence
	}

	// Ensure score doesn't go negative
	if score.FinalScore < 0 {
		score.FinalScore = 0
	}

	return score
}

// calculateBaseScore computes the base score from pattern matches
func calculateBaseScore(_ *MethodInfo, matches []PatternMatch, score *EnhancedScore) float64 {
	if len(matches) == 0 {
		return 0
	}

	// Use the highest scoring pattern match
	maxScore := 0.0
	for i := range matches {
		if matches[i].MatchScore > maxScore {
			maxScore = matches[i].MatchScore
		}
		if matches[i].Pattern != nil {
			score.MatchedPatterns = append(score.MatchedPatterns, matches[i].Pattern.ID)
		}
	}

	return maxScore
}

// calculateConfidence determines confidence based on evidence quality (Requirement 20.1)
func calculateConfidence(mi *MethodInfo, matches []PatternMatch) float64 {
	if len(matches) == 0 {
		return 0.0
	}

	// Evidence sources with weights (total = 1.0)
	confidence := 0.0

	// 1. Name match evidence (weight: 0.20)
	if mi.HasSecurityName || mi.HasCheckPrefix {
		confidence += 0.20
	}

	// 2. API call evidence (weight: 0.30)
	if mi.HasSecurityAPI && len(mi.SecurityCalls) > 0 {
		confidence += 0.30
	}

	// 3. String constant evidence (weight: 0.20)
	if mi.HasSecurityStrings && len(mi.SecurityStrings) > 0 {
		confidence += 0.20
	}

	// 4. Structural evidence (weight: 0.20)
	if mi.ReturnsBoolean && mi.HasDualReturn {
		confidence += 0.20
	}

	// 5. Context evidence (weight: 0.10)
	if mi.IsAppCode && !mi.IsLibrary {
		confidence += 0.10
	}

	// Ensure confidence is in valid range
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// calculateStructuralBonus applies bonus for high structural similarity (Requirement 20.3)
func calculateStructuralBonus(_ *MethodInfo, matches []PatternMatch) float64 {
	if len(matches) == 0 {
		return 0
	}

	bonus := 0.0

	// Find the best pattern match
	var bestMatch *PatternMatch
	maxScore := 0.0
	for i := range matches {
		if matches[i].MatchScore > maxScore {
			maxScore = matches[i].MatchScore
			bestMatch = &matches[i]
		}
	}

	if bestMatch == nil {
		return 0
	}

	// Count matched parts
	matchedParts := len(bestMatch.MatchedParts)

	// High structural similarity: 4+ matched parts
	if matchedParts >= 4 {
		// 20% boost for strong structural match (Requirement 20.3)
		bonus = bestMatch.MatchScore * 0.20
	} else if matchedParts >= 3 {
		// 10% boost for moderate structural match
		bonus = bestMatch.MatchScore * 0.10
	}

	return bonus
}

// calculateThreatBonus applies bonus for detected advanced threats
func calculateThreatBonus(analysis *AdvancedThreatAnalysis) float64 {
	if analysis == nil || analysis.ThreatCount == 0 {
		return 0
	}

	bonus := 0.0

	// Apply bonus based on threat severity
	for _, threat := range analysis.Threats {
		threatBonus := 0.0
		switch threat.Severity {
		case "critical":
			threatBonus = 25.0 * threat.Confidence
		case "high":
			threatBonus = 15.0 * threat.Confidence
		case "medium":
			threatBonus = 8.0 * threat.Confidence
		case "low":
			threatBonus = 3.0 * threat.Confidence
		}
		bonus += threatBonus
	}

	return bonus
}

// IsSuperficialMatch checks if a match is only superficial (Requirement 20.4)
func IsSuperficialMatch(_ *MethodInfo, match *PatternMatch) bool {
	if match == nil {
		return true
	}

	// Superficial if only name matches but no other evidence
	nameOnlyMatch := false
	hasOtherEvidence := false

	for _, part := range match.MatchedParts {
		if len(part) >= 11 && part[:11] == "method_name" {
			nameOnlyMatch = true
		} else {
			hasOtherEvidence = true
		}
	}

	// Superficial if:
	// 1. Only name matches, no API calls or strings
	// 2. Very low match score (<15)
	// 3. Only 1 matched part
	return (nameOnlyMatch && !hasOtherEvidence) ||
		match.MatchScore < 15 ||
		len(match.MatchedParts) <= 1
}

// ApplySuperficialPenalty applies 30% penalty for superficial matches (Requirement 20.4)
func ApplySuperficialPenalty(score float64, isSuperficial bool) float64 {
	if isSuperficial {
		return score * 0.70 // 30% penalty
	}
	return score
}

// FilterLowConfidenceResults filters out results below confidence threshold (Requirement 20.5)
func FilterLowConfidenceResults(scores []*EnhancedScore, minConfidence float64) []*EnhancedScore {
	filtered := make([]*EnhancedScore, 0, len(scores))

	for _, score := range scores {
		if score.Confidence >= minConfidence {
			filtered = append(filtered, score)
		}
	}

	return filtered
}

// RankByConfidence sorts results by confidence-weighted score
func RankByConfidence(scores []*EnhancedScore) []*EnhancedScore {
	// Simple bubble sort (good enough for small lists)
	n := len(scores)
	for i := 0; i < n-1; i++ {
		for j := 0; j < n-i-1; j++ {
			// Sort by final score descending
			if scores[j].FinalScore < scores[j+1].FinalScore {
				scores[j], scores[j+1] = scores[j+1], scores[j]
			}
		}
	}
	return scores
}
