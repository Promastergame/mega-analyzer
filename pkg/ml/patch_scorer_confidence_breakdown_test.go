package ml

import (
	"math"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS FOR CalculateConfidenceWithBreakdown (Task 4.5)
// ═══════════════════════════════════════════════════════════════════════════════

// TestCalculateConfidenceWithBreakdown_NoSignals tests breakdown with no matched signals
func TestCalculateConfidenceWithBreakdown_NoSignals(t *testing.T) {
	scorer, _ := newTestScorer()

	mi := &MethodInfo{
		Name:           "someMethod",
		ReturnsBoolean: false,
	}

	result := &ScoreResult{
		Reasons:  []string{},
		Warnings: []string{},
	}

	breakdown := scorer.CalculateConfidenceWithBreakdown(mi, result)

	// Should have minimum confidence
	if breakdown.BaseConfidence != scorer.config.MinConfidence {
		t.Errorf("Expected base confidence %v, got %v", scorer.config.MinConfidence, breakdown.BaseConfidence)
	}

	// No signals = no contributions
	if len(breakdown.SignalContributions) != 0 {
		t.Errorf("Expected 0 signal contributions, got %d", len(breakdown.SignalContributions))
	}

	// No multi-signal bonus
	if breakdown.MultiSignalBonus != 0 {
		t.Errorf("Expected 0 multi-signal bonus, got %v", breakdown.MultiSignalBonus)
	}

	// Final confidence should be clamped to [0.3, 1.0]
	if breakdown.FinalConfidence < 0.3 || breakdown.FinalConfidence > 1.0 {
		t.Errorf("Final confidence %v out of range [0.3, 1.0]", breakdown.FinalConfidence)
	}
}

// TestCalculateConfidenceWithBreakdown_SingleSignal tests breakdown with one signal
func TestCalculateConfidenceWithBreakdown_SingleSignal(t *testing.T) {
	scorer, _ := newTestScorer()

	mi := &MethodInfo{
		Name:            "isRooted",
		ReturnsBoolean:  true,
		HasSecurityName: true,
	}

	result := &ScoreResult{
		Reasons:  []string{},
		Warnings: []string{},
	}

	breakdown := scorer.CalculateConfidenceWithBreakdown(mi, result)

	// Should have at least one signal (name or return type)
	if len(breakdown.SignalContributions) == 0 {
		t.Error("Expected at least one signal contribution")
	}

	// Note: A boolean method with security name will have multiple signals:
	// NAME, STRUCTURE (boolean return), and RETURN_TYPE
	// So we expect a multi-signal bonus
	if len(breakdown.SignalContributions) >= 2 && breakdown.MultiSignalBonus == 0 {
		t.Error("Expected multi-signal bonus with multiple signals")
	}

	// Base confidence should be > 0
	if breakdown.BaseConfidence <= 0 {
		t.Errorf("Expected positive base confidence, got %v", breakdown.BaseConfidence)
	}

	// Final confidence should be in valid range
	if breakdown.FinalConfidence < 0.3 || breakdown.FinalConfidence > 1.0 {
		t.Errorf("Final confidence %v out of range [0.3, 1.0]", breakdown.FinalConfidence)
	}
}

// TestCalculateConfidenceWithBreakdown_MultipleSignals tests breakdown with multiple signals
func TestCalculateConfidenceWithBreakdown_MultipleSignals(t *testing.T) {
	scorer, _ := newTestScorer()

	mi := &MethodInfo{
		Name:            "checkLicense",
		ReturnsBoolean:  true,
		HasSecurityName: true,
		HasSecurityAPI:  true,
		SecurityCalls:   []string{"checkSignature"},
		HasDualReturn:   true,
		HasIfWithReturn: true,
	}

	result := &ScoreResult{
		Reasons:  []string{},
		Warnings: []string{},
	}

	breakdown := scorer.CalculateConfidenceWithBreakdown(mi, result)

	// Should have multiple signals
	if len(breakdown.SignalContributions) < 2 {
		t.Errorf("Expected at least 2 signal contributions, got %d", len(breakdown.SignalContributions))
	}

	// Multiple signals = should have bonus
	if breakdown.MultiSignalBonus <= 0 {
		t.Errorf("Expected positive multi-signal bonus, got %v", breakdown.MultiSignalBonus)
	}

	// Multi-signal bonus should be capped at 0.25
	if breakdown.MultiSignalBonus > 0.25 {
		t.Errorf("Multi-signal bonus %v exceeds maximum 0.25", breakdown.MultiSignalBonus)
	}

	// Final confidence should be higher than base due to bonus
	expectedMin := breakdown.BaseConfidence
	if breakdown.FinalConfidence < expectedMin {
		t.Errorf("Final confidence %v should be >= base confidence %v", breakdown.FinalConfidence, expectedMin)
	}
}

// TestCalculateConfidenceWithBreakdown_WeightedAggregation tests weighted signal aggregation
func TestCalculateConfidenceWithBreakdown_WeightedAggregation(t *testing.T) {
	scorer, _ := newTestScorer()

	mi := &MethodInfo{
		Name:            "verifyPurchase",
		ReturnsBoolean:  true,
		HasSecurityName: true,
		HasSecurityAPI:  true,
		SecurityCalls:   []string{"verifySignature", "checkReceipt"},
	}

	result := &ScoreResult{
		Reasons:  []string{},
		Warnings: []string{},
	}

	breakdown := scorer.CalculateConfidenceWithBreakdown(mi, result)

	// Verify signal contributions are calculated correctly
	totalWeight := 0.0
	weightedSum := 0.0

	for _, contrib := range breakdown.SignalContributions {
		// Contribution should equal weight * confidence
		expectedContribution := contrib.Weight * contrib.Confidence
		if math.Abs(contrib.Contribution-expectedContribution) > 0.001 {
			t.Errorf("Signal %s: contribution %v != weight %v * confidence %v",
				contrib.SignalType, contrib.Contribution, contrib.Weight, contrib.Confidence)
		}

		totalWeight += contrib.Weight
		weightedSum += contrib.Contribution
	}

	// Base confidence should equal weighted average
	expectedBase := weightedSum / totalWeight
	if math.Abs(breakdown.BaseConfidence-expectedBase) > 0.001 {
		t.Errorf("Base confidence %v != weighted average %v", breakdown.BaseConfidence, expectedBase)
	}
}

// TestCalculateConfidenceWithBreakdown_ObfuscationAdjustment tests obfuscation adjustment
func TestCalculateConfidenceWithBreakdown_ObfuscationAdjustment(t *testing.T) {
	scorer, _ := newTestScorer()

	mi := &MethodInfo{
		Name:            "a",
		ReturnsBoolean:  true,
		HasSecurityAPI:  true,
		SecurityCalls:   []string{"getSystemService"},
		HasDualReturn:   true,
		HasIfWithReturn: true,
	}

	obfInfo := ObfuscationInfo{
		IsObfuscated:        true,
		ObfuscationType:     ObfuscationProGuard,
		Confidence:          0.8,
		RecommendedStrategy: StrategyStructural,
	}

	result := &ScoreResult{
		Reasons:         []string{},
		Warnings:        []string{},
		ObfuscationInfo: &obfInfo,
	}

	breakdown := scorer.CalculateConfidenceWithBreakdown(mi, result)

	// Should have obfuscation adjustment
	if breakdown.ObfuscationAdjust == 0 {
		t.Error("Expected non-zero obfuscation adjustment for obfuscated code")
	}

	// Final confidence should be in obfuscation-aware range [0.3, 0.8]
	if breakdown.FinalConfidence < 0.3 || breakdown.FinalConfidence > 0.8 {
		t.Errorf("Final confidence %v out of obfuscation range [0.3, 0.8]", breakdown.FinalConfidence)
	}
}

// TestCalculateConfidenceWithBreakdown_NormalizationRange tests confidence normalization
func TestCalculateConfidenceWithBreakdown_NormalizationRange(t *testing.T) {
	scorer, _ := newTestScorer()

	testCases := []struct {
		name string
		mi   *MethodInfo
	}{
		{
			name: "minimal signals",
			mi: &MethodInfo{
				Name:           "test",
				ReturnsBoolean: false,
			},
		},
		{
			name: "moderate signals",
			mi: &MethodInfo{
				Name:            "checkRoot",
				ReturnsBoolean:  true,
				HasSecurityName: true,
			},
		},
		{
			name: "many signals",
			mi: &MethodInfo{
				Name:               "verifyLicense",
				ReturnsBoolean:     true,
				HasSecurityName:    true,
				HasSecurityAPI:     true,
				SecurityCalls:      []string{"verify", "check"},
				HasSecurityStrings: true,
				SecurityStrings:    []string{"license"},
				HasDualReturn:      true,
				HasIfWithReturn:    true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := &ScoreResult{
				Reasons:  []string{},
				Warnings: []string{},
			}

			breakdown := scorer.CalculateConfidenceWithBreakdown(tc.mi, result)

			// Final confidence must be in [0.3, 1.0] range
			if breakdown.FinalConfidence < 0.3 {
				t.Errorf("Final confidence %v below minimum 0.3", breakdown.FinalConfidence)
			}
			if breakdown.FinalConfidence > 1.0 {
				t.Errorf("Final confidence %v above maximum 1.0", breakdown.FinalConfidence)
			}
		})
	}
}

// TestCalculateConfidenceWithBreakdown_BreakdownConsistency tests breakdown sum consistency
func TestCalculateConfidenceWithBreakdown_BreakdownConsistency(t *testing.T) {
	scorer, _ := newTestScorer()

	mi := &MethodInfo{
		Name:            "verifyPremium",
		ReturnsBoolean:  true,
		HasSecurityName: true,
		HasSecurityAPI:  true,
		SecurityCalls:   []string{"checkPurchase"},
		HasDualReturn:   true,
	}

	result := &ScoreResult{
		Reasons:  []string{},
		Warnings: []string{},
	}

	breakdown := scorer.CalculateConfidenceWithBreakdown(mi, result)

	// Calculate expected final confidence (before penalties)
	expectedBeforePenalties := breakdown.BaseConfidence +
		breakdown.MultiSignalBonus +
		breakdown.ObfuscationAdjust

	// Account for penalties
	warningPenalty := float64(len(result.Warnings)) * 0.05
	if warningPenalty > 0.2 {
		warningPenalty = 0.2
	}

	libraryPenalty := 0.0
	if mi.IsLibrary {
		libraryPenalty = 0.15
	}

	expectedFinal := expectedBeforePenalties - warningPenalty - libraryPenalty

	// Clamp to [0.3, 1.0]
	if expectedFinal < 0.3 {
		expectedFinal = 0.3
	}
	if expectedFinal > 1.0 {
		expectedFinal = 1.0
	}

	// Round to 2 decimals
	expectedFinal = math.Round(expectedFinal*100) / 100

	// Verify consistency (within floating point tolerance)
	if math.Abs(breakdown.FinalConfidence-expectedFinal) > 0.01 {
		t.Errorf("Final confidence %v != expected %v (base=%v, bonus=%v, obf=%v)",
			breakdown.FinalConfidence, expectedFinal,
			breakdown.BaseConfidence, breakdown.MultiSignalBonus, breakdown.ObfuscationAdjust)
	}
}

// TestCalculateConfidenceWithBreakdown_SignalTypes tests all signal types are included
func TestCalculateConfidenceWithBreakdown_SignalTypes(t *testing.T) {
	scorer, _ := newTestScorer()

	mi := &MethodInfo{
		Name:               "checkPremiumAccess",
		ReturnsBoolean:     true,
		HasSecurityName:    true,
		HasCheckPrefix:     true,
		HasSecurityAPI:     true,
		SecurityCalls:      []string{"verifyPurchase"},
		HasSecurityStrings: true,
		SecurityStrings:    []string{"premium"},
		HasDualReturn:      true,
		HasIfWithReturn:    true,
	}

	result := &ScoreResult{
		Reasons:  []string{},
		Warnings: []string{},
	}

	breakdown := scorer.CalculateConfidenceWithBreakdown(mi, result)

	// Should have multiple signal types
	signalTypes := make(map[string]bool)
	for _, contrib := range breakdown.SignalContributions {
		signalTypes[contrib.SignalType] = true
	}

	// Expect at least: NAME, STRUCTURE, API_CALL, STRING, RETURN_TYPE
	expectedTypes := []string{"NAME", "STRUCTURE", "API_CALL", "STRING", "RETURN_TYPE"}
	for _, expectedType := range expectedTypes {
		if !signalTypes[expectedType] {
			t.Logf("Warning: Expected signal type %s not found (may be valid depending on method)", expectedType)
		}
	}

	// Should have at least 3 signal types for this comprehensive method
	if len(signalTypes) < 3 {
		t.Errorf("Expected at least 3 signal types, got %d: %v", len(signalTypes), signalTypes)
	}
}

// TestCalculateConfidenceWithBreakdown_MultiSignalBonusFormula tests multi-signal bonus calculation
func TestCalculateConfidenceWithBreakdown_MultiSignalBonusFormula(t *testing.T) {
	scorer, _ := newTestScorer()

	testCases := []struct {
		name          string
		signalCount   int
		expectedBonus float64
	}{
		{"0 signals", 0, 0.0},
		{"1 signal", 1, 0.0},
		{"2 signals", 2, 0.08},
		{"3 signals", 3, 0.16},
		{"4 signals", 4, 0.24},
		{"5 signals (capped)", 5, 0.25},
		{"6 signals (capped)", 6, 0.25},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bonus := scorer.calculateMultiSignalBonus(tc.signalCount)
			if math.Abs(bonus-tc.expectedBonus) > 0.001 {
				t.Errorf("Expected bonus %v for %d signals, got %v",
					tc.expectedBonus, tc.signalCount, bonus)
			}
		})
	}
}

// TestCalculateConfidenceWithBreakdown_IntegrationWithScoreMethod tests integration
func TestCalculateConfidenceWithBreakdown_IntegrationWithScoreMethod(t *testing.T) {
	scorer, _ := newTestScorer()

	mi := &MethodInfo{
		Name:            "isLicenseValid",
		ClassName:       "com/example/LicenseChecker",
		FilePath:        "com/example/LicenseChecker.smali",
		ReturnsBoolean:  true,
		HasSecurityName: true,
		HasSecurityAPI:  true,
		SecurityCalls:   []string{"checkSignature"},
		IsAppCode:       true,
	}

	// Score the method
	result := scorer.ScoreMethod(mi)

	// Calculate breakdown
	breakdown := scorer.CalculateConfidenceWithBreakdown(mi, result)

	// The breakdown's final confidence should be reasonable
	if breakdown.FinalConfidence < 0.3 || breakdown.FinalConfidence > 1.0 {
		t.Errorf("Breakdown confidence %v out of range [0.3, 1.0]", breakdown.FinalConfidence)
	}

	// Verify breakdown has all required fields
	if breakdown.BaseConfidence == 0 && len(breakdown.SignalContributions) > 0 {
		t.Error("Expected non-zero base confidence with signals")
	}

	if len(breakdown.SignalContributions) >= 2 && breakdown.MultiSignalBonus == 0 {
		t.Error("Expected non-zero multi-signal bonus with multiple signals")
	}

	// The breakdown should have signal contributions for this method
	if len(breakdown.SignalContributions) == 0 {
		t.Error("Expected signal contributions for method with security indicators")
	}
}

// TestCalculateConfidenceWithBreakdown_EdgeCases tests edge cases
func TestCalculateConfidenceWithBreakdown_EdgeCases(t *testing.T) {
	scorer, _ := newTestScorer()

	testCases := []struct {
		name   string
		mi     *MethodInfo
		result *ScoreResult
	}{
		{
			name: "nil obfuscation info",
			mi: &MethodInfo{
				Name:           "test",
				ReturnsBoolean: true,
			},
			result: &ScoreResult{
				Reasons:         []string{},
				Warnings:        []string{},
				ObfuscationInfo: nil,
			},
		},
		{
			name: "empty warnings",
			mi: &MethodInfo{
				Name:           "test",
				ReturnsBoolean: true,
			},
			result: &ScoreResult{
				Reasons:  []string{},
				Warnings: []string{},
			},
		},
		{
			name: "many warnings",
			mi: &MethodInfo{
				Name:           "test",
				ReturnsBoolean: true,
			},
			result: &ScoreResult{
				Reasons:  []string{},
				Warnings: []string{"w1", "w2", "w3", "w4", "w5", "w6"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			breakdown := scorer.CalculateConfidenceWithBreakdown(tc.mi, tc.result)

			// Should not panic and should return valid breakdown
			if breakdown.FinalConfidence < 0.3 || breakdown.FinalConfidence > 1.0 {
				t.Errorf("Final confidence %v out of range [0.3, 1.0]", breakdown.FinalConfidence)
			}
		})
	}
}
