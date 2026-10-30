package ml

import (
	"math"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SCORER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func newTestScorer() (*PatchScorer, *PatchAnalyzer) {
	pa := NewPatchAnalyzer()
	ps := NewPatchScorer(pa)
	return ps, pa
}

func TestScoreLicenseCheck(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/app/LicenseChecker.smali", []byte(smaliLicenseCheck))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])

	if result.FinalScore < HighRiskThreshold {
		t.Errorf("License check score %.1f should be HIGH risk (>= %.1f)", result.FinalScore, HighRiskThreshold)
	}
	if result.RiskLevel != RiskClassHigh {
		t.Errorf("Risk level = %s, want HIGH", result.RiskLevel)
	}
	if result.SuggestedPatch != PatchReturnTrue {
		t.Errorf("Suggested patch = %s, want return_true", result.SuggestedPatch)
	}
	if result.PatchCategory != PatchCatLicense {
		t.Errorf("Category = %s, want license_check", result.PatchCategory)
	}
	if len(result.Reasons) == 0 {
		t.Error("Should have reasons")
	}
}

func TestScoreRootDetection(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/app/security/RootDetector.smali", []byte(smaliRootCheck))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])

	if result.FinalScore < MediumRiskThreshold {
		t.Errorf("Root detection score %.1f should be at least MEDIUM (>= %.1f)", result.FinalScore, MediumRiskThreshold)
	}
	if result.SuggestedPatch != PatchReturnFalse {
		t.Errorf("Root detection should suggest return_false, got %s", result.SuggestedPatch)
	}
}

func TestScoreEmulatorDetection(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/app/EmulatorDetector.smali", []byte(smaliEmulatorCheck))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])

	if result.FinalScore < MediumRiskThreshold {
		t.Errorf("Emulator detection score %.1f too low", result.FinalScore)
	}
	if result.SuggestedPatch != PatchReturnFalse {
		t.Errorf("Emulator detection should suggest return_false, got %s", result.SuggestedPatch)
	}
}

func TestScorePremiumCheck(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/app/PremiumManager.smali", []byte(smaliPremiumCheck))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])

	if result.FinalScore < MediumRiskThreshold {
		t.Errorf("Premium check score %.1f too low", result.FinalScore)
	}
	if result.SuggestedPatch != PatchReturnTrue {
		t.Errorf("Premium should suggest return_true, got %s", result.SuggestedPatch)
	}
}

func TestScoreAdShow(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/app/ads/AdManager.smali", []byte(smaliAdShow))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])

	if result.FinalScore < LowRiskThreshold {
		t.Errorf("Ad show score %.1f too low", result.FinalScore)
	}
}

func TestScoreTrialExpiry(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/app/TrialManager.smali", []byte(smaliTrialExpiry))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])

	if result.FinalScore < MediumRiskThreshold {
		t.Errorf("Trial expiry score %.1f too low", result.FinalScore)
	}
}

func TestScoreSubscription(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/app/billing/SubscriptionManager.smali", []byte(smaliSubscription))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])

	if result.FinalScore < MediumRiskThreshold {
		t.Errorf("Subscription score %.1f too low", result.FinalScore)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAFE METHOD SCORING — должны быть LOW или NONE
// ═══════════════════════════════════════════════════════════════════════════════

func TestScoreGetterIsLow(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/app/User.smali", []byte(smaliGetter))

	if len(classInfo.Methods) == 0 {
		t.Skip("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])

	if result.RiskLevel == RiskClassHigh || result.RiskLevel == RiskClassMedium {
		t.Errorf("Getter should NOT be high/medium risk, got %s (score %.1f)", result.RiskLevel, result.FinalScore)
	}
}

func TestScoreConstructorIsNone(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/app/Helper.smali", []byte(smaliConstructor))

	if len(classInfo.Methods) == 0 {
		t.Skip("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])

	if result.RiskLevel != RiskClassNone {
		t.Errorf("Constructor should be NONE risk, got %s", result.RiskLevel)
	}
}

func TestScoreSyntheticIsNone(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/google/ads/AdView.smali", []byte(smaliSynthetic))

	if len(classInfo.Methods) == 0 {
		t.Skip("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])

	if result.RiskLevel != RiskClassNone {
		t.Errorf("Synthetic accessor should be NONE risk, got %s", result.RiskLevel)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH SCORING
// ═══════════════════════════════════════════════════════════════════════════════

func TestScoreBatch(t *testing.T) {
	ps, pa := newTestScorer()

	candidates := []AnalysisCandidate{
		{FilePath: "com/app/LicenseChecker.smali", Content: []byte(smaliLicenseCheck), IsAppCode: true},
		{FilePath: "com/app/security/RootDetector.smali", Content: []byte(smaliRootCheck), IsAppCode: true},
		{FilePath: "com/app/PremiumManager.smali", Content: []byte(smaliPremiumCheck), IsAppCode: true},
		{FilePath: "com/app/User.smali", Content: []byte(smaliGetter), IsAppCode: true},
		{FilePath: "com/app/Helper.smali", Content: []byte(smaliConstructor), IsAppCode: true},
	}

	batchResult := pa.BatchAnalyze(candidates)
	scored := ps.ScoreBatch(batchResult)

	if len(scored) == 0 {
		t.Fatal("Should find some patch points")
	}

	// Проверяем сортировку (по убыванию)
	for i := 1; i < len(scored); i++ {
		if scored[i].Score.FinalScore > scored[i-1].Score.FinalScore {
			t.Errorf("Results not sorted: [%d]=%.1f > [%d]=%.1f",
				i, scored[i].Score.FinalScore, i-1, scored[i-1].Score.FinalScore)
		}
	}

	// Первый должен быть license или root (high score)
	first := scored[0]
	if first.Score.RiskLevel != RiskClassHigh && first.Score.RiskLevel != RiskClassMedium {
		t.Errorf("Top result should be high/medium risk, got %s", first.Score.RiskLevel)
	}
}

func TestScoreConfidenceRange(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/app/LicenseChecker.smali", []byte(smaliLicenseCheck))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])

	if result.Confidence < 0 || result.Confidence > 1 {
		t.Errorf("Confidence %.2f out of range [0, 1]", result.Confidence)
	}
}

func TestExplainScore(t *testing.T) {
	ps, pa := newTestScorer()
	classInfo := pa.AnalyzeSmaliContent("com/app/LicenseChecker.smali", []byte(smaliLicenseCheck))

	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods")
	}

	result := ps.ScoreMethod(&classInfo.Methods[0])
	sm := &ScoredMethod{Method: classInfo.Methods[0], Score: *result}

	explanation := ExplainScore(sm)
	if explanation == "" {
		t.Error("ExplainScore returned empty string")
	}
	if len(explanation) < 50 {
		t.Errorf("Explanation too short: %q", explanation)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TASK 4.2: MULTI-SIGNAL AGGREGATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestSignalWeights_AllTypesDefined(t *testing.T) {
	// Verify all signal types have weights defined
	expectedWeights := map[SignalType]float64{
		SignalName:       1.0,
		SignalStructure:  0.9,
		SignalAPICall:    1.1,
		SignalString:     0.8,
		SignalReturnType: 0.7,
	}

	for signalType, expectedWeight := range expectedWeights {
		weight, exists := SignalWeights[signalType]
		if !exists {
			t.Errorf("SignalWeights missing entry for %s", signalType)
		}
		if weight != expectedWeight {
			t.Errorf("SignalWeights[%s] = %.1f, want %.1f", signalType, weight, expectedWeight)
		}
	}
}

func TestCollectMatchSignals_UsesSignalWeights(t *testing.T) {
	ps, pa := newTestScorer()

	// Create a method with multiple signals
	smali := `
.class public Lcom/app/LicenseChecker;
.super Ljava/lang/Object;

.method public isLicenseValid()Z
    .locals 2
    
    const-string v0, "license_key"
    invoke-static {v0}, Lcom/app/Security;->checkLicense(Ljava/lang/String;)Z
    move-result v1
    
    if-eqz v1, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`

	classInfo := pa.AnalyzeSmaliContent("com/app/LicenseChecker.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods analyzed")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	signals := ps.collectMatchSignals(mi, result)

	// Verify signals use SignalWeights map
	for _, signal := range signals {
		expectedWeight := SignalWeights[signal.Type]
		if signal.Weight != expectedWeight {
			t.Errorf("Signal %s has weight %.1f, expected %.1f from SignalWeights map",
				signal.Type, signal.Weight, expectedWeight)
		}
	}
}

func TestCalculateSignalContributions_EmptySignals(t *testing.T) {
	ps, _ := newTestScorer()

	signals := []MatchSignal{}
	contributions := ps.calculateSignalContributions(signals)

	if len(contributions) != 0 {
		t.Errorf("Expected 0 contributions for empty signals, got %d", len(contributions))
	}
}

func TestCalculateSignalContributions_SingleSignal(t *testing.T) {
	ps, _ := newTestScorer()

	signals := []MatchSignal{
		{
			Type:       SignalName,
			Value:      "isLicenseValid",
			Weight:     SignalWeights[SignalName],
			Confidence: 0.85,
		},
	}

	contributions := ps.calculateSignalContributions(signals)

	if len(contributions) != 1 {
		t.Fatalf("Expected 1 contribution, got %d", len(contributions))
	}

	c := contributions[0]
	if c.SignalType != string(SignalName) {
		t.Errorf("SignalType = %s, want %s", c.SignalType, SignalName)
	}
	if c.Value != "isLicenseValid" {
		t.Errorf("Value = %s, want isLicenseValid", c.Value)
	}
	if c.Weight != 1.0 {
		t.Errorf("Weight = %.1f, want 1.0", c.Weight)
	}
	if c.Confidence != 0.85 {
		t.Errorf("Confidence = %.2f, want 0.85", c.Confidence)
	}

	expectedContribution := 1.0 * 0.85
	if c.Contribution != expectedContribution {
		t.Errorf("Contribution = %.2f, want %.2f (weight * confidence)", c.Contribution, expectedContribution)
	}
}

func TestCalculateSignalContributions_MultipleSignals(t *testing.T) {
	ps, _ := newTestScorer()

	signals := []MatchSignal{
		{
			Type:       SignalName,
			Value:      "isRooted",
			Weight:     SignalWeights[SignalName],
			Confidence: 0.7,
		},
		{
			Type:       SignalStructure,
			Value:      "boolean=true,dual_return=true",
			Weight:     SignalWeights[SignalStructure],
			Confidence: 0.8,
		},
		{
			Type:       SignalAPICall,
			Value:      "Runtime.exec",
			Weight:     SignalWeights[SignalAPICall],
			Confidence: 0.9,
		},
	}

	contributions := ps.calculateSignalContributions(signals)

	if len(contributions) != 3 {
		t.Fatalf("Expected 3 contributions, got %d", len(contributions))
	}

	// Verify each contribution
	expectedContributions := []struct {
		signalType   string
		weight       float64
		confidence   float64
		contribution float64
	}{
		{string(SignalName), 1.0, 0.7, 0.7},
		{string(SignalStructure), 0.9, 0.8, 0.72},
		{string(SignalAPICall), 1.1, 0.9, 0.99},
	}

	const tolerance = 0.0001

	for i, expected := range expectedContributions {
		c := contributions[i]
		if c.SignalType != expected.signalType {
			t.Errorf("contributions[%d].SignalType = %s, want %s", i, c.SignalType, expected.signalType)
		}
		if c.Weight != expected.weight {
			t.Errorf("contributions[%d].Weight = %.1f, want %.1f", i, c.Weight, expected.weight)
		}
		if c.Confidence != expected.confidence {
			t.Errorf("contributions[%d].Confidence = %.1f, want %.1f", i, c.Confidence, expected.confidence)
		}
		if math.Abs(c.Contribution-expected.contribution) > tolerance {
			t.Errorf("contributions[%d].Contribution = %.4f, want %.4f", i, c.Contribution, expected.contribution)
		}
	}
}

func TestCalculateSignalContributions_AllSignalTypes(t *testing.T) {
	ps, _ := newTestScorer()

	// Create signals for all types
	signals := []MatchSignal{
		{Type: SignalName, Value: "checkPremium", Weight: SignalWeights[SignalName], Confidence: 0.85},
		{Type: SignalStructure, Value: "boolean=true", Weight: SignalWeights[SignalStructure], Confidence: 0.8},
		{Type: SignalAPICall, Value: "checkLicense", Weight: SignalWeights[SignalAPICall], Confidence: 0.9},
		{Type: SignalString, Value: "premium", Weight: SignalWeights[SignalString], Confidence: 0.65},
		{Type: SignalReturnType, Value: "Z", Weight: SignalWeights[SignalReturnType], Confidence: 0.7},
	}

	contributions := ps.calculateSignalContributions(signals)

	if len(contributions) != 5 {
		t.Fatalf("Expected 5 contributions (one per signal type), got %d", len(contributions))
	}

	// Verify all signal types are present
	signalTypes := make(map[string]bool)
	for _, c := range contributions {
		signalTypes[c.SignalType] = true

		// Verify contribution calculation
		expectedContribution := c.Weight * c.Confidence
		if c.Contribution != expectedContribution {
			t.Errorf("Signal %s: contribution = %.2f, want %.2f (weight * confidence)",
				c.SignalType, c.Contribution, expectedContribution)
		}
	}

	expectedTypes := []string{
		string(SignalName),
		string(SignalStructure),
		string(SignalAPICall),
		string(SignalString),
		string(SignalReturnType),
	}

	for _, expectedType := range expectedTypes {
		if !signalTypes[expectedType] {
			t.Errorf("Missing signal type in contributions: %s", expectedType)
		}
	}
}

func TestCalculateSignalContributions_WeightedCalculation(t *testing.T) {
	ps, _ := newTestScorer()

	testCases := []struct {
		name           string
		signalType     SignalType
		confidence     float64
		expectedWeight float64
	}{
		{"Name signal", SignalName, 0.8, 1.0},
		{"Structure signal", SignalStructure, 0.75, 0.9},
		{"API call signal", SignalAPICall, 0.85, 1.1},
		{"String signal", SignalString, 0.7, 0.8},
		{"Return type signal", SignalReturnType, 0.65, 0.7},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signals := []MatchSignal{
				{
					Type:       tc.signalType,
					Value:      "test",
					Weight:     SignalWeights[tc.signalType],
					Confidence: tc.confidence,
				},
			}

			contributions := ps.calculateSignalContributions(signals)

			if len(contributions) != 1 {
				t.Fatalf("Expected 1 contribution, got %d", len(contributions))
			}

			c := contributions[0]
			if c.Weight != tc.expectedWeight {
				t.Errorf("Weight = %.1f, want %.1f", c.Weight, tc.expectedWeight)
			}

			expectedContribution := tc.expectedWeight * tc.confidence
			if c.Contribution != expectedContribution {
				t.Errorf("Contribution = %.2f, want %.2f", c.Contribution, expectedContribution)
			}
		})
	}
}

func TestCalculateSignalContributions_IntegrationWithRealMethod(t *testing.T) {
	ps, pa := newTestScorer()

	// Use a real method with multiple signals
	classInfo := pa.AnalyzeSmaliContent("com/app/LicenseChecker.smali", []byte(smaliLicenseCheck))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods analyzed")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	signals := ps.collectMatchSignals(mi, result)
	contributions := ps.calculateSignalContributions(signals)

	// Verify we have contributions
	if len(contributions) == 0 {
		t.Fatal("Expected at least one contribution from license check method")
	}

	// Verify all contributions have valid values
	for i, c := range contributions {
		if c.SignalType == "" {
			t.Errorf("contributions[%d].SignalType is empty", i)
		}
		if c.Weight <= 0 {
			t.Errorf("contributions[%d].Weight = %.2f, should be positive", i, c.Weight)
		}
		if c.Confidence < 0 || c.Confidence > 1 {
			t.Errorf("contributions[%d].Confidence = %.2f, should be in [0, 1]", i, c.Confidence)
		}
		if c.Contribution <= 0 {
			t.Errorf("contributions[%d].Contribution = %.2f, should be positive", i, c.Contribution)
		}

		// Verify contribution calculation
		expectedContribution := c.Weight * c.Confidence
		if c.Contribution != expectedContribution {
			t.Errorf("contributions[%d].Contribution = %.2f, want %.2f (weight * confidence)",
				i, c.Contribution, expectedContribution)
		}
	}
}

func TestCalculateSignalContributions_PreservesSignalData(t *testing.T) {
	ps, _ := newTestScorer()

	signals := []MatchSignal{
		{
			Type:       SignalAPICall,
			Value:      "Runtime.exec,su,busybox",
			Weight:     SignalWeights[SignalAPICall],
			Confidence: 0.9,
		},
		{
			Type:       SignalString,
			Value:      "root,superuser,magisk",
			Weight:     SignalWeights[SignalString],
			Confidence: 0.8,
		},
	}

	contributions := ps.calculateSignalContributions(signals)

	if len(contributions) != 2 {
		t.Fatalf("Expected 2 contributions, got %d", len(contributions))
	}

	// Verify signal values are preserved
	if contributions[0].Value != "Runtime.exec,su,busybox" {
		t.Errorf("First contribution value not preserved: %s", contributions[0].Value)
	}
	if contributions[1].Value != "root,superuser,magisk" {
		t.Errorf("Second contribution value not preserved: %s", contributions[1].Value)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// TASK 4.3: MULTI-SIGNAL BONUS CALCULATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestCalculateMultiSignalBonus_ZeroSignals(t *testing.T) {
	ps, _ := newTestScorer()

	bonus := ps.calculateMultiSignalBonus(0)

	if bonus != 0.0 {
		t.Errorf("calculateMultiSignalBonus(0) = %.2f, want 0.0", bonus)
	}
}

func TestCalculateMultiSignalBonus_OneSignal(t *testing.T) {
	ps, _ := newTestScorer()

	bonus := ps.calculateMultiSignalBonus(1)

	if bonus != 0.0 {
		t.Errorf("calculateMultiSignalBonus(1) = %.2f, want 0.0", bonus)
	}
}

func TestCalculateMultiSignalBonus_TwoSignals(t *testing.T) {
	ps, _ := newTestScorer()

	bonus := ps.calculateMultiSignalBonus(2)

	expected := 0.08 // (2-1) * 0.08 = 0.08
	if bonus != expected {
		t.Errorf("calculateMultiSignalBonus(2) = %.2f, want %.2f", bonus, expected)
	}
}

func TestCalculateMultiSignalBonus_ThreeSignals(t *testing.T) {
	ps, _ := newTestScorer()

	bonus := ps.calculateMultiSignalBonus(3)

	expected := 0.16 // (3-1) * 0.08 = 0.16
	if bonus != expected {
		t.Errorf("calculateMultiSignalBonus(3) = %.2f, want %.2f", bonus, expected)
	}
}

func TestCalculateMultiSignalBonus_FourSignals(t *testing.T) {
	ps, _ := newTestScorer()

	bonus := ps.calculateMultiSignalBonus(4)

	expected := 0.24 // (4-1) * 0.08 = 0.24
	if bonus != expected {
		t.Errorf("calculateMultiSignalBonus(4) = %.2f, want %.2f", bonus, expected)
	}
}

func TestCalculateMultiSignalBonus_FiveSignals_Capped(t *testing.T) {
	ps, _ := newTestScorer()

	bonus := ps.calculateMultiSignalBonus(5)

	// (5-1) * 0.08 = 0.32, but capped at 0.25
	expected := 0.25
	if bonus != expected {
		t.Errorf("calculateMultiSignalBonus(5) = %.2f, want %.2f (capped)", bonus, expected)
	}
}

func TestCalculateMultiSignalBonus_SixSignals_Capped(t *testing.T) {
	ps, _ := newTestScorer()

	bonus := ps.calculateMultiSignalBonus(6)

	// (6-1) * 0.08 = 0.40, but capped at 0.25
	expected := 0.25
	if bonus != expected {
		t.Errorf("calculateMultiSignalBonus(6) = %.2f, want %.2f (capped)", bonus, expected)
	}
}

func TestCalculateMultiSignalBonus_TenSignals_Capped(t *testing.T) {
	ps, _ := newTestScorer()

	bonus := ps.calculateMultiSignalBonus(10)

	// (10-1) * 0.08 = 0.72, but capped at 0.25
	expected := 0.25
	if bonus != expected {
		t.Errorf("calculateMultiSignalBonus(10) = %.2f, want %.2f (capped)", bonus, expected)
	}
}

func TestCalculateMultiSignalBonus_NegativeSignals(t *testing.T) {
	ps, _ := newTestScorer()

	bonus := ps.calculateMultiSignalBonus(-1)

	if bonus != 0.0 {
		t.Errorf("calculateMultiSignalBonus(-1) = %.2f, want 0.0", bonus)
	}
}

func TestCalculateMultiSignalBonus_Formula(t *testing.T) {
	ps, _ := newTestScorer()

	testCases := []struct {
		signalCount int
		expected    float64
		description string
	}{
		{0, 0.0, "zero signals"},
		{1, 0.0, "one signal"},
		{2, 0.08, "two signals: (2-1)*0.08"},
		{3, 0.16, "three signals: (3-1)*0.08"},
		{4, 0.24, "four signals: (4-1)*0.08"},
		{5, 0.25, "five signals: capped at 0.25"},
		{6, 0.25, "six signals: capped at 0.25"},
		{7, 0.25, "seven signals: capped at 0.25"},
		{100, 0.25, "many signals: capped at 0.25"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			bonus := ps.calculateMultiSignalBonus(tc.signalCount)

			if bonus != tc.expected {
				t.Errorf("calculateMultiSignalBonus(%d) = %.2f, want %.2f (%s)",
					tc.signalCount, bonus, tc.expected, tc.description)
			}
		})
	}
}

func TestCalculateMultiSignalBonus_MaximumBonus(t *testing.T) {
	ps, _ := newTestScorer()

	// Test that the maximum bonus is 0.25
	for signalCount := 5; signalCount <= 20; signalCount++ {
		bonus := ps.calculateMultiSignalBonus(signalCount)

		if bonus > 0.25 {
			t.Errorf("calculateMultiSignalBonus(%d) = %.2f, exceeds maximum 0.25",
				signalCount, bonus)
		}

		if bonus != 0.25 {
			t.Errorf("calculateMultiSignalBonus(%d) = %.2f, want 0.25 (maximum)",
				signalCount, bonus)
		}
	}
}

func TestCalculateMultiSignalBonus_MonotonicIncrease(t *testing.T) {
	ps, _ := newTestScorer()

	// Test that bonus increases monotonically until cap
	prevBonus := 0.0
	for signalCount := 1; signalCount <= 10; signalCount++ {
		bonus := ps.calculateMultiSignalBonus(signalCount)

		if bonus < prevBonus {
			t.Errorf("Bonus decreased from %.2f to %.2f at signalCount=%d",
				prevBonus, bonus, signalCount)
		}

		prevBonus = bonus
	}
}

func TestCalculateMultiSignalBonus_IntegrationWithConfidence(t *testing.T) {
	ps, pa := newTestScorer()

	// Create a method with multiple signals
	smali := `
.class public Lcom/app/security/RootChecker;
.super Ljava/lang/Object;

.method public isRooted()Z
    .locals 3
    
    const-string v0, "su"
    const-string v1, "/system/xbin/su"
    
    invoke-static {v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    move-result-object v2
    invoke-virtual {v2}, Ljava/io/File;->exists()Z
    move-result v2
    
    if-eqz v2, :cond_0
    const/4 v0, 0x1
    return v0
    :cond_0
    const/4 v0, 0x0
    return v0
.end method
`

	classInfo := pa.AnalyzeSmaliContent("com/app/security/RootChecker.smali", []byte(smali))
	if len(classInfo.Methods) == 0 {
		t.Fatal("No methods analyzed")
	}

	mi := &classInfo.Methods[0]
	result := ps.ScoreMethod(mi)

	signals := ps.collectMatchSignals(mi, result)
	signalCount := len(signals)

	if signalCount < 2 {
		t.Skipf("Method has only %d signal(s), need at least 2 for multi-signal bonus test", signalCount)
	}

	// Calculate expected bonus
	expectedBonus := ps.calculateMultiSignalBonus(signalCount)

	// Verify bonus is applied (confidence should be higher with multiple signals)
	if expectedBonus == 0.0 {
		t.Errorf("Expected non-zero bonus for %d signals", signalCount)
	}

	// Verify bonus follows formula
	expectedFormula := math.Min(float64(signalCount-1)*0.08, 0.25)
	if expectedBonus != expectedFormula {
		t.Errorf("Bonus %.2f doesn't match formula %.2f for %d signals",
			expectedBonus, expectedFormula, signalCount)
	}
}

func TestCalculateMultiSignalBonus_EdgeCases(t *testing.T) {
	ps, _ := newTestScorer()

	testCases := []struct {
		name        string
		signalCount int
		expected    float64
	}{
		{"Large negative", -100, 0.0},
		{"Negative one", -1, 0.0},
		{"Zero", 0, 0.0},
		{"One", 1, 0.0},
		{"Boundary at two", 2, 0.08},
		{"Just before cap", 4, 0.24},
		{"At cap threshold", 5, 0.25},
		{"Just after cap", 6, 0.25},
		{"Large positive", 1000, 0.25},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bonus := ps.calculateMultiSignalBonus(tc.signalCount)

			if bonus != tc.expected {
				t.Errorf("calculateMultiSignalBonus(%d) = %.2f, want %.2f",
					tc.signalCount, bonus, tc.expected)
			}
		})
	}
}

func TestCalculateMultiSignalBonus_AllSignalCounts(t *testing.T) {
	ps, _ := newTestScorer()

	// Test all signal counts from 0 to 10
	expectedBonuses := map[int]float64{
		0:  0.0,
		1:  0.0,
		2:  0.08,
		3:  0.16,
		4:  0.24,
		5:  0.25,
		6:  0.25,
		7:  0.25,
		8:  0.25,
		9:  0.25,
		10: 0.25,
	}

	for signalCount, expected := range expectedBonuses {
		bonus := ps.calculateMultiSignalBonus(signalCount)

		if bonus != expected {
			t.Errorf("calculateMultiSignalBonus(%d) = %.2f, want %.2f",
				signalCount, bonus, expected)
		}
	}
}
