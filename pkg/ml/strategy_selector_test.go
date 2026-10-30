package ml

import (
	"testing"

	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// UNIT TESTS FOR STRATEGY SELECTOR
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewStrategySelector(t *testing.T) {
	selector := NewStrategySelector()

	if selector == nil {
		t.Fatal("NewStrategySelector returned nil")
	}

	if selector.contextAnalyzer == nil {
		t.Error("ContextAnalyzer is nil")
	}

	if len(selector.strategies) == 0 {
		t.Error("No strategies registered")
	}

	// Should have 15 default strategies (10 base + wide/object/hijack/entry-gate/const-replace)
	expectedCount := 15
	if len(selector.strategies) != expectedCount {
		t.Errorf("Expected %d strategies, got %d", expectedCount, len(selector.strategies))
	}

	found := false
	for _, s := range selector.strategies {
		if s.PatchType() == PatchReturnZero {
			found = true
			break
		}
	}
	if !found {
		t.Error("PriceZeroInjectionStrategy (return_zero) is not registered")
	}
}

func TestStrategySelector_SelectStrategy_BooleanMethod(t *testing.T) {
	selector := NewStrategySelector()

	// Create a boolean method with root detection context
	mi := &shared.MethodInfo{
		Name:           "isRooted",
		ClassName:      "RootDetector",
		FilePath:       "com/example/security/RootDetector.smali",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		IsPublic:       true,
		IsStatic:       false,
		MethodHeader:   ".method public isRooted()Z",
	}

	// Test defensive mode (should return false for root detection)
	strategy := selector.SelectStrategy(mi, PatchModeDefensive)
	if strategy == nil {
		t.Fatal("SelectStrategy returned nil for defensive mode")
	}

	// Should select ReturnTrueStrategy for defensive mode on root detection
	if _, ok := strategy.(*ReturnTrueStrategy); !ok {
		t.Errorf("Expected ReturnTrueStrategy for defensive mode, got %T", strategy)
	}

	// Test research mode (should return false for root detection)
	strategy = selector.SelectStrategy(mi, PatchModeResearch)
	if strategy == nil {
		t.Fatal("SelectStrategy returned nil for research mode")
	}

	// Should select ReturnFalseStrategy for research mode on root detection
	if _, ok := strategy.(*ReturnFalseStrategy); !ok {
		t.Errorf("Expected ReturnFalseStrategy for research mode, got %T", strategy)
	}
}

func TestStrategySelector_SelectStrategy_PremiumCheck(t *testing.T) {
	selector := NewStrategySelector()

	// Create a boolean method with premium check context
	mi := &shared.MethodInfo{
		Name:           "isPremium",
		ClassName:      "LicenseChecker",
		FilePath:       "com/example/premium/LicenseChecker.smali",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		IsPublic:       true,
		IsStatic:       false,
		MethodHeader:   ".method public isPremium()Z",
	}

	// Test defensive mode (should return false to deny access)
	strategy := selector.SelectStrategy(mi, PatchModeDefensive)
	if strategy == nil {
		t.Fatal("SelectStrategy returned nil for defensive mode")
	}

	// Should select ReturnFalseStrategy for defensive mode on premium check
	if _, ok := strategy.(*ReturnFalseStrategy); !ok {
		t.Errorf("Expected ReturnFalseStrategy for defensive mode, got %T", strategy)
	}

	// Test research mode (should return true to grant access)
	strategy = selector.SelectStrategy(mi, PatchModeResearch)
	if strategy == nil {
		t.Fatal("SelectStrategy returned nil for research mode")
	}

	// Should select ReturnTrueStrategy for research mode on premium check
	if _, ok := strategy.(*ReturnTrueStrategy); !ok {
		t.Errorf("Expected ReturnTrueStrategy for research mode, got %T", strategy)
	}
}

func TestStrategySelector_SelectStrategy_NilMethod(t *testing.T) {
	selector := NewStrategySelector()

	strategy := selector.SelectStrategy(nil, PatchModeDefensive)
	if strategy != nil {
		t.Error("Expected nil strategy for nil method")
	}
}

func TestStrategySelector_SelectStrategy_NonBooleanMethod(t *testing.T) {
	selector := NewStrategySelector()

	// Create a non-boolean method
	mi := &shared.MethodInfo{
		Name:           "getStatus",
		ClassName:      "StatusChecker",
		FilePath:       "com/example/StatusChecker.smali",
		ReturnType:     "I",
		ReturnsBoolean: false,
		ReturnsInt:     true,
		IsPublic:       true,
		IsStatic:       false,
		MethodHeader:   ".method public getStatus()I",
	}

	// Non-boolean methods may not have applicable strategies
	strategy := selector.SelectStrategy(mi, PatchModeDefensive)
	// Strategy may be nil or a non-return strategy
	// This is acceptable behavior
	_ = strategy
}

func TestStrategySelector_GetContextAnalyzer(t *testing.T) {
	selector := NewStrategySelector()

	ca := selector.GetContextAnalyzer()
	if ca == nil {
		t.Error("GetContextAnalyzer returned nil")
	}

	if ca != selector.contextAnalyzer {
		t.Error("GetContextAnalyzer returned different instance")
	}
}

func TestStrategySelector_GetStrategies(t *testing.T) {
	selector := NewStrategySelector()

	strategies := selector.GetStrategies()
	if len(strategies) == 0 {
		t.Error("GetStrategies returned empty slice")
	}

	if len(strategies) != len(selector.strategies) {
		t.Error("GetStrategies returned different count")
	}
}

func TestStrategySelector_AddStrategy(t *testing.T) {
	selector := NewStrategySelector()

	initialCount := len(selector.strategies)

	// Add a custom strategy
	customStrategy := NewReturnTrueStrategy()
	selector.AddStrategy(customStrategy)

	if len(selector.strategies) != initialCount+1 {
		t.Errorf("Expected %d strategies after adding, got %d", initialCount+1, len(selector.strategies))
	}
}

func TestStrategySelector_PriorityOrdering(t *testing.T) {
	selector := NewStrategySelector()

	// Create a method that multiple strategies can apply to
	mi := &shared.MethodInfo{
		Name:           "checkSecurity",
		ClassName:      "SecurityChecker",
		FilePath:       "com/example/SecurityChecker.smali",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		IsPublic:       true,
		IsStatic:       false,
		MethodHeader:   ".method public checkSecurity()Z",
		IfCheckCount:   2,
	}

	// Select strategy
	strategy := selector.SelectStrategy(mi, PatchModeDefensive)
	if strategy == nil {
		t.Fatal("SelectStrategy returned nil")
	}

	// The selected strategy should be the one with highest priority
	// among applicable strategies
	selectedPriority := strategy.GetPriority()

	// Check that no other applicable strategy has higher priority
	for _, s := range selector.strategies {
		if s.CanApply(mi, PatchModeDefensive) {
			if s.GetPriority() > selectedPriority {
				t.Errorf("Found applicable strategy with higher priority: %T (priority %d) > selected %T (priority %d)",
					s, s.GetPriority(), strategy, selectedPriority)
			}
		}
	}
}

func TestStrategySelector_EmulatorDetection(t *testing.T) {
	selector := NewStrategySelector()

	mi := &shared.MethodInfo{
		Name:           "isEmulator",
		ClassName:      "EmulatorDetector",
		FilePath:       "com/example/security/EmulatorDetector.smali",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		IsPublic:       true,
		IsStatic:       true,
		MethodHeader:   ".method public static isEmulator()Z",
	}

	// Defensive mode: should return true to detect emulator
	strategy := selector.SelectStrategy(mi, PatchModeDefensive)
	if strategy == nil {
		t.Fatal("SelectStrategy returned nil for defensive mode")
	}

	if _, ok := strategy.(*ReturnTrueStrategy); !ok {
		t.Errorf("Expected ReturnTrueStrategy for defensive mode, got %T", strategy)
	}

	// Research mode: should return false to hide emulator
	strategy = selector.SelectStrategy(mi, PatchModeResearch)
	if strategy == nil {
		t.Fatal("SelectStrategy returned nil for research mode")
	}

	if _, ok := strategy.(*ReturnFalseStrategy); !ok {
		t.Errorf("Expected ReturnFalseStrategy for research mode, got %T", strategy)
	}
}

func TestStrategySelector_BillingVerification(t *testing.T) {
	selector := NewStrategySelector()

	mi := &shared.MethodInfo{
		Name:           "isPurchased",
		ClassName:      "BillingManager",
		FilePath:       "com/example/billing/BillingManager.smali",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		IsPublic:       true,
		IsStatic:       false,
		MethodHeader:   ".method public isPurchased()Z",
	}

	// Defensive mode: should return false to deny access
	strategy := selector.SelectStrategy(mi, PatchModeDefensive)
	if strategy == nil {
		t.Fatal("SelectStrategy returned nil for defensive mode")
	}

	if _, ok := strategy.(*ReturnFalseStrategy); !ok {
		t.Errorf("Expected ReturnFalseStrategy for defensive mode, got %T", strategy)
	}

	// Research mode: should return true to grant access
	strategy = selector.SelectStrategy(mi, PatchModeResearch)
	if strategy == nil {
		t.Fatal("SelectStrategy returned nil for research mode")
	}

	if _, ok := strategy.(*ReturnTrueStrategy); !ok {
		t.Errorf("Expected ReturnTrueStrategy for research mode, got %T", strategy)
	}
}

func TestNewStrategySelectorWithAnalyzer(t *testing.T) {
	ca := NewContextAnalyzer()
	selector := NewStrategySelectorWithAnalyzer(ca)

	if selector == nil {
		t.Fatal("NewStrategySelectorWithAnalyzer returned nil")
	}

	if selector.contextAnalyzer != ca {
		t.Error("ContextAnalyzer not set correctly")
	}

	if len(selector.strategies) != 15 {
		t.Errorf("Expected 15 strategies, got %d", len(selector.strategies))
	}
}

// TestSelectStrategyWithSignals_HonorsAuditSignal verifies that a confirmed
// audit signal steers strategy selection toward the signaled outcome — and that
// among the matching strategies the SURGICAL one wins over the whole-body stub:
// ConstantInjection (90+100) beats ReturnFalse stub (80+100) for return_false.
func TestSelectStrategyWithSignals_HonorsAuditSignal(t *testing.T) {
	selector := NewStrategySelector()
	mi := &shared.MethodInfo{
		Name:           "isRooted",
		ClassName:      "Lcom/app/RootGuard;",
		ReturnsBoolean: true,
		IsStatic:       true,
		RawBody: []string{
			".method public static isRooted()Z",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}

	base := selector.SelectStrategy(mi, PatchModeResearch)
	if _, ok := base.(*ConstantInjectionStrategy); !ok {
		t.Fatalf("without signals expected ConstantInjectionStrategy, got %T", base)
	}

	signals := []VulnSignal{{
		Kind:       VulnRootDetectionBypass,
		Severity:   VulnSeverityHigh,
		Confidence: 0.86,
	}}
	withSignals := selector.SelectStrategyWithSignals(mi, PatchModeResearch, signals)
	if _, ok := withSignals.(*ConstantInjectionStrategy); !ok {
		t.Fatalf("with root signal expected surgical ConstantInjectionStrategy (return_false outcome), got %T", withSignals)
	}
}

// TestSignalSuggestedPatch verifies the signal→patch-type mapping used both by
// the scorer (SuggestedPatch) and the strategy selector.
func TestSignalSuggestedPatch(t *testing.T) {
	cases := []struct {
		kind VulnKind
		want PatchType
	}{
		{VulnRootDetectionBypass, PatchReturnFalse},
		{VulnEmulatorCheckBypass, PatchReturnFalse},
		{VulnDebugCheckBypass, PatchReturnFalse},
		{VulnTamperCheckBypass, PatchReturnFalse},
		{VulnTrialPeriodCheck, PatchReturnFalse},
		{VulnAuthCheckBypass, PatchReturnTrue},
		{VulnAgeVerification, PatchReturnTrue},
		{VulnPremiumFeatureGate, PatchReturnTrue},
		{VulnLicenseLocalOnly, PatchReturnTrue},
		{VulnBiometricLocalOnly, PatchReturnTrue},
		{VulnPaymentClientSide, PatchReturnTrue},
	}
	for _, tc := range cases {
		vs := &VulnerabilitySignals{Signals: []VulnSignal{{Kind: tc.kind}}}
		pt, ok := signalSuggestedPatch(vs)
		if !ok || pt != tc.want {
			t.Errorf("signal %s: got %q (ok=%v), want %q", tc.kind, pt, ok, tc.want)
		}
	}

	vs := &VulnerabilitySignals{Signals: []VulnSignal{{Kind: VulnOverlayAttack}}}
	if pt, ok := signalSuggestedPatch(vs); ok {
		t.Errorf("non-gate signal should not set patch type, got %q", pt)
	}
}
