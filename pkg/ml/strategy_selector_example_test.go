package ml

import (
	"fmt"

	"mega-analyzer/pkg/ml/internal/shared"
)

// Example demonstrating StrategySelector usage for root detection in defensive mode
func ExampleStrategySelector_defensive() {
	selector := NewStrategySelector()

	// Create a method representing root detection
	mi := &shared.MethodInfo{
		Name:           "isRooted",
		ClassName:      "RootDetector",
		FilePath:       "com/example/security/RootDetector.smali",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		IsPublic:       true,
		MethodHeader:   ".method public isRooted()Z",
	}

	// Select strategy for defensive mode
	strategy := selector.SelectStrategy(mi, PatchModeDefensive)
	if strategy != nil {
		fmt.Printf("Selected strategy: %s\n", strategy.GetDescription())
		fmt.Printf("Priority: %d\n", strategy.GetPriority())
	}

	// Output:
	// Selected strategy: Returns true (0x1) for boolean methods. Used for threat detection in defensive mode or access granting in research mode.
	// Priority: 80
}

// Example demonstrating StrategySelector usage for premium check in research mode
func ExampleStrategySelector_research() {
	selector := NewStrategySelector()

	// Create a method representing premium check
	mi := &shared.MethodInfo{
		Name:           "isPremium",
		ClassName:      "LicenseChecker",
		FilePath:       "com/example/premium/LicenseChecker.smali",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		IsPublic:       true,
		MethodHeader:   ".method public isPremium()Z",
	}

	// Select strategy for research mode
	strategy := selector.SelectStrategy(mi, PatchModeResearch)
	if strategy != nil {
		fmt.Printf("Selected strategy: %s\n", strategy.GetDescription())
		fmt.Printf("Priority: %d\n", strategy.GetPriority())
	}

	// Output:
	// Selected strategy: Returns true (0x1) for boolean methods. Used for threat detection in defensive mode or access granting in research mode.
	// Priority: 80
}

// Example demonstrating context-aware strategy selection
func ExampleStrategySelector_contextAware() {
	selector := NewStrategySelector()

	// Root detection method
	rootMethod := &shared.MethodInfo{
		Name:           "checkRoot",
		ClassName:      "SecurityChecker",
		FilePath:       "com/example/SecurityChecker.smali",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		IsPublic:       true,
		MethodHeader:   ".method public checkRoot()Z",
	}

	// Billing verification method
	billingMethod := &shared.MethodInfo{
		Name:           "isPurchased",
		ClassName:      "BillingManager",
		FilePath:       "com/example/billing/BillingManager.smali",
		ReturnType:     "Z",
		ReturnsBoolean: true,
		IsPublic:       true,
		MethodHeader:   ".method public isPurchased()Z",
	}

	// Both methods in research mode
	rootStrategy := selector.SelectStrategy(rootMethod, PatchModeResearch)
	billingStrategy := selector.SelectStrategy(billingMethod, PatchModeResearch)

	fmt.Printf("Root detection strategy: %T\n", rootStrategy)
	fmt.Printf("Billing strategy: %T\n", billingStrategy)

	// Output:
	// Root detection strategy: *ml.ReturnFalseStrategy
	// Billing strategy: *ml.ReturnTrueStrategy
}
