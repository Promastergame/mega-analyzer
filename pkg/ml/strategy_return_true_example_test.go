package ml

import (
	"fmt"

	"mega-analyzer/pkg/ml/internal/shared"
)

// Example demonstrates how to use ReturnTrueStrategy
func ExampleReturnTrueStrategy() {
	// Create strategy
	strategy := NewReturnTrueStrategy()

	// Create a method info for a root detection method
	mi := &shared.MethodInfo{
		Name:           "isRooted",
		ClassName:      "RootDetector",
		FilePath:       "com/example/security/RootDetector.smali",
		ReturnsBoolean: true,
		ReturnType:     "Z",
		IsPublic:       true,
		IsStatic:       true,
		MethodHeader:   ".method public static isRooted()Z",
		RawBody: []string{
			".method public static isRooted()Z",
			"    .registers 2",
			"    # original root detection code",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}

	// Check if strategy can apply in defensive mode
	if strategy.CanApply(mi, PatchModeDefensive) {
		fmt.Println("Strategy applicable in defensive mode")

		// Generate patch
		patch, err := strategy.Generate(mi, PatchModeDefensive)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		fmt.Printf("Patch Type: %s\n", patch.PatchType)
		fmt.Printf("Mode: %s\n", patch.Mode)
		fmt.Printf("Description: %s\n", patch.Description)
		fmt.Printf("\nExplanation:\n")
		fmt.Printf("  Reason: %s\n", patch.Explanation.Reason)
		fmt.Printf("  Impact: %s\n", patch.Explanation.Impact)
	}

	// Output:
	// Strategy applicable in defensive mode
	// Patch Type: return_true
	// Mode: defensive
	// Description: Return true (0x1)
	//
	// Explanation:
	//   Reason: Method appears to perform root detection but may not detect all root indicators
	//   Impact: App will always detect root, potentially blocking functionality on rooted devices
}

// Example demonstrates ReturnTrueStrategy with premium check in research mode
func ExampleReturnTrueStrategy_premiumCheck() {
	strategy := NewReturnTrueStrategy()

	// Create a method info for a premium check
	mi := &shared.MethodInfo{
		Name:           "isPremium",
		ClassName:      "LicenseChecker",
		FilePath:       "com/example/license/LicenseChecker.smali",
		ReturnsBoolean: true,
		ReturnType:     "Z",
		IsPublic:       true,
		IsStatic:       false,
		MethodHeader:   ".method public isPremium()Z",
		RawBody: []string{
			".method public isPremium()Z",
			"    .registers 3",
			"    # check license",
			"    const/4 v0, 0x0",
			"    return v0",
			".end method",
		},
	}

	// Check if strategy can apply in research mode
	if strategy.CanApply(mi, PatchModeResearch) {
		fmt.Println("Strategy applicable in research mode")

		// Generate patch
		patch, err := strategy.Generate(mi, PatchModeResearch)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		fmt.Printf("Patch Type: %s\n", patch.PatchType)
		fmt.Printf("Mode: %s\n", patch.Mode)
		fmt.Printf("\nExplanation:\n")
		fmt.Printf("  Reason: %s\n", patch.Explanation.Reason)
		fmt.Printf("  Why This Patch: %s\n", patch.Explanation.WhyThisPatch)
		fmt.Printf("  Impact: %s\n", patch.Explanation.Impact)
	}

	// Output:
	// Strategy applicable in research mode
	// Patch Type: return_true
	// Mode: research
	//
	// Explanation:
	//   Reason: Method appears to check premium/license status, blocking access to premium features
	//   Why This Patch: Returning true bypasses the check by indicating premium/paid status, granting access to restricted features
	//   Impact: Premium features will be accessible without valid license
}
