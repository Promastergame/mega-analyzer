package ml

import (
	"mega-analyzer/pkg/ml/internal/shared"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH STRATEGY INTERFACE
//
// Defines the strategy pattern for intelligent patch generation.
// Each strategy implements different patching approaches (return true/false,
// condition inversion, partial bypass, nop injection, etc.)
//
// Requirements: 1.4 - Support at least 5 patch strategies
// ═══════════════════════════════════════════════════════════════════════════════

// PatchStrategy interface for strategy pattern
type PatchStrategy interface {
	// CanApply checks if this strategy is applicable to the given method
	// in the specified mode (defensive/research)
	//
	// Parameters:
	//   - mi: Method information containing structure, calls, and context
	//   - mode: Operational mode (defensive for fixes, research for bypasses)
	//
	// Returns:
	//   - true if this strategy can be applied to the method
	CanApply(mi *shared.MethodInfo, mode PatchMode) bool

	// Generate creates the patch for the given method
	//
	// Parameters:
	//   - mi: Method information containing structure, calls, and context
	//   - mode: Operational mode (defensive for fixes, research for bypasses)
	//
	// Returns:
	//   - Generated patch with code, explanation, and metadata
	//   - Error if patch generation fails
	Generate(mi *shared.MethodInfo, mode PatchMode) (*GeneratedPatch, error)

	// GetPriority returns the strategy priority
	// Higher values indicate preferred strategies when multiple strategies
	// are applicable to the same method
	//
	// Returns:
	//   - Priority value (higher = preferred)
	GetPriority() int

	// PatchType returns the patch type this strategy produces.
	// Used to correlate vulnerability signals with the most surgical strategy.
	PatchType() PatchType

	// GetDescription returns a human-readable description of what this
	// strategy does and when it should be used
	//
	// Returns:
	//   - Human-readable description string
	GetDescription() string
}
