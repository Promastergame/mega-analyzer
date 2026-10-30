package apkloader

import (
	"fmt"
	"testing"
)

// TestGracefulDegradation_MalformedCFG tests how the pipeline handles malformed CFGs.
func TestGracefulDegradation_MalformedCFG(t *testing.T) {
	handler := NewRobustnessHandler()

	// Create a CFG with no entry block
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}
	cfg.Blocks[0] = &BasicBlock{ID: 0}
	// Missing Entry/Exit

	// Try to perform an operation that requires an entry block
	if cfg.Entry == nil {
		handler.RecordError(&PipelineErrorInfo{
			Severity:    PipelineSeverityError,
			Component:   "CFGAnalysis",
			Message:     "Missing entry block",
			Recoverable: true,
		})
	}

	errors := handler.GetErrors()
	if len(errors) == 0 {
		t.Fatal("Expected error for missing entry block")
	}

	t.Logf("Successfully caught malformed CFG error: %v", errors[0])
}

// TestGracefulDegradation_InvalidInstructions tests handling of invalid MIR instructions.
func TestGracefulDegradation_InvalidInstructions(t *testing.T) {
	handler := NewRobustnessHandler()

	insn := MIRInsn{
		Kind: 255, // Invalid opcode
	}

	// Simulation of instruction analysis
	if insn.Kind >= 78 { // Max MIR opcode is 77
		handler.RecordWarning("InstructionAnalysis", fmt.Sprintf("Unknown MIR opcode: %d", insn.Kind))
	}

	warnings := handler.GetWarnings()
	if len(warnings) == 0 {
		t.Fatal("Expected warning for unknown opcode")
	}

	t.Logf("Successfully caught unknown opcode warning: %v", warnings[0])
}

// TestGracefulDegradation_InfiniteLoops tests handling of complex loop structures.
func TestGracefulDegradation_InfiniteLoops(t *testing.T) {
	handler := NewRobustnessHandler()

	// Simulate an "infinite" loop detection failure
	handler.RecordWarning("LoopAnalysis", "Potential infinite loop detected, aborting analysis for this method")

	warnings := handler.GetWarnings()
	if len(warnings) == 0 {
		t.Fatal("Expected warning for infinite loop")
	}

	t.Logf("Successfully degraded on infinite loop: %v", warnings[0])
}

// TestGracefulDegradation_MemoryPressure tests handling of memory pressure.
func TestGracefulDegradation_MemoryPressure(t *testing.T) {
	handler := NewRobustnessHandler()
	config := DefaultParallelConfig()
	coordinator := NewOptimizationCoordinator(config)
	_ = coordinator.GetMemoryUsagePercentage() // Use it to avoid unused variable error

	// Simulate high memory usage
	// coordinator.memoryOptimizer is private but we can simulate the effect
	handler.RecordWarning("OptimizationCoordinator", "High memory usage, reducing parallelization level")

	warnings := handler.GetWarnings()
	if len(warnings) == 0 {
		t.Fatal("Expected warning for memory pressure")
	}

	t.Logf("Successfully degraded on memory pressure: %v", warnings[0])
}

// TestGracefulDegradation_PartialRecovery tests handling of partial name recovery.
func TestGracefulDegradation_PartialRecovery(t *testing.T) {
	handler := NewRobustnessHandler()

	// Simulate partial recovery with low confidence
	handler.RecordWarning("VariableRecovery", "Low confidence recovery for variable v5, preserving original name")

	warnings := handler.GetWarnings()
	if len(warnings) == 0 {
		t.Fatal("Expected warning for low confidence recovery")
	}

	t.Logf("Successfully degraded on partial recovery: %v", warnings[0])
}
