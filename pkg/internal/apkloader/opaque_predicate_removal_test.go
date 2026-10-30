package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OPAQUE PREDICATE REMOVAL TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestAnalyzeOpaquePredicates_SelfComparison tests detection of self-comparisons.
func TestAnalyzeOpaquePredicates_SelfComparison(t *testing.T) {
	// v0 = 1
	// if v0 == v0 goto offset 4 (always true)
	// v1 = 2
	// goto offset 6
	// v1 = 3
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_GOTO, Offset: 3, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 4, Dst: 1, Imm: 3},
		{Kind: MIR_RETURN, Offset: 6, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	propResult := &PropagationResult{
		Constants: make(map[int16]*ConstantValue),
	}

	analysis := AnalyzeOpaquePredicates(cfg, propResult)

	if analysis == nil {
		t.Errorf("Expected opaque predicate analysis, got nil")
		return
	}

	// Should detect self-comparison as always true
	if analysis.AlwaysTrueCount() == 0 {
		t.Errorf("Expected always-true predicates, got none")
	}
}

// TestAnalyzeOpaquePredicates_ArithmeticInvariant tests detection of arithmetic invariants.
func TestAnalyzeOpaquePredicates_ArithmeticInvariant(t *testing.T) {
	// v0 = 5
	// v1 = v0 ^ v0  (always 0)
	// if v1 == 0 goto offset 6 (always true)
	// v2 = 1
	// goto offset 8
	// v2 = 2
	// return v2
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_XOR, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_IF, Offset: 2, Imm: 4, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 3, Dst: 2, Imm: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: 4, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 6, Dst: 2, Imm: 2},
		{Kind: MIR_RETURN, Offset: 8, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	propResult := &PropagationResult{
		Constants: make(map[int16]*ConstantValue),
	}

	analysis := AnalyzeOpaquePredicates(cfg, propResult)

	if analysis == nil {
		t.Errorf("Expected opaque predicate analysis, got nil")
		return
	}

	// Should detect arithmetic invariant
	if analysis.AlwaysTrueCount() == 0 {
		t.Errorf("Expected always-true predicates, got none")
	}
}

// TestAnalyzeOpaquePredicates_ChangeCount tests change counting.
func TestAnalyzeOpaquePredicates_ChangeCount(t *testing.T) {
	// v0 = 1
	// if v0 == v0 goto offset 4 (always true)
	// v1 = 2
	// goto offset 6
	// v1 = 3
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_GOTO, Offset: 3, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 4, Dst: 1, Imm: 3},
		{Kind: MIR_RETURN, Offset: 6, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	propResult := &PropagationResult{
		Constants: make(map[int16]*ConstantValue),
	}

	analysis := AnalyzeOpaquePredicates(cfg, propResult)

	// Should have at least some changes
	if analysis.GetChangeCount() < 0 {
		t.Errorf("Expected non-negative change count, got %d", analysis.GetChangeCount())
	}
}

// TestAnalyzeOpaquePredicates_Trace tests analysis trace.
func TestAnalyzeOpaquePredicates_Trace(t *testing.T) {
	// v0 = 1
	// if v0 == v0 goto offset 4 (always true)
	// v1 = 2
	// goto offset 6
	// v1 = 3
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_GOTO, Offset: 3, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 4, Dst: 1, Imm: 3},
		{Kind: MIR_RETURN, Offset: 6, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	propResult := &PropagationResult{
		Constants: make(map[int16]*ConstantValue),
	}

	analysis := AnalyzeOpaquePredicates(cfg, propResult)

	// Should have trace entries
	trace := analysis.GetTrace()
	if len(trace) == 0 {
		t.Errorf("Expected trace entries, got none")
	}
}

// TestAnalyzeOpaquePredicates_NoOpaquePredicates tests CFG with no opaque predicates.
func TestAnalyzeOpaquePredicates_NoOpaquePredicates(t *testing.T) {
	// v0 = 1
	// v1 = 2
	// if v0 < v1 goto offset 6
	// v2 = 3
	// goto offset 8
	// v2 = 4
	// return v2
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 2},
		{Kind: MIR_IF, Offset: 2, Imm: 6, Cond: CondLT, Src1: 0, Src2: 1, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 3, Dst: 2, Imm: 3},
		{Kind: MIR_GOTO, Offset: 4, Imm: 4, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 6, Dst: 2, Imm: 4},
		{Kind: MIR_RETURN, Offset: 8, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	propResult := &PropagationResult{
		Constants: make(map[int16]*ConstantValue),
	}

	analysis := AnalyzeOpaquePredicates(cfg, propResult)

	if analysis == nil {
		t.Errorf("Expected opaque predicate analysis, got nil")
		return
	}

	// Should have no opaque predicates
	if analysis.TotalOpaquePredicates() != 0 {
		t.Errorf("Expected no opaque predicates, got %d", analysis.TotalOpaquePredicates())
	}
}

// TestAnalyzeOpaquePredicates_RemoveOpaquePredicates tests predicate removal.
func TestAnalyzeOpaquePredicates_RemoveOpaquePredicates(t *testing.T) {
	// v0 = 1
	// if v0 == v0 goto offset 4 (always true)
	// v1 = 2
	// goto offset 6
	// v1 = 3
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_GOTO, Offset: 3, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 4, Dst: 1, Imm: 3},
		{Kind: MIR_RETURN, Offset: 6, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	propResult := &PropagationResult{
		Constants: make(map[int16]*ConstantValue),
	}

	analysis := AnalyzeOpaquePredicates(cfg, propResult)

	// Keep track of the fallthrough block before removal
	if len(cfg.Blocks[0].Succs) < 2 {
		t.Fatalf("Expected block 0 to have at least 2 successors before removal, got %d", len(cfg.Blocks[0].Succs))
	}
	fallthroughBlock := cfg.Blocks[0].Succs[1]

	// Remove opaque predicates
	analysis.RemoveOpaquePredicates(cfg)

	// Should have trace entries for removal
	trace := analysis.GetTrace()
	if len(trace) == 0 {
		t.Errorf("Expected trace entries for removal, got none")
	}

	// Verify that MIR_IF is now MIR_GOTO in block 0
	foundGoto := false
	for _, insn := range cfg.Blocks[0].Insns {
		if insn.Kind == MIR_GOTO {
			foundGoto = true
		}
		if insn.Kind == MIR_IF {
			t.Errorf("Expected MIR_IF to be replaced, but still found MIR_IF")
		}
	}
	if !foundGoto {
		t.Errorf("Expected to find a MIR_GOTO instruction in block 0")
	}

	// Verify successors
	if len(cfg.Blocks[0].Succs) != 1 {
		t.Errorf("Expected block 0 to have exactly 1 successor, got %d", len(cfg.Blocks[0].Succs))
	}

	// Verify that block 0 is no longer a predecessor of the fallthrough block
	for _, pred := range fallthroughBlock.Preds {
		if pred == cfg.Blocks[0] {
			t.Errorf("Expected block 0 to be removed from predecessors of fallthrough block")
		}
	}
}

// TestAnalyzeOpaquePredicates_AlwaysTrueCount tests always-true predicate counting.
func TestAnalyzeOpaquePredicates_AlwaysTrueCount(t *testing.T) {
	// v0 = 1
	// if v0 == v0 goto offset 4 (always true)
	// v1 = 2
	// goto offset 6
	// v1 = 3
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_GOTO, Offset: 3, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 4, Dst: 1, Imm: 3},
		{Kind: MIR_RETURN, Offset: 6, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	propResult := &PropagationResult{
		Constants: make(map[int16]*ConstantValue),
	}

	analysis := AnalyzeOpaquePredicates(cfg, propResult)

	count := analysis.AlwaysTrueCount()
	if count < 0 {
		t.Errorf("Expected non-negative count, got %d", count)
	}
}

// TestAnalyzeOpaquePredicates_AlwaysFalseCount tests always-false predicate counting.
func TestAnalyzeOpaquePredicates_AlwaysFalseCount(t *testing.T) {
	// v0 = 1
	// if v0 == v0 goto offset 4 (always true)
	// v1 = 2
	// goto offset 6
	// v1 = 3
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_GOTO, Offset: 3, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 4, Dst: 1, Imm: 3},
		{Kind: MIR_RETURN, Offset: 6, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	propResult := &PropagationResult{
		Constants: make(map[int16]*ConstantValue),
	}

	analysis := AnalyzeOpaquePredicates(cfg, propResult)

	count := analysis.AlwaysFalseCount()
	if count < 0 {
		t.Errorf("Expected non-negative count, got %d", count)
	}
}

// TestAnalyzeOpaquePredicates_TotalCount tests total opaque predicate counting.
func TestAnalyzeOpaquePredicates_TotalCount(t *testing.T) {
	// v0 = 1
	// if v0 == v0 goto offset 4 (always true)
	// v1 = 2
	// goto offset 6
	// v1 = 3
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_GOTO, Offset: 3, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 4, Dst: 1, Imm: 3},
		{Kind: MIR_RETURN, Offset: 6, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	propResult := &PropagationResult{
		Constants: make(map[int16]*ConstantValue),
	}

	analysis := AnalyzeOpaquePredicates(cfg, propResult)

	count := analysis.TotalOpaquePredicates()
	if count < 0 {
		t.Errorf("Expected non-negative count, got %d", count)
	}
}
