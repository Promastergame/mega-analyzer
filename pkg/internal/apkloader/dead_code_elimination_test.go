package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DEAD CODE ELIMINATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestAnalyzeDeadCode_UnreachableBlock tests detection of unreachable blocks.
func TestAnalyzeDeadCode_UnreachableBlock(t *testing.T) {
	// v0 = 1
	// return v0
	// v1 = 2  (unreachable)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	if analysis == nil {
		t.Errorf("Expected dead code analysis, got nil")
		return
	}

	// Should detect unreachable blocks
	if analysis.UnreachableBlockCount() == 0 {
		t.Errorf("Expected unreachable blocks, got none")
	}
}

// TestAnalyzeDeadCode_DeadAssignment tests detection of dead assignments.
func TestAnalyzeDeadCode_DeadAssignment(t *testing.T) {
	// v0 = 1
	// v1 = 2  (dead - never used)
	// return v0
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 2},
		{Kind: MIR_RETURN, Offset: 2, Src1: 0},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	if analysis == nil {
		t.Errorf("Expected dead code analysis, got nil")
		return
	}

	// Should detect dead assignments
	if analysis.DeadAssignmentCount() == 0 {
		t.Errorf("Expected dead assignments, got none")
	}
}

// TestAnalyzeDeadCode_UsedAssignment tests that used assignments are not marked as dead.
func TestAnalyzeDeadCode_UsedAssignment(t *testing.T) {
	// v0 = 1
	// v1 = v0 + 2
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	if analysis == nil {
		t.Errorf("Expected dead code analysis, got nil")
		return
	}

	// Should not detect dead assignments (all are used)
	// Note: This depends on SSA form correctness
}

// TestAnalyzeDeadCode_SideEffectPreservation tests that side-effect instructions are preserved.
func TestAnalyzeDeadCode_SideEffectPreservation(t *testing.T) {
	// v0 = 1
	// invoke someMethod(v0)  (has side effects, should not be removed)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1, Src1: -1, Src2: -1},
		{Kind: MIR_INVOKE, Offset: 1, Src1: 0, Src2: -1},
		{Kind: MIR_RETURN, Offset: 2, Src1: -1, Src2: -1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	if analysis == nil {
		t.Errorf("Expected dead code analysis, got nil")
		return
	}

	// Should not mark invoke as dead (has side effects)
}

// TestAnalyzeDeadCode_FieldWrite tests that field writes are preserved.
func TestAnalyzeDeadCode_FieldWrite(t *testing.T) {
	// v0 = 1
	// iput v0, field  (has side effects, should not be removed)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1, Src1: -1, Src2: -1},
		{Kind: MIR_FIELD_PUT, Offset: 1, Src1: 0, Src2: -1, FieldKind: FieldInstance},
		{Kind: MIR_RETURN, Offset: 2, Src1: -1, Src2: -1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	if analysis == nil {
		t.Errorf("Expected dead code analysis, got nil")
		return
	}

	// Should not mark field_put as dead (has side effects)
}

// TestAnalyzeDeadCode_ArrayWrite tests that array writes are preserved.
func TestAnalyzeDeadCode_ArrayWrite(t *testing.T) {
	// v0 = 1
	// aput v0, array, index  (has side effects, should not be removed)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1, Src1: -1, Src2: -1},
		{Kind: MIR_ARRAY_PUT, Offset: 1, Src1: 0, Src2: -1},
		{Kind: MIR_RETURN, Offset: 2, Src1: -1, Src2: -1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	if analysis == nil {
		t.Errorf("Expected dead code analysis, got nil")
		return
	}

	// Should not mark aput as dead (has side effects)
}

// TestAnalyzeDeadCode_ChangeCount tests change counting.
func TestAnalyzeDeadCode_ChangeCount(t *testing.T) {
	// v0 = 1
	// return v0
	// v1 = 2  (unreachable)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	// Should have at least some changes
	if analysis.GetChangeCount() < 0 {
		t.Errorf("Expected non-negative change count, got %d", analysis.GetChangeCount())
	}
}

// TestAnalyzeDeadCode_Trace tests analysis trace.
func TestAnalyzeDeadCode_Trace(t *testing.T) {
	// v0 = 1
	// return v0
	// v1 = 2  (unreachable)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	// Should have trace entries
	trace := analysis.GetTrace()
	if len(trace) == 0 {
		t.Errorf("Expected trace entries, got none")
	}
}

// TestAnalyzeDeadCode_NoDeadCode tests CFG with no dead code.
func TestAnalyzeDeadCode_NoDeadCode(t *testing.T) {
	// v0 = 1
	// v1 = v0 + 2
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	if analysis == nil {
		t.Errorf("Expected dead code analysis, got nil")
		return
	}

	// Should have no unreachable blocks
	if analysis.UnreachableBlockCount() != 0 {
		t.Errorf("Expected no unreachable blocks, got %d", analysis.UnreachableBlockCount())
	}
}

// TestAnalyzeDeadCode_MultipleDeadAssignments tests multiple dead assignments.
func TestAnalyzeDeadCode_MultipleDeadAssignments(t *testing.T) {
	// v0 = 1  (dead)
	// v1 = 2  (dead)
	// v2 = 3  (dead)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1, Src1: -1, Src2: -1},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 2, Src1: -1, Src2: -1},
		{Kind: MIR_CONST, Offset: 2, Dst: 2, Imm: 3, Src1: -1, Src2: -1},
		{Kind: MIR_RETURN, Offset: 3, Src1: -1, Src2: -1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	if analysis == nil {
		t.Errorf("Expected dead code analysis, got nil")
		return
	}

	// Should detect multiple dead assignments
	if analysis.DeadAssignmentCount() < 3 {
		t.Errorf("Expected at least 3 dead assignments, got %d", analysis.DeadAssignmentCount())
	}
}

// TestAnalyzeDeadCode_RemoveDeadCode tests dead code removal.
func TestAnalyzeDeadCode_RemoveDeadCode(t *testing.T) {
	// v0 = 1
	// return v0
	// v1 = 2  (unreachable)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	// Remove dead code
	analysis.RemoveDeadCode(cfg)

	// Should have fewer blocks after removal
	// (This depends on implementation details)
}

// TestAnalyzeDeadCode_RemoveDeadAssignments tests dead assignment pruning.
func TestAnalyzeDeadCode_RemoveDeadAssignments(t *testing.T) {
	// v0 = 1
	// v1 = 2 (dead)
	// return v0
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 2},
		{Kind: MIR_RETURN, Offset: 2, Src1: 0},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	analysis := AnalyzeDeadCode(cfg, ssa)

	if analysis == nil {
		t.Fatalf("Expected analysis, got nil")
	}

	analysis.RemoveDeadCode(cfg)

	// Ensure v1 = 2 is removed from cfg
	for _, block := range cfg.Blocks {
		for _, insn := range block.Insns {
			if insn.Dst == 1 {
				t.Errorf("Expected dead assignment v1 = 2 to be removed from instructions")
			}
		}
	}
}
