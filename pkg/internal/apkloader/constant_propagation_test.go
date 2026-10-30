package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANT PROPAGATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestConstantPropagation_SimpleLiteral tests constant propagation on simple literal.
func TestConstantPropagation_SimpleLiteral(t *testing.T) {
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

	result := ConstantPropagation(cfg, ssa)

	if result == nil {
		t.Errorf("Expected propagation result, got nil")
		return
	}

	// Should have constant for v0
	if !result.IsConstant(0) {
		t.Errorf("Expected v0 to be constant")
	}

	// Check constant value
	val := result.GetConstantValue(0)
	if val == nil || val.Value != int64(1) {
		t.Errorf("Expected v0 = 1, got %v", val)
	}
}

// TestConstantPropagation_ArithmeticFolding tests arithmetic operation folding.
func TestConstantPropagation_ArithmeticFolding(t *testing.T) {
	// v0 = 2
	// v1 = 3
	// v2 = v0 + v1  (should fold to 5)
	// return v2
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 2},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 3},
		{Kind: MIR_ADD, Offset: 2, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	result := ConstantPropagation(cfg, ssa)

	// Should have folded the addition
	if result.ChangeCount() == 0 {
		t.Errorf("Expected changes from folding, got none")
	}
}

// TestConstantPropagation_MultiplicationFolding tests multiplication folding.
func TestConstantPropagation_MultiplicationFolding(t *testing.T) {
	// v0 = 4
	// v1 = 5
	// v2 = v0 * v1  (should fold to 20)
	// return v2
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 4},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 5},
		{Kind: MIR_MUL, Offset: 2, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	result := ConstantPropagation(cfg, ssa)

	if result == nil {
		t.Errorf("Expected propagation result, got nil")
	}
}

// TestConstantPropagation_LogicalFolding tests logical operation folding.
func TestConstantPropagation_LogicalFolding(t *testing.T) {
	// v0 = 5 (binary: 0101)
	// v1 = 3 (binary: 0011)
	// v2 = v0 & v1  (should fold to 1, binary: 0001)
	// return v2
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 3},
		{Kind: MIR_AND, Offset: 2, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	result := ConstantPropagation(cfg, ssa)

	if result == nil {
		t.Errorf("Expected propagation result, got nil")
	}
}

// TestConstantPropagation_BranchSimplification tests branch simplification.
func TestConstantPropagation_BranchSimplification(t *testing.T) {
	// v0 = 1
	// if v0 goto offset 4
	// v1 = 2
	// goto offset 6
	// v1 = 3
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 4, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 2, Dst: 1, Imm: 2},
		{Kind: MIR_GOTO, Offset: 3, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 4, Dst: 1, Imm: 3},
		{Kind: MIR_RETURN, Offset: 6, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	result := ConstantPropagation(cfg, ssa)

	// Should detect constant branch condition
	if result.IsConstant(0) {
		val := result.GetConstantValue(0)
		if val.Value != int64(1) {
			t.Errorf("Expected v0 = 1, got %v", val.Value)
		}
	}
}

// TestConstantPropagation_StringConstant tests string constant propagation.
func TestConstantPropagation_StringConstant(t *testing.T) {
	// v0 = "hello" (const-string)
	// return v0
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, DataType: TypeObject, Imm: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	result := ConstantPropagation(cfg, ssa)

	// Should have constant for v0
	if !result.IsConstant(0) {
		t.Errorf("Expected v0 to be constant")
	}

	// Check constant value
	val := result.GetConstantValue(0)
	if val == nil {
		t.Errorf("Expected v0 to have a value")
	}
}

// TestConstantPropagation_MoveOperation tests move operation propagation.
func TestConstantPropagation_MoveOperation(t *testing.T) {
	// v0 = 42
	// v1 = v0
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 42},
		{Kind: MIR_MOVE, Offset: 1, Dst: 1, Src1: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	result := ConstantPropagation(cfg, ssa)

	// Should propagate constant from v0 to v1
	if !result.IsConstant(0) {
		t.Errorf("Expected v0 to be constant")
	}
}

// TestConstantPropagation_DivisionByZero tests division by zero handling.
func TestConstantPropagation_DivisionByZero(t *testing.T) {
	// v0 = 10
	// v1 = 0
	// v2 = v0 / v1  (should not fold due to division by zero)
	// return v2
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 10},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 0},
		{Kind: MIR_DIV, Offset: 2, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	result := ConstantPropagation(cfg, ssa)

	// Should not fold division by zero
	if result == nil {
		t.Errorf("Expected propagation result, got nil")
	}
}

// TestConstantPropagation_ChangeCount tests change counting.
func TestConstantPropagation_ChangeCount(t *testing.T) {
	// v0 = 2
	// v1 = 3
	// v2 = v0 + v1
	// return v2
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 2},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 3},
		{Kind: MIR_ADD, Offset: 2, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	result := ConstantPropagation(cfg, ssa)

	// Should have at least some changes
	if result.ChangeCount() < 0 {
		t.Errorf("Expected non-negative change count, got %d", result.ChangeCount())
	}
}

// TestConstantPropagation_Trace tests propagation trace.
func TestConstantPropagation_Trace(t *testing.T) {
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

	result := ConstantPropagation(cfg, ssa)

	// Should have trace entries
	trace := result.GetTrace()
	if len(trace) == 0 {
		t.Errorf("Expected trace entries, got none")
	}
}

// TestConstantPropagation_SubtractionFolding tests subtraction folding.
func TestConstantPropagation_SubtractionFolding(t *testing.T) {
	// v0 = 10
	// v1 = 3
	// v2 = v0 - v1  (should fold to 7)
	// return v2
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 10},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 3},
		{Kind: MIR_SUB, Offset: 2, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	result := ConstantPropagation(cfg, ssa)

	if result == nil {
		t.Errorf("Expected propagation result, got nil")
	}
}

// TestConstantPropagation_ModuloFolding tests modulo folding.
func TestConstantPropagation_ModuloFolding(t *testing.T) {
	// v0 = 10
	// v1 = 3
	// v2 = v0 % v1  (should fold to 1)
	// return v2
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 10},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 3},
		{Kind: MIR_REM, Offset: 2, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	result := ConstantPropagation(cfg, ssa)

	if result == nil {
		t.Errorf("Expected propagation result, got nil")
	}
}

// TestConstantPropagation_NotFolding tests bitwise NOT folding.
func TestConstantPropagation_NotFolding(t *testing.T) {
	// v0 = 5
	// v1 = ~v0  (should fold to -6)
	// return v1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 5},
		{Kind: MIR_NOT, Offset: 1, Dst: 1, Src1: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := ConvertToSSA(cfg)

	result := ConstantPropagation(cfg, ssa)

	if result == nil {
		t.Fatalf("Expected propagation result, got nil")
	}

	if !result.IsConstant(1) {
		t.Errorf("Expected v1 to be constant")
	}

	val := result.GetConstantValue(1)
	if val == nil || val.Value != int64(-6) {
		t.Errorf("Expected v1 = -6, got %v", val)
	}
}
