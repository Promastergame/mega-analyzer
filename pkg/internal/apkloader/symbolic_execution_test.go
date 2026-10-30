package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SYMBOLIC EXECUTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestSymbolicExecution_ConstantPropagation tests constant propagation in symbolic execution.
func TestSymbolicExecution_ConstantPropagation(t *testing.T) {
	// Create a simple CFG with constant assignment
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   2,
		Insns: []MIRInsn{
			{
				Kind: MIR_CONST,
				Dst:  0,
				Imm:  42,
			},
			{
				Kind: MIR_MOVE,
				Dst:  1,
				Src1: 0,
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	// Create SSA form
	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 2,
	}

	// Perform symbolic execution
	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Verify results
	if result.PathCount == 0 {
		t.Errorf("Expected at least 1 path, got %d", result.PathCount)
	}

	if len(result.SymbolicValues) == 0 {
		t.Errorf("Expected symbolic values, got none")
	}

	// Check that v0 has concrete value 42
	if val, ok := result.SymbolicValues[0]; ok {
		if val.IsSymbolic {
			t.Errorf("Expected v0 to be concrete, got symbolic")
		}
		if concrete, ok := val.Concrete.(int64); ok {
			if concrete != 42 {
				t.Errorf("Expected v0 = 42, got %d", concrete)
			}
		}
	}

	// Check that v1 has concrete value 42 (moved from v0)
	if val, ok := result.SymbolicValues[1]; ok {
		if val.IsSymbolic {
			t.Errorf("Expected v1 to be concrete, got symbolic")
		}
		if concrete, ok := val.Concrete.(int64); ok {
			if concrete != 42 {
				t.Errorf("Expected v1 = 42, got %d", concrete)
			}
		}
	}
}

// TestSymbolicExecution_ArithmeticFolding tests arithmetic operation folding.
func TestSymbolicExecution_ArithmeticFolding(t *testing.T) {
	// Create a CFG with arithmetic operations
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   3,
		Insns: []MIRInsn{
			{
				Kind: MIR_CONST,
				Dst:  0,
				Imm:  10,
			},
			{
				Kind: MIR_CONST,
				Dst:  1,
				Imm:  5,
			},
			{
				Kind: MIR_ADD,
				Dst:  2,
				Src1: 0,
				Src2: 1,
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 3,
	}

	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Check that v2 = 15 (10 + 5)
	if val, ok := result.SymbolicValues[2]; ok {
		if val.IsSymbolic {
			t.Errorf("Expected v2 to be concrete, got symbolic")
		}
		if concrete, ok := val.Concrete.(int64); ok {
			if concrete != 15 {
				t.Errorf("Expected v2 = 15, got %d", concrete)
			}
		}
	}
}

// TestSymbolicExecution_SymbolicValues tests symbolic value tracking.
func TestSymbolicExecution_SymbolicValues(t *testing.T) {
	// Create a CFG with symbolic operations
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   2,
		Insns: []MIRInsn{
			{
				Kind: MIR_CONST,
				Dst:  1,
				Imm:  5,
			},
			{
				Kind: MIR_ADD,
				Dst:  2,
				Src1: 0, // v0 is symbolic (parameter)
				Src2: 1, // v1 is concrete (5)
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 3,
	}

	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Check that v2 is symbolic (v0 + 5)
	if val, ok := result.SymbolicValues[2]; ok {
		if !val.IsSymbolic {
			t.Errorf("Expected v2 to be symbolic, got concrete")
		}
		if val.Symbolic == "" {
			t.Errorf("Expected v2 to have symbolic expression, got empty")
		}
	}
}

// TestSymbolicExecution_DepthLimiting tests execution depth limiting.
func TestSymbolicExecution_DepthLimiting(t *testing.T) {
	// Create a CFG with many blocks
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 5),
	}

	// Create a chain of blocks
	for i := 0; i < 5; i++ {
		block := &BasicBlock{
			ID:    i,
			Start: i,
			End:   i + 1,
			Insns: []MIRInsn{
				{
					Kind: MIR_CONST,
					Dst:  int16(i),
					Imm:  int64(i),
				},
			},
			Succs: make([]*BasicBlock, 0),
			Preds: make([]*BasicBlock, 0),
		}

		cfg.Blocks[i] = block
	}

	// Connect blocks after all are created
	for i := 0; i < 4; i++ {
		cfg.Blocks[i].Succs = append(cfg.Blocks[i].Succs, cfg.Blocks[i+1])
		cfg.Blocks[i+1].Preds = append(cfg.Blocks[i+1].Preds, cfg.Blocks[i])
	}

	cfg.Entry = cfg.Blocks[0]

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 5,
	}

	// Execute with depth limit of 2
	executor := NewSymbolicExecutor(cfg, ssa)
	executor.SetMaxDepth(2)
	result := executor.Execute()

	// Check that execution was limited
	if result.ExecutionDepth > 2 {
		t.Errorf("Expected execution depth <= 2, got %d", result.ExecutionDepth)
	}

	if result.PrunedPaths == 0 {
		t.Errorf("Expected some paths to be pruned, got 0")
	}
}

// TestSymbolicExecution_PathLimiting tests path count limiting.
func TestSymbolicExecution_PathLimiting(t *testing.T) {
	// Create a CFG with branching
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 3),
	}

	// Entry block
	entryBlock := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind: MIR_CONST,
				Dst:  0,
				Imm:  1,
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	// Branch block
	branchBlock := &BasicBlock{
		ID:    1,
		Start: 1,
		End:   2,
		Insns: []MIRInsn{
			{
				Kind: MIR_IF,
				Src1: 0,
				Cond: CondNE,
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	// Exit block
	exitBlock := &BasicBlock{
		ID:    2,
		Start: 2,
		End:   3,
		Insns: []MIRInsn{
			{
				Kind: MIR_CONST,
				Dst:  1,
				Imm:  0,
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = entryBlock
	cfg.Blocks[1] = branchBlock
	cfg.Blocks[2] = exitBlock

	entryBlock.Succs = append(entryBlock.Succs, branchBlock)
	branchBlock.Preds = append(branchBlock.Preds, entryBlock)
	branchBlock.Succs = append(branchBlock.Succs, exitBlock)
	branchBlock.Succs = append(branchBlock.Succs, exitBlock)
	exitBlock.Preds = append(exitBlock.Preds, branchBlock)

	cfg.Entry = entryBlock

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 2,
	}

	// Execute with path limit of 1
	executor := NewSymbolicExecutor(cfg, ssa)
	executor.SetMaxPaths(1)
	result := executor.Execute()

	// Check that path count was limited
	if result.PathCount > 1 {
		t.Errorf("Expected path count <= 1, got %d", result.PathCount)
	}

	// Note: With concrete condition (v0 = 1, which is != 0), we only explore one path
	// So pruning may not occur. This is expected behavior.
}

// TestSymbolicExecution_StateManagement tests state management.
func TestSymbolicExecution_StateManagement(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   2,
		Insns: []MIRInsn{
			{
				Kind: MIR_CONST,
				Dst:  0,
				Imm:  10,
			},
			{
				Kind: MIR_MOVE,
				Dst:  1,
				Src1: 0,
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 2,
	}

	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Check that state was properly managed
	if len(result.Paths) == 0 {
		t.Errorf("Expected at least 1 path, got 0")
	}

	path := result.Paths[0]
	if path.State == nil {
		t.Errorf("Expected path state, got nil")
	}

	if len(path.State.Registers) == 0 {
		t.Errorf("Expected registers in state, got 0")
	}

	if len(path.Instructions) == 0 {
		t.Errorf("Expected instructions in path, got 0")
	}
}

// TestSymbolicExecution_LogicalOperations tests logical operations.
func TestSymbolicExecution_LogicalOperations(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   3,
		Insns: []MIRInsn{
			{
				Kind: MIR_CONST,
				Dst:  0,
				Imm:  0xFF,
			},
			{
				Kind: MIR_CONST,
				Dst:  1,
				Imm:  0x0F,
			},
			{
				Kind: MIR_AND,
				Dst:  2,
				Src1: 0,
				Src2: 1,
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 3,
	}

	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Check that v2 = 0x0F (0xFF & 0x0F)
	if val, ok := result.SymbolicValues[2]; ok {
		if val.IsSymbolic {
			t.Errorf("Expected v2 to be concrete, got symbolic")
		}
		if concrete, ok := val.Concrete.(int64); ok {
			if concrete != 0x0F {
				t.Errorf("Expected v2 = 0x0F, got 0x%X", concrete)
			}
		}
	}
}

// TestSymbolicExecution_FieldOperations tests field read/write operations.
func TestSymbolicExecution_FieldOperations(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   2,
		Insns: []MIRInsn{
			{
				Kind:   MIR_FIELD_PUT,
				Src1:   0,
				RefIdx: 1,
			},
			{
				Kind:   MIR_FIELD_GET,
				Dst:    1,
				RefIdx: 1,
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 2,
	}

	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Check that field operations were tracked
	if len(result.Paths) == 0 {
		t.Errorf("Expected at least 1 path, got 0")
	}

	path := result.Paths[0]
	if len(path.State.Memory) == 0 {
		t.Errorf("Expected memory state, got empty")
	}
}

// TestSymbolicExecution_Trace tests execution trace generation.
func TestSymbolicExecution_Trace(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind: MIR_CONST,
				Dst:  0,
				Imm:  42,
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 1,
	}

	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Check that trace was generated
	if len(result.Trace) == 0 {
		t.Errorf("Expected trace entries, got 0")
	}

	// Check for expected trace messages
	hasStartMessage := false
	hasCompleteMessage := false

	for _, msg := range result.Trace {
		if msg == "Starting symbolic execution" {
			hasStartMessage = true
		}
		if msg == "Symbolic execution complete: 1 paths explored, 0 pruned" {
			hasCompleteMessage = true
		}
	}

	if !hasStartMessage {
		t.Errorf("Expected 'Starting symbolic execution' in trace")
	}

	if !hasCompleteMessage {
		t.Errorf("Expected completion message in trace")
	}
}

// TestSymbolicExecution_SortingByDepth tests sorting paths by depth.
func TestSymbolicExecution_SortingByDepth(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind: MIR_CONST,
				Dst:  0,
				Imm:  0,
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 1,
	}

	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Sort by depth
	result.SortPathsByDepth()

	// Check that paths are sorted
	for i := 1; i < len(result.Paths); i++ {
		if result.Paths[i].State.Depth < result.Paths[i-1].State.Depth {
			t.Errorf("Paths not sorted by depth")
		}
	}
}

// TestSymbolicExecution_GetPathsTerminated tests getting terminated paths.
func TestSymbolicExecution_GetPathsTerminated(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind: MIR_CONST,
				Dst:  0,
				Imm:  0,
			},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 1,
	}

	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Get terminated paths
	terminatedPaths := result.GetPathsTerminated()

	// Check that we have terminated paths
	if len(terminatedPaths) == 0 {
		t.Errorf("Expected terminated paths, got 0")
	}

	// Check that all returned paths are terminated
	for _, path := range terminatedPaths {
		if !path.State.IsTerminated {
			t.Errorf("Expected terminated path, got non-terminated")
		}
	}
}

// TestSymbolicExecution_EdgeCase_EmptyBlock tests edge case with empty block.
func TestSymbolicExecution_EdgeCase_EmptyBlock(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   0,
		Insns: make([]MIRInsn, 0),
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 0,
	}

	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Should handle empty block gracefully
	if result == nil {
		t.Fatalf("Expected result, got nil")
	}
	if len(result.Paths) == 0 {
		t.Errorf("Expected at least 1 path, got 0")
	}
}

// TestSymbolicExecution_EdgeCase_NilCFG tests edge case with nil CFG.
func TestSymbolicExecution_EdgeCase_NilCFG(t *testing.T) {
	ssa := &SSAForm{
		CFG:              nil,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 0,
	}

	executor := NewSymbolicExecutor(nil, ssa)

	// Should handle nil CFG gracefully
	if executor == nil {
		t.Errorf("Expected executor, got nil")
	}
}

// TestSymbolicExecution_MultipleRegisters tests handling of multiple registers.
func TestSymbolicExecution_MultipleRegisters(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   5,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Dst: 0, Imm: 1},
			{Kind: MIR_CONST, Dst: 1, Imm: 2},
			{Kind: MIR_CONST, Dst: 2, Imm: 3},
			{Kind: MIR_ADD, Dst: 3, Src1: 0, Src2: 1},
			{Kind: MIR_ADD, Dst: 4, Src1: 3, Src2: 2},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 5,
	}

	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Check v3 = 3 (1 + 2)
	if val, ok := result.SymbolicValues[3]; ok {
		if concrete, ok := val.Concrete.(int64); ok {
			if concrete != 3 {
				t.Errorf("Expected v3 = 3, got %d", concrete)
			}
		}
	}

	// Check v4 = 6 (3 + 3)
	if val, ok := result.SymbolicValues[4]; ok {
		if concrete, ok := val.Concrete.(int64); ok {
			if concrete != 6 {
				t.Errorf("Expected v4 = 6, got %d", concrete)
			}
		}
	}
}

// TestSymbolicExecution_DivisionByZero tests handling of division by zero.
func TestSymbolicExecution_DivisionByZero(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   3,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Dst: 0, Imm: 10},
			{Kind: MIR_CONST, Dst: 1, Imm: 0},
			{Kind: MIR_DIV, Dst: 2, Src1: 0, Src2: 1},
		},
		Succs: make([]*BasicBlock, 0),
		Preds: make([]*BasicBlock, 0),
	}

	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:              cfg,
		Variables:        make([]*SSAVariable, 0),
		VarByID:          make(map[int16]*SSAVariable),
		RegisterToVar:    make(map[int16]*SSAVariable),
		PhiFunctions:     make(map[*BasicBlock][]*SSAVariable),
		NextVarID:        0,
		OriginalRegCount: 3,
	}

	executor := NewSymbolicExecutor(cfg, ssa)
	result := executor.Execute()

	// Should handle division by zero gracefully
	if result == nil {
		t.Fatalf("Expected result, got nil")
	}
	// v2 should not have a value (division by zero) or should be symbolic
	// The implementation doesn't set v2 when division by zero occurs
	if val, ok := result.SymbolicValues[2]; ok {
		// If v2 exists, it should be symbolic (not computed)
		if !val.IsSymbolic {
			t.Errorf("Expected v2 to be symbolic or absent (division by zero)")
		}
	}
}
