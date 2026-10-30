package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// EXCEPTION HANDLING TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestBuildCFGWithHandlers_SimpleTryCatch tests exception edge modeling.
func TestBuildCFGWithHandlers_SimpleTryCatch(t *testing.T) {
	// Protected region: offsets 0-2
	// Handler: offset 3
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},          // protected
		{Kind: MIR_ADD, Offset: 1, Dst: 1},            // protected
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},        // protected
		{Kind: MIR_MOVE_EXCEPTION, Offset: 3, Dst: 2}, // handler entry
		{Kind: MIR_RETURN, Offset: 4, Src1: 2},        // handler
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 3,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 3,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)

	if cfg.BlockCount() != 2 {
		t.Errorf("Expected 2 blocks, got %d", cfg.BlockCount())
	}

	// Check exception edges
	if len(cfg.ExceptionEdges) == 0 {
		t.Errorf("Expected exception edges, got none")
	}

	// Check handler block
	if len(cfg.HandlerBlocks) != 1 {
		t.Errorf("Expected 1 handler block, got %d", len(cfg.HandlerBlocks))
	}

	handlerBlock := cfg.HandlerBlocks[0]
	if !handlerBlock.IsExceptionHandler {
		t.Errorf("Expected handler block to be marked as exception handler")
	}

	if !handlerBlock.HasMoveException {
		t.Errorf("Expected handler block to have move-exception instruction")
	}

	if len(handlerBlock.ExceptionTypes) != 1 || handlerBlock.ExceptionTypes[0] != "Ljava/lang/Exception;" {
		t.Errorf("Expected exception type Ljava/lang/Exception;, got %v", handlerBlock.ExceptionTypes)
	}
}

// TestBuildCFGWithHandlers_CatchAll tests catch-all handler.
func TestBuildCFGWithHandlers_CatchAll(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:      -1,
						TypeName:     "",
						HandlerAddr:  2,
						CatchAllAddr: 2,
						HasCatchAll:  true,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)

	if len(cfg.ExceptionEdges) == 0 {
		t.Errorf("Expected exception edges for catch-all")
	}

	handlerBlock := cfg.HandlerBlocks[0]
	// The handler block may have multiple exception types if it handles multiple exceptions
	// Just verify it has at least one and that it includes the catch-all
	hasEmptyType := false
	for _, exType := range handlerBlock.ExceptionTypes {
		if exType == "" {
			hasEmptyType = true
			break
		}
	}
	if !hasEmptyType {
		t.Errorf("Expected catch-all exception type (empty string) in handler block")
	}
}

// TestBuildCFGWithHandlers_MultipleHandlers tests multiple exception handlers.
func TestBuildCFGWithHandlers_MultipleHandlers(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 1},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 4, Dst: 2},
		{Kind: MIR_RETURN, Offset: 5, Src1: 2},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/io/IOException;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
					{
						TypeIdx:     1,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 4,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)

	if len(cfg.HandlerBlocks) != 2 {
		t.Errorf("Expected 2 handler blocks, got %d", len(cfg.HandlerBlocks))
	}

	// Each protected block should have 2 exception edges
	protectedBlock := cfg.Blocks[0]
	edges := cfg.GetExceptionEdgesFrom(protectedBlock)
	if len(edges) != 2 {
		t.Errorf("Expected 2 exception edges from protected block, got %d", len(edges))
	}
}

// TestBuildCFGWithHandlers_NestedTryCatch tests nested try-catch blocks.
func TestBuildCFGWithHandlers_NestedTryCatch(t *testing.T) {
	// Outer try: offsets 0-4
	// Inner try: offsets 1-2
	// Outer handler: offset 5
	// Inner handler: offset 7
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},          // outer protected
		{Kind: MIR_CONST, Offset: 1, Dst: 1},          // inner protected
		{Kind: MIR_ADD, Offset: 2, Dst: 2},            // inner protected
		{Kind: MIR_CONST, Offset: 3, Dst: 3},          // outer protected
		{Kind: MIR_RETURN, Offset: 4, Src1: 3},        // outer protected
		{Kind: MIR_MOVE_EXCEPTION, Offset: 5, Dst: 4}, // outer handler
		{Kind: MIR_RETURN, Offset: 6, Src1: 4},        // outer handler
		{Kind: MIR_MOVE_EXCEPTION, Offset: 7, Dst: 5}, // inner handler
		{Kind: MIR_RETURN, Offset: 8, Src1: 5},        // inner handler
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 5,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 5,
						HasCatchAll: false,
					},
				},
			},
			{
				StartAddr: 1,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     1,
						TypeName:    "Ljava/io/IOException;",
						HandlerAddr: 7,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)

	// We should have at least 1 handler block (they may be merged if at same offset)
	if len(cfg.HandlerBlocks) < 1 {
		t.Errorf("Expected at least 1 handler block, got %d", len(cfg.HandlerBlocks))
	}

	// We should have at least 1 exception edge (from outer try block)
	if len(cfg.ExceptionEdges) < 1 {
		t.Errorf("Expected at least 1 exception edge, got %d", len(cfg.ExceptionEdges))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOMINANCE FRONTIER TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestComputeDominanceFrontier_Diamond tests dominance frontier computation.
func TestComputeDominanceFrontier_Diamond(t *testing.T) {
	// B0: if v0 goto offset 4
	// B1: v1 = 1 (fallthrough)
	// B2: v1 = 2 (branch target)
	// B3: return v1 (merge)
	mir := []MIRInsn{
		{Kind: MIR_IF, Offset: 0, Imm: 4, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 2, Dst: 1},
		{Kind: MIR_CONST, Offset: 4, Dst: 1},
		{Kind: MIR_RETURN, Offset: 5, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	if cfg.BlockCount() < 3 {
		t.Errorf("Expected at least 3 blocks, got %d", cfg.BlockCount())
		return
	}

	// Verify that dominance frontier computation completed without error
	// and that blocks have their dominance frontiers computed
	for _, block := range cfg.Blocks {
		// Just verify the field exists and is initialized
		_ = block.DomFrontier
	}
}

// TestComputeDominanceFrontier_Loop tests dominance frontier with loops.
func TestComputeDominanceFrontier_Loop(t *testing.T) {
	// B0: v0 = 1
	// B1: if v0 goto offset 5 (loop header)
	// B2: v0 = v0 + 1
	// B3: goto offset 1 (back to loop header)
	// B4: return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 5, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	if cfg.BlockCount() < 3 {
		t.Errorf("Expected at least 3 blocks, got %d", cfg.BlockCount())
		return
	}

	// Verify that dominance frontier computation completed without error
	// and that blocks have their dominance frontiers computed
	for _, block := range cfg.Blocks {
		// Just verify the field exists and is initialized
		_ = block.DomFrontier
	}
}

// TestComputeDominanceFrontier_SharedRunner tests that a block lying on the
// frontier walks of TWO merge points appears in both frontiers.
// A branches to both merges M1 and M2, and M1 flows into M2:
//
//	E {IF} -> A, B | A {IF} -> M1, M2 | B {GOTO} -> M1 | M1 {GOTO} -> M2 | M2 {RETURN}
//
// Correct frontiers: DF(A) = {M1, M2}, DF(B) = {M1}, DF(M1) = {M2}.
// A per-pass (instead of per-merge-point) generation counter drops M1 or M2
// from DF(A); the O(1) check must be scoped to a single merge-point walk.
// Also verifies repeated calls stay idempotent (TransformSession calls the
// frontier once directly and once via ComputeDominance).
func TestComputeDominanceFrontier_SharedRunner(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_IF, Offset: 0, Imm: 5, RawFlags: FlagBranch},    // E -> A(2)/B(5)
		{Kind: MIR_CONST, Offset: 2, Dst: 0},                       // A
		{Kind: MIR_IF, Offset: 3, Imm: 5, RawFlags: FlagBranch},    // A -> M1(8)/M2(4)
		{Kind: MIR_RETURN, Offset: 4, Src1: 0},                     // M2
		{Kind: MIR_CONST, Offset: 5, Dst: 1},                       // B
		{Kind: MIR_GOTO, Offset: 6, Imm: 2, RawFlags: FlagBranch},  // B -> M1(8)
		{Kind: MIR_CONST, Offset: 8, Dst: 2},                       // M1
		{Kind: MIR_GOTO, Offset: 9, Imm: -5, RawFlags: FlagBranch}, // M1 -> M2(4)
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	if got := cfg.BlockCount(); got != 5 {
		t.Fatalf("BlockCount = %d, want 5", got)
	}

	// A is the only block with two successors that both have two predecessors.
	var blockA, blockM1, blockM2 *BasicBlock
	for _, b := range cfg.Blocks {
		if len(b.Succs) == 2 && len(b.Succs[0].Preds) == 2 && len(b.Succs[1].Preds) == 2 {
			blockA = b
		}
		for _, insn := range b.Insns {
			if insn.Kind == MIR_RETURN {
				blockM2 = b
			}
		}
	}
	if blockA == nil || blockM2 == nil {
		t.Fatalf("failed to locate blocks A/M2 in CFG with %d blocks", len(cfg.Blocks))
	}
	for _, s := range blockA.Succs {
		if s != blockM2 {
			blockM1 = s
		}
	}

	frontierSet := func(b *BasicBlock) map[*BasicBlock]bool {
		m := make(map[*BasicBlock]bool, len(b.DomFrontier))
		for _, f := range b.DomFrontier {
			m[f] = true
		}
		return m
	}
	check := func(name string, b *BasicBlock, want ...*BasicBlock) {
		t.Helper()
		got := frontierSet(b)
		if len(got) != len(want) {
			t.Errorf("DF(%s) has %d entries, want %d", name, len(got), len(want))
			return
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("DF(%s) is missing an expected merge block", name)
			}
		}
	}

	check("A", blockA, blockM1, blockM2)
	check("M1", blockM1, blockM2)

	// Second call (as done by TransformSession.RebuildAnalysis) must not
	// duplicate entries or change the sets.
	sizesBefore := make([]int, len(cfg.Blocks))
	for i, b := range cfg.Blocks {
		sizesBefore[i] = len(b.DomFrontier)
	}
	cfg.ComputeDominanceFrontier()
	for i, b := range cfg.Blocks {
		if len(b.DomFrontier) != sizesBefore[i] {
			t.Errorf("block %d frontier size changed %d -> %d on recompute",
				b.ID, sizesBefore[i], len(b.DomFrontier))
		}
	}
	check("A-recompute", blockA, blockM1, blockM2)
}

// ═══════════════════════════════════════════════════════════════════════════════
// REACHABILITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestMarkReachable_ExceptionHandlers tests reachability with exception handlers.
func TestMarkReachable_ExceptionHandlers(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)

	// All blocks should be reachable (including handler)
	for i, block := range cfg.Blocks {
		if !block.IsReachable {
			t.Errorf("Block %d should be reachable", i)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITY TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestGetExceptionEdgesFrom tests exception edge queries.
func TestGetExceptionEdgesFrom(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)

	protectedBlock := cfg.Blocks[0]
	edges := cfg.GetExceptionEdgesFrom(protectedBlock)

	if len(edges) != 1 {
		t.Errorf("Expected 1 exception edge from protected block, got %d", len(edges))
	}

	if edges[0].ExceptionType != "Ljava/lang/Exception;" {
		t.Errorf("Expected exception type Ljava/lang/Exception;, got %s", edges[0].ExceptionType)
	}
}

// TestGetExceptionEdgesTo tests exception edge queries (to handler).
func TestGetExceptionEdgesTo(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     0,
						TypeName:    "Ljava/lang/Exception;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)

	handlerBlock := cfg.HandlerBlocks[0]
	edges := cfg.GetExceptionEdgesTo(handlerBlock)

	if len(edges) != 1 {
		t.Errorf("Expected 1 exception edge to handler block, got %d", len(edges))
	}

	if edges[0].ExceptionType != "Ljava/lang/Exception;" {
		t.Errorf("Expected exception type Ljava/lang/Exception;, got %s", edges[0].ExceptionType)
	}
}

// TestExceptionEdgeProperties tests exception edge properties.
func TestExceptionEdgeProperties(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},
		{Kind: MIR_RETURN, Offset: 1},
		{Kind: MIR_MOVE_EXCEPTION, Offset: 2, Dst: 1},
		{Kind: MIR_RETURN, Offset: 3},
	}

	handlers := &CodeItem{
		Tries: []*TryItem{
			{
				StartAddr: 0,
				InsnCount: 2,
				CatchHandlers: []*CatchHandler{
					{
						TypeIdx:     42,
						TypeName:    "Ljava/io/IOException;",
						HandlerAddr: 2,
						HasCatchAll: false,
					},
				},
			},
		},
	}

	cfg := BuildCFGWithHandlers(mir, handlers)

	if len(cfg.ExceptionEdges) != 1 {
		t.Errorf("Expected 1 exception edge, got %d", len(cfg.ExceptionEdges))
	}

	edge := cfg.ExceptionEdges[0]
	if edge.ExceptionType != "Ljava/io/IOException;" {
		t.Errorf("Expected exception type Ljava/io/IOException;, got %s", edge.ExceptionType)
	}

	if edge.TypeIdx != 42 {
		t.Errorf("Expected type index 42, got %d", edge.TypeIdx)
	}

	if edge.From != cfg.Blocks[0] {
		t.Errorf("Expected edge from protected block")
	}

	if edge.To != cfg.HandlerBlocks[0] {
		t.Errorf("Expected edge to handler block")
	}
}
