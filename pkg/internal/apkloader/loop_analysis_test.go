package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP ANALYSIS TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestAnalyzeLoops_SimpleLoop tests loop detection on simple loop.
func TestAnalyzeLoops_SimpleLoop(t *testing.T) {
	// v0 = 1
	// if v0 goto offset 5 (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 5, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	analysis := AnalyzeLoops(cfg)

	if analysis == nil {
		t.Errorf("Expected loop analysis, got nil")
		return
	}

	// Should detect at least one loop
	if analysis.LoopCount() == 0 {
		t.Errorf("Expected at least 1 loop, got %d", analysis.LoopCount())
	}
}

// TestAnalyzeLoops_NestedLoops tests loop detection on nested loops.
func TestAnalyzeLoops_NestedLoops(t *testing.T) {
	// Outer loop: v0 = 0; while v0 < 10
	// Inner loop: v1 = 0; while v1 < 5
	// v1 = v1 + 1
	// v0 = v0 + 1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 11, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 3, Dst: 1, Imm: 0},
		{Kind: MIR_IF, Offset: 4, Imm: 5, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 6, Dst: 1, Src1: 1, Src2: 1},
		{Kind: MIR_GOTO, Offset: 7, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 9, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 10, Imm: -9, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 12},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	analysis := AnalyzeLoops(cfg)

	// Should detect at least 2 loops
	if analysis.LoopCount() < 2 {
		t.Errorf("Expected at least 2 loops, got %d", analysis.LoopCount())
	}

	// Check nesting depth
	depth := analysis.NestedLoopDepth()
	if depth < 2 {
		t.Errorf("Expected nesting depth >= 2, got %d", depth)
	}
}

// TestAnalyzeLoops_BackEdgeDetection tests back edge detection.
func TestAnalyzeLoops_BackEdgeDetection(t *testing.T) {
	// v0 = 1
	// if v0 goto offset 5 (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 5, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	analysis := AnalyzeLoops(cfg)

	// Find the loop
	if analysis.LoopCount() > 0 {
		loop := analysis.AllLoops[0]
		// Should have at least one back edge
		if len(loop.BackEdges) == 0 {
			t.Errorf("Expected back edges, got none")
		}
	}
}

// TestAnalyzeLoops_LoopHeader tests loop header identification.
func TestAnalyzeLoops_LoopHeader(t *testing.T) {
	// v0 = 1
	// if v0 goto offset 5 (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 5, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	analysis := AnalyzeLoops(cfg)

	// Find the loop header
	var loopHeader *BasicBlock
	for _, loop := range analysis.AllLoops {
		loopHeader = loop.Header
		break
	}

	if loopHeader == nil {
		t.Errorf("Expected loop header, got nil")
		return
	}

	// Check that the header is identified as a loop header
	if !analysis.IsLoopHeader(loopHeader) {
		t.Errorf("Expected block to be identified as loop header")
	}
}

// TestAnalyzeLoops_LoopBlocks tests loop block identification.
func TestAnalyzeLoops_LoopBlocks(t *testing.T) {
	// v0 = 1
	// if v0 goto offset 5 (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 5, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	analysis := AnalyzeLoops(cfg)

	// Find the loop
	if analysis.LoopCount() > 0 {
		loop := analysis.AllLoops[0]
		// Should have at least 2 blocks (header + body)
		if len(loop.Blocks) < 2 {
			t.Errorf("Expected at least 2 blocks in loop, got %d", len(loop.Blocks))
		}
	}
}

// TestAnalyzeLoops_GetLoopForBlock tests block-to-loop mapping.
func TestAnalyzeLoops_GetLoopForBlock(t *testing.T) {
	// v0 = 1
	// if v0 goto offset 5 (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 5, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	analysis := AnalyzeLoops(cfg)

	// Get loop for a block in the loop
	if len(cfg.Blocks) > 2 {
		block := cfg.Blocks[2] // Block in loop body
		loop := analysis.GetLoopForBlock(block)
		if loop == nil {
			t.Errorf("Expected to find loop for block in loop body")
		}
	}
}

// TestAnalyzeLoops_LoopCount tests loop counting.
func TestAnalyzeLoops_LoopCount(t *testing.T) {
	// v0 = 1
	// if v0 goto offset 5 (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 5, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	analysis := AnalyzeLoops(cfg)

	count := analysis.LoopCount()
	if count == 0 {
		t.Errorf("Expected at least 1 loop, got %d", count)
	}
}

// TestAnalyzeLoops_NestedLoopDepth tests nesting depth calculation.
func TestAnalyzeLoops_NestedLoopDepth(t *testing.T) {
	// Outer loop: v0 = 0; while v0 < 10
	// Inner loop: v1 = 0; while v1 < 5
	// v1 = v1 + 1
	// v0 = v0 + 1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 11, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 3, Dst: 1, Imm: 0},
		{Kind: MIR_IF, Offset: 4, Imm: 5, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 6, Dst: 1, Src1: 1, Src2: 1},
		{Kind: MIR_GOTO, Offset: 7, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 9, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 10, Imm: -9, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 12},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	analysis := AnalyzeLoops(cfg)

	depth := analysis.NestedLoopDepth()
	if depth < 1 {
		t.Errorf("Expected nesting depth >= 1, got %d", depth)
	}
}

// TestAnalyzeLoops_LoopHierarchy tests loop hierarchy building.
func TestAnalyzeLoops_LoopHierarchy(t *testing.T) {
	// Outer loop: v0 = 0; while v0 < 10
	// Inner loop: v1 = 0; while v1 < 5
	// v1 = v1 + 1
	// v0 = v0 + 1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 11, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 3, Dst: 1, Imm: 0},
		{Kind: MIR_IF, Offset: 4, Imm: 5, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 6, Dst: 1, Src1: 1, Src2: 1},
		{Kind: MIR_GOTO, Offset: 7, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 9, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 10, Imm: -9, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 12},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	analysis := AnalyzeLoops(cfg)

	// Check that hierarchy is built
	if analysis.Hierarchy == nil && analysis.LoopCount() > 0 {
		t.Errorf("Expected loop hierarchy to be built")
	}

	// Check parent-child relationships
	for _, loop := range analysis.AllLoops {
		if loop.Parent != nil {
			// Parent should contain this loop
			found := false
			for _, child := range loop.Parent.Children {
				if child == loop {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Loop not found in parent's children")
			}
		}
	}
}

// TestAnalyzeLoops_GetLoopByHeader tests loop lookup by header.
func TestAnalyzeLoops_GetLoopByHeader(t *testing.T) {
	// v0 = 1
	// if v0 goto offset 5 (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 5, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 0},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	analysis := AnalyzeLoops(cfg)

	// Get loop by header
	if analysis.LoopCount() > 0 {
		loop := analysis.AllLoops[0]
		header := loop.Header
		retrievedLoop := analysis.GetLoopByHeader(header)
		if retrievedLoop != loop {
			t.Errorf("Expected to retrieve same loop by header")
		}
	}
}

// TestAnalyzeLoops_NoLoops tests CFG with no loops.
func TestAnalyzeLoops_NoLoops(t *testing.T) {
	// Linear code with no loops
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	analysis := AnalyzeLoops(cfg)

	// Should have no loops
	if analysis.LoopCount() != 0 {
		t.Errorf("Expected 0 loops, got %d", analysis.LoopCount())
	}
}
