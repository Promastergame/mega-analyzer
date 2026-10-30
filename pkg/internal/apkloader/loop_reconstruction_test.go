package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP RECONSTRUCTION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

// TestLoopReconstruction_CountedLoop tests reconstruction of a counted loop (for loop).
func TestLoopReconstruction_CountedLoop(t *testing.T) {
	// v0 = 0
	// if v0 >= 10 goto exit (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Should reconstruct at least one loop
	if lr.ReconstructionCount() == 0 {
		t.Errorf("Expected at least 1 reconstructed loop, got %d", lr.ReconstructionCount())
	}

	// Check that a loop was reconstructed
	if len(lr.ReconstructedLoops) > 0 {
		for _, reconstructed := range lr.ReconstructedLoops {
			// Should be a for loop or condition-based loop
			if reconstructed.LoopType != ReconstructedLoopFor &&
				reconstructed.LoopType != ReconstructedLoopWhile &&
				reconstructed.LoopType != ReconstructedLoopUnknown {
				t.Errorf("Expected for/while/unknown loop type, got %d", reconstructed.LoopType)
			}

			// Should have loop body
			if len(reconstructed.LoopBody) == 0 {
				t.Errorf("Expected loop body, got empty")
			}

			// Should have confidence score
			if reconstructed.ConfidenceScore <= 0 {
				t.Errorf("Expected positive confidence score, got %d", reconstructed.ConfidenceScore)
			}
		}
	}
}

// TestLoopReconstruction_ConditionBasedLoop tests reconstruction of a condition-based loop (while).
func TestLoopReconstruction_ConditionBasedLoop(t *testing.T) {
	// v0 = 0
	// if v0 >= 10 goto exit (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Should reconstruct at least one loop
	if lr.ReconstructionCount() == 0 {
		t.Errorf("Expected at least 1 reconstructed loop, got %d", lr.ReconstructionCount())
	}
}

// TestLoopReconstruction_NestedLoops tests reconstruction of nested loops.
func TestLoopReconstruction_NestedLoops(t *testing.T) {
	// Outer loop: v0 = 0; while v0 < 10
	// Inner loop: v1 = 0; while v1 < 5
	// v1 = v1 + 1
	// v0 = v0 + 1
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 3, Dst: 1, Imm: 0},
		{Kind: MIR_IF, Offset: 4, Imm: 8, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 6, Dst: 1, Src1: 1, Src2: 1},
		{Kind: MIR_GOTO, Offset: 7, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 9, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 10, Imm: -9, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 12},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Should reconstruct at least 1 loop (nested loops may be detected as 1 or 2 depending on analysis)
	if lr.ReconstructionCount() < 1 {
		t.Errorf("Expected at least 1 reconstructed loop, got %d", lr.ReconstructionCount())
	}
}

// TestLoopReconstruction_NoLoops tests reconstruction on code with no loops.
func TestLoopReconstruction_NoLoops(t *testing.T) {
	// Linear code with no loops
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 1, Src1: 0, Src2: 0},
		{Kind: MIR_RETURN, Offset: 2, Src1: 1},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Should have no reconstructed loops
	if lr.ReconstructionCount() != 0 {
		t.Errorf("Expected 0 reconstructed loops, got %d", lr.ReconstructionCount())
	}
}

// TestLoopReconstruction_GetReconstructedLoop tests loop retrieval.
func TestLoopReconstruction_GetReconstructedLoop(t *testing.T) {
	// v0 = 0
	// if v0 >= 10 goto exit (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Get reconstructed loop
	if len(loopAnalysis.AllLoops) > 0 {
		originalLoop := loopAnalysis.AllLoops[0]
		reconstructed := lr.GetReconstructedLoop(originalLoop)

		if reconstructed == nil {
			t.Errorf("Expected to retrieve reconstructed loop")
		}
	}
}

// TestLoopReconstruction_LoopTypeString tests loop type string conversion.
func TestLoopReconstruction_LoopTypeString(t *testing.T) {
	cfg := &CFG{}
	ssa := ConvertToSSA(cfg)
	loopAnalysis := &LoopAnalysis{}

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)

	tests := []struct {
		loopType ReconstructedLoopType
		expected string
	}{
		{ReconstructedLoopFor, "for"},
		{ReconstructedLoopForEach, "for-each"},
		{ReconstructedLoopWhile, "while"},
		{ReconstructedLoopDoWhile, "do-while"},
		{ReconstructedLoopUnknown, "unknown"},
	}

	for _, test := range tests {
		result := lr.loopTypeString(test.loopType)
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}

// TestLoopReconstruction_InsnKindString tests instruction kind string conversion.
func TestLoopReconstruction_InsnKindString(t *testing.T) {
	cfg := &CFG{}
	ssa := ConvertToSSA(cfg)
	loopAnalysis := &LoopAnalysis{}

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)

	tests := []struct {
		kind     MIROpKind
		expected string
	}{
		{MIR_CONST, "const"},
		{MIR_ADD, "add"},
		{MIR_SUB, "sub"},
		{MIR_MUL, "mul"},
		{MIR_DIV, "div"},
		{MIR_IF, "if"},
		{MIR_GOTO, "goto"},
		{MIR_RETURN, "return"},
		{MIR_INVOKE, "invoke"},
	}

	for _, test := range tests {
		result := lr.insnKindString(test.kind)
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}

// TestLoopReconstruction_AverageConfidence tests average confidence calculation.
func TestLoopReconstruction_AverageConfidence(t *testing.T) {
	// v0 = 0
	// if v0 >= 10 goto exit (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Get average confidence
	avgConfidence := lr.AverageConfidence()

	// Should have positive average confidence if loops were reconstructed
	if lr.ReconstructionCount() > 0 && avgConfidence <= 0 {
		t.Errorf("Expected positive average confidence, got %d", avgConfidence)
	}

	// Should be 0 if no loops were reconstructed
	if lr.ReconstructionCount() == 0 && avgConfidence != 0 {
		t.Errorf("Expected 0 average confidence for no loops, got %d", avgConfidence)
	}
}

// TestLoopReconstruction_GetTrace tests trace retrieval.
func TestLoopReconstruction_GetTrace(t *testing.T) {
	// v0 = 0
	// if v0 >= 10 goto exit (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Get trace
	trace := lr.GetTrace()

	// Should have trace entries if loops were reconstructed
	if lr.ReconstructionCount() > 0 && len(trace) == 0 {
		t.Errorf("Expected trace entries, got none")
	}
}

// TestLoopReconstruction_VerifySemanticEquivalence tests semantic equivalence verification.
func TestLoopReconstruction_VerifySemanticEquivalence(t *testing.T) {
	// v0 = 0
	// if v0 >= 10 goto exit (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Verify semantic equivalence
	for _, reconstructed := range lr.ReconstructedLoops {
		if !lr.VerifySemanticEquivalence(reconstructed) {
			t.Errorf("Expected semantic equivalence verification to pass")
		}
	}
}

// TestLoopReconstruction_GenerateGotoComment tests goto comment generation.
func TestLoopReconstruction_GenerateGotoComment(t *testing.T) {
	// v0 = 0
	// if v0 >= 10 goto exit (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)

	// Generate goto comment for a loop
	if len(loopAnalysis.AllLoops) > 0 {
		loop := loopAnalysis.AllLoops[0]
		comment := lr.generateGotoComment(loop)

		// Should contain "Original goto structure"
		if len(comment) == 0 {
			t.Errorf("Expected goto comment, got empty")
		}

		// Should contain comment markers
		if comment[0:2] != "//" {
			t.Errorf("Expected comment to start with //")
		}
	}
}

// TestLoopReconstruction_GetChangeCount tests change count.
func TestLoopReconstruction_GetChangeCount(t *testing.T) {
	// v0 = 0
	// if v0 >= 10 goto exit (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Get change count
	changeCount := lr.GetChangeCount()

	// Should match reconstruction count
	if changeCount != lr.ReconstructionCount() {
		t.Errorf("Expected change count %d, got %d", lr.ReconstructionCount(), changeCount)
	}
}

// TestLoopReconstruction_LoopBodyPreservation tests that loop body is preserved.
func TestLoopReconstruction_LoopBodyPreservation(t *testing.T) {
	// v0 = 0
	// if v0 >= 10 goto exit (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Check that loop body is preserved
	for _, reconstructed := range lr.ReconstructedLoops {
		if len(reconstructed.LoopBody) == 0 {
			t.Errorf("Expected loop body to be preserved")
		}

		// Loop body should match original loop blocks
		if len(reconstructed.LoopBody) != len(reconstructed.OriginalLoop.Blocks) {
			t.Errorf("Expected loop body size %d, got %d",
				len(reconstructed.OriginalLoop.Blocks), len(reconstructed.LoopBody))
		}
	}
}

// TestLoopReconstruction_ConfidenceScores tests confidence score assignment.
func TestLoopReconstruction_ConfidenceScores(t *testing.T) {
	// v0 = 0
	// if v0 >= 10 goto exit (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Check confidence scores
	for _, reconstructed := range lr.ReconstructedLoops {
		// Confidence should be between 0 and 100
		if reconstructed.ConfidenceScore < 0 || reconstructed.ConfidenceScore > 100 {
			t.Errorf("Expected confidence score between 0 and 100, got %d", reconstructed.ConfidenceScore)
		}

		// Confidence should be positive for reconstructed loops
		if reconstructed.ConfidenceScore <= 0 {
			t.Errorf("Expected positive confidence score, got %d", reconstructed.ConfidenceScore)
		}
	}
}

// TestLoopReconstruction_SemanticSafety tests semantic safety flag.
func TestLoopReconstruction_SemanticSafety(t *testing.T) {
	// v0 = 0
	// if v0 >= 10 goto exit (loop header)
	// v0 = v0 + 1
	// goto offset 1 (back to loop header)
	// return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 0},
		{Kind: MIR_IF, Offset: 1, Imm: 10, RawFlags: FlagBranch},
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 1},
		{Kind: MIR_GOTO, Offset: 4, Imm: -3, RawFlags: FlagBranch},
		{Kind: MIR_RETURN, Offset: 6},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	loopAnalysis := AnalyzeLoops(cfg)
	ssa := ConvertToSSA(cfg)

	lr := NewLoopReconstruction(cfg, ssa, loopAnalysis)
	lr.ReconstructLoops()

	// Check semantic safety
	for _, reconstructed := range lr.ReconstructedLoops {
		// All reconstructed loops should be marked as semantically safe
		if !reconstructed.IsSemanticallySafe {
			t.Errorf("Expected reconstructed loop to be marked as semantically safe")
		}
	}
}
