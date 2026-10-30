package apkloader

import (
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SSA Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestDominanceFrontier_Linear(t *testing.T) {
	// Linear: B0 -> B1 -> B2 (no merge points, DF = empty)
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 1},
		{Kind: MIR_ADD, Offset: 1, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_RETURN, Offset: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	df := cfg.DominanceFrontier()

	// Linear code has no merge points, so all DF sets should be empty
	for id, blocks := range df {
		if len(blocks) > 0 {
			t.Errorf("block %d: expected empty DF, got %v", id, blocks)
		}
	}
}

func TestDominanceFrontier_IfMerge(t *testing.T) {
	// Diamond: B0 -> B1 (then), B2 (else) -> B3 (merge)
	// B0: if v0 goto +4
	// B1: const v1, 1
	// B2: const v1, 2
	// B3: return v1 (merge)
	mir := []MIRInsn{
		{Kind: MIR_IF, Offset: 0, Imm: 4, RawFlags: FlagBranch}, // B0: if v0 goto offset 4
		{Kind: MIR_CONST, Offset: 2, Dst: 1},                    // B1: v1 = 1 (fallthrough)
		{Kind: MIR_GOTO, Offset: 3, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 4, Dst: 1},   // B2: v1 = 2 (branch target)
		{Kind: MIR_RETURN, Offset: 5, Src1: 1}, // B3: return v1 (after goto target)
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	df := cfg.DominanceFrontier()

	// B3 is merge point, B1 and B2 should have B3 in their DF
	foundB3inDF := false
	for id, blocks := range df {
		for _, b := range blocks {
			if b.ID == 3 {
				foundB3inDF = true
				t.Logf("block %d has B3 in DF (correct)", id)
			}
		}
	}

	if !foundB3inDF {
		t.Log("DF contents:")
		for id, blocks := range df {
			if len(blocks) > 0 {
				t.Logf("  DF(%d) = %v", id, blockIds(blocks))
			}
		}
		t.Logf("Blocks: %d", len(cfg.Blocks))
		for i, b := range cfg.Blocks {
			t.Logf("  B%d: Insns=%d, Preds=%v, Succs=%v", b.ID, len(b.Insns), blockIds(b.Preds), blockIds(b.Succs))
			if i < len(b.Insns) {
				last := b.Insns[len(b.Insns)-1]
				t.Logf("    Last: Kind=%d, Flags=%v", last.Kind, last.RawFlags)
			}
		}
	}
}

func TestBuildSSA_Linear(t *testing.T) {
	// Linear: no phis needed
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0}, // v0_1 = const
		{Kind: MIR_CONST, Offset: 1, Dst: 1}, // v1_1 = const
		{Kind: MIR_ADD, Offset: 2, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	ssa := BuildSSA(cfg, mir)
	if ssa == nil {
		t.Fatal("BuildSSA returned nil")
	}

	// Linear code should have no phis
	for _, sb := range ssa.Blocks {
		if len(sb.Phis) > 0 {
			t.Errorf("block %d: expected 0 phis in linear code, got %d", sb.ID, len(sb.Phis))
		}
	}

	// Check versioning: v0 should have version 1 (defined once)
	// v0 starts as version 1 (pushed)
	t.Logf("MaxReg: %d", ssa.MaxReg)
	for _, sb := range ssa.Blocks {
		for _, insn := range sb.Insns {
			t.Logf("  %s = %s(...)", insn.Dst.String(), insn.MIR.Kind.String())
		}
	}
}

func TestBuildSSA_IfMerge(t *testing.T) {
	// Diamond with v1 defined in both branches
	// Offsets: 0=IF, 2=CONST, 3=GOTO, 4=CONST, 5=RETURN
	// IF @0 targets @4 (offset 4 = 0 + 4)
	// GOTO @3 targets @5 (offset 5 = 3 + 2)
	mir := []MIRInsn{
		{Kind: MIR_IF, Offset: 0, Imm: 4, Src1: 0, RawFlags: FlagBranch}, // B0: if v0 goto offset 4
		{Kind: MIR_CONST, Offset: 2, Dst: 1},                             // B1: v1 = 1 (fallthrough)
		{Kind: MIR_GOTO, Offset: 3, Imm: 2, RawFlags: FlagBranch},        // goto offset 5
		{Kind: MIR_CONST, Offset: 4, Dst: 1},                             // B2: v1 = 2 (branch target)
		{Kind: MIR_RETURN, Offset: 5},                                    // B3: return (merge)
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	ssa := BuildSSA(cfg, mir)
	if ssa == nil {
		t.Fatal("BuildSSA returned nil")
	}

	// Find merge block (should have phi for v1)
	var mergeBlock *SSABlock
	for _, sb := range ssa.Blocks {
		if len(sb.Preds) >= 2 {
			mergeBlock = sb
			break
		}
	}

	if mergeBlock == nil {
		t.Fatal("no merge block found")
	}

	// Check for phi in merge block
	foundPhiForV1 := false
	for _, phi := range mergeBlock.Phis {
		if phi.Dst.Reg == 1 {
			foundPhiForV1 = true
			t.Logf("Found phi for v1: %s = phi(%v)", phi.Dst.String(), phi.Operands)
			// Should have 2 operands (from B1 and B2)
			if len(phi.Operands) != len(mergeBlock.Preds) {
				t.Errorf("phi for v1: expected %d operands, got %d", len(mergeBlock.Preds), len(phi.Operands))
			}
		}
	}

	if !foundPhiForV1 {
		t.Errorf("merge block %d should have phi for v1", mergeBlock.ID)
		t.Logf("Phis in merge block:")
		for _, phi := range mergeBlock.Phis {
			t.Logf("  v%d_%d", phi.Dst.Reg, phi.Dst.Version)
		}
	}
}

func TestBuildSSA_Loop(t *testing.T) {
	// Simple loop:
	// B0: v0 = 1
	// B1: if v0 goto B2 else B3
	// B2: v0 = v0 + 1; goto B1
	// B3: return
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},               // B0
		{Kind: MIR_IF, Offset: 1, Imm: 5, RawFlags: FlagBranch},    // B1: loop header
		{Kind: MIR_ADD, Offset: 3, Dst: 0, Src1: 0, Src2: 0},       // B2: body (v0 = v0 + 1)
		{Kind: MIR_GOTO, Offset: 4, Imm: -4, RawFlags: FlagBranch}, // back to B1
		{Kind: MIR_RETURN, Offset: 6},                              // B3: exit
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	cfg.DetectLoops()

	ssa := BuildSSA(cfg, mir)
	if ssa == nil {
		t.Fatal("BuildSSA returned nil")
	}

	// Loop header should have phi for v1
	for _, sb := range ssa.Blocks {
		if sb.IsLoopHeader {
			t.Logf("Loop header B%d has %d phis", sb.ID, len(sb.Phis))
			for _, phi := range sb.Phis {
				t.Logf("  v%d_%d", phi.Dst.Reg, phi.Dst.Version)
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════════

func blockIds(blocks []*BasicBlock) []int {
	ids := make([]int, len(blocks))
	for i, b := range blocks {
		ids[i] = b.ID
	}
	return ids
}

// String helpers for MIRKind
func (k MIROpKind) String() string {
	names := []string{
		"NOP", "MOVE", "MOVE_RESULT", "MOVE_EXCEPTION", "CONST",
		"ADD", "SUB", "MUL", "DIV", "REM", "NEG", "NOT",
		"AND", "OR", "XOR", "SHL", "SHR", "USHR",
		"CONVERT", "CMP",
		"IF", "GOTO", "SWITCH", "RETURN", "THROW",
		"NEW_INSTANCE", "NEW_ARRAY", "ARRAY_LENGTH", "ARRAY_GET", "ARRAY_PUT",
		"FILL_ARRAY", "CHECK_CAST", "INSTANCE_OF",
		"FIELD_GET", "FIELD_PUT", "INVOKE",
		"MONITOR_ENTER", "MONITOR_EXIT", "PAYLOAD",
	}
	if int(k) < len(names) {
		return names[k]
	}
	return "UNKNOWN"
}

func TestTaintEngine_Basic(t *testing.T) {
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0},                 // v0 = const
		{Kind: MIR_MOVE, Offset: 1, Dst: 1, Src1: 0},         // v1 = v0
		{Kind: MIR_ADD, Offset: 2, Dst: 2, Src1: 1, Src2: 0}, // v2 = v1 + v0
		{Kind: MIR_RETURN, Offset: 3, Src1: 2},               // return v2
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()
	ssa := BuildSSA(cfg, mir)
	if ssa == nil {
		t.Fatal("BuildSSA failed")
	}

	te := NewTaintEngine(ssa)
	if te == nil {
		t.Fatal("NewTaintEngine failed")
	}

	// Mark source and sink
	v0 := SSAVar{Reg: 0, Version: 1}
	v2 := SSAVar{Reg: 2, Version: 1}
	te.MarkSource(v0, TaintSourceFieldLoad, "ref1")
	te.MarkSink(v2, TaintSinkBranch)

	// Propagate
	te.Propagate()

	// Detect flows
	flows := te.DetectFlows()
	t.Logf("Detected flows: %d", len(flows))

	// Backward slice
	bSlice := te.DefUse.BackwardSlice(v2)
	t.Logf("Backward slice size: %d", len(bSlice))

	// Forward slice
	fSlice := te.DefUse.ForwardSlice(v0)
	t.Logf("Forward slice size: %d", len(fSlice))

	// Test LicenseGateDetector
	lgd := NewLicenseGateDetector(ssa)
	if lgd != nil {
		res := lgd.Analyze()
		t.Logf("LicenseGateDetector Analyze: %v", res)
	}
}
