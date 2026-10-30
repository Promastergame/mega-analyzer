package apkloader

import (
	"strings"
	"testing"
)

func TestTransformSessionFoldsInstructionsAndBranches(t *testing.T) {
	entry := &BasicBlock{ID: 0, IsReachable: true, Insns: []MIRInsn{
		{Kind: MIR_CONST, DataType: TypeInt, Dst: 0, Src1: -1, Src2: -1, Imm: 4},
		{Kind: MIR_CONST, DataType: TypeInt, Dst: 1, Src1: -1, Src2: -1, Imm: 5},
		{Kind: MIR_ADD, DataType: TypeInt, Dst: 2, Src1: 0, Src2: 1},
		{Kind: MIR_IF, Cond: CondEQZ, Dst: -1, Src1: 2, Src2: -1},
	}}
	taken := &BasicBlock{ID: 1, IsReachable: true, Insns: []MIRInsn{{Kind: MIR_RETURN, Dst: -1, Src1: -1, Src2: -1}}}
	fall := &BasicBlock{ID: 2, IsReachable: true, Insns: []MIRInsn{{Kind: MIR_RETURN, Dst: -1, Src1: -1, Src2: -1}}}
	entry.Succs = []*BasicBlock{taken, fall}
	taken.Preds = []*BasicBlock{entry}
	fall.Preds = []*BasicBlock{entry}
	cfg := &CFG{Blocks: []*BasicBlock{entry, taken, fall}, Entry: entry}

	s := NewTransformSession(cfg)
	changes := s.FoldLocalConstants("Lx;", "m")
	if changes != 2 {
		t.Fatalf("expected arithmetic+branch rewrite, got %d journal=%+v", changes, s.Journal)
	}
	if got := entry.Insns[2]; got.Kind != MIR_CONST || got.Imm != 9 {
		t.Fatalf("arithmetic was not materially folded: %+v", got)
	}
	if got := entry.Insns[3]; got.Kind != MIR_NOP {
		t.Fatalf("false branch was not removed: %+v", got)
	}
	if len(entry.Succs) != 1 || entry.Succs[0] != fall {
		t.Fatalf("expected only fallthrough successor, got %+v", entry.Succs)
	}
	if taken.IsReachable {
		t.Fatal("discarded taken block should be unreachable after CFG normalization")
	}
	if len(s.Journal) != 2 || s.Journal[0].Proof == "" || s.Journal[1].Proof == "" {
		t.Fatalf("missing transformation proofs: %+v", s.Journal)
	}
}

func TestTransformSessionDoesNotPropagateAcrossConflictingPredecessors(t *testing.T) {
	left := &BasicBlock{ID: 0, IsReachable: true, Insns: []MIRInsn{{Kind: MIR_CONST, DataType: TypeInt, Dst: 0, Src1: -1, Src2: -1, Imm: 1}}}
	right := &BasicBlock{ID: 1, IsReachable: true, Insns: []MIRInsn{{Kind: MIR_CONST, DataType: TypeInt, Dst: 0, Src1: -1, Src2: -1, Imm: 2}}}
	join := &BasicBlock{ID: 2, IsReachable: true, Insns: []MIRInsn{{Kind: MIR_ADD, DataType: TypeInt, Dst: 1, Src1: 0, Src2: 0}}}
	left.Succs = []*BasicBlock{join}
	right.Succs = []*BasicBlock{join}
	join.Preds = []*BasicBlock{left, right}
	cfg := &CFG{Blocks: []*BasicBlock{left, right, join}, Entry: left}
	s := NewTransformSession(cfg)
	s.FoldLocalConstants("Lx;", "m")
	if join.Insns[0].Kind != MIR_ADD {
		t.Fatalf("unsafe cross-predecessor fold occurred: %+v", join.Insns[0])
	}
}

// Regression test for a bug where deobfuscation_pipeline.go bulk-imported
// journal entries into PrettySmaliGenerator.ConstantPropagation (keyed only by
// register), so a register reused across blocks with different folded values
// rendered the same (last block's) value everywhere. The fix relies on
// FoldLocalConstants mutating each instruction's own Imm in place, which
// formatInstructionKind must read directly instead of through that map.
func TestPrettySmaliRendersPerInstructionConstantAfterReusedRegisterFold(t *testing.T) {
	a := &BasicBlock{ID: 0, IsReachable: true, Insns: []MIRInsn{
		{Kind: MIR_CONST, DataType: TypeInt, Dst: 0, Src1: -1, Src2: -1, Imm: 5},
		{Kind: MIR_MOVE, DataType: TypeInt, Dst: 1, Src1: 0, Src2: -1},
	}}
	b := &BasicBlock{ID: 1, IsReachable: true, Insns: []MIRInsn{
		{Kind: MIR_CONST, DataType: TypeInt, Dst: 2, Src1: -1, Src2: -1, Imm: 9},
		{Kind: MIR_MOVE, DataType: TypeInt, Dst: 1, Src1: 2, Src2: -1},
		{Kind: MIR_RETURN, Dst: -1, Src1: -1, Src2: -1},
	}}
	a.Succs = []*BasicBlock{b}
	b.Preds = []*BasicBlock{a}
	cfg := &CFG{Blocks: []*BasicBlock{a, b}, Entry: a}

	s := NewTransformSession(cfg)
	if changes := s.FoldLocalConstants("Lx;", "m"); changes != 2 {
		t.Fatalf("expected 2 constant folds, got %d journal=%+v", changes, s.Journal)
	}

	// Deliberately do NOT call gen.AddConstantValue — the fixed pipeline no
	// longer bulk-imports the journal, relying solely on each instruction's own
	// (already-mutated) Imm.
	gen := NewPrettySmaliGenerator(cfg, s.SSA)
	lineA := gen.formatInstructionKind(&a.Insns[1])
	lineB := gen.formatInstructionKind(&b.Insns[1])
	if !strings.Contains(lineA, "0x5") {
		t.Fatalf("block a's folded v1 should render its own value 5, got %q", lineA)
	}
	if !strings.Contains(lineB, "0x9") {
		t.Fatalf("block b's folded v1 should render its own value 9, got %q", lineB)
	}
}

func TestUnsignedShiftUsesDalvikWidth(t *testing.T) {
	v, ok := evalMIRBinary(MIR_USHR, TypeInt, -1, 1)
	if !ok || v != 2147483647 {
		t.Fatalf("int ushr mismatch: %d %v", v, ok)
	}
	v, ok = evalMIRBinary(MIR_SHL, TypeInt, 1, 33)
	if !ok || v != 2 { // Dalvik masks int shift distance with 0x1f.
		t.Fatalf("masked int shift mismatch: %d %v", v, ok)
	}
}
