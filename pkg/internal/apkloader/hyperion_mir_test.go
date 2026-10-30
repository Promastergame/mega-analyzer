package apkloader

import "testing"

// ═══════════════════════════════════════════════════════════════════════════════
// MIR Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestLowerToMIR_ConstReturn(t *testing.T) {
	raw := []RawInsn{
		{Op: 0x12, Format: Fmt11n, Regs: [3]uint16{0, 0, 0}, RegCount: 1, Imm: 1, Offset: 0, Size: 1, Flags: FlagConst},
		{Op: 0x0F, Format: Fmt11x, Regs: [3]uint16{0, 0, 0}, RegCount: 1, Offset: 1, Size: 1, Flags: FlagReturn},
	}

	mir := LowerToMIR(raw)
	if len(mir) != 2 {
		t.Fatalf("expected 2 MIR insns, got %d", len(mir))
	}

	// const/4 v0, 1 → MIR_CONST
	if mir[0].Kind != MIR_CONST {
		t.Errorf("insn[0].Kind = %d, want MIR_CONST", mir[0].Kind)
	}
	if mir[0].Dst != 0 {
		t.Errorf("insn[0].Dst = %d, want 0", mir[0].Dst)
	}
	if mir[0].Imm != 1 {
		t.Errorf("insn[0].Imm = %d, want 1", mir[0].Imm)
	}

	// return v0 → MIR_RETURN
	if mir[1].Kind != MIR_RETURN {
		t.Errorf("insn[1].Kind = %d, want MIR_RETURN", mir[1].Kind)
	}
	if mir[1].Src1 != 0 {
		t.Errorf("insn[1].Src1 = %d, want 0", mir[1].Src1)
	}
}

func TestLowerToMIR_BinopNormalization(t *testing.T) {
	// All three forms should normalize to the same MIR_ADD:
	// add-int (0x90), add-int/2addr (0xB0), add-int/lit8 (0xD8)
	variants := []RawInsn{
		{Op: 0x90, Format: Fmt23x, Regs: [3]uint16{0, 1, 2}, RegCount: 3, Offset: 0, Size: 2},
		{Op: 0xB0, Format: Fmt12x, Regs: [3]uint16{0, 1, 0}, RegCount: 2, Offset: 2, Size: 1},
		{Op: 0xD8, Format: Fmt22b, Regs: [3]uint16{0, 1, 0}, RegCount: 2, Imm: 5, Offset: 3, Size: 2},
	}

	mir := LowerToMIR(variants)
	if len(mir) != 3 {
		t.Fatalf("expected 3 MIR insns, got %d", len(mir))
	}

	for i, m := range mir {
		if m.Kind != MIR_ADD {
			t.Errorf("insn[%d]: Kind = %d, want MIR_ADD (%d)", i, m.Kind, MIR_ADD)
		}
		if m.DataType != TypeInt {
			t.Errorf("insn[%d]: DataType = %d, want TypeInt", i, m.DataType)
		}
	}
}

func TestLowerToMIR_IfConditions(t *testing.T) {
	tests := []struct {
		op   uint8
		cond MIRCondition
	}{
		{0x32, CondEQ},
		{0x33, CondNE},
		{0x34, CondLT},
		{0x38, CondEQZ},
		{0x39, CondNEZ},
	}

	for _, tt := range tests {
		raw := []RawInsn{{
			Op: tt.op, Format: Fmt22t, Regs: [3]uint16{0, 1, 0},
			RegCount: 2, Imm: 5, Offset: 0, Size: 2, Flags: FlagBranch,
		}}
		mir := LowerToMIR(raw)
		if mir[0].Kind != MIR_IF {
			t.Errorf("op 0x%02x: Kind = %d, want MIR_IF", tt.op, mir[0].Kind)
		}
		if mir[0].Cond != tt.cond {
			t.Errorf("op 0x%02x: Cond = %d, want %d", tt.op, mir[0].Cond, tt.cond)
		}
	}
}

func TestLowerToMIR_FieldAccess(t *testing.T) {
	raw := []RawInsn{
		{Op: 0x54, Format: Fmt22c, Regs: [3]uint16{0, 1, 0}, RegCount: 2, RefIdx: 42, RefKind: RefField, Offset: 0, Size: 2, Flags: FlagFieldOp},
		{Op: 0x62, Format: Fmt21c, Regs: [3]uint16{0, 0, 0}, RegCount: 1, RefIdx: 10, RefKind: RefField, Offset: 2, Size: 2, Flags: FlagFieldOp},
	}

	mir := LowerToMIR(raw)

	// iget-object → instance field get
	if mir[0].Kind != MIR_FIELD_GET {
		t.Errorf("iget: Kind = %d, want MIR_FIELD_GET", mir[0].Kind)
	}
	if mir[0].FieldKind != FieldInstance {
		t.Errorf("iget: FieldKind = %d, want FieldInstance", mir[0].FieldKind)
	}

	// sget-object → static field get
	if mir[1].Kind != MIR_FIELD_GET {
		t.Errorf("sget: Kind = %d, want MIR_FIELD_GET", mir[1].Kind)
	}
	if mir[1].FieldKind != FieldStatic {
		t.Errorf("sget: FieldKind = %d, want FieldStatic", mir[1].FieldKind)
	}
}

func TestLowerToMIR_Invoke(t *testing.T) {
	raw := []RawInsn{
		{Op: 0x6E, Format: Fmt35c, RegCount: 2, RefIdx: 100, RefKind: RefMethod, Offset: 0, Size: 3, Flags: FlagInvoke},
		{Op: 0x71, Format: Fmt35c, RegCount: 1, RefIdx: 200, RefKind: RefMethod, Offset: 3, Size: 3, Flags: FlagInvoke},
	}

	mir := LowerToMIR(raw)
	if mir[0].Kind != MIR_INVOKE {
		t.Errorf("invoke-virtual: Kind = %d, want MIR_INVOKE", mir[0].Kind)
	}
	if mir[0].InvokeKind != InvokeVirtual {
		t.Errorf("invoke-virtual: InvokeKind = %d, want InvokeVirtual", mir[0].InvokeKind)
	}
	if mir[1].InvokeKind != InvokeStatic {
		t.Errorf("invoke-static: InvokeKind = %d, want InvokeStatic", mir[1].InvokeKind)
	}
}

func TestLowerToMIR_Empty(t *testing.T) {
	result := LowerToMIR(nil)
	if result != nil {
		t.Errorf("LowerToMIR(nil) should return nil, got %v", result)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CFG Tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestBuildCFG_LinearMethod(t *testing.T) {
	// Simple: const + return (no branches → 1 block)
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0},
		{Kind: MIR_RETURN, Offset: 1},
	}

	cfg := BuildCFG(mir)
	if cfg.BlockCount() != 1 {
		t.Errorf("linear method: blocks = %d, want 1", cfg.BlockCount())
	}
	if len(cfg.Entry.Insns) != 2 {
		t.Errorf("entry block insns = %d, want 2", len(cfg.Entry.Insns))
	}
}

func TestBuildCFG_IfBranch(t *testing.T) {
	// if-eqz v0, +2; const/4 v0, 1; return v0
	mir := []MIRInsn{
		{Kind: MIR_IF, Offset: 0, Imm: 4, RawFlags: FlagBranch}, // → offset 4
		{Kind: MIR_CONST, Offset: 2},                            // fallthrough
		{Kind: MIR_RETURN, Offset: 3},                           // block end
		{Kind: MIR_CONST, Offset: 4},                            // branch target
		{Kind: MIR_RETURN, Offset: 5},
	}

	cfg := BuildCFG(mir)

	// Should have 3 blocks: [if], [const+return], [const+return]
	if cfg.BlockCount() < 2 {
		t.Errorf("if-branch: blocks = %d, want >= 2", cfg.BlockCount())
	}

	// Entry should have 2 successors (taken + fallthrough)
	if len(cfg.Entry.Succs) != 2 {
		t.Errorf("entry succs = %d, want 2", len(cfg.Entry.Succs))
	}
}

func TestBuildCFG_Goto(t *testing.T) {
	// goto +2; nop; return
	mir := []MIRInsn{
		{Kind: MIR_GOTO, Offset: 0, Imm: 2, RawFlags: FlagBranch},
		{Kind: MIR_NOP, Offset: 1},
		{Kind: MIR_RETURN, Offset: 2},
	}

	cfg := BuildCFG(mir)
	if cfg.BlockCount() < 2 {
		t.Errorf("goto: blocks = %d, want >= 2", cfg.BlockCount())
	}

	// Entry should have exactly 1 successor (the goto target)
	if len(cfg.Entry.Succs) != 1 {
		t.Errorf("entry succs = %d, want 1", len(cfg.Entry.Succs))
	}
}

func TestBuildCFG_Dominance(t *testing.T) {
	// Simple diamond: entry → if → [then, else] → merge → return
	mir := []MIRInsn{
		{Kind: MIR_IF, Offset: 0, Imm: 3, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 2},
		{Kind: MIR_RETURN, Offset: 3},
	}

	cfg := BuildCFG(mir)
	cfg.ComputeDominance()

	// Entry block should dominate all other blocks
	if cfg.Entry.IDom != nil {
		t.Error("entry should have no immediate dominator")
	}
	for _, b := range cfg.Blocks[1:] {
		if b.IDom == nil {
			t.Errorf("block %d should have an immediate dominator", b.ID)
		}
	}
}

func TestBuildCFG_Empty(t *testing.T) {
	cfg := BuildCFG(nil)
	if cfg.BlockCount() != 0 {
		t.Errorf("empty CFG should have 0 blocks, got %d", cfg.BlockCount())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Benchmarks
// ═══════════════════════════════════════════════════════════════════════════════

func BenchmarkLowerToMIR(b *testing.B) {
	// Build a realistic raw instruction stream
	raw := make([]RawInsn, 500)
	for i := range raw {
		switch i % 5 {
		case 0:
			raw[i] = RawInsn{Op: 0x12, Flags: FlagConst, Size: 1, Offset: uint32(i)}
		case 1:
			raw[i] = RawInsn{Op: 0x90, Size: 2, Offset: uint32(i)}
		case 2:
			raw[i] = RawInsn{Op: 0x54, Flags: FlagFieldOp, RefKind: RefField, Size: 2, Offset: uint32(i)}
		case 3:
			raw[i] = RawInsn{Op: 0x6E, Flags: FlagInvoke, RefKind: RefMethod, Size: 3, Offset: uint32(i)}
		case 4:
			raw[i] = RawInsn{Op: 0x38, Flags: FlagBranch, Imm: 2, Size: 2, Offset: uint32(i)}
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		mir := LowerToMIR(raw)
		_ = mir
	}
}

func BenchmarkBuildCFG(b *testing.B) {
	// Create MIR with branches to force multiple blocks
	mir := make([]MIRInsn, 200)
	for i := range mir {
		switch i % 10 {
		case 0:
			mir[i] = MIRInsn{Kind: MIR_IF, Offset: uint32(i), Imm: 5, RawFlags: FlagBranch}
		case 9:
			mir[i] = MIRInsn{Kind: MIR_RETURN, Offset: uint32(i)}
		default:
			mir[i] = MIRInsn{Kind: MIR_CONST, Offset: uint32(i)}
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		cfg := BuildCFG(mir)
		cfg.ComputeDominance()
		_ = cfg
	}
}
