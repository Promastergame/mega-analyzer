package apkloader

import (
	"testing"
)

// TestUnaryKindFix verifies that unary opcodes 0x7B..0x80 map correctly to NEG vs NOT.
func TestUnaryKindFix(t *testing.T) {
	tests := []struct {
		op       uint8
		expected MIROpKind
	}{
		{0x7B, MIR_NEG}, // neg-int
		{0x7C, MIR_NOT}, // not-int
		{0x7D, MIR_NEG}, // neg-long
		{0x7E, MIR_NOT}, // not-long
		{0x7F, MIR_NEG}, // neg-float
		{0x80, MIR_NEG}, // neg-double
	}

	for _, tc := range tests {
		raw := RawInsn{Op: tc.op, Regs: [3]uint16{0, 1, 0}}
		mir := lowerOne(&raw)
		if mir.Kind != tc.expected {
			t.Errorf("op 0x%02X: got kind %v, want %v", tc.op, mir.Kind, tc.expected)
		}
	}
}

// TestRsubLoweringAndFolding verifies rsub-int opcodes 0xD1 and 0xD9 map to MIR_RSUB and fold correctly.
func TestRsubLoweringAndFolding(t *testing.T) {
	rawLit16 := RawInsn{Op: 0xD1, Regs: [3]uint16{0, 1, 0}, Imm: 10} // rsub-int v0, v1, 10
	mirLit16 := lowerOne(&rawLit16)
	if mirLit16.Kind != MIR_RSUB {
		t.Fatalf("0xD1: got kind %v, want MIR_RSUB", mirLit16.Kind)
	}

	rawLit8 := RawInsn{Op: 0xD9, Regs: [3]uint16{0, 1, 0}, Imm: 10} // rsub-int/lit8 v0, v1, 10
	mirLit8 := lowerOne(&rawLit8)
	if mirLit8.Kind != MIR_RSUB {
		t.Fatalf("0xD9: got kind %v, want MIR_RSUB", mirLit8.Kind)
	}

	// Constant propagation test: v0 = 10 - v1 (v1 = 3) -> v0 = 7
	block := &BasicBlock{
		ID: 0,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Dst: 1, Imm: 3},
			mirLit16,
		},
	}
	cfg := &CFG{Blocks: []*BasicBlock{block}, Entry: block}
	pr := ConstantPropagation(cfg, nil)

	c := pr.GetConstantValue(0)
	if c == nil || c.Value != int64(7) {
		t.Fatalf("rsub constant folding: got %v, want 7", c)
	}
}

// TestAputOperandAssignment verifies APUT operand fields for SSA safety (Dst == -1, Src3 = value).
func TestAputOperandAssignment(t *testing.T) {
	// aput v0, v1, v2 => Regs[0]=val(0), Regs[1]=array(1), Regs[2]=index(2)
	raw := RawInsn{Op: 0x4B, Regs: [3]uint16{0, 1, 2}}
	mir := lowerOne(&raw)

	if mir.Kind != MIR_ARRAY_PUT {
		t.Fatalf("got kind %v, want MIR_ARRAY_PUT", mir.Kind)
	}
	if mir.Dst != -1 {
		t.Errorf("APUT Dst must be -1, got %d", mir.Dst)
	}
	if mir.Src1 != 1 {
		t.Errorf("APUT Src1 (array) got %d, want 1", mir.Src1)
	}
	if mir.Src2 != 2 {
		t.Errorf("APUT Src2 (index) got %d, want 2", mir.Src2)
	}
	if mir.Src3 != 0 {
		t.Errorf("APUT Src3 (value) got %d, want 0", mir.Src3)
	}
}

// TestCheckCastDestination verifies CHECK_CAST sets Dst to Regs[0].
func TestCheckCastDestination(t *testing.T) {
	raw := RawInsn{Op: 0x1F, Regs: [3]uint16{4, 0, 0}}
	mir := lowerOne(&raw)

	if mir.Kind != MIR_CHECK_CAST {
		t.Fatalf("got kind %v, want MIR_CHECK_CAST", mir.Kind)
	}
	if mir.Dst != 4 || mir.Src1 != 4 {
		t.Errorf("CHECK_CAST Dst/Src1 got Dst=%d Src1=%d, want 4", mir.Dst, mir.Src1)
	}
}

// TestCmplCmpgDistinction verifies cmpl vs cmpg lowering.
func TestCmplCmpgDistinction(t *testing.T) {
	cmpl := lowerOne(&RawInsn{Op: 0x2D, Regs: [3]uint16{0, 1, 2}})
	if cmpl.Kind != MIR_CMPL || cmpl.CmpKind != CmpL {
		t.Errorf("cmpl: got kind %v cmpKind %v", cmpl.Kind, cmpl.CmpKind)
	}

	cmpg := lowerOne(&RawInsn{Op: 0x2E, Regs: [3]uint16{0, 1, 2}})
	if cmpg.Kind != MIR_CMPG || cmpg.CmpKind != CmpG {
		t.Errorf("cmpg: got kind %v cmpKind %v", cmpg.Kind, cmpg.CmpKind)
	}
}

// TestUnknownOpcodeLowering verifies unknown opcodes become MIR_UNKNOWN.
func TestUnknownOpcodeLowering(t *testing.T) {
	raw := RawInsn{Op: 0xFD}
	mir := lowerOne(&raw)

	if mir.Kind != MIR_UNKNOWN {
		t.Errorf("unknown op: got kind %v, want MIR_UNKNOWN", mir.Kind)
	}
	if mir.Imm != 0xFD {
		t.Errorf("unknown op: got Imm %d, want 0xFD", mir.Imm)
	}
}

// TestInvokeArgsAndMIRMethod verifies MIRMethod construction and invoke args.
func TestInvokeArgsAndMIRMethod(t *testing.T) {
	raws := []RawInsn{
		{Op: 0x6E, Offset: 0, RegCount: 2, Regs: [3]uint16{5, 6, 0}, RefIdx: 10},
	}
	code := &CodeItem{
		Insns: []uint16{0x206E, 0x000A, 0x0065}, // inline code units
	}

	method := LowerMethodToMIR(raws, code)
	if len(method.Insns) != 1 {
		t.Fatalf("expected 1 insn, got %d", len(method.Insns))
	}
	if method.Insns[0].Kind != MIR_INVOKE {
		t.Fatalf("got kind %v, want MIR_INVOKE", method.Insns[0].Kind)
	}
	if len(method.Insns[0].Args()) != 2 {
		t.Fatalf("got %d args, want 2", len(method.Insns[0].Args()))
	}
}

// TestSwitchTargetsCFG verifies switch target leaders and edges are added to CFG.
func TestSwitchTargetsCFG(t *testing.T) {
	// Offset 0: MIR_SWITCH (Imm=4 points to offset 4)
	// Offset 3: MIR_RETURN (fallthrough)
	// Offset 4: MIR_PAYLOAD (packed-switch payload with 1 target pointing to offset 10)
	// Offset 10: MIR_CONST (switch target)
	// Offset 11: MIR_RETURN
	mir := []MIRInsn{
		{Kind: MIR_SWITCH, Offset: 0, Imm: 4, Src1: 0},
		{Kind: MIR_RETURN, Offset: 3},
		{Kind: MIR_PAYLOAD, Offset: 4},
		{Kind: MIR_CONST, Offset: 10, Dst: 1, Imm: 42},
		{Kind: MIR_RETURN, Offset: 11},
	}

	codeUnits := []uint16{
		0x002B, 0x0004, 0x0000, // offset 0..2: switch v0, +4
		0x000E,         // offset 3: return-void
		0x0100, 0x0001, // offset 4..5: packed-switch, size=1
		0x0000, 0x0000, // offset 6..7: first_key=0
		0x000A, 0x0000, // offset 8..9: target_rel=+10 (points to PC offset 10)
		0x0012, // offset 10: const/4 v1, 42
		0x000E, // offset 11: return-void
	}

	handlers := &CodeItem{Insns: codeUnits}
	cfg := BuildCFGWithHandlers(mir, handlers)

	// Block containing switch should have 2 successors: fallthrough (offset 3) and target (offset 10)
	switchBlock := cfg.offsetToBlock[0]
	if switchBlock == nil {
		t.Fatalf("missing block for switch offset 0")
	}
	if len(switchBlock.Succs) < 2 {
		t.Errorf("switch block should have at least 2 successors (target + fallthrough), got %d", len(switchBlock.Succs))
	}

	targetBlock := cfg.offsetToBlock[10]
	if targetBlock == nil {
		t.Fatalf("missing block for target offset 10")
	}
	if !targetBlock.IsReachable {
		t.Errorf("switch target block offset 10 should be marked reachable")
	}
}
