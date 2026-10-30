package ssair

import (
	"strings"
	"testing"
)

func TestTypeString(t *testing.T) {
	cases := map[Type]string{
		TypeVoid: "void", TypeBool: "bool", TypeI8: "i8", TypeI16: "i16",
		TypeI32: "i32", TypeI64: "i64", TypeF32: "f32", TypeF64: "f64",
		TypePtr: "ptr", TypeArray: "array", TypeStruct: "struct", TypeFunc: "func",
	}
	for ty, want := range cases {
		if got := ty.String(); got != want {
			t.Errorf("Type(%d).String() = %q, want %q", ty, got, want)
		}
	}
	if got := Type(99).String(); !strings.HasPrefix(got, "type(") {
		t.Errorf("unknown Type fallback wrong: %s", got)
	}
}

func TestOpcodeString(t *testing.T) {
	wellKnown := []Opcode{OpAdd, OpSub, OpMul, OpCmpEq, OpCmpNe, OpBranch, OpCondBranch,
		OpReturn, OpCall, OpPhi, OpConst, OpOpaqueTrue, OpOpaqueFalse}
	for _, o := range wellKnown {
		if got := o.String(); got == "" || strings.HasPrefix(got, "op(") {
			t.Errorf("opcode %d should have a name, got %q", o, got)
		}
	}
	if got := Opcode(9999).String(); !strings.HasPrefix(got, "op(") {
		t.Errorf("unknown opcode fallback wrong: %s", got)
	}
}

func makeModule(t *testing.T) *Module {
	t.Helper()
	m := NewModule("demo", "smali")
	if m.Name != "demo" || m.Source != "smali" {
		t.Fatalf("NewModule fields wrong: %+v", m)
	}
	return m
}

func TestModuleAddFunctionAndDump(t *testing.T) {
	m := makeModule(t)
	f := m.AddFunction("foo", TypeI32, TypeI32, TypeI32)
	if f.Name != "foo" || len(f.Params) != 2 {
		t.Fatalf("AddFunction params not stored: %+v", f)
	}

	bb := f.NewBlock("entry")
	if bb.Func != f {
		t.Errorf("NewBlock did not link Func back-reference")
	}
	if got := bb.String(); got != "entry" {
		t.Errorf("BasicBlock.String() = %q, want entry", got)
	}

	// Block without label falls back to bb%d.
	bb2 := f.NewBlock("")
	if !strings.HasPrefix(bb2.String(), "bb") {
		t.Errorf("unlabeled block should print bbN, got %s", bb2.String())
	}

	// Add a const + add instruction so Dump has something to render.
	c1 := f.NewValue("c1", TypeI32)
	cInst := &Instruction{Op: OpConst, Result: c1, ConstI64: 5}
	c1.DefInst = cInst
	bb.Append(cInst)

	c2 := f.NewValue("c2", TypeI32)
	cInst2 := &Instruction{Op: OpConst, Result: c2, ConstI64: 7}
	c2.DefInst = cInst2
	bb.Append(cInst2)

	sum := f.NewValue("sum", TypeI32)
	addInst := &Instruction{Op: OpAdd, Result: sum, Operands: []*Value{c1, c2}}
	sum.DefInst = addInst
	bb.Append(addInst)

	bb.Append(&Instruction{Op: OpReturn, Operands: []*Value{sum}})

	if f.Entry() != bb {
		t.Errorf("Entry should point to first block")
	}

	dump := m.Dump()
	for _, w := range []string{"module", "func @foo", "entry", "add", "ret"} {
		if !strings.Contains(dump, w) {
			t.Errorf("Dump missing %q\n%s", w, dump)
		}
	}

	stats := m.Stats()
	if stats.Functions != 1 {
		t.Errorf("Stats.Functions = %d, want 1", stats.Functions)
	}
	if stats.Blocks != 2 {
		t.Errorf("Stats.Blocks = %d, want 2", stats.Blocks)
	}
	if stats.Instructions != 4 {
		t.Errorf("Stats.Instructions = %d, want 4", stats.Instructions)
	}
}

func TestEntryEmptyFunction(t *testing.T) {
	f := &Function{Name: "empty"}
	if f.Entry() != nil {
		t.Errorf("Entry of empty function should be nil")
	}
}

func TestValueString(t *testing.T) {
	v1 := &Value{ID: 0, Name: "x"}
	if got := v1.String(); got != "%x" {
		t.Errorf("named Value.String() = %q, want %%x", got)
	}
	v2 := &Value{ID: 7}
	if got := v2.String(); got != "%v7" {
		t.Errorf("unnamed Value.String() = %q, want %%v7", got)
	}
}

func TestInstructionString(t *testing.T) {
	v := &Value{ID: 0, Name: "r"}
	inst := &Instruction{
		Op: OpConst, Result: v, ConstI64: 42,
	}
	got := inst.String()
	if !strings.Contains(got, "const") || !strings.Contains(got, "42") {
		t.Errorf("Instruction.String missing fields: %q", got)
	}

	// const string variant
	si := &Instruction{Op: OpConst, Result: v, ConstStr: "hi"}
	if !strings.Contains(si.String(), `"hi"`) {
		t.Errorf("string const not rendered: %q", si.String())
	}

	// add a, b
	a := &Value{ID: 1, Name: "a"}
	b := &Value{ID: 2, Name: "b"}
	add := &Instruction{Op: OpAdd, Result: v, Operands: []*Value{a, b}}
	if !strings.Contains(add.String(), "%a") || !strings.Contains(add.String(), "%b") {
		t.Errorf("Operands not rendered: %q", add.String())
	}
}

func TestTerminatorRecognition(t *testing.T) {
	m := makeModule(t)
	f := m.AddFunction("g", TypeVoid)
	bb := f.NewBlock("entry")

	if bb.Terminator() != nil {
		t.Error("empty block has no terminator")
	}

	// Non-terminator instruction shouldn't be treated as terminator.
	v := f.NewValue("x", TypeI32)
	inst := &Instruction{Op: OpConst, Result: v, ConstI64: 1}
	v.DefInst = inst
	bb.Append(inst)
	if bb.Terminator() != nil {
		t.Errorf("Terminator should be nil for non-terminator-tail")
	}

	// Branch IS a terminator.
	br := &Instruction{Op: OpBranch}
	bb.Append(br)
	if bb.Terminator() != br {
		t.Errorf("OpBranch must be recognised as terminator")
	}
}

func TestConstFoldPass(t *testing.T) {
	m := makeModule(t)
	f := m.AddFunction("addconst", TypeI32)
	bb := f.NewBlock("entry")

	c1, c1Inst := mkConst(f, 10)
	c2, c2Inst := mkConst(f, 20)
	bb.Append(c1Inst)
	bb.Append(c2Inst)

	sum := f.NewValue("sum", TypeI32)
	addInst := &Instruction{Op: OpAdd, Result: sum, Operands: []*Value{c1, c2}}
	sum.DefInst = addInst
	bb.Append(addInst)

	pass := ConstFoldPass{}
	if pass.Name() != "const-fold" {
		t.Errorf("Name = %s", pass.Name())
	}
	if !pass.Run(m) {
		t.Fatal("ConstFoldPass should report changed=true")
	}
	if addInst.Op != OpConst {
		t.Errorf("after folding, op should be OpConst, got %s", addInst.Op)
	}
	if addInst.ConstI64 != 30 {
		t.Errorf("folded value = %d, want 30", addInst.ConstI64)
	}

	// Second run should be a no-op.
	if pass.Run(m) {
		t.Error("second run should be idempotent")
	}
}

func TestConstFoldPassAllOps(t *testing.T) {
	cases := []struct {
		op   Opcode
		l, r int64
		want int64
	}{
		{OpAdd, 3, 4, 7},
		{OpSub, 10, 4, 6},
		{OpMul, 3, 5, 15},
		{OpXor, 0xF0, 0x0F, 0xFF},
		{OpAnd, 0xF0, 0x33, 0x30},
		{OpOr, 0xF0, 0x0F, 0xFF},
	}
	for _, c := range cases {
		m := makeModule(t)
		f := m.AddFunction("f", TypeI32)
		bb := f.NewBlock("e")
		l, li := mkConst(f, c.l)
		r, ri := mkConst(f, c.r)
		bb.Append(li)
		bb.Append(ri)
		out := f.NewValue("o", TypeI32)
		ai := &Instruction{Op: c.op, Result: out, Operands: []*Value{l, r}}
		out.DefInst = ai
		bb.Append(ai)
		(ConstFoldPass{}).Run(m)
		if ai.ConstI64 != c.want {
			t.Errorf("%s(%d,%d) = %d, want %d", c.op, c.l, c.r, ai.ConstI64, c.want)
		}
	}
}

func TestDCEPass(t *testing.T) {
	m := makeModule(t)
	f := m.AddFunction("dce", TypeI32)
	bb := f.NewBlock("entry")

	// Dead: unused const.
	dead, deadInst := mkConst(f, 99)
	_ = dead
	bb.Append(deadInst)

	// Live: used by return.
	live, liveInst := mkConst(f, 5)
	bb.Append(liveInst)
	bb.Append(&Instruction{Op: OpReturn, Operands: []*Value{live}})

	pass := DCEPass{}
	if pass.Name() != "dce" {
		t.Errorf("Name = %s", pass.Name())
	}
	if !pass.Run(m) {
		t.Fatal("DCEPass should report changed=true")
	}
	for _, inst := range bb.Instructions {
		if inst == deadInst {
			t.Errorf("dead instruction not removed")
		}
	}
}

func TestOpaquePredicatePass(t *testing.T) {
	m := makeModule(t)
	f := m.AddFunction("opq", TypeVoid)
	entry := f.NewBlock("entry")
	tt := f.NewBlock("taken")
	ff := f.NewBlock("untaken")

	cond := f.NewValue("c", TypeBool)
	cInst := &Instruction{Op: OpOpaqueTrue, Result: cond}
	cond.DefInst = cInst
	entry.Append(cInst)
	br := &Instruction{Op: OpCondBranch, Operands: []*Value{cond}, TrueBlock: tt, FalseBlock: ff}
	entry.Append(br)

	tt.Append(&Instruction{Op: OpReturn})
	ff.Append(&Instruction{Op: OpReturn})

	pass := &OpaquePredicatePass{}
	if pass.Name() != "opaque-predicate-removal" {
		t.Errorf("Name = %s", pass.Name())
	}
	if !pass.Run(m) {
		t.Fatal("OpaquePredicatePass should detect change")
	}
	if br.Op != OpBranch {
		t.Errorf("OpaqueTrue branch should be normalised to OpBranch, got %s", br.Op)
	}
	if br.FalseBlock != nil {
		t.Errorf("FalseBlock should be cleared")
	}
	if pass.Removed != 1 {
		t.Errorf("Removed counter = %d, want 1", pass.Removed)
	}
}

func TestOpaquePredicatePassFalse(t *testing.T) {
	m := makeModule(t)
	f := m.AddFunction("opqf", TypeVoid)
	entry := f.NewBlock("e")
	tt := f.NewBlock("t")
	ff := f.NewBlock("f")
	c := f.NewValue("c", TypeBool)
	ci := &Instruction{Op: OpOpaqueFalse, Result: c}
	c.DefInst = ci
	entry.Append(ci)
	br := &Instruction{Op: OpCondBranch, Operands: []*Value{c}, TrueBlock: tt, FalseBlock: ff}
	entry.Append(br)

	(&OpaquePredicatePass{}).Run(m)
	if br.Op != OpBranch || br.TrueBlock != ff || br.FalseBlock != nil {
		t.Errorf("Opaque-false should rewrite to unconditional branch into the false target: %+v", br)
	}
}

func TestOpaquePredicatePassXEqX(t *testing.T) {
	m := makeModule(t)
	f := m.AddFunction("xx", TypeVoid)
	bb := f.NewBlock("e")
	tt := f.NewBlock("t")
	ff := f.NewBlock("f")

	x := f.NewValue("x", TypeI32)
	cond := f.NewValue("c", TypeBool)
	cmp := &Instruction{Op: OpCmpEq, Result: cond, Operands: []*Value{x, x}}
	cond.DefInst = cmp
	bb.Append(cmp)
	br := &Instruction{Op: OpCondBranch, Operands: []*Value{cond}, TrueBlock: tt, FalseBlock: ff}
	bb.Append(br)

	if !(&OpaquePredicatePass{}).Run(m) {
		t.Fatal("x == x should be flagged opaque")
	}
	if br.Op != OpBranch {
		t.Errorf("expected normalised OpBranch")
	}
}

func TestPipelineFixpoint(t *testing.T) {
	m := makeModule(t)
	f := m.AddFunction("fp", TypeI32)
	bb := f.NewBlock("e")
	a, ai := mkConst(f, 1)
	b, bi := mkConst(f, 2)
	bb.Append(ai)
	bb.Append(bi)
	sum := f.NewValue("sum", TypeI32)
	add := &Instruction{Op: OpAdd, Result: sum, Operands: []*Value{a, b}}
	sum.DefInst = add
	bb.Append(add)
	bb.Append(&Instruction{Op: OpReturn, Operands: []*Value{sum}})

	pl := NewPipeline(ConstFoldPass{}, DCEPass{})
	if pl.MaxIters <= 0 {
		t.Errorf("MaxIters should default >0")
	}
	changes := pl.Run(m)
	if changes == 0 {
		t.Errorf("pipeline should detect changes")
	}
}

func TestHasSideEffectsClassification(t *testing.T) {
	for _, op := range []Opcode{OpStore, OpCall, OpInvoke, OpReturn, OpBranch, OpCondBranch, OpSwitch, OpUnreachable} {
		if !hasSideEffects(&Instruction{Op: op}) {
			t.Errorf("%s should be side-effecting", op)
		}
	}
	for _, op := range []Opcode{OpAdd, OpConst, OpCmpEq} {
		if hasSideEffects(&Instruction{Op: op}) {
			t.Errorf("%s should NOT be side-effecting", op)
		}
	}
}

// mkConst builds a const instruction wired to a fresh value.
func mkConst(f *Function, v int64) (*Value, *Instruction) {
	val := f.NewValue("", TypeI64)
	inst := &Instruction{Op: OpConst, Result: val, ConstI64: v}
	val.DefInst = inst
	return val, inst
}
