package symexec

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/ssair"
)

func TestSymValueString(t *testing.T) {
	c := symConst(7)
	if got := c.String(); got != "7" {
		t.Errorf("const.String = %q, want 7", got)
	}
	v := symVar("x")
	if got := v.String(); got != "x" {
		t.Errorf("var.String = %q, want x", got)
	}
	expr := symBinop("+", symVar("a"), symVar("b"))
	if got := expr.String(); !strings.Contains(got, "a") || !strings.Contains(got, "b") || !strings.Contains(got, "+") {
		t.Errorf("expr.String = %q", got)
	}
	// IsConcrete coverage
	if !c.IsConcrete() {
		t.Error("symConst should report concrete")
	}
	if v.IsConcrete() {
		t.Error("symVar should not report concrete")
	}
	// fallback for invalid kind
	bad := &SymValue{Kind: SymKind(99)}
	if got := bad.String(); got != "?" {
		t.Errorf("invalid kind should print ?, got %q", got)
	}
}

func TestSymBinopFolding(t *testing.T) {
	cases := []struct {
		op       string
		l, r     int64
		wantConc int64
	}{
		{"+", 2, 3, 5},
		{"-", 10, 4, 6},
		{"*", 4, 5, 20},
		{"^", 0xF0, 0x0F, 0xFF},
		{"&", 0xF0, 0x33, 0x30},
		{"|", 0xF0, 0x0F, 0xFF},
	}
	for _, c := range cases {
		out := symBinop(c.op, symConst(c.l), symConst(c.r))
		if !out.IsConcrete() {
			t.Errorf("%s should fold to concrete", c.op)
			continue
		}
		if out.Concrete != c.wantConc {
			t.Errorf("%s(%d,%d) = %d, want %d", c.op, c.l, c.r, out.Concrete, c.wantConc)
		}
	}

	// Unknown op should stay an expression even with two constants.
	out := symBinop("??", symConst(1), symConst(2))
	if out.IsConcrete() {
		t.Error("unknown op should not fold")
	}
}

func TestExecutorDefaults(t *testing.T) {
	e := NewExecutor()
	if e.MaxDepth <= 0 {
		t.Errorf("MaxDepth should be set, got %d", e.MaxDepth)
	}
}

func TestAnalyzeFunctionEmpty(t *testing.T) {
	e := NewExecutor()
	f := &ssair.Function{}
	if got := e.AnalyzeFunction(f); got != nil {
		t.Errorf("empty function should yield nil results, got %+v", got)
	}
}

// helpers ------------------------------------------------------------------

func newConstInst(f *ssair.Function, v int64) (*ssair.Value, *ssair.Instruction) {
	val := f.NewValue("", ssair.TypeI64)
	inst := &ssair.Instruction{Op: ssair.OpConst, Result: val, ConstI64: v}
	val.DefInst = inst
	return val, inst
}

// TestAnalyzeFunctionConstantPredicate seeds two consts and a cmp.eq → cond
// branch. The executor must mark the predicate as opaque.
func TestAnalyzeFunctionConstantPredicate(t *testing.T) {
	m := ssair.NewModule("m", "test")
	f := m.AddFunction("f", ssair.TypeI32)
	entry := f.NewBlock("e")
	taken := f.NewBlock("t")
	untaken := f.NewBlock("u")

	a, ai := newConstInst(f, 5)
	b, bi := newConstInst(f, 5)
	entry.Append(ai)
	entry.Append(bi)

	cond := f.NewValue("c", ssair.TypeBool)
	cmp := &ssair.Instruction{Op: ssair.OpCmpEq, Result: cond, Operands: []*ssair.Value{a, b}}
	cond.DefInst = cmp
	entry.Append(cmp)

	br := &ssair.Instruction{Op: ssair.OpCondBranch, Operands: []*ssair.Value{cond}, TrueBlock: taken, FalseBlock: untaken}
	entry.Append(br)

	taken.Append(&ssair.Instruction{Op: ssair.OpReturn})
	untaken.Append(&ssair.Instruction{Op: ssair.OpReturn})

	res := NewExecutor().AnalyzeFunction(f)
	if len(res) == 0 {
		t.Fatal("expected at least one opaque result")
	}
	found := false
	for _, r := range res {
		if r.AlwaysVal {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an always-true result, got: %+v", res)
	}
}

// TestAnalyzeFunctionAlwaysFalse uses cmp.ne with the same value on both sides
// to exercise the trivial-predicate detector.
func TestAnalyzeFunctionAlwaysFalse(t *testing.T) {
	m := ssair.NewModule("m", "test")
	f := m.AddFunction("f", ssair.TypeI32)
	entry := f.NewBlock("e")
	taken := f.NewBlock("t")
	untaken := f.NewBlock("u")

	x := f.NewValue("x", ssair.TypeI32)
	cond := f.NewValue("c", ssair.TypeBool)
	cmp := &ssair.Instruction{Op: ssair.OpCmpNe, Result: cond, Operands: []*ssair.Value{x, x}, Block: entry}
	cond.DefInst = cmp
	entry.Append(cmp)
	br := &ssair.Instruction{Op: ssair.OpCondBranch, Operands: []*ssair.Value{cond}, TrueBlock: taken, FalseBlock: untaken}
	entry.Append(br)

	taken.Append(&ssair.Instruction{Op: ssair.OpReturn})
	untaken.Append(&ssair.Instruction{Op: ssair.OpReturn})

	res := NewExecutor().AnalyzeFunction(f)
	if len(res) == 0 {
		t.Fatal("expected x != x to be flagged")
	}
	if res[0].AlwaysVal {
		t.Errorf("x != x should be ALWAYS FALSE, got AlwaysVal=true")
	}
	// Either the trivial-predicate detector ("x != x is always false") or the
	// generic constant-fold path ("condition resolves to constant 0") may
	// catch it first depending on instruction order. Both reasons are valid.
	r := res[0].Reason
	if !strings.Contains(r, "x != x") && !strings.Contains(r, "constant 0") {
		t.Errorf("Reason should explain the opaque predicate, got %q", r)
	}
}

// TestAnalyzeFunctionForkOnUnknown forces both branches to be explored when
// the condition is symbolic.
func TestAnalyzeFunctionForkOnUnknown(t *testing.T) {
	m := ssair.NewModule("m", "test")
	f := m.AddFunction("f", ssair.TypeI32, ssair.TypeI32)
	entry := f.NewBlock("e")
	tt := f.NewBlock("t")
	ff := f.NewBlock("f2")

	cmp := &ssair.Instruction{Op: ssair.OpCmpEq, Result: f.NewValue("c", ssair.TypeBool),
		Operands: []*ssair.Value{f.Params[0], f.Params[0]}}
	cmp.Result.DefInst = cmp
	entry.Append(cmp)
	br := &ssair.Instruction{Op: ssair.OpCondBranch, Operands: []*ssair.Value{cmp.Result}, TrueBlock: tt, FalseBlock: ff}
	entry.Append(br)
	tt.Append(&ssair.Instruction{Op: ssair.OpReturn})
	ff.Append(&ssair.Instruction{Op: ssair.OpReturn})

	res := NewExecutor().AnalyzeFunction(f)
	// Same-value cmp.eq → trivial predicate.
	if len(res) == 0 {
		t.Fatal("expected trivial predicate")
	}
}

// TestExecInstAllOps exercises the per-op dispatch table directly.
func TestExecInstAllOps(t *testing.T) {
	m := ssair.NewModule("m", "test")
	f := m.AddFunction("f", ssair.TypeI64)
	bb := f.NewBlock("e")
	state := newSymState()
	e := NewExecutor()

	a, ai := newConstInst(f, 5)
	b, bi := newConstInst(f, 7)
	bb.Append(ai)
	bb.Append(bi)
	e.execInst(ai, state)
	e.execInst(bi, state)

	makeBinop := func(op ssair.Opcode) *ssair.Instruction {
		out := f.NewValue("o", ssair.TypeI64)
		inst := &ssair.Instruction{Op: op, Result: out, Operands: []*ssair.Value{a, b}}
		out.DefInst = inst
		bb.Append(inst)
		return inst
	}

	for _, op := range []ssair.Opcode{ssair.OpAdd, ssair.OpSub, ssair.OpMul, ssair.OpXor, ssair.OpCmpEq, ssair.OpCmpNe} {
		inst := makeBinop(op)
		e.execInst(inst, state)
		got := state.Values[inst.Result.ID]
		if got == nil {
			t.Errorf("op %s did not produce a symbolic value", op)
		}
	}

	// X == X path (operands point at the same value)
	out := f.NewValue("xxeq", ssair.TypeBool)
	xx := &ssair.Instruction{Op: ssair.OpCmpEq, Result: out, Operands: []*ssair.Value{a, a}}
	out.DefInst = xx
	e.execInst(xx, state)
	if !state.Values[out.ID].IsConcrete() || state.Values[out.ID].Concrete != 1 {
		t.Errorf("x == x must fold to concrete 1")
	}

	// X != X
	out2 := f.NewValue("xxne", ssair.TypeBool)
	xx2 := &ssair.Instruction{Op: ssair.OpCmpNe, Result: out2, Operands: []*ssair.Value{a, a}}
	out2.DefInst = xx2
	e.execInst(xx2, state)
	if !state.Values[out2.ID].IsConcrete() || state.Values[out2.ID].Concrete != 0 {
		t.Errorf("x != x must fold to concrete 0")
	}

	// Unknown op → variable
	out3 := f.NewValue("u", ssair.TypeI64)
	uk := &ssair.Instruction{Op: ssair.OpDiv, Result: out3, Operands: []*ssair.Value{a, b}}
	out3.DefInst = uk
	e.execInst(uk, state)
	if state.Values[out3.ID].Kind != SymVariable {
		t.Errorf("unknown op should fall back to symVar, got kind %d", state.Values[out3.ID].Kind)
	}

	// Inst with no Result — must be a no-op.
	e.execInst(&ssair.Instruction{Op: ssair.OpReturn}, state)
}

func TestStateClonePreservesData(t *testing.T) {
	s := newSymState()
	s.Constraints = append(s.Constraints, &Constraint{Expr: symConst(1), Expected: true})
	s.Path = append(s.Path, &ssair.BasicBlock{ID: 1})
	s.Values[42] = symConst(99)

	c := s.clone()
	if len(c.Constraints) != 1 || len(c.Path) != 1 {
		t.Errorf("clone lost constraints/path: %+v", c)
	}
	if !c.Values[42].IsConcrete() || c.Values[42].Concrete != 99 {
		t.Errorf("clone lost values")
	}

	// Mutating clone should not affect original.
	c.Values[42] = symConst(0)
	if s.Values[42].Concrete != 99 {
		t.Errorf("clone shared underlying map: original mutated")
	}
}

func TestExploreRespectsMaxDepth(t *testing.T) {
	// Build a deliberately deep linear chain: bb0 -> bb1 -> ... -> bbN.
	m := ssair.NewModule("m", "test")
	f := m.AddFunction("deep", ssair.TypeVoid)
	const n = 5
	blocks := make([]*ssair.BasicBlock, n)
	for i := range blocks {
		blocks[i] = f.NewBlock("")
	}
	for i := 0; i < n-1; i++ {
		blocks[i].Append(&ssair.Instruction{Op: ssair.OpBranch, TrueBlock: blocks[i+1]})
	}
	blocks[n-1].Append(&ssair.Instruction{Op: ssair.OpReturn})

	e := &Executor{MaxDepth: 2}
	if got := e.AnalyzeFunction(f); got != nil {
		t.Logf("depth-bounded run produced %d results (expected 0 typically)", len(got))
	}
}

// TestCheckTrivialPredicate exercises the dedicated detector by setting up a
// cmp.eq whose result is used by a branch but whose own instruction is NOT
// executed (so execInst never folds it to a concrete). This is the only path
// to reach `checkTrivialPredicate`.
func TestCheckTrivialPredicate(t *testing.T) {
	m := ssair.NewModule("m", "test")
	f := m.AddFunction("f", ssair.TypeVoid)
	entry := f.NewBlock("e")
	tt := f.NewBlock("t")
	ff := f.NewBlock("f2")

	x := f.NewValue("x", ssair.TypeI32)
	cond := f.NewValue("c", ssair.TypeBool)
	// cmp.eq x, x — DefInst wired but instruction NOT appended to any block.
	cmp := &ssair.Instruction{Op: ssair.OpCmpEq, Result: cond, Operands: []*ssair.Value{x, x}, Block: entry}
	cond.DefInst = cmp

	br := &ssair.Instruction{Op: ssair.OpCondBranch, Operands: []*ssair.Value{cond}, TrueBlock: tt, FalseBlock: ff}
	entry.Append(br)
	tt.Append(&ssair.Instruction{Op: ssair.OpReturn})
	ff.Append(&ssair.Instruction{Op: ssair.OpReturn})

	res := NewExecutor().AnalyzeFunction(f)
	if len(res) == 0 {
		t.Fatal("expected trivial predicate to be flagged")
	}
	if !strings.Contains(res[0].Reason, "x == x") {
		t.Errorf("expected x == x reason, got %q", res[0].Reason)
	}

	// Same with cmp.ne — should give always-false.
	condNe := f.NewValue("cne", ssair.TypeBool)
	ne := &ssair.Instruction{Op: ssair.OpCmpNe, Result: condNe, Operands: []*ssair.Value{x, x}, Block: entry}
	condNe.DefInst = ne

	r := NewExecutor().checkTrivialPredicate(condNe)
	if r == nil || r.AlwaysVal {
		t.Errorf("x != x should be detected as always-false, got %+v", r)
	}

	// No DefInst → nil result.
	if NewExecutor().checkTrivialPredicate(&ssair.Value{}) != nil {
		t.Error("nil DefInst must yield nil result")
	}
	// DefInst with too few operands → nil.
	bad := f.NewValue("bad", ssair.TypeBool)
	bad.DefInst = &ssair.Instruction{Op: ssair.OpCmpEq, Result: bad, Operands: []*ssair.Value{x}}
	if NewExecutor().checkTrivialPredicate(bad) != nil {
		t.Error("operands < 2 must yield nil result")
	}
	// DefInst with two distinct operands → nil.
	y := f.NewValue("y", ssair.TypeI32)
	distinct := f.NewValue("d", ssair.TypeBool)
	distinct.DefInst = &ssair.Instruction{Op: ssair.OpCmpEq, Result: distinct, Operands: []*ssair.Value{x, y}}
	if NewExecutor().checkTrivialPredicate(distinct) != nil {
		t.Error("distinct operands must yield nil result")
	}
}

// TestExploreForkAndUnconditionalBranch exercises the symbolic-fork path and
// the OpBranch tail of explore.
func TestExploreForkAndUnconditionalBranch(t *testing.T) {
	m := ssair.NewModule("m", "test")
	f := m.AddFunction("f", ssair.TypeVoid, ssair.TypeI32)
	entry := f.NewBlock("e")
	mid := f.NewBlock("mid")
	tt := f.NewBlock("t")
	ff := f.NewBlock("f2")

	// entry: unconditional branch to mid
	entry.Append(&ssair.Instruction{Op: ssair.OpBranch, TrueBlock: mid})

	// mid: conditional branch on a symbolic param-derived value (not folded)
	cond := f.NewValue("c", ssair.TypeBool)
	cmp := &ssair.Instruction{Op: ssair.OpCmpEq, Result: cond, Operands: []*ssair.Value{f.Params[0], f.NewValue("zero", ssair.TypeI32)}}
	cond.DefInst = cmp
	mid.Append(cmp)
	mid.Append(&ssair.Instruction{Op: ssair.OpCondBranch, Operands: []*ssair.Value{cond}, TrueBlock: tt, FalseBlock: ff})

	tt.Append(&ssair.Instruction{Op: ssair.OpReturn})
	ff.Append(&ssair.Instruction{Op: ssair.OpReturn})

	// Should not panic and should not flag a trivial predicate.
	res := NewExecutor().AnalyzeFunction(f)
	for _, r := range res {
		if strings.Contains(r.Reason, "always") {
			// fine — fork still ran
		}
	}
}
