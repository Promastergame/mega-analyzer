package smt

import "testing"

// ═══════════════════════════════════════════════════════════════════════════════
// Sort / Op String tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSort_String(t *testing.T) {
	tests := []struct {
		s    Sort
		want string
	}{
		{SortBool, "Bool"},
		{SortInt, "Int"},
		{SortBitvec32, "BV32"},
		{SortBitvec64, "BV64"},
		{SortString, "String"},
		{SortRef, "Ref"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Sort(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestCompOp_String(t *testing.T) {
	tests := []struct {
		op   CompOp
		want string
	}{
		{OpEq, "="},
		{OpNe, "≠"},
		{OpLt, "<"},
		{OpLe, "≤"},
		{OpGt, ">"},
		{OpGe, "≥"},
	}
	for _, tt := range tests {
		if got := tt.op.String(); got != tt.want {
			t.Errorf("CompOp(%d).String() = %q, want %q", tt.op, got, tt.want)
		}
	}
}

func TestArithOp_String(t *testing.T) {
	tests := []struct {
		op   ArithOp
		want string
	}{
		{OpAdd, "+"},
		{OpSub, "-"},
		{OpMul, "*"},
		{OpDiv, "/"},
		{OpMod, "%"},
	}
	for _, tt := range tests {
		if got := tt.op.String(); got != tt.want {
			t.Errorf("ArithOp(%d).String() = %q, want %q", tt.op, got, tt.want)
		}
	}
}

func TestSolverResult_String(t *testing.T) {
	tests := []struct {
		r    SolverResult
		want string
	}{
		{Satisfiable, "SAT"},
		{Unsatisfiable, "UNSAT"},
		{Unknown, "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("SolverResult(%d).String() = %q, want %q", tt.r, got, tt.want)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Expression String tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestBoolConst_String(t *testing.T) {
	if (&BoolConst{Value: true}).String() != "true" {
		t.Fatal("true const")
	}
	if (&BoolConst{Value: false}).String() != "false" {
		t.Fatal("false const")
	}
}

func TestIntConst_String(t *testing.T) {
	if (&IntConst{Value: 42}).String() != "42" {
		t.Fatal("int const")
	}
	if (&IntConst{Value: -1}).String() != "-1" {
		t.Fatal("negative int const")
	}
}

func TestOr_String(t *testing.T) {
	expr := &Or{Left: &BoolConst{Value: true}, Right: &BoolConst{Value: false}}
	if expr.String() != "(true ∨ false)" {
		t.Fatalf("got %q", expr.String())
	}
}

func TestNot_String(t *testing.T) {
	expr := &Not{Inner: &BoolConst{Value: true}}
	if expr.String() != "¬true" {
		t.Fatalf("got %q", expr.String())
	}
}

func TestCompare_String(t *testing.T) {
	expr := &Compare{Op: OpLt, Left: &IntConst{Value: 3}, Right: &IntConst{Value: 5}}
	if expr.String() != "(3 < 5)" {
		t.Fatalf("got %q", expr.String())
	}
}

func TestArith_String(t *testing.T) {
	expr := &Arith{Op: OpAdd, Left: &IntConst{Value: 2}, Right: &IntConst{Value: 3}}
	if expr.String() != "(2 + 3)" {
		t.Fatalf("got %q", expr.String())
	}
	if expr.GetSort() != SortInt {
		t.Fatal("arith sort should be Int")
	}
}

func TestSymValue_String(t *testing.T) {
	sv := &SymValue{ID: 1, Name: "myVar", Sort: SortBool}
	if sv.String() != "myVar" {
		t.Fatalf("got %q", sv.String())
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// GetSort tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestExpr_GetSort(t *testing.T) {
	if (&BoolConst{}).GetSort() != SortBool {
		t.Fatal("BoolConst sort")
	}
	if (&IntConst{}).GetSort() != SortInt {
		t.Fatal("IntConst sort")
	}
	if (&And{}).GetSort() != SortBool {
		t.Fatal("And sort")
	}
	if (&Or{}).GetSort() != SortBool {
		t.Fatal("Or sort")
	}
	if (&Not{}).GetSort() != SortBool {
		t.Fatal("Not sort")
	}
	if (&Compare{}).GetSort() != SortBool {
		t.Fatal("Compare sort")
	}
	if (&NullCheck{}).GetSort() != SortBool {
		t.Fatal("NullCheck sort")
	}

	sym := &SymValue{Sort: SortBitvec32}
	if (&SymRef{Sym: sym}).GetSort() != SortBitvec32 {
		t.Fatal("SymRef sort")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// Solver comparison operators
// ═══════════════════════════════════════════════════════════════════════════════

func TestSolver_CompareNe(t *testing.T) {
	solver := NewSolver()
	pc := NewPathCondition()
	pc.Add(&Compare{Op: OpNe, Left: &IntConst{Value: 3}, Right: &IntConst{Value: 5}})
	result, _ := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("3 != 5 should be SAT, got %s", result)
	}

	pc2 := NewPathCondition()
	pc2.Add(&Compare{Op: OpNe, Left: &IntConst{Value: 5}, Right: &IntConst{Value: 5}})
	result2, _ := solver.CheckSat(pc2)
	if result2 != Unsatisfiable {
		t.Fatalf("5 != 5 should be UNSAT, got %s", result2)
	}
}

func TestSolver_CompareLe(t *testing.T) {
	solver := NewSolver()
	pc := NewPathCondition()
	pc.Add(&Compare{Op: OpLe, Left: &IntConst{Value: 3}, Right: &IntConst{Value: 5}})
	result, _ := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("3 <= 5 should be SAT, got %s", result)
	}

	pc2 := NewPathCondition()
	pc2.Add(&Compare{Op: OpLe, Left: &IntConst{Value: 5}, Right: &IntConst{Value: 5}})
	result2, _ := solver.CheckSat(pc2)
	if result2 != Satisfiable {
		t.Fatalf("5 <= 5 should be SAT, got %s", result2)
	}

	pc3 := NewPathCondition()
	pc3.Add(&Compare{Op: OpLe, Left: &IntConst{Value: 6}, Right: &IntConst{Value: 5}})
	result3, _ := solver.CheckSat(pc3)
	if result3 != Unsatisfiable {
		t.Fatalf("6 <= 5 should be UNSAT, got %s", result3)
	}
}

func TestSolver_CompareGt(t *testing.T) {
	solver := NewSolver()
	pc := NewPathCondition()
	pc.Add(&Compare{Op: OpGt, Left: &IntConst{Value: 5}, Right: &IntConst{Value: 3}})
	result, _ := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("5 > 3 should be SAT, got %s", result)
	}

	pc2 := NewPathCondition()
	pc2.Add(&Compare{Op: OpGt, Left: &IntConst{Value: 3}, Right: &IntConst{Value: 5}})
	result2, _ := solver.CheckSat(pc2)
	if result2 != Unsatisfiable {
		t.Fatalf("3 > 5 should be UNSAT, got %s", result2)
	}
}

func TestSolver_CompareGe(t *testing.T) {
	solver := NewSolver()
	pc := NewPathCondition()
	pc.Add(&Compare{Op: OpGe, Left: &IntConst{Value: 5}, Right: &IntConst{Value: 5}})
	result, _ := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("5 >= 5 should be SAT, got %s", result)
	}

	pc2 := NewPathCondition()
	pc2.Add(&Compare{Op: OpGe, Left: &IntConst{Value: 3}, Right: &IntConst{Value: 5}})
	result2, _ := solver.CheckSat(pc2)
	if result2 != Unsatisfiable {
		t.Fatalf("3 >= 5 should be UNSAT, got %s", result2)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ConditionBuilder extended tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestConditionBuilder_FromIfEqz_NotTaken(t *testing.T) {
	solver := NewSolver()
	cb := NewConditionBuilder(solver)
	expr := cb.FromIfEqz("v0", false)
	// Not taken means value is non-zero → SymRef
	if _, ok := expr.(*SymRef); !ok {
		t.Fatalf("expected SymRef, got %T", expr)
	}
}

func TestConditionBuilder_FromIfNez_NotTaken(t *testing.T) {
	solver := NewSolver()
	cb := NewConditionBuilder(solver)
	expr := cb.FromIfNez("v0", false)
	// Not taken means value is zero → Not(SymRef)
	if _, ok := expr.(*Not); !ok {
		t.Fatalf("expected Not, got %T", expr)
	}
}

func TestConditionBuilder_FromIfEq(t *testing.T) {
	solver := NewSolver()
	cb := NewConditionBuilder(solver)

	// Branch taken → reg1 == reg2
	expr := cb.FromIfEq("v0", "v1", true)
	cmp, ok := expr.(*Compare)
	if !ok {
		t.Fatalf("expected Compare, got %T", expr)
	}
	if cmp.Op != OpEq {
		t.Fatalf("expected OpEq, got %v", cmp.Op)
	}

	// Branch not taken → NOT(reg1 == reg2)
	expr2 := cb.FromIfEq("v2", "v3", false)
	if _, ok := expr2.(*Not); !ok {
		t.Fatalf("expected Not, got %T", expr2)
	}
}

func TestConditionBuilder_FromIfLt(t *testing.T) {
	solver := NewSolver()
	cb := NewConditionBuilder(solver)

	expr := cb.FromIfLt("v0", "v1", true)
	cmp, ok := expr.(*Compare)
	if !ok {
		t.Fatalf("expected Compare, got %T", expr)
	}
	if cmp.Op != OpLt {
		t.Fatalf("expected OpLt, got %v", cmp.Op)
	}

	expr2 := cb.FromIfLt("v2", "v3", false)
	if _, ok := expr2.(*Not); !ok {
		t.Fatalf("expected Not, got %T", expr2)
	}
}

func TestConditionBuilder_FromConst(t *testing.T) {
	solver := NewSolver()
	cb := NewConditionBuilder(solver)

	expr := cb.FromConst("v0", 42)
	cmp, ok := expr.(*Compare)
	if !ok {
		t.Fatalf("expected Compare, got %T", expr)
	}
	if cmp.Op != OpEq {
		t.Fatalf("expected OpEq, got %v", cmp.Op)
	}
	intConst, ok := cmp.Right.(*IntConst)
	if !ok {
		t.Fatalf("expected IntConst on right, got %T", cmp.Right)
	}
	if intConst.Value != 42 {
		t.Fatalf("expected 42, got %d", intConst.Value)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DPLL solver tests
// ═══════════════════════════════════════════════════════════════════════════════

func TestSolver_DPLL_OrSAT(t *testing.T) {
	solver := NewSolver()
	x := solver.NewSymbol("x", SortBool)
	y := solver.NewSymbol("y", SortBool)

	// (x OR y) AND (NOT x OR y) — SAT with y=true
	pc := NewPathCondition()
	pc.Add(&Or{Left: &SymRef{Sym: x}, Right: &SymRef{Sym: y}})
	pc.Add(&Or{Left: &Not{Inner: &SymRef{Sym: x}}, Right: &SymRef{Sym: y}})

	result, _ := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("expected SAT, got %s", result)
	}
}

func TestSolver_DPLL_ComplexUNSAT(t *testing.T) {
	solver := NewSolver()
	x := solver.NewSymbol("x", SortBool)

	// x AND NOT x — UNSAT
	pc := NewPathCondition()
	pc.Add(&And{
		Left:  &SymRef{Sym: x},
		Right: &Not{Inner: &SymRef{Sym: x}},
	})

	result, _ := solver.CheckSat(pc)
	if result != Unsatisfiable {
		t.Fatalf("expected UNSAT, got %s", result)
	}
}

func TestSolver_WithAssumptions(t *testing.T) {
	solver := NewSolver()
	x := solver.NewSymbol("x", SortBool)

	pc := NewPathCondition()
	pc.AddAssumption(&SymRef{Sym: x})    // assume x is true
	pc.Add(&Not{Inner: &SymRef{Sym: x}}) // require NOT x

	result, _ := solver.CheckSat(pc)
	if result != Unsatisfiable {
		t.Fatalf("assumption x=true + constraint NOT x should be UNSAT, got %s", result)
	}
}

func TestSolver_MultipleConstraints(t *testing.T) {
	solver := NewSolver()

	// 3 < 5 AND 5 > 3 AND 5 == 5 — all SAT
	pc := NewPathCondition()
	pc.Add(&Compare{Op: OpLt, Left: &IntConst{Value: 3}, Right: &IntConst{Value: 5}})
	pc.Add(&Compare{Op: OpGt, Left: &IntConst{Value: 5}, Right: &IntConst{Value: 3}})
	pc.Add(&Compare{Op: OpEq, Left: &IntConst{Value: 5}, Right: &IntConst{Value: 5}})

	result, _ := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("expected SAT, got %s", result)
	}
}

func TestSolver_MixedConstraints(t *testing.T) {
	solver := NewSolver()

	// 3 < 5 AND 5 == 3 — UNSAT (second is false)
	pc := NewPathCondition()
	pc.Add(&Compare{Op: OpLt, Left: &IntConst{Value: 3}, Right: &IntConst{Value: 5}})
	pc.Add(&Compare{Op: OpEq, Left: &IntConst{Value: 5}, Right: &IntConst{Value: 3}})

	result, _ := solver.CheckSat(pc)
	if result != Unsatisfiable {
		t.Fatalf("expected UNSAT, got %s", result)
	}
}

func TestPathCondition_String_Empty(t *testing.T) {
	pc := NewPathCondition()
	if pc.String() != "true (unconstrained)" {
		t.Fatalf("got %q", pc.String())
	}
}

func TestPathCondition_String_Multiple(t *testing.T) {
	pc := NewPathCondition()
	pc.Add(&BoolConst{Value: true})
	pc.Add(&BoolConst{Value: false})
	s := pc.String()
	if s == "true (unconstrained)" {
		t.Fatal("should not be unconstrained")
	}
}

func TestNewSolver(t *testing.T) {
	s := NewSolver()
	if s == nil {
		t.Fatal("expected non-nil")
	}
	if s.maxDepth != 32 {
		t.Fatalf("maxDepth = %d, want 32", s.maxDepth)
	}
	if s.timeout != 10000 {
		t.Fatalf("timeout = %d, want 10000", s.timeout)
	}
}

func TestNewSymbol(t *testing.T) {
	s := NewSolver()
	sym := s.NewSymbol("test", SortInt)
	if sym.Name != "test" {
		t.Fatalf("Name = %q", sym.Name)
	}
	if sym.Sort != SortInt {
		t.Fatalf("Sort = %v", sym.Sort)
	}
	if sym.ID != 1 {
		t.Fatalf("ID = %d, want 1", sym.ID)
	}

	sym2 := s.NewSymbol("test2", SortBool)
	if sym2.ID != 2 {
		t.Fatalf("ID = %d, want 2", sym2.ID)
	}
}

func TestPathAnalyzer_New(t *testing.T) {
	pa := NewPathAnalyzer()
	if pa == nil {
		t.Fatal("expected non-nil")
	}
	if pa.solver == nil {
		t.Fatal("solver should not be nil")
	}
}

func TestReachabilityResult_Fields(t *testing.T) {
	pa := NewPathAnalyzer()
	pc := NewPathCondition()
	pc.Add(&BoolConst{Value: true})

	result := pa.CheckReachability(pc)
	if result.Reachable != Satisfiable {
		t.Fatal("should be reachable")
	}
	if result.PathCondition == "" {
		t.Fatal("PathCondition string should not be empty")
	}
	if result.Model == nil {
		t.Fatal("Model should not be nil for SAT")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Additional solver tests for coverage boost
// ═══════════════════════════════════════════════════════════════════

func TestSolver_DPLL_ThreeVars(t *testing.T) {
	solver := NewSolver()
	x := solver.NewSymbol("x", SortBool)
	y := solver.NewSymbol("y", SortBool)
	z := solver.NewSymbol("z", SortBool)

	// (x OR y) AND (NOT y OR z) AND x — SAT with x=true, z=true
	pc := NewPathCondition()
	pc.Add(&Or{Left: &SymRef{Sym: x}, Right: &SymRef{Sym: y}})
	pc.Add(&Or{Left: &Not{Inner: &SymRef{Sym: y}}, Right: &SymRef{Sym: z}})
	pc.Add(&SymRef{Sym: x})

	result, model := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("expected SAT, got %s", result)
	}
	if model == nil {
		t.Fatal("model should not be nil")
	}
	if model.Assignments["x"] != true {
		t.Fatal("x should be true")
	}
}

func TestSolver_DPLL_AllFalse(t *testing.T) {
	solver := NewSolver()
	x := solver.NewSymbol("x", SortBool)
	y := solver.NewSymbol("y", SortBool)

	// NOT x AND NOT y — SAT with x=false, y=false
	pc := NewPathCondition()
	pc.Add(&Not{Inner: &SymRef{Sym: x}})
	pc.Add(&Not{Inner: &SymRef{Sym: y}})

	result, model := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("expected SAT, got %s", result)
	}
	if model.Assignments["x"] != false {
		t.Fatalf("x should be false, got %v", model.Assignments["x"])
	}
	if model.Assignments["y"] != false {
		t.Fatalf("y should be false, got %v", model.Assignments["y"])
	}
}

func TestSolver_NestedNot(t *testing.T) {
	solver := NewSolver()
	x := solver.NewSymbol("x", SortBool)

	// NOT NOT x — SAT with x=true
	pc := NewPathCondition()
	pc.Add(&Not{Inner: &Not{Inner: &SymRef{Sym: x}}})

	result, _ := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("expected SAT for double negation, got %s", result)
	}
}

func TestSolver_OrWithFalse(t *testing.T) {
	solver := NewSolver()

	// false OR false — UNSAT
	pc := NewPathCondition()
	pc.Add(&Or{Left: &BoolConst{Value: false}, Right: &BoolConst{Value: false}})

	result, _ := solver.CheckSat(pc)
	if result != Unsatisfiable {
		t.Fatalf("expected UNSAT for false OR false, got %s", result)
	}
}

func TestSolver_AndWithTrue(t *testing.T) {
	solver := NewSolver()

	// true AND true — SAT
	pc := NewPathCondition()
	pc.Add(&And{Left: &BoolConst{Value: true}, Right: &BoolConst{Value: true}})

	result, _ := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("expected SAT for true AND true, got %s", result)
	}
}

func TestSolver_AndWithFalse(t *testing.T) {
	solver := NewSolver()

	// true AND false — UNSAT
	pc := NewPathCondition()
	pc.Add(&And{Left: &BoolConst{Value: true}, Right: &BoolConst{Value: false}})

	result, _ := solver.CheckSat(pc)
	if result != Unsatisfiable {
		t.Fatalf("expected UNSAT for true AND false, got %s", result)
	}
}

func TestSolver_NullCheck(t *testing.T) {
	solver := NewSolver()
	obj := solver.NewSymbol("obj", SortRef)

	// NullCheck is always unknown (solver can't resolve refs)
	pc := NewPathCondition()
	pc.Add(&NullCheck{Ref: &SymRef{Sym: obj}, IsNull: true})

	result, _ := solver.CheckSat(pc)
	// NullCheck evaluates to unknown, so DPLL should handle it
	_ = result // just ensure no panic
}

func TestSolver_IntSymbolicUnknown(t *testing.T) {
	solver := NewSolver()
	x := solver.NewSymbol("x", SortInt)

	// x == 5 with symbolic x — should be unknown or SAT
	pc := NewPathCondition()
	pc.Add(&Compare{Op: OpEq, Left: &SymRef{Sym: x}, Right: &IntConst{Value: 5}})

	result, _ := solver.CheckSat(pc)
	// Can't resolve symbolic int, should be Unknown
	if result == Unsatisfiable {
		t.Fatal("symbolic int comparison should not be UNSAT")
	}
}

func TestPathCondition_AddMultiple(t *testing.T) {
	pc := NewPathCondition()
	pc.Add(&BoolConst{Value: true})
	pc.Add(&BoolConst{Value: true})
	pc.Add(&BoolConst{Value: true})

	if len(pc.Constraints) != 3 {
		t.Fatalf("expected 3 constraints, got %d", len(pc.Constraints))
	}
}

func TestPathCondition_Assumptions(t *testing.T) {
	pc := NewPathCondition()
	pc.AddAssumption(&BoolConst{Value: true})
	pc.AddAssumption(&BoolConst{Value: true})

	if len(pc.Assumptions) != 2 {
		t.Fatalf("expected 2 assumptions, got %d", len(pc.Assumptions))
	}
}

func TestArith_Expressions(t *testing.T) {
	a := &Arith{Op: OpSub, Left: &IntConst{Value: 10}, Right: &IntConst{Value: 3}}
	if a.String() != "(10 - 3)" {
		t.Fatalf("got %q", a.String())
	}
	if a.GetSort() != SortInt {
		t.Fatal("arith sort should be Int")
	}

	m := &Arith{Op: OpMul, Left: &IntConst{Value: 4}, Right: &IntConst{Value: 5}}
	if m.String() != "(4 * 5)" {
		t.Fatalf("got %q", m.String())
	}

	d := &Arith{Op: OpDiv, Left: &IntConst{Value: 10}, Right: &IntConst{Value: 2}}
	if d.String() != "(10 / 2)" {
		t.Fatalf("got %q", d.String())
	}

	mod := &Arith{Op: OpMod, Left: &IntConst{Value: 7}, Right: &IntConst{Value: 3}}
	if mod.String() != "(7 % 3)" {
		t.Fatalf("got %q", mod.String())
	}
}
