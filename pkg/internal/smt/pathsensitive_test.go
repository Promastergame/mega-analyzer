package smt

import (
	"testing"
)

func TestSolverSimpleSAT(t *testing.T) {
	solver := NewSolver()

	// Simple: true is satisfiable
	pc := NewPathCondition()
	pc.Add(&BoolConst{Value: true})

	result, model := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("expected SAT, got %s", result)
	}
	if model == nil {
		t.Fatal("model should not be nil for SAT")
	}
}

func TestSolverSimpleUNSAT(t *testing.T) {
	solver := NewSolver()

	// false is unsatisfiable
	pc := NewPathCondition()
	pc.Add(&BoolConst{Value: false})

	result, _ := solver.CheckSat(pc)
	if result != Unsatisfiable {
		t.Fatalf("expected UNSAT, got %s", result)
	}
}

func TestSolverContradiction(t *testing.T) {
	solver := NewSolver()

	// x AND NOT x is UNSAT
	x := solver.NewSymbol("isRooted", SortBool)
	pc := NewPathCondition()
	pc.Add(&SymRef{Sym: x})
	pc.Add(&Not{Inner: &SymRef{Sym: x}})

	result, _ := solver.CheckSat(pc)
	if result != Unsatisfiable {
		t.Fatalf("expected UNSAT for contradiction, got %s", result)
	}
}

func TestSolverAndConstraint(t *testing.T) {
	solver := NewSolver()

	// isDebuggable AND isRooted — should be SAT
	debuggable := solver.NewSymbol("isDebuggable", SortBool)
	rooted := solver.NewSymbol("isRooted", SortBool)

	pc := NewPathCondition()
	pc.Add(&And{
		Left:  &SymRef{Sym: debuggable},
		Right: &SymRef{Sym: rooted},
	})

	result, model := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("expected SAT, got %s", result)
	}

	// Model should assign both to true
	if model.Assignments["isDebuggable"] != true {
		t.Errorf("expected isDebuggable=true, got %v", model.Assignments["isDebuggable"])
	}
	if model.Assignments["isRooted"] != true {
		t.Errorf("expected isRooted=true, got %v", model.Assignments["isRooted"])
	}
}

func TestSolverOrConstraint(t *testing.T) {
	solver := NewSolver()

	// x OR y — should be SAT
	x := solver.NewSymbol("x", SortBool)
	y := solver.NewSymbol("y", SortBool)

	pc := NewPathCondition()
	pc.Add(&Or{
		Left:  &SymRef{Sym: x},
		Right: &SymRef{Sym: y},
	})

	result, _ := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("expected SAT, got %s", result)
	}
}

func TestSolverIntComparison(t *testing.T) {
	solver := NewSolver()

	// 5 == 5 is SAT
	pc := NewPathCondition()
	pc.Add(&Compare{
		Op:    OpEq,
		Left:  &IntConst{Value: 5},
		Right: &IntConst{Value: 5},
	})

	result, _ := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("expected SAT for 5==5, got %s", result)
	}
}

func TestSolverIntComparisonUNSAT(t *testing.T) {
	solver := NewSolver()

	// 5 == 3 is UNSAT
	pc := NewPathCondition()
	pc.Add(&Compare{
		Op:    OpEq,
		Left:  &IntConst{Value: 5},
		Right: &IntConst{Value: 3},
	})

	result, _ := solver.CheckSat(pc)
	if result != Unsatisfiable {
		t.Fatalf("expected UNSAT for 5==3, got %s", result)
	}
}

func TestSolverLessThan(t *testing.T) {
	solver := NewSolver()

	// 3 < 5 is SAT
	pc := NewPathCondition()
	pc.Add(&Compare{
		Op:    OpLt,
		Left:  &IntConst{Value: 3},
		Right: &IntConst{Value: 5},
	})

	result, _ := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("expected SAT for 3<5, got %s", result)
	}

	// 5 < 3 is UNSAT
	pc2 := NewPathCondition()
	pc2.Add(&Compare{
		Op:    OpLt,
		Left:  &IntConst{Value: 5},
		Right: &IntConst{Value: 3},
	})

	result2, _ := solver.CheckSat(pc2)
	if result2 != Unsatisfiable {
		t.Fatalf("expected UNSAT for 5<3, got %s", result2)
	}
}

func TestPathConditionClone(t *testing.T) {
	pc := NewPathCondition()
	pc.Add(&BoolConst{Value: true})
	pc.AddAssumption(&BoolConst{Value: true})

	clone := pc.Clone()
	clone.Add(&BoolConst{Value: false})

	if len(pc.Constraints) != 1 {
		t.Fatal("original should not be modified by clone")
	}
	if len(clone.Constraints) != 2 {
		t.Fatal("clone should have 2 constraints")
	}
}

func TestPathConditionString(t *testing.T) {
	solver := NewSolver()
	x := solver.NewSymbol("isDebuggable", SortBool)
	y := solver.NewSymbol("isRooted", SortBool)

	pc := NewPathCondition()
	pc.Add(&And{
		Left:  &SymRef{Sym: x},
		Right: &SymRef{Sym: y},
	})

	s := pc.String()
	if s == "" {
		t.Fatal("path condition string should not be empty")
	}
	if s == "true (unconstrained)" {
		t.Fatal("should not be unconstrained")
	}
}

func TestConditionBuilderIfEqz(t *testing.T) {
	solver := NewSolver()
	cb := NewConditionBuilder(solver)

	// if-eqz taken → value is false/zero
	expr := cb.FromIfEqz("v0", true)
	if expr == nil {
		t.Fatal("expression should not be nil")
	}

	// Should be Not(v0)
	notExpr, ok := expr.(*Not)
	if !ok {
		t.Fatalf("expected Not, got %T", expr)
	}
	if notExpr.Inner == nil {
		t.Fatal("inner should not be nil")
	}
}

func TestConditionBuilderIfNez(t *testing.T) {
	solver := NewSolver()
	cb := NewConditionBuilder(solver)

	// if-nez taken → value is true/non-zero
	expr := cb.FromIfNez("v1", true)
	if expr == nil {
		t.Fatal("expression should not be nil")
	}

	// Should be SymRef(v1)
	_, ok := expr.(*SymRef)
	if !ok {
		t.Fatalf("expected SymRef, got %T", expr)
	}
}

func TestPathAnalyzerReachability(t *testing.T) {
	pa := NewPathAnalyzer()

	// Reachable path (no constraints)
	pc := NewPathCondition()
	result := pa.CheckReachability(pc)
	if result.Reachable != Satisfiable {
		t.Fatalf("unconstrained path should be reachable, got %s", result.Reachable)
	}

	// Unreachable path (contradiction)
	solver := NewSolver()
	x := solver.NewSymbol("flag", SortBool)
	pc2 := NewPathCondition()
	pc2.Add(&SymRef{Sym: x})
	pc2.Add(&Not{Inner: &SymRef{Sym: x}})

	pa2 := &PathAnalyzer{solver: solver}
	result2 := pa2.CheckReachability(pc2)
	if result2.Reachable != Unsatisfiable {
		t.Fatalf("contradictory path should be unreachable, got %s", result2.Reachable)
	}
}

func TestExprString(t *testing.T) {
	solver := NewSolver()
	x := solver.NewSymbol("isDebuggable", SortBool)
	y := solver.NewSymbol("isRooted", SortBool)

	expr := &And{
		Left:  &SymRef{Sym: x},
		Right: &SymRef{Sym: y},
	}

	s := expr.String()
	if s != "(isDebuggable ∧ isRooted)" {
		t.Errorf("unexpected string: %s", s)
	}
}

func TestNullCheck(t *testing.T) {
	solver := NewSolver()
	obj := solver.NewSymbol("obj", SortRef)

	nullCheck := &NullCheck{Ref: &SymRef{Sym: obj}, IsNull: true}
	if nullCheck.String() != "(obj == null)" {
		t.Errorf("unexpected: %s", nullCheck.String())
	}

	nonNullCheck := &NullCheck{Ref: &SymRef{Sym: obj}, IsNull: false}
	if nonNullCheck.String() != "(obj != null)" {
		t.Errorf("unexpected: %s", nonNullCheck.String())
	}
}

func TestEmptyPathCondition(t *testing.T) {
	solver := NewSolver()
	pc := NewPathCondition()

	result, model := solver.CheckSat(pc)
	if result != Satisfiable {
		t.Fatalf("empty path condition should be SAT, got %s", result)
	}
	if model == nil {
		t.Fatal("model should not be nil")
	}
}
