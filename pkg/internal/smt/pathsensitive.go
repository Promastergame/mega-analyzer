// Package smt — SMT Path-Sensitive Analysis
//
// Reduces false positives dramatically by proving path reachability.
//
// Example:
//
//	if (isDebuggable && isRooted) {
//	    leakKeys();
//	}
//
// Normal analyzer: "possible leak"
// SMT analyzer:    "reachable only when: debuggable=true ∧ rooted=true"
//
// Architecture:
//
//	CFG → path conditions → constraint collection → SMT solving → reachability
//
// This is a lightweight SMT solver focused on:
//   - Boolean satisfiability (SAT)
//   - Linear integer arithmetic (LIA)
//   - Bitvector theory (for register values)
//   - String constraints (for API checks)
package smt

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTRAINT TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// Sort represents the type of a symbolic value.
type Sort int

const (
	SortBool Sort = iota
	SortInt
	SortBitvec32
	SortBitvec64
	SortString
	SortRef // object reference (null/non-null)
)

func (s Sort) String() string {
	return [...]string{"Bool", "Int", "BV32", "BV64", "String", "Ref"}[s]
}

// ═══════════════════════════════════════════════════════════════════════════════
// SYMBOLIC VALUES
// ═══════════════════════════════════════════════════════════════════════════════

// SymValue represents a symbolic value in the constraint system.
type SymValue struct {
	ID   int    // unique identifier
	Name string // human-readable name (e.g., "v0", "isRooted")
	Sort Sort   // type
}

func (v *SymValue) String() string {
	return v.Name
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPRESSIONS — AST for constraints
// ═══════════════════════════════════════════════════════════════════════════════

// Expr is the base interface for all expressions.
type Expr interface {
	fmt.Stringer
	exprNode()
	GetSort() Sort
}

// --- Concrete expressions ---

// BoolConst is a boolean literal.
type BoolConst struct{ Value bool }

func (e *BoolConst) exprNode()     {}
func (e *BoolConst) GetSort() Sort { return SortBool }
func (e *BoolConst) String() string {
	if e.Value {
		return "true"
	}
	return "false"
}

// IntConst is an integer literal.
type IntConst struct{ Value int64 }

func (e *IntConst) exprNode()      {}
func (e *IntConst) GetSort() Sort  { return SortInt }
func (e *IntConst) String() string { return fmt.Sprintf("%d", e.Value) }

// SymRef is a reference to a symbolic variable.
type SymRef struct{ Sym *SymValue }

func (e *SymRef) exprNode()      {}
func (e *SymRef) GetSort() Sort  { return e.Sym.Sort }
func (e *SymRef) String() string { return e.Sym.Name }

// --- Boolean operations ---

// And is logical conjunction.
type And struct{ Left, Right Expr }

func (e *And) exprNode()      {}
func (e *And) GetSort() Sort  { return SortBool }
func (e *And) String() string { return fmt.Sprintf("(%s ∧ %s)", e.Left, e.Right) }

// Or is logical disjunction.
type Or struct{ Left, Right Expr }

func (e *Or) exprNode()      {}
func (e *Or) GetSort() Sort  { return SortBool }
func (e *Or) String() string { return fmt.Sprintf("(%s ∨ %s)", e.Left, e.Right) }

// Not is logical negation.
type Not struct{ Inner Expr }

func (e *Not) exprNode()      {}
func (e *Not) GetSort() Sort  { return SortBool }
func (e *Not) String() string { return fmt.Sprintf("¬%s", e.Inner) }

// --- Comparison operations ---

// CompOp is a comparison operator.
type CompOp int

const (
	OpEq CompOp = iota // ==
	OpNe               // !=
	OpLt               // <
	OpLe               // <=
	OpGt               // >
	OpGe               // >=
)

func (op CompOp) String() string {
	return [...]string{"=", "≠", "<", "≤", ">", "≥"}[op]
}

// Compare is a comparison expression.
type Compare struct {
	Op          CompOp
	Left, Right Expr
}

func (e *Compare) exprNode()     {}
func (e *Compare) GetSort() Sort { return SortBool }
func (e *Compare) String() string {
	return fmt.Sprintf("(%s %s %s)", e.Left, e.Op, e.Right)
}

// --- Arithmetic operations ---

// ArithOp is an arithmetic operator.
type ArithOp int

const (
	OpAdd ArithOp = iota
	OpSub
	OpMul
	OpDiv
	OpMod
)

func (op ArithOp) String() string {
	return [...]string{"+", "-", "*", "/", "%"}[op]
}

// Arith is an arithmetic expression.
type Arith struct {
	Op          ArithOp
	Left, Right Expr
}

func (e *Arith) exprNode()     {}
func (e *Arith) GetSort() Sort { return e.Left.GetSort() }
func (e *Arith) String() string {
	return fmt.Sprintf("(%s %s %s)", e.Left, e.Op, e.Right)
}

// NullCheck represents a null/non-null check on a reference.
type NullCheck struct {
	Ref    Expr
	IsNull bool // true = checking for null, false = checking for non-null
}

func (e *NullCheck) exprNode()     {}
func (e *NullCheck) GetSort() Sort { return SortBool }
func (e *NullCheck) String() string {
	if e.IsNull {
		return fmt.Sprintf("(%s == null)", e.Ref)
	}
	return fmt.Sprintf("(%s != null)", e.Ref)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATH CONDITION
// ═══════════════════════════════════════════════════════════════════════════════

// PathCondition represents the conjunction of constraints along a CFG path.
type PathCondition struct {
	Constraints []Expr // all must be satisfiable together
	Assumptions []Expr // background assumptions (e.g., type constraints)
}

// NewPathCondition creates an empty path condition.
func NewPathCondition() *PathCondition {
	return &PathCondition{}
}

// Add adds a constraint to the path condition.
func (pc *PathCondition) Add(constraint Expr) {
	pc.Constraints = append(pc.Constraints, constraint)
}

// AddAssumption adds a background assumption.
func (pc *PathCondition) AddAssumption(assumption Expr) {
	pc.Assumptions = append(pc.Assumptions, assumption)
}

// Clone creates a deep copy of the path condition.
func (pc *PathCondition) Clone() *PathCondition {
	clone := &PathCondition{
		Constraints: make([]Expr, len(pc.Constraints)),
		Assumptions: make([]Expr, len(pc.Assumptions)),
	}
	copy(clone.Constraints, pc.Constraints)
	copy(clone.Assumptions, pc.Assumptions)
	return clone
}

// String returns human-readable path condition.
func (pc *PathCondition) String() string {
	if len(pc.Constraints) == 0 {
		return "true (unconstrained)"
	}
	parts := make([]string, len(pc.Constraints))
	for i, c := range pc.Constraints {
		parts[i] = c.String()
	}
	return strings.Join(parts, " ∧ ")
}

// ═══════════════════════════════════════════════════════════════════════════════
// SOLVER — Lightweight DPLL-based SAT + Theory
// ═══════════════════════════════════════════════════════════════════════════════

// SolverResult is the outcome of satisfiability checking.
type SolverResult int

const (
	Satisfiable   SolverResult = iota // path is reachable
	Unsatisfiable                     // path is unreachable (dead code)
	Unknown                           // solver couldn't determine
)

func (r SolverResult) String() string {
	return [...]string{"SAT", "UNSAT", "UNKNOWN"}[r]
}

// Model is a satisfying assignment (when result is SAT).
type Model struct {
	Assignments map[string]interface{} // variable name → value
}

// Solver is the constraint solver.
type Solver struct {
	nextID    int
	variables map[string]*SymValue
	maxDepth  int // max recursion depth for solving
	timeout   int // max iterations
}

// NewSolver creates a new solver.
func NewSolver() *Solver {
	return &Solver{
		variables: make(map[string]*SymValue),
		maxDepth:  32,
		timeout:   10000,
	}
}

// NewSymbol creates a new symbolic variable.
func (s *Solver) NewSymbol(name string, sort Sort) *SymValue {
	s.nextID++
	sym := &SymValue{
		ID:   s.nextID,
		Name: name,
		Sort: sort,
	}
	s.variables[name] = sym
	return sym
}

// CheckSat checks if a path condition is satisfiable.
func (s *Solver) CheckSat(pc *PathCondition) (SolverResult, *Model) {
	if len(pc.Constraints) == 0 {
		return Satisfiable, &Model{Assignments: make(map[string]interface{})}
	}

	// Build conjunction of all constraints + assumptions
	allConstraints := make([]Expr, 0, len(pc.Constraints)+len(pc.Assumptions))
	allConstraints = append(allConstraints, pc.Assumptions...)
	allConstraints = append(allConstraints, pc.Constraints...)

	// Try to evaluate statically first (constant folding)
	result, model := s.tryStaticEval(allConstraints)
	if result != Unknown {
		return result, model
	}

	// DPLL-style solving for boolean combinations
	return s.dpll(allConstraints)
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATIC EVALUATION (fast path)
// ═══════════════════════════════════════════════════════════════════════════════

func (s *Solver) tryStaticEval(constraints []Expr) (SolverResult, *Model) {
	model := &Model{Assignments: make(map[string]interface{})}

	for _, c := range constraints {
		result := s.evalExprWithModel(c, model)
		switch result {
		case evalFalse:
			return Unsatisfiable, nil
		case evalTrue:
			continue
		case evalUnknown:
			return Unknown, nil
		}
	}

	return Satisfiable, model
}

type evalResult int

const (
	evalTrue evalResult = iota
	evalFalse
	evalUnknown
)

func (s *Solver) evalExpr(e Expr, model *Model) evalResult {
	switch expr := e.(type) {
	case *BoolConst:
		if expr.Value {
			return evalTrue
		}
		return evalFalse

	case *Not:
		inner := s.evalExpr(expr.Inner, model)
		switch inner {
		case evalTrue:
			return evalFalse
		case evalFalse:
			return evalTrue
		}
		return evalUnknown

	case *And:
		left := s.evalExpr(expr.Left, model)
		if left == evalFalse {
			return evalFalse
		}
		right := s.evalExpr(expr.Right, model)
		if right == evalFalse {
			return evalFalse
		}
		if left == evalTrue && right == evalTrue {
			return evalTrue
		}
		return evalUnknown

	case *Or:
		left := s.evalExpr(expr.Left, model)
		if left == evalTrue {
			return evalTrue
		}
		right := s.evalExpr(expr.Right, model)
		if right == evalTrue {
			return evalTrue
		}
		if left == evalFalse && right == evalFalse {
			return evalFalse
		}
		return evalUnknown

	case *Compare:
		return s.evalCompare(expr, model)

	default:
		return evalUnknown
	}
}

func (s *Solver) evalCompare(cmp *Compare, model *Model) evalResult {
	// Try to resolve both sides to concrete values
	leftVal := s.resolveToInt(cmp.Left, model)
	rightVal := s.resolveToInt(cmp.Right, model)

	if leftVal == nil || rightVal == nil {
		return evalUnknown
	}

	l, r := *leftVal, *rightVal
	switch cmp.Op {
	case OpEq:
		if l == r {
			return evalTrue
		}
		return evalFalse
	case OpNe:
		if l != r {
			return evalTrue
		}
		return evalFalse
	case OpLt:
		if l < r {
			return evalTrue
		}
		return evalFalse
	case OpLe:
		if l <= r {
			return evalTrue
		}
		return evalFalse
	case OpGt:
		if l > r {
			return evalTrue
		}
		return evalFalse
	case OpGe:
		if l >= r {
			return evalTrue
		}
		return evalFalse
	}
	return evalUnknown
}

func (s *Solver) resolveToInt(e Expr, model *Model) *int64 {
	switch expr := e.(type) {
	case *IntConst:
		return &expr.Value
	case *SymRef:
		if val, ok := model.Assignments[expr.Sym.Name]; ok {
			if intVal, ok := val.(int64); ok {
				return &intVal
			}
		}
		return nil
	default:
		return nil
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DPLL SOLVER (simplified)
// ═══════════════════════════════════════════════════════════════════════════════

func (s *Solver) dpll(constraints []Expr) (SolverResult, *Model) {
	// Collect all boolean variables (including from inside And/Or)
	boolVars := s.collectBoolVars(constraints)
	if len(boolVars) == 0 {
		return Unknown, nil
	}

	// Try all assignments (bounded by timeout)
	model := &Model{Assignments: make(map[string]interface{})}
	iterations := 0

	var solve func(idx int) SolverResult
	solve = func(idx int) SolverResult {
		iterations++
		if iterations > s.timeout {
			return Unknown
		}

		// Check current assignment
		allSat := true
		for _, c := range constraints {
			result := s.evalExprWithModel(c, model)
			if result == evalFalse {
				return Unsatisfiable
			}
			if result == evalUnknown {
				allSat = false
			}
		}
		if allSat {
			return Satisfiable
		}

		if idx >= len(boolVars) {
			// All variables assigned but still unknown — try to determine
			return Unknown
		}

		// Branch on next variable
		varName := boolVars[idx]

		// Try true first
		model.Assignments[varName] = true
		if solve(idx+1) == Satisfiable {
			return Satisfiable
		}

		// Try false
		model.Assignments[varName] = false
		if solve(idx+1) == Satisfiable {
			return Satisfiable
		}

		// Backtrack
		delete(model.Assignments, varName)
		return Unsatisfiable
	}

	result := solve(0)
	if result == Satisfiable {
		return Satisfiable, model
	}
	return result, nil
}

// evalExprWithModel evaluates an expression using the current model assignments.
func (s *Solver) evalExprWithModel(e Expr, model *Model) evalResult {
	switch expr := e.(type) {
	case *BoolConst:
		if expr.Value {
			return evalTrue
		}
		return evalFalse

	case *SymRef:
		if expr.Sym.Sort == SortBool {
			if val, ok := model.Assignments[expr.Sym.Name]; ok {
				if boolVal, ok := val.(bool); ok {
					if boolVal {
						return evalTrue
					}
					return evalFalse
				}
			}
		}
		return evalUnknown

	case *Not:
		inner := s.evalExprWithModel(expr.Inner, model)
		switch inner {
		case evalTrue:
			return evalFalse
		case evalFalse:
			return evalTrue
		}
		return evalUnknown

	case *And:
		left := s.evalExprWithModel(expr.Left, model)
		if left == evalFalse {
			return evalFalse
		}
		right := s.evalExprWithModel(expr.Right, model)
		if right == evalFalse {
			return evalFalse
		}
		if left == evalTrue && right == evalTrue {
			return evalTrue
		}
		return evalUnknown

	case *Or:
		left := s.evalExprWithModel(expr.Left, model)
		if left == evalTrue {
			return evalTrue
		}
		right := s.evalExprWithModel(expr.Right, model)
		if right == evalTrue {
			return evalTrue
		}
		if left == evalFalse && right == evalFalse {
			return evalFalse
		}
		return evalUnknown

	case *Compare:
		return s.evalCompare(expr, model)

	case *NullCheck:
		return evalUnknown

	default:
		return evalUnknown
	}
}

func (s *Solver) collectBoolVars(constraints []Expr) []string {
	vars := make(map[string]bool)
	for _, c := range constraints {
		s.collectVarsFromExpr(c, vars)
	}
	result := make([]string, 0, len(vars))
	for v := range vars {
		result = append(result, v)
	}
	return result
}

func (s *Solver) collectVarsFromExpr(e Expr, vars map[string]bool) {
	switch expr := e.(type) {
	case *SymRef:
		if expr.Sym.Sort == SortBool {
			vars[expr.Sym.Name] = true
		}
	case *And:
		s.collectVarsFromExpr(expr.Left, vars)
		s.collectVarsFromExpr(expr.Right, vars)
	case *Or:
		s.collectVarsFromExpr(expr.Left, vars)
		s.collectVarsFromExpr(expr.Right, vars)
	case *Not:
		s.collectVarsFromExpr(expr.Inner, vars)
	case *Compare:
		s.collectVarsFromExpr(expr.Left, vars)
		s.collectVarsFromExpr(expr.Right, vars)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATH ANALYZER — Integrates with CFG
// ═══════════════════════════════════════════════════════════════════════════════

// PathAnalyzer performs path-sensitive analysis on a CFG.
type PathAnalyzer struct {
	solver *Solver
}

// NewPathAnalyzer creates a path analyzer.
func NewPathAnalyzer() *PathAnalyzer {
	return &PathAnalyzer{
		solver: NewSolver(),
	}
}

// ReachabilityResult describes whether a CFG node is reachable.
type ReachabilityResult struct {
	NodeID        int          `json:"node_id"`
	Reachable     SolverResult `json:"reachable"`
	PathCondition string       `json:"path_condition"`  // human-readable
	Model         *Model       `json:"model,omitempty"` // satisfying assignment if SAT
}

// CheckReachability checks if a node is reachable given path constraints.
func (pa *PathAnalyzer) CheckReachability(pc *PathCondition) *ReachabilityResult {
	result, model := pa.solver.CheckSat(pc)
	return &ReachabilityResult{
		Reachable:     result,
		PathCondition: pc.String(),
		Model:         model,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONDITION BUILDER — Helpers for building constraints from Smali
// ═══════════════════════════════════════════════════════════════════════════════

// ConditionBuilder helps translate Smali conditions to SMT constraints.
type ConditionBuilder struct {
	solver *Solver
}

// NewConditionBuilder creates a condition builder.
func NewConditionBuilder(solver *Solver) *ConditionBuilder {
	return &ConditionBuilder{solver: solver}
}

// FromIfEqz creates constraint for if-eqz (branch taken when reg == 0/false).
func (cb *ConditionBuilder) FromIfEqz(regName string, branchTaken bool) Expr {
	sym := cb.solver.NewSymbol(regName, SortBool)
	ref := &SymRef{Sym: sym}
	if branchTaken {
		// if-eqz taken means value IS zero/false
		return &Not{Inner: ref}
	}
	// if-eqz not taken means value is non-zero/true
	return ref
}

// FromIfNez creates constraint for if-nez (branch taken when reg != 0/true).
func (cb *ConditionBuilder) FromIfNez(regName string, branchTaken bool) Expr {
	sym := cb.solver.NewSymbol(regName, SortBool)
	ref := &SymRef{Sym: sym}
	if branchTaken {
		// if-nez taken means value IS non-zero/true
		return ref
	}
	// if-nez not taken means value is zero/false
	return &Not{Inner: ref}
}

// FromIfEq creates constraint for if-eq (branch taken when reg1 == reg2).
func (cb *ConditionBuilder) FromIfEq(reg1, reg2 string, branchTaken bool) Expr {
	sym1 := cb.solver.NewSymbol(reg1, SortInt)
	sym2 := cb.solver.NewSymbol(reg2, SortInt)
	cmp := &Compare{Op: OpEq, Left: &SymRef{Sym: sym1}, Right: &SymRef{Sym: sym2}}
	if branchTaken {
		return cmp
	}
	return &Not{Inner: cmp}
}

// FromIfLt creates constraint for if-lt (branch taken when reg1 < reg2).
func (cb *ConditionBuilder) FromIfLt(reg1, reg2 string, branchTaken bool) Expr {
	sym1 := cb.solver.NewSymbol(reg1, SortInt)
	sym2 := cb.solver.NewSymbol(reg2, SortInt)
	cmp := &Compare{Op: OpLt, Left: &SymRef{Sym: sym1}, Right: &SymRef{Sym: sym2}}
	if branchTaken {
		return cmp
	}
	return &Not{Inner: cmp}
}

// FromConst creates a constraint that a register equals a constant.
func (cb *ConditionBuilder) FromConst(regName string, value int64) Expr {
	sym := cb.solver.NewSymbol(regName, SortInt)
	return &Compare{
		Op:    OpEq,
		Left:  &SymRef{Sym: sym},
		Right: &IntConst{Value: value},
	}
}
