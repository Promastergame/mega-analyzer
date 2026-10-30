// Package symexec provides a lightweight symbolic execution engine
// focused on detecting and resolving opaque predicates in obfuscated
// code. It works over the SSA IR and uses SMT-like constraint solving
// to prove that certain branches are always-true or always-false.
package symexec

import (
	"fmt"

	"mega-analyzer/pkg/internal/ssair"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SYMBOLIC VALUES
// ═══════════════════════════════════════════════════════════════════════════════

// SymValue represents a symbolic expression.
type SymValue struct {
	Kind     SymKind
	Concrete int64  // for constants
	Name     string // for symbolic variables
	Op       string // for expressions
	Left     *SymValue
	Right    *SymValue
}

// SymKind classifies a symbolic value.
type SymKind uint8

const (
	SymConcrete SymKind = iota // known integer
	SymVariable                // unknown symbolic variable
	SymExpr                    // binary expression
)

func (s *SymValue) String() string {
	switch s.Kind {
	case SymConcrete:
		return fmt.Sprintf("%d", s.Concrete)
	case SymVariable:
		return s.Name
	case SymExpr:
		return fmt.Sprintf("(%s %s %s)", s.Left, s.Op, s.Right)
	}
	return "?"
}

// IsConcrete returns true if the value is a known constant.
func (s *SymValue) IsConcrete() bool { return s.Kind == SymConcrete }

// Concrete constructors
func symConst(v int64) *SymValue   { return &SymValue{Kind: SymConcrete, Concrete: v} }
func symVar(name string) *SymValue { return &SymValue{Kind: SymVariable, Name: name} }

func symBinop(op string, l, r *SymValue) *SymValue {
	// Constant folding
	if l.IsConcrete() && r.IsConcrete() {
		var result int64
		switch op {
		case "+":
			result = l.Concrete + r.Concrete
		case "-":
			result = l.Concrete - r.Concrete
		case "*":
			result = l.Concrete * r.Concrete
		case "^":
			result = l.Concrete ^ r.Concrete
		case "&":
			result = l.Concrete & r.Concrete
		case "|":
			result = l.Concrete | r.Concrete
		default:
			return &SymValue{Kind: SymExpr, Op: op, Left: l, Right: r}
		}
		return symConst(result)
	}
	return &SymValue{Kind: SymExpr, Op: op, Left: l, Right: r}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SYMBOLIC STATE
// ═══════════════════════════════════════════════════════════════════════════════

// SymState holds the symbolic environment for one execution path.
type SymState struct {
	Values      map[int]*SymValue // value ID → symbolic value
	Constraints []*Constraint
	Path        []*ssair.BasicBlock
}

// Constraint is a path constraint.
type Constraint struct {
	Expr     *SymValue
	Expected bool // true if Expr must be != 0
}

func newSymState() *SymState {
	return &SymState{Values: make(map[int]*SymValue)}
}

func (s *SymState) clone() *SymState {
	c := &SymState{
		Values:      make(map[int]*SymValue, len(s.Values)),
		Constraints: make([]*Constraint, len(s.Constraints)),
		Path:        make([]*ssair.BasicBlock, len(s.Path)),
	}
	for k, v := range s.Values {
		c.Values[k] = v
	}
	copy(c.Constraints, s.Constraints)
	copy(c.Path, s.Path)
	return c
}

func (s *SymState) get(v *ssair.Value) *SymValue {
	if sv, ok := s.Values[v.ID]; ok {
		return sv
	}
	sv := symVar(v.String())
	s.Values[v.ID] = sv
	return sv
}

func (s *SymState) set(v *ssair.Value, sv *SymValue) {
	s.Values[v.ID] = sv
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXECUTOR
// ═══════════════════════════════════════════════════════════════════════════════

// OpaqueResult describes an opaque predicate finding.
type OpaqueResult struct {
	Block     *ssair.BasicBlock
	AlwaysVal bool   // true = always taken, false = never taken
	Reason    string // human-readable explanation
}

// Executor runs symbolic execution over SSA IR functions.
type Executor struct {
	MaxDepth int
	Results  []OpaqueResult
}

// NewExecutor creates a symbolic executor with default settings.
func NewExecutor() *Executor {
	return &Executor{MaxDepth: 64}
}

// AnalyzeFunction symbolically executes a function to find opaque predicates.
func (e *Executor) AnalyzeFunction(f *ssair.Function) []OpaqueResult {
	e.Results = nil
	if f.Entry() == nil {
		return nil
	}
	state := newSymState()
	for _, p := range f.Params {
		state.set(p, symVar(p.String()))
	}
	e.explore(f, f.Entry(), state, 0)
	return e.Results
}

func (e *Executor) explore(f *ssair.Function, bb *ssair.BasicBlock, state *SymState, depth int) {
	if depth > e.MaxDepth {
		return
	}
	state.Path = append(state.Path, bb)

	// Execute all instructions symbolically
	for _, inst := range bb.Instructions {
		e.execInst(inst, state)
	}

	// Check terminator for opaque predicates
	term := bb.Terminator()
	if term == nil {
		return
	}

	if term.Op == ssair.OpCondBranch && len(term.Operands) > 0 {
		condSym := state.get(term.Operands[0])
		if condSym.IsConcrete() {
			always := condSym.Concrete != 0
			e.Results = append(e.Results, OpaqueResult{
				Block:     bb,
				AlwaysVal: always,
				Reason:    fmt.Sprintf("condition resolves to constant %d", condSym.Concrete),
			})
			// Only explore the taken branch
			if always && term.TrueBlock != nil {
				e.explore(f, term.TrueBlock, state.clone(), depth+1)
			} else if !always && term.FalseBlock != nil {
				e.explore(f, term.FalseBlock, state.clone(), depth+1)
			}
			return
		}
		// Check for x == x (always true) or x != x (always false) patterns
		if result := e.checkTrivialPredicate(term.Operands[0]); result != nil {
			e.Results = append(e.Results, *result)
			return
		}
		// Fork both paths
		if term.TrueBlock != nil {
			ts := state.clone()
			ts.Constraints = append(ts.Constraints, &Constraint{Expr: condSym, Expected: true})
			e.explore(f, term.TrueBlock, ts, depth+1)
		}
		if term.FalseBlock != nil {
			fs := state.clone()
			fs.Constraints = append(fs.Constraints, &Constraint{Expr: condSym, Expected: false})
			e.explore(f, term.FalseBlock, fs, depth+1)
		}
	} else if term.Op == ssair.OpBranch && term.TrueBlock != nil {
		e.explore(f, term.TrueBlock, state.clone(), depth+1)
	}
}

func (e *Executor) execInst(inst *ssair.Instruction, state *SymState) {
	if inst.Result == nil {
		return
	}
	switch inst.Op {
	case ssair.OpConst:
		state.set(inst.Result, symConst(inst.ConstI64))
	case ssair.OpAdd:
		if len(inst.Operands) >= 2 {
			l := state.get(inst.Operands[0])
			r := state.get(inst.Operands[1])
			state.set(inst.Result, symBinop("+", l, r))
		}
	case ssair.OpSub:
		if len(inst.Operands) >= 2 {
			l := state.get(inst.Operands[0])
			r := state.get(inst.Operands[1])
			state.set(inst.Result, symBinop("-", l, r))
		}
	case ssair.OpMul:
		if len(inst.Operands) >= 2 {
			l := state.get(inst.Operands[0])
			r := state.get(inst.Operands[1])
			state.set(inst.Result, symBinop("*", l, r))
		}
	case ssair.OpXor:
		if len(inst.Operands) >= 2 {
			l := state.get(inst.Operands[0])
			r := state.get(inst.Operands[1])
			// x ^ x = 0
			if inst.Operands[0] == inst.Operands[1] {
				state.set(inst.Result, symConst(0))
			} else {
				state.set(inst.Result, symBinop("^", l, r))
			}
		}
	case ssair.OpCmpEq:
		if len(inst.Operands) >= 2 {
			l := state.get(inst.Operands[0])
			r := state.get(inst.Operands[1])
			if inst.Operands[0] == inst.Operands[1] {
				state.set(inst.Result, symConst(1)) // x == x is always true
			} else if l.IsConcrete() && r.IsConcrete() {
				if l.Concrete == r.Concrete {
					state.set(inst.Result, symConst(1))
				} else {
					state.set(inst.Result, symConst(0))
				}
			} else {
				state.set(inst.Result, symBinop("==", l, r))
			}
		}
	case ssair.OpCmpNe:
		if len(inst.Operands) >= 2 {
			if inst.Operands[0] == inst.Operands[1] {
				state.set(inst.Result, symConst(0)) // x != x is always false
			} else {
				l := state.get(inst.Operands[0])
				r := state.get(inst.Operands[1])
				state.set(inst.Result, symBinop("!=", l, r))
			}
		}
	default:
		state.set(inst.Result, symVar(inst.Result.String()))
	}
}

func (e *Executor) checkTrivialPredicate(cond *ssair.Value) *OpaqueResult {
	if cond.DefInst == nil {
		return nil
	}
	inst := cond.DefInst
	if len(inst.Operands) < 2 {
		return nil
	}
	if inst.Operands[0] == inst.Operands[1] {
		switch inst.Op {
		case ssair.OpCmpEq:
			return &OpaqueResult{
				Block:     inst.Block,
				AlwaysVal: true,
				Reason:    "x == x is always true (opaque predicate)",
			}
		case ssair.OpCmpNe:
			return &OpaqueResult{
				Block:     inst.Block,
				AlwaysVal: false,
				Reason:    "x != x is always false (opaque predicate)",
			}
		}
	}
	return nil
}
