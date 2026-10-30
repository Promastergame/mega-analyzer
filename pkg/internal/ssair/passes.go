// Package ssair — optimization passes for the SSA IR.
package ssair

// ═══════════════════════════════════════════════════════════════════════════════
// OPTIMIZATION PASSES
// ═══════════════════════════════════════════════════════════════════════════════

// Pass is an optimization/analysis pass over an SSA module.
type Pass interface {
	Name() string
	Run(m *Module) bool // returns true if anything changed
}

// Pipeline runs a sequence of passes until fixpoint.
type Pipeline struct {
	Passes   []Pass
	MaxIters int
}

// NewPipeline creates an optimization pipeline.
func NewPipeline(passes ...Pass) *Pipeline {
	return &Pipeline{Passes: passes, MaxIters: 10}
}

// Run executes all passes in order, repeating until fixpoint or max iterations.
func (p *Pipeline) Run(m *Module) int {
	totalChanges := 0
	for iter := 0; iter < p.MaxIters; iter++ {
		changed := false
		for _, pass := range p.Passes {
			if pass.Run(m) {
				changed = true
				totalChanges++
			}
		}
		if !changed {
			break
		}
	}
	return totalChanges
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANT FOLDING PASS
// ═══════════════════════════════════════════════════════════════════════════════

// ConstFoldPass folds constant arithmetic at compile time.
type ConstFoldPass struct{}

func (ConstFoldPass) Name() string { return "const-fold" }

func (ConstFoldPass) Run(m *Module) bool {
	changed := false
	for _, f := range m.Functions {
		for _, bb := range f.Blocks {
			for _, inst := range bb.Instructions {
				if inst.Result == nil || len(inst.Operands) < 2 {
					continue
				}
				lhs := findConstDef(inst.Operands[0])
				rhs := findConstDef(inst.Operands[1])
				if lhs == nil || rhs == nil {
					continue
				}
				var result int64
				switch inst.Op {
				case OpAdd:
					result = lhs.ConstI64 + rhs.ConstI64
				case OpSub:
					result = lhs.ConstI64 - rhs.ConstI64
				case OpMul:
					result = lhs.ConstI64 * rhs.ConstI64
				case OpXor:
					result = lhs.ConstI64 ^ rhs.ConstI64
				case OpAnd:
					result = lhs.ConstI64 & rhs.ConstI64
				case OpOr:
					result = lhs.ConstI64 | rhs.ConstI64
				default:
					continue
				}
				inst.Op = OpConst
				inst.Operands = nil
				inst.ConstI64 = result
				changed = true
			}
		}
	}
	return changed
}

func findConstDef(v *Value) *Instruction {
	if v == nil || v.DefInst == nil {
		return nil
	}
	if v.DefInst.Op == OpConst {
		return v.DefInst
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// DEAD CODE ELIMINATION PASS
// ═══════════════════════════════════════════════════════════════════════════════

// DCEPass removes instructions whose results are never used.
type DCEPass struct{}

func (DCEPass) Name() string { return "dce" }

func (DCEPass) Run(m *Module) bool {
	changed := false
	for _, f := range m.Functions {
		used := make(map[int]bool)
		// Mark phase: collect all used values
		for _, bb := range f.Blocks {
			for _, inst := range bb.Instructions {
				for _, op := range inst.Operands {
					if op != nil {
						used[op.ID] = true
					}
				}
			}
		}
		// Sweep phase: remove dead instructions
		for _, bb := range f.Blocks {
			live := make([]*Instruction, 0, len(bb.Instructions))
			for _, inst := range bb.Instructions {
				if inst.Result != nil && !used[inst.Result.ID] && !hasSideEffects(inst) {
					changed = true
					continue
				}
				live = append(live, inst)
			}
			bb.Instructions = live
		}
	}
	return changed
}

func hasSideEffects(inst *Instruction) bool {
	switch inst.Op {
	case OpStore, OpCall, OpInvoke, OpReturn, OpBranch, OpCondBranch,
		OpSwitch, OpUnreachable:
		return true
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// OPAQUE PREDICATE REMOVAL PASS
// ═══════════════════════════════════════════════════════════════════════════════

// OpaquePredicatePass detects and removes trivially-true/false branches.
type OpaquePredicatePass struct {
	Removed int
}

func (p *OpaquePredicatePass) Name() string { return "opaque-predicate-removal" }

func (p *OpaquePredicatePass) Run(m *Module) bool {
	changed := false
	for _, f := range m.Functions {
		for _, bb := range f.Blocks {
			term := bb.Terminator()
			if term == nil || term.Op != OpCondBranch {
				continue
			}
			if len(term.Operands) == 0 {
				continue
			}
			cond := term.Operands[0]
			if cond == nil || cond.DefInst == nil {
				continue
			}
			switch cond.DefInst.Op {
			case OpOpaqueTrue:
				// Always goes to TrueBlock — replace with unconditional branch
				term.Op = OpBranch
				term.Operands = nil
				term.FalseBlock = nil
				p.Removed++
				changed = true
			case OpOpaqueFalse:
				// Always goes to FalseBlock
				term.Op = OpBranch
				term.Operands = nil
				term.TrueBlock = term.FalseBlock
				term.FalseBlock = nil
				p.Removed++
				changed = true
			default:
				// Check for constant comparison patterns (xor eax,eax; cmp eax,0 → always true)
				if isAlwaysTrue(cond.DefInst) {
					term.Op = OpBranch
					term.Operands = nil
					term.FalseBlock = nil
					p.Removed++
					changed = true
				} else if isAlwaysFalse(cond.DefInst) {
					term.Op = OpBranch
					term.Operands = nil
					term.TrueBlock = term.FalseBlock
					term.FalseBlock = nil
					p.Removed++
					changed = true
				}
			}
		}
	}
	return changed
}

func isAlwaysTrue(inst *Instruction) bool {
	if inst.Op == OpCmpEq && len(inst.Operands) == 2 {
		return inst.Operands[0] == inst.Operands[1] // x == x is always true
	}
	return false
}

func isAlwaysFalse(inst *Instruction) bool {
	if inst.Op == OpCmpNe && len(inst.Operands) == 2 {
		return inst.Operands[0] == inst.Operands[1] // x != x is always false
	}
	return false
}
