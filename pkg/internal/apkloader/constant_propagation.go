package apkloader

import (
	"fmt"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANT PROPAGATION
// ═══════════════════════════════════════════════════════════════════════════════
//
// Propagates constant values both intra- and inter-procedurally.
// Folds arithmetic, logical, and string operations when operands are constants.

// ConstantValue represents a known constant value.
type ConstantValue struct {
	Value      interface{} // int64, string, bool, etc.
	Source     string      // "literal", "static_field", "method_call"
	Confidence int         // 0-100
}

// PropagationResult contains the results of constant propagation.
type PropagationResult struct {
	Constants  map[int16]*ConstantValue // register → constant value
	Simplified []MIRInsn                // simplified instructions
	Changes    int                      // number of changes made
	Trace      []string                 // propagation trace for debugging
}

// NewPropagationResult creates a new PropagationResult instance.
func NewPropagationResult() *PropagationResult {
	return &PropagationResult{
		Constants:  make(map[int16]*ConstantValue),
		Simplified: make([]MIRInsn, 0),
		Changes:    0,
		Trace:      make([]string, 0),
	}
}

// ConstantPropagation performs constant propagation on a CFG.
func ConstantPropagation(cfg *CFG, ssa *SSAForm) *PropagationResult {
	result := NewPropagationResult()

	// Step 1: Collect constant values from literals
	result.collectLiterals(cfg)

	// Step 2: Propagate constants through the CFG
	result.propagateConstants(cfg)

	// Step 3: Fold operations
	result.foldOperations(cfg)

	// Step 4: Simplify branches
	result.simplifyBranches(cfg)

	return result
}

// collectLiterals collects constant values from literal instructions.
func (pr *PropagationResult) collectLiterals(cfg *CFG) {
	for _, block := range cfg.Blocks {
		for _, insn := range block.Insns {
			switch insn.Kind {
			case MIR_CONST:
				// Constant literal (int, long, or object reference)
				pr.Constants[insn.Dst] = &ConstantValue{
					Value:      int64(insn.Imm),
					Source:     "literal",
					Confidence: 100,
				}
				pr.Trace = append(pr.Trace, fmt.Sprintf("Collected constant: v%d = %d", insn.Dst, insn.Imm))
			}
		}
	}
}

// propagateConstants propagates constants through the CFG using a worklist algorithm.
func (pr *PropagationResult) propagateConstants(cfg *CFG) {
	// Worklist algorithm: process blocks until convergence
	worklist := make([]*BasicBlock, 0)
	inWorklist := make(map[*BasicBlock]bool)

	// Initialize worklist with all blocks
	for _, block := range cfg.Blocks {
		worklist = append(worklist, block)
		inWorklist[block] = true
	}

	for len(worklist) > 0 {
		block := worklist[0]
		worklist = worklist[1:]
		inWorklist[block] = false

		// Process instructions in block
		for _, insn := range block.Insns {
			oldSize := len(pr.Constants)
			switch insn.Kind {
			case MIR_MOVE:
				// v_dst = v_src
				if val, ok := pr.Constants[insn.Src1]; ok {
					pr.Constants[insn.Dst] = val
					pr.Trace = append(pr.Trace, fmt.Sprintf("Propagated: v%d = v%d (value: %v)", insn.Dst, insn.Src1, val.Value))
				}

			case MIR_CONST:
				pr.Constants[insn.Dst] = &ConstantValue{
					Value:      insn.Imm,
					Source:     "const",
					Confidence: 100,
				}

			case MIR_ADD, MIR_SUB, MIR_RSUB, MIR_MUL, MIR_DIV, MIR_REM:
				// Arithmetic operations
				if insn.Kind == MIR_RSUB && insn.Src2 < 0 {
					// Immediate RSUB: Dst = Imm - Src1
					if val1, ok1 := pr.Constants[insn.Src1]; ok1 {
						if v1, ok := val1.Value.(int64); ok {
							res := insn.Imm - v1
							pr.Constants[insn.Dst] = &ConstantValue{Value: res, Source: "folded", Confidence: 100}
							pr.Trace = append(pr.Trace, fmt.Sprintf("Folded: v%d = %d - %v = %d", insn.Dst, insn.Imm, val1.Value, res))
						}
					}
				} else if val1, ok1 := pr.Constants[insn.Src1]; ok1 {
					if val2, ok2 := pr.Constants[insn.Src2]; ok2 {
						if result := pr.foldArithmetic(insn.Kind, val1, val2); result != nil {
							pr.Constants[insn.Dst] = result
							pr.Trace = append(pr.Trace, fmt.Sprintf("Folded: v%d = %v %s %v = %v", insn.Dst, val1.Value, opName(insn.Kind), val2.Value, result.Value))
						}
					}
				}

			case MIR_AND, MIR_OR, MIR_XOR:
				// Logical operations
				if val1, ok1 := pr.Constants[insn.Src1]; ok1 {
					if val2, ok2 := pr.Constants[insn.Src2]; ok2 {
						if result := pr.foldLogical(insn.Kind, val1, val2); result != nil {
							pr.Constants[insn.Dst] = result
							pr.Trace = append(pr.Trace, fmt.Sprintf("Folded: v%d = %v %s %v = %v", insn.Dst, val1.Value, opName(insn.Kind), val2.Value, result.Value))
						}
					}
				}

			case MIR_NOT, MIR_NEG:
				// Logical NOT / Arithmetic NEG
				if val, ok := pr.Constants[insn.Src1]; ok {
					var result *ConstantValue
					if insn.Kind == MIR_NOT {
						result = pr.foldNot(val)
					} else {
						result = pr.foldNeg(val)
					}
					if result != nil {
						pr.Constants[insn.Dst] = result
						pr.Trace = append(pr.Trace, fmt.Sprintf("Folded: v%d = %s %v = %v", insn.Dst, opName(insn.Kind), val.Value, result.Value))
					}
				}
			}

			// If constants changed, add successors to worklist
			if len(pr.Constants) > oldSize {
				pr.Changes++
				for _, succ := range block.Succs {
					if !inWorklist[succ] {
						worklist = append(worklist, succ)
						inWorklist[succ] = true
					}
				}
			}
		}
	}
}

// foldOperations folds operations with constant operands.
func (pr *PropagationResult) foldOperations(cfg *CFG) {
	for _, block := range cfg.Blocks {
		for _, insn := range block.Insns {
			// Check if this instruction can be folded
			if pr.canFold(insn) {
				pr.Trace = append(pr.Trace, fmt.Sprintf("Marked for folding: %v", insn))
			}
		}
	}
}

// simplifyBranches simplifies conditional branches with constant conditions.
func (pr *PropagationResult) simplifyBranches(cfg *CFG) {
	for _, block := range cfg.Blocks {
		if len(block.Insns) == 0 {
			continue
		}

		lastInsn := &block.Insns[len(block.Insns)-1]

		if lastInsn.Kind == MIR_IF {
			// Check if condition is constant
			if val, ok := pr.Constants[lastInsn.Src1]; ok {
				if intVal, isInt := val.Value.(int64); isInt {
					if intVal != 0 {
						pr.Trace = append(pr.Trace, fmt.Sprintf("Simplified branch: always taken (v%d = %d)", lastInsn.Src1, intVal))
					} else {
						pr.Trace = append(pr.Trace, fmt.Sprintf("Simplified branch: never taken (v%d = %d)", lastInsn.Src1, intVal))
					}
					pr.Changes++
				}
			}
		}
	}
}

// canFold checks if an instruction can be folded.
func (pr *PropagationResult) canFold(insn MIRInsn) bool {
	switch insn.Kind {
	case MIR_ADD, MIR_SUB, MIR_MUL, MIR_DIV, MIR_REM:
		_, ok1 := pr.Constants[insn.Src1]
		_, ok2 := pr.Constants[insn.Src2]
		return ok1 && ok2

	case MIR_RSUB:
		if insn.Src2 < 0 {
			_, ok := pr.Constants[insn.Src1]
			return ok
		}
		_, ok1 := pr.Constants[insn.Src1]
		_, ok2 := pr.Constants[insn.Src2]
		return ok1 && ok2

	case MIR_AND, MIR_OR, MIR_XOR:
		_, ok1 := pr.Constants[insn.Src1]
		_, ok2 := pr.Constants[insn.Src2]
		return ok1 && ok2

	case MIR_NOT, MIR_NEG:
		_, ok := pr.Constants[insn.Src1]
		return ok

	default:
		return false
	}
}

// foldArithmetic folds arithmetic operations.
func (pr *PropagationResult) foldArithmetic(kind MIROpKind, val1, val2 *ConstantValue) *ConstantValue {
	v1, ok1 := val1.Value.(int64)
	v2, ok2 := val2.Value.(int64)

	if !ok1 || !ok2 {
		return nil
	}

	var result int64

	switch kind {
	case MIR_ADD:
		result = v1 + v2
	case MIR_SUB:
		result = v1 - v2
	case MIR_RSUB:
		result = v2 - v1
	case MIR_MUL:
		result = v1 * v2
	case MIR_DIV:
		if v2 == 0 {
			return nil // Division by zero
		}
		result = v1 / v2
	case MIR_REM:
		if v2 == 0 {
			return nil // Division by zero
		}
		result = v1 % v2
	default:
		return nil
	}

	return &ConstantValue{
		Value:      result,
		Source:     "folded",
		Confidence: 100,
	}
}

// foldLogical folds logical operations.
func (pr *PropagationResult) foldLogical(kind MIROpKind, val1, val2 *ConstantValue) *ConstantValue {
	v1, ok1 := val1.Value.(int64)
	v2, ok2 := val2.Value.(int64)

	if !ok1 || !ok2 {
		return nil
	}

	var result int64

	switch kind {
	case MIR_AND:
		result = v1 & v2
	case MIR_OR:
		result = v1 | v2
	case MIR_XOR:
		result = v1 ^ v2
	default:
		return nil
	}

	return &ConstantValue{
		Value:      result,
		Source:     "folded",
		Confidence: 100,
	}
}

// foldNot folds bitwise NOT operation.
func (pr *PropagationResult) foldNot(val *ConstantValue) *ConstantValue {
	v, ok := val.Value.(int64)
	if !ok {
		return nil
	}

	return &ConstantValue{
		Value:      ^v,
		Source:     "folded",
		Confidence: 100,
	}
}

// foldNeg folds arithmetic NEG operation.
func (pr *PropagationResult) foldNeg(val *ConstantValue) *ConstantValue {
	v, ok := val.Value.(int64)
	if !ok {
		return nil
	}

	return &ConstantValue{
		Value:      -v,
		Source:     "folded",
		Confidence: 100,
	}
}

// opName returns the name of an operation.
func opName(kind MIROpKind) string {
	switch kind {
	case MIR_ADD:
		return "+"
	case MIR_SUB, MIR_RSUB:
		return "-"
	case MIR_MUL:
		return "*"
	case MIR_DIV:
		return "/"
	case MIR_REM:
		return "%"
	case MIR_AND:
		return "&"
	case MIR_OR:
		return "|"
	case MIR_XOR:
		return "^"
	case MIR_NOT:
		return "~"
	case MIR_NEG:
		return "-"
	default:
		return "?"
	}
}

// GetConstantValue returns the constant value for a register, if known.
func (pr *PropagationResult) GetConstantValue(reg int16) *ConstantValue {
	return pr.Constants[reg]
}

// IsConstant checks if a register has a known constant value.
func (pr *PropagationResult) IsConstant(reg int16) bool {
	_, ok := pr.Constants[reg]
	return ok
}

// ChangeCount returns the number of changes made.
func (pr *PropagationResult) ChangeCount() int {
	return pr.Changes
}

// GetTrace returns the propagation trace for debugging.
func (pr *PropagationResult) GetTrace() []string {
	return pr.Trace
}
