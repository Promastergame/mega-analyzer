package apkloader

import (
	"fmt"
)

// ═══════════════════════════════════════════════════════════════════════════════
// OPAQUE PREDICATE REMOVAL
// ═══════════════════════════════════════════════════════════════════════════════
//
// Removes conditions that are statically provable as always true or always false.
// Simplifies control flow after removing opaque predicates.

// OpaquePredicateAnalysis contains the results of opaque predicate analysis.
type OpaquePredicateAnalysis struct {
	AlwaysTrue  []OpaquePredicate // predicates that are always true
	AlwaysFalse []OpaquePredicate // predicates that are always false
	Confidence  map[int]int       // confidence scores for each predicate
	Changes     int               // number of changes made
	Trace       []string          // analysis trace for debugging
}

// OpaquePredicate represents a predicate that can be statically evaluated.
type OpaquePredicate struct {
	Block      *BasicBlock
	Insn       int
	Condition  string // description of the condition
	Result     bool   // true if always true, false if always false
	Confidence int    // 0-100
}

// AnalyzeOpaquePredicates performs opaque predicate analysis on a CFG.
func AnalyzeOpaquePredicates(cfg *CFG, propResult *PropagationResult) *OpaquePredicateAnalysis {
	analysis := &OpaquePredicateAnalysis{
		AlwaysTrue:  make([]OpaquePredicate, 0),
		AlwaysFalse: make([]OpaquePredicate, 0),
		Confidence:  make(map[int]int),
		Changes:     0,
		Trace:       make([]string, 0),
	}

	// Step 1: Detect arithmetic invariants
	analysis.detectArithmeticInvariants(cfg, propResult)

	// Step 2: Detect self-comparisons
	analysis.detectSelfComparisons(cfg)

	// Step 3: Detect type incompatibilities
	analysis.detectTypeIncompatibilities(cfg)

	// Step 4: Simplify control flow
	analysis.simplifyControlFlow(cfg)

	return analysis
}

// constValueAsInt64 extracts the int64 from a *ConstantValue, returning (0, false) if not applicable.
func constValueAsInt64(cv *ConstantValue) (int64, bool) {
	if cv == nil {
		return 0, false
	}
	switch v := cv.Value.(type) {
	case int64:
		return v, true
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	default:
		return 0, false
	}
}

// detectArithmeticInvariants detects arithmetic invariants like x*x >= 0, (x^x) == 0.
// It evaluates MIR_IF conditions whose operands are known constants from propagation.
func (opa *OpaquePredicateAnalysis) detectArithmeticInvariants(cfg *CFG, prop *PropagationResult) {
	if prop == nil {
		return
	}
	for _, block := range cfg.Blocks {
		if block == nil || len(block.Insns) == 0 {
			continue
		}
		for insnIdx, insn := range block.Insns {
			if insn.Kind != MIR_IF {
				continue
			}
			// Case 1: Both operands are known constants → evaluate binary condition.
			if insn.Src1 >= 0 && insn.Src2 >= 0 {
				cv1, ok1 := prop.Constants[insn.Src1]
				cv2, ok2 := prop.Constants[insn.Src2]
				if ok1 && ok2 {
					v1, int1 := constValueAsInt64(cv1)
					v2, int2 := constValueAsInt64(cv2)
					if int1 && int2 {
						result := evaluateCondition(insn.Cond, v1, v2)
						pred := OpaquePredicate{
							Block:      block,
							Insn:       insnIdx,
							Condition:  fmt.Sprintf("const(%d) %v const(%d)", v1, insn.Cond, v2),
							Result:     result,
							Confidence: 100,
						}
						if result {
							opa.AlwaysTrue = append(opa.AlwaysTrue, pred)
						} else {
							opa.AlwaysFalse = append(opa.AlwaysFalse, pred)
						}
						opa.Changes++
						opa.Trace = append(opa.Trace, fmt.Sprintf(
							"Arithmetic invariant: const(%d) %v const(%d) → %v", v1, insn.Cond, v2, result))
						continue
					}
				}
			}
			// Case 2: Unary condition (EQZ/NEZ/GEZ/etc.) with a single known constant operand.
			if insn.Src1 >= 0 && insn.Src2 == -1 {
				cv1, ok1 := prop.Constants[insn.Src1]
				if ok1 {
					v1, int1 := constValueAsInt64(cv1)
					if int1 {
						result := evaluateUnaryCondition(insn.Cond, v1)
						if result != nil {
							pred := OpaquePredicate{
								Block:      block,
								Insn:       insnIdx,
								Condition:  fmt.Sprintf("%v(const(%d))", insn.Cond, v1),
								Result:     *result,
								Confidence: 100,
							}
							if *result {
								opa.AlwaysTrue = append(opa.AlwaysTrue, pred)
							} else {
								opa.AlwaysFalse = append(opa.AlwaysFalse, pred)
							}
							opa.Changes++
							opa.Trace = append(opa.Trace, fmt.Sprintf(
								"Unary arithmetic invariant: %v(const(%d)) → %v", insn.Cond, v1, *result))
						}
					}
				}
			}
		}
	}
}

// evaluateCondition evaluates a MIRCond comparison between two known int64 values.
func evaluateCondition(cond MIRCondition, a, b int64) bool {
	switch cond {
	case CondEQ:
		return a == b
	case CondNE:
		return a != b
	case CondGE:
		return a >= b
	case CondGT:
		return a > b
	case CondLE:
		return a <= b
	case CondLT:
		return a < b
	default:
		return false
	}
}

// evaluateUnaryCondition evaluates a unary MIRCond (EQZ/NEZ/GEZ/etc.) on one known value.
func evaluateUnaryCondition(cond MIRCondition, v int64) *bool {
	var result bool
	switch cond {
	case CondEQZ:
		result = v == 0
	case CondNEZ:
		result = v != 0
	case CondGEZ:
		result = v >= 0
	case CondGTZ:
		result = v > 0
	case CondLEZ:
		result = v <= 0
	case CondLTZ:
		result = v < 0
	default:
		return nil
	}
	return &result
}

// detectSelfComparisons detects self-comparisons like x == x, x != x.
func (opa *OpaquePredicateAnalysis) detectSelfComparisons(cfg *CFG) {
	for _, block := range cfg.Blocks {
		if len(block.Insns) == 0 {
			continue
		}

		lastInsn := &block.Insns[len(block.Insns)-1]

		if lastInsn.Kind == MIR_IF {
			src1 := lastInsn.Src1
			src2 := lastInsn.Src2

			// x == x or x != x (self-comparison)
			if src1 != -1 && src2 != -1 && src1 == src2 {
				// Condition depends on the IF condition type
				isAlwaysTrue := false
				switch lastInsn.Cond {
				case CondEQ, CondGE, CondLE, CondEQZ, CondGEZ, CondLEZ:
					isAlwaysTrue = true
				case CondNE, CondLT, CondGT, CondNEZ, CondLTZ, CondGTZ:
					isAlwaysTrue = false
				}

				predicate := OpaquePredicate{
					Block:      block,
					Insn:       len(block.Insns) - 1,
					Condition:  fmt.Sprintf("v%d vs v%d", src1, src2),
					Result:     isAlwaysTrue,
					Confidence: 100,
				}

				if isAlwaysTrue {
					opa.AlwaysTrue = append(opa.AlwaysTrue, predicate)
				} else {
					opa.AlwaysFalse = append(opa.AlwaysFalse, predicate)
				}
				opa.Trace = append(opa.Trace, fmt.Sprintf("Detected self-comparison: v%d (always %v)", src1, isAlwaysTrue))
				opa.Changes++
			}
		}
	}
}

// detectTypeIncompatibilities detects comparisons with incompatible types.
func (opa *OpaquePredicateAnalysis) detectTypeIncompatibilities(cfg *CFG) {
	// This would require type information from the SSA form
	// For now, this is a placeholder
}

// simplifyControlFlow simplifies control flow after removing opaque predicates.
func (opa *OpaquePredicateAnalysis) simplifyControlFlow(_ *CFG) {
	for _, pred := range opa.AlwaysTrue {
		opa.Trace = append(opa.Trace, fmt.Sprintf(
			"Proved always-true at block %d insn %d (will remove false branch): %s",
			pred.Block.ID, pred.Insn, pred.Condition))
	}
	for _, pred := range opa.AlwaysFalse {
		opa.Trace = append(opa.Trace, fmt.Sprintf(
			"Proved always-false at block %d insn %d (will remove taken branch): %s",
			pred.Block.ID, pred.Insn, pred.Condition))
	}
}

// RemoveOpaquePredicates removes opaque predicates from the CFG.
func (opa *OpaquePredicateAnalysis) RemoveOpaquePredicates(cfg *CFG) {
	// For each always-true predicate, remove the false branch
	for _, pred := range opa.AlwaysTrue {
		block := pred.Block
		if len(block.Succs) >= 2 {
			taken := block.Succs[0]
			fallthroughBlock := block.Succs[1]

			// Remove edge from block to fallthroughBlock
			block.Succs = []*BasicBlock{taken}
			removePred(fallthroughBlock, block)
			block.IsFallthrough = false

			// Convert MIR_IF to MIR_GOTO
			if pred.Insn < len(block.Insns) {
				insn := &block.Insns[pred.Insn]
				insn.Kind = MIR_GOTO
				// Keep Offset and Imm (Imm is target relative offset)
			}
			opa.Trace = append(opa.Trace, fmt.Sprintf("Removing false branch for always-true predicate at block %d", pred.Block.ID))
			opa.Changes++
		}
	}

	// For each always-false predicate, remove the taken branch
	for _, pred := range opa.AlwaysFalse {
		block := pred.Block
		if len(block.Succs) >= 2 {
			taken := block.Succs[0]
			fallthroughBlock := block.Succs[1]

			// Remove edge from block to taken
			block.Succs = []*BasicBlock{fallthroughBlock}
			removePred(taken, block)

			// Remove MIR_IF from block
			if pred.Insn < len(block.Insns) {
				block.Insns = append(block.Insns[:pred.Insn], block.Insns[pred.Insn+1:]...)
			}
			opa.Trace = append(opa.Trace, fmt.Sprintf("Removing taken branch for always-false predicate at block %d", pred.Block.ID))
			opa.Changes++
		}
	}
}

func removePred(block *BasicBlock, predToRemove *BasicBlock) {
	newPreds := make([]*BasicBlock, 0, len(block.Preds))
	for _, p := range block.Preds {
		if p != predToRemove {
			newPreds = append(newPreds, p)
		}
	}
	block.Preds = newPreds
}

// GetAlwaysTruePredicates returns all always-true predicates.
func (opa *OpaquePredicateAnalysis) GetAlwaysTruePredicates() []OpaquePredicate {
	return opa.AlwaysTrue
}

// GetAlwaysFalsePredicates returns all always-false predicates.
func (opa *OpaquePredicateAnalysis) GetAlwaysFalsePredicates() []OpaquePredicate {
	return opa.AlwaysFalse
}

// GetChangeCount returns the number of changes made.
func (opa *OpaquePredicateAnalysis) GetChangeCount() int {
	return opa.Changes
}

// GetTrace returns the analysis trace for debugging.
func (opa *OpaquePredicateAnalysis) GetTrace() []string {
	return opa.Trace
}

// AlwaysTrueCount returns the number of always-true predicates.
func (opa *OpaquePredicateAnalysis) AlwaysTrueCount() int {
	return len(opa.AlwaysTrue)
}

// AlwaysFalseCount returns the number of always-false predicates.
func (opa *OpaquePredicateAnalysis) AlwaysFalseCount() int {
	return len(opa.AlwaysFalse)
}

// TotalOpaquePredicates returns the total number of opaque predicates.
func (opa *OpaquePredicateAnalysis) TotalOpaquePredicates() int {
	return len(opa.AlwaysTrue) + len(opa.AlwaysFalse)
}
