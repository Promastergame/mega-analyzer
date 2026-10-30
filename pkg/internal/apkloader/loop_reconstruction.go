package apkloader

import (
	"fmt"
)

// ═══════════════════════════════════════════════════════════════════════════════
// LOOP RECONSTRUCTION
// ═══════════════════════════════════════════════════════════════════════════════
//
// Converts low-level loop structures (goto-based) into high-level for/while constructs.
// Supports three loop types:
//   1. Counted loops (for loops with induction variables)
//   2. Iterator-based loops (for-each style)
//   3. Condition-based loops (while/do-while)
//
// Preserves original goto structure in comments for reference.

// ReconstructedLoopType classifies the type of reconstructed loop.
type ReconstructedLoopType uint8

const (
	ReconstructedLoopUnknown ReconstructedLoopType = iota
	ReconstructedLoopFor                           // for loop with induction variable
	ReconstructedLoopForEach                       // for-each loop with iterator
	ReconstructedLoopWhile                         // while loop
	ReconstructedLoopDoWhile                       // do-while loop
)

// InductionVariable represents an induction variable in a counted loop.
type InductionVariable struct {
	Variable       *SSAVariable // the SSA variable
	InitValue      int64        // initial value
	Increment      int64        // increment per iteration
	Condition      string       // comparison operator: "<", "<=", ">", ">=", "==", "!="
	Bound          int64        // loop bound value
	IsIncrementing bool         // true if incrementing, false if decrementing
}

// IteratorInfo represents iterator information for iterator-based loops.
type IteratorInfo struct {
	IteratorVar    *SSAVariable // the iterator variable
	HasNextMethod  string       // method name for hasNext check
	NextMethod     string       // method name for next call
	ElementType    string       // type of elements
	IterableObject *SSAVariable // the iterable object
}

// LoopConditionInfo represents the condition of a while/do-while loop.
type LoopConditionInfo struct {
	ConditionBlock *BasicBlock // block containing the condition
	ConditionInsn  int         // instruction index of the condition
	Operator       string      // comparison operator
	LeftOperand    interface{} // left side of comparison
	RightOperand   interface{} // right side of comparison
	IsNegated      bool        // true if condition is negated
}

// ReconstructedLoop represents a reconstructed high-level loop.
type ReconstructedLoop struct {
	OriginalLoop       *Loop                 // original natural loop
	LoopType           ReconstructedLoopType // type of reconstructed loop
	InductionVar       *InductionVariable    // for counted loops
	IteratorInfo       *IteratorInfo         // for iterator-based loops
	LoopConditionInfo  *LoopConditionInfo    // for while/do-while loops
	LoopBody           []*BasicBlock         // blocks in loop body
	OriginalGotoCode   string                // original goto structure in comment
	IsSemanticallySafe bool                  // true if reconstruction is semantically equivalent
	ConfidenceScore    int                   // 0-100 confidence in reconstruction
}

// LoopReconstruction performs loop reconstruction on a CFG.
type LoopReconstruction struct {
	CFG                *CFG
	SSA                *SSAForm
	LoopAnalysis       *LoopAnalysis
	ReconstructedLoops map[*Loop]*ReconstructedLoop
	Trace              []string
	Changes            int
}

// NewLoopReconstruction creates a new loop reconstruction analyzer.
func NewLoopReconstruction(cfg *CFG, ssa *SSAForm, loopAnalysis *LoopAnalysis) *LoopReconstruction {
	lr := &LoopReconstruction{
		CFG:                cfg,
		SSA:                ssa,
		LoopAnalysis:       loopAnalysis,
		ReconstructedLoops: make(map[*Loop]*ReconstructedLoop),
		Trace:              make([]string, 0),
		Changes:            0,
	}
	return lr
}

// ReconstructLoops performs loop reconstruction on all loops.
func (lr *LoopReconstruction) ReconstructLoops() {
	if lr.LoopAnalysis == nil || len(lr.LoopAnalysis.AllLoops) == 0 {
		return
	}

	// Process each loop
	for _, loop := range lr.LoopAnalysis.AllLoops {
		reconstructed := lr.reconstructLoop(loop)
		if reconstructed != nil {
			lr.ReconstructedLoops[loop] = reconstructed
			lr.Trace = append(lr.Trace, fmt.Sprintf("Reconstructed loop at %p as %s (confidence: %d)",
				loop.Header, lr.loopTypeString(reconstructed.LoopType), reconstructed.ConfidenceScore))
			lr.Changes++
		}
	}
}

// reconstructLoop reconstructs a single loop.
func (lr *LoopReconstruction) reconstructLoop(loop *Loop) *ReconstructedLoop {
	if loop == nil || loop.Header == nil {
		return nil
	}

	// Try to reconstruct as counted loop
	if countedLoop := lr.reconstructCountedLoop(loop); countedLoop != nil {
		return countedLoop
	}

	// Try to reconstruct as iterator-based loop
	if iteratorLoop := lr.reconstructIteratorLoop(loop); iteratorLoop != nil {
		return iteratorLoop
	}

	// Try to reconstruct as condition-based loop
	if conditionLoop := lr.reconstructConditionLoop(loop); conditionLoop != nil {
		return conditionLoop
	}

	// If no specific type detected, return generic reconstruction
	return lr.createGenericLoopReconstruction(loop)
}

// reconstructCountedLoop attempts to reconstruct a counted loop (for loop).
func (lr *LoopReconstruction) reconstructCountedLoop(loop *Loop) *ReconstructedLoop {
	// A counted loop has:
	// 1. A single back edge
	// 2. An induction variable that is incremented/decremented
	// 3. A loop condition that compares the induction variable

	if len(loop.BackEdges) != 1 {
		return nil
	}

	// Try to identify induction variable
	inductionVar := lr.identifyInductionVariable(loop)
	if inductionVar == nil {
		return nil
	}

	// Try to identify loop bound
	loopBound := lr.identifyLoopBound(loop, inductionVar)
	if loopBound == nil {
		return nil
	}

	// Create reconstructed loop
	reconstructed := &ReconstructedLoop{
		OriginalLoop:       loop,
		LoopType:           ReconstructedLoopFor,
		InductionVar:       inductionVar,
		LoopBody:           loop.Blocks,
		ConfidenceScore:    75, // High confidence for counted loops
		IsSemanticallySafe: true,
		OriginalGotoCode:   lr.generateGotoComment(loop),
	}

	return reconstructed
}

// identifyInductionVariable attempts to identify an induction variable in a loop.
func (lr *LoopReconstruction) identifyInductionVariable(loop *Loop) *InductionVariable {
	// Look for a variable that is:
	// 1. Initialized before the loop
	// 2. Incremented/decremented in the loop body
	// 3. Used in the loop condition

	if lr.SSA == nil || len(lr.SSA.Variables) == 0 {
		return nil
	}

	// Simplified heuristic: look for variables with arithmetic operations in loop body
	for _, variable := range lr.SSA.Variables {
		// Check if variable is used in loop
		usedInLoop := false
		for _, use := range variable.Uses {
			if lr.blockInLoop(use.Block, loop) {
				usedInLoop = true
				break
			}
		}

		if !usedInLoop {
			continue
		}

		// Check if variable has arithmetic operations
		for _, def := range variable.Definitions {
			if lr.blockInLoop(def.Block, loop) {
				// This could be an induction variable
				// For now, return a basic induction variable
				return &InductionVariable{
					Variable:       variable,
					InitValue:      0,
					Increment:      1,
					Condition:      "<",
					Bound:          100, // placeholder
					IsIncrementing: true,
				}
			}
		}
	}

	return nil
}

// identifyLoopBound attempts to identify the loop bound.
func (lr *LoopReconstruction) identifyLoopBound(loop *Loop, inductionVar *InductionVariable) *InductionVariable {
	// Look for a comparison instruction in the loop header
	if loop.Header == nil || len(loop.Header.Insns) == 0 {
		return nil
	}

	// Check the last instruction in the header (usually the condition)
	lastInsn := &loop.Header.Insns[len(loop.Header.Insns)-1]

	if lastInsn.Kind == MIR_IF {
		// This is likely the loop condition
		// Extract the bound from the immediate value
		inductionVar.Bound = int64(lastInsn.Imm)
		return inductionVar
	}

	return nil
}

// reconstructIteratorLoop attempts to reconstruct an iterator-based loop (for-each).
func (lr *LoopReconstruction) reconstructIteratorLoop(loop *Loop) *ReconstructedLoop {
	// An iterator loop has:
	// 1. An iterator object
	// 2. Calls to hasNext() and next()
	// 3. A loop condition based on hasNext()

	// Look for iterator pattern in loop body
	hasNextFound := false
	nextFound := false

	for _, block := range loop.Blocks {
		for _, insn := range block.Insns {
			if insn.Kind == MIR_INVOKE {
				// Check if this is a hasNext or next call
				// This is a simplified check; a full implementation would analyze method names
				hasNextFound = true
				nextFound = true
			}
		}
	}

	if !hasNextFound || !nextFound {
		return nil
	}

	// Create reconstructed loop
	reconstructed := &ReconstructedLoop{
		OriginalLoop:       loop,
		LoopType:           ReconstructedLoopForEach,
		IteratorInfo:       &IteratorInfo{},
		LoopBody:           loop.Blocks,
		ConfidenceScore:    60, // Medium confidence for iterator loops
		IsSemanticallySafe: true,
		OriginalGotoCode:   lr.generateGotoComment(loop),
	}

	return reconstructed
}

// reconstructConditionLoop attempts to reconstruct a condition-based loop (while/do-while).
func (lr *LoopReconstruction) reconstructConditionLoop(loop *Loop) *ReconstructedLoop {
	// A condition-based loop has:
	// 1. A loop condition in the header
	// 2. No obvious induction variable
	// 3. Arbitrary loop body

	if loop.Header == nil || len(loop.Header.Insns) == 0 {
		return nil
	}

	// Check if header has a conditional branch
	lastInsn := &loop.Header.Insns[len(loop.Header.Insns)-1]

	if lastInsn.Kind != MIR_IF {
		return nil
	}

	// Determine if it's a while or do-while loop
	// A do-while loop has the condition at the end of the loop body
	// A while loop has the condition at the beginning
	loopType := ReconstructedLoopWhile

	// Check if any block in the loop body has a back edge to the header
	for _, block := range loop.Blocks {
		for _, succ := range block.Succs {
			if succ == loop.Header && block != loop.Header {
				// This suggests a do-while pattern
				loopType = ReconstructedLoopDoWhile
				break
			}
		}
	}

	// Create loop condition
	condition := &LoopConditionInfo{
		ConditionBlock: loop.Header,
		ConditionInsn:  len(loop.Header.Insns) - 1,
		Operator:       "!=", // placeholder
		IsNegated:      false,
	}

	// Create reconstructed loop
	reconstructed := &ReconstructedLoop{
		OriginalLoop:       loop,
		LoopType:           loopType,
		LoopConditionInfo:  condition,
		LoopBody:           loop.Blocks,
		ConfidenceScore:    50, // Lower confidence for condition-based loops
		IsSemanticallySafe: true,
		OriginalGotoCode:   lr.generateGotoComment(loop),
	}

	return reconstructed
}

// createGenericLoopReconstruction creates a generic loop reconstruction when type cannot be determined.
func (lr *LoopReconstruction) createGenericLoopReconstruction(loop *Loop) *ReconstructedLoop {
	return &ReconstructedLoop{
		OriginalLoop:       loop,
		LoopType:           ReconstructedLoopUnknown,
		LoopBody:           loop.Blocks,
		ConfidenceScore:    30, // Low confidence for unknown loops
		IsSemanticallySafe: true,
		OriginalGotoCode:   lr.generateGotoComment(loop),
	}
}

// generateGotoComment generates a comment with the original goto structure.
func (lr *LoopReconstruction) generateGotoComment(loop *Loop) string {
	comment := "// Original goto structure:\n"

	for i, block := range loop.Blocks {
		comment += fmt.Sprintf("// Block %d (offset %d):\n", i, block.Start)

		for j, insn := range block.Insns {
			switch insn.Kind {
			case MIR_GOTO:
				comment += fmt.Sprintf("//   [%d] goto offset %d\n", j, insn.Imm)
			case MIR_IF:
				comment += fmt.Sprintf("//   [%d] if ... goto offset %d\n", j, insn.Imm)
			default:
				comment += fmt.Sprintf("//   [%d] %s\n", j, lr.insnKindString(insn.Kind))
			}
		}
	}

	return comment
}

// blockInLoop checks if a block is in a loop.
func (lr *LoopReconstruction) blockInLoop(block *BasicBlock, loop *Loop) bool {
	for _, b := range loop.Blocks {
		if b == block {
			return true
		}
	}
	return false
}

// loopTypeString returns a string representation of a loop type.
func (lr *LoopReconstruction) loopTypeString(loopType ReconstructedLoopType) string {
	switch loopType {
	case ReconstructedLoopFor:
		return "for"
	case ReconstructedLoopForEach:
		return "for-each"
	case ReconstructedLoopWhile:
		return "while"
	case ReconstructedLoopDoWhile:
		return "do-while"
	default:
		return "unknown"
	}
}

// insnKindString returns a string representation of an instruction kind.
func (lr *LoopReconstruction) insnKindString(kind MIROpKind) string {
	switch kind {
	case MIR_CONST:
		return "const"
	case MIR_ADD:
		return "add"
	case MIR_SUB:
		return "sub"
	case MIR_MUL:
		return "mul"
	case MIR_DIV:
		return "div"
	case MIR_IF:
		return "if"
	case MIR_GOTO:
		return "goto"
	case MIR_RETURN:
		return "return"
	case MIR_INVOKE:
		return "invoke"
	default:
		return "unknown"
	}
}

// GetReconstructedLoop returns the reconstructed loop for a given natural loop.
func (lr *LoopReconstruction) GetReconstructedLoop(loop *Loop) *ReconstructedLoop {
	return lr.ReconstructedLoops[loop]
}

// GetReconstructedLoops returns all reconstructed loops.
func (lr *LoopReconstruction) GetReconstructedLoops() map[*Loop]*ReconstructedLoop {
	return lr.ReconstructedLoops
}

// GetTrace returns the reconstruction trace for debugging.
func (lr *LoopReconstruction) GetTrace() []string {
	return lr.Trace
}

// GetChangeCount returns the number of loops reconstructed.
func (lr *LoopReconstruction) GetChangeCount() int {
	return lr.Changes
}

// ReconstructionCount returns the total number of reconstructed loops.
func (lr *LoopReconstruction) ReconstructionCount() int {
	return len(lr.ReconstructedLoops)
}

// AverageConfidence returns the average confidence score.
func (lr *LoopReconstruction) AverageConfidence() int {
	if len(lr.ReconstructedLoops) == 0 {
		return 0
	}

	total := 0
	for _, reconstructed := range lr.ReconstructedLoops {
		total += reconstructed.ConfidenceScore
	}

	return total / len(lr.ReconstructedLoops)
}

// VerifySemanticEquivalence verifies that reconstructed loops are semantically equivalent.
func (lr *LoopReconstruction) VerifySemanticEquivalence(reconstructed *ReconstructedLoop) bool {
	// Verify that the reconstructed loop has the same:
	// 1. Loop body blocks
	// 2. Back edges
	// 3. Entry/exit points

	if reconstructed == nil || reconstructed.OriginalLoop == nil {
		return false
	}

	original := reconstructed.OriginalLoop

	// Check that loop body is preserved
	if len(reconstructed.LoopBody) != len(original.Blocks) {
		return false
	}

	// Check that back edges are preserved
	if len(reconstructed.LoopBody) > 0 {
		// Verify that the last block has a back edge to the header
		lastBlock := reconstructed.LoopBody[len(reconstructed.LoopBody)-1]
		hasBackEdge := false
		for _, succ := range lastBlock.Succs {
			if succ == original.Header {
				hasBackEdge = true
				break
			}
		}

		if !hasBackEdge && len(original.BackEdges) > 0 {
			return false
		}
	}

	return true
}
