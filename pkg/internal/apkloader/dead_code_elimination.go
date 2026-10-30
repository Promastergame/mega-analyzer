package apkloader

import (
	"fmt"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DEAD CODE ELIMINATION
// ═══════════════════════════════════════════════════════════════════════════════
//
// Removes unreachable and ineffective code while preserving semantics.
// Eliminates assignments whose results are never used (if they have no side effects).

// DeadCodeAnalysis contains the results of dead code analysis.
type DeadCodeAnalysis struct {
	UnreachableBlocks []*BasicBlock      // blocks that are unreachable from entry
	DeadAssignments   []DeadAssignment   // assignments with no uses
	SideEffectFree    map[MIROpKind]bool // instruction kinds with no side effects
	Changes           int                // number of changes made
	Trace             []string           // analysis trace for debugging
}

// DeadAssignment represents an assignment with no uses.
type DeadAssignment struct {
	Block *BasicBlock
	Insn  int
	Reg   int16
}

// AnalyzeDeadCode performs dead code analysis on a CFG.
func AnalyzeDeadCode(cfg *CFG, ssa *SSAForm) *DeadCodeAnalysis {
	analysis := &DeadCodeAnalysis{
		UnreachableBlocks: make([]*BasicBlock, 0),
		DeadAssignments:   make([]DeadAssignment, 0),
		SideEffectFree:    initSideEffectMap(),
		Changes:           0,
		Trace:             make([]string, 0),
	}

	// Step 1: Identify unreachable blocks
	analysis.findUnreachableBlocks(cfg)

	// Step 2: Identify dead assignments
	analysis.findDeadAssignments(cfg, ssa)

	// Step 3: Identify dead branches
	analysis.findDeadBranches(cfg)

	return analysis
}

// initSideEffectMap initializes the side effect map.
func initSideEffectMap() map[MIROpKind]bool {
	sideEffectFree := make(map[MIROpKind]bool)

	// Instructions with no side effects
	sideEffectFree[MIR_CONST] = true
	sideEffectFree[MIR_MOVE] = true
	sideEffectFree[MIR_ADD] = true
	sideEffectFree[MIR_SUB] = true
	sideEffectFree[MIR_RSUB] = true
	sideEffectFree[MIR_MUL] = true
	sideEffectFree[MIR_DIV] = true
	sideEffectFree[MIR_REM] = true
	sideEffectFree[MIR_AND] = true
	sideEffectFree[MIR_OR] = true
	sideEffectFree[MIR_XOR] = true
	sideEffectFree[MIR_NOT] = true
	sideEffectFree[MIR_NEG] = true
	sideEffectFree[MIR_CMP] = true
	sideEffectFree[MIR_CMPL] = true
	sideEffectFree[MIR_CMPG] = true
	sideEffectFree[MIR_CONVERT] = true

	// Instructions with side effects
	sideEffectFree[MIR_INVOKE] = false
	sideEffectFree[MIR_FIELD_PUT] = false
	sideEffectFree[MIR_ARRAY_PUT] = false
	sideEffectFree[MIR_THROW] = false
	sideEffectFree[MIR_RETURN] = false

	return sideEffectFree
}

// findUnreachableBlocks identifies blocks that are unreachable from the entry block.
func (dca *DeadCodeAnalysis) findUnreachableBlocks(cfg *CFG) {
	for _, block := range cfg.Blocks {
		if !block.IsReachable {
			dca.UnreachableBlocks = append(dca.UnreachableBlocks, block)
			dca.Trace = append(dca.Trace, fmt.Sprintf("Found unreachable block: %d", block.ID))
			dca.Changes++
		}
	}
}

// findDeadAssignments identifies assignments whose results are never used.
func (dca *DeadCodeAnalysis) findDeadAssignments(_ *CFG, ssa *SSAForm) {
	if ssa == nil {
		return
	}

	// For each SSA variable, check if it has any uses
	for _, variable := range ssa.Variables {
		if len(variable.Uses) == 0 && !variable.IsPhiResult {
			// This variable is never used
			// Find the instruction that defines it
			if len(variable.Definitions) > 0 {
				def := variable.Definitions[0]
				if def.Insn >= 0 && def.Block != nil && def.Insn < len(def.Block.Insns) {
					insn := &def.Block.Insns[def.Insn]

					// Check if the instruction has side effects
					if dca.hasSideEffect(insn.Kind) {
						continue // Don't remove instructions with side effects
					}

					// This is a dead assignment
					dca.DeadAssignments = append(dca.DeadAssignments, DeadAssignment{
						Block: def.Block,
						Insn:  def.Insn,
						Reg:   variable.OrigRegister,
					})
					dca.Trace = append(dca.Trace, fmt.Sprintf("Found dead assignment: v%d at block %d, insn %d", variable.OrigRegister, def.Block.ID, def.Insn))
					dca.Changes++
				}
			}
		}
	}
}

// findDeadBranches identifies branches that are always taken or never taken.
func (dca *DeadCodeAnalysis) findDeadBranches(cfg *CFG) {
	for _, block := range cfg.Blocks {
		if len(block.Insns) == 0 {
			continue
		}

		lastInsn := &block.Insns[len(block.Insns)-1]

		if lastInsn.Kind == MIR_IF {
			// Check if this is an opaque predicate (always true or always false)
			// This would be detected by constant propagation
			// For now, just mark it as a potential dead branch
			dca.Trace = append(dca.Trace, fmt.Sprintf("Found conditional branch at block %d", block.ID))
		}
	}
}

// hasSideEffect checks if an instruction has side effects.
func (dca *DeadCodeAnalysis) hasSideEffect(kind MIROpKind) bool {
	if sideEffectFree, ok := dca.SideEffectFree[kind]; ok {
		return !sideEffectFree
	}
	// Default to assuming side effects for unknown instructions
	return true
}

// RemoveDeadCode removes dead code from the CFG.
func (dca *DeadCodeAnalysis) RemoveDeadCode(cfg *CFG) {
	// Remove unreachable blocks
	reachableBlocks := make([]*BasicBlock, 0)
	for _, block := range cfg.Blocks {
		if block.IsReachable {
			reachableBlocks = append(reachableBlocks, block)
		}
	}
	cfg.Blocks = reachableBlocks

	// Remove dead assignments
	deadByBlock := make(map[*BasicBlock]map[int]bool)
	for _, da := range dca.DeadAssignments {
		if da.Block != nil {
			if deadByBlock[da.Block] == nil {
				deadByBlock[da.Block] = make(map[int]bool)
			}
			deadByBlock[da.Block][da.Insn] = true
		}
	}

	for block, deadInsns := range deadByBlock {
		newInsns := make([]MIRInsn, 0, len(block.Insns))
		for idx, insn := range block.Insns {
			if !deadInsns[idx] {
				newInsns = append(newInsns, insn)
			}
		}
		block.Insns = newInsns
	}
}

// GetUnreachableBlocks returns all unreachable blocks.
func (dca *DeadCodeAnalysis) GetUnreachableBlocks() []*BasicBlock {
	return dca.UnreachableBlocks
}

// GetDeadAssignments returns all dead assignments.
func (dca *DeadCodeAnalysis) GetDeadAssignments() []DeadAssignment {
	return dca.DeadAssignments
}

// GetChangeCount returns the number of changes made.
func (dca *DeadCodeAnalysis) GetChangeCount() int {
	return dca.Changes
}

// GetTrace returns the analysis trace for debugging.
func (dca *DeadCodeAnalysis) GetTrace() []string {
	return dca.Trace
}

// UnreachableBlockCount returns the number of unreachable blocks.
func (dca *DeadCodeAnalysis) UnreachableBlockCount() int {
	return len(dca.UnreachableBlocks)
}

// DeadAssignmentCount returns the number of dead assignments.
func (dca *DeadCodeAnalysis) DeadAssignmentCount() int {
	return len(dca.DeadAssignments)
}
