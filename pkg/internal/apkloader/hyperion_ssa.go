package apkloader

import "fmt"

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Phase 3.5: SSA Form Construction (Cytron Algorithm)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Converts MIR into SSA form via:
//   1. Dominance Frontier calculation (Cooper-Harvey-Kennedy)
//   2. Phi-function placement
//   3. Variable renaming (stack-based)
//
// SSA enables sparse dataflow analysis — the foundation for taint tracking.

import "sort"

// SSAVar represents a variable in SSA form (original reg + version).
// Version 0 = entry value (parameter or undefined).
type SSAVar struct {
	Reg     uint16 // original register number
	Version uint32 // SSA version (0 = entry)
}

// SSAPhi represents a phi-function: v = φ(v1, v2, ..., vn)
// One operand per predecessor block.
type SSAPhi struct {
	Dst      SSAVar      // result variable
	Operands []SSAVar    // one per predecessor (index matches block.Preds)
	Block    *BasicBlock // owning block
}

// SSAInsn wraps MIRInsn with SSA operands.
type SSAInsn struct {
	MIR  *MIRInsn // original instruction
	Dst  SSAVar   // destination (if any)
	Srcs []SSAVar // source operands
}

// SSABlock is a basic block in SSA form.
type SSABlock struct {
	*BasicBlock
	Phis    []*SSAPhi         // phi-functions at block entry
	Insns   []*SSAInsn        // SSA instructions
	LiveIn  map[uint16]SSAVar // register -> SSAVar at entry
	LiveOut map[uint16]SSAVar // register -> SSAVar at exit
}

// SSAFunction holds the complete SSA form of a method.
type SSAFunction struct {
	Blocks []*SSABlock
	Entry  *SSABlock
	MaxReg uint16 // highest register number used
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOMINANCE FRONTIER
// ═══════════════════════════════════════════════════════════════════════════════

// DominanceFrontier returns DF(n) = { y | n dominates pred(y), n does not dom y }
// Uses Cooper-Harvey-Kennedy algorithm: O(N^2) worst case, fast for method-level.
func (cfg *CFG) DominanceFrontier() map[int][]*BasicBlock {
	df := make(map[int][]*BasicBlock)

	for _, b := range cfg.Blocks {
		// Block with multiple predecessors is merge point
		if len(b.Preds) < 2 {
			continue
		}

		for _, p := range b.Preds {
			runner := p
			// Walk up dominator tree until we hit b's immediate dominator
			for runner != b.IDom && runner != nil {
				df[runner.ID] = append(df[runner.ID], b)
				runner = runner.IDom
			}
		}
	}

	return df
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHI PLACEMENT
// ═══════════════════════════════════════════════════════════════════════════════

// RegDef represents a register definition site.
type RegDef struct {
	Block *BasicBlock
	Insn  *MIRInsn
	Reg   uint16
}

// findRegDefs locates all definitions of each register in MIR.
func findRegDefs(cfg *CFG, mir []MIRInsn) map[uint16][]*BasicBlock {
	defs := make(map[uint16][]*BasicBlock)

	for i := range cfg.Blocks {
		block := cfg.Blocks[i]
		for j := range block.Insns {
			insn := &block.Insns[j]
			if insn.Dst >= 0 {
				reg := uint16(insn.Dst)
				// Add block if not already in list
				found := false
				for _, b := range defs[reg] {
					if b == block {
						found = true
						break
					}
				}
				if !found {
					defs[reg] = append(defs[reg], block)
				}
			}
		}
	}

	// Also mark parameter registers (v0..vN) as defined in entry block
	if cfg.Entry != nil && len(mir) > 0 {
		// Detect parameter registers from insSize (approximate)
		// For now, assume v0-v3 might be params
		for r := uint16(0); r < 4 && r < 256; r++ {
			found := false
			for _, b := range defs[r] {
				if b == cfg.Entry {
					found = true
					break
				}
			}
			if !found {
				defs[r] = append(defs[r], cfg.Entry)
			}
		}
	}

	return defs
}

// PlacePhis determines where phi-functions are needed using iterated DF.
func PlacePhis(cfg *CFG, defs map[uint16][]*BasicBlock) map[uint16][]*BasicBlock {
	df := cfg.DominanceFrontier()
	phiPlacements := make(map[uint16][]*BasicBlock)

	for reg, defBlocks := range defs {
		// Worklist = blocks with definitions
		worklist := make([]*BasicBlock, len(defBlocks))
		copy(worklist, defBlocks)

		// Track which blocks already have phi for this reg
		hasPhi := make(map[int]bool)

		for len(worklist) > 0 {
			// Pop from front
			b := worklist[0]
			worklist = worklist[1:]

			// Check DF of this block
			for _, y := range df[b.ID] {
				if hasPhi[y.ID] {
					continue
				}

				// Place phi for reg in block y
				phiPlacements[reg] = append(phiPlacements[reg], y)
				hasPhi[y.ID] = true

				// Add y to worklist if it also defines reg
				definesReg := false
				for _, db := range defs[reg] {
					if db == y {
						definesReg = true
						break
					}
				}
				if !definesReg {
					worklist = append(worklist, y)
				}
			}
		}
	}

	return phiPlacements
}

// ═══════════════════════════════════════════════════════════════════════════════
// VARIABLE RENAMING
// ═══════════════════════════════════════════════════════════════════════════════

// varStack tracks the current SSA version for each register.
type varStack struct {
	stack map[uint16][]uint32 // reg -> stack of versions
	count map[uint16]uint32   // reg -> next version number
}

func newVarStack() *varStack {
	return &varStack{
		stack: make(map[uint16][]uint32),
		count: make(map[uint16]uint32),
	}
}

// push creates a new version for register.
func (vs *varStack) push(reg uint16) uint32 {
	ver := vs.count[reg]
	vs.count[reg] = ver + 1
	vs.stack[reg] = append(vs.stack[reg], ver)
	return ver
}

// pop removes the top version for register.
func (vs *varStack) pop(reg uint16) {
	if s := vs.stack[reg]; len(s) > 0 {
		vs.stack[reg] = s[:len(s)-1]
	}
}

// top returns the current version for register (0 if none).
func (vs *varStack) top(reg uint16) uint32 {
	if s := vs.stack[reg]; len(s) > 0 {
		return s[len(s)-1]
	}
	return 0
}

// snapshot saves current state for restoration.
func (vs *varStack) snapshot() map[uint16]int {
	snap := make(map[uint16]int)
	for reg, s := range vs.stack {
		snap[reg] = len(s)
	}
	return snap
}

// restore rolls back to snapshot.
func (vs *varStack) restore(snap map[uint16]int) {
	for reg, height := range snap {
		if s := vs.stack[reg]; len(s) > height {
			vs.stack[reg] = s[:height]
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSA CONSTRUCTION
// ═══════════════════════════════════════════════════════════════════════════════

// BuildSSA constructs SSA form from CFG and MIR.
func BuildSSA(cfg *CFG, mir []MIRInsn) *SSAFunction {
	if cfg.Entry == nil || len(cfg.Blocks) == 0 {
		return nil
	}

	// Step 1: Find all register definitions
	defs := findRegDefs(cfg, mir)

	// Step 2: Determine phi placement
	phiPlacements := PlacePhis(cfg, defs)

	// Step 3: Initialize SSABlocks
	ssaBlocks := make(map[int]*SSABlock)
	for _, b := range cfg.Blocks {
		ssaBlocks[b.ID] = &SSABlock{
			BasicBlock: b,
			Phis:       nil,
			Insns:      make([]*SSAInsn, 0, len(b.Insns)),
			LiveIn:     make(map[uint16]SSAVar),
			LiveOut:    make(map[uint16]SSAVar),
		}
	}

	// Create phi functions
	maxReg := uint16(0)
	for reg, blocks := range phiPlacements {
		if reg > maxReg {
			maxReg = reg
		}
		for _, b := range blocks {
			phi := &SSAPhi{
				Dst:      SSAVar{Reg: reg, Version: 1}, // temporary
				Operands: make([]SSAVar, len(b.Preds)),
				Block:    b,
			}
			sb := ssaBlocks[b.ID]
			sb.Phis = append(sb.Phis, phi)
		}
	}

	// Find max register from MIR too
	for _, insn := range mir {
		if insn.Dst >= 0 && uint16(insn.Dst) > maxReg {
			maxReg = uint16(insn.Dst)
		}
		if insn.Src1 >= 0 && uint16(insn.Src1) > maxReg {
			maxReg = uint16(insn.Src1)
		}
		if insn.Src2 >= 0 && uint16(insn.Src2) > maxReg {
			maxReg = uint16(insn.Src2)
		}
		if insn.Src3 >= 0 && uint16(insn.Src3) > maxReg {
			maxReg = uint16(insn.Src3)
		}
		for _, argReg := range insn.Args() {
			if argReg > maxReg {
				maxReg = argReg
			}
		}
	}

	// Step 4: Rename variables (dominator tree walk)
	vs := newVarStack()

	// Sort blocks by ID for deterministic order
	sortedBlocks := make([]*BasicBlock, len(cfg.Blocks))
	copy(sortedBlocks, cfg.Blocks)
	sort.Slice(sortedBlocks, func(i, j int) bool {
		return sortedBlocks[i].ID < sortedBlocks[j].ID
	})

	// Build dominator tree children map
	children := make(map[int][]*BasicBlock)
	for _, b := range sortedBlocks {
		if b.IDom != nil {
			children[b.IDom.ID] = append(children[b.IDom.ID], b)
		}
	}

	// Recursive rename starting from entry
	var rename func(b *BasicBlock)
	rename = func(b *BasicBlock) {
		sb := ssaBlocks[b.ID]
		snap := vs.snapshot()

		// Process phi results (assign new versions)
		for _, phi := range sb.Phis {
			phi.Dst.Version = vs.push(phi.Dst.Reg)
		}

		// Process regular instructions
		for i := range b.Insns {
			mir := &b.Insns[i]
			ssaInsn := &SSAInsn{MIR: mir}

			// Rename sources
			if mir.Src1 >= 0 {
				reg := uint16(mir.Src1)
				ssaInsn.Srcs = append(ssaInsn.Srcs, SSAVar{Reg: reg, Version: vs.top(reg)})
			}
			if mir.Src2 >= 0 {
				reg := uint16(mir.Src2)
				ssaInsn.Srcs = append(ssaInsn.Srcs, SSAVar{Reg: reg, Version: vs.top(reg)})
			}
			if mir.Src3 >= 0 {
				reg := uint16(mir.Src3)
				ssaInsn.Srcs = append(ssaInsn.Srcs, SSAVar{Reg: reg, Version: vs.top(reg)})
			}
			for _, argReg := range mir.Args() {
				ssaInsn.Srcs = append(ssaInsn.Srcs, SSAVar{Reg: argReg, Version: vs.top(argReg)})
			}

			// Rename destination
			if mir.Dst >= 0 {
				reg := uint16(mir.Dst)
				ver := vs.push(reg)
				ssaInsn.Dst = SSAVar{Reg: reg, Version: ver}
				sb.LiveOut[reg] = ssaInsn.Dst
			}

			sb.Insns = append(sb.Insns, ssaInsn)
		}

		// Fill phi operands in successors
		for _, succ := range b.Succs {
			succBlock := ssaBlocks[succ.ID]
			for _, phi := range succBlock.Phis {
				// Find which predecessor index we are
				for i, pred := range succ.Preds {
					if pred == b {
						reg := phi.Dst.Reg
						phi.Operands[i] = SSAVar{Reg: reg, Version: vs.top(reg)}
						break
					}
				}
			}
		}

		// Recurse to dominator children
		for _, child := range children[b.ID] {
			rename(child)
		}

		vs.restore(snap)
	}

	rename(cfg.Entry)

	// Collect blocks in order
	ssaBlockList := make([]*SSABlock, len(sortedBlocks))
	for i, b := range sortedBlocks {
		ssaBlockList[i] = ssaBlocks[b.ID]
	}

	return &SSAFunction{
		Blocks: ssaBlockList,
		Entry:  ssaBlocks[cfg.Entry.ID],
		MaxReg: maxReg,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SSA QUERIES
// ═══════════════════════════════════════════════════════════════════════════════

// GetVersion returns the SSA version of a register at instruction position.
func (sb *SSABlock) GetVersion(reg uint16, insnIdx int) SSAVar {
	// Check if defined by a phi
	for _, phi := range sb.Phis {
		if phi.Dst.Reg == reg {
			return phi.Dst
		}
	}

	// Walk through instructions
	for i := 0; i <= insnIdx && i < len(sb.Insns); i++ {
		if sb.Insns[i].Dst.Reg == reg {
			return sb.Insns[i].Dst
		}
	}

	// Return entry value
	return SSAVar{Reg: reg, Version: 0}
}

// String returns human-readable SSA form.
func (v SSAVar) String() string {
	return fmt.Sprintf("v%d_%d", v.Reg, v.Version)
}
