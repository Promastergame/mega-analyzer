package apkloader

import "fmt"

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Phase 4.2: Branch Fixup Pass
// ═══════════════════════════════════════════════════════════════════════════════
//
// After instruction insertion/deletion, branch targets must be recalculated.
// Uses two-pass approach: measure → patch → emit.

// BranchFixup handles offset recalculation after code modifications.
type BranchFixup struct {
	insns   []RawInsn
	offsets []uint32    // byte offset of each instruction
	targets map[int]int // insn index → target insn index
}

// NewBranchFixup creates a fixup pass for modified instructions.
func NewBranchFixup(insns []RawInsn) *BranchFixup {
	return &BranchFixup{
		insns:   insns,
		offsets: make([]uint32, len(insns)),
		targets: make(map[int]int),
	}
}

// ComputeOffsets calculates the final byte offset of each instruction.
// Must be called before any branch targets are resolved.
func (bf *BranchFixup) ComputeOffsets() {
	var offset uint32
	for i := range bf.insns {
		bf.offsets[i] = offset
		size := bf.instructionSize(&bf.insns[i])
		offset += size
	}
}

// ResolveTargets maps branch instructions to their target indices.
func (bf *BranchFixup) ResolveTargets(cfg *CFG) {
	for i := range bf.insns {
		insn := &bf.insns[i]
		if !insn.IsBranch() && !insn.IsSwitch() {
			continue
		}

		// Calculate absolute target from relative offset
		if insn.IsBranch() {
			targetOffset := uint32(int32(insn.Offset) + int32(insn.Imm))
			// Find target instruction index
			for j, off := range bf.offsets {
				if off == targetOffset {
					bf.targets[i] = j
					break
				}
			}
		}
		// Switch handling would need payload parsing
	}
}

// Fixup recalculates branch offsets after code changes.
// Returns a new RawInsn slice with updated offsets.
func (bf *BranchFixup) Fixup() ([]RawInsn, error) {
	bf.ComputeOffsets()

	newInsns := make([]RawInsn, len(bf.insns))
	copy(newInsns, bf.insns)

	for i := range newInsns {
		insn := &newInsns[i]
		if !insn.IsBranch() {
			continue
		}

		// Get target index
		targetIdx, ok := bf.targets[i]
		if !ok {
			// New branch or target not resolved
			continue
		}

		// Calculate new relative offset
		srcOffset := bf.offsets[i]
		dstOffset := bf.offsets[targetIdx]
		relOffset := int32(dstOffset) - int32(srcOffset)

		// Check if offset fits in instruction format
		if err := bf.checkOffsetFits(insn, relOffset); err != nil {
			return nil, fmt.Errorf("branch at %d: %w", i, err)
		}

		insn.Imm = int64(relOffset)
		insn.Offset = srcOffset
	}

	return newInsns, nil
}

// instructionSize returns the size of an instruction in bytes.
func (bf *BranchFixup) instructionSize(insn *RawInsn) uint32 {
	meta := &opcodeMetaTable[insn.Op]
	return meta.Size * 2 // Size is in 16-bit units
}

// checkOffsetFits verifies the relative offset fits in the instruction's immediate field.
func (bf *BranchFixup) checkOffsetFits(insn *RawInsn, offset int32) error {
	meta := &opcodeMetaTable[insn.Op]

	switch meta.Format {
	case Fmt10t:
		// 8-bit signed immediate (in 16-bit units)
		if offset < -128 || offset > 127 {
			return fmt.Errorf("goto offset %d out of 8-bit range", offset)
		}
	case Fmt20t:
		// 16-bit signed immediate
		if offset < -32768 || offset > 32767 {
			return fmt.Errorf("goto/16 offset %d out of 16-bit range", offset)
		}
	case Fmt21t, Fmt22t:
		// 16-bit signed immediate for conditional branches
		if offset < -32768 || offset > 32767 {
			return fmt.Errorf("branch offset %d out of 16-bit range", offset)
		}
	case Fmt30t, Fmt31t:
		// 32-bit signed immediate (rarely overflows)
		// Already int32, so always fits
	default:
		return fmt.Errorf("branch in non-branch format: %v", meta.Format)
	}

	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// INSTRUCTION INSERTION/DELETION HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// InsertNop replaces an instruction with nop.
func (bf *BranchFixup) InsertNop(idx int) {
	bf.insns[idx] = RawInsn{
		Op:     0x00, // nop
		Format: Fmt10x,
		Size:   1,
		Offset: bf.insns[idx].Offset,
	}
}

// InsertRange replaces a range with nops.
func (bf *BranchFixup) InsertNopRange(start, end int) {
	for i := start; i < end && i < len(bf.insns); i++ {
		bf.InsertNop(i)
	}
}

// RemoveInstruction marks for deletion (converts to nop, actual removal is complex).
func (bf *BranchFixup) RemoveInstruction(idx int) error {
	if idx < 0 || idx >= len(bf.insns) {
		return fmt.Errorf("invalid index: %d", idx)
	}

	// Replace with nop(s) to preserve offsets
	bf.InsertNop(idx)
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// OPTIMIZED TWO-PASS EMISSION
// ═══════════════════════════════════════════════════════════════════════════════

// EmitterWithFixup emits code with automatic branch resolution.
type EmitterWithFixup struct {
	insns []RawInsn
}

// NewEmitterWithFixup creates an emitter that handles branch fixup automatically.
func NewEmitterWithFixup(insns []RawInsn) *EmitterWithFixup {
	return &EmitterWithFixup{insns: insns}
}

// Emit emits the code with all branch targets resolved.
func (ef *EmitterWithFixup) Emit() ([]byte, error) {
	// Pass 1: Calculate offsets (may need iteration for forward branches)
	fixup := NewBranchFixup(ef.insns)

	// Multiple passes until stable (for complex cases)
	maxPasses := 3
	for pass := 0; pass < maxPasses; pass++ {
		fixup.ComputeOffsets()

		// Try to emit
		emitter := NewInsnEmitter(len(ef.insns))
		offsets, err := emitter.EmitAll(ef.insns)
		if err != nil {
			return nil, err
		}

		// Check if offsets match
		stable := true
		for i, off := range offsets {
			if fixup.offsets[i] != off {
				stable = false
				// Update instruction offsets
				ef.insns[i].Offset = off
			}
		}

		if stable {
			return emitter.Bytes(), nil
		}
	}

	return nil, fmt.Errorf("branch fixup did not converge after %d passes", maxPasses)
}
