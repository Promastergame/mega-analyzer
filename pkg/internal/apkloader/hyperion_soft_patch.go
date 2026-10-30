package apkloader

import "fmt"

// SoftPatch injects a guard at method entry instead of replacing the body.
//
// For a boolean method, produces:
//
//	const/4 v0, <val>
//	if-<cond> v0, :original_entry   ← skip guard if condition met
//	return v0                        ← forced return
//	:original_entry
//	<original code>
//
// For the simplest case (unconditional guard), produces:
//
//	const/4 v0, <val>
//	return v0
//	<original code nop'd>            ← NOT nop'd: original preserved after return
//
// The key difference from AlwaysReturnTrue: original instructions remain in
// Modified and are reachable if the caller patches the guard branch later.

// GuardReturnTrue injects "const/4 v0,1; return v0" at offset 0,
// shifting original code to offset 4. Original logic is preserved and reachable.
func (p *Patcher) GuardReturnTrue() error {
	return p.injectGuard(1)
}

// GuardReturnFalse injects "const/4 v0,0; return v0" at offset 0.
func (p *Patcher) GuardReturnFalse() error {
	return p.injectGuard(0)
}

// GuardReturnVoid injects "return-void" at offset 0, preserving original body.
func (p *Patcher) GuardReturnVoid() error {
	guard := []RawInsn{
		{Op: 0x0E, Format: Fmt10x, Size: 1, Offset: 0},
	}
	return p.prependGuard(guard, "guard_return_void")
}

// GuardCondition injects a conditional early-return at method entry.
// condReg is the register to test (must already hold the condition value).
// If condReg != 0, returns retVal immediately; otherwise falls through.
func (p *Patcher) GuardCondition(condReg uint16, retVal int16) error {
	if len(p.Original) == 0 {
		return fmt.Errorf("empty method")
	}
	// Original entry is at offset 6 (3 instructions × 2 bytes each)
	// if-eqz condReg, +3  → skip to original if condReg == 0
	// const/4 v0, retVal
	// return v0
	// <original code at offset 6>
	originalEntry := uint32(6)
	relOffset := int64(originalEntry) // relative from if-eqz offset=0
	guard := []RawInsn{
		{
			Op:     0x38, // if-eqz
			Format: Fmt21t,
			Regs:   [3]uint16{condReg},
			Imm:    relOffset,
			Size:   2,
			Flags:  FlagBranch,
			Offset: 0,
		},
		{Op: 0x12, Format: Fmt11n, Regs: [3]uint16{0}, Imm: int64(retVal), Size: 1, Offset: 4},
		{Op: 0x0F, Format: Fmt11x, Regs: [3]uint16{0}, Size: 1, Offset: 6},
	}
	return p.prependGuard(guard, fmt.Sprintf("guard_cond_reg%d_ret%d", condReg, retVal))
}

// injectGuard prepends "const/4 v0,val; return v0" — original body follows.
func (p *Patcher) injectGuard(val int16) error {
	guard := []RawInsn{
		{Op: 0x12, Format: Fmt11n, Regs: [3]uint16{0}, Imm: int64(val), Size: 1, Offset: 0},
		{Op: 0x0F, Format: Fmt11x, Regs: [3]uint16{0}, Size: 1, Offset: 2},
	}
	return p.prependGuard(guard, fmt.Sprintf("guard_return_%d", val))
}

// prependGuard shifts all existing offsets and prepends guard instructions.
func (p *Patcher) prependGuard(guard []RawInsn, reason string) error {
	if len(p.Original) == 0 {
		return fmt.Errorf("empty method")
	}
	shift := uint32(0)
	for _, g := range guard {
		shift += uint32(g.Size) * 2
	}
	// Shift original offsets
	shifted := make([]RawInsn, len(p.Modified))
	copy(shifted, p.Modified)
	for i := range shifted {
		shifted[i].Offset += shift
		// Fix branch targets that pointed into original body
		if shifted[i].IsBranch() {
			shifted[i].Imm -= int64(shift) // relative offset stays correct after shift
		}
	}
	p.Modified = append(guard, shifted...)
	p.record("soft_guard", 0, shift, reason)
	return nil
}
