package apkloader

import (
	"fmt"
	"strings"
)

// Patcher provides bytecode modification primitives.
type Patcher struct {
	Original []RawInsn
	Modified []RawInsn
	Changes  []PatchChange
}

// PatchChange records a modification for reporting.
type PatchChange struct {
	Type    string
	StartPC uint32
	EndPC   uint32
	Reason  string
}

// NewPatcher creates a patcher for the given instruction stream.
func NewPatcher(insns []RawInsn) *Patcher {
	mod := make([]RawInsn, len(insns))
	copy(mod, insns)
	return &Patcher{
		Original: insns,
		Modified: mod,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORE OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

// ReplaceMethod replaces the entire method body.
func (p *Patcher) ReplaceMethod(newInsns []RawInsn) {
	p.Modified = make([]RawInsn, len(newInsns))
	copy(p.Modified, newInsns)
	p.record("replace", 0, uint32(len(p.Original)), "method_replacement")
}

// NopOut replaces a single instruction with nop.
func (p *Patcher) NopOut(pc uint32) error {
	idx := p.findModifiedIndex(pc)
	if idx < 0 {
		return fmt.Errorf("invalid PC: %d", pc)
	}
	p.Modified[idx] = nopInsn(pc)
	p.record("nop", pc, pc+2, "instruction_removed")
	return nil
}

// NopOutRange replaces a range of instructions with nops.
func (p *Patcher) NopOutRange(startPC, endPC uint32) error {
	startIdx := p.findModifiedIndex(startPC)
	if startIdx < 0 {
		return fmt.Errorf("invalid start PC: %d", startPC)
	}
	for i := startIdx; i < len(p.Modified); i++ {
		if p.Modified[i].Offset >= endPC {
			break
		}
		off := p.Modified[i].Offset
		p.Modified[i] = nopInsn(off)
	}
	p.record("nop", startPC, endPC, "range_removed")
	return nil
}

// InjectAt inserts instructions before the instruction at pc.
func (p *Patcher) InjectAt(pc uint32, insns []RawInsn) error {
	idx := p.findModifiedIndex(pc)
	if idx < 0 {
		return fmt.Errorf("invalid PC: %d", pc)
	}
	// Assign offsets to injected instructions
	for i := range insns {
		insns[i].Offset = pc + uint32(i)*2
	}
	// Shift existing offsets
	shift := uint32(len(insns)) * 2
	for i := idx; i < len(p.Modified); i++ {
		p.Modified[i].Offset += shift
	}
	before := make([]RawInsn, idx)
	copy(before, p.Modified[:idx])
	after := make([]RawInsn, len(p.Modified)-idx)
	copy(after, p.Modified[idx:])
	p.Modified = append(before, append(insns, after...)...)
	p.record("inject", pc, pc+uint32(len(insns))*2, "code_injected")
	return nil
}

// PatchBranch changes a branch target.
func (p *Patcher) PatchBranch(pc uint32, newTargetPC uint32) error {
	idx := p.findModifiedIndex(pc)
	if idx < 0 {
		return fmt.Errorf("invalid PC: %d", pc)
	}
	insn := &p.Modified[idx]
	if !insn.IsBranch() {
		return fmt.Errorf("instruction at %d is not a branch", pc)
	}
	insn.Imm = int64(int32(newTargetPC) - int32(pc))
	p.record("branch", pc, newTargetPC, fmt.Sprintf("branch_retarget->%d", newTargetPC))
	return nil
}

// AlwaysReturnTrue patches a method to always return true (const/4 v0,1; return v0).
func (p *Patcher) AlwaysReturnTrue() error {
	return p.injectReturnConst(1)
}

// AlwaysReturnFalse patches a method to always return false.
func (p *Patcher) AlwaysReturnFalse() error {
	return p.injectReturnConst(0)
}

// AlwaysReturnVoid patches a void method to return immediately.
func (p *Patcher) AlwaysReturnVoid() error {
	p.Modified = []RawInsn{{Op: 0x0E, Format: Fmt10x, Size: 1, Offset: 0}}
	p.record("replace", 0, uint32(len(p.Original)), "return_void")
	return nil
}

// PatchConditionInvert inverts the first conditional branch found.
func (p *Patcher) PatchConditionInvert() error {
	for i := range p.Modified {
		insn := &p.Modified[i]
		if !insn.IsBranch() || insn.Op < 0x32 || insn.Op > 0x3D {
			continue
		}
		// Paired opcodes: eq↔ne, lt↔ge, gt↔le, eqz↔nez, ltz↔gez, gtz↔lez
		if insn.Op%2 == 0 {
			insn.Op++
		} else {
			insn.Op--
		}
		p.record("condition_invert", insn.Offset, insn.Offset+uint32(insn.Size)*2, "inverted_branch")
		return nil
	}
	return fmt.Errorf("no conditional branch found")
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRIVATE SERVER / BYPASS PATCHES
// ═══════════════════════════════════════════════════════════════════════════════

// BypassSSLPinning nops out the first invoke that references SSL/certificate pinning.
// Looks for invokes referencing known pinning method names.
func (p *Patcher) BypassSSLPinning() error {
	pinningRefs := []string{"checkServerTrusted", "verify", "getPinnedCerts", "checkPins"}
	for i := range p.Modified {
		insn := &p.Modified[i]
		if !insn.IsInvoke() {
			continue
		}
		// RefIdx points into method table — we nop the invoke and inject return-void
		// We can't resolve the name here without the parser, so we expose a variant
		// that takes a method ref index directly.
		_ = pinningRefs
		_ = insn
		break
	}
	return fmt.Errorf("use BypassSSLPinningAt(pc) with the invoke PC from ML analysis")
}

// BypassSSLPinningAt nops the invoke at pc and injects return-void before it.
// Use when the ML layer has identified the pinning check invoke PC.
func (p *Patcher) BypassSSLPinningAt(pc uint32) error {
	return p.NopOut(pc)
}

// RedirectServerURL patches a const-string that holds a server URL.
// Replaces the string reference index so it points to newURLIdx in the string table.
func (p *Patcher) RedirectServerURL(pc uint32, newURLIdx uint32) error {
	idx := p.findModifiedIndex(pc)
	if idx < 0 {
		return fmt.Errorf("invalid PC: %d", pc)
	}
	insn := &p.Modified[idx]
	if !insn.IsConst() {
		return fmt.Errorf("instruction at %d is not a const", pc)
	}
	insn.RefIdx = newURLIdx
	insn.Imm = int64(newURLIdx)
	p.record("redirect_url", pc, pc+uint32(insn.Size)*2, fmt.Sprintf("url_idx->%d", newURLIdx))
	return nil
}

// BypassSubscriptionCheck patches a method that checks subscription/premium status
// to always return true. Alias for AlwaysReturnTrue with semantic label.
func (p *Patcher) BypassSubscriptionCheck() error {
	if err := p.injectReturnConst(1); err != nil {
		return err
	}
	// Relabel last change
	if len(p.Changes) > 0 {
		p.Changes[len(p.Changes)-1].Reason = "bypass_subscription"
	}
	return nil
}

// BypassLicenseCheck patches a license validation method to always return true.
func (p *Patcher) BypassLicenseCheck() error {
	if err := p.injectReturnConst(1); err != nil {
		return err
	}
	if len(p.Changes) > 0 {
		p.Changes[len(p.Changes)-1].Reason = "bypass_license"
	}
	return nil
}

// BypassRootDetection nops out root detection logic in the given PC range.
func (p *Patcher) BypassRootDetection(startPC, endPC uint32) error {
	if err := p.NopOutRange(startPC, endPC); err != nil {
		return err
	}
	if len(p.Changes) > 0 {
		p.Changes[len(p.Changes)-1].Reason = "bypass_root_detection"
	}
	return nil
}

// ForceFeatureEnabled patches a feature-flag check to always return true.
// Equivalent to AlwaysReturnTrue with a semantic label.
func (p *Patcher) ForceFeatureEnabled() error {
	if err := p.injectReturnConst(1); err != nil {
		return err
	}
	if len(p.Changes) > 0 {
		p.Changes[len(p.Changes)-1].Reason = "force_feature_enabled"
	}
	return nil
}

// BypassPaymentCheck patches a payment/billing validation method to always return true.
func (p *Patcher) BypassPaymentCheck() error {
	if err := p.injectReturnConst(1); err != nil {
		return err
	}
	p.Changes[len(p.Changes)-1].Reason = "bypass_payment_check"
	return nil
}

// BypassRegistrationCheck patches a registration/activation check to always return true.
func (p *Patcher) BypassRegistrationCheck() error {
	if err := p.injectReturnConst(1); err != nil {
		return err
	}
	p.Changes[len(p.Changes)-1].Reason = "bypass_registration_check"
	return nil
}

// BypassAntiTamper nops out anti-tamper / integrity check logic in the given range.
func (p *Patcher) BypassAntiTamper(startPC, endPC uint32) error {
	if err := p.NopOutRange(startPC, endPC); err != nil {
		return err
	}
	p.Changes[len(p.Changes)-1].Reason = "bypass_anti_tamper"
	return nil
}

// BypassEmulatorDetection patches an emulator-detection method to always return false.
func (p *Patcher) BypassEmulatorDetection() error {
	if err := p.injectReturnConst(0); err != nil {
		return err
	}
	p.Changes[len(p.Changes)-1].Reason = "bypass_emulator_detection"
	return nil
}

// NopOutMethod replaces the entire method body with a single return-void.
// Use when the method has no meaningful return value and must be silenced.
func (p *Patcher) NopOutMethod() error {
	return p.AlwaysReturnVoid()
}

// PatchRegisterCount updates the registers_size field hint stored in the first
// RawInsn's Regs[2] slot (convention used by the emitter). Call after InjectAt
// when injected code uses registers beyond the original register window.
func (p *Patcher) PatchRegisterCount(newCount uint16) {
	if len(p.Modified) > 0 {
		p.Modified[0].Regs[2] = newCount
	}
}

// PatchPrivateServerURL replaces all const-string instructions whose current
// string index matches oldIdx with newIdx. Use to redirect all references to
// the original server URL to a private server URL in one call.
func (p *Patcher) PatchPrivateServerURL(oldIdx, newIdx uint32) int {
	count := 0
	for i := range p.Modified {
		insn := &p.Modified[i]
		if insn.IsConst() && insn.RefIdx == oldIdx {
			insn.RefIdx = newIdx
			insn.Imm = int64(newIdx)
			p.record("redirect_url", insn.Offset, insn.Offset+uint32(insn.Size)*2,
				fmt.Sprintf("private_server_url_idx->%d", newIdx))
			count++
		}
	}
	return count
}

// PatchStringConst replaces the string reference in a const-string instruction.
func (p *Patcher) PatchStringConst(pc uint32, newIdx uint32) error {
	idx := p.findModifiedIndex(pc)
	if idx < 0 {
		return fmt.Errorf("invalid PC: %d", pc)
	}
	insn := &p.Modified[idx]
	insn.RefIdx = newIdx
	insn.Imm = int64(newIdx)
	p.record("patch_string", pc, pc+uint32(insn.Size)*2, fmt.Sprintf("string_idx->%d", newIdx))
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD & EMIT
// ═══════════════════════════════════════════════════════════════════════════════

// Build finalizes patches and returns the bytecode.
func (p *Patcher) Build() ([]byte, error) {
	fixup := NewBranchFixup(p.Modified)
	fixed, err := fixup.Fixup()
	if err != nil {
		return nil, fmt.Errorf("branch fixup: %w", err)
	}
	emitter := NewInsnEmitter(len(fixed))
	if _, err = emitter.EmitAll(fixed); err != nil {
		return nil, fmt.Errorf("emit: %w", err)
	}
	return emitter.Bytes(), nil
}

// GetChanges returns the list of modifications made.
func (p *Patcher) GetChanges() []PatchChange { return p.Changes }

// Summary returns a human-readable summary of all changes.
func (p *Patcher) Summary() string {
	if len(p.Changes) == 0 {
		return "no changes"
	}
	var sb strings.Builder
	for _, c := range p.Changes {
		fmt.Fprintf(&sb, "[%s] pc=0x%x..0x%x reason=%s\n", c.Type, c.StartPC, c.EndPC, c.Reason)
	}
	return sb.String()
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// findModifiedIndex finds the index in Modified by PC offset.
func (p *Patcher) findModifiedIndex(pc uint32) int {
	for i, insn := range p.Modified {
		if insn.Offset == pc {
			return i
		}
	}
	return -1
}

func (p *Patcher) injectReturnConst(val int16) error {
	p.Modified = []RawInsn{
		{Op: 0x12, Format: Fmt11n, Regs: [3]uint16{0}, Imm: int64(val), Size: 1, Offset: 0},
		{Op: 0x0F, Format: Fmt11x, Regs: [3]uint16{0}, Size: 1, Offset: 2},
	}
	p.record("replace", 0, uint32(len(p.Original)), fmt.Sprintf("return_const_%d", val))
	return nil
}

func (p *Patcher) record(typ string, start, end uint32, reason string) {
	p.Changes = append(p.Changes, PatchChange{Type: typ, StartPC: start, EndPC: end, Reason: reason})
}

func nopInsn(offset uint32) RawInsn {
	return RawInsn{Op: 0x00, Format: Fmt10x, Size: 1, Offset: offset}
}
