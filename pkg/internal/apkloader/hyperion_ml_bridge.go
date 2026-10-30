package apkloader

import (
	"fmt"
	"strings"
)

// PatchType identifies the type of patch operation.
type PatchType int

const (
	PatchNop PatchType = iota
	PatchReturnTrue
	PatchReturnFalse
	PatchReturnVoid
	PatchReturnMaxInt
	PatchConditionInvert
	PatchInjectAt
	PatchBranchTarget
	PatchStringConst
	PatchBypassSSLAt
	PatchBypassSubscription
	PatchBypassLicense
	PatchBypassRootDetection
	PatchForceFeature
	PatchRedirectURL
	PatchSoftGuardTrue
	PatchSoftGuardFalse
	PatchSoftGuardVoid
	PatchBypassPayment
	PatchBypassRegistration
	PatchBypassAntiTamper
	PatchBypassEmulator
	PatchNopMethod
	PatchPrivateServerURL
)

// PatchOp is a single patch operation.
type PatchOp struct {
	Type   PatchType
	Start  uint32
	End    uint32
	Target uint32
	Data   []RawInsn
	Idx    uint32 // string/method ref index for redirect ops
}

// PatchPlan is the normalized patch description from ML layer.
type PatchPlan struct {
	Method string
	Ops    []PatchOp
}

// MLPatchBridge executes PatchPlan via Hyperion Patcher.
type MLPatchBridge struct {
	Parser *DEXParser
}

func NewMLPatchBridge(parser *DEXParser) *MLPatchBridge {
	return &MLPatchBridge{Parser: parser}
}

// ExecuteResult holds the output of Execute including analysis and validation.
type ExecuteResult struct {
	Bytecode   []byte
	Profile    MethodProfile
	Strategy   SafePatchStrategy
	Validation ValidationResult
}

// Execute applies a PatchPlan to the DEX.
// Automatically analyzes the method, upgrades hard-replace ops to soft-guard
// for complex methods, and validates the result before returning.
func (b *MLPatchBridge) Execute(plan *PatchPlan) (*ExecuteResult, error) {
	method := b.findEncodedMethod(plan.Method)
	if method == nil {
		return nil, fmt.Errorf("method not found: %s", plan.Method)
	}

	// Return-type guard: boolean/int stubs on reference-returning methods
	// produce invalid bytecode (int returned where an object is expected),
	// which fails DEX verification at class load. Refuse loudly instead.
	if err := checkReturnCompatibility(method, plan); err != nil {
		return nil, err
	}

	insns, err := b.decodeMethod(method)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	profile := Analyze(insns, method.Code)
	strategy := RecommendStrategy(profile)

	if strategy == StrategyUnsafe {
		return nil, fmt.Errorf("method %s is unsafe to patch: %s", plan.Method, profile.Complexity)
	}

	patcher := NewPatcher(insns)
	for i, op := range plan.Ops {
		effective := b.effectiveOp(op, strategy)
		if err := b.applyOp(patcher, &effective); err != nil {
			return nil, fmt.Errorf("op[%d] %v: %w", i, op.Type, err)
		}
	}

	code, vres, err := patcher.BuildValidated()
	if err != nil {
		return nil, fmt.Errorf("build: %w (validation: %v)", err, vres.Errors)
	}

	return &ExecuteResult{
		Bytecode:   code,
		Profile:    profile,
		Strategy:   strategy,
		Validation: vres,
	}, nil
}

// ApplyInPlacePatch overwrites the original Dalvik bytecode with the patched version.
// This is ONLY possible if len(patched_bytes) <= len(original_bytes), which
// makes it a true "In-Place" patch (O(1) memory, zero allocation).
func (b *MLPatchBridge) ApplyInPlacePatch(plan *PatchPlan, result *ExecuteResult) error {
	method := b.findEncodedMethod(plan.Method)
	if method == nil {
		return fmt.Errorf("method not found: %s", plan.Method)
	}

	if method.CodeOff == 0 || method.Code == nil {
		return fmt.Errorf("method has no code")
	}

	newInsnsSize := uint32(len(result.Bytecode) / 2) // length in 16-bit code units
	oldInsnsSize := method.Code.InsnsSize

	if newInsnsSize > oldInsnsSize {
		return fmt.Errorf("patched code size (%d) exceeds original size (%d), in-place patch impossible without relocation", newInsnsSize, oldInsnsSize)
	}

	// Byte offset of the instruction array inside the DEX data section.
	// CodeItem Header: registers_size (2), ins_size (2), outs_size (2), tries_size (2), debug_info_off (4), insns_size (4) = 16 bytes.
	insnsByteOffset := method.CodeOff + 16

	// Overwrite the mapped memory directly
	for i := 0; i < len(result.Bytecode); i++ {
		b.Parser.data[insnsByteOffset+uint32(i)] = result.Bytecode[i]
	}

	// Pad the rest with 0x00 (nop) if the new code is smaller
	paddingBytes := (oldInsnsSize - newInsnsSize) * 2
	for i := uint32(0); i < paddingBytes; i++ {
		b.Parser.data[insnsByteOffset+uint32(len(result.Bytecode))+i] = 0x00
	}

	// Update the parsed CodeItem so further accesses see the new code
	for i := uint32(0); i < newInsnsSize; i++ {
		method.Code.Insns[i] = uint16(result.Bytecode[i*2]) | (uint16(result.Bytecode[i*2+1]) << 8)
	}
	for i := newInsnsSize; i < oldInsnsSize; i++ {
		method.Code.Insns[i] = 0x0000
	}

	return nil
}

// checkReturnCompatibility refuses stub ops whose emitted return instruction
// does not match the method's declared return type. Reference returns
// ("L…;", "[…") need return-object + null, wide needs return-wide; a plain
// const/4+return would fail DEX verification and crash the app at class load.
func checkReturnCompatibility(method *EncodedMethod, plan *PatchPlan) error {
	if method == nil {
		return nil
	}
	rt := strings.TrimSpace(method.ReturnType)
	isReference := strings.HasPrefix(rt, "L") || strings.HasPrefix(rt, "[")
	isWide := rt == "J" || rt == "D"
	for _, op := range plan.Ops {
		switch op.Type {
		case PatchReturnTrue, PatchReturnFalse,
			PatchBypassSubscription, PatchBypassLicense, PatchForceFeature,
			PatchBypassPayment, PatchBypassRegistration:
			if isReference || isWide || rt == "V" {
				return fmt.Errorf(
					"stub %d is incompatible with return type %s of %s; refusing to generate unverifiable bytecode",
					op.Type, rt, method.Name)
			}
		case PatchReturnVoid:
			if rt != "V" {
				return fmt.Errorf(
					"return-void stub incompatible with non-void return type %s of %s",
					rt, method.Name)
			}
		}
	}
	return nil
}

// ExecuteAndSplice applies a PatchPlan and returns the FULL DEX image with
// the patched method spliced in place. Unlike Execute (which yields only the
// method's instruction bytes), this result is safe to write back as the whole
// classes.dex file.
//
// Single return-semantics plans take the direct synthesis path (correct stubs
// for every return kind, immune to soft-guard validator gaps and in-place size
// limits). Everything else goes through the full Execute pipeline.
func (b *MLPatchBridge) ExecuteAndSplice(plan *PatchPlan) ([]byte, error) {
	if b == nil || b.Parser == nil || plan == nil {
		return nil, fmt.Errorf("DEX parser and patch plan are required")
	}
	method := b.findEncodedMethod(plan.Method)
	if method == nil {
		return nil, fmt.Errorf("method not found: %s", plan.Method)
	}
	if method.CodeOff == 0 || method.Code == nil {
		return nil, fmt.Errorf("method has no code")
	}

	// Determine whether this is a whole-method stub before changing the frame.
	// Growing a frame for a surgical plan would silently move its parameters.
	units, ok, err := trySynthesizeStub(method, plan, 0)
	if err != nil {
		return nil, err
	}
	if ok {
		if method.Name == "<init>" || method.Name == "<clinit>" || method.Code.TriesSize != 0 {
			return nil, fmt.Errorf("whole-method stub cannot preserve constructor or exception handling in %s", plan.Method)
		}
		if len(units) > int(method.Code.InsnsSize) {
			return nil, fmt.Errorf("stub size %d exceeds body %d", len(units), method.Code.InsnsSize)
		}
		scratch, err := ensureScratchLocal(b.Parser.data, method)
		if err != nil {
			return nil, err
		}
		units, _, err = trySynthesizeStub(method, plan, scratch)
		if err != nil {
			return nil, err
		}
		if err := b.spliceStub(method, units); err != nil {
			return nil, err
		}
		if err := finalizeDEX(b.Parser.data); err != nil {
			return nil, err
		}
		out := make([]byte, len(b.Parser.data))
		copy(out, b.Parser.data)
		return out, nil
	}

	result, err := b.Execute(plan)
	if err != nil {
		return nil, err
	}
	if err := b.ApplyInPlacePatch(plan, result); err != nil {
		return nil, err
	}
	if err := finalizeDEX(b.Parser.data); err != nil {
		return nil, err
	}
	out := make([]byte, len(b.Parser.data))
	copy(out, b.Parser.data)
	return out, nil
}

// effectiveOp upgrades a hard-replace op to soft-guard when the method is complex.
func (b *MLPatchBridge) effectiveOp(op PatchOp, strategy SafePatchStrategy) PatchOp {
	if strategy != StrategySoftGuard {
		return op
	}
	switch op.Type {
	case PatchReturnTrue, PatchBypassSubscription, PatchBypassLicense, PatchForceFeature,
		PatchBypassPayment, PatchBypassRegistration:
		op.Type = PatchSoftGuardTrue
	case PatchReturnFalse, PatchBypassEmulator:
		op.Type = PatchSoftGuardFalse
	case PatchReturnVoid, PatchNopMethod:
		op.Type = PatchSoftGuardVoid
	}
	return op
}

func (b *MLPatchBridge) applyOp(p *Patcher, op *PatchOp) error {
	switch op.Type {
	case PatchNop:
		return p.NopOutRange(op.Start, op.End)
	case PatchReturnTrue:
		return p.AlwaysReturnTrue()
	case PatchReturnFalse:
		return p.AlwaysReturnFalse()
	case PatchReturnVoid:
		return p.AlwaysReturnVoid()
	case PatchConditionInvert:
		return p.PatchConditionInvert()
	case PatchBranchTarget:
		return p.PatchBranch(op.Start, op.Target)
	case PatchInjectAt:
		return p.InjectAt(op.Start, op.Data)
	case PatchStringConst:
		return p.PatchStringConst(op.Start, op.Idx)
	case PatchBypassSSLAt:
		return p.BypassSSLPinningAt(op.Start)
	case PatchBypassSubscription:
		return p.BypassSubscriptionCheck()
	case PatchBypassLicense:
		return p.BypassLicenseCheck()
	case PatchBypassRootDetection:
		return p.BypassRootDetection(op.Start, op.End)
	case PatchForceFeature:
		return p.ForceFeatureEnabled()
	case PatchRedirectURL:
		return p.RedirectServerURL(op.Start, op.Idx)
	case PatchSoftGuardTrue:
		return p.GuardReturnTrue()
	case PatchSoftGuardFalse:
		return p.GuardReturnFalse()
	case PatchSoftGuardVoid:
		return p.GuardReturnVoid()
	case PatchBypassPayment:
		return p.BypassPaymentCheck()
	case PatchBypassRegistration:
		return p.BypassRegistrationCheck()
	case PatchBypassAntiTamper:
		return p.BypassAntiTamper(op.Start, op.End)
	case PatchBypassEmulator:
		return p.BypassEmulatorDetection()
	case PatchNopMethod:
		return p.NopOutMethod()
	case PatchPrivateServerURL:
		p.PatchPrivateServerURL(op.Start, op.Idx)
		return nil
	default:
		return fmt.Errorf("unknown patch type: %d", op.Type)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// METHOD LOOKUP
// ═══════════════════════════════════════════════════════════════════════════════

// findEncodedMethod finds an EncodedMethod by full descriptor.
// Accepts: "Lclass;->name(params)ret" or "Lclass;->name" (partial match).
func (b *MLPatchBridge) findEncodedMethod(descriptor string) *EncodedMethod {
	for _, cls := range b.Parser.GetClasses() {
		for _, m := range cls.DirectMethods {
			if matchDescriptor(cls.ClassName, m, descriptor) {
				return m
			}
		}
		for _, m := range cls.VirtualMethods {
			if matchDescriptor(cls.ClassName, m, descriptor) {
				return m
			}
		}
	}
	return nil
}

// matchDescriptor checks if an EncodedMethod matches the given descriptor.
// Supports full "Lclass;->name(params)ret" and partial "Lclass;->name".
func matchDescriptor(className string, m *EncodedMethod, descriptor string) bool {
	// Full descriptor match
	full := buildDescriptor(className, m)
	if full == descriptor {
		return true
	}
	// Partial: "Lclass;->name" without signature
	if !strings.Contains(descriptor, "(") {
		partial := className + "->" + m.Name
		return partial == descriptor
	}
	return false
}

func buildDescriptor(className string, m *EncodedMethod) string {
	if m == nil {
		return ""
	}
	return MethodDescriptor(className, m.Name, m.Parameters, m.ReturnType)
}

// decodeMethod decodes an EncodedMethod's CodeItem into RawInsn slice.
func (b *MLPatchBridge) decodeMethod(m *EncodedMethod) ([]RawInsn, error) {
	if m.Code == nil {
		return nil, fmt.Errorf("method %s has no code (abstract/native)", m.Name)
	}
	return DecodeMethodIR(m.Code.Insns, nil), nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIRECT STUB SYNTHESIS — fast path for simple return stubs
//
// The full Execute pipeline (analyze → strategy → soft-guard → branch fixup)
// can reject valid targets (soft-guard validator gaps) or produce code larger
// than the original body (in-place size limit). For plans that are a single
// return-semantics op we bypass the pipeline entirely and synthesize a minimal
// register-safe stub matching the declared return type:
//
//	Z/I/S/B/C/F  → const/4 vN,(0|1) ; return vN      (MaxInt → const 0x7fffffff)
//	J/D          → const-wide/16 vN,(0|1) ; return-wide
//	L…; / […]    → const/4 vN,0 ; return-object vN   (null)
//	V            → return-void
//
// The scratch register is guaranteed to be a local: when the frame has zero
// locals the CodeItem's registers_size is grown by one or two slots in place.
// ═══════════════════════════════════════════════════════════════════════════════

const accStatic = 0x0008

// paramRegisterCount counts frame slots consumed by parameters (wide = 2).
func paramRegisterCount(method *EncodedMethod) int {
	n := 0
	if method.AccessFlags&accStatic == 0 {
		n++ // this
	}
	for _, p := range method.Parameters {
		if p == "J" || p == "D" {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// ensureScratchLocal reserves an encodable local (a pair for J/D) for a
// whole-method stub. Surgical plans must never grow the parameter window.
func ensureScratchLocal(data []byte, method *EncodedMethod) (uint16, error) {
	if method == nil || method.Code == nil || method.CodeOff == 0 {
		return 0, fmt.Errorf("method has no code")
	}
	if uint64(method.CodeOff)+16 > uint64(len(data)) {
		return 0, fmt.Errorf("method %s code header is outside DEX", method.Name)
	}
	if method.ReturnType == "V" {
		return 0, nil
	}
	width := uint16(1)
	if method.ReturnType == "J" || method.ReturnType == "D" {
		width = 2
	}
	paramCount := paramRegisterCount(method)
	if paramCount > 0xFFFF {
		return 0, fmt.Errorf("method %s: parameter register space exhausted", method.Name)
	}
	params := uint16(paramCount)
	total := method.Code.RegistersSize
	if params > total {
		return 0, fmt.Errorf("method %s: registers_size %d < param regs %d", method.Name, total, params)
	}
	locals := total - params
	if locals < width {
		growth := width - locals
		if uint32(total)+uint32(growth) > 0xFFFF {
			return 0, fmt.Errorf("method %s: register space exhausted", method.Name)
		}
		total += growth
		putU16(data, method.CodeOff, total)
		method.Code.RegistersSize = total
		locals = width
	}
	// Keep const/4 encodable and avoid making a short body need a wider const.
	scratch := locals - width
	if scratch > 15 {
		scratch = 15
	}
	return scratch, nil
}

func putU16(data []byte, off uint32, v uint16) {
	data[off] = byte(v)
	data[off+1] = byte(v >> 8)
}

// stubUnitsFor builds instruction words for a typed return stub targeting the
// given scratch register. Dalvik code units are little-endian: the OPCODE is
// always the LOW byte, so every word is built as op | reg<<8 (+operand bits).
func stubUnitsFor(returnType string, pt PatchType, scratch uint16) ([]uint16, error) {
	if scratch > 255 {
		return nil, fmt.Errorf("stub register v%d exceeds the return instruction limit v255", scratch)
	}
	aaWord := func(op uint8) uint16 { return uint16(op) | scratch<<8 } // 11x/AA-form
	constantReturn := func(value int16, returnOp uint8) []uint16 {
		if scratch <= 15 {
			return []uint16{0x0012 | scratch<<8 | uint16(value&0xF)<<12, aaWord(returnOp)}
		}
		return []uint16{aaWord(0x13), uint16(value), aaWord(returnOp)}
	}

	rt := strings.TrimSpace(returnType)
	switch rt {
	case "V":
		// return-void is 10x format: no register field, upper byte must be 0.
		return []uint16{0x000E}, nil
	case "J", "D":
		v := int16(0)
		if pt == PatchReturnTrue {
			v = 1
		}
		return []uint16{aaWord(0x16), uint16(v), aaWord(0x10)}, nil // const-wide/16 ; return-wide
	}
	if strings.HasPrefix(rt, "L") || strings.HasPrefix(rt, "[") {
		// null reference regardless of true/false semantics
		return constantReturn(0, 0x11), nil
	}
	// 32-bit primitives (Z I S B C F)
	switch pt {
	case PatchReturnTrue:
		return constantReturn(1, 0x0F), nil
	case PatchReturnFalse:
		return constantReturn(0, 0x0F), nil
	case PatchReturnMaxInt:
		if rt == "Z" {
			return constantReturn(1, 0x0F), nil
		}
		// const vN, 0x7fffffff (31i: [op|AA<<8, lo, hi]) ; return vN
		return []uint16{aaWord(0x14), 0xFFFF, 0x7FFF, aaWord(0x0F)}, nil
	}
	return nil, fmt.Errorf("stub synthesis unsupported for op %d on %s", pt, returnType)
}

// trySynthesizeStub reports whether the plan is a single return-stub op and,
// if so, produces its instruction units. ok=false means the caller should use
// the full Execute pipeline.
func trySynthesizeStub(method *EncodedMethod, plan *PatchPlan, scratch uint16) (units []uint16, ok bool, err error) {
	if len(plan.Ops) != 1 || method == nil {
		return nil, false, nil
	}
	pt := plan.Ops[0].Type
	switch pt {
	case PatchReturnTrue, PatchReturnFalse, PatchReturnVoid, PatchReturnMaxInt,
		PatchBypassSubscription, PatchBypassLicense, PatchForceFeature,
		PatchBypassPayment, PatchBypassRegistration:
		// map alias ops to their boolean semantics
		mapped := pt
		switch pt {
		case PatchBypassSubscription, PatchBypassLicense, PatchForceFeature,
			PatchBypassPayment, PatchBypassRegistration:
			mapped = PatchReturnTrue
		}
		u, err := stubUnitsFor(method.ReturnType, mapped, scratch)
		if err != nil {
			return nil, true, err
		}
		return u, true, nil
	}
	return nil, false, nil
}

// spliceStub writes units over the method body, nop-pads the remainder and
// mirrors the change into the parsed CodeItem.
func (b *MLPatchBridge) spliceStub(method *EncodedMethod, units []uint16) error {
	if len(units) > int(method.Code.InsnsSize) {
		return fmt.Errorf("stub size %d exceeds body %d", len(units), method.Code.InsnsSize)
	}
	off := method.CodeOff + 16
	for i, u := range units {
		putU16(b.Parser.data, off+uint32(i*2), u)
	}
	for i := len(units); i < int(method.Code.InsnsSize); i++ {
		putU16(b.Parser.data, off+uint32(i*2), 0x0000)
	}
	copy(method.Code.Insns[:len(units)], units)
	for i := len(units); i < len(method.Code.Insns); i++ {
		method.Code.Insns[i] = 0
	}
	// Old debug entries refer to instructions and registers removed by the stub.
	clear(b.Parser.data[method.CodeOff+8 : method.CodeOff+12])
	method.Code.DebugInfoOff = 0
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH PLAN BUILDER
// ═══════════════════════════════════════════════════════════════════════════════

type PatchPlanBuilder struct {
	method string
	ops    []PatchOp
}

func NewPatchPlanBuilder(method string) *PatchPlanBuilder {
	return &PatchPlanBuilder{method: method}
}

func (b *PatchPlanBuilder) NopOut(start, end uint32) *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchNop, Start: start, End: end})
}
func (b *PatchPlanBuilder) ReturnTrue() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchReturnTrue})
}
func (b *PatchPlanBuilder) ReturnFalse() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchReturnFalse})
}
func (b *PatchPlanBuilder) ReturnVoid() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchReturnVoid})
}
func (b *PatchPlanBuilder) ReturnMaxInt() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchReturnMaxInt})
}
func (b *PatchPlanBuilder) InvertCondition() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchConditionInvert})
}
func (b *PatchPlanBuilder) Inject(atPC uint32, insns []RawInsn) *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchInjectAt, Start: atPC, Data: insns})
}
func (b *PatchPlanBuilder) BypassSSL(pc uint32) *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchBypassSSLAt, Start: pc})
}
func (b *PatchPlanBuilder) BypassSubscription() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchBypassSubscription})
}
func (b *PatchPlanBuilder) BypassLicense() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchBypassLicense})
}
func (b *PatchPlanBuilder) BypassRoot(start, end uint32) *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchBypassRootDetection, Start: start, End: end})
}
func (b *PatchPlanBuilder) ForceFeature() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchForceFeature})
}
func (b *PatchPlanBuilder) RedirectURL(pc uint32, newIdx uint32) *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchRedirectURL, Start: pc, Idx: newIdx})
}
func (b *PatchPlanBuilder) BypassPayment() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchBypassPayment})
}
func (b *PatchPlanBuilder) BypassRegistration() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchBypassRegistration})
}
func (b *PatchPlanBuilder) BypassAntiTamper(start, end uint32) *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchBypassAntiTamper, Start: start, End: end})
}
func (b *PatchPlanBuilder) BypassEmulator() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchBypassEmulator})
}

// BypassDebugDetection patches a debug-detection method to always report
// no debugger attached (equivalent to ReturnFalse on a boolean method).
func (b *PatchPlanBuilder) BypassDebugDetection() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchReturnFalse})
}
func (b *PatchPlanBuilder) NopMethod() *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchNopMethod})
}
func (b *PatchPlanBuilder) PrivateServerURL(oldIdx, newIdx uint32) *PatchPlanBuilder {
	return b.add(PatchOp{Type: PatchPrivateServerURL, Start: oldIdx, Idx: newIdx})
}
func (b *PatchPlanBuilder) Build() *PatchPlan {
	return &PatchPlan{Method: b.method, Ops: b.ops}
}
func (b *PatchPlanBuilder) add(op PatchOp) *PatchPlanBuilder {
	b.ops = append(b.ops, op)
	return b
}
