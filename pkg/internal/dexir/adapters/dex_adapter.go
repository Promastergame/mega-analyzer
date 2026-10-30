// Package adapters hosts the dexir input adapters (binary DEX and
// legacy smali text). They live outside the dexir core so that dexir
// stays dependency-free: apkloader/parser/types transitively import
// cfg, and cfg imports dexir — keeping the adapters in dexir would
// create an import cycle.
package adapters

import (
	"fmt"

	"mega-analyzer/pkg/internal/apkloader"
	. "mega-analyzer/pkg/internal/dexir"
)

// ═══════════════════════════════════════════════════════════════
// DEX ADAPTER — binary DEX → typed IR (no text round-trip)
// ═══════════════════════════════════════════════════════════════
//
// Converts apkloader's parsed DEX structures directly into the typed
// IR. Instruction decoding reuses apkloader's zero-allocation
// DecodeMethodIR; references are resolved through the parser's
// id-tables. Strings may alias mmap'd DEX data — keep the parser
// alive for the IR's lifetime.

// FromDEX converts every class in a parsed DEX file to typed IR.
// Classes without a name are skipped.
func FromDEX(p *apkloader.DEXParser) []*Class {
	if p == nil {
		return nil
	}
	classes := p.GetClasses()
	out := make([]*Class, 0, len(classes))
	for _, cd := range classes {
		if cd == nil {
			continue
		}
		out = append(out, ClassFromDEX(p, cd))
	}
	return out
}

// ClassFromDEX converts a single class definition.
func ClassFromDEX(p *apkloader.DEXParser, cd *apkloader.ClassDef) *Class {
	if p == nil || cd == nil {
		return nil
	}

	cls := &Class{
		Descriptor:  cd.ClassName,
		SuperClass:  cd.SuperClass,
		Interfaces:  cd.Interfaces,
		SourceFile:  cd.SourceFile,
		AccessFlags: cd.AccessFlags,
		Fields:      make([]*Field, 0, len(cd.StaticFields)+len(cd.InstanceFields)),
	}

	for _, f := range cd.StaticFields {
		cls.Fields = append(cls.Fields, &Field{
			Name:        f.Name,
			Type:        f.TypeName,
			AccessFlags: f.AccessFlags,
			IsStatic:    true,
		})
	}
	for _, f := range cd.InstanceFields {
		cls.Fields = append(cls.Fields, &Field{
			Name:        f.Name,
			Type:        f.TypeName,
			AccessFlags: f.AccessFlags,
		})
	}

	methodCount := len(cd.DirectMethods) + len(cd.VirtualMethods)
	cls.Methods = make([]*Method, 0, methodCount)
	for _, em := range cd.DirectMethods {
		cls.Methods = append(cls.Methods, MethodFromDEX(p, em))
	}
	for _, em := range cd.VirtualMethods {
		cls.Methods = append(cls.Methods, MethodFromDEX(p, em))
	}

	// Annotation presence: the parser exposes the annotations offset;
	// full encoded-annotation decoding lands in a later task. Record
	// presence when the class carries an annotations directory.
	if cd.AnnotationsOff != 0 {
		cls.Annotations = []*Annotation{{Type: "<class-annotations-present>"}}
	}

	return cls
}

// MethodFromDEX converts one encoded method, decoding its bytecode via
// the zero-allocation structural decoder and resolving all references.
func MethodFromDEX(p *apkloader.DEXParser, em *apkloader.EncodedMethod) *Method {
	if em == nil {
		return nil
	}

	m := &Method{
		Name:        em.Name,
		AccessFlags: em.AccessFlags,
		IsStatic:    em.AccessFlags&0x0008 != 0,
		ReturnType:  em.ReturnType,
		Params:      em.Parameters,
	}
	if m.ReturnType == "" {
		m.ReturnType = "V"
	}

	code := p.GetMethodCode(em) // triggers lazy loading when needed
	if code == nil {
		m.RegistersSize, m.Locals, m.InsSize, m.OutsSize = -1, -1, 0, 0
		return m
	}

	m.RegistersSize = int(code.RegistersSize)
	m.Locals = int(code.RegistersSize) - int(code.InsSize)
	m.InsSize = int(code.InsSize)
	m.OutsSize = int(code.OutsSize)
	m.ParamRegisters = paramRegisters(code.RegistersSize, code.InsSize, em.Parameters)

	raw := apkloader.DecodeMethodIR(code.Insns, nil)

	// Pass 1: typed instructions.
	insns := make([]*Instruction, 0, len(raw))
	for i := range raw {
		ins := insnFromRaw(p, &raw[i], code.Insns)
		if ins != nil {
			insns = append(insns, ins)
		}
	}
	m.Instructions = insns

	// Pass 2: try/catch ranges + synthesized labels.
	buildTryCatchesAndLabels(m, code, insns)

	return m
}

// paramRegisters computes the starting v-register of each parameter.
// Parameter registers occupy the top of the frame: p0 starts at
// registersSize - insSize.
func paramRegisters(regsSize, insSize uint16, params []string) []int32 {
	if insSize == 0 {
		return nil
	}
	out := make([]int32, 0, len(params)+1)
	start := int32(regsSize) - int32(insSize)
	r := start
	// The caller decides whether a 'this' slot exists by counting
	// insSize against declared params; we emit one entry per consumed
	// register block matching the parameter list, plus a leading slot
	// when insSize exceeds the declared width (the implicit 'this').
	declared := 0
	for _, pt := range params {
		if pt == "J" || pt == "D" {
			declared += 2
		} else {
			declared++
		}
	}
	if int(insSize) > declared {
		out = append(out, r) // implicit 'this'
		r++
	}
	for _, pt := range params {
		out = append(out, r)
		if pt == "J" || pt == "D" {
			r += 2
		} else {
			r++
		}
	}
	return out
}

// insnFromRaw converts one RawInsn to a typed Instruction.
func insnFromRaw(p *apkloader.DEXParser, raw *apkloader.RawInsn, code []uint16) *Instruction {
	if raw.Flags&apkloader.FlagPayload != 0 && raw.Op == 0x00 {
		// Payload pseudo-instruction: decode the embedded table.
		return payloadInsn(raw, code)
	}

	ins := &Instruction{
		Offset:       raw.Offset,
		Size:         raw.Size,
		Op:           Opcode(raw.Op),
		Dst:          NoRegister,
		BranchOffset: -1,
		BranchTarget: -1,
	}

	assignRegisters(ins, raw, code)

	// Immediate values.
	switch raw.Format {
	case apkloader.Fmt11n, apkloader.Fmt21s, apkloader.Fmt21h,
		apkloader.Fmt31i, apkloader.Fmt51l, apkloader.Fmt22b,
		apkloader.Fmt22s:
		ins.HasImm = true
		ins.Imm = raw.Imm
	}
	// fill-array-data: immediate is the payload offset.
	if raw.Op == 0x26 {
		ins.HasImm = true
		ins.Imm = raw.Imm
		ins.BranchOffset = int32(raw.Imm)
		ins.BranchTarget = int32(raw.Offset) + int32(raw.Imm)
		if ins.BranchTarget < 0 {
			ins.BranchTarget = 0
		}
		target := int64(raw.Offset) + raw.Imm
		if target >= 0 && target < int64(len(code)) {
			ins.Payload = decodePayloadTable(code, uint32(target))
		}
	}

	// Resolved references.
	switch raw.RefKind {
	case apkloader.RefString:
		ins.HasStr = true
		ins.Str = p.GetStringByIndex(raw.RefIdx)
	case apkloader.RefType:
		ins.Type = p.GetTypeByIndex(raw.RefIdx)
	case apkloader.RefField:
		if f := p.GetFieldByID(raw.RefIdx); f != nil {
			ins.Field = &FieldRef{Class: f.ClassName, Name: f.FieldName, Type: f.TypeName}
		}
	case apkloader.RefMethod:
		if mm := p.GetMethodByID(raw.RefIdx); mm != nil {
			ins.Method = &MethodRef{
				Class:      mm.ClassName,
				Name:       mm.MethodName,
				ReturnType: mm.ReturnType,
				Params:     mm.Parameters,
				Proto:      buildProtoFromParts(mm.Parameters, mm.ReturnType),
			}
		}
	}

	// Branches.
	if raw.Flags&apkloader.FlagBranch != 0 && raw.Op != 0x2B && raw.Op != 0x2C {
		ins.BranchOffset = int32(raw.Imm)
		ins.BranchTarget = int32(raw.Offset) + int32(raw.Imm)
		if ins.BranchTarget < 0 {
			ins.BranchTarget = 0
		}
	}

	// Switch instructions: resolve the payload table (keys+targets).
	// Targets stay relative to the switch instruction, exactly as
	// encoded; use PayloadTargetAbs for absolute offsets.
	if raw.Op == 0x2B || raw.Op == 0x2C {
		ins.HasImm = true
		ins.Imm = raw.Imm
		ins.BranchOffset = int32(raw.Imm)
		ins.BranchTarget = int32(raw.Offset) + int32(raw.Imm)
		if ins.BranchTarget < 0 {
			ins.BranchTarget = 0
		}
		target := int64(raw.Offset) + raw.Imm
		if target >= 0 && target < int64(len(code)) {
			ins.Payload = decodePayloadTable(code, uint32(target))
		}
	}

	return ins
}

// assignRegisters fills Dst/Srcs according to the instruction format.
func assignRegisters(ins *Instruction, raw *apkloader.RawInsn, code []uint16) {
	op := raw.Op
	switch {
	case raw.Flags&apkloader.FlagInvoke != 0:
		// invoke-* and filled-new-array: all registers are arguments.
		regs := apkloader.DecodeInvokeRegs(raw, code)
		if regs == nil && raw.RegCount > 0 && raw.RegCount <= 3 {
			regs = make([]uint16, 0, raw.RegCount)
			for i := uint8(0); i < raw.RegCount; i++ {
				regs = append(regs, raw.Regs[i])
			}
		}
		ins.Srcs = make([]int32, len(regs))
		for i, r := range regs {
			ins.Srcs[i] = int32(r)
		}

	case op >= 0x01 && op <= 0x09:
		// move family: vA = vB
		if raw.RegCount >= 2 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[1])}
		}

	case op >= 0x0A && op <= 0x0D:
		// move-result / move-exception: vAA
		if raw.RegCount >= 1 {
			ins.Dst = int32(raw.Regs[0])
		}

	case op >= 0x0F && op <= 0x11, op == 0x27:
		// return vAA / throw vAA
		if raw.RegCount >= 1 {
			ins.Srcs = []int32{int32(raw.Regs[0])}
		}

	case op >= 0x12 && op <= 0x1C, op == 0x22:
		// const family, const-class, new-instance: vAA = literal/ref
		if raw.RegCount >= 1 {
			ins.Dst = int32(raw.Regs[0])
		}

	case op == 0x1D || op == 0x1E:
		// monitor-enter/exit: source register
		if raw.RegCount >= 1 {
			ins.Srcs = []int32{int32(raw.Regs[0])}
		}

	case op == 0x1F:
		// check-cast vAA: both reads and writes vAA
		if raw.RegCount >= 1 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[0])}
		}

	case op == 0x20:
		// instance-of vA, vB
		if raw.RegCount >= 2 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[1])}
		}

	case op == 0x21:
		// array-length vA, vB
		if raw.RegCount >= 2 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[1])}
		}

	case op == 0x23:
		// new-array vA, vB
		if raw.RegCount >= 2 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[1])}
		}

	case op >= 0x28 && op <= 0x2A:
		// goto — no registers

	case op == 0x2B || op == 0x2C:
		// switch vAA
		if raw.RegCount >= 1 {
			ins.Srcs = []int32{int32(raw.Regs[0])}
		}

	case op >= 0x2D && op <= 0x31:
		// cmp: vAA = vBB cmp vCC
		if raw.RegCount >= 3 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[1]), int32(raw.Regs[2])}
		}

	case op >= 0x32 && op <= 0x37:
		// if vA, vB
		if raw.RegCount >= 2 {
			ins.Srcs = []int32{int32(raw.Regs[0]), int32(raw.Regs[1])}
		}

	case op >= 0x38 && op <= 0x3D:
		// if vAA (vs zero)
		if raw.RegCount >= 1 {
			ins.Srcs = []int32{int32(raw.Regs[0])}
		}

	case op >= 0x44 && op <= 0x51:
		// aget/aput: vAA, vBB, vCC
		if raw.RegCount >= 3 {
			if op <= 0x4A {
				ins.Dst = int32(raw.Regs[0])
				ins.Srcs = []int32{int32(raw.Regs[1]), int32(raw.Regs[2])}
			} else {
				ins.Srcs = []int32{int32(raw.Regs[0]), int32(raw.Regs[1]), int32(raw.Regs[2])}
			}
		}

	case op >= 0x52 && op <= 0x58:
		// iget: vA, vB, field
		if raw.RegCount >= 2 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[1])}
		}

	case op >= 0x59 && op <= 0x5F:
		// iput: vA, vB
		if raw.RegCount >= 2 {
			ins.Srcs = []int32{int32(raw.Regs[0]), int32(raw.Regs[1])}
		}

	case op >= 0x60 && op <= 0x66:
		// sget: vAA
		if raw.RegCount >= 1 {
			ins.Dst = int32(raw.Regs[0])
		}

	case op >= 0x67 && op <= 0x6D:
		// sput: vAA
		if raw.RegCount >= 1 {
			ins.Srcs = []int32{int32(raw.Regs[0])}
		}

	case op >= 0x7B && op <= 0x8F:
		// unary ops: vA = op vB
		if raw.RegCount >= 2 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[1])}
		}

	case op >= 0x90 && op <= 0xAF:
		// binop/23x: vAA = vBB op vCC
		if raw.RegCount >= 3 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[1]), int32(raw.Regs[2])}
		}

	case op >= 0xB0 && op <= 0xCF:
		// binop/2addr: vA = vA op vB
		if raw.RegCount >= 2 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[0]), int32(raw.Regs[1])}
		}

	case op >= 0xD0 && op <= 0xD7:
		// binop/lit16: vA, vB, #+CCCC
		if raw.RegCount >= 2 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[1])}
			ins.HasImm = true
			ins.Imm = raw.Imm
		}

	case op >= 0xD8 && op <= 0xE2:
		// binop/lit8: vAA, vBB, #+CC
		if raw.RegCount >= 2 {
			ins.Dst = int32(raw.Regs[0])
			ins.Srcs = []int32{int32(raw.Regs[1])}
			ins.HasImm = true
			ins.Imm = raw.Imm
		}

	case op == 0x26:
		// fill-array-data vAA
		if raw.RegCount >= 1 {
			ins.Srcs = []int32{int32(raw.Regs[0])}
		}
	}
}

// payloadInsn decodes a payload pseudo-instruction into a typed
// Instruction carrying the table.
func payloadInsn(raw *apkloader.RawInsn, code []uint16) *Instruction {
	ins := &Instruction{
		Offset:       raw.Offset,
		Size:         raw.Size,
		Dst:          NoRegister,
		BranchOffset: -1,
		BranchTarget: -1,
	}
	if raw.Offset < uint32(len(code)) {
		ident := code[raw.Offset]
		switch ident {
		case 0x0100:
			ins.Op = OpPackedSwitchPayload
		case 0x0200:
			ins.Op = OpSparseSwitchPayload
		case 0x0300:
			ins.Op = OpFillArrayDataPayload
		default:
			ins.Op = OpNop
			return ins
		}
		ins.Payload = decodePayloadTable(code, raw.Offset)
	}
	return ins
}

// decodePayloadTable decodes a payload table at pos without copying the
// code slice (array-data values are sub-sliced from the code words).
func decodePayloadTable(code []uint16, pos uint32) *Payload {
	n := uint32(len(code))
	if pos+2 > n {
		return nil
	}
	ident := code[pos]

	switch ident {
	case 0x0100: // packed-switch: ident, size(u16), firstKey(i32), targets[size](i32)
		if pos+4 > n {
			return nil
		}
		size := uint32(code[pos+1])
		firstKey := int32(uint32(code[pos+2]) | uint32(code[pos+3])<<16)
		if pos+4+size*2 > n {
			return nil
		}
		targets := make([]int32, size)
		for i := uint32(0); i < size; i++ {
			base := pos + 4 + i*2
			targets[i] = int32(uint32(code[base]) | uint32(code[base+1])<<16)
		}
		return &Payload{Kind: PayloadPackedSwitch, FirstKey: firstKey, Targets: targets}

	case 0x0200: // sparse-switch: ident, size(u16), keys[size](i32), targets[size](i32)
		if pos+2 > n {
			return nil
		}
		size := uint32(code[pos+1])
		if pos+2+size*4 > n {
			return nil
		}
		keys := make([]int32, size)
		targets := make([]int32, size)
		for i := uint32(0); i < size; i++ {
			kb := pos + 2 + i*2
			keys[i] = int32(uint32(code[kb]) | uint32(code[kb+1])<<16)
			tb := pos + 2 + size*2 + i*2
			targets[i] = int32(uint32(code[tb]) | uint32(code[tb+1])<<16)
		}
		return &Payload{Kind: PayloadSparseSwitch, Keys: keys, Targets: targets}

	case 0x0300: // fill-array-data: ident, elemWidth(u16), elemCount(u32), data
		if pos+4 > n {
			return nil
		}
		elemWidth := int(code[pos+1])
		elemCount := uint32(code[pos+2]) | uint32(code[pos+3])<<16
		if elemWidth == 0 || elemWidth > 8 {
			return nil
		}
		totalBytes := uint64(elemCount) * uint64(elemWidth)
		dataWords := (totalBytes + 1) / 2
		if pos+4+uint32(dataWords) > n {
			return nil
		}
		values := make([]byte, 0, totalBytes)
		for i := uint32(0); i < uint32(dataWords); i++ {
			w := code[pos+4+i]
			values = append(values, byte(w), byte(w>>8))
		}
		values = values[:totalBytes]
		return &Payload{Kind: PayloadArrayData, ElemWidth: elemWidth, Values: values}
	}
	return nil
}

// buildTryCatchesAndLabels fills Method.TryCatches and Labels, then
// resolves BranchLabel for every branch instruction.
func buildTryCatchesAndLabels(m *Method, code *apkloader.CodeItem, insns []*Instruction) {
	labelNames := map[uint32][]string{}

	for i, t := range code.Tries {
		start := t.StartAddr
		end := start + uint32(t.InsnCount)
		labelNames[start] = append(labelNames[start], fmt.Sprintf("try_start_%d", i))
		labelNames[end] = append(labelNames[end], fmt.Sprintf("try_end_%d", i))

		for _, h := range t.CatchHandlers {
			tc := &TryCatch{
				StartOffset: start,
				EndOffset:   end,
				Type:        h.TypeName,
				StartLabel:  fmt.Sprintf("try_start_%d", i),
				EndLabel:    fmt.Sprintf("try_end_%d", i),
			}
			handlerAddr := h.HandlerAddr
			if h.HasCatchAll {
				tc.Type = ""
				labelNames[h.HandlerAddr] = append(labelNames[h.HandlerAddr], fmt.Sprintf("catchall_%d", i))
				tc.HandlerLabel = fmt.Sprintf("catchall_%d", i)
			} else {
				labelNames[h.HandlerAddr] = append(labelNames[h.HandlerAddr], fmt.Sprintf("catch_%d_%x", i, h.HandlerAddr))
				tc.HandlerLabel = fmt.Sprintf("catch_%d_%x", i, h.HandlerAddr)
			}
			tc.HandlerOffset = handlerAddr
			m.TryCatches = append(m.TryCatches, tc)
		}
	}

	// Branch targets become labels.
	for _, ins := range insns {
		targets := branchTargetsOf(ins)
		for _, tgt := range targets {
			if tgt >= 0 && len(labelNames[uint32(tgt)]) == 0 {
				labelNames[uint32(tgt)] = []string{fmt.Sprintf("lbl_%x", tgt)}
			}
		}
	}
	// Materialize label list (ordered by offset).
	if len(labelNames) > 0 {
		ordered := make([]uint32, 0, len(labelNames))
		for off := range labelNames {
			ordered = append(ordered, off)
		}
		sortU32(ordered)
		for _, off := range ordered {
			for _, name := range labelNames[off] {
				m.Labels = append(m.Labels, &Label{Name: name, Offset: off})
			}
		}
	}

	// Wire branch labels.
	for _, ins := range insns {
		switch ins.Op {
		case OpPackedSwitch, OpSparseSwitch:
			if ins.Payload != nil {
				ins.Payload.TargetLabels = make([]string, len(ins.Payload.Targets))
				for i, tgt := range ins.Payload.Targets {
					abs := ins.Offset + uint32(tgt)
					if names := labelNames[abs]; len(names) > 0 {
						ins.Payload.TargetLabels[i] = names[0]
					}
				}
			}
		default:
			if ins.BranchTarget >= 0 {
				if names := labelNames[uint32(ins.BranchTarget)]; len(names) > 0 {
					ins.BranchLabel = names[0]
				}
			}
		}
	}
}

// branchTargetsOf returns the absolute branch target offsets of an
// instruction (switch payloads contribute every case target).
func branchTargetsOf(ins *Instruction) []int32 {
	if ins.Op == OpPackedSwitch || ins.Op == OpSparseSwitch {
		if ins.Payload != nil {
			out := make([]int32, len(ins.Payload.Targets))
			for i, t := range ins.Payload.Targets {
				out[i] = t + int32(ins.Offset)
			}
			return out
		}
		return nil
	}
	if ins.BranchTarget >= 0 {
		return []int32{ins.BranchTarget}
	}
	return nil
}

// buildProtoFromParts renders "(params)return".
func buildProtoFromParts(params []string, ret string) string {
	b := make([]byte, 0, 16)
	b = append(b, '(')
	for _, p := range params {
		b = append(b, p...)
	}
	b = append(b, ')')
	if ret == "" {
		ret = "V"
	}
	b = append(b, ret...)
	return string(b)
}

// sortU32 sorts a small slice ascending (insertion sort — label maps
// are small; avoids importing sort for a hot path).
func sortU32(a []uint32) {
	for i := 1; i < len(a); i++ {
		v := a[i]
		j := i - 1
		for j >= 0 && a[j] > v {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = v
	}
}
