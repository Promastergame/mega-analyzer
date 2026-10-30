package apkloader

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Phase 2: Mid-Level IR (MIR)
// ═══════════════════════════════════════════════════════════════════════════════
//
// MIR normalizes Dalvik-specific instruction variants into canonical operations.
// Example: add-int, add-int/2addr, add-int/lit8, add-int/lit16 → MIR_ADD
//
// This layer is the bridge between raw bytecode and high-level analysis (CFG/SSA).
// The MIR is what the ML engine and pattern matchers actually consume.

// MIROpKind is the canonical operation type.
type MIROpKind uint8

const (
	MIR_NOP MIROpKind = iota

	// ── Data Movement ────────────────────────────────────────
	MIR_MOVE           // reg → reg
	MIR_MOVE_RESULT    // implicit result → reg
	MIR_MOVE_EXCEPTION // exception object → reg
	MIR_CONST          // literal → reg

	// ── Arithmetic ───────────────────────────────────────────
	MIR_ADD
	MIR_SUB
	MIR_RSUB // reverse subtract (Imm - Src1)
	MIR_MUL
	MIR_DIV
	MIR_REM
	MIR_NEG
	MIR_NOT // bitwise not

	// ── Bitwise ──────────────────────────────────────────────
	MIR_AND
	MIR_OR
	MIR_XOR
	MIR_SHL
	MIR_SHR
	MIR_USHR

	// ── Conversion ───────────────────────────────────────────
	MIR_CONVERT // int→long, float→int, etc.

	// ── Comparison ───────────────────────────────────────────
	MIR_CMP  // cmp-long → unified
	MIR_CMPL // cmpl-float, cmpl-double (NaN → -1)
	MIR_CMPG // cmpg-float, cmpg-double (NaN → +1)

	// ── Branching ────────────────────────────────────────────
	MIR_IF     // conditional branch
	MIR_GOTO   // unconditional branch
	MIR_SWITCH // packed/sparse switch
	MIR_RETURN // method return
	MIR_THROW  // throw exception

	// ── Object / Array ───────────────────────────────────────
	MIR_NEW_INSTANCE
	MIR_NEW_ARRAY
	MIR_ARRAY_LENGTH
	MIR_ARRAY_GET
	MIR_ARRAY_PUT
	MIR_FILL_ARRAY
	MIR_CHECK_CAST
	MIR_INSTANCE_OF

	// ── Field Access ─────────────────────────────────────────
	MIR_FIELD_GET // iget/sget → unified
	MIR_FIELD_PUT // iput/sput → unified

	// ── Method Invocation ────────────────────────────────────
	MIR_INVOKE // all invoke variants → unified

	// ── Monitor ──────────────────────────────────────────────
	MIR_MONITOR_ENTER
	MIR_MONITOR_EXIT

	// ── Payload (pseudo) / Unknown ───────────────────────────
	MIR_PAYLOAD // switch/array data payload
	MIR_UNKNOWN // unmapped / custom opcode
)

// MIRCondition describes a comparison condition for MIR_IF.
type MIRCondition uint8

const (
	CondEQ  MIRCondition = iota // ==
	CondNE                      // !=
	CondLT                      // <
	CondGE                      // >=
	CondGT                      // >
	CondLE                      // <=
	CondEQZ                     // == 0
	CondNEZ                     // != 0
	CondLTZ                     // < 0
	CondGEZ                     // >= 0
	CondGTZ                     // > 0
	CondLEZ                     // <= 0
)

// MIRDataType describes the data type of an operation.
type MIRDataType uint8

const (
	TypeInt MIRDataType = iota
	TypeLong
	TypeFloat
	TypeDouble
	TypeObject
	TypeByte
	TypeChar
	TypeShort
	TypeBoolean
	TypeVoid
	TypeUnknown
)

// MIRFieldKind indicates instance vs static field access.
type MIRFieldKind uint8

const (
	FieldInstance MIRFieldKind = iota
	FieldStatic
)

// MIRInvokeKind indicates the dispatch mechanism.
type MIRInvokeKind uint8

const (
	InvokeVirtual MIRInvokeKind = iota
	InvokeSuper
	InvokeDirect
	InvokeStatic
	InvokeInterface
)

// ConstKind describes the sub-kind of constant loading.
type ConstKind uint8

const (
	ConstLit ConstKind = iota
	ConstString
	ConstClass
)

// CmpKind describes comparison semantics (handling of NaNs).
type CmpKind uint8

const (
	CmpL CmpKind = iota
	CmpG
	CmpLong
)

// MIRInsn is a normalized mid-level instruction.
// It strips Dalvik encoding details and presents a clean semantic view.
type MIRInsn struct {
	Kind     MIROpKind    // canonical operation
	DataType MIRDataType  // operation data type
	Cond     MIRCondition // condition for MIR_IF
	Offset   uint32       // original PC offset

	// Destination register (-1 if none)
	Dst int16

	// Source registers/operands
	Src1 int16
	Src2 int16
	Src3 int16 // 3rd source operand (e.g., value for APUT)

	// Immediate value (constant, branch offset, field/method index)
	Imm int64

	// Reference index into string/type/field/method tables
	RefIdx  uint32
	RefKind RefKind

	// Sub-kind for multi-variant operations
	FieldKind  MIRFieldKind  // for MIR_FIELD_GET/PUT
	InvokeKind MIRInvokeKind // for MIR_INVOKE
	ConstKind  ConstKind     // for MIR_CONST (lit, string, class)
	CmpKind    CmpKind       // for MIR_CMP / MIR_CMPL / MIR_CMPG

	// Register arguments for invoke and filled-new-array.
	// Stored inline to avoid heap allocation for the common case (≤5 args).
	// Use Args() to get a slice view.
	ArgsData [5]uint16
	ArgsLen  uint8

	// Original RawInsn flags (preserved for fast filtering)
	RawFlags InsnFlags
}

// Args returns a slice view of the inline argument registers for this instruction.
// The returned slice is valid for the lifetime of the MIRInsn.
func (m *MIRInsn) Args() []uint16 {
	if m.ArgsLen == 0 {
		return nil
	}
	return m.ArgsData[:m.ArgsLen]
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOWERING: RawInsn → MIRInsn
// ═══════════════════════════════════════════════════════════════════════════════

// LowerToMIR converts a stream of RawInsn into normalized MIRInsn.
// This is the core normalization pass.
func LowerToMIR(raw []RawInsn) []MIRInsn {
	if len(raw) == 0 {
		return nil
	}

	mir := make([]MIRInsn, 0, len(raw))
	for i := range raw {
		m := lowerOne(&raw[i])
		mir = append(mir, m)
	}
	return mir
}

// lowerOne normalizes a single RawInsn into a MIRInsn.
func lowerOne(r *RawInsn) MIRInsn {
	m := MIRInsn{
		Offset:   r.Offset,
		RawFlags: r.Flags,
		RefIdx:   r.RefIdx,
		RefKind:  r.RefKind,
		Dst:      -1,
		Src1:     -1,
		Src2:     -1,
		Src3:     -1,
	}

	op := r.Op

	switch {
	// ── NOP ──────────────────────────────────────────────────
	case op == 0x00:
		m.Kind = MIR_NOP

	// ── MOVE (0x01–0x09) ─────────────────────────────────────
	case op >= 0x01 && op <= 0x09:
		m.Kind = MIR_MOVE
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1])
		m.DataType = moveDataType(op)

	// ── MOVE-RESULT (0x0A–0x0C) ──────────────────────────────
	case op >= 0x0A && op <= 0x0C:
		m.Kind = MIR_MOVE_RESULT
		m.Dst = int16(r.Regs[0])
		m.DataType = moveResultDataType(op)

	// ── MOVE-EXCEPTION (0x0D) ────────────────────────────────
	case op == 0x0D:
		m.Kind = MIR_MOVE_EXCEPTION
		m.Dst = int16(r.Regs[0])
		m.DataType = TypeObject

	// ── RETURN (0x0E–0x11) ───────────────────────────────────
	case op >= 0x0E && op <= 0x11:
		m.Kind = MIR_RETURN
		if op != 0x0E { // return-void has no register
			m.Src1 = int16(r.Regs[0])
		}
		m.DataType = returnDataType(op)

	// ── CONST (0x12–0x1C) ────────────────────────────────────
	case op >= 0x12 && op <= 0x19:
		m.Kind = MIR_CONST
		m.ConstKind = ConstLit
		m.Dst = int16(r.Regs[0])
		m.Imm = r.Imm
		m.DataType = constDataType(op)

	case op == 0x1A || op == 0x1B: // const-string
		m.Kind = MIR_CONST
		m.ConstKind = ConstString
		m.Dst = int16(r.Regs[0])
		m.Imm = int64(r.RefIdx)
		m.DataType = TypeObject

	case op == 0x1C: // const-class
		m.Kind = MIR_CONST
		m.ConstKind = ConstClass
		m.Dst = int16(r.Regs[0])
		m.Imm = int64(r.RefIdx)
		m.DataType = TypeObject

	// ── MONITOR (0x1D–0x1E) ──────────────────────────────────
	case op == 0x1D:
		m.Kind = MIR_MONITOR_ENTER
		m.Src1 = int16(r.Regs[0])
	case op == 0x1E:
		m.Kind = MIR_MONITOR_EXIT
		m.Src1 = int16(r.Regs[0])

	// ── CHECK-CAST (0x1F) ────────────────────────────────────
	case op == 0x1F:
		m.Kind = MIR_CHECK_CAST
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[0])

	// ── INSTANCE-OF (0x20) ───────────────────────────────────
	case op == 0x20:
		m.Kind = MIR_INSTANCE_OF
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1])

	// ── ARRAY-LENGTH (0x21) ──────────────────────────────────
	case op == 0x21:
		m.Kind = MIR_ARRAY_LENGTH
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1])

	// ── NEW-INSTANCE (0x22) ──────────────────────────────────
	case op == 0x22:
		m.Kind = MIR_NEW_INSTANCE
		m.Dst = int16(r.Regs[0])

	// ── NEW-ARRAY (0x23) ─────────────────────────────────────
	case op == 0x23:
		m.Kind = MIR_NEW_ARRAY
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1]) // size register

	// ── FILLED-NEW-ARRAY (0x24–0x25) ─────────────────────────
	case op == 0x24 || op == 0x25:
		m.Kind = MIR_NEW_ARRAY
		m.Imm = int64(r.RegCount)
		m.RefIdx = r.RefIdx
		if r.RegCount > 0 && int(r.RegCount) <= len(m.ArgsData) && int(r.RegCount) <= len(r.Regs) {
			m.ArgsLen = r.RegCount
			copy(m.ArgsData[:], r.Regs[:r.RegCount])
		}

	// ── FILL-ARRAY-DATA (0x26) ───────────────────────────────
	case op == 0x26:
		m.Kind = MIR_FILL_ARRAY
		m.Src1 = int16(r.Regs[0])
		m.Imm = r.Imm

	// ── THROW (0x27) ─────────────────────────────────────────
	case op == 0x27:
		m.Kind = MIR_THROW
		m.Src1 = int16(r.Regs[0])

	// ── GOTO (0x28–0x2A) ─────────────────────────────────────
	case op >= 0x28 && op <= 0x2A:
		m.Kind = MIR_GOTO
		m.Imm = r.Imm

	// ── SWITCH (0x2B–0x2C) ───────────────────────────────────
	case op == 0x2B || op == 0x2C:
		m.Kind = MIR_SWITCH
		m.Src1 = int16(r.Regs[0])
		m.Imm = r.Imm

	// ── CMP (0x2D–0x31) ──────────────────────────────────────
	case op == 0x2D || op == 0x2F: // cmpl-float, cmpl-double
		m.Kind = MIR_CMPL
		m.CmpKind = CmpL
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1])
		m.Src2 = int16(r.Regs[2])
		m.DataType = cmpDataType(op)

	case op == 0x2E || op == 0x30: // cmpg-float, cmpg-double
		m.Kind = MIR_CMPG
		m.CmpKind = CmpG
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1])
		m.Src2 = int16(r.Regs[2])
		m.DataType = cmpDataType(op)

	case op == 0x31: // cmp-long
		m.Kind = MIR_CMP
		m.CmpKind = CmpLong
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1])
		m.Src2 = int16(r.Regs[2])
		m.DataType = TypeLong

	// ── IF (two-reg: 0x32–0x37) ──────────────────────────────
	case op >= 0x32 && op <= 0x37:
		m.Kind = MIR_IF
		m.Src1 = int16(r.Regs[0])
		m.Src2 = int16(r.Regs[1])
		m.Imm = r.Imm
		m.Cond = ifCondition(op)

	// ── IF-ZERO (0x38–0x3D) ──────────────────────────────────
	case op >= 0x38 && op <= 0x3D:
		m.Kind = MIR_IF
		m.Src1 = int16(r.Regs[0])
		m.Imm = r.Imm
		m.Cond = ifzCondition(op)

	// ── AGET (0x44–0x4A) ─────────────────────────────────────
	case op >= 0x44 && op <= 0x4A:
		m.Kind = MIR_ARRAY_GET
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1]) // array ref
		m.Src2 = int16(r.Regs[2]) // index
		m.DataType = agetDataType(op)

	// ── APUT (0x4B–0x51) ─────────────────────────────────────
	case op >= 0x4B && op <= 0x51:
		m.Kind = MIR_ARRAY_PUT
		m.Dst = -1                // Dst is -1 (no destination defined)
		m.Src1 = int16(r.Regs[1]) // array ref
		m.Src2 = int16(r.Regs[2]) // index
		m.Src3 = int16(r.Regs[0]) // value
		m.DataType = aputDataType(op)

	// ── IGET (0x52–0x58) ─────────────────────────────────────
	case op >= 0x52 && op <= 0x58:
		m.Kind = MIR_FIELD_GET
		m.FieldKind = FieldInstance
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1]) // object ref
		m.DataType = fieldDataType(op - 0x52)

	// ── IPUT (0x59–0x5F) ─────────────────────────────────────
	case op >= 0x59 && op <= 0x5F:
		m.Kind = MIR_FIELD_PUT
		m.FieldKind = FieldInstance
		m.Src1 = int16(r.Regs[0]) // value
		m.Src2 = int16(r.Regs[1]) // object ref
		m.DataType = fieldDataType(op - 0x59)

	// ── SGET (0x60–0x66) ─────────────────────────────────────
	case op >= 0x60 && op <= 0x66:
		m.Kind = MIR_FIELD_GET
		m.FieldKind = FieldStatic
		m.Dst = int16(r.Regs[0])
		m.DataType = fieldDataType(op - 0x60)

	// ── SPUT (0x67–0x6D) ─────────────────────────────────────
	case op >= 0x67 && op <= 0x6D:
		m.Kind = MIR_FIELD_PUT
		m.FieldKind = FieldStatic
		m.Src1 = int16(r.Regs[0]) // value
		m.DataType = fieldDataType(op - 0x67)

	// ── INVOKE (0x6E–0x72, 0x74–0x78) ────────────────────────
	case op >= 0x6E && op <= 0x72:
		m.Kind = MIR_INVOKE
		m.InvokeKind = invokeKind(op)
		m.Imm = int64(r.RegCount)
		if r.RegCount > 0 && int(r.RegCount) <= len(m.ArgsData) && int(r.RegCount) <= len(r.Regs) {
			m.ArgsLen = r.RegCount
			copy(m.ArgsData[:], r.Regs[:r.RegCount])
		}

	case op >= 0x74 && op <= 0x78:
		m.Kind = MIR_INVOKE
		m.InvokeKind = invokeKind(op - 6) // range variants offset by 6
		m.Imm = int64(r.RegCount)
		if r.RegCount > 0 && int(r.RegCount) <= len(m.ArgsData) && int(r.RegCount) <= len(r.Regs) {
			m.ArgsLen = r.RegCount
			copy(m.ArgsData[:], r.Regs[:r.RegCount])
		}

	// ── UNARY (0x7B–0x8F) ────────────────────────────────────
	case op >= 0x7B && op <= 0x80: // neg-int through neg-double
		m.Kind = unaryKind(op)
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1])
		m.DataType = unaryDataType(op)
	case op >= 0x81 && op <= 0x8F: // conversions
		m.Kind = MIR_CONVERT
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1])

	// ── BINOP 23x (0x90–0xAF) ────────────────────────────────
	case op >= 0x90 && op <= 0xAF:
		m.Kind = binopKind(op)
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1])
		m.Src2 = int16(r.Regs[2])
		m.DataType = binopDataType(op)

	// ── BINOP/2ADDR (0xB0–0xCF) ──────────────────────────────
	case op >= 0xB0 && op <= 0xCF:
		m.Kind = binopKind(0x90 + (op - 0xB0)) // normalize to base binop
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[0]) // dst == src1 for 2addr
		m.Src2 = int16(r.Regs[1])
		m.DataType = binopDataType(0x90 + (op - 0xB0))

	// ── BINOP/LIT16 (0xD0–0xD7) ─────────────────────────────
	case op >= 0xD0 && op <= 0xD7:
		m.Kind = litBinopKind(op)
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1])
		m.Imm = r.Imm
		m.DataType = TypeInt

	// ── BINOP/LIT8 (0xD8–0xE2) ──────────────────────────────
	case op >= 0xD8 && op <= 0xE2:
		m.Kind = lit8BinopKind(op)
		m.Dst = int16(r.Regs[0])
		m.Src1 = int16(r.Regs[1])
		m.Imm = r.Imm
		m.DataType = TypeInt

	// ── PAYLOAD / UNKNOWN ────────────────────────────────────
	default:
		if r.Flags&FlagPayload != 0 {
			m.Kind = MIR_PAYLOAD
		} else {
			m.Kind = MIR_UNKNOWN
			m.Imm = int64(op)
		}
	}

	return m
}

// MIRMethod is a canonical, self-contained method IR container.
type MIRMethod struct {
	Insns      []MIRInsn
	InvokeArgs map[uint32][]uint16 // offset -> argument registers
	Tries      []*TryItem
	Handlers   []*CatchHandler
}

// LowerMethodToMIR builds a self-contained MIRMethod from raw instructions and code item.
func LowerMethodToMIR(raw []RawInsn, code *CodeItem) MIRMethod {
	insns := LowerToMIR(raw)
	invokeArgs := make(map[uint32][]uint16)
	var codeUnits []uint16
	if code != nil {
		codeUnits = code.Insns
	}

	for i := range insns {
		m := &insns[i]
		if m.Kind == MIR_INVOKE || (m.Kind == MIR_NEW_ARRAY && raw[i].Op >= 0x24 && raw[i].Op <= 0x25) {
			var args []uint16
			if codeUnits != nil {
				args = DecodeInvokeRegs(&raw[i], codeUnits)
			}
			if len(args) == 0 && raw[i].RegCount > 0 && raw[i].RegCount <= 3 {
				args = raw[i].Regs[:raw[i].RegCount]
			}
			if len(args) > 0 {
				if n := len(args); n <= len(m.ArgsData) {
					m.ArgsLen = uint8(n)
					copy(m.ArgsData[:], args)
				}
				invokeArgs[m.Offset] = m.Args()
			}
		}
	}

	res := MIRMethod{
		Insns:      insns,
		InvokeArgs: invokeArgs,
	}
	if code != nil {
		res.Tries = code.Tries
		res.Handlers = code.Handlers
	}
	return res
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER: opcode → data type / condition / kind mappings
// ═══════════════════════════════════════════════════════════════════════════════

func moveDataType(op uint8) MIRDataType {
	switch {
	case op <= 0x03:
		return TypeInt
	case op <= 0x06:
		return TypeLong
	default:
		return TypeObject
	}
}

func moveResultDataType(op uint8) MIRDataType {
	switch op {
	case 0x0A:
		return TypeInt
	case 0x0B:
		return TypeLong
	default:
		return TypeObject
	}
}

func returnDataType(op uint8) MIRDataType {
	switch op {
	case 0x0E:
		return TypeVoid
	case 0x0F:
		return TypeInt
	case 0x10:
		return TypeLong
	default:
		return TypeObject
	}
}

func constDataType(op uint8) MIRDataType {
	if op <= 0x15 {
		return TypeInt
	}
	return TypeLong // const-wide variants
}

func cmpDataType(op uint8) MIRDataType {
	switch op {
	case 0x2D, 0x2E:
		return TypeFloat
	case 0x2F, 0x30:
		return TypeDouble
	default:
		return TypeLong
	}
}

func ifCondition(op uint8) MIRCondition {
	return MIRCondition(op - 0x32) // 0x32=eq, 0x33=ne, ...
}

func ifzCondition(op uint8) MIRCondition {
	return MIRCondition(op - 0x38 + uint8(CondEQZ))
}

func agetDataType(op uint8) MIRDataType {
	types := [...]MIRDataType{TypeInt, TypeLong, TypeObject, TypeBoolean, TypeByte, TypeChar, TypeShort}
	return types[op-0x44]
}

func aputDataType(op uint8) MIRDataType {
	types := [...]MIRDataType{TypeInt, TypeLong, TypeObject, TypeBoolean, TypeByte, TypeChar, TypeShort}
	return types[op-0x4B]
}

func fieldDataType(offset uint8) MIRDataType {
	types := [...]MIRDataType{TypeInt, TypeLong, TypeObject, TypeBoolean, TypeByte, TypeChar, TypeShort}
	if int(offset) < len(types) {
		return types[offset]
	}
	return TypeUnknown
}

func invokeKind(op uint8) MIRInvokeKind {
	return MIRInvokeKind(op - 0x6E)
}

func unaryKind(op uint8) MIROpKind {
	switch op {
	case 0x7B, 0x7D, 0x7F, 0x80:
		return MIR_NEG
	case 0x7C, 0x7E:
		return MIR_NOT
	default:
		return MIR_NOP
	}
}

func unaryDataType(op uint8) MIRDataType {
	switch {
	case op <= 0x7C:
		return TypeInt
	case op <= 0x7E:
		return TypeLong
	case op == 0x7F:
		return TypeFloat
	default:
		return TypeDouble
	}
}

func binopKind(op uint8) MIROpKind {
	// Group of 11 ops per data type: add, sub, mul, div, rem, and, or, xor, shl, shr, ushr
	idx := (op - 0x90) % 11
	kinds := [...]MIROpKind{MIR_ADD, MIR_SUB, MIR_MUL, MIR_DIV, MIR_REM, MIR_AND, MIR_OR, MIR_XOR, MIR_SHL, MIR_SHR, MIR_USHR}
	return kinds[idx]
}

func binopDataType(op uint8) MIRDataType {
	group := (op - 0x90) / 11
	types := [...]MIRDataType{TypeInt, TypeLong, TypeFloat, TypeDouble}
	if int(group) < len(types) {
		return types[group]
	}
	return TypeUnknown
}

func litBinopKind(op uint8) MIROpKind {
	kinds := [...]MIROpKind{MIR_ADD, MIR_RSUB, MIR_MUL, MIR_DIV, MIR_REM, MIR_AND, MIR_OR, MIR_XOR}
	return kinds[op-0xD0]
}

func lit8BinopKind(op uint8) MIROpKind {
	kinds := [...]MIROpKind{MIR_ADD, MIR_RSUB, MIR_MUL, MIR_DIV, MIR_REM, MIR_AND, MIR_OR, MIR_XOR, MIR_SHL, MIR_SHR, MIR_USHR}
	return kinds[op-0xD8]
}
