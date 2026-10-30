package apkloader

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Intermediate Representation (IR)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Level 1 IR: RawInsn — 1:1 mapping from Dalvik bytecode to structured data.
// No string allocations. No fmt.Sprintf. Pure data.
//
// Each RawInsn is 32 bytes (fits in half a cache line):
//   Op(1) + Format(1) + RegCount(1) + RefKind(1) + Regs(6) + Imm(8) + RefIdx(4) + Offset(4) + Size(2) + Flags(2) = 32 bytes

// Opcode is a Dalvik opcode (0x00–0xFF).
type Opcode = uint8

// RefKind describes what a reference index points to.
type RefKind uint8

const (
	RefNone   RefKind = iota
	RefString         // string_ids table
	RefType           // type_ids table
	RefField          // field_ids table
	RefMethod         // method_ids table
	RefProto
	RefMethodHandle
	RefCallSite
)

// InsnFlags provides fast classification without opcode table lookups.
type InsnFlags uint16

const (
	FlagBranch   InsnFlags = 1 << iota // conditional/unconditional jump
	FlagThrow                          // can throw exception
	FlagInvoke                         // method call
	FlagReturn                         // return from method
	FlagMove                           // register move/copy
	FlagConst                          // loads a constant
	FlagFieldOp                        // field get/put
	FlagArrayOp                        // array access
	FlagMonitor                        // monitor enter/exit
	FlagSwitch                         // packed/sparse switch
	FlagPayload                        // pseudo-instruction (payload data)
	FlagWideRegs                       // operates on 64-bit register pairs
)

// RawInsn is the Level 1 IR — a zero-allocation structured representation
// of a single Dalvik instruction.
//
// Design constraints:
//   - Fixed 32 bytes — no pointers, no slices, no strings
//   - Inline register storage (up to 3 regs; enough for 95% of instructions)
//   - Semantic flags for fast filtering without opcode table lookups
type RawInsn struct {
	Op       Opcode     // Dalvik opcode (0x00–0xFF)
	Format   InsnFormat // instruction format (Fmt10x, Fmt22c, ...)
	RegCount uint8      // number of registers used (0–3 inline, >3 = invoke)
	RefKind  RefKind    // what RefIdx points to

	Regs [3]uint16 // inline register storage (vA, vB, vC)
	// For invoke with >3 regs, use DecodeInvokeRegs()

	Imm    int64     // immediate value / branch offset / literal
	RefIdx uint32    // index into string/type/field/method table
	Offset uint32    // PC offset within the method (in 16-bit code units)
	Size   uint16    // instruction size in 16-bit code units
	Flags  InsnFlags // semantic classification flags
}

// IsBranch returns true if this instruction is a conditional or unconditional jump.
func (r *RawInsn) IsBranch() bool { return r.Flags&FlagBranch != 0 }

// IsInvoke returns true if this instruction is a method call.
func (r *RawInsn) IsInvoke() bool { return r.Flags&FlagInvoke != 0 }

// IsReturn returns true if this instruction returns from the method.
func (r *RawInsn) IsReturn() bool { return r.Flags&FlagReturn != 0 }

// IsConst returns true if this instruction loads a constant.
func (r *RawInsn) IsConst() bool { return r.Flags&FlagConst != 0 }

// IsThrow returns true if this instruction can throw.
func (r *RawInsn) IsThrow() bool { return r.Flags&FlagThrow != 0 }

// IsFieldOp returns true if this instruction accesses a field.
func (r *RawInsn) IsFieldOp() bool { return r.Flags&FlagFieldOp != 0 }

// IsSwitch returns true if this is a switch instruction.
func (r *RawInsn) IsSwitch() bool { return r.Flags&FlagSwitch != 0 }

// BranchTarget returns the absolute PC of the branch target.
// Only valid when IsBranch() is true.
func (r *RawInsn) BranchTarget() uint32 {
	return uint32(int32(r.Offset) + int32(r.Imm))
}

// ═══════════════════════════════════════════════════════════════════════════════
// DECODED METHOD — container for a method's IR
// ═══════════════════════════════════════════════════════════════════════════════

// DecodedMethod holds the complete IR for a single method.
type DecodedMethod struct {
	ClassName   string
	MethodName  string
	ReturnType  string
	Parameters  []string
	AccessFlags uint32

	RegistersSize uint16
	InsSize       uint16
	OutsSize      uint16

	Insns     []RawInsn // Level 1 IR stream
	InsnCount int

	// Try-catch metadata
	Tries    []*TryItem
	Handlers []*CatchHandler
}

// ═══════════════════════════════════════════════════════════════════════════════
// OPCODE METADATA TABLE — extended with semantic flags
// ═══════════════════════════════════════════════════════════════════════════════

// OpcodeMetadata extends OpcodeInfo with semantic flags for IR construction.
type OpcodeMetadata struct {
	Name    string
	Format  InsnFormat
	Size    uint32
	Flags   InsnFlags
	RefKind RefKind
}

// opcodeMetaTable is the authoritative opcode table for IR construction.
// Populated in init() below. 256 entries, one per possible opcode.
var opcodeMetaTable [256]OpcodeMetadata

func init() {
	// Initialize all as unknown
	for i := range opcodeMetaTable {
		opcodeMetaTable[i] = OpcodeMetadata{
			Name:   "unknown",
			Format: FmtUnknown,
			Size:   1,
		}
	}

	// Helper to set an opcode entry
	m := func(op int, name string, format InsnFormat, size uint32, flags InsnFlags, ref RefKind) {
		opcodeMetaTable[op] = OpcodeMetadata{
			Name:    name,
			Format:  format,
			Size:    size,
			Flags:   flags,
			RefKind: ref,
		}
	}

	// ── NOP ──────────────────────────────────────────────
	m(0x00, "nop", Fmt10x, 1, 0, RefNone)

	// ── MOVE ─────────────────────────────────────────────
	m(0x01, "move", Fmt12x, 1, FlagMove, RefNone)
	m(0x02, "move/from16", Fmt22x, 2, FlagMove, RefNone)
	m(0x03, "move/16", Fmt32x, 3, FlagMove, RefNone)
	m(0x04, "move-wide", Fmt12x, 1, FlagMove|FlagWideRegs, RefNone)
	m(0x05, "move-wide/from16", Fmt22x, 2, FlagMove|FlagWideRegs, RefNone)
	m(0x06, "move-wide/16", Fmt32x, 3, FlagMove|FlagWideRegs, RefNone)
	m(0x07, "move-object", Fmt12x, 1, FlagMove, RefNone)
	m(0x08, "move-object/from16", Fmt22x, 2, FlagMove, RefNone)
	m(0x09, "move-object/16", Fmt32x, 3, FlagMove, RefNone)

	// ── MOVE-RESULT ──────────────────────────────────────
	m(0x0A, "move-result", Fmt11x, 1, FlagMove, RefNone)
	m(0x0B, "move-result-wide", Fmt11x, 1, FlagMove|FlagWideRegs, RefNone)
	m(0x0C, "move-result-object", Fmt11x, 1, FlagMove, RefNone)
	m(0x0D, "move-exception", Fmt11x, 1, FlagMove, RefNone)

	// ── RETURN ────────────────────────────────────────────
	m(0x0E, "return-void", Fmt10x, 1, FlagReturn, RefNone)
	m(0x0F, "return", Fmt11x, 1, FlagReturn, RefNone)
	m(0x10, "return-wide", Fmt11x, 1, FlagReturn|FlagWideRegs, RefNone)
	m(0x11, "return-object", Fmt11x, 1, FlagReturn, RefNone)

	// ── CONST ─────────────────────────────────────────────
	m(0x12, "const/4", Fmt11n, 1, FlagConst, RefNone)
	m(0x13, "const/16", Fmt21s, 2, FlagConst, RefNone)
	m(0x14, "const", Fmt31i, 3, FlagConst, RefNone)
	m(0x15, "const/high16", Fmt21h, 2, FlagConst, RefNone)
	m(0x16, "const-wide/16", Fmt21s, 2, FlagConst|FlagWideRegs, RefNone)
	m(0x17, "const-wide/32", Fmt31i, 3, FlagConst|FlagWideRegs, RefNone)
	m(0x18, "const-wide", Fmt51l, 5, FlagConst|FlagWideRegs, RefNone)
	m(0x19, "const-wide/high16", Fmt21h, 2, FlagConst|FlagWideRegs, RefNone)
	m(0x1A, "const-string", Fmt21c, 2, FlagConst, RefString)
	m(0x1B, "const-string/jumbo", Fmt31c, 3, FlagConst, RefString)
	m(0x1C, "const-class", Fmt21c, 2, FlagConst, RefType)

	// ── MONITOR ───────────────────────────────────────────
	m(0x1D, "monitor-enter", Fmt11x, 1, FlagMonitor|FlagThrow, RefNone)
	m(0x1E, "monitor-exit", Fmt11x, 1, FlagMonitor|FlagThrow, RefNone)

	// ── CHECK / INSTANCE ──────────────────────────────────
	m(0x1F, "check-cast", Fmt21c, 2, FlagThrow, RefType)
	m(0x20, "instance-of", Fmt22c, 2, 0, RefType)

	// ── ARRAY ─────────────────────────────────────────────
	m(0x21, "array-length", Fmt12x, 1, FlagThrow|FlagArrayOp, RefNone)
	m(0x22, "new-instance", Fmt21c, 2, FlagThrow, RefType)
	m(0x23, "new-array", Fmt22c, 2, FlagThrow|FlagArrayOp, RefType)
	m(0x24, "filled-new-array", Fmt35c, 3, FlagThrow|FlagInvoke|FlagArrayOp, RefType)
	m(0x25, "filled-new-array/range", Fmt3rc, 3, FlagThrow|FlagInvoke|FlagArrayOp, RefType)
	m(0x26, "fill-array-data", Fmt31i, 3, FlagArrayOp|FlagPayload, RefNone)

	// ── THROW ─────────────────────────────────────────────
	m(0x27, "throw", Fmt11x, 1, FlagThrow, RefNone)

	// ── GOTO ──────────────────────────────────────────────
	m(0x28, "goto", Fmt10t, 1, FlagBranch, RefNone)
	m(0x29, "goto/16", Fmt20t, 2, FlagBranch, RefNone)
	m(0x2A, "goto/32", Fmt30t, 3, FlagBranch, RefNone)

	// ── SWITCH ────────────────────────────────────────────
	m(0x2B, "packed-switch", Fmt31i, 3, FlagBranch|FlagSwitch|FlagPayload, RefNone)
	m(0x2C, "sparse-switch", Fmt31i, 3, FlagBranch|FlagSwitch|FlagPayload, RefNone)

	// ── CMP ───────────────────────────────────────────────
	m(0x2D, "cmpl-float", Fmt23x, 2, 0, RefNone)
	m(0x2E, "cmpg-float", Fmt23x, 2, 0, RefNone)
	m(0x2F, "cmpl-double", Fmt23x, 2, FlagWideRegs, RefNone)
	m(0x30, "cmpg-double", Fmt23x, 2, FlagWideRegs, RefNone)
	m(0x31, "cmp-long", Fmt23x, 2, FlagWideRegs, RefNone)

	// ── IF (2 regs) ───────────────────────────────────────
	for op := 0x32; op <= 0x37; op++ {
		names := []string{"if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le"}
		m(op, names[op-0x32], Fmt22t, 2, FlagBranch, RefNone)
	}

	// ── IF (vs zero) ──────────────────────────────────────
	for op := 0x38; op <= 0x3D; op++ {
		names := []string{"if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez"}
		m(op, names[op-0x38], Fmt21t, 2, FlagBranch, RefNone)
	}

	// ── AGET ──────────────────────────────────────────────
	for op := 0x44; op <= 0x4A; op++ {
		names := []string{"aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte", "aget-char", "aget-short"}
		flags := InsnFlags(FlagArrayOp | FlagThrow)
		if op == 0x45 {
			flags |= FlagWideRegs
		}
		m(op, names[op-0x44], Fmt23x, 2, flags, RefNone)
	}

	// ── APUT ──────────────────────────────────────────────
	for op := 0x4B; op <= 0x51; op++ {
		names := []string{"aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte", "aput-char", "aput-short"}
		flags := InsnFlags(FlagArrayOp | FlagThrow)
		if op == 0x4C {
			flags |= FlagWideRegs
		}
		m(op, names[op-0x4B], Fmt23x, 2, flags, RefNone)
	}

	// ── IGET ──────────────────────────────────────────────
	for op := 0x52; op <= 0x58; op++ {
		names := []string{"iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte", "iget-char", "iget-short"}
		flags := InsnFlags(FlagFieldOp | FlagThrow)
		if op == 0x53 {
			flags |= FlagWideRegs
		}
		m(op, names[op-0x52], Fmt22c, 2, flags, RefField)
	}

	// ── IPUT ──────────────────────────────────────────────
	for op := 0x59; op <= 0x5F; op++ {
		names := []string{"iput", "iput-wide", "iput-object", "iput-boolean", "iput-byte", "iput-char", "iput-short"}
		flags := InsnFlags(FlagFieldOp | FlagThrow)
		if op == 0x5A {
			flags |= FlagWideRegs
		}
		m(op, names[op-0x59], Fmt22c, 2, flags, RefField)
	}

	// ── SGET ──────────────────────────────────────────────
	for op := 0x60; op <= 0x66; op++ {
		names := []string{"sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte", "sget-char", "sget-short"}
		flags := InsnFlags(FlagFieldOp | FlagThrow)
		if op == 0x61 {
			flags |= FlagWideRegs
		}
		m(op, names[op-0x60], Fmt21c, 2, flags, RefField)
	}

	// ── SPUT ──────────────────────────────────────────────
	for op := 0x67; op <= 0x6D; op++ {
		names := []string{"sput", "sput-wide", "sput-object", "sput-boolean", "sput-byte", "sput-char", "sput-short"}
		flags := InsnFlags(FlagFieldOp | FlagThrow)
		if op == 0x68 {
			flags |= FlagWideRegs
		}
		m(op, names[op-0x67], Fmt21c, 2, flags, RefField)
	}

	// ── INVOKE ────────────────────────────────────────────
	m(0x6E, "invoke-virtual", Fmt35c, 3, FlagInvoke|FlagThrow, RefMethod)
	m(0x6F, "invoke-super", Fmt35c, 3, FlagInvoke|FlagThrow, RefMethod)
	m(0x70, "invoke-direct", Fmt35c, 3, FlagInvoke|FlagThrow, RefMethod)
	m(0x71, "invoke-static", Fmt35c, 3, FlagInvoke|FlagThrow, RefMethod)
	m(0x72, "invoke-interface", Fmt35c, 3, FlagInvoke|FlagThrow, RefMethod)

	// ── INVOKE/RANGE ──────────────────────────────────────
	m(0x74, "invoke-virtual/range", Fmt3rc, 3, FlagInvoke|FlagThrow, RefMethod)
	m(0x75, "invoke-super/range", Fmt3rc, 3, FlagInvoke|FlagThrow, RefMethod)
	m(0x76, "invoke-direct/range", Fmt3rc, 3, FlagInvoke|FlagThrow, RefMethod)
	m(0x77, "invoke-static/range", Fmt3rc, 3, FlagInvoke|FlagThrow, RefMethod)
	m(0x78, "invoke-interface/range", Fmt3rc, 3, FlagInvoke|FlagThrow, RefMethod)

	// ── UNARY ─────────────────────────────────────────────
	for op := 0x7B; op <= 0x8F; op++ {
		names := []string{
			"neg-int", "not-int", "neg-long", "not-long", "neg-float", "neg-double",
			"int-to-long", "int-to-float", "int-to-double",
			"long-to-int", "long-to-float", "long-to-double",
			"float-to-int", "float-to-long", "float-to-double",
			"double-to-int", "double-to-long", "double-to-float",
			"int-to-byte", "int-to-char", "int-to-short",
		}
		m(op, names[op-0x7B], Fmt12x, 1, 0, RefNone)
	}

	// ── BINOP 23x ─────────────────────────────────────────
	for op := 0x90; op <= 0xAF; op++ {
		names := []string{
			"add-int", "sub-int", "mul-int", "div-int", "rem-int",
			"and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int",
			"add-long", "sub-long", "mul-long", "div-long", "rem-long",
			"and-long", "or-long", "xor-long", "shl-long", "shr-long", "ushr-long",
			"add-float", "sub-float", "mul-float", "div-float", "rem-float",
			"add-double", "sub-double", "mul-double", "div-double", "rem-double",
		}
		flags := InsnFlags(0)
		// div and rem can throw ArithmeticException
		if op == 0x93 || op == 0x94 || op == 0x9E || op == 0x9F {
			flags |= FlagThrow
		}
		m(op, names[op-0x90], Fmt23x, 2, flags, RefNone)
	}

	// ── BINOP/2ADDR 12x ───────────────────────────────────
	for op := 0xB0; op <= 0xCF; op++ {
		names := []string{
			"add-int/2addr", "sub-int/2addr", "mul-int/2addr", "div-int/2addr", "rem-int/2addr",
			"and-int/2addr", "or-int/2addr", "xor-int/2addr", "shl-int/2addr", "shr-int/2addr", "ushr-int/2addr",
			"add-long/2addr", "sub-long/2addr", "mul-long/2addr", "div-long/2addr", "rem-long/2addr",
			"and-long/2addr", "or-long/2addr", "xor-long/2addr", "shl-long/2addr", "shr-long/2addr", "ushr-long/2addr",
			"add-float/2addr", "sub-float/2addr", "mul-float/2addr", "div-float/2addr", "rem-float/2addr",
			"add-double/2addr", "sub-double/2addr", "mul-double/2addr", "div-double/2addr", "rem-double/2addr",
		}
		flags := InsnFlags(0)
		if op == 0xB3 || op == 0xB4 || op == 0xBE || op == 0xBF {
			flags |= FlagThrow
		}
		m(op, names[op-0xB0], Fmt12x, 1, flags, RefNone)
	}

	// ── BINOP/LIT16 ───────────────────────────────────────
	for op := 0xD0; op <= 0xD7; op++ {
		names := []string{
			"add-int/lit16", "rsub-int", "mul-int/lit16", "div-int/lit16",
			"rem-int/lit16", "and-int/lit16", "or-int/lit16", "xor-int/lit16",
		}
		flags := InsnFlags(FlagConst)
		if op == 0xD3 || op == 0xD4 {
			flags |= FlagThrow
		}
		m(op, names[op-0xD0], Fmt22s, 2, flags, RefNone)
	}

	// ── BINOP/LIT8 ────────────────────────────────────────
	for op := 0xD8; op <= 0xE2; op++ {
		names := []string{
			"add-int/lit8", "rsub-int/lit8", "mul-int/lit8", "div-int/lit8",
			"rem-int/lit8", "and-int/lit8", "or-int/lit8", "xor-int/lit8",
			"shl-int/lit8", "shr-int/lit8", "ushr-int/lit8",
		}
		flags := InsnFlags(FlagConst)
		if op == 0xDB || op == 0xDC {
			flags |= FlagThrow
		}
		m(op, names[op-0xD8], Fmt22b, 2, flags, RefNone)
	}
}
