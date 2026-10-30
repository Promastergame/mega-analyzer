// Package dexir defines the shared typed intermediate representation for
// Dalvik classes used by the semantic analysis engine.
//
// Two adapters produce this IR:
//
//   - FromDEX (dex_adapter.go): converts apkloader's parsed binary DEX
//     structures directly — no smali text round-trip, references fully
//     resolved, exact register counts preserved.
//   - FromSmaliClass (smali_adapter.go): converts the output of the
//     legacy text parser (parser.SmaliParser) for standalone .smali
//     inputs, re-scanning method bodies for labels, payloads and
//     register operands.
//
// Design notes:
//
//   - Registers are v-registers: 0..RegistersSize-1. Parameter registers
//     occupy the top of the frame (p0 = RegistersSize-InsSize).
//   - Branches carry BOTH a code-unit offset representation (Offset /
//     BranchTarget, produced by the DEX adapter) and a label
//     representation (BranchLabel / Labels, produced by both adapters).
//     DEX-origin BranchTarget values are -1 when not applicable.
//   - Strings produced by the DEX adapter may point into mmap'd DEX
//     data (zero-copy). They are only valid while the originating
//     DEXParser and its mapping stay alive.
package dexir

import "strings"

// ═══════════════════════════════════════════════════════════════
// OPCODES
// ═══════════════════════════════════════════════════════════════

// Opcode is a Dalvik opcode (0x00–0xE2 defined; 0xE3+ reserved).
type Opcode uint8

// Named opcode constants used by the IR and its consumers.
const (
	OpNop Opcode = 0x00

	OpMove             Opcode = 0x01
	OpMoveFrom16       Opcode = 0x02
	OpMove16           Opcode = 0x03
	OpMoveWide         Opcode = 0x04
	OpMoveWideFrom16   Opcode = 0x05
	OpMoveWide16       Opcode = 0x06
	OpMoveObject       Opcode = 0x07
	OpMoveObjectFrom16 Opcode = 0x08
	OpMoveObject16     Opcode = 0x09

	OpMoveResult       Opcode = 0x0A
	OpMoveResultWide   Opcode = 0x0B
	OpMoveResultObject Opcode = 0x0C
	OpMoveException    Opcode = 0x0D

	OpReturnVoid   Opcode = 0x0E
	OpReturn       Opcode = 0x0F
	OpReturnWide   Opcode = 0x10
	OpReturnObject Opcode = 0x11

	OpConst4           Opcode = 0x12
	OpConst16          Opcode = 0x13
	OpConst32          Opcode = 0x14
	OpConstHigh16      Opcode = 0x15
	OpConstWide16      Opcode = 0x16
	OpConstWide32      Opcode = 0x17
	OpConstWide        Opcode = 0x18
	OpConstWideHigh16  Opcode = 0x19
	OpConstString      Opcode = 0x1A
	OpConstStringJumbo Opcode = 0x1B
	OpConstClass       Opcode = 0x1C

	OpMonitorEnter Opcode = 0x1D
	OpMonitorExit  Opcode = 0x1E

	OpCheckCast   Opcode = 0x1F
	OpInstanceOf  Opcode = 0x20
	OpArrayLength Opcode = 0x21
	OpNewInstance Opcode = 0x22
	OpNewArray    Opcode = 0x23

	OpFilledNewArray      Opcode = 0x24
	OpFilledNewArrayRange Opcode = 0x25
	OpFillArrayData       Opcode = 0x26
	OpThrow               Opcode = 0x27

	OpGoto   Opcode = 0x28
	OpGoto16 Opcode = 0x29
	OpGoto32 Opcode = 0x2A

	OpPackedSwitch Opcode = 0x2B
	OpSparseSwitch Opcode = 0x2C

	OpCmplFloat  Opcode = 0x2D
	OpCmpgFloat  Opcode = 0x2E
	OpCmplDouble Opcode = 0x2F
	OpCmpgDouble Opcode = 0x30
	OpCmpLong    Opcode = 0x31

	OpIfEq Opcode = 0x32
	OpIfNe Opcode = 0x33
	OpIfLt Opcode = 0x34
	OpIfGe Opcode = 0x35
	OpIfGt Opcode = 0x36
	OpIfLe Opcode = 0x37

	OpIfEqz Opcode = 0x38
	OpIfNez Opcode = 0x39
	OpIfLtz Opcode = 0x3A
	OpIfGez Opcode = 0x3B
	OpIfGtz Opcode = 0x3C
	OpIfLez Opcode = 0x3D

	OpAget Opcode = 0x44
	OpAput Opcode = 0x4B

	OpIget Opcode = 0x52
	OpIput Opcode = 0x59
	OpSget Opcode = 0x60
	OpSput Opcode = 0x67

	OpInvokeVirtual        Opcode = 0x6E
	OpInvokeSuper          Opcode = 0x6F
	OpInvokeDirect         Opcode = 0x70
	OpInvokeStatic         Opcode = 0x71
	OpInvokeInterface      Opcode = 0x72
	OpInvokeVirtualRange   Opcode = 0x74
	OpInvokeSuperRange     Opcode = 0x75
	OpInvokeDirectRange    Opcode = 0x76
	OpInvokeStaticRange    Opcode = 0x77
	OpInvokeInterfaceRange Opcode = 0x78

	// Payload pseudo-instructions (not real opcodes; used by the IR to
	// represent data tables embedded in the code stream).
	OpPackedSwitchPayload  Opcode = 0xF0
	OpSparseSwitchPayload  Opcode = 0xF1
	OpFillArrayDataPayload Opcode = 0xF2
)

// opcodeNames maps opcodes to their smali mnemonics.
var opcodeNames = map[Opcode]string{
	0x00: "nop",
	0x01: "move", 0x02: "move/from16", 0x03: "move/16",
	0x04: "move-wide", 0x05: "move-wide/from16", 0x06: "move-wide/16",
	0x07: "move-object", 0x08: "move-object/from16", 0x09: "move-object/16",
	0x0A: "move-result", 0x0B: "move-result-wide", 0x0C: "move-result-object", 0x0D: "move-exception",
	0x0E: "return-void", 0x0F: "return", 0x10: "return-wide", 0x11: "return-object",
	0x12: "const/4", 0x13: "const/16", 0x14: "const", 0x15: "const/high16",
	0x16: "const-wide/16", 0x17: "const-wide/32", 0x18: "const-wide", 0x19: "const-wide/high16",
	0x1A: "const-string", 0x1B: "const-string/jumbo", 0x1C: "const-class",
	0x1D: "monitor-enter", 0x1E: "monitor-exit",
	0x1F: "check-cast", 0x20: "instance-of", 0x21: "array-length",
	0x22: "new-instance", 0x23: "new-array",
	0x24: "filled-new-array", 0x25: "filled-new-array/range",
	0x26: "fill-array-data", 0x27: "throw",
	0x28: "goto", 0x29: "goto/16", 0x2A: "goto/32",
	0x2B: "packed-switch", 0x2C: "sparse-switch",
	0x2D: "cmpl-float", 0x2E: "cmpg-float", 0x2F: "cmpl-double", 0x30: "cmpg-double", 0x31: "cmp-long",
	0x32: "if-eq", 0x33: "if-ne", 0x34: "if-lt", 0x35: "if-ge", 0x36: "if-gt", 0x37: "if-le",
	0x38: "if-eqz", 0x39: "if-nez", 0x3A: "if-ltz", 0x3B: "if-gez", 0x3C: "if-gtz", 0x3D: "if-lez",
	0x44: "aget", 0x45: "aget-wide", 0x46: "aget-object", 0x47: "aget-boolean",
	0x48: "aget-byte", 0x49: "aget-char", 0x4A: "aget-short",
	0x4B: "aput", 0x4C: "aput-wide", 0x4D: "aput-object", 0x4E: "aput-boolean",
	0x4F: "aput-byte", 0x50: "aput-char", 0x51: "aput-short",
	0x52: "iget", 0x53: "iget-wide", 0x54: "iget-object", 0x55: "iget-boolean",
	0x56: "iget-byte", 0x57: "iget-char", 0x58: "iget-short",
	0x59: "iput", 0x5A: "iput-wide", 0x5B: "iput-object", 0x5C: "iput-boolean",
	0x5D: "iput-byte", 0x5E: "iput-char", 0x5F: "iput-short",
	0x60: "sget", 0x61: "sget-wide", 0x62: "sget-object", 0x63: "sget-boolean",
	0x64: "sget-byte", 0x65: "sget-char", 0x66: "sget-short",
	0x67: "sput", 0x68: "sput-wide", 0x69: "sput-object", 0x6A: "sput-boolean",
	0x6B: "sput-byte", 0x6C: "sput-char", 0x6D: "sput-short",
	0x6E: "invoke-virtual", 0x6F: "invoke-super", 0x70: "invoke-direct",
	0x71: "invoke-static", 0x72: "invoke-interface",
	0x74: "invoke-virtual/range", 0x75: "invoke-super/range", 0x76: "invoke-direct/range",
	0x77: "invoke-static/range", 0x78: "invoke-interface/range",
	0x7B: "neg-int", 0x7C: "not-int", 0x7D: "neg-long", 0x7E: "not-long",
	0x7F: "neg-float", 0x80: "neg-double",
	0x81: "int-to-long", 0x82: "int-to-float", 0x83: "int-to-double",
	0x84: "long-to-int", 0x85: "long-to-float", 0x86: "long-to-double",
	0x87: "float-to-int", 0x88: "float-to-long", 0x89: "float-to-double",
	0x8A: "double-to-int", 0x8B: "double-to-long", 0x8C: "double-to-float",
	0x8D: "int-to-byte", 0x8E: "int-to-char", 0x8F: "int-to-short",
	0x90: "add-int", 0x91: "sub-int", 0x92: "mul-int", 0x93: "div-int", 0x94: "rem-int",
	0x95: "and-int", 0x96: "or-int", 0x97: "xor-int", 0x98: "shl-int", 0x99: "shr-int", 0x9A: "ushr-int",
	0x9B: "add-long", 0x9C: "sub-long", 0x9D: "mul-long", 0x9E: "div-long", 0x9F: "rem-long",
	0xA0: "and-long", 0xA1: "or-long", 0xA2: "xor-long", 0xA3: "shl-long", 0xA4: "shr-long", 0xA5: "ushr-long",
	0xA6: "add-float", 0xA7: "sub-float", 0xA8: "mul-float", 0xA9: "div-float", 0xAA: "rem-float",
	0xAB: "add-double", 0xAC: "sub-double", 0xAD: "mul-double", 0xAE: "div-double", 0xAF: "rem-double",
	0xB0: "add-int/2addr", 0xB1: "sub-int/2addr", 0xB2: "mul-int/2addr", 0xB3: "div-int/2addr",
	0xB4: "rem-int/2addr", 0xB5: "and-int/2addr", 0xB6: "or-int/2addr", 0xB7: "xor-int/2addr",
	0xB8: "shl-int/2addr", 0xB9: "shr-int/2addr", 0xBA: "ushr-int/2addr",
	0xBB: "add-long/2addr", 0xBC: "sub-long/2addr", 0xBD: "mul-long/2addr", 0xBE: "div-long/2addr",
	0xBF: "rem-long/2addr", 0xC0: "and-long/2addr", 0xC1: "or-long/2addr", 0xC2: "xor-long/2addr",
	0xC3: "shl-long/2addr", 0xC4: "shr-long/2addr", 0xC5: "ushr-long/2addr",
	0xC6: "add-float/2addr", 0xC7: "sub-float/2addr", 0xC8: "mul-float/2addr", 0xC9: "div-float/2addr",
	0xCA: "rem-float/2addr", 0xCB: "add-double/2addr", 0xCC: "sub-double/2addr", 0xCD: "mul-double/2addr",
	0xCE: "div-double/2addr", 0xCF: "rem-double/2addr",
	0xD0: "add-int/lit16", 0xD1: "rsub-int", 0xD2: "mul-int/lit16", 0xD3: "div-int/lit16",
	0xD4: "rem-int/lit16", 0xD5: "and-int/lit16", 0xD6: "or-int/lit16", 0xD7: "xor-int/lit16",
	0xD8: "add-int/lit8", 0xD9: "rsub-int/lit8", 0xDA: "mul-int/lit8", 0xDB: "div-int/lit8",
	0xDC: "rem-int/lit8", 0xDD: "and-int/lit8", 0xDE: "or-int/lit8", 0xDF: "xor-int/lit8",
	0xE0: "shl-int/lit8", 0xE1: "shr-int/lit8", 0xE2: "ushr-int/lit8",
	0xF0: ".packed-switch", 0xF1: ".sparse-switch", 0xF2: ".array-data",
}

// Name returns the smali mnemonic for the opcode (e.g. "invoke-virtual").
// Unknown opcodes render as "op-NN".
func (op Opcode) Name() string {
	if n, ok := opcodeNames[op]; ok {
		return n
	}
	const hexdigits = "0123456789abcdef"
	return "op-" + string(hexdigits[op>>4]) + string(hexdigits[op&0xF])
}

// OpcodeFromName maps a smali mnemonic back to its opcode.
// Returns (0, false) for unknown names.
func OpcodeFromName(name string) (Opcode, bool) {
	for op, n := range opcodeNames {
		if n == name {
			return op, true
		}
	}
	return 0, false
}

// ═══════════════════════════════════════════════════════════════
// REFERENCES
// ═══════════════════════════════════════════════════════════════

// MethodRef is a fully resolved method reference.
type MethodRef struct {
	Class      string   // owning class type descriptor, e.g. "Lcom/x/Y;"
	Name       string   // method name, e.g. "doIt" or "<init>"
	Proto      string   // full prototype, e.g. "(ILjava/lang/String;)V"
	ReturnType string   // descriptor, e.g. "V"
	Params     []string // parameter descriptors
}

// String renders the reference in smali syntax: Lcls;->name(proto)ret.
func (r *MethodRef) String() string {
	if r == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(r.Class)
	b.WriteString("->")
	b.WriteString(r.Name)
	b.WriteString(r.Proto)
	return b.String()
}

// FieldRef is a fully resolved field reference.
type FieldRef struct {
	Class string // owning class type descriptor
	Name  string // field name
	Type  string // field type descriptor
}

// String renders the reference in smali syntax: Lcls;->name:type.
func (r *FieldRef) String() string {
	if r == nil {
		return ""
	}
	return r.Class + "->" + r.Name + ":" + r.Type
}

// ═══════════════════════════════════════════════════════════════
// PAYLOADS
// ═══════════════════════════════════════════════════════════════

// PayloadKind classifies embedded payload tables.
type PayloadKind uint8

const (
	PayloadNone PayloadKind = iota
	PayloadPackedSwitch
	PayloadSparseSwitch
	PayloadArrayData
)

// Payload holds decoded switch tables and array-data bodies.
type Payload struct {
	Kind PayloadKind

	// Switch payloads (PackedSwitch/SparseSwitch):
	FirstKey int32   // packed-switch only: first key value
	Keys     []int32 // sparse-switch: sorted key list; packed: nil
	// Targets holds the absolute branch target (in 16-bit code units,
	// relative to the switch instruction itself, as encoded in DEX)
	// for each key. Both kinds populate this.
	Targets      []int32
	TargetLabels []string // label names corresponding to Targets (may be empty)

	// Array-data payload:
	ElemWidth int    // element size in bytes (1, 2, 4 or 8)
	Values    []byte // raw element bytes, little-endian, unpadded
}

// ═══════════════════════════════════════════════════════════════
// INSTRUCTION
// ═══════════════════════════════════════════════════════════════

// NoRegister marks "no destination / no source register".
const NoRegister int32 = -1

// Instruction is a fully typed Dalvik instruction.
//
// Register semantics: Dst is the written register (NoRegister when the
// instruction writes none). Srcs holds read registers in encoding order.
// For invoke/filled-new-array instructions Srcs holds the argument
// registers.
type Instruction struct {
	Offset uint32 // absolute offset in 16-bit code units (DEX adapter); 0-based
	Line   int    // 1-based source line for text-origin IR; 0 for DEX-origin
	Size   uint16 // instruction size in 16-bit code units (text adapter: 0 = unknown)
	Op     Opcode

	Dst  int32   // destination register or NoRegister
	Srcs []int32 // source/argument registers (nil when none)

	HasImm bool
	Imm    int64 // immediate literal / lit16 / lit8 / array-data offset

	HasStr bool
	Str    string // const-string value (unescaped)

	Type string // type descriptor for type-referencing opcodes

	Method *MethodRef // invoke-* targets
	Field  *FieldRef  // field get/put targets

	// Branch information. BranchOffset is relative (in code units) to
	// this instruction; BranchTarget is the absolute target offset.
	// Both are -1 for non-branch instructions. For switch and
	// fill-array-data they point at the payload table. BranchLabel
	// names the target label when labels are available.
	BranchOffset int32
	BranchTarget int32
	BranchLabel  string

	Payload *Payload // switch/array-data table for switch & fill-array-data
}

// PayloadTargetAbs returns the absolute code-unit offset of the i-th
// switch payload target, using the offset of this switch instruction.
// Targets are stored relative to the switch instruction, exactly as
// encoded in DEX.
func (ins *Instruction) PayloadTargetAbs(i int) int32 {
	if ins.Payload == nil || i < 0 || i >= len(ins.Payload.Targets) {
		return -1
	}
	return int32(ins.Offset) + ins.Payload.Targets[i]
}

// IsBranch reports whether the instruction transfers control conditionally
// or unconditionally (goto/if-*; switch instructions report true too —
// their table targets live in Payload).
func (ins *Instruction) IsBranch() bool {
	switch ins.Op {
	case OpGoto, OpGoto16, OpGoto32,
		OpIfEq, OpIfNe, OpIfLt, OpIfGe, OpIfGt, OpIfLe,
		OpIfEqz, OpIfNez, OpIfLtz, OpIfGez, OpIfGtz, OpIfLez,
		OpPackedSwitch, OpSparseSwitch:
		return true
	}
	return false
}

// IsInvoke reports whether the instruction calls a method.
func (ins *Instruction) IsInvoke() bool {
	return ins.Op >= OpInvokeVirtual && ins.Op <= OpInvokeInterfaceRange &&
		ins.Op != 0x73 && ins.Op != 0x79 // unused opcode gaps
}

// IsReturn reports whether the instruction exits the method.
func (ins *Instruction) IsReturn() bool {
	return ins.Op >= OpReturnVoid && ins.Op <= OpReturnObject
}

// IsPayload reports whether this is a payload pseudo-instruction.
func (ins *Instruction) IsPayload() bool {
	return ins.Op >= OpPackedSwitchPayload
}

// ═══════════════════════════════════════════════════════════════
// METHOD / CLASS
// ═══════════════════════════════════════════════════════════════

// Label marks a code position by name.
type Label struct {
	Name   string // without leading ':'
	Offset uint32 // code-unit offset (DEX adapter); text adapter fills from position
	Line   int    // 1-based line for text-origin IR
}

// TryCatch describes one exception handler range.
type TryCatch struct {
	StartOffset   uint32 // first covered code unit
	EndOffset     uint32 // one past last covered code unit
	Type          string // caught exception descriptor, or "" for catch-all
	HandlerOffset uint32
	// Label forms (text-origin, or synthesized by the DEX adapter):
	StartLabel   string
	EndLabel     string
	HandlerLabel string
}

// Method is the typed IR of a single method.
type Method struct {
	Name        string
	AccessFlags uint32 // DEX access flags; text-origin: parsed flag bits where available
	IsStatic    bool
	ReturnType  string   // descriptor, e.g. "V"
	Params      []string // parameter descriptors (excludes implicit 'this')

	RegistersSize int // total v-registers (.registers); -1 = unknown
	Locals        int // .locals count; -1 = unknown
	InsSize       int // parameter registers count from code_item (DEX only)
	OutsSize      int // outgoing call arg slots (DEX only)

	// ParamRegisters maps parameter index -> starting v-register
	// (p0 = RegistersSize-InsSize). Only populated by the DEX adapter.
	ParamRegisters []int32

	Instructions []*Instruction
	Labels       []*Label
	TryCatches   []*TryCatch

	// Annotations: at minimum presence + simple key values.
	Annotations []*Annotation

	LineStart int // 1-based line of .method directive (text-origin)
	LineEnd   int // 1-based line of .end method (text-origin)
}

// RegisterCount returns the authoritative register count:
// RegistersSize when known, otherwise Locals+param-width when Locals
// is known, else 0.
func (m *Method) RegisterCount() int {
	if m.RegistersSize >= 0 {
		return m.RegistersSize
	}
	if m.Locals >= 0 {
		total := m.Locals + m.paramRegisterWidth()
		if !m.IsStatic {
			total++ // implicit 'this'
		}
		return total
	}
	return 0
}

// paramRegisterWidth returns the number of registers consumed by the
// declared parameters (long/double take 2).
func (m *Method) paramRegisterWidth() int {
	w := 0
	for _, p := range m.Params {
		if p == "J" || p == "D" {
			w += 2
		} else {
			w++
		}
	}
	return w
}

// ResolvePRegisters rewrites negative p-register encodings in all
// instructions of m into absolute v-registers using the total register
// count (p0 = total - paramWidth). Text-origin IR emits p-registers as
// -(N+2) sentinels because the register count is only known after the
// .registers/.locals directives are parsed; call this (idempotent)
// before reading registers. Requires m.RegistersSize > 0.
func ResolvePRegisters(m *Method) {
	if m == nil || m.RegistersSize <= 0 {
		return
	}
	total := int32(m.RegistersSize)
	paramWidth := int32(m.paramRegisterWidth())
	if !m.IsStatic {
		paramWidth++
	}
	base := total - paramWidth
	fix := func(r int32) int32 {
		if r < NoRegister {
			return base + (-(r + 2))
		}
		return r
	}
	for _, ins := range m.Instructions {
		if ins == nil {
			continue
		}
		ins.Dst = fix(ins.Dst)
		for i, r := range ins.Srcs {
			ins.Srcs[i] = fix(r)
		}
	}
}

// Field is a typed class field.
type Field struct {
	Name        string
	Type        string // descriptor
	AccessFlags uint32
	IsStatic    bool
	Annotations []*Annotation
}

// Annotation captures annotation presence and, where available, simple
// encoded-name/value pairs. Values are stored in their smali literal
// form (e.g. `"text"` for strings, `0x1` for ints).
type Annotation struct {
	Type   string            // descriptor, e.g. "Ldalvik/annotation/Signature;"
	Values map[string]string // may be empty; nil-safe via helper
}

// Get returns the value for key, or "" when absent.
func (a *Annotation) Get(key string) string {
	if a == nil || a.Values == nil {
		return ""
	}
	return a.Values[key]
}

// Class is the typed IR of a single class.
type Class struct {
	Descriptor  string // e.g. "Lcom/example/Foo;"
	SuperClass  string // descriptor, or "" for java.lang.Object root
	Interfaces  []string
	SourceFile  string
	AccessFlags uint32

	Fields  []*Field
	Methods []*Method

	Annotations []*Annotation
}

// ClassName returns the dotted Java-style class name
// (e.g. "com.example.Foo").
func (c *Class) ClassName() string {
	d := c.Descriptor
	if strings.HasPrefix(d, "L") && strings.HasSuffix(d, ";") {
		d = d[1 : len(d)-1]
	}
	return strings.ReplaceAll(d, "/", ".")
}

// FindMethod returns the method with the given name and prototype
// ("" matches any proto), or nil.
func (c *Class) FindMethod(name, proto string) *Method {
	for _, m := range c.Methods {
		if m.Name != name {
			continue
		}
		if proto == "" {
			return m
		}
		if buildProto(m) == proto {
			return m
		}
	}
	return nil
}

// buildProto renders "(params)return" for a method.
func buildProto(m *Method) string {
	var b strings.Builder
	b.WriteByte('(')
	for _, p := range m.Params {
		b.WriteString(p)
	}
	b.WriteByte(')')
	b.WriteString(m.ReturnType)
	return b.String()
}
