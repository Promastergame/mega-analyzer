package apkloader

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════
// ФОРМАТЫ ИНСТРУКЦИЙ
// ═══════════════════════════════════════════

type InsnFormat uint8

const (
	Fmt10x InsnFormat = iota
	Fmt12x
	Fmt11n
	Fmt11x
	Fmt10t
	Fmt20t
	Fmt22x
	Fmt21t
	Fmt21s
	Fmt21h
	Fmt21c
	Fmt23x
	Fmt22b
	Fmt22t
	Fmt22s
	Fmt22c
	Fmt30t
	Fmt32x
	Fmt31i
	Fmt31t // same encoding as Fmt31i but for branch targets
	Fmt31c
	Fmt35c
	Fmt3rc
	Fmt51l
	Fmt45cc
	Fmt4rcc
	FmtUnknown
)

type OpcodeInfo struct {
	Name   string
	Format InsnFormat
	Size   uint32
}

var opcodeTable [256]OpcodeInfo

func init() {
	for i := range opcodeTable {
		opcodeTable[i] = OpcodeInfo{
			Name:   fmt.Sprintf("unknown_%02x", i),
			Format: FmtUnknown,
			Size:   1,
		}
	}

	// NOP и pseudo-opcodes
	set(0x00, "nop", Fmt10x, 1)

	// MOVE
	set(0x01, "move", Fmt12x, 1)
	set(0x02, "move/from16", Fmt22x, 2)
	set(0x03, "move/16", Fmt32x, 3)
	set(0x04, "move-wide", Fmt12x, 1)
	set(0x05, "move-wide/from16", Fmt22x, 2)
	set(0x06, "move-wide/16", Fmt32x, 3)
	set(0x07, "move-object", Fmt12x, 1)
	set(0x08, "move-object/from16", Fmt22x, 2)
	set(0x09, "move-object/16", Fmt32x, 3)

	// MOVE-RESULT
	set(0x0A, "move-result", Fmt11x, 1)
	set(0x0B, "move-result-wide", Fmt11x, 1)
	set(0x0C, "move-result-object", Fmt11x, 1)
	set(0x0D, "move-exception", Fmt11x, 1)

	// RETURN
	set(0x0E, "return-void", Fmt10x, 1)
	set(0x0F, "return", Fmt11x, 1)
	set(0x10, "return-wide", Fmt11x, 1)
	set(0x11, "return-object", Fmt11x, 1)

	// CONST
	set(0x12, "const/4", Fmt11n, 1)
	set(0x13, "const/16", Fmt21s, 2)
	set(0x14, "const", Fmt31i, 3)
	set(0x15, "const/high16", Fmt21h, 2)
	set(0x16, "const-wide/16", Fmt21s, 2)
	set(0x17, "const-wide/32", Fmt31i, 3)
	set(0x18, "const-wide", Fmt51l, 5)
	set(0x19, "const-wide/high16", Fmt21h, 2)
	set(0x1A, "const-string", Fmt21c, 2)
	set(0x1B, "const-string/jumbo", Fmt31c, 3)
	set(0x1C, "const-class", Fmt21c, 2)

	// MONITOR
	set(0x1D, "monitor-enter", Fmt11x, 1)
	set(0x1E, "monitor-exit", Fmt11x, 1)

	// CHECK / INSTANCE
	set(0x1F, "check-cast", Fmt21c, 2)
	set(0x20, "instance-of", Fmt22c, 2)

	// ARRAY
	set(0x21, "array-length", Fmt12x, 1)
	set(0x22, "new-instance", Fmt21c, 2)
	set(0x23, "new-array", Fmt22c, 2)
	set(0x24, "filled-new-array", Fmt35c, 3)
	set(0x25, "filled-new-array/range", Fmt3rc, 3)
	set(0x26, "fill-array-data", Fmt31i, 3)

	// THROW
	set(0x27, "throw", Fmt11x, 1)

	// GOTO
	set(0x28, "goto", Fmt10t, 1)
	set(0x29, "goto/16", Fmt20t, 2)
	set(0x2A, "goto/32", Fmt30t, 3)

	// SWITCH
	set(0x2B, "packed-switch", Fmt31i, 3)
	set(0x2C, "sparse-switch", Fmt31i, 3)

	// CMP
	set(0x2D, "cmpl-float", Fmt23x, 2)
	set(0x2E, "cmpg-float", Fmt23x, 2)
	set(0x2F, "cmpl-double", Fmt23x, 2)
	set(0x30, "cmpg-double", Fmt23x, 2)
	set(0x31, "cmp-long", Fmt23x, 2)

	// IF (2 regs)
	set(0x32, "if-eq", Fmt22t, 2)
	set(0x33, "if-ne", Fmt22t, 2)
	set(0x34, "if-lt", Fmt22t, 2)
	set(0x35, "if-ge", Fmt22t, 2)
	set(0x36, "if-gt", Fmt22t, 2)
	set(0x37, "if-le", Fmt22t, 2)

	// IF (1 reg, vs zero)
	set(0x38, "if-eqz", Fmt21t, 2)
	set(0x39, "if-nez", Fmt21t, 2)
	set(0x3A, "if-ltz", Fmt21t, 2)
	set(0x3B, "if-gez", Fmt21t, 2)
	set(0x3C, "if-gtz", Fmt21t, 2)
	set(0x3D, "if-lez", Fmt21t, 2)

	// AGET
	set(0x44, "aget", Fmt23x, 2)
	set(0x45, "aget-wide", Fmt23x, 2)
	set(0x46, "aget-object", Fmt23x, 2)
	set(0x47, "aget-boolean", Fmt23x, 2)
	set(0x48, "aget-byte", Fmt23x, 2)
	set(0x49, "aget-char", Fmt23x, 2)
	set(0x4A, "aget-short", Fmt23x, 2)

	// APUT
	set(0x4B, "aput", Fmt23x, 2)
	set(0x4C, "aput-wide", Fmt23x, 2)
	set(0x4D, "aput-object", Fmt23x, 2)
	set(0x4E, "aput-boolean", Fmt23x, 2)
	set(0x4F, "aput-byte", Fmt23x, 2)
	set(0x50, "aput-char", Fmt23x, 2)
	set(0x51, "aput-short", Fmt23x, 2)

	// IGET
	set(0x52, "iget", Fmt22c, 2)
	set(0x53, "iget-wide", Fmt22c, 2)
	set(0x54, "iget-object", Fmt22c, 2)
	set(0x55, "iget-boolean", Fmt22c, 2)
	set(0x56, "iget-byte", Fmt22c, 2)
	set(0x57, "iget-char", Fmt22c, 2)
	set(0x58, "iget-short", Fmt22c, 2)

	// IPUT
	set(0x59, "iput", Fmt22c, 2)
	set(0x5A, "iput-wide", Fmt22c, 2)
	set(0x5B, "iput-object", Fmt22c, 2)
	set(0x5C, "iput-boolean", Fmt22c, 2)
	set(0x5D, "iput-byte", Fmt22c, 2)
	set(0x5E, "iput-char", Fmt22c, 2)
	set(0x5F, "iput-short", Fmt22c, 2)

	// SGET
	set(0x60, "sget", Fmt21c, 2)
	set(0x61, "sget-wide", Fmt21c, 2)
	set(0x62, "sget-object", Fmt21c, 2)
	set(0x63, "sget-boolean", Fmt21c, 2)
	set(0x64, "sget-byte", Fmt21c, 2)
	set(0x65, "sget-char", Fmt21c, 2)
	set(0x66, "sget-short", Fmt21c, 2)

	// SPUT
	set(0x67, "sput", Fmt21c, 2)
	set(0x68, "sput-wide", Fmt21c, 2)
	set(0x69, "sput-object", Fmt21c, 2)
	set(0x6A, "sput-boolean", Fmt21c, 2)
	set(0x6B, "sput-byte", Fmt21c, 2)
	set(0x6C, "sput-char", Fmt21c, 2)
	set(0x6D, "sput-short", Fmt21c, 2)

	// INVOKE
	set(0x6E, "invoke-virtual", Fmt35c, 3)
	set(0x6F, "invoke-super", Fmt35c, 3)
	set(0x70, "invoke-direct", Fmt35c, 3)
	set(0x71, "invoke-static", Fmt35c, 3)
	set(0x72, "invoke-interface", Fmt35c, 3)

	// INVOKE/RANGE
	set(0x74, "invoke-virtual/range", Fmt3rc, 3)
	set(0x75, "invoke-super/range", Fmt3rc, 3)
	set(0x76, "invoke-direct/range", Fmt3rc, 3)
	set(0x77, "invoke-static/range", Fmt3rc, 3)
	set(0x78, "invoke-interface/range", Fmt3rc, 3)

	// UNARY
	set(0x7B, "neg-int", Fmt12x, 1)
	set(0x7C, "not-int", Fmt12x, 1)
	set(0x7D, "neg-long", Fmt12x, 1)
	set(0x7E, "not-long", Fmt12x, 1)
	set(0x7F, "neg-float", Fmt12x, 1)
	set(0x80, "neg-double", Fmt12x, 1)

	// CONVERSION
	set(0x81, "int-to-long", Fmt12x, 1)
	set(0x82, "int-to-float", Fmt12x, 1)
	set(0x83, "int-to-double", Fmt12x, 1)
	set(0x84, "long-to-int", Fmt12x, 1)
	set(0x85, "long-to-float", Fmt12x, 1)
	set(0x86, "long-to-double", Fmt12x, 1)
	set(0x87, "float-to-int", Fmt12x, 1)
	set(0x88, "float-to-long", Fmt12x, 1)
	set(0x89, "float-to-double", Fmt12x, 1)
	set(0x8A, "double-to-int", Fmt12x, 1)
	set(0x8B, "double-to-long", Fmt12x, 1)
	set(0x8C, "double-to-float", Fmt12x, 1)
	set(0x8D, "int-to-byte", Fmt12x, 1)
	set(0x8E, "int-to-char", Fmt12x, 1)
	set(0x8F, "int-to-short", Fmt12x, 1)

	// BINOP 23x
	set(0x90, "add-int", Fmt23x, 2)
	set(0x91, "sub-int", Fmt23x, 2)
	set(0x92, "mul-int", Fmt23x, 2)
	set(0x93, "div-int", Fmt23x, 2)
	set(0x94, "rem-int", Fmt23x, 2)
	set(0x95, "and-int", Fmt23x, 2)
	set(0x96, "or-int", Fmt23x, 2)
	set(0x97, "xor-int", Fmt23x, 2)
	set(0x98, "shl-int", Fmt23x, 2)
	set(0x99, "shr-int", Fmt23x, 2)
	set(0x9A, "ushr-int", Fmt23x, 2)
	set(0x9B, "add-long", Fmt23x, 2)
	set(0x9C, "sub-long", Fmt23x, 2)
	set(0x9D, "mul-long", Fmt23x, 2)
	set(0x9E, "div-long", Fmt23x, 2)
	set(0x9F, "rem-long", Fmt23x, 2)
	set(0xA0, "and-long", Fmt23x, 2)
	set(0xA1, "or-long", Fmt23x, 2)
	set(0xA2, "xor-long", Fmt23x, 2)
	set(0xA3, "shl-long", Fmt23x, 2)
	set(0xA4, "shr-long", Fmt23x, 2)
	set(0xA5, "ushr-long", Fmt23x, 2)
	set(0xA6, "add-float", Fmt23x, 2)
	set(0xA7, "sub-float", Fmt23x, 2)
	set(0xA8, "mul-float", Fmt23x, 2)
	set(0xA9, "div-float", Fmt23x, 2)
	set(0xAA, "rem-float", Fmt23x, 2)
	set(0xAB, "add-double", Fmt23x, 2)
	set(0xAC, "sub-double", Fmt23x, 2)
	set(0xAD, "mul-double", Fmt23x, 2)
	set(0xAE, "div-double", Fmt23x, 2)
	set(0xAF, "rem-double", Fmt23x, 2)

	// BINOP/2ADDR 12x
	set(0xB0, "add-int/2addr", Fmt12x, 1)
	set(0xB1, "sub-int/2addr", Fmt12x, 1)
	set(0xB2, "mul-int/2addr", Fmt12x, 1)
	set(0xB3, "div-int/2addr", Fmt12x, 1)
	set(0xB4, "rem-int/2addr", Fmt12x, 1)
	set(0xB5, "and-int/2addr", Fmt12x, 1)
	set(0xB6, "or-int/2addr", Fmt12x, 1)
	set(0xB7, "xor-int/2addr", Fmt12x, 1)
	set(0xB8, "shl-int/2addr", Fmt12x, 1)
	set(0xB9, "shr-int/2addr", Fmt12x, 1)
	set(0xBA, "ushr-int/2addr", Fmt12x, 1)
	set(0xBB, "add-long/2addr", Fmt12x, 1)
	set(0xBC, "sub-long/2addr", Fmt12x, 1)
	set(0xBD, "mul-long/2addr", Fmt12x, 1)
	set(0xBE, "div-long/2addr", Fmt12x, 1)
	set(0xBF, "rem-long/2addr", Fmt12x, 1)
	set(0xC0, "and-long/2addr", Fmt12x, 1)
	set(0xC1, "or-long/2addr", Fmt12x, 1)
	set(0xC2, "xor-long/2addr", Fmt12x, 1)
	set(0xC3, "shl-long/2addr", Fmt12x, 1)
	set(0xC4, "shr-long/2addr", Fmt12x, 1)
	set(0xC5, "ushr-long/2addr", Fmt12x, 1)
	set(0xC6, "add-float/2addr", Fmt12x, 1)
	set(0xC7, "sub-float/2addr", Fmt12x, 1)
	set(0xC8, "mul-float/2addr", Fmt12x, 1)
	set(0xC9, "div-float/2addr", Fmt12x, 1)
	set(0xCA, "rem-float/2addr", Fmt12x, 1)
	set(0xCB, "add-double/2addr", Fmt12x, 1)
	set(0xCC, "sub-double/2addr", Fmt12x, 1)
	set(0xCD, "mul-double/2addr", Fmt12x, 1)
	set(0xCE, "div-double/2addr", Fmt12x, 1)
	set(0xCF, "rem-double/2addr", Fmt12x, 1)

	// BINOP/LIT16
	set(0xD0, "add-int/lit16", Fmt22s, 2)
	set(0xD1, "rsub-int", Fmt22s, 2)
	set(0xD2, "mul-int/lit16", Fmt22s, 2)
	set(0xD3, "div-int/lit16", Fmt22s, 2)
	set(0xD4, "rem-int/lit16", Fmt22s, 2)
	set(0xD5, "and-int/lit16", Fmt22s, 2)
	set(0xD6, "or-int/lit16", Fmt22s, 2)
	set(0xD7, "xor-int/lit16", Fmt22s, 2)

	// BINOP/LIT8
	set(0xD8, "add-int/lit8", Fmt22b, 2)
	set(0xD9, "rsub-int/lit8", Fmt22b, 2)
	set(0xDA, "mul-int/lit8", Fmt22b, 2)
	set(0xDB, "div-int/lit8", Fmt22b, 2)
	set(0xDC, "rem-int/lit8", Fmt22b, 2)
	set(0xDD, "and-int/lit8", Fmt22b, 2)
	set(0xDE, "or-int/lit8", Fmt22b, 2)
	set(0xDF, "xor-int/lit8", Fmt22b, 2)
	set(0xE0, "shl-int/lit8", Fmt22b, 2)
	set(0xE1, "shr-int/lit8", Fmt22b, 2)
	set(0xE2, "ushr-int/lit8", Fmt22b, 2)
	set(0xFA, "invoke-polymorphic", Fmt45cc, 4)
	set(0xFB, "invoke-polymorphic/range", Fmt4rcc, 4)
	set(0xFC, "invoke-custom", Fmt35c, 3)
	set(0xFD, "invoke-custom/range", Fmt3rc, 3)
	set(0xFE, "const-method-handle", Fmt21c, 2)
	set(0xFF, "const-method-type", Fmt21c, 2)
}

func set(op int, name string, format InsnFormat, size uint32) {
	opcodeTable[op] = OpcodeInfo{Name: name, Format: format, Size: size}
}

// ═══════════════════════════════════════════
// ДЕКОДЕР ИНСТРУКЦИЙ
// ═══════════════════════════════════════════

// DecodeInsn — ПУНКТ 5: принимает парсер для резолва сигнатур
func DecodeInsn(insns []uint16, pos uint32, payloads map[uint32]bool, resolver *DEXParser) (string, uint32) {
	if pos >= uint32(len(insns)) {
		return "# end", 1
	}

	// Payload check
	if payloads != nil && payloads[pos] {
		return decodePayload(insns, pos)
	}

	insn := insns[pos]
	opcode := uint8(insn & 0xFF)

	// Pseudo-opcode payload
	if opcode == 0x00 && insn != 0x0000 {
		switch insn {
		case 0x0100:
			return decodePackedSwitchPayload(insns, pos)
		case 0x0200:
			return decodeSparseSwitchPayload(insns, pos)
		case 0x0300:
			return decodeFillArrayPayload(insns, pos)
		}
	}

	info := opcodeTable[opcode]

	if pos+info.Size > uint32(len(insns)) {
		return fmt.Sprintf("# truncated %s", info.Name), info.Size
	}

	switch info.Format {
	case Fmt10x:
		return info.Name, info.Size

	case Fmt12x:
		a := (insn >> 8) & 0xF
		b := (insn >> 12) & 0xF
		return fmt.Sprintf("%s v%d, v%d", info.Name, a, b), info.Size

	case Fmt11n:
		a := (insn >> 8) & 0xF
		b := int32((insn >> 12) & 0xF)
		if b&0x8 != 0 {
			b |= ^int32(0xF) // sign extend 4-bit
		}
		return fmt.Sprintf("%s v%d, %d", info.Name, a, b), info.Size

	case Fmt11x:
		a := (insn >> 8) & 0xFF
		return fmt.Sprintf("%s v%d", info.Name, a), info.Size

	case Fmt10t:
		a := int8((insn >> 8) & 0xFF)
		return fmt.Sprintf("%s %+d", info.Name, a), info.Size

	case Fmt20t:
		a := int16(insns[pos+1])
		return fmt.Sprintf("%s %+d", info.Name, a), info.Size

	case Fmt22x:
		a := (insn >> 8) & 0xFF
		b := insns[pos+1]
		return fmt.Sprintf("%s v%d, v%d", info.Name, a, b), info.Size

	case Fmt21t:
		a := (insn >> 8) & 0xFF
		b := int16(insns[pos+1])
		return fmt.Sprintf("%s v%d, %+d", info.Name, a, b), info.Size

	case Fmt21s:
		a := (insn >> 8) & 0xFF
		b := int16(insns[pos+1])
		return fmt.Sprintf("%s v%d, %d", info.Name, a, b), info.Size

	case Fmt21h:
		a := (insn >> 8) & 0xFF
		b := insns[pos+1]
		if opcode == 0x15 {
			return fmt.Sprintf("%s v%d, 0x%x", info.Name, a, uint32(b)<<16), info.Size
		}
		return fmt.Sprintf("%s v%d, 0x%x", info.Name, a, uint64(b)<<48), info.Size

	case Fmt21c:
		a := (insn >> 8) & 0xFF
		b := insns[pos+1]
		// ПУНКТ 5: резолвим ссылки если есть парсер
		ref := resolveRef(opcode, uint32(b), resolver)
		return fmt.Sprintf("%s v%d, %s", info.Name, a, ref), info.Size

	case Fmt23x:
		a := (insn >> 8) & 0xFF
		b := insns[pos+1] & 0xFF
		c := (insns[pos+1] >> 8) & 0xFF
		return fmt.Sprintf("%s v%d, v%d, v%d", info.Name, a, b, c), info.Size

	case Fmt22b:
		a := (insn >> 8) & 0xFF
		b := insns[pos+1] & 0xFF
		c := int8(insns[pos+1] >> 8)
		return fmt.Sprintf("%s v%d, v%d, %d", info.Name, a, b, c), info.Size

	case Fmt22t:
		a := (insn >> 8) & 0xF
		b := (insn >> 12) & 0xF
		c := int16(insns[pos+1])
		return fmt.Sprintf("%s v%d, v%d, %+d", info.Name, a, b, c), info.Size

	case Fmt22s:
		a := (insn >> 8) & 0xF
		b := (insn >> 12) & 0xF
		c := int16(insns[pos+1])
		return fmt.Sprintf("%s v%d, v%d, %d", info.Name, a, b, c), info.Size

	case Fmt22c:
		a := (insn >> 8) & 0xF
		b := (insn >> 12) & 0xF
		c := insns[pos+1]
		ref := resolveRef(opcode, uint32(c), resolver)
		return fmt.Sprintf("%s v%d, v%d, %s", info.Name, a, b, ref), info.Size

	case Fmt30t:
		lo := uint32(insns[pos+1])
		hi := uint32(insns[pos+2])
		offset := int32(lo | (hi << 16))
		return fmt.Sprintf("%s %+d", info.Name, offset), info.Size

	case Fmt32x:
		a := insns[pos+1]
		b := insns[pos+2]
		return fmt.Sprintf("%s v%d, v%d", info.Name, a, b), info.Size

	case Fmt31i:
		a := (insn >> 8) & 0xFF
		lo := uint32(insns[pos+1])
		hi := uint32(insns[pos+2])
		val := lo | (hi << 16)
		return fmt.Sprintf("%s v%d, 0x%x", info.Name, a, val), info.Size

	case Fmt31c:
		a := (insn >> 8) & 0xFF
		lo := uint32(insns[pos+1])
		hi := uint32(insns[pos+2])
		idx := lo | (hi << 16)
		ref := resolveString(idx, resolver)
		return fmt.Sprintf("%s v%d, %s", info.Name, a, ref), info.Size

	case Fmt35c:
		return decode35c(info.Name, insns, pos, resolver)
	case Fmt45cc:
		text, _ := decode35c(info.Name, insns, pos, resolver)
		return text + ", " + resolver.protoDescriptor(uint32(insns[pos+3])), 4

	case Fmt3rc:
		return decode3rc(info.Name, insns, pos, resolver)
	case Fmt4rcc:
		text, _ := decode3rc(info.Name, insns, pos, resolver)
		return text + ", " + resolver.protoDescriptor(uint32(insns[pos+3])), 4

	case Fmt51l:
		a := (insn >> 8) & 0xFF
		val := uint64(insns[pos+1]) |
			uint64(insns[pos+2])<<16 |
			uint64(insns[pos+3])<<32 |
			uint64(insns[pos+4])<<48
		return fmt.Sprintf("%s v%d, 0x%x", info.Name, a, val), info.Size

	default:
		return fmt.Sprintf("# unknown 0x%02x", opcode), info.Size
	}
}

// ═══════════════════════════════════════════
// ПУНКТ 5: резолв ссылок method/field/type/string
// ═══════════════════════════════════════════

// resolveRef резолвит ссылку по типу опкода
func resolveRef(opcode uint8, idx uint32, resolver *DEXParser) string {
	switch opcode {
	case 0xfa, 0xfb: return resolveMethod(idx, resolver)
	case 0xfc, 0xfd: return resolver.callSiteText(idx)
	case 0xfe: return resolver.methodHandleText(idx)
	case 0xff: return resolver.protoDescriptor(idx)
	case 0x24, 0x25: return resolveType(idx, resolver)
	}
	if resolver == nil {
		return fallbackRef(opcode, idx)
	}

	switch {
	// String refs
	case opcode == 0x1A || opcode == 0x1B:
		return resolveString(idx, resolver)

	// Type refs
	case opcode == 0x1C || opcode == 0x1F ||
		opcode == 0x20 || opcode == 0x22 || opcode == 0x23:
		return resolveType(idx, resolver)

	// Field refs (iget/iput/sget/sput)
	case opcode >= 0x52 && opcode <= 0x6D:
		return resolveField(idx, resolver)

	// Method refs (invoke)
	case opcode >= 0x6E && opcode <= 0x78:
		return resolveMethod(idx, resolver)

	default:
		return fallbackRef(opcode, idx)
	}
}

func resolveString(idx uint32, resolver *DEXParser) string {
	if resolver == nil || idx >= uint32(len(resolver.strings)) {
		return fmt.Sprintf("string@%04x", idx)
	}
	return quoteSmaliString(resolver.strings[idx])
}

// Replacer is safe for concurrent use. Building its lookup table for every
// const-string dominated allocation costs in string-heavy DEX classes.
var smaliStringEscaper = func() *strings.Replacer {
	pairs := []string{"\\", "\\\\", "\"", "\\\"", "\n", "\\n", "\r", "\\r", "\t", "\\t", "\b", "\\b", "\f", "\\f"}
	for c := byte(0); c < 0x20; c++ {
		if c == '\n' || c == '\r' || c == '\t' || c == '\b' || c == '\f' {
			continue
		}
		pairs = append(pairs, string([]byte{c}), fmt.Sprintf("\\u%04x", c))
	}
	pairs = append(pairs, "\x7f", "\\u007f")
	return strings.NewReplacer(pairs...)
}()

func quoteSmaliString(s string) string {
	return "\"" + smaliStringEscaper.Replace(s) + "\""
}

func resolveType(idx uint32, resolver *DEXParser) string {
	if resolver == nil {
		return fmt.Sprintf("type@%04x", idx)
	}
	t := resolver.getType(idx)
	if t == "" {
		return fmt.Sprintf("type@%04x", idx)
	}
	return t
}

func resolveField(idx uint32, resolver *DEXParser) string {
	if resolver == nil || idx >= uint32(len(resolver.fields)) {
		return fmt.Sprintf("field@%04x", idx)
	}
	f := resolver.fields[idx]
	if f == nil || f.ClassName == "" {
		return fmt.Sprintf("field@%04x", idx)
	}
	// Lclass;->name:type
	return fmt.Sprintf("%s->%s:%s", f.ClassName, f.FieldName, f.TypeName)
}

func resolveMethod(idx uint32, resolver *DEXParser) string {
	if resolver == nil || idx >= uint32(len(resolver.methods)) {
		return fmt.Sprintf("method@%04x", idx)
	}
	m := resolver.methods[idx]
	if m == nil || m.ClassName == "" {
		return fmt.Sprintf("method@%04x", idx)
	}

	// Lclass;->name(Params)ReturnType
	var params strings.Builder
	for _, p := range m.Parameters {
		params.WriteString(p)
	}

	ret := m.ReturnType
	if ret == "" {
		ret = "V"
	}

	return fmt.Sprintf("%s->%s(%s)%s", m.ClassName, m.MethodName, params.String(), ret)
}

func fallbackRef(opcode uint8, idx uint32) string {
	kind := opcodeRefKind(opcode)
	return fmt.Sprintf("%s@%04x", kind, idx)
}

// ═══════════════════════════════════════════
// INVOKE декодеры — теперь с резолвом
// ═══════════════════════════════════════════

func decode35c(name string, insns []uint16, pos uint32, resolver *DEXParser) (string, uint32) {
	if pos+2 >= uint32(len(insns)) {
		return name + " # truncated", 3
	}

	insn := insns[pos]
	argCount := (insn >> 12) & 0xF
	methodIdx := insns[pos+1]
	regWord := insns[pos+2]

	regs := make([]string, 0, argCount)
	if argCount >= 1 {
		regs = append(regs, fmt.Sprintf("v%d", regWord&0xF))
	}
	if argCount >= 2 {
		regs = append(regs, fmt.Sprintf("v%d", (regWord>>4)&0xF))
	}
	if argCount >= 3 {
		regs = append(regs, fmt.Sprintf("v%d", (regWord>>8)&0xF))
	}
	if argCount >= 4 {
		regs = append(regs, fmt.Sprintf("v%d", (regWord>>12)&0xF))
	}
	if argCount >= 5 {
		regs = append(regs, fmt.Sprintf("v%d", (insn>>8)&0xF))
	}

	// ПУНКТ 5: реальная сигнатура
	ref := resolveRef(uint8(insns[pos]), uint32(methodIdx), resolver)

	return fmt.Sprintf("%s {%s}, %s",
		name, strings.Join(regs, ", "), ref), 3
}

func decode3rc(name string, insns []uint16, pos uint32, resolver *DEXParser) (string, uint32) {
	if pos+2 >= uint32(len(insns)) {
		return name + " # truncated", 3
	}

	argCount := (insns[pos] >> 8) & 0xFF
	methodIdx := insns[pos+1]
	startReg := insns[pos+2]

	ref := resolveRef(uint8(insns[pos]), uint32(methodIdx), resolver)

	if argCount == 0 {
		return fmt.Sprintf("%s {}, %s", name, ref), 3
	}
	if argCount == 1 {
		return fmt.Sprintf("%s {v%d}, %s", name, startReg, ref), 3
	}
	return fmt.Sprintf("%s {v%d .. v%d}, %s",
		name, startReg, startReg+uint16(argCount)-1, ref), 3
}

// ═══════════════════════════════════════════
// PAYLOAD декодеры — ПУНКТ 3 + 4
// ═══════════════════════════════════════════

func decodePayload(insns []uint16, pos uint32) (string, uint32) {
	if pos >= uint32(len(insns)) {
		return "# payload end", 1
	}

	ident := insns[pos]
	switch ident {
	case 0x0100:
		return decodePackedSwitchPayload(insns, pos)
	case 0x0200:
		return decodeSparseSwitchPayload(insns, pos)
	case 0x0300:
		return decodeFillArrayPayload(insns, pos)
	default:
		return "nop", 1
	}
}

// ПУНКТ 3: проверяем выравнивание
func decodePackedSwitchPayload(insns []uint16, pos uint32) (string, uint32) {
	if pos+4 > uint32(len(insns)) {
		return ".packed-switch # truncated", 2
	}

	size := insns[pos+1]
	totalSize := uint32(4) + uint32(size)*2

	if pos+totalSize > uint32(len(insns)) {
		return fmt.Sprintf(".packed-switch # truncated (size=%d)", size), totalSize
	}

	firstKey := int32(uint32(insns[pos+2]) | uint32(insns[pos+3])<<16)

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf(".packed-switch %#x", firstKey))

	for i := uint16(0); i < size; i++ {
		tPos := pos + 4 + uint32(i)*2
		if tPos+1 >= uint32(len(insns)) {
			break
		}
		target := int32(uint32(insns[tPos]) | uint32(insns[tPos+1])<<16)
		buf.WriteString(fmt.Sprintf("\n        %+d", target))
	}
	buf.WriteString("\n    .end packed-switch")

	return buf.String(), totalSize
}

func decodeSparseSwitchPayload(insns []uint16, pos uint32) (string, uint32) {
	if pos+2 > uint32(len(insns)) {
		return ".sparse-switch # truncated", 2
	}

	size := insns[pos+1]
	totalSize := uint32(2) + uint32(size)*4

	if pos+totalSize > uint32(len(insns)) {
		return fmt.Sprintf(".sparse-switch # truncated (size=%d)", size), totalSize
	}

	var buf strings.Builder
	buf.WriteString(".sparse-switch")

	keysStart := pos + 2
	targetsStart := keysStart + uint32(size)*2

	for i := uint16(0); i < size; i++ {
		kPos := keysStart + uint32(i)*2
		tPos := targetsStart + uint32(i)*2

		if kPos+1 >= uint32(len(insns)) || tPos+1 >= uint32(len(insns)) {
			break
		}

		key := int32(uint32(insns[kPos]) | uint32(insns[kPos+1])<<16)
		target := int32(uint32(insns[tPos]) | uint32(insns[tPos+1])<<16)

		buf.WriteString(fmt.Sprintf("\n        %#x -> %+d", key, target))
	}
	buf.WriteString("\n    .end sparse-switch")

	return buf.String(), totalSize
}

// ПУНКТ 4: fill-array теперь выводит реальные значения
func decodeFillArrayPayload(insns []uint16, pos uint32) (string, uint32) {
	if pos+4 > uint32(len(insns)) {
		return ".array-data # truncated", 4
	}

	elemWidth := insns[pos+1]
	size := uint32(insns[pos+2]) | uint32(insns[pos+3])<<16

	dataBytes := uint64(size) * uint64(elemWidth)
	dataWords := (dataBytes + 1) / 2
	totalSize := uint32(4) + uint32(dataWords)

	if pos+totalSize > uint32(len(insns)) {
		return fmt.Sprintf(".array-data %d # truncated", elemWidth), totalSize
	}

	var buf strings.Builder
	buf.WriteString(fmt.Sprintf(".array-data %d", elemWidth))

	// Данные начинаются с pos+4 (в 16-bit словах)
	dataStart := pos + 4

	for i := uint32(0); i < size; i++ {
		byteOffset := i * uint32(elemWidth)
		wordOffset := dataStart + byteOffset/2

		switch elemWidth {
		case 1: // byte
			if wordOffset < uint32(len(insns)) {
				word := insns[wordOffset]
				if byteOffset%2 == 0 {
					buf.WriteString(fmt.Sprintf("\n        0x%02x", word&0xFF))
				} else {
					buf.WriteString(fmt.Sprintf("\n        0x%02x", (word>>8)&0xFF))
				}
			}

		case 2: // short
			if wordOffset < uint32(len(insns)) {
				buf.WriteString(fmt.Sprintf("\n        0x%04x", insns[wordOffset]))
			}

		case 4: // int/float
			if wordOffset+1 < uint32(len(insns)) {
				val := uint32(insns[wordOffset]) | uint32(insns[wordOffset+1])<<16
				buf.WriteString(fmt.Sprintf("\n        0x%08x", val))
			}

		case 8: // long/double
			if wordOffset+3 < uint32(len(insns)) {
				val := uint64(insns[wordOffset]) |
					uint64(insns[wordOffset+1])<<16 |
					uint64(insns[wordOffset+2])<<32 |
					uint64(insns[wordOffset+3])<<48
				buf.WriteString(fmt.Sprintf("\n        0x%016x", val))
			}

		default:
			buf.WriteString(fmt.Sprintf("\n        # elem[%d] width=%d", i, elemWidth))
		}
	}

	buf.WriteString("\n    .end array-data")

	return buf.String(), totalSize
}

func opcodeRefKind(opcode uint8) string {
	switch {
	case opcode == 0x1A || opcode == 0x1B:
		return "string"
	case opcode == 0x1C || opcode == 0x1F || opcode == 0x20 ||
		opcode == 0x22 || opcode == 0x23:
		return "type"
	case opcode >= 0x52 && opcode <= 0x6D:
		return "field"
	case opcode >= 0x6E && opcode <= 0x78:
		return "method"
	default:
		return "ref"
	}
}
