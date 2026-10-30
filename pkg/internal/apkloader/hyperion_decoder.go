package apkloader

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Structural Instruction Decoder
// ═══════════════════════════════════════════════════════════════════════════════
//
// Decodes Dalvik bytecode into RawInsn structs — ZERO string allocations.
// This replaces the old DecodeInsn() which returned fmt.Sprintf strings.
//
// Performance: ~500k instructions/sec on a single core (target: >1M with arena).

// DecodeMethodIR decodes an entire method's bytecode into a RawInsn slice.
// Uses the provided arena for allocation if non-nil, otherwise allocates on heap.
func DecodeMethodIR(insns []uint16, arena *Arena) []RawInsn {
	if len(insns) == 0 {
		return nil
	}

	n := uint32(len(insns))

	// Estimate instruction count: average Dalvik instruction is ~2 code units
	estimatedCount := int(n/2) + 1

	var result []RawInsn
	if arena != nil {
		result = arena.AllocRawInsnSlice(estimatedCount)
		result = result[:0] // use as dynamic slice within arena capacity
	} else {
		result = make([]RawInsn, 0, estimatedCount)
	}

	pos := uint32(0)
	for pos < n {
		insn := decodeRawInsn(insns, pos, n)
		result = append(result, insn)

		if insn.Size == 0 {
			pos++ // safety: never get stuck
		} else {
			pos += uint32(insn.Size)
		}
	}

	return result
}

// decodeRawInsn decodes a single instruction at the given position.
// No allocations. No fmt.Sprintf. Pure struct construction.
func decodeRawInsn(insns []uint16, pos, limit uint32) RawInsn {
	if pos >= limit {
		return RawInsn{Op: 0x00, Format: Fmt10x, Size: 1, Offset: pos}
	}

	word := insns[pos]
	opcode := uint8(word & 0xFF)

	// Handle pseudo-opcodes (payload markers)
	if opcode == 0x00 && word != 0x0000 {
		return decodePseudoInsn(insns, pos, limit, word)
	}

	meta := opcodeMetaTable[opcode]

	// Check bounds
	if pos+meta.Size > limit {
		return RawInsn{
			Op:     opcode,
			Format: meta.Format,
			Size:   1,
			Offset: pos,
			Flags:  meta.Flags,
		}
	}

	out := RawInsn{
		Op:      opcode,
		Format:  meta.Format,
		Size:    uint16(meta.Size),
		Offset:  pos,
		Flags:   meta.Flags,
		RefKind: meta.RefKind,
	}

	// Decode operands based on format
	switch meta.Format {
	case Fmt10x:
		// No operands (nop, return-void)

	case Fmt12x:
		// vA, vB (4-bit each)
		out.Regs[0] = (word >> 8) & 0xF
		out.Regs[1] = (word >> 12) & 0xF
		out.RegCount = 2

	case Fmt11n:
		// vA, #+B (4-bit reg, 4-bit signed literal)
		out.Regs[0] = (word >> 8) & 0xF
		out.RegCount = 1
		lit := int32((word >> 12) & 0xF)
		if lit&0x8 != 0 {
			lit |= ^int32(0xF) // sign extend
		}
		out.Imm = int64(lit)

	case Fmt11x:
		// vAA (8-bit register)
		out.Regs[0] = (word >> 8) & 0xFF
		out.RegCount = 1

	case Fmt10t:
		// +AA (8-bit signed branch offset)
		out.Imm = int64(int8((word >> 8) & 0xFF))

	case Fmt20t:
		// +AAAA (16-bit signed branch offset)
		out.Imm = int64(int16(insns[pos+1]))

	case Fmt22x:
		// vAA, vBBBB
		out.Regs[0] = (word >> 8) & 0xFF
		out.Regs[1] = insns[pos+1]
		out.RegCount = 2

	case Fmt21t:
		// vAA, +BBBB (branch)
		out.Regs[0] = (word >> 8) & 0xFF
		out.RegCount = 1
		out.Imm = int64(int16(insns[pos+1]))

	case Fmt21s:
		// vAA, #+BBBB
		out.Regs[0] = (word >> 8) & 0xFF
		out.RegCount = 1
		out.Imm = int64(int16(insns[pos+1]))

	case Fmt21h:
		// vAA, #+BBBB0000[00000000]
		out.Regs[0] = (word >> 8) & 0xFF
		out.RegCount = 1
		if opcode == 0x15 { // const/high16
			out.Imm = int64(uint32(insns[pos+1]) << 16)
		} else { // const-wide/high16
			out.Imm = int64(uint64(insns[pos+1]) << 48)
		}

	case Fmt21c:
		// vAA, ref@BBBB
		out.Regs[0] = (word >> 8) & 0xFF
		out.RegCount = 1
		out.RefIdx = uint32(insns[pos+1])

	case Fmt23x:
		// vAA, vBB, vCC
		out.Regs[0] = (word >> 8) & 0xFF
		out.Regs[1] = insns[pos+1] & 0xFF
		out.Regs[2] = (insns[pos+1] >> 8) & 0xFF
		out.RegCount = 3

	case Fmt22b:
		// vAA, vBB, #+CC
		out.Regs[0] = (word >> 8) & 0xFF
		out.Regs[1] = insns[pos+1] & 0xFF
		out.RegCount = 2
		out.Imm = int64(int8(insns[pos+1] >> 8))

	case Fmt22t:
		// vA, vB, +CCCC
		out.Regs[0] = (word >> 8) & 0xF
		out.Regs[1] = (word >> 12) & 0xF
		out.RegCount = 2
		out.Imm = int64(int16(insns[pos+1]))

	case Fmt22s:
		// vA, vB, #+CCCC
		out.Regs[0] = (word >> 8) & 0xF
		out.Regs[1] = (word >> 12) & 0xF
		out.RegCount = 2
		out.Imm = int64(int16(insns[pos+1]))

	case Fmt22c:
		// vA, vB, ref@CCCC
		out.Regs[0] = (word >> 8) & 0xF
		out.Regs[1] = (word >> 12) & 0xF
		out.RegCount = 2
		out.RefIdx = uint32(insns[pos+1])

	case Fmt30t:
		// +AAAAAAAA (32-bit signed branch offset)
		lo := uint32(insns[pos+1])
		hi := uint32(insns[pos+2])
		out.Imm = int64(int32(lo | (hi << 16)))

	case Fmt32x:
		// vAAAA, vBBBB
		out.Regs[0] = insns[pos+1]
		out.Regs[1] = insns[pos+2]
		out.RegCount = 2

	case Fmt31i:
		// vAA, #+BBBBBBBB
		out.Regs[0] = (word >> 8) & 0xFF
		out.RegCount = 1
		lo := uint32(insns[pos+1])
		hi := uint32(insns[pos+2])
		out.Imm = int64(int32(lo | (hi << 16)))

	case Fmt31c:
		// vAA, string@BBBBBBBB
		out.Regs[0] = (word >> 8) & 0xFF
		out.RegCount = 1
		lo := uint32(insns[pos+1])
		hi := uint32(insns[pos+2])
		out.RefIdx = lo | (hi << 16)

	case Fmt35c, Fmt45cc:
		// invoke {vC, vD, vE, vF, vG}, ref@BBBB
		argCount := (word >> 12) & 0xF
		out.RefIdx = uint32(insns[pos+1])
		regWord := insns[pos+2]
		out.RegCount = uint8(argCount)
		if argCount >= 1 {
			out.Regs[0] = regWord & 0xF
		}
		if argCount >= 2 {
			out.Regs[1] = (regWord >> 4) & 0xF
		}
		if argCount >= 3 {
			out.Regs[2] = (regWord >> 8) & 0xF
		}
		// For 4+ args, store extra info in Imm
		if argCount >= 4 {
			out.Imm = int64((regWord>>12)&0xF) | int64((word>>8)&0xF)<<4
		}
		if meta.Format==Fmt45cc {out.Imm |= int64(insns[pos+3])<<16}

	case Fmt3rc, Fmt4rcc:
		// invoke/range {vCCCC .. vNNNN}, ref@BBBB
		argCount := (word >> 8) & 0xFF
		out.RefIdx = uint32(insns[pos+1])
		startReg := insns[pos+2]
		out.RegCount = uint8(argCount)
		out.Regs[0] = startReg                        // first reg
		out.Regs[1] = startReg + uint16(argCount) - 1 // last reg (for range display)
		out.Imm = int64(argCount)
		if meta.Format==Fmt4rcc {out.Imm |= int64(insns[pos+3])<<16}

	case Fmt51l:
		// vAA, #+BBBBBBBBBBBBBBBB
		out.Regs[0] = (word >> 8) & 0xFF
		out.RegCount = 1
		out.Imm = int64(
			uint64(insns[pos+1]) |
				uint64(insns[pos+2])<<16 |
				uint64(insns[pos+3])<<32 |
				uint64(insns[pos+4])<<48,
		)

	default:
		out.Size = 1 // unknown — advance by 1
	}

	return out
}

// decodePseudoInsn handles payload pseudo-instructions (packed-switch, sparse-switch, fill-array).
func decodePseudoInsn(insns []uint16, pos, limit uint32, ident uint16) RawInsn {
	out := RawInsn{
		Op:     0x00,
		Format: FmtUnknown,
		Offset: pos,
		Flags:  FlagPayload,
	}

	switch ident {
	case 0x0100: // packed-switch payload
		if pos+2 < limit {
			size := insns[pos+1]
			out.Size = uint16(4 + uint32(size)*2)
			out.Imm = int64(size) // number of targets
		} else {
			out.Size = 2
		}

	case 0x0200: // sparse-switch payload
		if pos+2 < limit {
			size := insns[pos+1]
			out.Size = uint16(2 + uint32(size)*4)
			out.Imm = int64(size)
		} else {
			out.Size = 2
		}

	case 0x0300: // fill-array-data payload
		if pos+4 <= limit {
			elemWidth := insns[pos+1]
			elemCount := uint32(insns[pos+2]) | uint32(insns[pos+3])<<16
			dataBytes := uint64(elemCount) * uint64(elemWidth)
			dataWords := (dataBytes + 1) / 2
			out.Size = uint16(4 + dataWords)
			out.Imm = int64(elemCount)
			out.Regs[0] = elemWidth // store elem width
		} else {
			out.Size = 4
		}

	default:
		out.Size = 1 // nop
	}

	// Clamp size to avoid overrun
	if uint32(out.Size)+pos > limit {
		out.Size = uint16(limit - pos)
	}

	return out
}

// DecodeInvokeRegs extracts all register arguments for invoke instructions
// with more than 3 registers (uses the original code units).
func DecodeInvokeRegs(insn *RawInsn, codeUnits []uint16) []uint16 {
	if !insn.IsInvoke() {
		return nil
	}

	pos := insn.Offset
	if pos >= uint32(len(codeUnits)) {
		return nil
	}

	meta := opcodeMetaTable[insn.Op]

	switch meta.Format {
	case Fmt35c:
		word := codeUnits[pos]
		argCount := (word >> 12) & 0xF
		if argCount == 0 || pos+2 >= uint32(len(codeUnits)) {
			return nil
		}
		regWord := codeUnits[pos+2]
		regs := make([]uint16, 0, argCount)
		if argCount >= 1 {
			regs = append(regs, regWord&0xF)
		}
		if argCount >= 2 {
			regs = append(regs, (regWord>>4)&0xF)
		}
		if argCount >= 3 {
			regs = append(regs, (regWord>>8)&0xF)
		}
		if argCount >= 4 {
			regs = append(regs, (regWord>>12)&0xF)
		}
		if argCount >= 5 {
			regs = append(regs, (word>>8)&0xF)
		}
		return regs

	case Fmt3rc:
		argCount := int(insn.Imm)
		startReg := insn.Regs[0]
		regs := make([]uint16, argCount)
		for i := 0; i < argCount; i++ {
			regs[i] = startReg + uint16(i)
		}
		return regs

	default:
		return nil
	}
}
