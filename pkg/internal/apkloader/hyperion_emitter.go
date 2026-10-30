package apkloader

// ═══════════════════════════════════════════════════════════════════════════════
// HYPERION ENGINE v3.0 — Phase 4: Bytecode Emitter (IR → DEX)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Round-trip: RawInsn → Dalvik bytecode. Foundation for in-memory patching.

import (
	"encoding/binary"
	"fmt"
)

// InsnEmitter encodes RawInsn back to Dalvik bytecode.
type InsnEmitter struct {
	buf    []uint16
	offset uint32
}

// NewInsnEmitter creates an emitter with estimated capacity.
func NewInsnEmitter(estimatedInsn int) *InsnEmitter {
	return &InsnEmitter{
		buf: make([]uint16, 0, estimatedInsn*2),
	}
}

// Emit encodes a single RawInsn and returns its size in bytes.
func (e *InsnEmitter) Emit(insn *RawInsn) (int, error) {
	meta := &opcodeMetaTable[insn.Op]
	if meta.Format == FmtUnknown {
		return 0, fmt.Errorf("unknown opcode: 0x%02x", insn.Op)
	}

	startOffset := len(e.buf)

	switch meta.Format {
	case Fmt10x:
		e.emitFmt10x(insn.Op)
	case Fmt12x:
		e.emitFmt12x(uint16(insn.Op), insn.Regs[0], insn.Regs[1])
	case Fmt11n:
		e.emitFmt11n(insn.Op, insn.Regs[0], int16(insn.Imm))
	case Fmt11x:
		e.emitFmt11x(insn.Op, insn.Regs[0])
	case Fmt10t:
		e.emitFmt10t(insn.Op, int8(insn.Imm))
	case Fmt20t:
		e.emitFmt20t(insn.Op, int16(insn.Imm))
	case Fmt30t:
		e.emitFmt30t(insn.Op, int32(insn.Imm))
	case Fmt21c:
		e.emitFmt21c(insn.Op, insn.Regs[0], insn.RefIdx)
	case Fmt21s:
		e.emitFmt21s(insn.Op, insn.Regs[0], int16(insn.Imm))
	case Fmt21t:
		e.emitFmt21t(insn.Op, insn.Regs[0], int16(insn.Imm))
	case Fmt21h:
		e.emitFmt21h(insn.Op, insn.Regs[0], int16(insn.Imm))
	case Fmt22c:
		e.emitFmt22c(uint16(insn.Op), insn.Regs[0], insn.Regs[1], insn.RefIdx)
	case Fmt22s:
		e.emitFmt22s(uint16(insn.Op), insn.Regs[0], insn.Regs[1], int16(insn.Imm))
	case Fmt22t:
		e.emitFmt22t(uint16(insn.Op), insn.Regs[0], insn.Regs[1], int16(insn.Imm))
	case Fmt22b:
		e.emitFmt22b(uint16(insn.Op), insn.Regs[0], insn.Regs[1], int8(insn.Imm))
	case Fmt22x:
		e.emitFmt22x(uint16(insn.Op), insn.Regs[0], insn.Regs[1])
	case Fmt23x:
		e.emitFmt23x(uint16(insn.Op), insn.Regs[0], insn.Regs[1], insn.Regs[2])
	case Fmt32x:
		e.emitFmt32x(uint16(insn.Op), insn.Regs[0], insn.Regs[1])
	case Fmt31i:
		e.emitFmt31i(insn.Op, insn.Regs[0], int32(insn.Imm))
	case Fmt31t:
		// Fmt31t same encoding as Fmt31i
		e.emitFmt31i(insn.Op, insn.Regs[0], int32(insn.Imm))
	case Fmt31c:
		e.emitFmt31c(insn.Op, insn.Regs[0], insn.RefIdx)
	case Fmt35c:
		e.emitFmt35c(insn.Op, insn.RefIdx, insn.Regs[1], uint16(insn.RegCount))
	case Fmt3rc:
		e.emitFmt3rc(uint16(insn.Op), insn.Regs[0], uint16(insn.RefIdx), uint16(insn.RegCount))
	case Fmt51l:
		e.emitFmt51l(insn.Op, insn.Regs[0], insn.Imm)
	default:
		return 0, fmt.Errorf("unsupported format: %v", meta.Format)
	}

	return (len(e.buf) - startOffset) * 2, nil
}

// Bytes returns the encoded bytecode as bytes.
func (e *InsnEmitter) Bytes() []byte {
	byteBuf := make([]byte, len(e.buf)*2)
	for i, w := range e.buf {
		binary.LittleEndian.PutUint16(byteBuf[i*2:], w)
	}
	return byteBuf
}

// CodeUnits returns the encoded code units (16-bit words).
func (e *InsnEmitter) CodeUnits() []uint16 {
	return e.buf
}

// ═══════════════════════════════════════════════════════════════════════════════
// FORMAT ENCODERS
// ═══════════════════════════════════════════════════════════════════════════════

// Fmt10x: | op (8) | 0 (8) |
func (e *InsnEmitter) emitFmt10x(op uint8) {
	e.buf = append(e.buf, uint16(op))
}

// Fmt12x: | op (8) | vA (4) | vB (4) |
func (e *InsnEmitter) emitFmt12x(op, vA, vB uint16) {
	word := uint16(op) | ((vB & 0xF) << 12) | ((vA & 0xF) << 8)
	e.buf = append(e.buf, word)
}

// Fmt11n: | op (8) | vA (4) | signed #+B (4) |
func (e *InsnEmitter) emitFmt11n(op uint8, vA uint16, imm int16) {
	word := uint16(op) | ((uint16(imm) & 0xF) << 12) | ((vA & 0xF) << 8)
	e.buf = append(e.buf, word)
}

// Fmt11x: | op (8) | vAA (8) |
func (e *InsnEmitter) emitFmt11x(op uint8, vAA uint16) {
	word := uint16(op) | ((vAA & 0xFF) << 8)
	e.buf = append(e.buf, word)
}

// Fmt10t: | op (8) | +AA (8) |
func (e *InsnEmitter) emitFmt10t(op uint8, imm int8) {
	word := uint16(op) | (uint16(uint8(imm)) << 8)
	e.buf = append(e.buf, word)
}

// Fmt20t: | op (8) | 0 (8) | +AAAA (16) |
func (e *InsnEmitter) emitFmt20t(op uint8, imm int16) {
	e.buf = append(e.buf, uint16(op))
	e.buf = append(e.buf, uint16(imm))
}

// Fmt30t: | op (8) | 0 (8) | +AAAAAAAA (32) |
func (e *InsnEmitter) emitFmt30t(op uint8, imm int32) {
	e.buf = append(e.buf, uint16(op))
	e.buf = append(e.buf, uint16(imm))     // low
	e.buf = append(e.buf, uint16(imm>>16)) // high
}

// Fmt21c: | op (8) | vAA (8) | #+BBBB (16) |
func (e *InsnEmitter) emitFmt21c(op uint8, vAA uint16, refIdx uint32) {
	e.buf = append(e.buf, uint16(op)|((vAA&0xFF)<<8))
	e.buf = append(e.buf, uint16(refIdx))
}

// Fmt21s: | op (8) | vAA (8) | #+BBBB (16) |
func (e *InsnEmitter) emitFmt21s(op uint8, vAA uint16, imm int16) {
	e.buf = append(e.buf, uint16(op)|((vAA&0xFF)<<8))
	e.buf = append(e.buf, uint16(imm))
}

// Fmt21t: | op (8) | vAA (8) | +BBBB (16) |
func (e *InsnEmitter) emitFmt21t(op uint8, vAA uint16, imm int16) {
	e.buf = append(e.buf, uint16(op)|((vAA&0xFF)<<8))
	e.buf = append(e.buf, uint16(imm))
}

// Fmt21h: | op (8) | vAA (8) | #+BBBB0000 (16) |
func (e *InsnEmitter) emitFmt21h(op uint8, vAA uint16, imm int16) {
	e.buf = append(e.buf, uint16(op)|((vAA&0xFF)<<8))
	e.buf = append(e.buf, uint16(imm))
}

// Fmt22c: | op (8) | vA (4) | vB (4) | #+CCCC (16) |
func (e *InsnEmitter) emitFmt22c(op, vA, vB uint16, refIdx uint32) {
	word := uint16(op) | ((vB & 0xF) << 12) | ((vA & 0xF) << 8)
	e.buf = append(e.buf, word)
	e.buf = append(e.buf, uint16(refIdx))
}

// Fmt22s: | op (8) | vA (4) | vB (4) | #+CCCC (16) |
func (e *InsnEmitter) emitFmt22s(op, vA, vB uint16, imm int16) {
	word := uint16(op) | ((vB & 0xF) << 12) | ((vA & 0xF) << 8)
	e.buf = append(e.buf, word)
	e.buf = append(e.buf, uint16(imm))
}

// Fmt22t: | op (8) | vA (4) | vB (4) | +CCCC (16) |
func (e *InsnEmitter) emitFmt22t(op, vA, vB uint16, imm int16) {
	word := uint16(op) | ((vB & 0xF) << 12) | ((vA & 0xF) << 8)
	e.buf = append(e.buf, word)
	e.buf = append(e.buf, uint16(imm))
}

// Fmt22b: | op (8) | vA (8) | vB (8) | #+CC (8) |
func (e *InsnEmitter) emitFmt22b(op, vA, vB uint16, imm int8) {
	e.buf = append(e.buf, uint16(op)|((vA&0xFF)<<8))
	e.buf = append(e.buf, ((vB&0xFF)<<8)|uint16(uint8(imm)))
}

// Fmt22x: | op (8) | vAA (8) | vBBBB (16) |
func (e *InsnEmitter) emitFmt22x(op, vAA, vBBBB uint16) {
	e.buf = append(e.buf, uint16(op)|((vAA&0xFF)<<8))
	e.buf = append(e.buf, vBBBB)
}

// Fmt23x: | op (8) | vAA (8) | vBB (8) | vCC (8) |
func (e *InsnEmitter) emitFmt23x(op, vAA, vBB, vCC uint16) {
	e.buf = append(e.buf, uint16(op)|((vAA&0xFF)<<8))
	e.buf = append(e.buf, ((vBB&0xFF)<<8)|(vCC&0xFF))
}

// Fmt32x: | op (8) | 0 (8) | vAAAA (16) | vBBBB (16) |
func (e *InsnEmitter) emitFmt32x(op, vAAAA, vBBBB uint16) {
	e.buf = append(e.buf, uint16(op))
	e.buf = append(e.buf, vAAAA)
	e.buf = append(e.buf, vBBBB)
}

// Fmt31i: | op (8) | vAA (8) | #+BBBBBBBB (32) |
func (e *InsnEmitter) emitFmt31i(op uint8, vAA uint16, imm int32) {
	e.buf = append(e.buf, uint16(op)|((vAA&0xFF)<<8))
	e.buf = append(e.buf, uint16(imm))
	e.buf = append(e.buf, uint16(imm>>16))
}

// Fmt31t: | op (8) | vAA (8) | +BBBBBBBB (32) |
func (e *InsnEmitter) emitFmt31t(op uint8, vAA uint16, imm int32) {
	e.buf = append(e.buf, uint16(op)|((vAA&0xFF)<<8))
	e.buf = append(e.buf, uint16(imm))
	e.buf = append(e.buf, uint16(imm>>16))
}

// Fmt31c: | op (8) | vAA (8) | #+BBBBBBBB (32) |
func (e *InsnEmitter) emitFmt31c(op uint8, vAA uint16, refIdx uint32) {
	e.buf = append(e.buf, uint16(op)|((vAA&0xFF)<<8))
	e.buf = append(e.buf, uint16(refIdx))
	e.buf = append(e.buf, uint16(refIdx>>16))
}

// Fmt35c: | op (8) | A (4) | G (4) | B (4) | C (4) | D (4) | E (4) | F (4) | #+CCCC (16) |
// For invoke: A=count, G=first reg hi nibble, B=reg[4], C=reg[3], D=reg[2], E=reg[1], F=reg[0]
func (e *InsnEmitter) emitFmt35c(op uint8, refIdx uint32, vG uint16, argCount uint16) {
	// Simplified: emit as range invoke for now
	// Full implementation needs proper register packing
	word := uint16(op) | ((argCount & 0xF) << 12) | ((vG & 0xF) << 8)
	e.buf = append(e.buf, word)
	e.buf = append(e.buf, uint16(refIdx))
}

// Fmt3rc: | op (8) | AA (8) | #+BBBB (16) | CCCCC (16) |
func (e *InsnEmitter) emitFmt3rc(op, vC, refIdx uint16, count uint16) {
	e.buf = append(e.buf, uint16(op)|((count&0xFF)<<8))
	e.buf = append(e.buf, uint16(refIdx))
	e.buf = append(e.buf, vC)
}

// Fmt51l: | op (8) | vAA (8) | #+BBBBBBBBBBBBBBBB (64) |
func (e *InsnEmitter) emitFmt51l(op uint8, vAA uint16, imm int64) {
	e.buf = append(e.buf, uint16(op)|((vAA&0xFF)<<8))
	e.buf = append(e.buf, uint16(imm))
	e.buf = append(e.buf, uint16(imm>>16))
	e.buf = append(e.buf, uint16(imm>>32))
	e.buf = append(e.buf, uint16(imm>>48))
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH ENCODING
// ═══════════════════════════════════════════════════════════════════════════════

// EmitAll encodes a sequence of RawInsn, computing offsets.
func (e *InsnEmitter) EmitAll(insns []RawInsn) ([]uint32, error) {
	offsets := make([]uint32, len(insns))

	for i := range insns {
		offsets[i] = uint32(len(e.buf)) * 2 // byte offset
		size, err := e.Emit(&insns[i])
		if err != nil {
			return nil, fmt.Errorf("insn %d: %w", i, err)
		}
		_ = size
	}

	return offsets, nil
}
