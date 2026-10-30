package adapters

// Synthetic DEX builder for adapter tests. Produces a minimal but
// fully valid DEX 035 file with one class exercising const-string
// edge cases, branches, try/catch, switch payloads and array-data.

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

const (
	tdxV      = 0  // "V"
	tdxObject = 1  // "Ljava/lang/Object;"
	tdxIr     = 2  // "Lcom/test/Ir;"
	tdxInit   = 3  // "<init>"
	tdxSrc    = 4  // "Ir.java"
	tdxString = 5  // "Ljava/lang/String;"
	tdxLength = 6  // "length"
	tdxI      = 7  // "I"
	tdxName   = 8  // "name"
	tdxSw     = 9  // "sw"
	tdxTest   = 10 // "test"
	tdxHello  = 11 // edge-case const string
)

// tdxHelloStr exercises commas, escaped quotes, newline and unicode.
const tdxHelloStr = "hello, \"quoted\"\nünïcode ☺"

func tdxStrings() []string {
	return []string{
		"V", "Ljava/lang/Object;", "Lcom/test/Ir;", "<init>",
		"Ir.java", "Ljava/lang/String;", "length", "I",
		"name", "sw", "test", tdxHelloStr,
	}
}

func tdxULEB(v uint32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7F)
		v >>= 7
		if v != 0 {
			out = append(out, b|0x80)
		} else {
			out = append(out, b)
			return out
		}
	}
}

func tdxSLEB(v int32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7F)
		v >>= 7
		done := (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0)
		if !done {
			out = append(out, b|0x80)
		} else {
			out = append(out, b)
			return out
		}
	}
}

// tdxMUTF8 encodes a string as ULEB128(utf16 length) + UTF-8 + NUL.
func tdxMUTF8(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := tdxULEB(uint32(len(units)))
	out = append(out, s...)
	out = append(out, 0)
	return out
}

// tdxCodeItem serializes a code_item (header + insns + optional tries).
func tdxCodeItem(regs, ins, outs, tries uint16, insns []uint16, tryPayload []byte) []byte {
	var b bytes.Buffer
	le16 := func(v uint16) { _ = binary.Write(&b, binary.LittleEndian, v) }
	le32 := func(v uint32) { _ = binary.Write(&b, binary.LittleEndian, v) }
	le16(regs)
	le16(ins)
	le16(outs)
	le16(tries)
	le32(0) // debug_info_off
	le32(uint32(len(insns)))
	for _, u := range insns {
		le16(u)
	}
	if tries > 0 {
		if len(insns)%2 != 0 {
			le16(0) // padding to 4 bytes
		}
		b.Write(tryPayload)
	}
	return b.Bytes()
}

// buildIRTestDEX returns a complete synthetic DEX byte slice.
//
// Class Lcom/test/Ir; extends Object with:
//   - instance field "name" (String, private)
//   - direct  <init>()V: invoke-direct Object.<init> + return-void
//   - virtual sw()V:     packed-switch + payload table
//   - virtual test()V:   const-string, if-eqz, invoke-virtual
//     String.length, fill-array-data + payload, try/catch-all
func buildIRTestDEX() []byte {
	strs := tdxStrings()

	const (
		nStr, nTyp, nProto = 12, 5, 2
		nField, nMeth      = 1, 5
		nClass             = 1
	)

	headerSize := uint32(0x70)
	stringIDsOff := headerSize
	typeIDsOff := stringIDsOff + nStr*4
	protoIDsOff := typeIDsOff + nTyp*4
	fieldIDsOff := protoIDsOff + nProto*12
	methodIDsOff := fieldIDsOff + nField*8
	classDefsOff := methodIDsOff + nMeth*8
	dataStart := (classDefsOff + nClass*32 + 3) &^ 3

	// ── Data area ─────────────────────────────────────────
	// Code items come first so class_data can reference their offsets.
	var data []byte
	align := func() {
		for len(data)%4 != 0 {
			data = append(data, 0)
		}
	}
	ulebs := func(vals ...uint32) {
		for _, v := range vals {
			data = append(data, tdxULEB(v)...)
		}
	}

	// <init> code item (method idx 1)
	align()
	codeInitOff := dataStart + uint32(len(data))
	data = append(data, tdxCodeItem(1, 1, 1, 0, []uint16{
		0x1070, 0x0000, // invoke-direct {p0}, method@0
		0x0000, // regWord: p0
		0x000E, // return-void
	}, nil)...)

	// sw code item (method idx 2): packed-switch + payload
	align()
	codeSwOff := dataStart + uint32(len(data))
	data = append(data, tdxCodeItem(2, 1, 0, 0, []uint16{
		0x012B, 0x0004, 0x0000, // packed-switch v1, +4 (payload @4)
		0x000E,         // return-void
		0x0100, 0x0002, // payload ident, size=2
		0x000A, 0x0000, // firstKey = 10
		0x0003, 0x0000, // target0 (rel) = 3
		0x0003, 0x0000, // target1 (rel) = 3
	}, nil)...)

	// test code item (method idx 3): rich instruction mix + try/catch
	align()
	codeTestOff := dataStart + uint32(len(data))
	testInsns := []uint16{
		0x011A, 0x000B, // 0: const-string v1, string@11
		0x0138, 0x0009, // 2: if-eqz v1, +9  → target 11
		0x106E, 0x0004, // 4: invoke-virtual {…}, method@4 (String.length)
		0x0001,                 // 6: regWord {v1}
		0x0026, 0x0006, 0x0000, // 7: fill-array-data v0, +6 → payload @13
		0x000E,         // 10: return-void
		0x020D,         // 11: move-exception v2
		0x000E,         // 12: return-void
		0x0300,         // 13: array-data ident
		0x0002,         // elemWidth = 2
		0x0003, 0x0000, // elemCount = 3
		0x4241, // "AB"
		0x4443, // "CD"
		0x4645, // "EF"
	}
	tryPayload := []byte{}
	tryPayload = append(tryPayload,
		0x00, 0x00, 0x00, 0x00, // try0: start_addr = 0
		0x0B, 0x00, // insn_count = 11
		0x01, 0x00, // handler_off = 1 (past the 1-byte list size ULEB)
	)
	tryPayload = append(tryPayload, tdxULEB(1)...)
	tryPayload = append(tryPayload, tdxSLEB(0)...)  // size=0 → catch-all only
	tryPayload = append(tryPayload, tdxULEB(11)...) // catch-all addr = 11
	data = append(data, tdxCodeItem(3, 1, 1, 1, testInsns, tryPayload)...)

	// class_data (after code items so offsets are known)
	align()
	classDataOff := dataStart + uint32(len(data))
	// static=0, instance=1, direct=1, virtual=2
	ulebs(0, 1, 1, 2)
	// instance field: diff=0, access=0x2 (private)
	ulebs(0, 0x2)
	// direct method: <init> (idx 1): diff=1, access public|constructor, code
	ulebs(1, 0x10001, codeInitOff)
	// virtual methods: sw (idx 2), test (idx 3)
	ulebs(2, 0x1, codeSwOff)
	ulebs(1, 0x1, codeTestOff)

	// String data
	strOffs := make([]uint32, len(strs))
	for i, s := range strs {
		align()
		strOffs[i] = dataStart + uint32(len(data))
		data = append(data, tdxMUTF8(s)...)
	}

	fileSize := dataStart + uint32(len(data))

	// ── Fixed sections ────────────────────────────────────
	out := make([]byte, fileSize)
	copy(out[dataStart:], data) // data area (code items, class_data, strings)
	// Header
	copy(out[0:8], "dex\n035\x00")
	le32At := func(off uint32, v uint32) { binary.LittleEndian.PutUint32(out[off:], v) }
	le16At := func(off uint32, v uint16) { binary.LittleEndian.PutUint16(out[off:], v) }
	le32At(32, fileSize)
	le32At(36, headerSize)
	le32At(40, 0x12345678)
	le32At(56, nStr)
	le32At(60, stringIDsOff)
	le32At(64, nTyp)
	le32At(68, typeIDsOff)
	le32At(72, nProto)
	le32At(76, protoIDsOff)
	le32At(80, nField)
	le32At(84, fieldIDsOff)
	le32At(88, nMeth)
	le32At(92, methodIDsOff)
	le32At(96, nClass)
	le32At(100, classDefsOff)
	le32At(104, uint32(len(data)))
	le32At(108, dataStart)

	// string_ids
	for i, off := range strOffs {
		le32At(stringIDsOff+uint32(i)*4, off)
	}
	// type_ids: descriptor_idx
	types := []uint32{tdxObject, tdxIr, tdxString, tdxI, tdxV}
	for i, s := range types {
		le32At(typeIDsOff+uint32(i)*4, s)
	}
	// proto_ids: shorty_idx, return_type_idx, parameters_off
	// proto0 ()V, proto1 ()I
	le32At(protoIDsOff+0, tdxV)
	le32At(protoIDsOff+4, 4) // V type idx
	le32At(protoIDsOff+8, 0)
	le32At(protoIDsOff+12, tdxI)
	le32At(protoIDsOff+16, 3) // I type idx
	le32At(protoIDsOff+20, 0)
	// field_ids: class_idx(u16), type_idx(u16), name_idx(u32)
	le16At(fieldIDsOff+0, 1) // Ir
	le16At(fieldIDsOff+2, 2) // String
	le32At(fieldIDsOff+4, tdxName)
	// method_ids (sorted by class_idx, name_idx):
	// 0: Object.<init>, 1: Ir.<init>, 2: Ir.sw, 3: Ir.test, 4: String.length
	meths := []struct {
		class, proto uint16
		name         uint32
	}{
		{0, 0, tdxInit},
		{1, 0, tdxInit},
		{1, 0, tdxSw},
		{1, 0, tdxTest},
		{2, 1, tdxLength},
	}
	for i, m := range meths {
		base := methodIDsOff + uint32(i)*8
		le16At(base+0, m.class)
		le16At(base+2, m.proto)
		le32At(base+4, m.name)
	}
	// class_defs: one class
	cd := classDefsOff
	le32At(cd+0, 1)       // class_idx: Ir
	le32At(cd+4, 0x0021)  // access: public | super
	le32At(cd+8, 0)       // superclass: Object
	le32At(cd+12, 0)      // interfaces_off
	le32At(cd+16, tdxSrc) // source_file_idx
	le32At(cd+20, 0)      // annotations_off
	le32At(cd+24, classDataOff)
	le32At(cd+28, 0) // static_values_off

	return out
}
