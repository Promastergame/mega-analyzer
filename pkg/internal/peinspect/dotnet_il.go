package peinspect

// .NET IL call walker (ECMA-335 §III).
//
// MemberRef tables alone cannot tell whether a dangerous API is actually
// invoked: references include unused imports. This walker disassembles every
// managed method body (tiny + fat headers) and records call-like
// instructions — call, callvirt, newobj, jmp, calli, ldftn, ldvirtftn — with
// the target resolved through MethodDef / MemberRef / MethodSpec tokens.
// Unknown opcodes abort the walk of that method (never a mis-decode of the
// bytes after them); truncated operands abort it too. Hostile inputs yield
// fewer callsites, never a panic or an out-of-bounds read.

import (
	"encoding/binary"
	"fmt"
)

// ILCallSite is one call-like instruction found in a managed method body.
type ILCallSite struct {
	Caller   string `json:"caller"`             // "Namespace.Type.Method"
	ILOffset uint32 `json:"il_offset"`          // byte offset of the instruction in the body
	Op       string `json:"op"`                 // call, callvirt, newobj, jmp, calli, ldftn, ldvirtftn
	Target   string `json:"target"`             // resolved method or raw token when unresolvable
	Token    uint32 `json:"token"`              // raw metadata token
	Indirect bool   `json:"indirect,omitempty"` // calli / function-pointer loads
}

// maxILCallSites caps memory on hostile images with huge method tables.
const maxILCallSites = 2048

// collectILCalls walks every MethodDef with an RVA body and appends call-like
// targets to info. It runs after fillInfo so owner/memberRef names resolve.
func (td *tablesData) collectILCalls(r *dotnetReader, info *DotNetInfo) {
	for rid := uint32(1); rid <= td.rows[tMethodDef]; rid++ {
		row := td.row(tMethodDef, rid)
		if row == nil {
			continue
		}
		c := &rowCursor{row: row}
		rva := c.u32()
		c.u16() // ImplFlags
		c.u16() // Flags
		nameIdx := c.idx(td.strSz)
		if c.bad || rva == 0 {
			continue // abstract, P/Invoke, runtime-provided or bad row
		}
		bodyOff, ok := r.rva(uint64(rva), 1)
		if !ok {
			continue
		}
		code, ok := readMethodBody(r.data, bodyOff)
		if !ok {
			continue
		}
		method := heapString(td.strings, nameIdx)
		caller := td.ownerOfMethod(rid) + method
		if caller == "" {
			caller = method
		}
		if len(info.ILCallSites) >= maxILCallSites {
			info.ILTruncated = true
			return
		}
		info.ILMethodsWalked++
		walkILBody(td, info, caller, code)
	}
}

// readMethodBody returns the IL code bytes of the method body at file offset
// off, handling tiny (1-byte) and fat (12-byte) headers. Exception-clause
// sections after the code are not needed and skipped by construction.
func readMethodBody(data []byte, off uint64) ([]byte, bool) {
	if off >= uint64(len(data)) {
		return nil, false
	}
	b := data[off]
	switch b & 3 {
	case 2: // tiny header: code size in 6 high bits
		size := uint64(b >> 2)
		if off+1+size > uint64(len(data)) {
			return nil, false
		}
		return data[off+1 : off+1+size], true
	case 3: // fat header: flags(2) maxStack(2) codeSize(4) localVarSig(4)
		if off+12 > uint64(len(data)) {
			return nil, false
		}
		size := uint64(binary.LittleEndian.Uint32(data[off+4:]))
		if off+12+size > uint64(len(data)) {
			return nil, false
		}
		return data[off+12 : off+12+size], true
	default:
		return nil, false
	}
}

// ilOperand describes one opcode: operand byte size, or -1 for inline-switch,
// or -2 for unknown (aborts the method walk).
type ilOperand struct {
	size     int
	op       string // non-empty only for call-like opcodes
	indirect bool
}

// ilOneByte decodes a single-byte IL opcode (prefix 0xFE already consumed
// when twoByte is true).
func ilOneByte(twoByte bool, op byte) ilOperand {
	if twoByte {
		switch op {
		case 0x06:
			return ilOperand{size: 4, op: "ldftn", indirect: true}
		case 0x07:
			return ilOperand{size: 4, op: "ldvirtftn", indirect: true}
		}
		// Constrained./readonly./tail./unaligned./volatile. prefixes and the
		// rest of the 2-byte space: operand sizes per ECMA-335.
		switch {
		case op <= 0x02 || op == 0x19 || op == 0x1C:
			return ilOperand{size: 0}
		case op == 0x16:
			return ilOperand{size: 4}
		}
		return ilOperand{size: -2}
	}
	switch op {
	case 0x27:
		return ilOperand{size: 4, op: "jmp"}
	case 0x28:
		return ilOperand{size: 4, op: "call"}
	case 0x29:
		return ilOperand{size: 4, op: "calli", indirect: true}
	case 0x6F:
		return ilOperand{size: 4, op: "callvirt"}
	case 0x73:
		return ilOperand{size: 4, op: "newobj"}
	}
	switch {
	case op <= 0x0E || op == 0x14 || op == 0x16 || op == 0x46 || op == 0x48 ||
		op == 0x4A || op == 0x4C || op == 0x53 || op == 0x5A || op == 0x62 ||
		op == 0x63 || op == 0x65 || op == 0x66 || op == 0x7D || op == 0x7E:
		return ilOperand{size: 0}
	case op == 0x0F || op == 0x10 || op == 0x18 || op == 0x4B || op == 0x4D ||
		op == 0x59 || op == 0x5B || op == 0x70 || op == 0x71 || op == 0x72 ||
		op == 0x7C:
		return ilOperand{size: 1}
	case op == 0x11 || op == 0x12 || op == 0x19 || op == 0x1A || op == 0x4E ||
		op == 0x55 || op == 0x57 || op == 0x67 || op == 0x68 || op == 0x74 ||
		op == 0x75 || op == 0x76 || op == 0x77 || op == 0x79 || op == 0x7A ||
		op == 0x7B || op == 0xD0:
		return ilOperand{size: 2}
	case op == 0x13 || op == 0x15 || op == 0x17 || op == 0x1B || op == 0x1C ||
		op == 0x1D || op == 0x1E || op == 0x1F || op == 0x20 || op == 0x22 ||
		op == 0x26 || op == 0x2B || op == 0x2C || op == 0x2D || op == 0x2E ||
		op == 0x2F || op == 0x30 || op == 0x31 || op == 0x32 || op == 0x33 ||
		op == 0x34 || op == 0x35 || op == 0x36 || op == 0x37 || op == 0x38 ||
		op == 0x39 || op == 0x3A || op == 0x3B || op == 0x3C || op == 0x3D ||
		op == 0x3E || op == 0x3F || op == 0x40 || op == 0x41 || op == 0x42 ||
		op == 0x43 || op == 0x44 || op == 0x4F || op == 0x50 || op == 0x51 ||
		op == 0x52 || op == 0x54 || op == 0x56 || op == 0x58 || op == 0x5C ||
		op == 0x5D || op == 0x5E || op == 0x5F || op == 0x60 || op == 0x61 ||
		op == 0x64 || op == 0x69 || op == 0x6A || op == 0x6B || op == 0x6C ||
		op == 0x6D || op == 0x6E || op == 0x78 || op == 0x7F || op == 0xC2 ||
		op == 0xD1 || op == 0xD2 || op == 0xD3 || op == 0xD4 || op == 0xD5 ||
		op == 0xD6 || op == 0xDC || op == 0xDD || op == 0xDE || op == 0xDF ||
		op == 0xE0:
		return ilOperand{size: 4}
	case op == 0x21:
		return ilOperand{size: 8}
	case op == 0x45:
		return ilOperand{size: -1} // switch: u32 count + count×u32
	}
	return ilOperand{size: -2}
}

// walkILBody decodes code linearly, recording call-like instructions.
func walkILBody(td *tablesData, info *DotNetInfo, caller string, code []byte) {
	pc := 0
	for pc < len(code) {
		start := pc
		op := code[pc]
		pc++
		twoByte := false
		if op == 0xFE {
			if pc >= len(code) {
				return // truncated prefix
			}
			op = code[pc]
			pc++
			twoByte = true
		}
		dec := ilOneByte(twoByte, op)
		var operand uint32
		switch {
		case dec.size >= 0:
			if pc+dec.size > len(code) {
				return // truncated operand: stop this method, keep prior sites
			}
			if dec.size == 4 {
				operand = binary.LittleEndian.Uint32(code[pc:])
			}
			pc += dec.size
		case dec.size == -1:
			if pc+4 > len(code) {
				return
			}
			n := binary.LittleEndian.Uint32(code[pc:])
			if uint64(n) > uint64(len(code)-pc-4)/4 {
				return // switch table overruns the body
			}
			pc += 4 + int(n)*4
		default:
			return // unknown opcode: stop this method, keep prior sites
		}
		if dec.op == "" {
			continue
		}
		if len(info.ILCallSites) >= maxILCallSites {
			info.ILTruncated = true
			return
		}
		target := td.resolveCallToken(operand)
		info.ILCallSites = append(info.ILCallSites, ILCallSite{
			Caller:   caller,
			ILOffset: uint32(start),
			Op:       dec.op,
			Target:   target,
			Token:    operand,
			Indirect: dec.indirect,
		})
	}
}

// resolveCallToken renders a call/jmp/ldftn metadata token as a method name,
// falling back to the raw token when the row is missing.
func (td *tablesData) resolveCallToken(tok uint32) string {
	raw := fmt.Sprintf("token 0x%08X", tok)
	table, rid := tok>>24, tok&0xFFFFFF
	switch table {
	case 0x06: // MethodDef
		r := td.row(tMethodDef, rid)
		if r == nil {
			return raw
		}
		c := &rowCursor{row: r}
		c.u32() // RVA
		c.u16()
		c.u16()
		name := heapString(td.strings, c.idx(td.strSz))
		if c.bad || name == "" {
			return raw
		}
		if owner := td.ownerOfMethod(rid); owner != "" {
			return owner + name
		}
		return name
	case 0x0A: // MemberRef
		if name := td.memberRefFullName(rid); name != "" {
			return name
		}
		return raw
	case 0x2B: // MethodSpec: method (MethodDefOrRef) + instantiation blob
		r := td.row(0x2B, rid)
		if r == nil {
			return raw
		}
		c := &rowCursor{row: r}
		mdorSize := td.codedSize([]uint32{tMethodDef, tMemberRef}, 1)
		mdor := c.idx(mdorSize)
		if c.bad {
			return raw
		}
		var target uint32
		if mdor&1 == 0 {
			target = 0x06000000 | (mdor >> 1)
		} else {
			target = 0x0A000000 | (mdor >> 1)
		}
		return td.resolveCallToken(target) + "[generic]"
	}
	return raw
}
