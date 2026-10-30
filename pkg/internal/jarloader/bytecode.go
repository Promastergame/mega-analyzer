package jarloader

import (
	"encoding/binary"
	"fmt"
)

const maxClassCallSites = 4096

// CallSite is an encoded invocation, NOT proof of reachability or execution.
// Dynamic calls retain their bootstrap identity separately from direct targets.
type CallSite struct {
	Caller           string     `json:"caller"`
	CallerDescriptor string     `json:"caller_descriptor"`
	Offset           int        `json:"offset"`
	Opcode           string     `json:"opcode"`
	Target           MethodRef  `json:"target"`
	BootstrapIndex   uint16     `json:"bootstrap_index,omitempty"`
	Bootstrap        *MethodRef `json:"bootstrap,omitempty"`
}

type MethodBody struct {
	Name       string
	Descriptor string
	Access     uint16
	// Only exact trivial bodies are recognized; there is no speculative CFG.
	TrivialReturn string
	// MaxLocals sizes the abstract-interpretation frame. Code retains raw
	// bytes for precise argument resolution (bounded: tracked sinks, 64 KiB).
	MaxLocals uint16
	Code      []byte
}

// methodCallsPreciseTarget reports whether any decoded call invokes a
// precise-argument sink (see flow.go).
func methodCallsPreciseTarget(calls []CallSite) bool {
	for _, c := range calls {
		if preciseArgTargets[c.Target.Class+"."+c.Target.Name] {
			return true
		}
	}
	return false
}

func poolMethod(pool []constant, index uint16) MethodRef {
	c := pool[index] // caller checks the tag and index; validatePool checked links
	nt := pool[c.ntIndex]
	return MethodRef{Class: normalizeClassName(pool[pool[c.classIndex].nameIndex].utf8), Name: pool[nt.nameIndex].utf8, Descriptor: pool[nt.descIndex].utf8}
}

// decodeInstructions walks instruction boundaries, including switch alignment
// and wide. Operand bytes are never mistaken for opcodes. It checks branch
// destinations, not stack types, verifier constraints, or runtime dispatch.
func decodeInstructions(code []byte, pool []constant, limit int) ([]CallSite, int, bool, error) {
	var calls []CallSite
	var targets []int64
	starts := make([]bool, len(code))
	count, truncated := 0, false
	bad := func(pc int, why string) ([]CallSite, int, bool, error) {
		return nil, 0, false, fmt.Errorf("jarloader: bytecode offset %d: %s", pc, why)
	}
	for pc := 0; pc < len(code); {
		starts[pc] = true
		count++
		op, size := code[pc], 1
		switch {
		case op == 0x10 || op == 0x12 || op >= 0x15 && op <= 0x19 || op >= 0x36 && op <= 0x3a || op == 0xa9 || op == 0xbc:
			size = 2
		case op == 0x11 || op == 0x13 || op == 0x14 || op == 0x84 || op >= 0x99 && op <= 0xa8 || op >= 0xb2 && op <= 0xb8 || op == 0xbb || op == 0xbd || op == 0xc0 || op == 0xc1 || op == 0xc6 || op == 0xc7:
			size = 3
		case op == 0xc5:
			size = 4
		case op == 0xb9 || op == 0xba || op == 0xc8 || op == 0xc9:
			size = 5
		case op == 0xc4:
			if pc+1 >= len(code) {
				return bad(pc, "truncated wide")
			}
			next := code[pc+1]
			if next == 0x84 {
				size = 6
			} else if next >= 0x15 && next <= 0x19 || next >= 0x36 && next <= 0x3a || next == 0xa9 {
				size = 4
			} else {
				return bad(pc, "invalid wide opcode")
			}
		case op == 0xaa || op == 0xab:
			p := (pc + 4) &^ 3
			if p+8 > len(code) {
				return bad(pc, "truncated switch")
			}
			for _, pad := range code[pc+1 : p] {
				if pad != 0 {
					return bad(pc, "nonzero switch padding")
				}
			}
			i32 := func(at int) int64 { return int64(int32(binary.BigEndian.Uint32(code[at:]))) }
			targets = append(targets, int64(pc)+i32(p))
			if op == 0xaa {
				if p+12 > len(code) {
					return bad(pc, "truncated tableswitch")
				}
				low, high := i32(p+4), i32(p+8)
				n := high - low + 1
				if high < low || n > int64((len(code)-p-12)/4) {
					return bad(pc, "invalid tableswitch range")
				}
				for i := 0; i < int(n); i++ {
					targets = append(targets, int64(pc)+i32(p+12+4*i))
				}
				size = p + 12 + 4*int(n) - pc
			} else {
				n := i32(p + 4)
				if n < 0 || n > int64((len(code)-p-8)/8) {
					return bad(pc, "invalid lookupswitch count")
				}
				var previous int64
				for i := 0; i < int(n); i++ {
					key := i32(p + 8 + 8*i)
					if i > 0 && key <= previous {
						return bad(pc, "unsorted lookupswitch keys")
					}
					previous = key
					targets = append(targets, int64(pc)+i32(p+12+8*i))
				}
				size = p + 8 + 8*int(n) - pc
			}
		case op >= 0xca:
			return bad(pc, "reserved opcode")
		}
		if size > len(code)-pc {
			return bad(pc, "truncated instruction")
		}
		if op >= 0x99 && op <= 0xa8 || op == 0xc6 || op == 0xc7 {
			targets = append(targets, int64(pc)+int64(int16(binary.BigEndian.Uint16(code[pc+1:]))))
		}
		if op == 0xc8 || op == 0xc9 {
			targets = append(targets, int64(pc)+int64(int32(binary.BigEndian.Uint32(code[pc+1:]))))
		}
		if op >= 0xb6 && op <= 0xba {
			idx := binary.BigEndian.Uint16(code[pc+1:])
			if idx == 0 || int(idx) >= len(pool) {
				return bad(pc, "invalid invocation pool index")
			}
			c := pool[idx]
			call := CallSite{Offset: pc}
			switch op {
			case 0xb6, 0xb7, 0xb8:
				if c.tag != cpMethodref && !(op != 0xb6 && c.tag == cpInterfaceMethodref) {
					return bad(pc, "invalid method reference tag")
				}
				call.Opcode = map[byte]string{0xb6: "invokevirtual", 0xb7: "invokespecial", 0xb8: "invokestatic"}[op]
				call.Target = poolMethod(pool, idx)
			case 0xb9:
				if c.tag != cpInterfaceMethodref || code[pc+3] == 0 || code[pc+4] != 0 {
					return bad(pc, "invalid invokeinterface")
				}
				call.Opcode, call.Target = "invokeinterface", poolMethod(pool, idx)
			case 0xba:
				if c.tag != cpInvokeDynamic || code[pc+3] != 0 || code[pc+4] != 0 {
					return bad(pc, "invalid invokedynamic")
				}
				nt := pool[c.ntIndex]
				call.Opcode, call.BootstrapIndex = "invokedynamic", c.classIndex
				call.Target = MethodRef{Name: pool[nt.nameIndex].utf8, Descriptor: pool[nt.descIndex].utf8}
			}
			if len(calls) < limit {
				calls = append(calls, call)
			} else {
				truncated = true
			}
		}
		pc += size
	}
	for _, target := range targets {
		if target < 0 || target >= int64(len(code)) || !starts[int(target)] {
			return bad(0, "branch is not an instruction boundary")
		}
	}
	return calls, count, truncated, nil
}

// collectBytecode runs after structural validation. Unknown attributes remain
// skipped, not executed. No Java installation or decompiler is required.
func collectBytecode(r *reader, pool []constant, cf *ClassFile) error {
	cf.BytecodeParsed = true
	for kind := 0; kind < 2; kind++ {
		n, _ := r.u16()
		for i := 0; i < int(n); i++ {
			access, _ := r.u16()
			name, _ := r.u16()
			desc, _ := r.u16()
			attrs, _ := r.u16()
			method := MethodBody{Name: pool[name].utf8, Descriptor: pool[desc].utf8, Access: access}
			for j := 0; j < int(attrs); j++ {
				idx, _ := r.u16()
				size, _ := r.u32()
				data, _ := r.bytes(int(size))
				if kind != 1 || pool[idx].utf8 != "Code" {
					continue
				}
				method.MaxLocals = binary.BigEndian.Uint16(data[2:4])
				ncode := int(binary.BigEndian.Uint32(data[4:8]))
				code := data[8 : 8+ncode]
				calls, count, truncated, err := decodeInstructions(code, pool, maxClassCallSites-len(cf.CallSites))
				if err != nil {
					return fmt.Errorf("%s%s: %w", method.Name, method.Descriptor, err)
				}
				cf.InstructionCount += count
				cf.BytecodeTruncated = cf.BytecodeTruncated || truncated
				for _, call := range calls {
					call.Caller, call.CallerDescriptor = method.Name, method.Descriptor
					cf.CallSites = append(cf.CallSites, call)
				}
				// Retain raw code for precise argument resolution, but only
				// for methods that invoke a tracked sink and only when small:
				// unbounded retention would trade the class-bytes cap for RAM.
				if len(code) <= 64<<10 && methodCallsPreciseTarget(calls) {
					method.Code = append([]byte(nil), code...)
				}
				if binary.BigEndian.Uint16(data[8+ncode:]) == 0 {
					if len(code) == 1 && code[0] == 0xb1 {
						method.TrivialReturn = "void"
					}
					if len(code) == 2 && code[0] == 0x04 && code[1] == 0xac {
						method.TrivialReturn = "true"
					}
				}
			}
			if kind == 1 {
				cf.Methods = append(cf.Methods, method)
			}
		}
	}
	// Resolve the bootstrap method itself, never equate it with a lambda target.
	attrs, _ := r.u16()
	var bootstraps []uint16
	seen := false
	for i := 0; i < int(attrs); i++ {
		idx, _ := r.u16()
		size, _ := r.u32()
		data, _ := r.bytes(int(size))
		if pool[idx].utf8 != "BootstrapMethods" {
			continue
		}
		if seen {
			return fmt.Errorf("jarloader: duplicate BootstrapMethods")
		}
		seen = true
		b := &reader{b: data}
		n, err := b.u16()
		if err != nil {
			return err
		}
		for j := 0; j < int(n); j++ {
			ref, err := b.u16()
			if err != nil {
				return err
			}
			if ref == 0 || int(ref) >= len(pool) || pool[ref].tag != cpMethodHandle || (pool[ref].referenceKind != 6 && pool[ref].referenceKind != 8) {
				return fmt.Errorf("jarloader: invalid bootstrap method handle")
			}
			bootstraps = append(bootstraps, ref)
			args, err := b.u16()
			if err != nil {
				return err
			}
			for k := 0; k < int(args); k++ {
				arg, err := b.u16()
				if err != nil {
					return err
				}
				if arg == 0 || int(arg) >= len(pool) {
					return fmt.Errorf("jarloader: invalid bootstrap argument")
				}
				switch pool[arg].tag {
				case cpString, cpClass, cpInteger, cpLong, cpFloat, cpDouble, cpMethodHandle, cpMethodType, cpDynamic:
				default:
					return fmt.Errorf("jarloader: invalid bootstrap argument tag")
				}
			}
		}
		if b.pos != len(data) {
			return fmt.Errorf("jarloader: trailing BootstrapMethods bytes")
		}
	}
	for _, c := range pool {
		if (c.tag == cpInvokeDynamic || c.tag == cpDynamic) && int(c.classIndex) >= len(bootstraps) {
			return fmt.Errorf("jarloader: missing bootstrap method")
		}
	}
	for i := range cf.CallSites {
		call := &cf.CallSites[i]
		if call.Opcode == "invokedynamic" {
			ref := pool[bootstraps[call.BootstrapIndex]].referenceIndex
			m := poolMethod(pool, ref)
			call.Bootstrap = &m
		}
	}
	return nil
}
