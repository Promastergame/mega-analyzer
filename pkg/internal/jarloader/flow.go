package jarloader

// Intraprocedural constant-string propagation over JVM bytecode.
//
// This answers one narrow question with proof: which constant string flows
// into a given argument slot of a given call site? It does NOT do general
// taint analysis, interprocedural summaries, or reachability: anything it
// cannot model precisely degrades to Unknown, and only proven constants are
// ever reported. Exception-handler edges are not followed (only normal
// control flow); a constant reported here reached the call on an analyzed
// path, which is evidence — not proof of execution.

import (
	"strings"
)

// flowVal is a symbolic string value on the operand stack or in a local.
type flowVal struct {
	known bool
	s     string
}

func flowUnknown() flowVal { return flowVal{} }

func flowConst(s string) flowVal { return flowVal{known: true, s: s} }

// flowLimits bound the analysis. Exceeding them degrades to Unknown, never
// to a wrong constant.
const (
	flowMaxSteps       = 20000
	flowMaxVisitsPerPC = 4
)

// preciseArgTargets are calls whose first argument we resolve exactly.
// Every entry takes the resolved string in slot 0 (transformation name,
// algorithm name), regardless of overload arity.
var preciseArgTargets = map[string]bool{
	"javax.crypto.Cipher.getInstance":         true,
	"java.security.MessageDigest.getInstance": true,
}

// resolvePreciseArgs runs the propagation over one method body and returns,
// for each invoke of a precise target, the known argument-0 constant.
// Unknown arguments are simply absent from the map.
func resolvePreciseArgs(code []byte, maxLocals uint16, pool []constant) map[int]string {
	out := map[int]string{}
	if len(code) == 0 {
		return out
	}
	type state struct {
		stack  []flowVal
		locals []flowVal
	}
	newState := func() state {
		return state{locals: make([]flowVal, int(maxLocals))}
	}
	joinVal := func(a, b flowVal) flowVal {
		if a.known && b.known && a.s == b.s {
			return a
		}
		return flowUnknown()
	}
	states := map[int]state{}
	visits := map[int]int{}
	queue := []int{0}
	states[0] = newState()
	steps := 0

	copyState := func(s state) state {
		return state{
			stack:  append([]flowVal(nil), s.stack...),
			locals: append([]flowVal(nil), s.locals...),
		}
	}
	mergeInto := func(pc int, incoming state) {
		cur, ok := states[pc]
		if !ok {
			states[pc] = copyState(incoming)
			queue = append(queue, pc)
			return
		}
		merged := copyState(cur)
		changed := false
		if len(incoming.stack) != len(cur.stack) {
			// Unbalanced join (should not happen in verified code):
			// drop to empty rather than misalign slots.
			merged.stack = nil
			changed = len(cur.stack) != 0
		} else {
			for i := range incoming.stack {
				j := joinVal(cur.stack[i], incoming.stack[i])
				if j != cur.stack[i] {
					changed = true
				}
				merged.stack[i] = j
			}
		}
		if len(incoming.locals) != len(cur.locals) {
			merged.locals = make([]flowVal, len(cur.locals))
			changed = true
		} else {
			for i := range incoming.locals {
				j := joinVal(cur.locals[i], incoming.locals[i])
				if j != cur.locals[i] {
					changed = true
				}
				merged.locals[i] = j
			}
		}
		if changed && visits[pc] < flowMaxVisitsPerPC {
			states[pc] = merged
			queue = append(queue, pc)
		}
	}

	pop := func(st *state, n int) []flowVal {
		if n <= 0 || len(st.stack) < n {
			return nil
		}
		got := append([]flowVal(nil), st.stack[len(st.stack)-n:]...)
		st.stack = st.stack[:len(st.stack)-n]
		return got
	}

	for len(queue) > 0 && steps < flowMaxSteps {
		pc := queue[0]
		queue = queue[1:]
		steps++
		visits[pc]++
		cur, ok := states[pc]
		if !ok || pc < 0 || pc >= len(code) {
			continue
		}
		st := copyState(cur)
		op := code[pc]
		size, okSize := instrSize(code, pc)
		if !okSize {
			continue // undecodable here: path dies, no claims from it
		}
		next := pc + size
		succ := func(at int, s state) {
			if at < 0 || at >= len(code) {
				return
			}
			mergeInto(at, s)
		}

		// transfer implements the operand-stack effect. Anything unmodeled
		// resets the stack: sound (no wrong constants), possibly imprecise.
		// Invokes (0xb6-0xba) and control flow (branches, jumps, switches,
		// returns) are handled by their dedicated sections below and must
		// never reach the resetting default.
		u16 := func(at int) int {
			if at < 0 || at+1 >= len(code) {
				return -1
			}
			return int(code[at])<<8 | int(code[at+1])
		}
		isInvoke := op >= 0xb6 && op <= 0xba
		isControl := op >= 0x99 && op <= 0xa9 || op == 0xaa || op == 0xab ||
			op >= 0xac && op <= 0xb1 || op == 0xbf || op == 0xc8 || op == 0xc9
		if !isInvoke && !isControl {
			switch {
			case op == 0x12: // ldc
				idx := int(code[pc+1])
				if idx < len(pool) && pool[idx].tag == cpString {
					st.stack = append(st.stack, flowConst(pool[pool[idx].stringIndex].utf8))
				} else {
					st.stack = append(st.stack, flowUnknown())
				}
			case op == 0x13: // ldc_w
				idx := u16(pc + 1)
				if idx >= 0 && idx < len(pool) && pool[idx].tag == cpString {
					st.stack = append(st.stack, flowConst(pool[pool[idx].stringIndex].utf8))
				} else {
					st.stack = append(st.stack, flowUnknown())
				}
			case op == 0x14: // ldc2_w
				st.stack = append(st.stack, flowUnknown(), flowUnknown())
			case op >= 0x15 && op <= 0x19: // iload..aload
				n := int(code[pc+1])
				if n < len(st.locals) {
					st.stack = append(st.stack, st.locals[n])
				} else {
					st.stack = append(st.stack, flowUnknown())
				}
			case op >= 0x1a && op <= 0x2d: // *_load_n
				n := int((op - 0x1a) % 4)
				if n < len(st.locals) {
					st.stack = append(st.stack, st.locals[n])
				} else {
					st.stack = append(st.stack, flowUnknown())
				}
			case op >= 0x36 && op <= 0x3a: // istore..astore
				n := int(code[pc+1])
				if v := pop(&st, 1); v == nil {
					st.stack = nil
				} else if n < len(st.locals) {
					st.locals[n] = v[0]
				}
			case op >= 0x3b && op <= 0x4e: // *_store_n
				n := int((op - 0x3b) % 4)
				if v := pop(&st, 1); v == nil {
					st.stack = nil
				} else if n < len(st.locals) {
					st.locals[n] = v[0]
				}
			case op == 0x57: // pop
				if pop(&st, 1) == nil {
					st.stack = nil
				}
			case op == 0x59: // dup
				if len(st.stack) < 1 {
					st.stack = nil
				} else {
					st.stack = append(st.stack, st.stack[len(st.stack)-1])
				}
			case op == 0x5a: // dup_x1 [..., b, a] -> [..., a, b, a]
				if len(st.stack) < 2 {
					st.stack = nil
				} else {
					n := len(st.stack)
					a, b := st.stack[n-1], st.stack[n-2]
					st.stack = append(st.stack[:n-2], a, b, a)
				}
			case op == 0x5f: // swap
				if len(st.stack) < 2 {
					st.stack = nil
				} else {
					n := len(st.stack)
					st.stack[n-1], st.stack[n-2] = st.stack[n-2], st.stack[n-1]
				}
			case op == 0x84: // iinc: locals only, stack untouched
			case op == 0xc5: // multianewarray: pop dynamic dimension count
				if n := int(code[pc+3]); pop(&st, n) == nil {
					st.stack = nil
				} else {
					st.stack = append(st.stack, flowUnknown())
				}
			default:
				if pops, pushes, known := stackEffect(op); known {
					if pop(&st, pops) == nil {
						st.stack = nil
					} else {
						for i := 0; i < pushes; i++ {
							st.stack = append(st.stack, flowUnknown())
						}
					}
				} else {
					st.stack = nil
				}
			}
		}

		// Invokes pop exact slots from the descriptor and record precise
		// targets. Unresolvable references kill the path, never the truth.
		if isInvoke {
			idx := u16(pc + 1)
			if idx < 0 || idx >= len(pool) {
				continue
			}
			var ref MethodRef
			switch op {
			case 0xb6, 0xb7, 0xb8:
				c := pool[idx]
				if c.tag != cpMethodref && !(op != 0xb6 && c.tag == cpInterfaceMethodref) {
					continue
				}
				ref = poolMethod(pool, uint16(idx))
			case 0xb9:
				if pool[idx].tag != cpInterfaceMethodref {
					continue
				}
				ref = poolMethod(pool, uint16(idx))
			case 0xba:
				// invokedynamic dispatches via bootstrap: slot math from
				// the descriptor, values unknown.
				c := pool[idx]
				if c.tag != cpInvokeDynamic {
					continue
				}
				nt := pool[c.ntIndex]
				nargs := countParamSlots(pool[nt.descIndex].utf8)
				if pop(&st, nargs) == nil {
					continue
				}
				st.stack = append(st.stack, flowUnknown())
			}
			if op != 0xba {
				static := op == 0xb8
				nargs := countParamSlots(ref.Descriptor)
				need := nargs
				if !static {
					need++
				}
				vals := pop(&st, need)
				if vals == nil {
					continue
				}
				args := vals
				if !static {
					args = vals[:len(vals)-1]
				}
				if preciseArgTargets[ref.Class+"."+ref.Name] && len(args) > 0 && args[0].known {
					out[pc] = args[0].s
				}
				if ret := returnSlots(ref.Descriptor); ret > 0 {
					for i := 0; i < ret; i++ {
						st.stack = append(st.stack, flowUnknown())
					}
				}
			}
		}

		// Control-flow successors.
		switch {
		case op == 0xa7 || op == 0xc8: // goto / goto_w
			succ(pc+branchOffset(code, pc, op), st)
		case op == 0xa8 || op == 0xc9: // jsr / jsr_w (obsolete)
			st.stack = append(st.stack, flowUnknown())
			succ(pc+branchOffset(code, pc, op), st)
		case op == 0xa9: // ret: terminal for our purposes
		case op >= 0xac && op <= 0xb1 || op == 0xbf: // returns / athrow: terminal
		case op >= 0x99 && op <= 0xa6 || op == 0xc6 || op == 0xc7: // conditional branches
			pops := 1
			if op >= 0x9f && op <= 0xa6 {
				pops = 2
			}
			if pop(&st, pops) == nil {
				st = newState()
			}
			off := branchOffset(code, pc, op)
			succ(next, st)
			succ(pc+off, copyState(st))
		case op == 0xaa || op == 0xab: // switch: pop index, all targets
			if pop(&st, 1) == nil {
				st = newState()
			}
			for _, t := range switchTargets(code, pc, op) {
				succ(t, copyState(st))
			}
		default:
			succ(next, st)
		}
	}
	return out
}

// instrSize mirrors decodeInstructions: exact bytecode sizes, no operand
// decoding. Anything undecodable reports false and the path dies.
func instrSize(code []byte, pc int) (int, bool) {
	if pc < 0 || pc >= len(code) {
		return 0, false
	}
	op := code[pc]
	var size int
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
			return 0, false
		}
		next := code[pc+1]
		if next == 0x84 {
			size = 6
		} else if next >= 0x15 && next <= 0x19 || next >= 0x36 && next <= 0x3a || next == 0xa9 {
			size = 4
		} else {
			return 0, false
		}
	case op == 0xaa || op == 0xab:
		p := (pc + 4) &^ 3
		if p+8 > len(code) {
			return 0, false
		}
		if op == 0xaa {
			if p+12 > len(code) {
				return 0, false
			}
			i32 := func(at int) int64 {
				return int64(int32(uint32(code[at])<<24 | uint32(code[at+1])<<16 | uint32(code[at+2])<<8 | uint32(code[at+3])))
			}
			low, high := i32(p+4), i32(p+8)
			n := high - low + 1
			if high < low || n < 0 || n > int64((len(code)-p-12)/4) {
				return 0, false
			}
			size = p + 12 + 4*int(n) - pc
		} else {
			n := int64(int32(uint32(code[p+4])<<24 | uint32(code[p+5])<<16 | uint32(code[p+6])<<8 | uint32(code[p+7])))
			if n < 0 || n > int64((len(code)-p-8)/8) {
				return 0, false
			}
			size = p + 8 + 8*int(n) - pc
		}
	case op >= 0xca:
		return 0, false
	default:
		size = 1
	}
	if size <= 0 || size > len(code)-pc {
		return 0, false
	}
	return size, true
}

// stackEffect returns coarse pop/push counts for opcodes whose exact slots
// do not matter (results are always Unknown). ok=false means "unmodeled".
func stackEffect(op byte) (pops, pushes int, ok bool) {
	switch {
	case op <= 0x0f || op == 0x10 || op == 0x11:
		return 0, 1, true // const pushes (value unknown here)
	case op >= 0x2e && op <= 0x35: // *aload
		return 2, 1, true
	case op >= 0x4f && op <= 0x56: // *astore
		return 3, 0, true
	case op >= 0x60 && op <= 0x83 && op != 0x84:
		return arithEffect(op)
	case op >= 0x85 && op <= 0x93: // conversions
		return convEffect(op)
	case op == 0x94 || op == 0x97 || op == 0x98: // lcmp, dcmpl, dcmpg
		return 4, 1, true
	case op == 0x95 || op == 0x96: // fcmpl, fcmpg
		return 2, 1, true
	case op == 0xbb: // new
		return 0, 1, true
	case op == 0xbd: // anewarray
		return 1, 1, true
	case op == 0xbe: // arraylength
		return 1, 1, true
	case op == 0xc0 || op == 0xc1: // checkcast / instanceof
		return 1, 1, true
	case op == 0xc2 || op == 0xc3: // monitorenter/exit
		return 1, 0, true
	}
	return 0, 0, false
}

func arithEffect(op byte) (int, int, bool) {
	// Slot counts: int/float values occupy one slot, long/double two.
	switch op {
	case 0x60, 0x64, 0x68, 0x6c, 0x70, 0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82: // int binary
		return 2, 1, true
	case 0x74: // ineg
		return 1, 1, true
	case 0x61, 0x65, 0x69, 0x6d, 0x71, 0x79, 0x7d, 0x7f, 0x81, 0x83: // long binary
		return 4, 2, true
	case 0x75: // lneg
		return 2, 2, true
	case 0x62, 0x66, 0x6a, 0x6e, 0x72: // float binary
		return 2, 1, true
	case 0x76: // fneg
		return 1, 1, true
	case 0x63, 0x67, 0x6b, 0x6f, 0x73: // double binary
		return 4, 2, true
	case 0x77: // dneg
		return 2, 2, true
	}
	return 0, 0, false
}

func convEffect(op byte) (int, int, bool) {
	// pop slots, push slots; long/double occupy two.
	switch op {
	case 0x85: // i2l
		return 1, 2, true
	case 0x86: // i2f
		return 1, 1, true
	case 0x87: // i2d
		return 1, 2, true
	case 0x88, 0x89: // l2i, l2f
		return 2, 1, true
	case 0x8a: // l2d
		return 2, 2, true
	case 0x8b: // f2i
		return 1, 1, true
	case 0x8c, 0x8d: // f2l, f2d
		return 1, 2, true
	case 0x8e, 0x90: // d2i, d2f
		return 2, 1, true
	case 0x8f: // d2l
		return 2, 2, true
	case 0x91, 0x92, 0x93: // i2b, i2c, i2s
		return 1, 1, true
	}
	return 0, 0, false
}

// countParamSlots counts operand-stack slots in a method descriptor's
// parameter list (long/double occupy two).
func countParamSlots(desc string) int {
	i := strings.Index(desc, "(")
	j := strings.Index(desc, ")")
	if i < 0 || j < i {
		return 0
	}
	slots := 0
	for k := i + 1; k < j; {
		switch desc[k] {
		case 'B', 'C', 'F', 'I', 'S', 'Z':
			slots++
			k++
		case 'J', 'D':
			slots += 2
			k++
		case 'L':
			e := strings.Index(desc[k:], ";")
			if e < 0 {
				return slots
			}
			k += e + 1
			slots++
		case '[':
			for k < j && desc[k] == '[' {
				k++
			}
			if k < j && desc[k] == 'L' {
				e := strings.Index(desc[k:], ";")
				if e < 0 {
					return slots
				}
				k += e + 1
			} else if k < j {
				k++
			}
			slots++
		default:
			k++
		}
	}
	return slots
}

// returnSlots counts result slots from a method descriptor (0 for void).
func returnSlots(desc string) int {
	j := strings.Index(desc, ")")
	if j < 0 || j+1 >= len(desc) {
		return 0
	}
	switch desc[j+1] {
	case 'V':
		return 0
	case 'J', 'D':
		return 2
	default:
		return 1
	}
}

// branchOffset reads a 2-byte (or 4-byte wide) branch displacement.
func branchOffset(code []byte, pc int, op byte) int {
	if op == 0xc8 || op == 0xc9 {
		if pc+4 >= len(code) {
			return 0
		}
		return int(int32(uint32(code[pc+1])<<24 | uint32(code[pc+2])<<16 | uint32(code[pc+3])<<8 | uint32(code[pc+4])))
	}
	if pc+2 >= len(code) {
		return 0
	}
	return int(int16(uint16(code[pc+1])<<8 | uint16(code[pc+2])))
}

// switchTargets lists every branch destination of a switch instruction.
func switchTargets(code []byte, pc int, op byte) []int {
	p := (pc + 4) &^ 3
	get := func(at int) int64 {
		if at+3 >= len(code) {
			return 0
		}
		return int64(int32(uint32(code[at])<<24 | uint32(code[at+1])<<16 | uint32(code[at+2])<<8 | uint32(code[at+3])))
	}
	var out []int
	if p+8 > len(code) {
		return out
	}
	out = append(out, pc+int(get(p)))
	if op == 0xaa {
		low := get(p + 4)
		high := get(p + 8)
		n := high - low + 1
		if high < low || n < 0 || n > 1<<20 {
			return out[:1]
		}
		for i := int64(0); i < n; i++ {
			out = append(out, pc+int(get(p+12+int(i)*4)))
		}
	} else {
		n := get(p + 4)
		if n < 0 || n > 1<<20 {
			return out[:1]
		}
		for i := int64(0); i < n; i++ {
			out = append(out, pc+int(get(p+12+int(i)*8)))
		}
	}
	return out
}
