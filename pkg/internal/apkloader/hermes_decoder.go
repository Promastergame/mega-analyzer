package apkloader

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

// Operand layout alphabet: r/R register8/32, b/h/i unsigned8/16/32,
// a/A relative address8/32, I signed32, d double (IEEE-754 bits).
type hermesOpcode struct {
	name, operands              string
	strings, functions, bigints uint8
}

type HermesOperand struct {
	Kind  string `json:"kind"`
	Value uint64 `json:"value"`
}
type HermesInstruction struct {
	Offset         uint32          `json:"offset"`
	FunctionOffset uint32          `json:"function_offset"`
	Opcode         byte            `json:"opcode"`
	Name           string          `json:"name"`
	Size           uint8           `json:"size"`
	Operands       []HermesOperand `json:"operands,omitempty"`
	StringRefs     []uint32        `json:"string_refs,omitempty"`
	FunctionRefs   []uint32        `json:"function_refs,omitempty"`
	CallKind       string          `json:"call_kind,omitempty"`
}

type HermesCallEdge struct {
	Caller, Callee, Offset, FunctionOffset uint32
	Kind, Confidence                       string
	Resolved                               bool
	CalleeRegister                         *uint32
	BuiltinID                              *uint32
}

type HermesGraphCoverage struct {
	Status           string   `json:"status"`
	TotalFunctions   int      `json:"total_functions"`
	ScannedFunctions int      `json:"scanned_functions"`
	DecodedFunctions int      `json:"decoded_functions"`
	FailedFunctions  int      `json:"failed_functions"`
	SkippedFunctions int      `json:"skipped_functions"`
	TotalBytes       uint64   `json:"total_bytes"`
	ScannedBytes     uint64   `json:"scanned_bytes"`
	Instructions     uint64   `json:"instructions"`
	Calls            int      `json:"calls"`
	RecordedCalls    int      `json:"recorded_calls"`
	DroppedCalls     int      `json:"dropped_calls"`
	DirectCalls      int      `json:"direct_calls"`
	IndirectCalls    int      `json:"indirect_calls"`
	BuiltinCalls     int      `json:"builtin_calls"`
	FunctionLimit    int      `json:"function_limit"`
	ByteLimit        uint64   `json:"byte_limit"`
	CallLimit        int      `json:"call_limit"`
	Diagnostics      []string `json:"diagnostics,omitempty"`
}
type HermesFunctionGraph struct {
	Edges    []HermesCallEdge
	Coverage HermesGraphCoverage
}

type decodedHermesInstruction struct {
	op     *hermesOpcode
	values [6]uint64
	size   int
}

func hermesOperandWidth(kind byte) int {
	switch kind {
	case 'r', 'b', 'a':
		return 1
	case 'h':
		return 2
	case 'R', 'i', 'A', 'I':
		return 4
	case 'd':
		return 8
	}
	return 0
}

func (h *HermesIndex) decodeInstruction(code []byte, pc int) (decodedHermesInstruction, error) {
	var decoded decodedHermesInstruction
	if h.order != binary.LittleEndian {
		return decoded, fmt.Errorf("%w: big-endian instructions", ErrUnsupportedHermes)
	}
	opcode := code[pc]
	if int(opcode) >= len(h.spec.opcodes) {
		return decoded, fmt.Errorf("%w: unknown opcode 0x%02x at +0x%x", ErrUnsupportedHermes, opcode, pc)
	}
	op := &h.spec.opcodes[opcode]
	size := 1
	for i := range op.operands {
		size += hermesOperandWidth(op.operands[i])
	}
	if size > len(code)-pc {
		return decoded, fmt.Errorf("%w: truncated %s at +0x%x (need %d bytes, have %d)", ErrMalformedHermes, op.name, pc, size, len(code)-pc)
	}
	decoded.op, decoded.size = op, size
	at := pc + 1
	for i := range op.operands {
		width := hermesOperandWidth(op.operands[i])
		var value uint64
		switch width {
		case 1:
			value = uint64(code[at])
		case 2:
			value = uint64(binary.LittleEndian.Uint16(code[at:]))
		case 4:
			value = uint64(binary.LittleEndian.Uint32(code[at:]))
		case 8:
			value = binary.LittleEndian.Uint64(code[at:])
		}
		decoded.values[i] = value
		at += width
		if op.strings&(1<<i) != 0 {
			if _, valid := h.StringByID(uint32(value)); !valid {
				return decoded, fmt.Errorf("%w: %s references unavailable string %d at +0x%x", ErrMalformedHermes, op.name, value, pc)
			}
		}
		if op.functions&(1<<i) != 0 && value >= uint64(len(h.Functions)) {
			return decoded, fmt.Errorf("%w: %s references invalid function %d at +0x%x", ErrMalformedHermes, op.name, value, pc)
		}
		if op.bigints&(1<<i) != 0 && value >= uint64(h.Header.BigIntCount) {
			return decoded, fmt.Errorf("%w: %s references invalid bigint %d at +0x%x", ErrMalformedHermes, op.name, value, pc)
		}
	}
	return decoded, nil
}

func hermesCallKind(name string) string {
	switch {
	case strings.HasPrefix(name, "CallDirect"):
		return "direct"
	case strings.HasPrefix(name, "CallBuiltin"):
		return "builtin"
	case strings.HasPrefix(name, "Call") || strings.HasPrefix(name, "Construct"):
		return "indirect"
	case name == "DirectEval":
		return "dynamic_eval"
	default:
		return ""
	}
}

// DecodeFunction walks exact instruction boundaries. It returns the valid
// prefix and an error on a malformed/unknown instruction, never byte-resyncs.
func (h *HermesIndex) DecodeFunction(id uint32) ([]HermesInstruction, error) {
	if id >= uint32(len(h.Functions)) {
		return nil, fmt.Errorf("function index %d out of range", id)
	}
	fn := h.Functions[id]
	if !fn.Valid {
		return nil, fmt.Errorf("function %d has an invalid header/range", id)
	}
	if fn.BytecodeSize == 0 {
		return nil, nil
	}
	code := h.data[int(fn.BytecodeOffset):int(uint64(fn.BytecodeOffset)+uint64(fn.BytecodeSize))]
	var result []HermesInstruction
	for pc := 0; pc < len(code); {
		if len(result) >= 100_000 {
			return result, fmt.Errorf("function %d instruction output limit reached", id)
		}
		d, err := h.decodeInstruction(code, pc)
		if err != nil {
			return result, err
		}
		insn := HermesInstruction{Offset: fn.BytecodeOffset + uint32(pc), FunctionOffset: uint32(pc), Opcode: code[pc], Name: d.op.name, Size: uint8(d.size), CallKind: hermesCallKind(d.op.name)}
		for i := range d.op.operands {
			kind := string(d.op.operands[i])
			if d.op.strings&(1<<i) != 0 {
				kind = "string_id"
				insn.StringRefs = append(insn.StringRefs, uint32(d.values[i]))
			}
			if d.op.functions&(1<<i) != 0 {
				kind = "function_id"
				insn.FunctionRefs = append(insn.FunctionRefs, uint32(d.values[i]))
			}
			if d.op.bigints&(1<<i) != 0 {
				kind = "bigint_id"
			}
			insn.Operands = append(insn.Operands, HermesOperand{Kind: kind, Value: d.values[i]})
		}
		result = append(result, insn)
		pc += d.size
	}
	return result, nil
}

func (h *HermesIndex) BuildFunctionGraph() []HermesCallEdge {
	return h.BuildFunctionGraphLimited(0, 0, 0)
}
func (h *HermesIndex) BuildFunctionGraphLimited(maxFunctions int, maxBytes uint64, maxCalls int) []HermesCallEdge {
	return h.BuildFunctionGraphDetailed(maxFunctions, maxBytes, maxCalls).Edges
}

// BuildFunctionGraphDetailed keeps recursion and separate call sites. Indirect
// calls remain unresolved. Limits and decoding failures have explicit coverage.
// Zero limits mean no cap; callers handling untrusted files should set budgets.
func (h *HermesIndex) BuildFunctionGraphDetailed(maxFunctions int, maxBytes uint64, maxCalls int) HermesFunctionGraph {
	return h.BuildFunctionGraphContext(context.Background(), maxFunctions, maxBytes, maxCalls)
}

func (h *HermesIndex) BuildFunctionGraphContext(ctx context.Context, maxFunctions int, maxBytes uint64, maxCalls int) HermesFunctionGraph {
	g := HermesFunctionGraph{Coverage: HermesGraphCoverage{Status: h.AnalysisStatus, TotalFunctions: len(h.Functions), FunctionLimit: maxFunctions, ByteLimit: maxBytes, CallLimit: maxCalls}}
	c := &g.Coverage
	c.Diagnostics = append(c.Diagnostics, h.Diagnostics...)
	partial := func(message string) {
		c.Status = "partial"
		if len(c.Diagnostics) < 64 {
			c.Diagnostics = append(c.Diagnostics, message)
		}
	}
	for _, fn := range h.Functions {
		c.TotalBytes += uint64(fn.BytecodeSize)
	}
graphLoop:
	for i, fn := range h.Functions {
		if err := ctx.Err(); err != nil {
			partial(err.Error())
			break
		}
		if maxFunctions > 0 && i >= maxFunctions {
			partial("function decoding limit reached")
			break
		}
		if !fn.Valid {
			c.ScannedFunctions++
			c.FailedFunctions++
			partial(fmt.Sprintf("function %d has an invalid header/range", i))
			continue
		}
		if maxBytes > 0 && uint64(fn.BytecodeSize) > maxBytes-c.ScannedBytes {
			partial("bytecode decoding budget reached")
			break
		}
		c.ScannedFunctions++
		if fn.BytecodeSize == 0 {
			c.DecodedFunctions++
			continue
		}
		code := h.data[int(fn.BytecodeOffset):int(uint64(fn.BytecodeOffset)+uint64(fn.BytecodeSize))]
		pc := 0
		for pc < len(code) {
			if c.Instructions%4096 == 0 {
				if err := ctx.Err(); err != nil {
					partial(err.Error())
					break graphLoop
				}
			}
			d, err := h.decodeInstruction(code, pc)
			if err != nil {
				c.FailedFunctions++
				partial(fmt.Sprintf("function %d: %v", i, err))
				break
			}
			c.ScannedBytes += uint64(d.size)
			c.Instructions++
			kind := hermesCallKind(d.op.name)
			if kind != "" {
				c.Calls++
				edge := HermesCallEdge{Caller: uint32(i), Callee: math.MaxUint32, Offset: fn.BytecodeOffset + uint32(pc), FunctionOffset: uint32(pc), Kind: kind, Confidence: "unresolved"}
				switch kind {
				case "direct":
					edge.Callee, edge.Resolved, edge.Confidence = uint32(d.values[2]), true, "instruction"
					c.DirectCalls++
				case "builtin":
					id := uint32(d.values[1])
					edge.BuiltinID = &id
					edge.Confidence = "instruction"
					c.BuiltinCalls++
				default:
					register := uint32(d.values[1])
					edge.CalleeRegister = &register
					c.IndirectCalls++
				}
				if maxCalls <= 0 || len(g.Edges) < maxCalls {
					g.Edges = append(g.Edges, edge)
				} else {
					c.DroppedCalls++
				}
			}
			pc += d.size
		}
		if pc == len(code) {
			c.DecodedFunctions++
		}
	}
	c.RecordedCalls = len(g.Edges)
	c.SkippedFunctions = c.TotalFunctions - c.ScannedFunctions
	if c.DroppedCalls > 0 {
		partial(fmt.Sprintf("call-site output limit reached: %d/%d recorded", c.RecordedCalls, c.Calls))
	}
	return g
}
