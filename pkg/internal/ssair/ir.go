// Package ssair provides a unified Static Single Assignment Intermediate
// Representation that bridges Go analysis pipelines and the Rust OmniSec
// engine. Language-agnostic typed instruction graph for dataflow, DCE,
// and cross-module optimization.
package ssair

import (
	"fmt"
	"strings"
)

// Type represents an SSA type.
type Type uint8

const (
	TypeVoid Type = iota
	TypeBool
	TypeI8
	TypeI16
	TypeI32
	TypeI64
	TypeF32
	TypeF64
	TypePtr
	TypeArray
	TypeStruct
	TypeFunc
)

func (t Type) String() string {
	names := [...]string{"void", "bool", "i8", "i16", "i32", "i64", "f32", "f64", "ptr", "array", "struct", "func"}
	if int(t) < len(names) {
		return names[t]
	}
	return fmt.Sprintf("type(%d)", t)
}

// Value is a named SSA value (virtual register).
type Value struct {
	ID      int
	Name    string
	Ty      Type
	DefInst *Instruction
}

func (v *Value) String() string {
	if v.Name != "" {
		return "%" + v.Name
	}
	return fmt.Sprintf("%%v%d", v.ID)
}

// Opcode enumerates all SSA IR instructions.
type Opcode uint16

const (
	OpAdd Opcode = iota
	OpSub
	OpMul
	OpDiv
	OpMod
	OpNeg
	OpAnd
	OpOr
	OpXor
	OpShl
	OpShr
	OpNot
	OpCmpEq
	OpCmpNe
	OpCmpLt
	OpCmpLe
	OpCmpGt
	OpCmpGe
	OpLoad
	OpStore
	OpAlloca
	OpGetElementPtr
	OpBranch
	OpCondBranch
	OpSwitch
	OpReturn
	OpCall
	OpInvoke
	OpPhi
	OpConst
	OpGlobal
	OpCast
	OpBitcast
	OpTrunc
	OpZext
	OpSext
	OpNop
	OpUnreachable
	OpOpaqueTrue  // opaque predicate marker (always true)
	OpOpaqueFalse // opaque predicate marker (always false)
)

func (o Opcode) String() string {
	names := map[Opcode]string{
		OpAdd: "add", OpSub: "sub", OpMul: "mul", OpDiv: "div", OpMod: "mod", OpNeg: "neg",
		OpAnd: "and", OpOr: "or", OpXor: "xor", OpShl: "shl", OpShr: "shr", OpNot: "not",
		OpCmpEq: "cmp.eq", OpCmpNe: "cmp.ne", OpCmpLt: "cmp.lt", OpCmpLe: "cmp.le",
		OpCmpGt: "cmp.gt", OpCmpGe: "cmp.ge",
		OpLoad: "load", OpStore: "store", OpAlloca: "alloca", OpGetElementPtr: "gep",
		OpBranch: "br", OpCondBranch: "br.cond", OpSwitch: "switch",
		OpReturn: "ret", OpCall: "call", OpInvoke: "invoke", OpPhi: "phi",
		OpConst: "const", OpGlobal: "global",
		OpCast: "cast", OpBitcast: "bitcast", OpTrunc: "trunc", OpZext: "zext", OpSext: "sext",
		OpNop: "nop", OpUnreachable: "unreachable",
		OpOpaqueTrue: "opaque.true", OpOpaqueFalse: "opaque.false",
	}
	if s, ok := names[o]; ok {
		return s
	}
	return fmt.Sprintf("op(%d)", o)
}

// Instruction is a single SSA instruction.
type Instruction struct {
	Op         Opcode
	Result     *Value
	Operands   []*Value
	Block      *BasicBlock
	Metadata   map[string]string
	ConstI64   int64
	ConstF64   float64
	ConstStr   string
	TrueBlock  *BasicBlock
	FalseBlock *BasicBlock
	Targets    []*BasicBlock
}

func (inst *Instruction) String() string {
	var b strings.Builder
	if inst.Result != nil {
		fmt.Fprintf(&b, "%s = ", inst.Result)
	}
	b.WriteString(inst.Op.String())
	for i, op := range inst.Operands {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, " %s", op)
	}
	if inst.Op == OpConst {
		if inst.ConstStr != "" {
			fmt.Fprintf(&b, " %q", inst.ConstStr)
		} else {
			fmt.Fprintf(&b, " %d", inst.ConstI64)
		}
	}
	return b.String()
}

// BasicBlock is a sequence of instructions with a single entry/exit.
type BasicBlock struct {
	ID           int
	Label        string
	Instructions []*Instruction
	Preds        []*BasicBlock
	Succs        []*BasicBlock
	Func         *Function
	DomParent    *BasicBlock
	DomChildren  []*BasicBlock
	LoopDepth    int
}

func (bb *BasicBlock) String() string {
	if bb.Label != "" {
		return bb.Label
	}
	return fmt.Sprintf("bb%d", bb.ID)
}

// Append adds an instruction to this block.
func (bb *BasicBlock) Append(inst *Instruction) {
	inst.Block = bb
	bb.Instructions = append(bb.Instructions, inst)
}

// Terminator returns the last instruction if it's a control-flow terminator.
func (bb *BasicBlock) Terminator() *Instruction {
	if len(bb.Instructions) == 0 {
		return nil
	}
	last := bb.Instructions[len(bb.Instructions)-1]
	switch last.Op {
	case OpBranch, OpCondBranch, OpSwitch, OpReturn, OpUnreachable:
		return last
	}
	return nil
}

// Function represents a callable unit in SSA form.
type Function struct {
	Name        string
	Params      []*Value
	ReturnType  Type
	Blocks      []*BasicBlock
	Module      *Module
	nextValueID int
	nextBlockID int
}

// NewBlock creates a new basic block.
func (f *Function) NewBlock(label string) *BasicBlock {
	bb := &BasicBlock{ID: f.nextBlockID, Label: label, Func: f}
	f.nextBlockID++
	f.Blocks = append(f.Blocks, bb)
	return bb
}

// NewValue allocates a fresh SSA value.
func (f *Function) NewValue(name string, ty Type) *Value {
	v := &Value{ID: f.nextValueID, Name: name, Ty: ty}
	f.nextValueID++
	return v
}

// Entry returns the entry block.
func (f *Function) Entry() *BasicBlock {
	if len(f.Blocks) == 0 {
		return nil
	}
	return f.Blocks[0]
}

// Module is the top-level SSA IR container.
type Module struct {
	Name      string
	Source    string // "smali", "dex", "pe", "elf"
	Functions []*Function
	Globals   []*Value
}

// NewModule creates a new empty SSA IR module.
func NewModule(name, source string) *Module {
	return &Module{Name: name, Source: source}
}

// AddFunction registers a function in the module.
func (m *Module) AddFunction(name string, retType Type, params ...Type) *Function {
	f := &Function{Name: name, ReturnType: retType, Module: m}
	for i, pt := range params {
		p := f.NewValue(fmt.Sprintf("arg%d", i), pt)
		f.Params = append(f.Params, p)
	}
	m.Functions = append(m.Functions, f)
	return f
}

// Dump returns a human-readable textual representation.
func (m *Module) Dump() string {
	var b strings.Builder
	fmt.Fprintf(&b, "; module %q  source=%s\n", m.Name, m.Source)
	for _, f := range m.Functions {
		fmt.Fprintf(&b, "func @%s(", f.Name)
		for i, p := range f.Params {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s %s", p, p.Ty)
		}
		fmt.Fprintf(&b, ") -> %s {\n", f.ReturnType)
		for _, bb := range f.Blocks {
			fmt.Fprintf(&b, "  %s:\n", bb)
			for _, inst := range bb.Instructions {
				fmt.Fprintf(&b, "    %s\n", inst)
			}
		}
		b.WriteString("}\n\n")
	}
	return b.String()
}

// Stats returns summary statistics.
type ModuleStats struct {
	Functions, Blocks, Instructions, Globals, PhiNodes int
}

func (m *Module) Stats() ModuleStats {
	s := ModuleStats{Functions: len(m.Functions), Globals: len(m.Globals)}
	for _, f := range m.Functions {
		s.Blocks += len(f.Blocks)
		for _, bb := range f.Blocks {
			s.Instructions += len(bb.Instructions)
			for _, inst := range bb.Instructions {
				if inst.Op == OpPhi {
					s.PhiNodes++
				}
			}
		}
	}
	return s
}
