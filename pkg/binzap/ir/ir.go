// Package ir defines a small, dialect-neutral intermediate representation used
// by BinZAP's static analysis. Smali and x86 token streams are lowered into the
// same IR so that control-flow, data-flow and taint analysis can be written
// once and reused across both dialects.
package ir

// OpKind is the normalized operation category of an instruction.
type OpKind int

const (
	OpUnknown    OpKind = iota
	OpConst             // load a constant (string / int) into Dst
	OpMove              // Dst <- Args[0]
	OpInvoke            // call Method with Args; result (if any) in ResultReg
	OpMoveResult        // Dst <- result of preceding invoke
	OpReturn            // return (optionally Args[0])
	OpBranch            // conditional/unconditional jump to Target label
	OpFieldGet          // Dst <- field
	OpFieldPut          // field <- Args[0]
)

// Instr is a single normalized instruction.
type Instr struct {
	Op        OpKind
	Opcode    string   // raw opcode text (e.g. "invoke-virtual", "call")
	Dst       string   // destination register, if any
	Args      []string // source registers
	ResultReg string   // register receiving an invoke result (via move-result)
	Str       string   // string literal payload (const-string)
	HasStr    bool
	Method    string // method reference target (invoke)
	Target    string // branch target label
	Line      int
	Column    int
	Raw       string // reconstructed source text, used as evidence
}

// Block is a basic block: a maximal straight-line instruction sequence.
type Block struct {
	Label  string
	Instrs []*Instr
	Succs  []*Block
}

// Method is a lowered method/function.
type Method struct {
	Name    string
	Dialect string
	Params  []string
	Instrs  []*Instr // linear instruction list (program order)
	Blocks  []*Block // basic blocks with successor edges
}

// Program is the lowered representation of one analyzed file.
type Program struct {
	File    string
	Dialect string
	Methods []*Method
}

// Stats summarizes a lowered program (used by tests / diagnostics).
type Stats struct {
	Methods      int
	Instructions int
	Blocks       int
	Invokes      int
}

// Stats computes counts over the program.
func (p *Program) Stats() Stats {
	s := Stats{Methods: len(p.Methods)}
	for _, m := range p.Methods {
		s.Instructions += len(m.Instrs)
		s.Blocks += len(m.Blocks)
		for _, in := range m.Instrs {
			if in.Op == OpInvoke {
				s.Invokes++
			}
		}
	}
	return s
}
