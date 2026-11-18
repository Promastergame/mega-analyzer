package apkloader

import "fmt"

// TransformEntry is an auditable, machine-readable proof that the deobfuscator
// changed program IR. It records the exact method/block/instruction and the
// reason a semantics-preserving rewrite was permitted.
type TransformEntry struct {
	Pass       string  `json:"pass"`
	ClassName  string  `json:"class_name,omitempty"`
	MethodName string  `json:"method_name,omitempty"`
	BlockID    int     `json:"block_id"`
	InsnIndex  int     `json:"instruction_index"`
	Before     MIRInsn `json:"before"`
	After      MIRInsn `json:"after"`
	Proof      string  `json:"proof"`
	Confidence int     `json:"confidence"`
}

// TransformSession owns the current CFG and guarantees that graph metadata and
// SSA are rebuilt after control-flow rewrites. Passes must mutate through this
// object so stale SSA/dominator state cannot leak into later passes.
type TransformSession struct {
	CFG     *CFG
	SSA     *SSAForm
	Journal []TransformEntry
}

func NewTransformSession(cfg *CFG) *TransformSession {
	s := &TransformSession{CFG: cfg}
	s.RebuildAnalysis()
	return s
}

func (s *TransformSession) RebuildAnalysis() {
	if s == nil || s.CFG == nil {
		return
	}
	normalizeCFG(s.CFG)
	s.CFG.ComputeDominance()
	s.CFG.ComputeDominanceFrontier()
	s.SSA = ConvertToSSA(s.CFG)
}

// FoldLocalConstants performs path-safe basic-block constant propagation. The
// environment is intentionally reset at every block boundary: this is less
// aggressive than a global map but cannot fold through conflicting predecessor
// definitions. Every material rewrite is journaled.
func (s *TransformSession) FoldLocalConstants(className, methodName string) int {
	if s == nil || s.CFG == nil {
		return 0
	}
	changes := 0
	controlChanged := false
	for _, block := range s.CFG.Blocks {
		known := make(map[int16]int64)
		for i := range block.Insns {
			insn := &block.Insns[i]
			before := *insn
			var value int64
			var ok bool
			proof := ""

			switch insn.Kind {
			case MIR_CONST:
				known[insn.Dst] = normalizeMIRInt(insn.Imm, insn.DataType)
				continue
			case MIR_MOVE:
				value, ok = known[insn.Src1]
				if ok {
					proof = fmt.Sprintf("v%d is the local constant %d", insn.Src1, value)
				}
			case MIR_NEG, MIR_NOT:
				v, exists := known[insn.Src1]
				if exists {
					if insn.Kind == MIR_NEG {
						value = normalizeMIRInt(-v, insn.DataType)
						proof = fmt.Sprintf("negation of local constant v%d=%d", insn.Src1, v)
					} else {
						value = normalizeMIRInt(^v, insn.DataType)
						proof = fmt.Sprintf("bitwise complement of local constant v%d=%d", insn.Src1, v)
					}
					ok = true
				}
			case MIR_ADD, MIR_SUB, MIR_MUL, MIR_DIV, MIR_REM, MIR_AND, MIR_OR, MIR_XOR, MIR_SHL, MIR_SHR, MIR_USHR:
				a, aok := known[insn.Src1]
				b, bok := known[insn.Src2]
				if aok && bok {
					value, ok = evalMIRBinary(insn.Kind, insn.DataType, a, b)
					if ok {
						proof = fmt.Sprintf("both operands are local constants: v%d=%d, v%d=%d", insn.Src1, a, insn.Src2, b)
					}
				}
			case MIR_IF:
				a, aok := known[insn.Src1]
				b := int64(0)
				bok := true
				if insn.Cond <= CondLE {
					b, bok = known[insn.Src2]
				}
				if aok && bok && len(block.Succs) >= 2 {
					taken := evalMIRCondition(insn.Cond, a, b)
					if taken {
						insn.Kind = MIR_GOTO
						block.Succs = []*BasicBlock{block.Succs[0]}
						block.IsFallthrough = false
					} else {
						*insn = MIRInsn{Kind: MIR_NOP, Offset: insn.Offset, Dst: -1, Src1: -1, Src2: -1}
						block.Succs = []*BasicBlock{block.Succs[1]}
						block.IsFallthrough = true
					}
					proof = fmt.Sprintf("condition %d evaluated from local constants (%d,%d) => %v", before.Cond, a, b, taken)
					s.record("branch-fold", className, methodName, block.ID, i, before, *insn, proof)
					changes++
					controlChanged = true
				}
			}

			if ok && insn.Dst >= 0 {
				value = normalizeMIRInt(value, insn.DataType)
				*insn = MIRInsn{Kind: MIR_CONST, DataType: before.DataType, Offset: before.Offset, Dst: before.Dst, Src1: -1, Src2: -1, Imm: value, RawFlags: before.RawFlags}
				known[insn.Dst] = value
				s.record("constant-fold", className, methodName, block.ID, i, before, *insn, proof)
				changes++
			} else if insn.Dst >= 0 && insn.Kind != MIR_CONST {
				delete(known, insn.Dst)
			}
		}
	}
	if controlChanged {
		s.RebuildAnalysis()
	} else if changes > 0 {
		s.SSA = ConvertToSSA(s.CFG)
	}
	return changes
}

func (s *TransformSession) record(pass, className, methodName string, blockID, insnIndex int, before, after MIRInsn, proof string) {
	s.Journal = append(s.Journal, TransformEntry{Pass: pass, ClassName: className, MethodName: methodName, BlockID: blockID, InsnIndex: insnIndex, Before: before, After: after, Proof: proof, Confidence: 100})
}

func normalizeCFG(cfg *CFG) {
	if cfg == nil {
		return
	}
	present := make(map[*BasicBlock]bool, len(cfg.Blocks))
	for id, b := range cfg.Blocks {
		present[b] = true
		// Dominance and SSA use dense block indexes. Dead-code removal keeps
		// original IDs, so compact them before rebuilding those analyses.
		b.ID = id
		b.Preds = nil
		b.IsReachable = false
		b.IDom = nil
		b.Children = nil
		b.DomFrontier = nil
	}
	for _, b := range cfg.Blocks {
		uniq := make(map[*BasicBlock]bool)
		out := b.Succs[:0]
		for _, succ := range b.Succs {
			if succ != nil && present[succ] && !uniq[succ] {
				uniq[succ] = true
				out = append(out, succ)
				succ.Preds = append(succ.Preds, b)
			}
		}
		b.Succs = out
	}
	// Removed blocks must not remain reachable through stale handler edges.
	exceptionEdges := cfg.ExceptionEdges[:0]
	for _, edge := range cfg.ExceptionEdges {
		if edge != nil && present[edge.From] && present[edge.To] {
			exceptionEdges = append(exceptionEdges, edge)
		}
	}
	cfg.ExceptionEdges = exceptionEdges
	handlers := cfg.HandlerBlocks[:0]
	for _, handler := range cfg.HandlerBlocks {
		if present[handler] {
			handlers = append(handlers, handler)
		}
	}
	cfg.HandlerBlocks = handlers
	cfg.markReachable()
}

func normalizeMIRInt(v int64, typ MIRDataType) int64 {
	if typ == TypeLong {
		return v
	}
	return int64(int32(v))
}

func evalMIRBinary(kind MIROpKind, typ MIRDataType, a, b int64) (int64, bool) {
	var v int64
	switch kind {
	case MIR_ADD:
		v = a + b
	case MIR_SUB:
		v = a - b
	case MIR_MUL:
		v = a * b
	case MIR_DIV:
		if b == 0 {
			return 0, false
		}
		v = a / b
	case MIR_REM:
		if b == 0 {
			return 0, false
		}
		v = a % b
	case MIR_AND:
		v = a & b
	case MIR_OR:
		v = a | b
	case MIR_XOR:
		v = a ^ b
	case MIR_SHL:
		if typ == TypeLong {
			v = a << (uint64(b) & 63)
		} else {
			v = int64(int32(a) << (uint32(b) & 31))
		}
	case MIR_SHR:
		if typ == TypeLong {
			v = a >> (uint64(b) & 63)
		} else {
			v = int64(int32(a) >> (uint32(b) & 31))
		}
	case MIR_USHR:
		if typ == TypeLong {
			v = int64(uint64(a) >> (uint64(b) & 63))
		} else {
			v = int64(uint32(a) >> (uint32(b) & 31))
		}
	default:
		return 0, false
	}
	return normalizeMIRInt(v, typ), true
}

func evalMIRCondition(cond MIRCondition, a, b int64) bool {
	switch cond {
	case CondEQ, CondEQZ:
		return a == b
	case CondNE, CondNEZ:
		return a != b
	case CondLT, CondLTZ:
		return a < b
	case CondGE, CondGEZ:
		return a >= b
	case CondGT, CondGTZ:
		return a > b
	case CondLE, CondLEZ:
		return a <= b
	default:
		return false
	}
}
