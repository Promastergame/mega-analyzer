package ir

import (
	"regexp"
	"strings"

	"mega-analyzer/pkg/binzap/lex"
)

var (
	rxSmaliReg = regexp.MustCompile(`^[vp]\d+$`)
	rxX86Reg   = regexp.MustCompile(`^(eax|ebx|ecx|edx|esi|edi|ebp|esp|rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r\d+d?)$`)
)

func isRegister(dialect, s string) bool {
	if dialect == string(lex.DialectX86) {
		return rxX86Reg.MatchString(s)
	}
	return rxSmaliReg.MatchString(s)
}

// extractRegisters recovers register names from a raw operand token such as
// "{v0,", "v1}", "{v2,v3}" that the line-oriented lexer classifies as Unknown.
func extractRegisters(dialect, raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '{' || r == '}' || r == ',' || r == ' ' || r == '.'
	})
	var regs []string
	for _, f := range fields {
		if isRegister(dialect, f) {
			regs = append(regs, f)
		}
	}
	return regs
}

// LowerTokens lowers a token stream for a single file into an IR Program.
// Method boundaries are detected from smali `.method` / `.end method` markers;
// when absent, the whole file is treated as one synthetic method.
func LowerTokens(file string, dialect lex.Dialect, tokens []lex.Token) *Program {
	p := &Program{File: file, Dialect: string(dialect)}

	var cur *Method
	newMethod := func(name string) *Method {
		m := &Method{Name: name, Dialect: string(dialect)}
		p.Methods = append(p.Methods, m)
		return m
	}

	i := 0
	for i < len(tokens) {
		tok := tokens[i]

		// Method markers (smali) arrive as Unknown tokens like ".method".
		if tok.Type == lex.TokenUnknown && strings.HasPrefix(tok.Value, ".method") {
			name := ""
			j := i + 1
			for j < len(tokens) && tokens[j].Line == tok.Line {
				if tokens[j].Type == lex.TokenMethodRef || strings.Contains(tokens[j].Value, "(") {
					name = tokens[j].Value
				}
				j++
			}
			cur = newMethod(name)
			cur.Params = parseParams(name)
			i = j
			continue
		}
		if tok.Type == lex.TokenUnknown && strings.HasPrefix(tok.Value, ".end method") {
			cur = nil
			i++
			continue
		}

		if tok.Type != lex.TokenOpcode {
			i++
			continue
		}

		if cur == nil {
			cur = newMethod("<file>")
		}

		instr := &Instr{Opcode: tok.Value, Line: tok.Line, Column: tok.Column}
		rawParts := []string{tok.Value}
		j := i + 1
		for j < len(tokens) && tokens[j].Type != lex.TokenOpcode {
			op := tokens[j]
			if op.Type == lex.TokenUnknown && (strings.HasPrefix(op.Value, ".method") || strings.HasPrefix(op.Value, ".end method")) {
				break
			}
			rawParts = append(rawParts, op.Value)
			switch op.Type {
			case lex.TokenRegister:
				instr.Args = append(instr.Args, op.Value)
			case lex.TokenLiteralString:
				instr.Str = op.Value
				instr.HasStr = true
			case lex.TokenMethodRef:
				instr.Method = op.Value
			case lex.TokenUnknown:
				if regs := extractRegisters(string(dialect), op.Value); len(regs) > 0 {
					instr.Args = append(instr.Args, regs...)
				}
			}
			j++
		}
		instr.Raw = strings.Join(rawParts, " ")
		classify(string(dialect), instr)
		cur.Instrs = append(cur.Instrs, instr)
		i = j
	}

	for _, m := range p.Methods {
		linkMoveResults(m)
		m.Blocks = buildBlocks(m)
	}
	return p
}

func parseParams(sig string) []string {
	s := strings.Index(sig, "(")
	e := strings.Index(sig, ")")
	if s == -1 || e == -1 || s >= e {
		return nil
	}
	return strings.FieldsFunc(sig[s+1:e], func(r rune) bool { return r == ';' })
}

func classify(dialect string, in *Instr) {
	op := in.Opcode
	switch {
	case strings.HasPrefix(op, "const"):
		in.Op = OpConst
		if len(in.Args) > 0 {
			in.Dst = in.Args[0]
		}
	case strings.HasPrefix(op, "move-result"):
		in.Op = OpMoveResult
		if len(in.Args) > 0 {
			in.Dst = in.Args[0]
		}
	case strings.HasPrefix(op, "move"):
		in.Op = OpMove
		if len(in.Args) > 0 {
			in.Dst = in.Args[0]
		}
	case strings.HasPrefix(op, "invoke") || (dialect == "x86" && (op == "call" || op == "callq")):
		in.Op = OpInvoke
	case strings.HasPrefix(op, "return") || op == "ret":
		in.Op = OpReturn
	case strings.HasPrefix(op, "if-") || strings.HasPrefix(op, "goto") || (dialect == "x86" && strings.HasPrefix(op, "j")):
		in.Op = OpBranch
		if in.Method != "" {
			in.Target = in.Method
		}
	case strings.HasPrefix(op, "iget") || strings.HasPrefix(op, "sget"):
		in.Op = OpFieldGet
		if len(in.Args) > 0 {
			in.Dst = in.Args[0]
		}
	case strings.HasPrefix(op, "iput") || strings.HasPrefix(op, "sput"):
		in.Op = OpFieldPut
	default:
		in.Op = OpUnknown
	}
}

// linkMoveResults sets ResultReg on an invoke when immediately followed by a
// move-result* instruction.
func linkMoveResults(m *Method) {
	for idx := 0; idx < len(m.Instrs)-1; idx++ {
		if m.Instrs[idx].Op == OpInvoke && m.Instrs[idx+1].Op == OpMoveResult {
			m.Instrs[idx].ResultReg = m.Instrs[idx+1].Dst
		}
	}
}

// buildBlocks performs basic-block construction. A single block is sufficient
// for the intra-procedural taint pass; branch targets are retained on the
// instructions so future passes can refine reachability.
func buildBlocks(m *Method) []*Block {
	if len(m.Instrs) == 0 {
		return nil
	}
	b := &Block{Label: m.Name, Instrs: m.Instrs}
	return []*Block{b}
}
