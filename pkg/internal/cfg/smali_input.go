package cfg

import (
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/dexir"
)

// Keep this boundary independent of dexir/adapters: that package's DEX adapter
// imports apkloader, whose analysis dependencies already import cfg.
func buildSmaliInput(className, methodName, signature string, lines []string) BuildInput {
	out := BuildInput{ClassName: className, MethodName: methodName, Signature: signature,
		labelResolution: make(map[string]int)}
	tables := make(map[string]*dexir.Payload)
	var pendingLabels []string
	var catches []string
	var table *smaliPayload
	annotationDepth := 0
	for lineIndex, raw := range lines {
		line := stripSmaliComment(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		directive := fields[0]
		if table != nil {
			if directive == ".end" {
				if len(fields) == 2 && fields[1] == table.name && table.valid {
					for _, label := range table.labels {
						tables[label] = &table.payload
					}
				}
				table = nil
			} else {
				table.add(line)
			}
			continue
		}
		if directive == ".annotation" || directive == ".subannotation" {
			annotationDepth++
			continue
		}
		if annotationDepth > 0 {
			if directive == ".end" && len(fields) > 1 && (fields[1] == "annotation" || fields[1] == "subannotation") {
				annotationDepth--
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			name := fields[0]
			out.Labels = append(out.Labels, Label{Name: name, Line: lineIndex + 1})
			out.labelResolution[name] = len(out.Instructions)
			pendingLabels = append(pendingLabels, name)
			continue
		}
		switch directive {
		case ".packed-switch", ".sparse-switch", ".array-data":
			table = newSmaliPayload(fields, pendingLabels)
			for _, label := range pendingLabels {
				delete(out.labelResolution, label)
			}
			pendingLabels = nil
			continue
		case ".catch", ".catchall":
			catches = append(catches, line)
			continue
		}
		if strings.HasPrefix(directive, ".") {
			continue
		}
		opcode, operands := parseSmaliOpcode(line)
		out.Instructions = append(out.Instructions, Instruction{Index: len(out.Instructions), Line: lineIndex + 1,
			Opcode: opcode, Operands: operands, Raw: line, IR: irFromLegacy(opcode, operands)})
		pendingLabels = nil
	}
	// A label at the very end of the body addresses no instruction. Leaving
	// it in the resolution map would let a branch register a leader index
	// past the instruction slice.
	for name, idx := range out.labelResolution {
		if idx >= len(out.Instructions) {
			delete(out.labelResolution, name)
		}
	}
	for i := range out.Instructions {
		ir := out.Instructions[i].IR
		if p := tables[":"+ir.BranchLabel]; p != nil {
			if (ir.Op == dexir.OpPackedSwitch && p.Kind == dexir.PayloadPackedSwitch) ||
				(ir.Op == dexir.OpSparseSwitch && p.Kind == dexir.PayloadSparseSwitch) ||
				(ir.Op == dexir.OpFillArrayData && p.Kind == dexir.PayloadArrayData) {
				ir.Payload = p
			}
		}
	}
	for _, line := range catches {
		if block, ok := smaliCatchBlock(line, out.labelResolution, len(out.Instructions)); ok {
			block.ID = len(out.TryBlocks)
			out.TryBlocks = append(out.TryBlocks, block)
		}
	}
	return out
}

// stripSmaliComment preserves # and escaped quotes inside string/char literals.
func stripSmaliComment(line string) string {
	var quote byte
	escaped := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
		} else if c == '"' || c == '\'' {
			quote = c
		} else if c == '#' {
			return strings.TrimSpace(line[:i])
		}
	}
	return strings.TrimSpace(line)
}

func splitSmaliOperands(s string) []string {
	var out []string
	var quote byte
	escaped := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == quote {
				quote = 0
			}
		} else if c == '"' || c == '\'' {
			quote = c
		} else if c == ',' {
			if part := strings.TrimSpace(s[start:i]); part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	if part := strings.TrimSpace(s[start:]); part != "" {
		out = append(out, part)
	}
	return out
}

func smaliRegisterList(s string) []string {
	parts := strings.Split(s, "..")
	if len(parts) != 2 {
		return splitSmaliOperands(s)
	}
	first, last := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if len(first) < 2 || len(last) < 2 || first[0] != last[0] || (first[0] != 'v' && first[0] != 'p') {
		return nil
	}
	lo, e1 := strconv.ParseUint(first[1:], 10, 16)
	hi, e2 := strconv.ParseUint(last[1:], 10, 16)
	// A Dalvik range invocation encodes at most 255 register words.
	if e1 != nil || e2 != nil || hi < lo || hi-lo >= 255 {
		return nil
	}
	out := make([]string, 0, int(hi-lo)+1)
	for r := lo; r <= hi; r++ {
		out = append(out, string(first[0])+strconv.FormatUint(r, 10))
	}
	return out
}

type smaliPayload struct {
	name    string
	labels  []string
	payload dexir.Payload
	valid   bool
}

func newSmaliPayload(fields, labels []string) *smaliPayload {
	p := &smaliPayload{name: strings.TrimPrefix(fields[0], "."), labels: append([]string(nil), labels...), valid: true}
	switch p.name {
	case "packed-switch":
		p.payload.Kind = dexir.PayloadPackedSwitch
		if len(fields) != 2 {
			p.valid = false
			break
		}
		v, err := parseLegacyInt(fields[1])
		if err != nil || v < -(1<<31) || v > (1<<31)-1 {
			p.valid = false
		} else {
			p.payload.FirstKey = int32(v)
		}
	case "sparse-switch":
		p.payload.Kind = dexir.PayloadSparseSwitch
		p.valid = len(fields) == 1
	case "array-data":
		p.payload.Kind = dexir.PayloadArrayData
		if len(fields) != 2 {
			p.valid = false
			break
		}
		v, err := parseLegacyInt(fields[1])
		if err != nil || (v != 1 && v != 2 && v != 4 && v != 8) {
			p.valid = false
		} else {
			p.payload.ElemWidth = int(v)
		}
	}
	return p
}

func (p *smaliPayload) add(line string) {
	if !p.valid {
		return
	}
	switch p.payload.Kind {
	case dexir.PayloadPackedSwitch:
		f := strings.Fields(line)
		if len(f) != 1 || !strings.HasPrefix(f[0], ":") {
			p.valid = false
			return
		}
		p.payload.Targets = append(p.payload.Targets, 0)
		p.payload.TargetLabels = append(p.payload.TargetLabels, strings.TrimPrefix(f[0], ":"))
	case dexir.PayloadSparseSwitch:
		f := strings.Fields(line)
		if len(f) != 3 || f[1] != "->" || !strings.HasPrefix(f[2], ":") {
			p.valid = false
			return
		}
		v, err := parseLegacyInt(f[0])
		if err != nil || v < -(1<<31) || v > (1<<31)-1 {
			p.valid = false
			return
		}
		p.payload.Keys = append(p.payload.Keys, int32(v))
		p.payload.Targets = append(p.payload.Targets, 0)
		p.payload.TargetLabels = append(p.payload.TargetLabels, strings.TrimPrefix(f[2], ":"))
	case dexir.PayloadArrayData:
		token := strings.TrimSpace(line)
		if len(token) > 0 && strings.ContainsRune("tTsSlL", rune(token[len(token)-1])) {
			token = token[:len(token)-1]
		}
		v, err := parseLegacyInt(token)
		bits := uint64(v)
		if err != nil {
			// Hex encodings can specify the sign bit directly (not an error).
			if !strings.HasPrefix(token, "0x") && !strings.HasPrefix(token, "0X") {
				p.valid = false
				return
			}
			bits, err = strconv.ParseUint(token[2:], 16, 64)
			if err != nil {
				p.valid = false
				return
			}
		}
		for i := 0; i < p.payload.ElemWidth; i++ {
			p.payload.Values = append(p.payload.Values, byte(bits>>uint(i*8)))
		}
	}
}

func smaliCatchBlock(line string, labels map[string]int, n int) (TryBlock, bool) {
	open, close := strings.IndexByte(line, '{'), strings.IndexByte(line, '}')
	if open < 0 || close <= open {
		return TryBlock{}, false
	}
	head := strings.Fields(line[:open])
	exceptionType := ""
	if len(head) == 1 && head[0] == ".catchall" {
	} else if len(head) == 2 && head[0] == ".catch" {
		exceptionType = head[1]
	} else {
		return TryBlock{}, false
	}
	bounds := strings.Split(line[open+1:close], "..")
	tail := strings.Fields(line[close+1:])
	if len(bounds) != 2 || len(tail) != 1 {
		return TryBlock{}, false
	}
	start, ok1 := labels[strings.TrimSpace(bounds[0])]
	end, ok2 := labels[strings.TrimSpace(bounds[1])]
	handler, ok3 := labels[tail[0]]
	if !ok1 || !ok2 || !ok3 || start < 0 || start >= n || end <= start || end > n || handler < 0 || handler >= n {
		return TryBlock{}, false
	}
	return TryBlock{StartIdx: start, EndIdx: end - 1, Handlers: []ExceptionHandler{{Type: exceptionType, StartIdx: start, EndIdx: end - 1, HandlerIdx: handler}}}, true
}

// OperandCount counts typed register-word and literal/reference operands, not
// commas in source text. Raw-only hand-built graphs use the same boundary lexer.
func (i InstructionRef) OperandCount() int {
	ir := i.IR
	if ir == nil {
		_, operands := parseSmaliOpcode(i.Raw)
		return len(operands)
	}
	n := len(ir.Srcs)
	if ir.Dst != dexir.NoRegister {
		n++
		// In-place encodings read and write the same encoded operand.
		if len(ir.Srcs) > 0 && ir.Srcs[0] == ir.Dst && (strings.HasSuffix(i.Opcode, "/2addr") || i.Opcode == "check-cast") {
			n--
		}
	}
	if ir.HasImm {
		n++
	}
	if ir.HasStr {
		n++
	}
	if ir.Type != "" {
		n++
	}
	if ir.Method != nil {
		n++
	}
	if ir.Field != nil {
		n++
	}
	if ir.BranchLabel != "" || ir.IsBranch() || ir.Op == dexir.OpFillArrayData {
		n++
	}
	return n
}
