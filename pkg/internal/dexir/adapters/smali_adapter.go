package adapters

import (
	"encoding/binary"
	"math"
	"regexp"
	"strconv"
	"strings"

	. "mega-analyzer/pkg/internal/dexir"
	"mega-analyzer/pkg/internal/parser"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════
// SMALI TEXT ADAPTER — text IR → typed IR
// ═══════════════════════════════════════════════════════════════
//
// For standalone .smali inputs (no DEX available). Uses the pipeline
// parser for the class skeleton, then re-scans method bodies to
// recover labels, branch labels, payload tables and register operands
// that the skeleton model discards.

var (
	textInvokeRegex = regexp.MustCompile(
		`^invoke-(\w+?)(?:/range)?\s+\{([^}]*)\},\s*(\S+)$`)
	textConstStringRegex = regexp.MustCompile(
		`^const-string(?:/jumbo)?\s+([vp]\d+),\s*"((?:[^"\\]|\\.)*)"\s*(?:#.*)?$`)
	textFieldRegex = regexp.MustCompile(
		`^([si](?:get|put)(?:-\w+)?)\s+([vp]\d+)(?:,\s*([vp]\d+))?,\s*(\S+)$`)
	textBranchRegex = regexp.MustCompile(
		`^(if-\w+|goto(?:/16|/32)?)\s+(.*)$`)
	textSwitchRegex = regexp.MustCompile(
		`^(packed-switch|sparse-switch)\s+([vp]\d+),\s*(\S+)`)
	textFillArrayRegex = regexp.MustCompile(
		`^fill-array-data\s+([vp]\d+),\s*(\S+)`)
	textTypeOpRegex = regexp.MustCompile(
		`^(const-class|new-instance|check-cast|new-array|instance-of)\s+(.*)$`)
	textCatchRegex = regexp.MustCompile(
		`^\.catch\s+(\S+)\s+\{([^}]+)\}\s*(\S+)`)
	textCatchAllRegex = regexp.MustCompile(
		`^\.catchall\s+\{([^}]+)\}\s*(\S+)`)
	textRegListRegex = regexp.MustCompile(`^([vp]\d+)\s*\.\.\s*([vp]\d+)$`)
)

// FromSmaliText parses standalone smali source into typed IR.
func FromSmaliText(content string) (*Class, error) {
	sp := parser.NewSmaliParser(content)
	sc, err := sp.Parse()
	if err != nil {
		return nil, err
	}
	return FromSmaliClassLines(sc, sp.Lines()), nil
}

// FromSmaliClass converts the pipeline parser model to typed IR.
// content (the original smali source) enables body re-scanning for
// labels, payloads and operands; pass "" to convert only the
// structural fields captured by the parser.
func FromSmaliClass(sc *types.SmaliClass, content string) *Class {
	if sc == nil {
		return nil
	}
	return FromSmaliClassLines(sc, splitLines(content))
}

// FromSmaliClassLines reuses the parser's source line index. It reads lines
// without modifying them, preserving absolute instruction and label locations.
func FromSmaliClassLines(sc *types.SmaliClass, lines []string) *Class {
	if sc == nil {
		return nil
	}

	cls := &Class{
		Descriptor:  javaNameToDescriptor(sc.Name),
		SuperClass:  javaNameToDescriptor(sc.SuperClass),
		SourceFile:  sc.Source,
		AccessFlags: uint32(sc.Access),
	}
	if sc.SuperClass == "" {
		cls.SuperClass = ""
	}
	for _, iface := range sc.Interfaces {
		cls.Interfaces = append(cls.Interfaces, javaNameToDescriptor(iface))
	}

	for _, f := range sc.Fields {
		cls.Fields = append(cls.Fields, &Field{
			Name:        f.Name,
			Type:        f.Type,
			AccessFlags: uint32(f.Access),
			IsStatic:    uint32(f.Access)&0x0008 != 0,
		})
	}

	for i := range sc.Methods {
		cls.Methods = append(cls.Methods, methodFromText(&sc.Methods[i], lines))
	}
	return cls
}

// MethodFromBodyLines converts a single method body (the raw lines a
// pipeline parser stores as SmaliMethod.Body) into typed IR without
// needing the surrounding file. The body lines are treated exactly the
// way methodFromText treats the file slice [LineStart, LineEnd]: labels
// carry body-relative line numbers starting at 1.
//
// Note: payload tables are materialized as pseudo-instructions and
// then re-attached to their switch / fill-array-data instructions
// (pairTextPayloads); the pseudo-instructions remain in the stream so
// consumers can choose to skip them.
func MethodFromBodyLines(sm *types.SmaliMethod, body []string) *Method {
	if sm == nil {
		return nil
	}
	m := &Method{
		Name:        sm.Name,
		AccessFlags: uint32(sm.Access),
		IsStatic:    uint32(sm.Access)&0x0008 != 0,
		ReturnType:  sm.ReturnType,
		Params:      parseParamDescriptors(sm.Params),
		LineStart:   sm.LineStart,
		LineEnd:     sm.LineEnd,
	}

	// Register counts: the parser only records directives it saw.
	m.RegistersSize = -1
	m.Locals = -1
	if sm.Registers > 0 {
		m.RegistersSize = sm.Registers
	}
	if sm.Locals > 0 {
		m.Locals = sm.Locals
	}
	if m.RegistersSize < 0 && m.Locals >= 0 {
		w := 0
		for _, p := range m.Params {
			if p == "J" || p == "D" {
				w += 2
			} else {
				w++
			}
		}
		if !m.IsStatic {
			w++
		}
		m.RegistersSize = m.Locals + w
	}

	scanMethodBody(m, body, 1)
	pairTextPayloads(m)
	return m
}

func splitLines(content string) []string {
	if content == "" {
		return nil
	}
	return strings.Split(content, "\n")
}

// javaNameToDescriptor converts "com.example.Foo" to "Lcom/example/Foo;".
// Inputs already in descriptor form pass through unchanged.
func javaNameToDescriptor(name string) string {
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, "L") && strings.HasSuffix(name, ";") {
		return name
	}
	// Primitive descriptors pass through.
	if len(name) == 1 {
		return name
	}
	return "L" + strings.ReplaceAll(name, ".", "/") + ";"
}

// parseParamDescriptors splits a raw smali parameter string
// ("Ljava/lang/String;I[J") into individual descriptors.
func parseParamDescriptors(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		switch s[i] {
		case '[':
			j := i
			for j < len(s) && s[j] == '[' {
				j++
			}
			if j < len(s) && s[j] == 'L' {
				k := strings.IndexByte(s[j:], ';')
				if k < 0 {
					out = append(out, s[i:])
					return out
				}
				out = append(out, s[i:j+k+1])
				i = j + k + 1
			} else if j < len(s) {
				out = append(out, s[i:j+1])
				i = j + 1
			} else {
				return out
			}
		case 'L':
			k := strings.IndexByte(s[i:], ';')
			if k < 0 {
				out = append(out, s[i:])
				return out
			}
			out = append(out, s[i:i+k+1])
			i += k + 1
		default:
			out = append(out, s[i:i+1])
			i++
		}
	}
	return out
}

// methodFromText builds a typed Method from the parser model plus a
// body re-scan over the original source lines.
func methodFromText(sm *types.SmaliMethod, lines []string) *Method {
	m := &Method{
		Name:        sm.Name,
		AccessFlags: uint32(sm.Access),
		IsStatic:    uint32(sm.Access)&0x0008 != 0,
		ReturnType:  sm.ReturnType,
		Params:      parseParamDescriptors(sm.Params),
		LineStart:   sm.LineStart,
		LineEnd:     sm.LineEnd,
	}

	// Register counts: the parser only records directives it saw.
	m.RegistersSize = -1
	m.Locals = -1
	if sm.Registers > 0 {
		m.RegistersSize = sm.Registers
	}
	if sm.Locals > 0 {
		m.Locals = sm.Locals
	}
	if m.RegistersSize < 0 && m.Locals >= 0 {
		// Derivable total when .locals is known.
		w := 0
		for _, p := range m.Params {
			if p == "J" || p == "D" {
				w += 2
			} else {
				w++
			}
		}
		if !m.IsStatic {
			w++
		}
		m.RegistersSize = m.Locals + w
	}

	if sm.LineStart <= 0 || sm.LineStart > len(lines) {
		return m
	}
	end := sm.LineEnd
	if end <= 0 || end > len(lines) {
		end = len(lines)
	}
	if end < sm.LineStart {
		return m
	}
	scanMethodBody(m, lines[sm.LineStart-1:end], sm.LineStart)
	pairTextPayloads(m)
	return m
}

// pairTextPayloads re-attaches payload tables (materialized as
// pseudo-instructions by the body scan) to their switch /
// fill-array-data instructions. The DEX adapter exposes the table on
// the referring instruction itself. Labels select the actual table;
// source order is only a fallback for legacy numeric-only operands.
func pairTextPayloads(m *Method) {
	var tables []*Instruction // payload pseudo-instructions, in order
	tableIndex := make(map[*Instruction]int)
	for _, ins := range m.Instructions {
		if ins.IsPayload() && ins.Payload != nil {
			tableIndex[ins] = len(tables)
			tables = append(tables, ins)
		}
	}
	if len(tables) == 0 {
		return
	}

	// Both lists are emitted in source order. A label identifies the next
	// instruction, allowing aliases and multiple references to one table.
	byLabel := make(map[string]int)
	next := 0
	for _, label := range m.Labels {
		for next < len(m.Instructions) && m.Instructions[next].Line <= label.Line {
			next++
		}
		if next < len(m.Instructions) {
			if index, ok := tableIndex[m.Instructions[next]]; ok {
				byLabel[label.Name] = index
			}
		}
	}

	wantKind := func(op Opcode) PayloadKind {
		switch op {
		case OpPackedSwitch:
			return PayloadPackedSwitch
		case OpSparseSwitch:
			return PayloadSparseSwitch
		case OpFillArrayData:
			return PayloadArrayData
		}
		return PayloadNone
	}

	used := make([]bool, len(tables))
	for _, ins := range m.Instructions {
		kind := wantKind(ins.Op)
		if kind == PayloadNone || ins.Payload != nil {
			continue
		}
		if ins.BranchLabel != "" {
			if index, ok := byLabel[ins.BranchLabel]; ok && tables[index].Payload.Kind == kind {
				ins.Payload = tables[index].Payload
				used[index] = true
			}
			// A missing or incompatible named table must not attach unrelated
			// data just because another table happens to follow it.
			continue
		}
		for j, tbl := range tables {
			if used[j] || tbl.Payload.Kind != kind {
				continue
			}
			ins.Payload = tbl.Payload
			used[j] = true
			break
		}
	}
}

// payloadBuilder accumulates a payload table while scanning body lines.
type payloadBuilder struct {
	line     int
	kind     PayloadKind
	firstKey int32
	keys     []int32
	targets  []int32  // switch payloads: label targets resolve later
	labels   []string // switch payloads: target label names
	width    int
	values   []byte
}

// scanMethodBody walks the raw lines of one method body producing
// typed instructions, labels, try/catch entries and payloads.
func scanMethodBody(m *Method, body []string, baseLine int) {
	var open *payloadBuilder // payload table currently being collected

	for i, raw := range body {
		line := strings.TrimSpace(raw)
		lineNum := baseLine + i
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Inside a payload table?
		if open != nil {
			done := scanPayloadLine(open, line)
			if done {
				finishPayload(m, open)
				open = nil
			}
			continue
		}

		switch {
		case strings.HasPrefix(line, ".registers"):
			if v, ok := directiveInt(line); ok {
				m.RegistersSize = v
			}
		case strings.HasPrefix(line, ".locals"):
			if v, ok := directiveInt(line); ok {
				m.Locals = v
			}
		case strings.HasPrefix(line, ".param"), strings.HasPrefix(line, ".annotation"),
			strings.HasPrefix(line, ".end"), strings.HasPrefix(line, ".restart"),
			strings.HasPrefix(line, ".line"), strings.HasPrefix(line, ".prologue"):
			// directives without IR significance
		case strings.HasPrefix(line, ".catch"):
			if tc := parseTextCatch(line); tc != nil {
				m.TryCatches = append(m.TryCatches, tc)
			}
		case strings.HasPrefix(line, ".packed-switch"):
			open = &payloadBuilder{kind: PayloadPackedSwitch, line: lineNum}
			if parts := strings.Fields(line); len(parts) >= 2 {
				if v, err := parseImmediate(parts[1]); err == nil {
					open.firstKey = int32(v)
				}
			}
		case strings.HasPrefix(line, ".sparse-switch"):
			open = &payloadBuilder{kind: PayloadSparseSwitch, line: lineNum}
		case strings.HasPrefix(line, ".array-data"):
			open = &payloadBuilder{kind: PayloadArrayData, line: lineNum}
			if parts := strings.Fields(line); len(parts) >= 2 {
				if v, err := parseImmediate(parts[1]); err == nil {
					open.width = int(v)
				}
			}
		case strings.HasPrefix(line, ":"):
			name := strings.TrimPrefix(line, ":")
			if j := strings.IndexAny(name, " \t#"); j >= 0 {
				name = name[:j]
			}
			m.Labels = append(m.Labels, &Label{Name: name, Line: lineNum})
		default:
			if ins := parseTextInstruction(line, lineNum); ins != nil {
				m.Instructions = append(m.Instructions, ins)
			}
		}
	}
}

// scanPayloadLine consumes one line inside a payload table.
// Returns true when the table is complete.
func scanPayloadLine(pb *payloadBuilder, line string) bool {
	if strings.HasPrefix(line, ".end") {
		return true
	}
	switch pb.kind {
	case PayloadPackedSwitch:
		// Lines are labels (":lbl_x") or relative numeric targets.
		if strings.HasPrefix(line, ":") {
			pb.labels = append(pb.labels, strings.TrimPrefix(line, ":"))
			pb.targets = append(pb.targets, 0)
		} else if v, err := parseImmediate(line); err == nil {
			pb.targets = append(pb.targets, int32(v))
		}
	case PayloadSparseSwitch:
		// Lines: "K -> :lbl" or "K -> +N".
		parts := strings.Split(line, "->")
		if len(parts) == 2 {
			if k, err := parseImmediate(strings.TrimSpace(parts[0])); err == nil {
				pb.keys = append(pb.keys, int32(k))
				tgt := strings.TrimSpace(parts[1])
				if strings.HasPrefix(tgt, ":") {
					pb.labels = append(pb.labels, strings.TrimPrefix(tgt, ":"))
					pb.targets = append(pb.targets, 0)
				} else if v, err := parseImmediate(tgt); err == nil {
					pb.targets = append(pb.targets, int32(v))
				}
			}
		}
	case PayloadArrayData:
		// Literal values; multiple per line allowed.
		for _, tok := range strings.Split(line, ",") {
			appendArrayValue(pb, strings.TrimSpace(tok))
		}
	}
	return false
}

// appendArrayValue parses one array-data literal into bytes.
func appendArrayValue(pb *payloadBuilder, tok string) {
	if tok == "" {
		return
	}
	switch pb.width {
	case 1:
		if v, err := parseImmediate(tok); err == nil {
			pb.values = append(pb.values, byte(v))
		} else if len(tok) == 3 && tok[0] == '\'' && tok[2] == '\'' {
			pb.values = append(pb.values, tok[1])
		}
	case 2:
		if v, err := parseImmediate(tok); err == nil {
			pb.values = binary.LittleEndian.AppendUint16(pb.values, uint16(v))
		} else if len(tok) == 3 && tok[0] == '\'' && tok[2] == '\'' {
			pb.values = binary.LittleEndian.AppendUint16(pb.values, uint16(tok[1]))
		}
	case 4:
		if v, err := parseImmediate(tok); err == nil {
			pb.values = binary.LittleEndian.AppendUint32(pb.values, uint32(v))
		} else if f, err := strconv.ParseFloat(strings.TrimRight(tok, "fF"), 32); err == nil {
			pb.values = binary.LittleEndian.AppendUint32(pb.values, math.Float32bits(float32(f)))
		}
	case 8:
		if v, err := parseImmediate(tok); err == nil {
			pb.values = binary.LittleEndian.AppendUint64(pb.values, uint64(v))
		} else if f, err := strconv.ParseFloat(strings.TrimRight(tok, "Ll"), 64); err == nil {
			pb.values = binary.LittleEndian.AppendUint64(pb.values, math.Float64bits(f))
		}
	}
}

// finishPayload converts a completed builder into a pseudo-instruction.
func finishPayload(m *Method, pb *payloadBuilder) {
	op := OpPackedSwitchPayload
	switch pb.kind {
	case PayloadSparseSwitch:
		op = OpSparseSwitchPayload
	case PayloadArrayData:
		op = OpFillArrayDataPayload
	}
	ins := &Instruction{
		Line:         pb.line,
		Op:           op,
		Dst:          NoRegister,
		BranchOffset: -1,
		BranchTarget: -1,
		Payload: &Payload{
			Kind:         pb.kind,
			FirstKey:     pb.firstKey,
			Keys:         pb.keys,
			Targets:      pb.targets,
			TargetLabels: pb.labels,
			ElemWidth:    pb.width,
			Values:       pb.values,
		},
	}
	m.Instructions = append(m.Instructions, ins)
}

// parseTextInstruction converts one smali instruction line.
func parseTextInstruction(line string, lineNum int) *Instruction {
	ins := &Instruction{
		Line:         lineNum,
		Dst:          NoRegister,
		BranchOffset: -1,
		BranchTarget: -1,
	}

	opName := line
	if j := strings.IndexAny(line, " \t"); j >= 0 {
		opName = line[:j]
	}
	op, ok := OpcodeFromName(opName)
	if !ok {
		return nil
	}
	ins.Op = op
	operands := strings.TrimSpace(strings.TrimPrefix(line, opName))

	switch {
	case strings.HasPrefix(opName, "invoke-") || strings.HasPrefix(opName, "filled-new-array"):
		if m := textInvokeRegex.FindStringSubmatch(line); m != nil {
			ins.Srcs = parseRegisterList(m[2])
			ins.Method = parseMethodRefText(m[3])
		} else {
			ins.Srcs, ins.Method = parseInvokeFallback(operands)
		}

	case strings.HasPrefix(opName, "const-string"):
		if m := textConstStringRegex.FindStringSubmatch(line); m != nil {
			ins.Dst = parseRegister(m[1])
			ins.HasStr = true
			ins.Str = parser.UnescapeSmaliString(m[2])
		}

	case op >= OpIget && op <= OpSput+6:
		if m := textFieldRegex.FindStringSubmatch(line); m != nil {
			if strings.Contains(opName, "get") {
				ins.Dst = parseRegister(m[2])
				if m[3] != "" {
					ins.Srcs = []int32{parseRegister(m[3])}
				}
			} else {
				if m[3] != "" {
					ins.Srcs = []int32{parseRegister(m[2]), parseRegister(m[3])}
				} else {
					ins.Srcs = []int32{parseRegister(m[2])}
				}
			}
			ins.Field = parseFieldRefText(m[4])
		}

	case (op >= OpGoto && op <= OpGoto32) || (op >= OpIfEq && op <= OpIfLez):
		// NB: packed/sparse-switch (0x2B/0x2C) must NOT match here.
		if m := textBranchRegex.FindStringSubmatch(line); m != nil {
			rest := m[2]
			if op <= OpGoto32 {
				parseBranchOperand(ins, rest)
			} else if op >= OpIfEq && op <= OpIfLe {
				// if-XX vA, vB, :label
				parts := splitOperands(rest)
				for _, p := range parts[:max0(len(parts)-1)] {
					if r := parseRegister(p); r != NoRegister {
						ins.Srcs = append(ins.Srcs, r)
					}
				}
				if len(parts) > 0 {
					parseBranchOperand(ins, parts[len(parts)-1])
				}
			} else {
				// if-XXz vA, :label
				parts := splitOperands(rest)
				if len(parts) >= 1 {
					if r := parseRegister(parts[0]); r != NoRegister {
						ins.Srcs = []int32{r}
					}
				}
				if len(parts) >= 2 {
					parseBranchOperand(ins, parts[len(parts)-1])
				}
			}
		}

	case op == OpPackedSwitch || op == OpSparseSwitch:
		if m := textSwitchRegex.FindStringSubmatch(line); m != nil {
			ins.Srcs = []int32{parseRegister(m[2])}
			parseBranchOperand(ins, m[3])
			if ins.BranchOffset != -1 {
				// The DEX adapter exposes the payload offset as Imm;
				// mirror that for cross-adapter comparability.
				ins.HasImm = true
				ins.Imm = int64(ins.BranchOffset)
			}
		}

	case op == OpFillArrayData:
		if m := textFillArrayRegex.FindStringSubmatch(line); m != nil {
			ins.Srcs = []int32{parseRegister(m[1])}
			parseBranchOperand(ins, m[2])
			if ins.BranchOffset != -1 {
				ins.HasImm = true
				ins.Imm = int64(ins.BranchOffset)
			}
		}

	case op == OpConstClass || op == OpNewInstance || op == OpCheckCast ||
		op == OpNewArray || op == OpInstanceOf:
		if m := textTypeOpRegex.FindStringSubmatch(line); m != nil {
			parts := splitOperands(m[2])
			for i, p := range parts {
				if r := parseRegister(p); r != NoRegister {
					if i == 0 {
						if op == OpCheckCast {
							ins.Dst = r
							ins.Srcs = []int32{r}
						} else {
							ins.Dst = r
						}
					} else {
						ins.Srcs = append(ins.Srcs, r)
					}
					continue
				}
				if strings.HasPrefix(p, "L") || strings.HasPrefix(p, "[") {
					ins.Type = p
				}
			}
		}

	case op >= OpConst4 && op <= OpConstWideHigh16:
		parts := splitOperands(operands)
		if len(parts) >= 1 {
			ins.Dst = parseRegister(parts[0])
		}
		if len(parts) >= 2 {
			if v, err := parseImmediate(parts[1]); err == nil {
				ins.HasImm = true
				ins.Imm = v
			}
		}

	case op == OpReturnVoid:
		// no operands

	case op >= OpReturn && op <= OpReturnObject, op == OpThrow,
		op == OpMonitorEnter, op == OpMonitorExit:
		if r := parseRegister(firstOperand(operands)); r != NoRegister {
			ins.Srcs = []int32{r}
		}

	case op >= OpMove && op <= OpMoveObject16:
		parts := splitOperands(operands)
		if len(parts) >= 1 {
			ins.Dst = parseRegister(parts[0])
		}
		if len(parts) >= 2 {
			ins.Srcs = []int32{parseRegister(parts[1])}
		}

	case op >= OpMoveResult && op <= OpMoveResultObject, op == OpMoveException:
		if r := parseRegister(firstOperand(operands)); r != NoRegister {
			ins.Dst = r
		}

	case op >= OpCmplFloat && op <= OpCmpLong:
		parts := splitOperands(operands)
		if len(parts) >= 1 {
			ins.Dst = parseRegister(parts[0])
		}
		for _, p := range parts[1:] {
			if r := parseRegister(p); r != NoRegister {
				ins.Srcs = append(ins.Srcs, r)
			}
		}

	case op >= OpAget && op <= OpAput+6:
		parts := splitOperands(operands)
		if len(parts) >= 1 && op <= OpAget+6 {
			ins.Dst = parseRegister(parts[0])
			for _, p := range parts[1:] {
				if r := parseRegister(p); r != NoRegister {
					ins.Srcs = append(ins.Srcs, r)
				}
			}
		} else {
			for _, p := range parts {
				if r := parseRegister(p); r != NoRegister {
					ins.Srcs = append(ins.Srcs, r)
				}
			}
		}

	case op >= 0x7B && op <= 0x8F:
		// unary: vA, vB
		parts := splitOperands(operands)
		if len(parts) >= 1 {
			ins.Dst = parseRegister(parts[0])
		}
		if len(parts) >= 2 {
			ins.Srcs = []int32{parseRegister(parts[1])}
		}

	case op >= 0x90 && op <= 0xAF:
		// binop/23x: vAA, vBB, vCC
		parts := splitOperands(operands)
		if len(parts) >= 1 {
			ins.Dst = parseRegister(parts[0])
		}
		for _, p := range parts[1:] {
			if r := parseRegister(p); r != NoRegister {
				ins.Srcs = append(ins.Srcs, r)
			}
		}

	case op >= 0xB0 && op <= 0xCF:
		// binop/2addr: vA = vA op vB
		parts := splitOperands(operands)
		if len(parts) >= 1 {
			rA := parseRegister(parts[0])
			ins.Dst = rA
			if rA != NoRegister {
				ins.Srcs = append(ins.Srcs, rA)
			}
		}
		if len(parts) >= 2 {
			if r := parseRegister(parts[1]); r != NoRegister {
				ins.Srcs = append(ins.Srcs, r)
			}
		}

	case op >= 0xD0 && op <= 0xE2:
		// binop/lit: vA, vB, #+CC
		parts := splitOperands(operands)
		if len(parts) >= 1 {
			ins.Dst = parseRegister(parts[0])
		}
		if len(parts) >= 2 {
			ins.Srcs = []int32{parseRegister(parts[1])}
		}
		if len(parts) >= 3 {
			if v, err := parseImmediate(parts[2]); err == nil {
				ins.HasImm = true
				ins.Imm = v
			}
		}

	default:
		// generic: best-effort register scan
		for _, p := range splitOperands(operands) {
			if r := parseRegister(p); r != NoRegister {
				ins.Srcs = append(ins.Srcs, r)
			}
		}
	}

	return ins
}

// parseInvokeFallback handles invoke lines when the strict regex fails
// (e.g. unusual whitespace).
func parseInvokeFallback(operands string) ([]int32, *MethodRef) {
	i := strings.Index(operands, "{")
	j := strings.Index(operands, "}")
	if i < 0 || j < i {
		return nil, nil
	}
	regs := parseRegisterList(operands[i+1 : j])
	ref := parseMethodRefText(strings.TrimSpace(strings.TrimPrefix(operands[j+1:], ",")))
	return regs, ref
}

// parseBranchOperand fills BranchLabel or BranchOffset from ":lbl"/"+N".
func parseBranchOperand(ins *Instruction, operand string) {
	operand = strings.TrimSpace(strings.TrimSuffix(operand, ","))
	if strings.HasPrefix(operand, ":") {
		ins.BranchLabel = strings.TrimPrefix(operand, ":")
		return
	}
	if v, err := parseImmediate(operand); err == nil {
		ins.BranchOffset = int32(v)
	}
}

// parseRegister parses "v3"/"p0" into a v-register index. Relative
// p-registers cannot be resolved without a register count, so they map
// to their textual index negated-minus-two: pN -> -(N+2). Consumers
// resolve via Method.RegistersSize/InsSize when available.
func parseRegister(tok string) int32 {
	tok = strings.TrimSpace(tok)
	if len(tok) < 2 {
		return NoRegister
	}
	n, err := strconv.Atoi(tok[1:])
	if err != nil {
		return NoRegister
	}
	switch tok[0] {
	case 'v':
		return int32(n)
	case 'p':
		return -(int32(n) + 2)
	}
	return NoRegister
}

// parseRegisterList parses "{v0, p1 .. p3}" register lists.
func parseRegisterList(s string) []int32 {
	var out []int32
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if m := textRegListRegex.FindStringSubmatch(part); m != nil {
			a, b := parseRegister(m[1]), parseRegister(m[2])
			if a != NoRegister && b != NoRegister && b >= a {
				for r := a; r <= b; r++ {
					out = append(out, r)
				}
			}
			continue
		}
		if r := parseRegister(part); r != NoRegister {
			out = append(out, r)
		}
	}
	return out
}

// parseMethodRefText parses "Lcls;->name(proto)ret".
func parseMethodRefText(s string) *MethodRef {
	s = strings.TrimSpace(s)
	if j := strings.Index(s, "#"); j >= 0 {
		s = strings.TrimSpace(s[:j])
	}
	sep := strings.Index(s, "->")
	if sep < 0 {
		return nil
	}
	cls := s[:sep]
	rest := s[sep+2:]
	open := strings.IndexByte(rest, '(')
	if open < 0 {
		return &MethodRef{Class: cls, Name: rest}
	}
	name := rest[:open]
	closeIdx := strings.IndexByte(rest[open:], ')')
	if closeIdx < 0 {
		return &MethodRef{Class: cls, Name: name}
	}
	closeIdx += open
	proto := rest[open : closeIdx+1]
	ret := rest[closeIdx+1:]
	return &MethodRef{
		Class:      cls,
		Name:       name,
		Proto:      proto + ret,
		ReturnType: ret,
		Params:     parseParamDescriptors(proto[1 : len(proto)-1]),
	}
}

// parseFieldRefText parses "Lcls;->name:type".
func parseFieldRefText(s string) *FieldRef {
	s = strings.TrimSpace(s)
	if j := strings.Index(s, "#"); j >= 0 {
		s = strings.TrimSpace(s[:j])
	}
	sep := strings.Index(s, "->")
	if sep < 0 {
		return nil
	}
	cls := s[:sep]
	rest := s[sep+2:]
	colon := strings.LastIndexByte(rest, ':')
	if colon < 0 {
		return &FieldRef{Class: cls, Name: rest}
	}
	return &FieldRef{Class: cls, Name: rest[:colon], Type: rest[colon+1:]}
}

// parseTextCatch parses ".catch Ltype; {:a .. :b} :h" and ".catchall".
func parseTextCatch(line string) *TryCatch {
	if m := textCatchRegex.FindStringSubmatch(line); m != nil {
		tc := &TryCatch{Type: m[1]}
		exceptionLabelsFrom(tc, m[2], m[3])
		return tc
	}
	if m := textCatchAllRegex.FindStringSubmatch(line); m != nil {
		tc := &TryCatch{}
		exceptionLabelsFrom(tc, m[1], m[2])
		return tc
	}
	return nil
}

// exceptionLabelsFrom fills start/end/handler labels from text forms.
func exceptionLabelsFrom(tc *TryCatch, rangeStr, handler string) {
	parts := strings.Split(rangeStr, "..")
	if len(parts) == 2 {
		tc.StartLabel = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(parts[0]), ":"))
		tc.EndLabel = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(parts[1]), ":"))
	}
	tc.HandlerLabel = strings.TrimSpace(strings.TrimPrefix(handler, ":"))
}

// parseImmediate parses smali immediates: 0x-hex, decimal, floats,
// char literals, trailing L/f suffixes.
func parseImmediate(tok string) (int64, error) {
	tok = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(tok), ","))
	if tok == "" {
		return 0, strconv.ErrSyntax
	}
	// Char literal.
	if len(tok) == 3 && tok[0] == '\'' && tok[2] == '\'' {
		return int64(tok[1]), nil
	}
	clean := strings.TrimRight(tok, "tTsSlLfFdD")
	if clean == "" {
		clean = tok
	}
	if v, err := strconv.ParseInt(clean, 0, 64); err == nil {
		return v, nil
	}
	if f, err := strconv.ParseFloat(clean, 64); err == nil {
		if strings.ContainsAny(clean, ".eEpP") || strings.HasSuffix(tok, "f") || strings.HasSuffix(tok, "F") {
			return int64(math.Float64bits(f)), nil
		}
		return int64(f), nil
	}
	return 0, strconv.ErrSyntax
}

// splitOperands splits an operand string on commas, keeping labels and
// braces intact.
func splitOperands(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if j := strings.Index(p, "#"); j >= 0 {
			p = strings.TrimSpace(p[:j])
		}
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstOperand(s string) string {
	parts := splitOperands(s)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func directiveInt(line string) (int, bool) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0, false
	}
	v, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, false
	}
	return v, true
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}
