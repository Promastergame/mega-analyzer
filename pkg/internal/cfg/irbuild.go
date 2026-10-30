package cfg

import (
	"fmt"
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/dexir"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TYPED-IR BUILD ENTRY — CFG construction from dexir.Method
// ═══════════════════════════════════════════════════════════════════════════════
//
// Since the Task #5 migration the builder core consumes the typed IR
// (pkg/internal/dexir) exclusively: branch edges come from BranchLabel /
// BranchTarget, switch targets from Payload, def/use registers from
// Dst/Srcs and exception ranges from TryCatches. No instruction string
// is re-tokenized by the builder phases.
//
// Two adapters feed this entry point (package
// mega-analyzer/pkg/internal/dexir/adapters, kept out of the dexir
// core to avoid the apkloader→crackpoint→cfg import cycle):
//
//   - adapters.FromDEX        — binary DEX input (offsets + labels available)
//   - adapters.FromSmaliText /
//     adapters.MethodFromBodyLines — legacy smali text input
//
// Text-origin IR has Size=0 and unreliable Offset values; the builder
// therefore resolves edges through labels (BranchLabel /
// Payload.TargetLabels), which both adapters populate. DEX-origin
// BranchTarget offsets are used only as a fallback when a label is
// missing.

// IRBuildInput describes a typed-IR build request.
type IRBuildInput struct {
	MethodName string
	ClassName  string
	Signature  string
	Method     *dexir.Method

	// IncludeExceptions converts Method.TryCatches into builder
	// TryBlocks (exception edges + catch nodes). Off by default to
	// preserve the historical behavior of the smali-text pipeline,
	// which never supplied try/catch information to the CFG builder.
	IncludeExceptions bool
}

// BuildFromMethod constructs a CFG from a typed IR method.
func (b *CFGBuilder) BuildFromMethod(className string, m *dexir.Method) *ControlFlowGraph {
	res := b.BuildExFromMethod(IRBuildInput{ClassName: className, Method: m})
	if res == nil {
		return nil
	}
	return res.CFG
}

// BuildExFromMethod constructs a CFG from typed IR with full statistics.
func (b *CFGBuilder) BuildExFromMethod(input IRBuildInput) *BuildResult {
	if input.Method == nil {
		return nil
	}
	return b.BuildEx(BuildFromMethod(input))
}

// BuildFromMethod converts a typed IR method into the BuildInput the
// builder core consumes. Exported so callers that drive Build/BuildEx
// directly (caches, benchmarks) can reuse the same conversion.
//
// Semantics preserved from the legacy smali-text pipeline:
//
//   - payload pseudo-instructions never become basic-block content
//     (the text pipeline skipped "." directives entirely);
//   - p-registers are resolved to absolute v-registers whenever the
//     register count is known (SSA must not observe the negative
//     sentinels the text adapter emits);
//   - labels resolve to the next instruction, matching LabelIndex's
//     label.Line+1 convention;
//   - try/catch ranges are dropped unless IncludeExceptions is set.
func BuildFromMethod(input IRBuildInput) BuildInput {
	m := input.Method
	if m == nil {
		return BuildInput{MethodName: input.MethodName, ClassName: input.ClassName, Signature: input.Signature}
	}

	// Resolve p-register sentinels before anything reads registers.
	// Mutates m; idempotent once resolved.
	if m.RegistersSize > 0 {
		dexir.ResolvePRegisters(m)
	}

	instructions := make([]Instruction, 0, len(m.Instructions))
	// offsetToIdx supports DEX-origin label resolution (offset-based).
	offsetToIdx := make(map[uint32]int, len(m.Instructions))

	for _, ir := range m.Instructions {
		if ir == nil || ir.IsPayload() {
			continue // payload tables are data, not block content
		}
		ci := Instruction{
			Index:  len(instructions),
			Line:   ir.Line,
			Opcode: ir.Op.Name(),
			IR:     ir,
		}
		if _, exists := offsetToIdx[ir.Offset]; !exists {
			offsetToIdx[ir.Offset] = ci.Index
		}
		instructions = append(instructions, ci)
	}

	out := BuildInput{
		MethodName:   orStr(input.MethodName, m.Name),
		ClassName:    input.ClassName,
		Signature:    input.Signature,
		Instructions: instructions,
		Labels:       make([]Label, 0, len(m.Labels)),
	}

	// Resolve labels → instruction index. Text-origin labels carry
	// lines, DEX-origin labels carry offsets; remember how each one
	// resolved so BuildEx can wire the label index directly.
	out.labelResolution = make(map[string]int, len(m.Labels))
	instrByLine := make(map[int]int, len(instructions))
	for i := range instructions {
		instrByLine[instructions[i].Line] = i
	}
	for _, lbl := range m.Labels {
		if lbl == nil {
			continue
		}
		if idx, ok := instrByLine[lbl.Line+1]; ok {
			out.labelResolution[lbl.Name] = idx
			continue
		}
		if idx, ok := instrByLine[lbl.Line]; ok {
			out.labelResolution[lbl.Name] = idx
			continue
		}
		if idx, ok := offsetToIdx[lbl.Offset]; ok {
			out.labelResolution[lbl.Name] = idx
		}
	}

	// Try/catch ranges, only on request (see IRBuildInput).
	if input.IncludeExceptions {
		out.TryBlocks = tryBlocksFromIR(m.TryCatches, out.labelResolution, offsetToIdx, len(instructions))
	}

	return out
}

// tryBlocksFromIR converts typed TryCatch ranges into builder TryBlocks.
func tryBlocksFromIR(tcs []*dexir.TryCatch, labelRes map[string]int, offsetToIdx map[uint32]int, instrCount int) []TryBlock {
	if len(tcs) == 0 {
		return nil
	}

	resolveLabel := func(name string) (int, bool) {
		idx, ok := labelRes[name]
		return idx, ok
	}
	resolveOffset := func(off uint32) (int, bool) {
		idx, ok := offsetToIdx[off]
		return idx, ok
	}

	var blocks []TryBlock
	for _, tc := range tcs {
		if tc == nil {
			continue
		}
		startIdx, ok := resolveLabel(tc.StartLabel)
		if !ok {
			startIdx, ok = resolveOffset(tc.StartOffset)
		}
		if !ok {
			continue
		}

		// End is exclusive in the IR; the builder expects the last
		// covered instruction index.
		endIdx := -1
		if idx, ok := resolveLabel(tc.EndLabel); ok && idx > 0 {
			endIdx = idx - 1
		} else if idx, ok := resolveOffset(tc.EndOffset); ok && idx > 0 {
			endIdx = idx - 1
		}
		if endIdx < startIdx {
			endIdx = instrCount - 1
		}

		handlerIdx, ok := resolveLabel(tc.HandlerLabel)
		if !ok {
			handlerIdx, ok = resolveOffset(tc.HandlerOffset)
		}
		if !ok {
			continue
		}

		blocks = append(blocks, TryBlock{
			ID:       len(blocks),
			StartIdx: startIdx,
			EndIdx:   endIdx,
			Handlers: []ExceptionHandler{{
				Type:       tc.Type,
				StartIdx:   startIdx,
				EndIdx:     endIdx,
				HandlerIdx: handlerIdx,
			}},
		})
	}
	return blocks
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ═══════════════════════════════════════════════════════════════════════════════
// REGISTER RENDERING
// ═══════════════════════════════════════════════════════════════════════════════

// registerName renders a v-register index the way smali text does.
// Unresolved p-register sentinels (negative, from the text adapter when
// the register count is unknown) render as "pN" so def/use identities
// stay stable instead of disappearing.
func registerName(r int32) string {
	switch {
	case r == dexir.NoRegister:
		return ""
	case r >= 0:
		return "v" + strconv.FormatInt(int64(r), 10)
	default:
		return "p" + strconv.FormatInt(int64(-(r+2)), 10)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LEGACY BOUNDARY SHIM
// ═══════════════════════════════════════════════════════════════════════════════
//
// BuildInput handed in by legacy callers (hand-built tests, the line
// tokenizer) may lack the IR pointer. irFromLegacy reconstructs it from
// the already-tokenized Operand list. This is the ONLY place in the
// package that interprets instruction text, and it runs once at the
// build boundary — the phases themselves are fully typed.

func ensureLegacyIR(instructions []Instruction) {
	for i := range instructions {
		if instructions[i].IR == nil {
			instructions[i].IR = irFromLegacy(instructions[i].Opcode, instructions[i].Operands)
		}
	}
}

func irFromLegacy(opcode string, operands []string) *dexir.Instruction {
	ir := &dexir.Instruction{
		Dst:          dexir.NoRegister,
		BranchOffset: -1,
		BranchTarget: -1,
	}
	if op, ok := dexir.OpcodeFromName(opcode); ok {
		ir.Op = op
	}

	isReg := func(tok string) bool {
		return len(tok) >= 2 && (tok[0] == 'v' || tok[0] == 'p') && tok[1] >= '0' && tok[1] <= '9'
	}
	parseReg := func(tok string) int32 {
		tok = strings.TrimSpace(tok)
		if !isReg(tok) {
			return dexir.NoRegister
		}
		n, err := strconv.Atoi(tok[1:])
		if err != nil {
			return dexir.NoRegister
		}
		if tok[0] == 'p' {
			// Text-adapter p-sentinel encoding; ResolvePRegisters
			// rewrites it when the register count is known.
			return -(int32(n) + 2)
		}
		return int32(n)
	}
	branchLabel := func(tok string) {
		tok = strings.TrimSpace(tok)
		if strings.HasPrefix(tok, ":") {
			ir.BranchLabel = strings.TrimPrefix(tok, ":")
		}
	}

	switch {
	case strings.HasPrefix(opcode, "if-"):
		// if-XXz vA, :lbl | if-XX vA, vB, :lbl
		for i, op := range operands {
			if strings.HasPrefix(strings.TrimSpace(op), ":") {
				if i == len(operands)-1 {
					branchLabel(op)
				}
				continue
			}
			if r := parseReg(op); r != dexir.NoRegister {
				ir.Srcs = append(ir.Srcs, r)
			}
		}

	case strings.HasPrefix(opcode, "goto"):
		if len(operands) > 0 {
			branchLabel(operands[0])
		}

	case opcode == "packed-switch" || opcode == "sparse-switch",
		opcode == "fill-array-data":
		if len(operands) > 0 {
			if r := parseReg(operands[0]); r != dexir.NoRegister {
				ir.Srcs = []int32{r}
			}
		}
		for _, op := range operands[min(1, len(operands)):] {
			if strings.HasPrefix(strings.TrimSpace(op), ":") {
				branchLabel(op)
				break
			}
		}

	case strings.HasPrefix(opcode, "invoke-") || strings.HasPrefix(opcode, "filled-new-array"):
		for _, op := range operands {
			if r := parseReg(op); r != dexir.NoRegister {
				ir.Srcs = append(ir.Srcs, r)
				continue
			}
			if strings.Contains(op, "->") {
				ir.Method = parseLegacyMethodRef(op)
			}
		}

	case strings.HasPrefix(opcode, "const-string"):
		if len(operands) > 0 {
			ir.Dst = parseReg(operands[0])
		}
		if len(operands) > 1 {
			ir.HasStr = true
			ir.Str = strings.Trim(operands[len(operands)-1], `"`)
		}

	case strings.HasPrefix(opcode, "const"):
		if len(operands) > 0 {
			ir.Dst = parseReg(operands[0])
		}
		if opcode == "const-class" && len(operands) > 1 {
			ir.Type = strings.TrimSpace(operands[1])
		} else if len(operands) > 1 {
			tok := strings.TrimSpace(operands[len(operands)-1])
			if v, err := parseLegacyInt(tok); err == nil {
				ir.HasImm = true
				ir.Imm = v
			}
		}

	case strings.HasPrefix(opcode, "move-result"), opcode == "move-exception":
		if len(operands) > 0 {
			ir.Dst = parseReg(operands[0])
		}

	case strings.HasPrefix(opcode, "move"):
		if len(operands) > 0 {
			ir.Dst = parseReg(operands[0])
		}
		if len(operands) > 1 {
			if r := parseReg(operands[1]); r != dexir.NoRegister {
				ir.Srcs = []int32{r}
			}
		}

	case strings.HasPrefix(opcode, "iget") || strings.HasPrefix(opcode, "sget"):
		if len(operands) > 0 {
			ir.Dst = parseReg(operands[0])
		}
		if len(operands) > 1 {
			if r := parseReg(operands[1]); r != dexir.NoRegister {
				ir.Srcs = []int32{r}
			}
		}
		if len(operands) >= 2 {
			ir.Field = parseLegacyFieldRef(operands[len(operands)-1])
		}

	case strings.HasPrefix(opcode, "iput") || strings.HasPrefix(opcode, "sput"):
		for _, op := range operands {
			if r := parseReg(op); r != dexir.NoRegister {
				ir.Srcs = append(ir.Srcs, r)
			}
		}
		if len(operands) > 0 {
			ir.Field = parseLegacyFieldRef(operands[len(operands)-1])
		}

	case strings.HasPrefix(opcode, "aget"):
		if len(operands) > 0 {
			ir.Dst = parseReg(operands[0])
		}
		for _, op := range operands[min(1, len(operands)):] {
			if r := parseReg(op); r != dexir.NoRegister {
				ir.Srcs = append(ir.Srcs, r)
			}
		}

	case strings.HasPrefix(opcode, "aput"):
		for _, op := range operands {
			if r := parseReg(op); r != dexir.NoRegister {
				ir.Srcs = append(ir.Srcs, r)
			}
		}

	case opcode == "new-instance" || opcode == "new-array" ||
		opcode == "instance-of" || opcode == "check-cast":
		if len(operands) > 0 {
			ir.Dst = parseReg(operands[0])
			if opcode == "check-cast" && ir.Dst != dexir.NoRegister {
				ir.Srcs = []int32{ir.Dst}
			}
		}
		if opcode == "instance-of" && len(operands) > 1 {
			if r := parseReg(operands[1]); r != dexir.NoRegister {
				ir.Srcs = append(ir.Srcs, r)
			}
		}
		if len(operands) > 0 {
			if tok := strings.TrimSpace(operands[len(operands)-1]); !isReg(tok) {
				ir.Type = tok
			}
		}

	case opcode == "return-void", opcode == "nop":
		// no operands

	case strings.HasPrefix(opcode, "return"), opcode == "throw",
		opcode == "monitor-enter", opcode == "monitor-exit":
		if len(operands) > 0 {
			if r := parseReg(operands[0]); r != dexir.NoRegister {
				ir.Srcs = []int32{r}
			}
		}

	default:
		// Arithmetic/logical/conversion/cmp: first operand is the
		// destination when it is a register, the rest are sources.
		for i, op := range operands {
			if strings.HasPrefix(strings.TrimSpace(op), ":") {
				continue
			}
			r := parseReg(op)
			if r == dexir.NoRegister {
				continue
			}
			if i == 0 {
				ir.Dst = r
				// 2addr form: vA = vA op vB — vA is also a use.
				if strings.HasSuffix(opcode, "/2addr") {
					ir.Srcs = append(ir.Srcs, r)
				}
				continue
			}
			ir.Srcs = append(ir.Srcs, r)
		}
	}

	return ir
}

// parseLegacyMethodRef parses "Lcls;->name(proto)ret" tokens produced
// by the legacy tokenizer.
func parseLegacyMethodRef(s string) *dexir.MethodRef {
	s = strings.TrimSpace(s)
	sep := strings.Index(s, "->")
	if sep < 0 {
		return nil
	}
	cls := s[:sep]
	rest := s[sep+2:]
	open := strings.IndexByte(rest, '(')
	if open < 0 {
		return &dexir.MethodRef{Class: cls, Name: rest}
	}
	closeIdx := strings.IndexByte(rest[open:], ')')
	if closeIdx < 0 {
		return &dexir.MethodRef{Class: cls, Name: rest[:open]}
	}
	closeIdx += open
	return &dexir.MethodRef{
		Class:      cls,
		Name:       rest[:open],
		Proto:      rest[open:closeIdx+1] + rest[closeIdx+1:],
		ReturnType: rest[closeIdx+1:],
	}
}

// parseLegacyFieldRef parses "Lcls;->name:type" tokens.
func parseLegacyFieldRef(s string) *dexir.FieldRef {
	s = strings.TrimSpace(s)
	sep := strings.Index(s, "->")
	if sep < 0 {
		return nil
	}
	cls := s[:sep]
	rest := s[sep+2:]
	colon := strings.LastIndexByte(rest, ':')
	if colon < 0 {
		return &dexir.FieldRef{Class: cls, Name: rest}
	}
	return &dexir.FieldRef{Class: cls, Name: rest[:colon], Type: rest[colon+1:]}
}

// parseLegacyInt parses smali immediates ("0x1a", "42", "-1").
func parseLegacyInt(tok string) (int64, error) {
	tok = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(tok), ","))
	if strings.HasPrefix(tok, "-0x") || strings.HasPrefix(tok, "-0X") {
		v, err := strconv.ParseInt(tok[3:], 16, 64)
		return -v, err
	}
	if strings.HasPrefix(tok, "0x") || strings.HasPrefix(tok, "0X") {
		return strconv.ParseInt(tok[2:], 16, 64)
	}
	return strconv.ParseInt(tok, 10, 64)
}

// renderConstValue renders a typed immediate the way smali text does
// ("0x1", "-0x2"). The DFG SMT heuristics match these exact forms.
func renderConstValue(v int64) string {
	return fmt.Sprintf("%#x", v)
}
