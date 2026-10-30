package apkloader

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// JAVA PSEUDOCODE GENERATOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// Generates high-level Java-like pseudocode from deobfuscated code.
// Features:
//   - High-level control structures (if/else, loops, try-catch)
//   - Type annotations for variables and methods
//   - Recovered names from variable and method recovery
//   - Uncertainty markers for incomplete recovery
//   - Readability optimization (formatting, comments)

// PseudocodeGenerator generates Java pseudocode from CFG/SSA.
// Output is accumulated directly in sb (strings.Builder) to avoid the
// intermediate []string slice and the final strings.Join allocation.
type PseudocodeGenerator struct {
	CFG                    *CFG
	SSA                    *SSAForm
	VariableRecovery       *VariableRecovery
	MethodRecovery         map[string]*MethodRecoveryResult
	ConstantPropagation    map[int16]interface{}
	TypeInfo               map[int16]TypeInfo
	RecoveredNames         map[int16]string
	RecoveredMethodNames   map[string]string
	MethodSignature        *MethodSignature
	Indent                 int
	IndentString           string
	sb                     strings.Builder // replaces []Lines — no intermediate slice
	UncertaintyThreshold   int
	IncludeComments        bool
	IncludeOriginalNames   bool
	IncludeTypeAnnotations bool
}

// MethodSignature represents a method's signature.
type MethodSignature struct {
	ClassName      string
	MethodName     string
	ReturnType     TypeInfo
	ParameterTypes []TypeInfo
	ParameterNames []string
	IsStatic       bool
	IsConstructor  bool
}

// PseudocodeBlock represents a block of pseudocode.
type PseudocodeBlock struct {
	Type      string // "if", "else", "while", "for", "try", "catch", "finally", "block"
	Condition string
	Body      []string
	Children  []*PseudocodeBlock
}

// NewPseudocodeGenerator creates a new pseudocode generator.
func NewPseudocodeGenerator(
	cfg *CFG,
	ssa *SSAForm,
	varRecovery *VariableRecovery,
	methodRecovery map[string]*MethodRecoveryResult,
	constProp map[int16]interface{},
	methodSig *MethodSignature,
) *PseudocodeGenerator {
	return &PseudocodeGenerator{
		CFG:                    cfg,
		SSA:                    ssa,
		VariableRecovery:       varRecovery,
		MethodRecovery:         methodRecovery,
		ConstantPropagation:    constProp,
		TypeInfo:               make(map[int16]TypeInfo),
		RecoveredNames:         make(map[int16]string),
		RecoveredMethodNames:   make(map[string]string),
		MethodSignature:        methodSig,
		Indent:                 0,
		IndentString:           "    ",
		UncertaintyThreshold:   50,
		IncludeComments:        true,
		IncludeOriginalNames:   true,
		IncludeTypeAnnotations: true,
	}
}

// Generate generates pseudocode for the method.
// All output is written directly to sb; the final string is returned in one
// call to sb.String() without any intermediate join or copy.
func (pg *PseudocodeGenerator) Generate() string {
	pg.sb.Reset()

	// Step 1: Generate method signature
	pg.generateMethodSignature()

	// Step 2: Generate method body
	pg.generateMethodBody()

	return pg.sb.String()
}

// generateMethodSignature generates the method signature.
func (pg *PseudocodeGenerator) generateMethodSignature() {
	if pg.MethodSignature == nil {
		return
	}

	sig := pg.MethodSignature
	var sigBuf strings.Builder

	if sig.IsStatic {
		sigBuf.WriteString("static ")
	}

	if !sig.IsConstructor {
		sigBuf.WriteString(pg.formatType(sig.ReturnType))
		sigBuf.WriteString(" ")
	}

	methodName := sig.MethodName
	if recovered, ok := pg.RecoveredMethodNames[sig.MethodName]; ok {
		methodName = recovered
	}
	sigBuf.WriteString(methodName)

	sigBuf.WriteString("(")
	for i, paramType := range sig.ParameterTypes {
		if i > 0 {
			sigBuf.WriteString(", ")
		}
		sigBuf.WriteString(pg.formatType(paramType))
		sigBuf.WriteString(" ")
		if i < len(sig.ParameterNames) {
			sigBuf.WriteString(sig.ParameterNames[i])
		} else {
			fmt.Fprintf(&sigBuf, "arg%d", i)
		}
	}
	sigBuf.WriteString(")")

	pg.addLine(sigBuf.String() + " {")
	pg.Indent++
}

// generateMethodBody generates the method body.
func (pg *PseudocodeGenerator) generateMethodBody() {
	if pg.CFG == nil || pg.CFG.Entry == nil {
		pg.Indent--
		pg.addLine("}")
		return
	}

	pg.generateVariableDeclarations()
	pg.generateControlFlow()

	pg.Indent--
	pg.addLine("}")
}

// generateVariableDeclarations generates variable declarations.
func (pg *PseudocodeGenerator) generateVariableDeclarations() {
	if pg.SSA == nil || len(pg.SSA.Variables) == 0 {
		return
	}

	declaredVars := make(map[int16]bool)
	declared := 0

	for _, variable := range pg.SSA.Variables {
		if declaredVars[variable.ID] {
			continue
		}
		declaredVars[variable.ID] = true
		declared++

		typeInfo := pg.getVariableType(variable.ID)
		varName := pg.getVariableName(variable.ID)

		if pg.IncludeTypeAnnotations {
			pg.addLinef("%s %s;", pg.formatType(typeInfo), varName)
		} else {
			pg.addLinef("var %s;", varName)
		}

		if pg.IncludeComments && pg.IncludeOriginalNames && pg.VariableRecovery != nil {
			if result := pg.VariableRecovery.GetRecoveryResult(variable.ID); result != nil {
				if result.Confidence < pg.UncertaintyThreshold {
					pg.addLinef("// Original: v%d (confidence: %d%%)", variable.ID, result.Confidence)
				}
			}
		}
	}

	if declared > 0 {
		pg.addLine("")
	}
}

// generateControlFlow generates control flow structures.
func (pg *PseudocodeGenerator) generateControlFlow() {
	if pg.CFG == nil || pg.CFG.Entry == nil {
		return
	}

	visited := make(map[*BasicBlock]bool)
	pg.generateBlockSequence(pg.CFG.Entry, visited)
}

// generateBlockSequence generates a sequence of blocks.
func (pg *PseudocodeGenerator) generateBlockSequence(block *BasicBlock, visited map[*BasicBlock]bool) {
	pg.generateBlockSequenceUntil(block, nil, visited)
}

// generateBlockSequenceUntil emits blocks up to (but excluding) stop.
func (pg *PseudocodeGenerator) generateBlockSequenceUntil(block, stop *BasicBlock, visited map[*BasicBlock]bool) {
	if block == nil || block == stop || visited[block] {
		return
	}
	visited[block] = true

	// Loop headers with a back-edge are rendered as while loops so the
	// repetition is not lost as a one-shot if/else.
	if block.IsLoopHeader && len(block.Succs) == 2 {
		if pg.tryGenerateLoop(block, stop, visited) {
			return
		}
	}

	pg.generateBlockInstructions(block)

	if len(block.Succs) == 0 {
		return
	} else if len(block.Succs) == 1 {
		if block.Succs[0] == stop {
			return
		}
		pg.generateBlockSequenceUntil(block.Succs[0], stop, visited)
	} else if len(block.Succs) == 2 {
		pg.generateConditionalBranchUntil(block, stop, visited)
	} else {
		pg.generateMultipleSuccessors(block, visited)
	}
}

// generateBlockInstructions generates instructions in a block.
func (pg *PseudocodeGenerator) generateBlockInstructions(block *BasicBlock) {
	for i := 0; i < len(block.Insns); i++ {
		insn := &block.Insns[i]
		// Fuse invoke + move-result so the call assignment is not lost.
		// Dalvik returns values in a separate pseudo-register; Java needs
		// "vDst = call(args);".
		if insn.Kind == MIR_INVOKE && i+1 < len(block.Insns) && block.Insns[i+1].Kind == MIR_MOVE_RESULT {
			pg.generateInvokeWithResultInstruction(insn, &block.Insns[i+1])
			i++
			continue
		}
		if insn.Kind == MIR_MOVE_RESULT {
			pg.generateMoveResultInstruction(insn)
			continue
		}
		pg.generateInstruction(insn, i, block)
	}
}

// generateInstruction generates a single instruction.
func (pg *PseudocodeGenerator) generateInstruction(insn *MIRInsn, _ int, _ *BasicBlock) {
	switch insn.Kind {
	case MIR_CONST:
		pg.generateConstInstruction(insn)
	case MIR_MOVE:
		pg.generateMoveInstruction(insn)
	case MIR_MOVE_RESULT:
		pg.generateMoveResultInstruction(insn)
	case MIR_ADD, MIR_SUB, MIR_RSUB, MIR_MUL, MIR_DIV, MIR_REM:
		pg.generateArithmeticInstruction(insn)
	case MIR_AND, MIR_OR, MIR_XOR, MIR_SHL, MIR_SHR, MIR_USHR:
		pg.generateBitwiseInstruction(insn)
	case MIR_FIELD_GET:
		pg.generateFieldGetInstruction(insn)
	case MIR_FIELD_PUT:
		pg.generateFieldPutInstruction(insn)
	case MIR_ARRAY_GET:
		pg.generateArrayGetInstruction(insn)
	case MIR_ARRAY_PUT:
		pg.generateArrayPutInstruction(insn)
	case MIR_INVOKE:
		pg.generateInvokeInstruction(insn)
	case MIR_NEW_INSTANCE:
		pg.generateNewInstanceInstruction(insn)
	case MIR_NEW_ARRAY:
		pg.generateNewArrayInstruction(insn)
	case MIR_CHECK_CAST:
		pg.generateCheckCastInstruction(insn)
	case MIR_INSTANCE_OF:
		pg.generateInstanceOfInstruction(insn)
	case MIR_RETURN:
		pg.generateReturnInstruction(insn)
	case MIR_THROW:
		pg.generateThrowInstruction(insn)
	case MIR_MONITOR_ENTER:
		pg.generateMonitorEnterInstruction(insn)
	case MIR_MONITOR_EXIT:
		pg.generateMonitorExitInstruction(insn)
	}
}

func (pg *PseudocodeGenerator) generateConstInstruction(insn *MIRInsn) {
	if insn.Dst < 0 {
		return
	}
	pg.addLinef("%s = %s;", pg.getVariableName(insn.Dst), pg.formatConstantValue(insn.Imm, insn.DataType))
}

func (pg *PseudocodeGenerator) generateMoveInstruction(insn *MIRInsn) {
	if insn.Dst < 0 || insn.Src1 < 0 {
		return
	}
	pg.addLinef("%s = %s;", pg.getVariableName(insn.Dst), pg.getVariableName(insn.Src1))
}

func (pg *PseudocodeGenerator) generateArithmeticInstruction(insn *MIRInsn) {
	if insn.Dst < 0 || insn.Src1 < 0 {
		return
	}

	dstName := pg.getVariableName(insn.Dst)
	src1Name := pg.getVariableName(insn.Src1)

	var op string
	switch insn.Kind {
	case MIR_ADD:
		op = "+"
	case MIR_SUB:
		op = "-"
	case MIR_RSUB:
		op = "-"
		if insn.Src2 < 0 {
			pg.addLinef("%s = %s - %s;", dstName, pg.formatConstantValue(insn.Imm, insn.DataType), src1Name)
			return
		}
	case MIR_MUL:
		op = "*"
	case MIR_DIV:
		op = "/"
	case MIR_REM:
		op = "%"
	}

	if insn.Src2 >= 0 {
		src2Name := pg.getVariableName(insn.Src2)
		if insn.Kind == MIR_RSUB {
			pg.addLinef("%s = %s %s %s;", dstName, src2Name, op, src1Name)
		} else {
			pg.addLinef("%s = %s %s %s;", dstName, src1Name, op, src2Name)
		}
	} else {
		pg.addLinef("%s = %s %s %s;", dstName, src1Name, op, pg.formatConstantValue(insn.Imm, insn.DataType))
	}
}

func (pg *PseudocodeGenerator) generateBitwiseInstruction(insn *MIRInsn) {
	if insn.Dst < 0 || insn.Src1 < 0 {
		return
	}

	dstName := pg.getVariableName(insn.Dst)
	src1Name := pg.getVariableName(insn.Src1)

	var op string
	switch insn.Kind {
	case MIR_AND:
		op = "&"
	case MIR_OR:
		op = "|"
	case MIR_XOR:
		op = "^"
	case MIR_SHL:
		op = "<<"
	case MIR_SHR:
		op = ">>"
	case MIR_USHR:
		op = ">>>"
	}

	if insn.Src2 >= 0 {
		pg.addLinef("%s = %s %s %s;", dstName, src1Name, op, pg.getVariableName(insn.Src2))
	} else {
		pg.addLinef("%s = %s %s %s;", dstName, src1Name, op, pg.formatConstantValue(insn.Imm, insn.DataType))
	}
}

func (pg *PseudocodeGenerator) generateFieldGetInstruction(insn *MIRInsn) {
	if insn.Dst < 0 {
		return
	}
	dstName := pg.getVariableName(insn.Dst)
	fieldName := pg.formatFieldName(insn.RefIdx)

	if insn.FieldKind == FieldStatic {
		pg.addLinef("%s = %s;", dstName, fieldName)
	} else if insn.Src1 >= 0 {
		pg.addLinef("%s = %s.%s;", dstName, pg.getVariableName(insn.Src1), fieldName)
	}
}

func (pg *PseudocodeGenerator) generateFieldPutInstruction(insn *MIRInsn) {
	if insn.Src1 < 0 {
		return
	}
	fieldName := pg.formatFieldName(insn.RefIdx)
	valueName := pg.getVariableName(insn.Src1)

	if insn.FieldKind == FieldStatic {
		pg.addLinef("%s = %s;", fieldName, valueName)
	} else if insn.Src2 >= 0 {
		pg.addLinef("%s.%s = %s;", pg.getVariableName(insn.Src2), fieldName, valueName)
	}
}

func (pg *PseudocodeGenerator) generateArrayGetInstruction(insn *MIRInsn) {
	if insn.Dst < 0 || insn.Src1 < 0 || insn.Src2 < 0 {
		return
	}
	pg.addLinef("%s = %s[%s];", pg.getVariableName(insn.Dst), pg.getVariableName(insn.Src1), pg.getVariableName(insn.Src2))
}

func (pg *PseudocodeGenerator) generateArrayPutInstruction(insn *MIRInsn) {
	if insn.Src1 < 0 || insn.Src2 < 0 {
		return
	}
	valReg := insn.Src3
	if valReg < 0 {
		valReg = insn.Dst
	}
	if valReg >= 0 {
		pg.addLinef("%s[%s] = %s;", pg.getVariableName(insn.Src1), pg.getVariableName(insn.Src2), pg.getVariableName(valReg))
	}
}

func (pg *PseudocodeGenerator) formatInvokeCall(insn *MIRInsn) string {
	name := pg.formatMethodName(insn.RefIdx)
	args := insn.Args()
	if len(args) == 0 && insn.ArgsLen > 0 {
		// Defensive: Args() should already cover this, but keep the call
		// arguments visible even if the slice view is empty.
		n := int(insn.ArgsLen)
		if n > len(insn.ArgsData) {
			n = len(insn.ArgsData)
		}
		args = insn.ArgsData[:n]
	}
	if len(args) == 0 {
		return name + "()"
	}
	parts := make([]string, 0, len(args))
	for _, r := range args {
		parts = append(parts, pg.getVariableName(int16(r)))
	}
	out := name + "("
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out + ")"
}

func (pg *PseudocodeGenerator) generateInvokeInstruction(insn *MIRInsn) {
	pg.addLinef("%s;", pg.formatInvokeCall(insn))
}

func (pg *PseudocodeGenerator) generateInvokeWithResultInstruction(invoke, moveResult *MIRInsn) {
	call := pg.formatInvokeCall(invoke)
	if moveResult != nil && moveResult.Dst >= 0 {
		pg.addLinef("%s = %s;", pg.getVariableName(moveResult.Dst), call)
		return
	}
	pg.addLinef("%s;", call)
}

func (pg *PseudocodeGenerator) generateMoveResultInstruction(insn *MIRInsn) {
	if insn.Dst < 0 {
		return
	}
	// A lone move-result without its invoke in the same block means the
	// producer was emitted earlier; keep the assignment visible instead of
	// dropping it so data flow is not silently lost.
	pg.addLinef("%s = /* invoke-result */;", pg.getVariableName(insn.Dst))
}

func (pg *PseudocodeGenerator) generateNewInstanceInstruction(insn *MIRInsn) {
	if insn.Dst < 0 {
		return
	}
	pg.addLinef("%s = new %s();", pg.getVariableName(insn.Dst), pg.formatClassName(insn.RefIdx))
}

func (pg *PseudocodeGenerator) generateNewArrayInstruction(insn *MIRInsn) {
	if insn.Dst < 0 || insn.Src1 < 0 {
		return
	}
	pg.addLinef("%s = new %s[%s];", pg.getVariableName(insn.Dst), pg.formatType(TypeInfo{BaseType: "Object"}), pg.getVariableName(insn.Src1))
}

func (pg *PseudocodeGenerator) generateCheckCastInstruction(insn *MIRInsn) {
	if insn.Src1 < 0 {
		return
	}
	pg.addLinef("// checkcast %s to %s", pg.getVariableName(insn.Src1), pg.formatClassName(insn.RefIdx))
}

func (pg *PseudocodeGenerator) generateInstanceOfInstruction(insn *MIRInsn) {
	if insn.Dst < 0 || insn.Src1 < 0 {
		return
	}
	pg.addLinef("%s = %s instanceof %s;", pg.getVariableName(insn.Dst), pg.getVariableName(insn.Src1), pg.formatClassName(insn.RefIdx))
}

func (pg *PseudocodeGenerator) generateReturnInstruction(insn *MIRInsn) {
	if insn.Src1 >= 0 {
		pg.addLinef("return %s;", pg.getVariableName(insn.Src1))
	} else {
		pg.addLine("return;")
	}
}

func (pg *PseudocodeGenerator) generateThrowInstruction(insn *MIRInsn) {
	if insn.Src1 >= 0 {
		pg.addLinef("throw %s;", pg.getVariableName(insn.Src1))
	}
}

func (pg *PseudocodeGenerator) generateMonitorEnterInstruction(insn *MIRInsn) {
	if insn.Src1 >= 0 {
		pg.addLinef("synchronized (%s) {", pg.getVariableName(insn.Src1))
		pg.Indent++
	}
}

func (pg *PseudocodeGenerator) generateMonitorExitInstruction(_ *MIRInsn) {
	pg.Indent--
	pg.addLine("}")
}

func (pg *PseudocodeGenerator) generateConditionalBranch(block *BasicBlock, visited map[*BasicBlock]bool) {
	pg.generateConditionalBranchUntil(block, nil, visited)
}

func (pg *PseudocodeGenerator) generateConditionalBranchUntil(block, stop *BasicBlock, visited map[*BasicBlock]bool) {
	if len(block.Insns) == 0 {
		return
	}
	lastInsn := &block.Insns[len(block.Insns)-1]
	if lastInsn.Kind != MIR_IF {
		return
	}
	// Emit the branch head without the terminal IF itself (it is structural).
	// The head block's non-branch instructions were already emitted by the
	// caller via generateBlockInstructions, so here we only structure.
	cond := pg.formatCondition(lastInsn)
	left, right := block.Succs[0], block.Succs[1]

	// Diamond with a common join: emit the join once after both branches
	// instead of letting the first branch consume it via the shared visited
	// set (which previously moved a common return into only the first arm).
	if join := findDiamondJoin(left, right); join != nil && join != stop && !visited[join] {
		pg.addLinef("if (%s) {", cond)
		pg.Indent++
		pg.generateBlockSequenceUntil(left, join, visited)
		pg.Indent--
		pg.addLine("} else {")
		pg.Indent++
		pg.generateBlockSequenceUntil(right, join, visited)
		pg.Indent--
		pg.addLine("}")
		pg.generateBlockSequenceUntil(join, stop, visited)
		return
	}

	pg.addLinef("if (%s) {", cond)
	pg.Indent++
	if left != stop {
		pg.generateBlockSequenceUntil(left, stop, visited)
	}
	pg.Indent--
	pg.addLine("} else {")
	pg.Indent++
	if right != stop {
		pg.generateBlockSequenceUntil(right, stop, visited)
	}
	pg.Indent--
	pg.addLine("}")
}

// tryGenerateLoop renders a loop header with a back-edge as a while loop.
// Returns false when the shape is not a simple two-successor loop.
func (pg *PseudocodeGenerator) tryGenerateLoop(header, stop *BasicBlock, visited map[*BasicBlock]bool) bool {
	if len(header.Insns) == 0 || len(header.Succs) != 2 {
		return false
	}
	last := &header.Insns[len(header.Insns)-1]
	if last.Kind != MIR_IF {
		return false
	}
	body, exit := header.Succs[0], header.Succs[1]
	bodyLoops := blockCanReach(body, header, 32)
	exitLoops := blockCanReach(exit, header, 32)
	if !bodyLoops && !exitLoops {
		return false
	}
	// Emit header prefix (everything except the terminal IF) so setup code
	// before the loop condition is not lost.
	for i := 0; i < len(header.Insns)-1; i++ {
		insn := &header.Insns[i]
		if insn.Kind == MIR_INVOKE && i+1 < len(header.Insns)-1 && header.Insns[i+1].Kind == MIR_MOVE_RESULT {
			pg.generateInvokeWithResultInstruction(insn, &header.Insns[i+1])
			i++
			continue
		}
		if insn.Kind == MIR_MOVE_RESULT {
			pg.generateMoveResultInstruction(insn)
			continue
		}
		// Skip the terminal IF itself (structural).
		if insn.Kind == MIR_IF {
			continue
		}
		pg.generateInstruction(insn, i, header)
	}
	// Normalize so body is the looping successor.
	cond := pg.formatCondition(last)
	if !bodyLoops {
		body, exit = exit, body
		cond = negateCondition(cond)
	}
	pg.addLinef("while (%s) {", cond)
	pg.Indent++
	// Body up to the back-edge (exclude the header itself to avoid recursion).
	pg.generateBlockSequenceUntil(body, header, visited)
	pg.Indent--
	pg.addLine("}")
	if exit != stop {
		pg.generateBlockSequenceUntil(exit, stop, visited)
	}
	return true
}

func findDiamondJoin(left, right *BasicBlock) *BasicBlock {
	if left == nil || right == nil {
		return nil
	}
	if len(left.Succs) == 1 && len(right.Succs) == 1 && left.Succs[0] == right.Succs[0] {
		return left.Succs[0]
	}
	// General small-graph intersection: first common reachable block.
	lReach := reachableBlocks(left, 32)
	rReach := reachableBlocks(right, 32)
	// Prefer the nearest common block from the left side (BFS order).
	order := bfsOrder(left, 32)
	rSet := make(map[*BasicBlock]bool, len(rReach))
	for _, b := range rReach {
		rSet[b] = true
	}
	for _, b := range order {
		if b == left || b == right {
			continue
		}
		if rSet[b] {
			return b
		}
	}
	_ = lReach
	return nil
}

func reachableBlocks(start *BasicBlock, limit int) []*BasicBlock {
	return bfsOrder(start, limit)
}

func bfsOrder(start *BasicBlock, limit int) []*BasicBlock {
	if start == nil {
		return nil
	}
	var out []*BasicBlock
	seen := map[*BasicBlock]bool{start: true}
	queue := []*BasicBlock{start}
	for len(queue) > 0 && len(out) < limit {
		b := queue[0]
		queue = queue[1:]
		out = append(out, b)
		for _, s := range b.Succs {
			if s != nil && !seen[s] {
				seen[s] = true
				queue = append(queue, s)
			}
		}
	}
	return out
}

func blockCanReach(from, to *BasicBlock, limit int) bool {
	if from == nil || to == nil {
		return false
	}
	if from == to {
		return true
	}
	for _, b := range bfsOrder(from, limit) {
		if b == to {
			return true
		}
	}
	return false
}

func negateCondition(cond string) string {
	// Best-effort negation for generated conditions; unknown shapes fall
	// back to !(...) so the loop is still represented instead of dropped.
	negations := [][2]string{
		{" == 0", " != 0"}, {" != 0", " == 0"},
		{" < 0", " >= 0"}, {" >= 0", " < 0"},
		{" > 0", " <= 0"}, {" <= 0", " > 0"},
		{"==", "!="}, {"!=", "=="},
		{"<=", ">"}, {">=", "<"},
		{" < ", " >= "}, {" > ", " <= "},
		{"<", ">"}, {">", "<"},
	}
	// Try multi-char operators first (longest match).
	for _, p := range negations {
		if idx := indexOf(cond, p[0]); idx >= 0 {
			// Only negate the first operator occurrence.
			return cond[:idx] + p[1] + cond[idx+len(p[0]):]
		}
	}
	return "!(" + cond + ")"
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func (pg *PseudocodeGenerator) generateMultipleSuccessors(block *BasicBlock, visited map[*BasicBlock]bool) {
	for _, succ := range block.Succs {
		pg.generateBlockSequence(succ, visited)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (pg *PseudocodeGenerator) getVariableName(varID int16) string {
	if recovered, ok := pg.RecoveredNames[varID]; ok {
		return recovered
	}
	if pg.VariableRecovery != nil {
		if result := pg.VariableRecovery.GetRecoveryResult(varID); result != nil {
			if result.Confidence >= pg.UncertaintyThreshold {
				return result.SelectedName
			}
		}
	}
	return fmt.Sprintf("v%d", varID)
}

func (pg *PseudocodeGenerator) getVariableType(varID int16) TypeInfo {
	if typeInfo, ok := pg.TypeInfo[varID]; ok {
		return typeInfo
	}
	return TypeInfo{BaseType: "Object"}
}

func (pg *PseudocodeGenerator) formatType(typeInfo TypeInfo) string {
	if typeInfo.IsArray {
		return pg.formatType(TypeInfo{BaseType: typeInfo.BaseType}) + "[]"
	}
	return typeInfo.BaseType
}

func (pg *PseudocodeGenerator) formatConstantValue(value int64, dataType MIRDataType) string {
	switch dataType {
	case TypeInt, TypeShort, TypeByte:
		return fmt.Sprintf("%d", value)
	case TypeLong:
		return fmt.Sprintf("%dL", value)
	case TypeFloat:
		return fmt.Sprintf("%ff", float32(value))
	case TypeDouble:
		return fmt.Sprintf("%f", float64(value))
	case TypeBoolean:
		if value != 0 {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("0x%x", value)
	}
}

func (pg *PseudocodeGenerator) formatCondition(insn *MIRInsn) string {
	if insn.Src1 < 0 {
		return "true"
	}
	src1Name := pg.getVariableName(insn.Src1)

	var op string
	switch insn.Cond {
	case CondEQ:
		op = "=="
	case CondNE:
		op = "!="
	case CondLT:
		op = "<"
	case CondGE:
		op = ">="
	case CondGT:
		op = ">"
	case CondLE:
		op = "<="
	case CondEQZ:
		return fmt.Sprintf("%s == 0", src1Name)
	case CondNEZ:
		return fmt.Sprintf("%s != 0", src1Name)
	case CondLTZ:
		return fmt.Sprintf("%s < 0", src1Name)
	case CondGEZ:
		return fmt.Sprintf("%s >= 0", src1Name)
	case CondGTZ:
		return fmt.Sprintf("%s > 0", src1Name)
	case CondLEZ:
		return fmt.Sprintf("%s <= 0", src1Name)
	default:
		return "true"
	}

	if insn.Src2 >= 0 {
		return fmt.Sprintf("%s %s %s", src1Name, op, pg.getVariableName(insn.Src2))
	}
	return fmt.Sprintf("%s %s 0", src1Name, op)
}

func (pg *PseudocodeGenerator) formatFieldName(refIdx uint32) string {
	return fmt.Sprintf("field_%d", refIdx)
}

func (pg *PseudocodeGenerator) formatMethodName(refIdx uint32) string {
	return fmt.Sprintf("method_%d", refIdx)
}

func (pg *PseudocodeGenerator) formatClassName(refIdx uint32) string {
	return fmt.Sprintf("Class_%d", refIdx)
}

// addLine writes one indented line followed by a newline directly into sb.
func (pg *PseudocodeGenerator) addLine(line string) {
	for i := 0; i < pg.Indent; i++ {
		pg.sb.WriteString(pg.IndentString)
	}
	pg.sb.WriteString(line)
	pg.sb.WriteByte('\n')
}

// addLinef is a convenience wrapper around addLine for formatted output.
// It avoids the temporary string that fmt.Sprintf + addLine would produce.
func (pg *PseudocodeGenerator) addLinef(format string, args ...interface{}) {
	for i := 0; i < pg.Indent; i++ {
		pg.sb.WriteString(pg.IndentString)
	}
	fmt.Fprintf(&pg.sb, format, args...)
	pg.sb.WriteByte('\n')
}

// TypeInfo represents type information for a variable.
type TypeInfo struct {
	BaseType        string
	IsArray         bool
	ArrayDimensions int
	GenericParams   []TypeInfo
	Confidence      int
}
