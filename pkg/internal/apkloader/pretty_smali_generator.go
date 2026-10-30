package apkloader

import (
	"fmt"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PRETTY SMALI GENERATOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// Generates readable Smali output with recovered names and annotations.
// Features:
//   - Proper indentation and formatting
//   - Recovered variable and method names
//   - Confidence scores in comments
//   - Original name preservation in comments
//   - Obfuscation technique annotations
//   - Helpful comment generation

// PrettySmaliGenerator generates readable Smali code with annotations.
type PrettySmaliGenerator struct {
	CFG                    *CFG
	SSA                    *SSAForm
	VariableRecovery       *VariableRecovery
	MethodRecovery         map[string]*MethodRecoveryResult
	ConstantPropagation    map[int16]interface{}
	DetectedObfuscations   []string
	MinConfidenceThreshold int
	IncludeConfidenceScore bool
	IncludeOriginalNames   bool
	IncludeObfuscationInfo bool

	// Method metadata
	MethodName      string
	MethodSignature string

	// Indentation
	IndentLevel  int
	IndentString string
}

// MethodRecoveryResult contains the recovery result for a method.
type MethodRecoveryResult struct {
	MethodName string
	Confidence int
	Rationale  string
	Signals    []RecoverySignal
}

// RecoverySignal represents a signal used in method recovery.
type RecoverySignal struct {
	Type     string
	Evidence string
	Weight   int
}

// SmaliOutput represents the generated Smali code with metadata.
type SmaliOutput struct {
	Code              string
	VariableComments  map[string]string
	MethodComments    map[string]string
	ObfuscationNotes  []string
	RecoveryStats     RecoveryStats
	FormattingMetrics FormattingMetrics
}

// RecoveryStats contains statistics about the recovery process.
type RecoveryStats struct {
	VariablesRecovered        int
	VariablesWithHighConf     int
	MethodsRecovered          int
	MethodsWithHighConf       int
	ConstantsRecovered        int
	ObfuscationTechniques     []string
	AverageVariableConfidence int
	AverageMethodConfidence   int
}

// FormattingMetrics contains metrics about the formatting.
type FormattingMetrics struct {
	TotalLines          int
	CommentLines        int
	CodeLines           int
	AverageIndentation  int
	MaxIndentationLevel int
}

// NewPrettySmaliGenerator creates a new Pretty Smali generator.
func NewPrettySmaliGenerator(cfg *CFG, ssa *SSAForm) *PrettySmaliGenerator {
	return &PrettySmaliGenerator{
		CFG:                    cfg,
		SSA:                    ssa,
		VariableRecovery:       nil,
		MethodRecovery:         make(map[string]*MethodRecoveryResult),
		ConstantPropagation:    make(map[int16]interface{}),
		DetectedObfuscations:   make([]string, 0),
		IndentLevel:            0,
		IndentString:           "    ", // 4 spaces
		IncludeConfidenceScore: true,
		IncludeOriginalNames:   true,
		IncludeObfuscationInfo: true,
		MinConfidenceThreshold: 50,
	}
}

// SetVariableRecovery sets the variable recovery results.
func (psg *PrettySmaliGenerator) SetVariableRecovery(vr *VariableRecovery) {
	psg.VariableRecovery = vr
}

// AddMethodRecovery adds a method recovery result.
func (psg *PrettySmaliGenerator) AddMethodRecovery(methodName string, result *MethodRecoveryResult) {
	psg.MethodRecovery[methodName] = result
}

// AddConstantValue adds a constant value for a variable.
func (psg *PrettySmaliGenerator) AddConstantValue(varID int16, value interface{}) {
	psg.ConstantPropagation[varID] = value
}

// AddDetectedObfuscation adds a detected obfuscation technique.
func (psg *PrettySmaliGenerator) AddDetectedObfuscation(technique string) {
	psg.DetectedObfuscations = append(psg.DetectedObfuscations, technique)
}

// GenerateSmali generates readable Smali code with annotations.
func (psg *PrettySmaliGenerator) GenerateSmali() *SmaliOutput {
	output := &SmaliOutput{
		VariableComments:  make(map[string]string),
		MethodComments:    make(map[string]string),
		ObfuscationNotes:  make([]string, 0),
		RecoveryStats:     psg.calculateRecoveryStats(),
		FormattingMetrics: FormattingMetrics{},
	}

	var code strings.Builder

	// Generate header comments
	psg.writeHeader(&code, output)

	// Generate obfuscation technique annotations
	if psg.IncludeObfuscationInfo && len(psg.DetectedObfuscations) > 0 {
		psg.writeObfuscationAnnotations(&code, output)
	}

	// Generate variable recovery comments
	if psg.VariableRecovery != nil && psg.IncludeOriginalNames {
		psg.writeVariableRecoveryComments(&code, output)
	}

	// Generate method recovery comments
	if len(psg.MethodRecovery) > 0 && psg.IncludeOriginalNames {
		psg.writeMethodRecoveryComments(&code, output)
	}

	// Generate constant propagation comments
	if len(psg.ConstantPropagation) > 0 {
		psg.writeConstantPropagationComments(&code, output)
	}

	// Generate CFG structure comments
	psg.writeCFGStructure(&code, output)

	// Generate actual method body
	psg.writeMethodBody(&code, output)

	output.Code = code.String()
	psg.calculateFormattingMetrics(output)

	return output
}

// writeHeader writes the header comments.
func (psg *PrettySmaliGenerator) writeHeader(code *strings.Builder, _ *SmaliOutput) {
	code.WriteString("# ═══════════════════════════════════════════════════════════════════════════════\n")
	code.WriteString("# PRETTY SMALI OUTPUT — Deobfuscation Pipeline\n")
	code.WriteString("# ═══════════════════════════════════════════════════════════════════════════════\n")
	code.WriteString("#\n")
	code.WriteString("# This output contains recovered names and annotations from the deobfuscation pipeline.\n")
	code.WriteString("#\n")

	if psg.IncludeConfidenceScore {
		code.WriteString("# Confidence Scores:\n")
		code.WriteString("#   - 80-100: High confidence (reliable recovered names)\n")
		code.WriteString("#   - 50-79:  Medium confidence (reasonable but may need verification)\n")
		code.WriteString("#   - 0-49:   Low confidence (original names preserved)\n")
		code.WriteString("#\n")
	}

	code.WriteString("# Legend:\n")
	code.WriteString("#   [RECOVERED] — Name recovered from analysis\n")
	code.WriteString("#   [ORIGINAL]  — Original obfuscated name\n")
	code.WriteString("#   [CONFIDENCE] — Confidence score (0-100)\n")
	code.WriteString("#   [OBFUSCATION] — Detected obfuscation technique\n")
	code.WriteString("#\n")
	code.WriteString("# ═══════════════════════════════════════════════════════════════════════════════\n")
	code.WriteString("\n")
}

// writeObfuscationAnnotations writes obfuscation technique annotations.
func (psg *PrettySmaliGenerator) writeObfuscationAnnotations(code *strings.Builder, output *SmaliOutput) {
	code.WriteString("# DETECTED OBFUSCATION TECHNIQUES\n")
	code.WriteString("# ─────────────────────────────────────────────────────────────────────────────\n")

	for _, technique := range psg.DetectedObfuscations {
		code.WriteString(fmt.Sprintf("# [OBFUSCATION] %s\n", technique))
		output.ObfuscationNotes = append(output.ObfuscationNotes, technique)
	}

	code.WriteString("\n")
}

// writeVariableRecoveryComments writes variable recovery comments.
func (psg *PrettySmaliGenerator) writeVariableRecoveryComments(code *strings.Builder, output *SmaliOutput) {
	if psg.VariableRecovery == nil || psg.VariableRecovery.RecoveryCount() == 0 {
		return
	}

	code.WriteString("# VARIABLE RECOVERY\n")
	code.WriteString("# ─────────────────────────────────────────────────────────────────────────────\n")

	// Sort keys to ensure deterministic output
	var keys []int
	for varID := range psg.VariableRecovery.Results {
		keys = append(keys, int(varID))
	}
	sort.Ints(keys)

	for _, k := range keys {
		result := psg.VariableRecovery.Results[int16(k)]
		if result.Confidence < psg.MinConfidenceThreshold {
			continue
		}

		varName := fmt.Sprintf("v%d", result.Variable.ID)
		comment := psg.formatVariableComment(result)
		code.WriteString(comment)
		output.VariableComments[varName] = comment
	}

	code.WriteString("\n")
}

// formatVariableComment formats a variable recovery comment.
func (psg *PrettySmaliGenerator) formatVariableComment(result *VariableRecoveryResult) string {
	var comment strings.Builder

	varName := fmt.Sprintf("v%d", result.Variable.ID)
	comment.WriteString(fmt.Sprintf("# %s: ", varName))

	if psg.IncludeOriginalNames {
		comment.WriteString(fmt.Sprintf("[ORIGINAL: v%d] ", result.Variable.OrigRegister))
	}

	comment.WriteString(fmt.Sprintf("[RECOVERED: %s] ", result.SelectedName))

	if psg.IncludeConfidenceScore {
		comment.WriteString(fmt.Sprintf("[CONFIDENCE: %d%%] ", result.Confidence))
	}

	comment.WriteString(fmt.Sprintf("(%s)\n", result.Rationale))

	return comment.String()
}

// writeMethodRecoveryComments writes method recovery comments.
func (psg *PrettySmaliGenerator) writeMethodRecoveryComments(code *strings.Builder, output *SmaliOutput) {
	if len(psg.MethodRecovery) == 0 {
		return
	}

	code.WriteString("# METHOD RECOVERY\n")
	code.WriteString("# ─────────────────────────────────────────────────────────────────────────────\n")

	// Sort keys to ensure deterministic output
	var keys []string
	for methodName := range psg.MethodRecovery {
		keys = append(keys, methodName)
	}
	sort.Strings(keys)

	for _, methodName := range keys {
		result := psg.MethodRecovery[methodName]
		if result.Confidence < psg.MinConfidenceThreshold {
			continue
		}

		comment := psg.formatMethodComment(methodName, result)
		code.WriteString(comment)
		output.MethodComments[methodName] = comment
	}

	code.WriteString("\n")
}

// formatMethodComment formats a method recovery comment.
func (psg *PrettySmaliGenerator) formatMethodComment(methodName string, result *MethodRecoveryResult) string {
	var comment strings.Builder

	comment.WriteString(fmt.Sprintf("# %s: ", methodName))

	if psg.IncludeOriginalNames {
		comment.WriteString(fmt.Sprintf("[ORIGINAL: %s] ", methodName))
	}

	comment.WriteString(fmt.Sprintf("[RECOVERED: %s] ", result.MethodName))

	if psg.IncludeConfidenceScore {
		comment.WriteString(fmt.Sprintf("[CONFIDENCE: %d%%] ", result.Confidence))
	}

	comment.WriteString(fmt.Sprintf("(%s)\n", result.Rationale))

	// Add recovery signals
	if len(result.Signals) > 0 {
		comment.WriteString("#   Signals:\n")
		for _, signal := range result.Signals {
			comment.WriteString(fmt.Sprintf("#     - %s: %s (weight: %d)\n", signal.Type, signal.Evidence, signal.Weight))
		}
	}

	return comment.String()
}

// writeConstantPropagationComments writes constant propagation comments.
func (psg *PrettySmaliGenerator) writeConstantPropagationComments(code *strings.Builder, _ *SmaliOutput) {
	code.WriteString("# CONSTANT PROPAGATION\n")
	code.WriteString("# ─────────────────────────────────────────────────────────────────────────────\n")

	// Sort keys to ensure deterministic output
	var keys []int
	for varID := range psg.ConstantPropagation {
		keys = append(keys, int(varID))
	}
	sort.Ints(keys)

	for _, k := range keys {
		varID := int16(k)
		value := psg.ConstantPropagation[varID]
		varName := fmt.Sprintf("v%d", varID)
		code.WriteString(fmt.Sprintf("# %s = %v\n", varName, value))
	}

	code.WriteString("\n")
}

// writeCFGStructure writes CFG structure comments.
func (psg *PrettySmaliGenerator) writeCFGStructure(code *strings.Builder, _ *SmaliOutput) {
	if psg.CFG == nil || len(psg.CFG.Blocks) == 0 {
		return
	}

	code.WriteString("# CONTROL FLOW GRAPH STRUCTURE\n")
	code.WriteString("# ─────────────────────────────────────────────────────────────────────────────\n")
	code.WriteString(fmt.Sprintf("# Total Basic Blocks: %d\n", len(psg.CFG.Blocks)))

	reachableCount := 0
	for _, block := range psg.CFG.Blocks {
		if block.IsReachable {
			reachableCount++
		}
	}
	code.WriteString(fmt.Sprintf("# Reachable Blocks: %d\n", reachableCount))
	code.WriteString(fmt.Sprintf("# Unreachable Blocks: %d\n", len(psg.CFG.Blocks)-reachableCount))

	loopHeaderCount := 0
	for _, block := range psg.CFG.Blocks {
		if block.IsLoopHeader {
			loopHeaderCount++
		}
	}
	code.WriteString(fmt.Sprintf("# Loop Headers: %d\n", loopHeaderCount))

	exceptionHandlerCount := len(psg.CFG.HandlerBlocks)
	code.WriteString(fmt.Sprintf("# Exception Handlers: %d\n", exceptionHandlerCount))

	code.WriteString("\n")
}

// writeMethodBody writes the actual method code.
func (psg *PrettySmaliGenerator) writeMethodBody(code *strings.Builder, _ *SmaliOutput) {
	if psg.CFG == nil {
		return
	}

	methodName := psg.MethodName
	if methodName == "" {
		methodName = "unknownMethod"
	}
	signature := psg.MethodSignature
	if signature == "" {
		signature = "()V"
	}

	code.WriteString(fmt.Sprintf(".method public %s%s\n", methodName, signature))
	psg.Indent()

	for _, block := range psg.CFG.Blocks {
		if !block.IsReachable {
			continue
		}

		code.WriteString(fmt.Sprintf("%s# Block %d\n", psg.GetIndentString(), block.ID))
		for _, insn := range block.Insns {
			code.WriteString(psg.FormatInstruction(&insn))
			code.WriteString("\n")
		}
		code.WriteString("\n")
	}

	psg.Dedent()
	code.WriteString(".end method\n")
}

// calculateRecoveryStats calculates recovery statistics.
func (psg *PrettySmaliGenerator) calculateRecoveryStats() RecoveryStats {
	stats := RecoveryStats{
		ObfuscationTechniques: psg.DetectedObfuscations,
	}

	if psg.VariableRecovery != nil {
		stats.VariablesRecovered = psg.VariableRecovery.RecoveryCount()

		totalConfidence := 0
		highConfCount := 0
		for _, result := range psg.VariableRecovery.Results {
			totalConfidence += result.Confidence
			if result.Confidence >= 80 {
				highConfCount++
			}
		}

		stats.VariablesWithHighConf = highConfCount
		if stats.VariablesRecovered > 0 {
			stats.AverageVariableConfidence = totalConfidence / stats.VariablesRecovered
		}
	}

	if len(psg.MethodRecovery) > 0 {
		stats.MethodsRecovered = len(psg.MethodRecovery)

		totalConfidence := 0
		highConfCount := 0
		for _, result := range psg.MethodRecovery {
			totalConfidence += result.Confidence
			if result.Confidence >= 80 {
				highConfCount++
			}
		}

		stats.MethodsWithHighConf = highConfCount
		if stats.MethodsRecovered > 0 {
			stats.AverageMethodConfidence = totalConfidence / stats.MethodsRecovered
		}
	}

	stats.ConstantsRecovered = len(psg.ConstantPropagation)

	return stats
}

// calculateFormattingMetrics calculates formatting metrics.
func (psg *PrettySmaliGenerator) calculateFormattingMetrics(output *SmaliOutput) {
	lines := strings.Split(output.Code, "\n")
	output.FormattingMetrics.TotalLines = len(lines)

	commentLines := 0
	codeLines := 0
	maxIndent := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			commentLines++
		} else if len(trimmed) > 0 {
			codeLines++
		}

		// Calculate indentation
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent > maxIndent {
			maxIndent = indent
		}
	}

	output.FormattingMetrics.CommentLines = commentLines
	output.FormattingMetrics.CodeLines = codeLines
	output.FormattingMetrics.MaxIndentationLevel = maxIndent / len(psg.IndentString)

	if output.FormattingMetrics.TotalLines > 0 {
		output.FormattingMetrics.AverageIndentation = maxIndent / output.FormattingMetrics.TotalLines
	}
}

// FormatInstruction formats a single instruction with recovered names.
func (psg *PrettySmaliGenerator) FormatInstruction(insn *MIRInsn) string {
	var result strings.Builder

	// Add indentation
	for i := 0; i < psg.IndentLevel; i++ {
		result.WriteString(psg.IndentString)
	}

	// Format instruction based on kind
	result.WriteString(psg.formatInstructionKind(insn))

	// Add inline comments for recovered names
	if psg.VariableRecovery != nil && insn.Dst >= 0 {
		if recoveredName := psg.VariableRecovery.GetRecoveredName(int16(insn.Dst)); recoveredName != "" {
			confidence := psg.VariableRecovery.GetConfidence(int16(insn.Dst))
			if confidence >= psg.MinConfidenceThreshold {
				result.WriteString(fmt.Sprintf(" # v%d → %s (%d%%)", insn.Dst, recoveredName, confidence))
			}
		}
	}

	return result.String()
}

// formatInstructionKind formats the instruction kind.
func (psg *PrettySmaliGenerator) formatInstructionKind(insn *MIRInsn) string {
	switch insn.Kind {
	case MIR_MOVE:
		return fmt.Sprintf("move v%d, v%d", insn.Dst, insn.Src1)
	case MIR_CONST:
		if val, ok := psg.ConstantPropagation[insn.Dst]; ok {
			switch v := val.(type) {
			case string:
				return fmt.Sprintf("const-string v%d, %q", insn.Dst, v)
			case int, int32, int64:
				return fmt.Sprintf("const v%d, 0x%x", insn.Dst, v)
			}
		}
		if insn.DataType == TypeObject && insn.Imm == 0 {
			// Could be a null or a string constant index (simplified)
			return fmt.Sprintf("const v%d, 0x%x", insn.Dst, insn.Imm)
		}
		return fmt.Sprintf("const v%d, 0x%x", insn.Dst, insn.Imm)
	case MIR_ADD:
		return fmt.Sprintf("add v%d, v%d, v%d", insn.Dst, insn.Src1, insn.Src2)
	case MIR_SUB:
		return fmt.Sprintf("sub v%d, v%d, v%d", insn.Dst, insn.Src1, insn.Src2)
	case MIR_RSUB:
		if insn.Src2 < 0 {
			return fmt.Sprintf("rsub-int v%d, v%d, 0x%x", insn.Dst, insn.Src1, insn.Imm)
		}
		return fmt.Sprintf("rsub-int v%d, v%d, v%d", insn.Dst, insn.Src1, insn.Src2)
	case MIR_MUL:
		return fmt.Sprintf("mul v%d, v%d, v%d", insn.Dst, insn.Src1, insn.Src2)
	case MIR_DIV:
		return fmt.Sprintf("div v%d, v%d, v%d", insn.Dst, insn.Src1, insn.Src2)
	case MIR_IF:
		return fmt.Sprintf("if v%d, v%d (cond: %v)", insn.Src1, insn.Src2, insn.Cond)
	case MIR_GOTO:
		return fmt.Sprintf("goto 0x%x", insn.Imm)
	case MIR_RETURN:
		if insn.Src1 >= 0 {
			return fmt.Sprintf("return v%d", insn.Src1)
		}
		return "return"
	case MIR_INVOKE:
		return fmt.Sprintf("invoke v%d (method: 0x%x)", insn.Src1, insn.RefIdx)
	case MIR_FIELD_GET:
		return fmt.Sprintf("field-get v%d (field: 0x%x)", insn.Dst, insn.RefIdx)
	case MIR_FIELD_PUT:
		return fmt.Sprintf("field-put v%d (field: 0x%x)", insn.Src1, insn.RefIdx)
	case MIR_ARRAY_GET:
		return fmt.Sprintf("array-get v%d, v%d[v%d]", insn.Dst, insn.Src1, insn.Src2)
	case MIR_ARRAY_PUT:
		valReg := insn.Src3
		if valReg < 0 {
			valReg = insn.Src1
		}
		return fmt.Sprintf("array-put v%d, v%d[v%d]", valReg, insn.Src1, insn.Src2)
	case MIR_NEG:
		return fmt.Sprintf("neg v%d, v%d", insn.Dst, insn.Src1)
	case MIR_NOT:
		return fmt.Sprintf("not v%d, v%d", insn.Dst, insn.Src1)
	case MIR_CMPL:
		return fmt.Sprintf("cmpl v%d, v%d, v%d", insn.Dst, insn.Src1, insn.Src2)
	case MIR_CMPG:
		return fmt.Sprintf("cmpg v%d, v%d, v%d", insn.Dst, insn.Src1, insn.Src2)
	case MIR_XOR:
		if insn.Src2 == -1 {
			return fmt.Sprintf("xor-int/lit v%d, v%d, 0x%x", insn.Dst, insn.Src1, insn.Imm)
		}
		return fmt.Sprintf("xor-int v%d, v%d, v%d", insn.Dst, insn.Src1, insn.Src2)
	case MIR_AND:
		if insn.Src2 == -1 {
			return fmt.Sprintf("and-int/lit v%d, v%d, 0x%x", insn.Dst, insn.Src1, insn.Imm)
		}
		return fmt.Sprintf("and-int v%d, v%d, v%d", insn.Dst, insn.Src1, insn.Src2)
	case MIR_OR:
		if insn.Src2 == -1 {
			return fmt.Sprintf("or-int/lit v%d, v%d, 0x%x", insn.Dst, insn.Src1, insn.Imm)
		}
		return fmt.Sprintf("or-int v%d, v%d, v%d", insn.Dst, insn.Src1, insn.Src2)
	case MIR_NOP:
		return "nop"
	default:
		return fmt.Sprintf("unknown-op (kind: %v)", insn.Kind)
	}
}

// Indent increases the indentation level.
func (psg *PrettySmaliGenerator) Indent() {
	psg.IndentLevel++
}

// Dedent decreases the indentation level.
func (psg *PrettySmaliGenerator) Dedent() {
	if psg.IndentLevel > 0 {
		psg.IndentLevel--
	}
}

// GetIndentString returns the current indentation string.
func (psg *PrettySmaliGenerator) GetIndentString() string {
	var result strings.Builder
	for i := 0; i < psg.IndentLevel; i++ {
		result.WriteString(psg.IndentString)
	}
	return result.String()
}
