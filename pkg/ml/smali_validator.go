package ml

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI VALIDATOR
//
// Validates generated Smali bytecode for syntactic correctness.
// Ensures patches are valid before application to prevent APK rebuild failures.
//
// Requirements:
//   - 1.5: Validate Smali bytecode structure
//   - 1.6: Calculate minimum register requirements
// ═══════════════════════════════════════════════════════════════════════════════

// ValidationError represents a specific validation error
type ValidationError struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
	Code    string `json:"code"`
	Context string `json:"context,omitempty"`
}

// Error implements the error interface
func (ve ValidationError) Error() string {
	if ve.Line > 0 {
		return fmt.Sprintf("line %d: %s (%s)", ve.Line, ve.Message, ve.Code)
	}
	return fmt.Sprintf("%s (%s)", ve.Message, ve.Code)
}

// ValidationResult contains validation results
type ValidationResult struct {
	Valid    bool              `json:"valid"`
	Errors   []ValidationError `json:"errors"`
	Warnings []string          `json:"warnings"`
}

// Validation error codes
const (
	ErrInvalidSmali       = "INVALID_SMALI"
	ErrRegisterOverflow   = "REGISTER_OVERFLOW"
	ErrMissingEndMethod   = "MISSING_END_METHOD"
	ErrInvalidInstruction = "INVALID_INSTRUCTION"
	ErrControlFlowIssue   = "CONTROL_FLOW_ISSUE"
	ErrMissingMethodStart = "MISSING_METHOD_START"
	ErrInvalidRegister    = "INVALID_REGISTER"
	ErrInvalidReturn      = "INVALID_RETURN"
	ErrMissingLabel       = "MISSING_LABEL"
)

// OpcodeInfo contains information about a Smali opcode
type OpcodeInfo struct {
	Name         string
	MinRegisters int
	Format       string
}

// Package-level compiled regexes. Previously these were compiled with
// regexp.MustCompile INSIDE per-line helpers (extractUsedRegisters ran 2
// compilations per line of smali!). Hoisting them removes O(lines) regex
// compilations from every Validate call — measurable win on large methods,
// zero behavior change.
var (
	svRegistersRe = regexp.MustCompile(`\.registers\s+(\d+)`)
	svLocalsRe    = regexp.MustCompile(`\.locals\s+(\d+)`)
	svVRegRe      = regexp.MustCompile(`\bv(\d+)\b`)
	svPRegRe      = regexp.MustCompile(`\bp(\d+)\b`)
	svLabelRe     = regexp.MustCompile(`:[A-Za-z0-9_.$-]+`)
)

// SmaliValidator validates generated Smali bytecode
type SmaliValidator struct {
	opcodeTable map[string]OpcodeInfo
}

// NewSmaliValidator creates a new SmaliValidator
func NewSmaliValidator() *SmaliValidator {
	sv := &SmaliValidator{
		opcodeTable: make(map[string]OpcodeInfo),
	}
	sv.initOpcodeTable()
	return sv
}

// initOpcodeTable initializes the opcode lookup table
func (sv *SmaliValidator) initOpcodeTable() {
	// Common Dalvik opcodes with their register requirements
	opcodes := []OpcodeInfo{
		// Move operations
		{"move", 2, "12x"},
		{"move/from16", 2, "22x"},
		{"move/16", 2, "32x"},
		{"move-wide", 2, "12x"},
		{"move-object", 2, "12x"},

		// Const operations
		{"const/4", 1, "11n"},
		{"const/16", 1, "21s"},
		{"const", 1, "31i"},
		{"const/high16", 1, "21h"},
		{"const-wide/16", 1, "21s"},
		{"const-wide/32", 1, "31i"},
		{"const-wide", 1, "51l"},
		{"const-string", 1, "21c"},
		{"const-class", 1, "21c"},

		// Return operations
		{"return-void", 0, "10x"},
		{"return", 1, "11x"},
		{"return-wide", 1, "11x"},
		{"return-object", 1, "11x"},

		// Conditional branches
		{"if-eq", 2, "22t"},
		{"if-ne", 2, "22t"},
		{"if-lt", 2, "22t"},
		{"if-ge", 2, "22t"},
		{"if-gt", 2, "22t"},
		{"if-le", 2, "22t"},
		{"if-eqz", 1, "21t"},
		{"if-nez", 1, "21t"},
		{"if-ltz", 1, "21t"},
		{"if-gez", 1, "21t"},
		{"if-gtz", 1, "21t"},
		{"if-lez", 1, "21t"},

		// Goto operations
		{"goto", 0, "10t"},
		{"goto/16", 0, "20t"},
		{"goto/32", 0, "30t"},

		// Invoke operations
		{"invoke-virtual", 0, "35c"},
		{"invoke-super", 0, "35c"},
		{"invoke-direct", 0, "35c"},
		{"invoke-static", 0, "35c"},
		{"invoke-interface", 0, "35c"},

		// Nop
		{"nop", 0, "10x"},

		// Array operations
		{"aget", 3, "23x"},
		{"aget-wide", 3, "23x"},
		{"aget-object", 3, "23x"},
		{"aget-boolean", 3, "23x"},
		{"aget-byte", 3, "23x"},
		{"aget-char", 3, "23x"},
		{"aget-short", 3, "23x"},
		{"aput", 3, "23x"},
		{"aput-wide", 3, "23x"},
		{"aput-object", 3, "23x"},

		// Instance operations
		{"iget", 2, "22c"},
		{"iget-wide", 2, "22c"},
		{"iget-object", 2, "22c"},
		{"iget-boolean", 2, "22c"},
		{"iput", 2, "22c"},
		{"iput-wide", 2, "22c"},
		{"iput-object", 2, "22c"},
		{"iput-boolean", 2, "22c"},

		// Static operations
		{"sget", 1, "21c"},
		{"sget-wide", 1, "21c"},
		{"sget-object", 1, "21c"},
		{"sget-boolean", 1, "21c"},
		{"sput", 1, "21c"},
		{"sput-wide", 1, "21c"},
		{"sput-object", 1, "21c"},
		{"sput-boolean", 1, "21c"},

		// New operations
		{"new-instance", 1, "21c"},
		{"new-array", 2, "22c"},

		// ── Полный набор Dalvik/ART опкодов (ранее отсутствовали → валидный
		// smali помечался INVALID_INSTRUCTION, а опечатки проходили) ──

		// Move (расширенные)
		{"move-wide/from16", 2, "22x"},
		{"move-wide/16", 2, "32x"},
		{"move-object/from16", 2, "22x"},
		{"move-object/16", 2, "32x"},
		{"move-result", 1, "11x"},
		{"move-result-wide", 1, "11x"},
		{"move-result-object", 1, "11x"},
		{"move-exception", 1, "11x"},

		// Const (расширенные)
		{"const-wide/high16", 1, "21h"},
		{"const-string/jumbo", 1, "31c"},
		{"const-method-handle", 1, "21c"},
		{"const-method-type", 1, "21c"},

		// Monitor / throw
		{"monitor-enter", 1, "11x"},
		{"monitor-exit", 1, "11x"},
		{"throw", 1, "11x"},

		// Instance/static (полные семейства)
		{"iget-char", 2, "22c"},
		{"iget-short", 2, "22c"},
		{"iget-byte", 2, "22c"},
		{"iput-char", 2, "22c"},
		{"iput-short", 2, "22c"},
		{"iput-byte", 2, "22c"},
		{"sget-char", 1, "21c"},
		{"sget-short", 1, "21c"},
		{"sget-byte", 1, "21c"},
		{"sput-char", 1, "21c"},
		{"sput-short", 1, "21c"},
		{"sput-byte", 1, "21c"},

		// Arrays
		{"array-length", 2, "12x"},
		{"filled-new-array", 0, "35c"},
		{"filled-new-array/range", 0, "3rc"},
		{"fill-array-data", 1, "31t"},

		// Type ops
		{"check-cast", 1, "21c"},
		{"instance-of", 2, "22c"},

		// Switch
		{"packed-switch", 1, "31t"},
		{"sparse-switch", 1, "31t"},

		// Invoke (расширенные)
		{"invoke-virtual/range", 0, "3rc"},
		{"invoke-super/range", 0, "3rc"},
		{"invoke-direct/range", 0, "3rc"},
		{"invoke-static/range", 0, "3rc"},
		{"invoke-interface/range", 0, "3rc"},
		{"invoke-polymorphic", 0, "45cc"},
		{"invoke-polymorphic/range", 0, "4rcc"},
		{"invoke-custom", 0, "35c"},
		{"invoke-custom/range", 0, "3rc"},

		// Unary ops (12x)
		{"neg-int", 2, "12x"}, {"not-int", 2, "12x"},
		{"neg-long", 2, "12x"}, {"not-long", 2, "12x"},
		{"neg-float", 2, "12x"}, {"neg-double", 2, "12x"},
		{"int-to-long", 2, "12x"}, {"int-to-float", 2, "12x"}, {"int-to-double", 2, "12x"},
		{"long-to-int", 2, "12x"}, {"long-to-float", 2, "12x"}, {"long-to-double", 2, "12x"},
		{"float-to-int", 2, "12x"}, {"float-to-long", 2, "12x"}, {"float-to-double", 2, "12x"},
		{"double-to-int", 2, "12x"}, {"double-to-long", 2, "12x"}, {"double-to-float", 2, "12x"},
		{"int-to-byte", 2, "12x"}, {"int-to-char", 2, "12x"}, {"int-to-short", 2, "12x"},

		// Binary ops (23x)
		{"add-int", 3, "23x"}, {"sub-int", 3, "23x"}, {"mul-int", 3, "23x"},
		{"div-int", 3, "23x"}, {"rem-int", 3, "23x"}, {"and-int", 3, "23x"},
		{"or-int", 3, "23x"}, {"xor-int", 3, "23x"}, {"shl-int", 3, "23x"},
		{"shr-int", 3, "23x"}, {"ushr-int", 3, "23x"},
		{"add-long", 3, "23x"}, {"sub-long", 3, "23x"}, {"mul-long", 3, "23x"},
		{"div-long", 3, "23x"}, {"rem-long", 3, "23x"}, {"and-long", 3, "23x"},
		{"or-long", 3, "23x"}, {"xor-long", 3, "23x"}, {"shl-long", 3, "23x"},
		{"shr-long", 3, "23x"}, {"ushr-long", 3, "23x"},
		{"add-float", 3, "23x"}, {"sub-float", 3, "23x"}, {"mul-float", 3, "23x"},
		{"div-float", 3, "23x"}, {"rem-float", 3, "23x"},
		{"add-double", 3, "23x"}, {"sub-double", 3, "23x"}, {"mul-double", 3, "23x"},
		{"div-double", 3, "23x"}, {"rem-double", 3, "23x"},

		// Binary ops /2addr (12x)
		{"add-int/2addr", 2, "12x"}, {"sub-int/2addr", 2, "12x"}, {"mul-int/2addr", 2, "12x"},
		{"div-int/2addr", 2, "12x"}, {"rem-int/2addr", 2, "12x"}, {"and-int/2addr", 2, "12x"},
		{"or-int/2addr", 2, "12x"}, {"xor-int/2addr", 2, "12x"}, {"shl-int/2addr", 2, "12x"},
		{"shr-int/2addr", 2, "12x"}, {"ushr-int/2addr", 2, "12x"},
		{"add-long/2addr", 2, "12x"}, {"sub-long/2addr", 2, "12x"}, {"mul-long/2addr", 2, "12x"},
		{"div-long/2addr", 2, "12x"}, {"rem-long/2addr", 2, "12x"}, {"and-long/2addr", 2, "12x"},
		{"or-long/2addr", 2, "12x"}, {"xor-long/2addr", 2, "12x"}, {"shl-long/2addr", 2, "12x"},
		{"shr-long/2addr", 2, "12x"}, {"ushr-long/2addr", 2, "12x"},
		{"add-float/2addr", 2, "12x"}, {"sub-float/2addr", 2, "12x"}, {"mul-float/2addr", 2, "12x"},
		{"div-float/2addr", 2, "12x"}, {"rem-float/2addr", 2, "12x"},
		{"add-double/2addr", 2, "12x"}, {"sub-double/2addr", 2, "12x"}, {"mul-double/2addr", 2, "12x"},
		{"div-double/2addr", 2, "12x"}, {"rem-double/2addr", 2, "12x"},

		// Binary ops /lit16 и /lit8
		{"add-int/lit16", 2, "22s"}, {"rsub-int", 2, "22s"}, {"mul-int/lit16", 2, "22s"},
		{"div-int/lit16", 2, "22s"}, {"rem-int/lit16", 2, "22s"}, {"and-int/lit16", 2, "22s"},
		{"or-int/lit16", 2, "22s"}, {"xor-int/lit16", 2, "22s"},
		{"add-int/lit8", 2, "22b"}, {"rsub-int/lit8", 2, "22b"}, {"mul-int/lit8", 2, "22b"},
		{"div-int/lit8", 2, "22b"}, {"rem-int/lit8", 2, "22b"}, {"and-int/lit8", 2, "22b"},
		{"or-int/lit8", 2, "22b"}, {"xor-int/lit8", 2, "22b"}, {"shl-int/lit8", 2, "22b"},
		{"shr-int/lit8", 2, "22b"}, {"ushr-int/lit8", 2, "22b"},

		// Comparisons
		{"cmpl-float", 3, "23x"}, {"cmpg-float", 3, "23x"},
		{"cmpl-double", 3, "23x"}, {"cmpg-double", 3, "23x"}, {"cmp-long", 3, "23x"},
	}

	for _, op := range opcodes {
		sv.opcodeTable[op.Name] = op
	}
}

// Validate validates Smali bytecode
func (sv *SmaliValidator) Validate(smaliCode string) ValidationResult {
	result := ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []string{},
	}

	if smaliCode == "" {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Message: "Empty Smali code",
			Code:    ErrInvalidSmali,
		})
		return result
	}

	lines := validationLines(smaliCode)

	// 1. Check method header/footer pairing
	if !sv.checkMethodPairing(lines) {
		result.Valid = false
		result.Errors = append(result.Errors, ValidationError{
			Message: "Missing .end method or .method directive",
			Code:    ErrMissingEndMethod,
		})
	}

	// 2. Validate register usage
	maxReg := sv.extractRegisterCount(lines)
	if maxReg == 16 && !sv.hasRegisterDirective(lines) {
		result.Warnings = append(result.Warnings, "Missing .registers/.locals directive; default register budget assumed")
	}
	for i, line := range lines {
		regs := sv.extractUsedRegisters(line)
		for _, reg := range regs {
			if reg >= maxReg {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Line:    i + 1,
					Message: fmt.Sprintf("Register v%d exceeds .registers %d", reg, maxReg),
					Code:    ErrRegisterOverflow,
					Context: strings.TrimSpace(line),
				})
			}
		}
	}

	// 2b. Validate p-register usage against actual parameter count.
	// pN is an ALIAS for v(maxReg-paramRegs+N): using pN with N >= paramRegs
	// silently addresses a local register or falls out of budget — the #1
	// cause of "patch applied, app crashes at runtime".
	if paramRegs, ok := sv.methodParamRegisters(lines); ok {
		for i, line := range lines {
			for _, m := range svPRegRe.FindAllStringSubmatch(smaliRegisterOperands(line), -1) {
				var n int
				fmt.Sscanf(m[1], "%d", &n)
				if n >= paramRegs {
					result.Valid = false
					result.Errors = append(result.Errors, ValidationError{
						Line:    i + 1,
						Message: fmt.Sprintf("Register p%d exceeds parameter register count %d", n, paramRegs),
						Code:    ErrInvalidRegister,
						Context: strings.TrimSpace(line),
					})
				}
			}
		}
	}

	// 2c. Validate formats where every register operand is encoded in 4 bits.
	// Formats such as 11x, 21x, 22x and 22b have wider register fields and
	// must not reject v16+ merely because another format uses four-bit fields.
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !sv.isInstruction(trimmed) {
			continue
		}
		op := sv.opcodeTable[strings.Fields(trimmed)[0]]
		if !isNarrowFormat(op.Format) {
			continue
		}
		for _, m := range svVRegRe.FindAllStringSubmatch(smaliRegisterOperands(trimmed), -1) {
			var n int
			fmt.Sscanf(m[1], "%d", &n)
			if n > 15 {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Line:    i + 1,
					Message: fmt.Sprintf("Register v%d does not fit 4-bit format %s of %s (use /from16 or /16 variant)", n, op.Format, op.Name),
					Code:    ErrRegisterOverflow,
					Context: trimmed,
				})
			}
		}
	}

	// 2d. Validate 8-bit register fields: most Dalvik formats encode the
	// first register in 8 bits (v0-v255). Only /16, /range, /jumbo, 32x and
	// 51l variants address v256+. A v300 in `const/16 v300` is NOT assembled
	// by apktool — catch it here instead of shipping a crashing patch.
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !sv.isInstruction(trimmed) {
			continue
		}
		opName := strings.Fields(trimmed)[0]
		if allowsWideRegister(opName) {
			continue
		}
		for _, m := range svVRegRe.FindAllStringSubmatch(smaliRegisterOperands(trimmed), -1) {
			var n int
			fmt.Sscanf(m[1], "%d", &n)
			if n > 255 {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Line:    i + 1,
					Message: fmt.Sprintf("Register v%d does not fit 8-bit field of %s (use /16 or /range variant)", n, opName),
					Code:    ErrRegisterOverflow,
					Context: trimmed,
				})
			}
		}
	}

	// 2e. Validate const literal widths: const/4 holds -8..7, const/16 holds
	// -32768..32767, const/high16 requires low 16 bits zero. An out-of-range
	// literal assembles to a DIFFERENT value or fails — never silently pass.
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !sv.isInstruction(trimmed) {
			continue
		}
		fields := strings.Fields(trimmed)
		opName := fields[0]
		if opName != "const/4" && opName != "const/16" && opName != "const/high16" && opName != "const-wide/16" {
			continue
		}
		litStr := fields[len(fields)-1]
		lit, ok := parseSmaliLiteral(litStr)
		if !ok {
			continue // не парсится — не наша проверка (синтаксис ловит isInstruction)
		}
		bad := false
		switch opName {
		case "const/4":
			bad = lit < -8 || lit > 7
		case "const/16", "const-wide/16":
			bad = lit < -32768 || lit > 32767
		case "const/high16":
			bad = (lit & 0xFFFF) != 0
		}
		if bad {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Line:    i + 1,
				Message: fmt.Sprintf("Literal %s does not fit %s width", litStr, opName),
				Code:    ErrInvalidInstruction,
				Context: trimmed,
			})
		}
	}
	// 3. Validate instruction syntax
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if sv.isInstruction(trimmed) {
			if !sv.validateInstruction(trimmed) {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Line:    i + 1,
					Message: "Invalid instruction syntax",
					Code:    ErrInvalidInstruction,
					Context: trimmed,
				})
			}
		}
	}

	// 4. Check control flow
	if !sv.validateControlFlow(lines) {
		result.Warnings = append(result.Warnings,
			"Potential control flow issue detected")
	}

	if err := sv.validateReturnType(lines); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, *err)
	}
	if missing := sv.missingBranchLabels(lines); len(missing) > 0 {
		result.Valid = false
		for _, label := range missing {
			result.Errors = append(result.Errors, ValidationError{
				Message: "Branch target label is not defined",
				Code:    ErrMissingLabel,
				Context: label,
			})
		}
	}
	if sv.hasTryCatch(lines) {
		result.Warnings = append(result.Warnings, "Patch touches a method with try/catch metadata; manual review required before writing")
	}

	return result
}

// checkMethodPairing checks if .method and .end method are properly paired
func (sv *SmaliValidator) checkMethodPairing(lines []string) bool {
	hasMethodStart := false
	hasMethodEnd := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ".method ") {
			hasMethodStart = true
		}
		if trimmed == ".end method" {
			hasMethodEnd = true
		}
	}

	return hasMethodStart && hasMethodEnd
}

// extractRegisterCount extracts the TOTAL register budget of a method.
// For `.registers N` this is N directly. For `.locals N` the total budget
// is N + paramRegs (because p-registers alias v[N]..v[N+paramRegs-1]).
// Without either directive, 16 is assumed.
func (sv *SmaliValidator) extractRegisterCount(lines []string) int {
	for _, line := range lines {
		matches := svRegistersRe.FindStringSubmatch(line)
		if len(matches) > 1 {
			var count int
			fmt.Sscanf(matches[1], "%d", &count)
			return count
		}
		matches = svLocalsRe.FindStringSubmatch(line)
		if len(matches) > 1 {
			var count int
			fmt.Sscanf(matches[1], "%d", &count)
			// .locals N means N local registers (v0..v(N-1)); the actual budget
			// is N + paramRegs because pN aliases v(N+paramIdx).
			if paramRegs, ok := sv.methodParamRegisters(lines); ok {
				return count + paramRegs
			}
			return count
		}
	}

	// Default to a reasonable number if not found
	return 16
}

func (sv *SmaliValidator) hasRegisterDirective(lines []string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ".registers ") || strings.HasPrefix(trimmed, ".locals ") {
			return true
		}
	}
	return false
}

// extractUsedRegisters extracts register numbers used in an instruction
func (sv *SmaliValidator) extractUsedRegisters(line string) []int {
	registers := []int{}

	// Extract v registers
	vMatches := svVRegRe.FindAllStringSubmatch(smaliRegisterOperands(line), -1)
	for _, match := range vMatches {
		if len(match) > 1 {
			var regNum int
			fmt.Sscanf(match[1], "%d", &regNum)
			registers = append(registers, regNum)
		}
	}

	// p-регистры здесь НЕ проверяются: их валидность зависит от сигнатуры
	// метода и теперь строго проверяется в Validate (шаг 2b) через
	// methodParamRegisters. Старый хак «pN>15 → invalid» был неверен для
	// методов с >16 параметрами и дублировал работу.

	return registers
}

// isInstruction checks if a line is a Smali instruction
func (sv *SmaliValidator) isInstruction(line string) bool {
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ".") {
		return false
	}

	// Check if it starts with a known opcode
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return false
	}

	opcode := parts[0]
	_, exists := sv.opcodeTable[opcode]
	return exists
}

// validateInstruction validates a single instruction
func (sv *SmaliValidator) validateInstruction(line string) bool {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return false
	}

	opcode := parts[0]

	// Check if opcode exists
	opcodeInfo, exists := sv.opcodeTable[opcode]
	if !exists {
		// Unknown opcode, but might be valid - don't fail
		return true
	}

	// Basic validation: check if we have enough operands
	// This is a simplified check - real validation would be more complex
	operands := parts[1:]

	// For most instructions, we just check that operands exist
	if opcodeInfo.MinRegisters > 0 && len(operands) == 0 {
		return false
	}

	return true
}

// validateControlFlow performs basic control flow validation
func (sv *SmaliValidator) validateControlFlow(lines []string) bool {
	hasReturn := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "return") {
			hasReturn = true
			break
		}
	}

	// A method should have at least one return statement
	return hasReturn
}

func (sv *SmaliValidator) validateReturnType(lines []string) *ValidationError {
	returnType := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ".method ") {
			if idx := strings.LastIndex(trimmed, ")"); idx != -1 && idx+1 < len(trimmed) {
				returnType = trimmed[idx+1:]
			}
			break
		}
	}
	if returnType == "" {
		return nil
	}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "return") {
			continue
		}
		opcode := strings.Fields(trimmed)[0]
		if isReturnOpcodeCompatible(opcode, returnType) {
			continue
		}
		return &ValidationError{
			Line:    i + 1,
			Message: fmt.Sprintf("Return opcode %s is incompatible with method return type %s", opcode, returnType),
			Code:    ErrInvalidReturn,
			Context: trimmed,
		}
	}
	return nil
}

func isReturnOpcodeCompatible(opcode, returnType string) bool {
	switch {
	case returnType == "V":
		return opcode == "return-void"
	case returnType == "J" || returnType == "D":
		return opcode == "return-wide"
	case strings.HasPrefix(returnType, "L") || strings.HasPrefix(returnType, "["):
		return opcode == "return-object"
	default:
		return opcode == "return"
	}
}

func (sv *SmaliValidator) missingBranchLabels(lines []string) []string {
	defined := make(map[string]struct{})
	used := make(map[string]struct{})
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ":") {
			defined[strings.Fields(trimmed)[0]] = struct{}{}
			continue
		}
		if strings.HasPrefix(trimmed, "if-") || strings.HasPrefix(trimmed, "goto") || strings.HasPrefix(trimmed, ".catch") {
			for _, label := range svLabelRe.FindAllString(trimmed, -1) {
				used[label] = struct{}{}
			}
		}
	}
	missing := make([]string, 0)
	for label := range used {
		if _, ok := defined[label]; !ok {
			missing = append(missing, label)
		}
	}
	return missing
}

func (sv *SmaliValidator) hasTryCatch(lines []string) bool {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, ".catch") || strings.HasPrefix(trimmed, ":try_start") || strings.HasPrefix(trimmed, ":try_end") {
			return true
		}
	}
	return false
}

// CalculateMinRegisters calculates minimum required registers for a patch type
func (sv *SmaliValidator) CalculateMinRegisters(patchType PatchType, isStatic bool) int {
	baseRegs := 0
	if !isStatic {
		baseRegs = 1 // p0 for instance methods (this pointer)
	}

	switch patchType {
	case PatchReturnTrue, PatchReturnFalse:
		// Need v0 for const/4 instruction
		return baseRegs + 1

	case PatchReturnMaxInt, PatchReturnZero:
		// Need v0 for const instruction
		return baseRegs + 1

	case PatchReturnVoid:
		// No registers needed for return-void
		return baseRegs

	case PatchNop:
		// Nop doesn't need registers
		return baseRegs

	case PatchRemoveCheck:
		// Depends on what we're doing, conservative estimate
		return baseRegs + 2

	default:
		// Conservative estimate for unknown patch types
		return baseRegs + 2
	}
}

// isNarrowFormat reports whether every register operand in an instruction
// format is encoded in four bits (v0–v15 only). Formats with mixed or wider
// fields are deliberately excluded because they require operand-position-aware
// validation rather than a blanket v16+ rejection.
func isNarrowFormat(format string) bool {
	switch format {
	// These formats encode every register operand in a four-bit nibble.
	case "11n", "12x", "22c", "22s", "22t":
		return true
	}
	return false
}

// parseSmaliLiteral разбирает smali-литерал (деcятичный, hex 0x, отрицательный).
// strconv.ParseInt с base=0 понимает и "42", и "0x8", и "-0x1" — в отличие от
// fmt.Sscanf("%d"), который на "0x8" молча парсит "0" и пропускает битые ширины.
func parseSmaliLiteral(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	// Суффикс L у wide-литералов (0x7fffL) — отрезаем.
	s = strings.TrimSuffix(strings.TrimSuffix(s, "L"), "l")
	n, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Mixed-width moves need operand-position-aware checking in ValidateStrict.
func allowsWideRegister(opcode string) bool {
	return strings.HasSuffix(opcode, "/range") ||
		(strings.HasPrefix(opcode, "move") &&
			(strings.HasSuffix(opcode, "/16") || strings.HasSuffix(opcode, "/from16")))
}

// methodParamRegisters extracts the parameter register count from the .method
// header using the package-level countParamRegisters (descriptor-aware:
// wide types count as 2, implicit `this` as 1 for instance methods).
func (sv *SmaliValidator) methodParamRegisters(lines []string) (int, bool) {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, ".method ") {
			continue
		}
		isStatic := strings.Contains(" "+strings.ToLower(trimmed)+" ", " static ")
		sig := ""
		if m := lintDescRe.FindStringSubmatch(trimmed); len(m) > 1 {
			sig = m[1]
		}
		if sig == "" {
			return 0, false
		}
		return countParamRegisters(sig, isStatic), true
	}
	return 0, false
}
