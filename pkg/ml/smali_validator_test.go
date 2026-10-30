package ml

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI VALIDATOR TESTS
//
// Tests for SmaliValidator validation methods and register calculation.
//
// Requirements:
//   - 1.5: Validate Smali bytecode structure
//   - 1.6: Calculate minimum register requirements
// ═══════════════════════════════════════════════════════════════════════════════

func TestSmaliValidator_ValidateValidCode(t *testing.T) {
	validator := NewSmaliValidator()

	validCode := `.method public isRooted()Z
    .registers 2

    const/4 v0, 0x1
    return v0
.end method`

	result := validator.Validate(validCode)

	if !result.Valid {
		t.Errorf("Expected valid code to pass validation, got errors: %v", result.Errors)
	}

	if len(result.Errors) > 0 {
		t.Errorf("Expected no errors, got %d errors", len(result.Errors))
	}
}

func TestSmaliValidator_ValidateEmptyCode(t *testing.T) {
	validator := NewSmaliValidator()

	result := validator.Validate("")

	if result.Valid {
		t.Error("Expected empty code to fail validation")
	}

	if len(result.Errors) == 0 {
		t.Error("Expected errors for empty code")
	}

	if result.Errors[0].Code != ErrInvalidSmali {
		t.Errorf("Expected error code %s, got %s", ErrInvalidSmali, result.Errors[0].Code)
	}
}

func TestSmaliValidator_ValidateMissingEndMethod(t *testing.T) {
	validator := NewSmaliValidator()

	invalidCode := `.method public isRooted()Z
    .registers 2

    const/4 v0, 0x1
    return v0`

	result := validator.Validate(invalidCode)

	if result.Valid {
		t.Error("Expected code without .end method to fail validation")
	}

	foundError := false
	for _, err := range result.Errors {
		if err.Code == ErrMissingEndMethod {
			foundError = true
			break
		}
	}

	if !foundError {
		t.Errorf("Expected error code %s, got errors: %v", ErrMissingEndMethod, result.Errors)
	}
}

func TestSmaliValidator_ValidateMissingMethodStart(t *testing.T) {
	validator := NewSmaliValidator()

	invalidCode := `    .registers 2

    const/4 v0, 0x1
    return v0
.end method`

	result := validator.Validate(invalidCode)

	if result.Valid {
		t.Error("Expected code without .method to fail validation")
	}
}

func TestSmaliValidator_ValidateRegisterOverflow(t *testing.T) {
	validator := NewSmaliValidator()

	invalidCode := `.method public isRooted()Z
    .registers 2

    const/4 v5, 0x1
    return v5
.end method`

	result := validator.Validate(invalidCode)

	if result.Valid {
		t.Error("Expected code with register overflow to fail validation")
	}

	foundError := false
	for _, err := range result.Errors {
		if err.Code == ErrRegisterOverflow {
			foundError = true
			if !strings.Contains(err.Message, "v5") {
				t.Errorf("Expected error message to mention v5, got: %s", err.Message)
			}
			break
		}
	}

	if !foundError {
		t.Errorf("Expected error code %s, got errors: %v", ErrRegisterOverflow, result.Errors)
	}
}

func TestSmaliValidator_ValidateMultipleRegisters(t *testing.T) {
	validator := NewSmaliValidator()

	validCode := `.method public checkPremium()Z
    .registers 3

    const/4 v0, 0x1
    const/4 v1, 0x0
    if-eq v0, v1, :cond_0
    
    :cond_0
    return v0
.end method`

	result := validator.Validate(validCode)

	if !result.Valid {
		t.Errorf("Expected valid code with multiple registers to pass, got errors: %v", result.Errors)
	}
}

func TestSmaliValidator_ValidateReturnVoid(t *testing.T) {
	validator := NewSmaliValidator()

	validCode := `.method public doSomething()V
    .registers 1

    return-void
.end method`

	result := validator.Validate(validCode)

	if !result.Valid {
		t.Errorf("Expected valid return-void code to pass, got errors: %v", result.Errors)
	}
}

func TestSmaliValidator_ValidateWithComments(t *testing.T) {
	validator := NewSmaliValidator()

	validCode := `.method public isRooted()Z
    .registers 2

    # Check for root
    const/4 v0, 0x1
    # Return true
    return v0
.end method`

	result := validator.Validate(validCode)

	if !result.Valid {
		t.Errorf("Expected valid code with comments to pass, got errors: %v", result.Errors)
	}
}

func TestSmaliValidator_ValidateComplexMethod(t *testing.T) {
	validator := NewSmaliValidator()

	validCode := `.method public isPremium()Z
    .registers 4

    const/4 v0, 0x0
    const/4 v1, 0x1
    
    invoke-virtual {p0}, Lcom/example/App;->getStatus()I
    move-result v2
    
    if-eqz v2, :cond_false
    
    const/4 v0, 0x1
    
    :cond_false
    return v0
.end method`

	result := validator.Validate(validCode)

	if !result.Valid {
		t.Errorf("Expected valid complex method to pass, got errors: %v", result.Errors)
	}
}

func TestSmaliValidator_CalculateMinRegisters_ReturnTrue_Static(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchReturnTrue, true)

	expected := 1 // v0 only
	if minRegs != expected {
		t.Errorf("Expected %d registers for static return_true, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_CalculateMinRegisters_ReturnTrue_Instance(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchReturnTrue, false)

	expected := 2 // p0 + v0
	if minRegs != expected {
		t.Errorf("Expected %d registers for instance return_true, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_CalculateMinRegisters_ReturnFalse_Static(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchReturnFalse, true)

	expected := 1 // v0 only
	if minRegs != expected {
		t.Errorf("Expected %d registers for static return_false, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_CalculateMinRegisters_ReturnFalse_Instance(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchReturnFalse, false)

	expected := 2 // p0 + v0
	if minRegs != expected {
		t.Errorf("Expected %d registers for instance return_false, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_CalculateMinRegisters_ReturnVoid_Static(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchReturnVoid, true)

	expected := 0 // No registers needed
	if minRegs != expected {
		t.Errorf("Expected %d registers for static return_void, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_CalculateMinRegisters_ReturnVoid_Instance(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchReturnVoid, false)

	expected := 1 // p0 only
	if minRegs != expected {
		t.Errorf("Expected %d registers for instance return_void, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_CalculateMinRegisters_ReturnZero_Static(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchReturnMaxInt, true)

	expected := 1 // v0 only
	if minRegs != expected {
		t.Errorf("Expected %d registers for static return_zero, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_CalculateMinRegisters_ReturnZero_Instance(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchReturnMaxInt, false)

	expected := 2 // p0 + v0
	if minRegs != expected {
		t.Errorf("Expected %d registers for instance return_zero, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_CalculateMinRegisters_Nop_Static(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchNop, true)

	expected := 0 // No registers needed
	if minRegs != expected {
		t.Errorf("Expected %d registers for static nop, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_CalculateMinRegisters_Nop_Instance(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchNop, false)

	expected := 1 // p0 only
	if minRegs != expected {
		t.Errorf("Expected %d registers for instance nop, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_CalculateMinRegisters_RemoveCheck_Static(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchRemoveCheck, true)

	expected := 2 // Conservative estimate
	if minRegs != expected {
		t.Errorf("Expected %d registers for static remove_check, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_CalculateMinRegisters_RemoveCheck_Instance(t *testing.T) {
	validator := NewSmaliValidator()

	minRegs := validator.CalculateMinRegisters(PatchRemoveCheck, false)

	expected := 3 // p0 + conservative estimate
	if minRegs != expected {
		t.Errorf("Expected %d registers for instance remove_check, got %d", expected, minRegs)
	}
}

func TestSmaliValidator_ExtractRegisterCount(t *testing.T) {
	validator := NewSmaliValidator()

	tests := []struct {
		name     string
		code     string
		expected int
	}{
		{
			name: "registers 2",
			code: `.method public test()V
    .registers 2
    return-void
.end method`,
			expected: 2,
		},
		{
			name: "registers 5",
			code: `.method public test()V
    .registers 5
    return-void
.end method`,
			expected: 5,
		},
		{
			name: "no registers directive",
			code: `.method public test()V
    return-void
.end method`,
			expected: 16, // Default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := strings.Split(tt.code, "\n")
			count := validator.extractRegisterCount(lines)
			if count != tt.expected {
				t.Errorf("Expected %d registers, got %d", tt.expected, count)
			}
		})
	}
}

func TestSmaliValidator_ExtractUsedRegisters(t *testing.T) {
	validator := NewSmaliValidator()

	tests := []struct {
		name     string
		line     string
		expected []int
	}{
		{
			name:     "single v register",
			line:     "const/4 v0, 0x1",
			expected: []int{0},
		},
		{
			name:     "multiple v registers",
			line:     "if-eq v0, v1, :cond_0",
			expected: []int{0, 1},
		},
		{
			name:     "no registers",
			line:     "return-void",
			expected: []int{},
		},
		{
			name:     "p register",
			line:     "invoke-virtual {p0}, Lcom/example/Test;->method()V",
			expected: []int{},
		},
		{
			name:     "mixed v and p registers",
			line:     "invoke-virtual {p0, v0}, Lcom/example/Test;->method(I)V",
			expected: []int{0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regs := validator.extractUsedRegisters(tt.line)
			if len(regs) != len(tt.expected) {
				t.Errorf("Expected %d registers, got %d: %v", len(tt.expected), len(regs), regs)
				return
			}
			for i, reg := range regs {
				if reg != tt.expected[i] {
					t.Errorf("Expected register v%d at position %d, got v%d", tt.expected[i], i, reg)
				}
			}
		})
	}
}

func TestSmaliValidator_IsInstruction(t *testing.T) {
	validator := NewSmaliValidator()

	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{
			name:     "const instruction",
			line:     "const/4 v0, 0x1",
			expected: true,
		},
		{
			name:     "return instruction",
			line:     "return v0",
			expected: true,
		},
		{
			name:     "comment",
			line:     "# This is a comment",
			expected: false,
		},
		{
			name:     "directive",
			line:     ".registers 2",
			expected: false,
		},
		{
			name:     "empty line",
			line:     "",
			expected: false,
		},
		{
			name:     "label",
			line:     ":cond_0",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.isInstruction(tt.line)
			if result != tt.expected {
				t.Errorf("Expected isInstruction(%q) = %v, got %v", tt.line, tt.expected, result)
			}
		})
	}
}

func TestSmaliValidator_ValidateInstruction(t *testing.T) {
	validator := NewSmaliValidator()

	tests := []struct {
		name     string
		line     string
		expected bool
	}{
		{
			name:     "valid const",
			line:     "const/4 v0, 0x1",
			expected: true,
		},
		{
			name:     "valid return",
			line:     "return v0",
			expected: true,
		},
		{
			name:     "valid if-eq",
			line:     "if-eq v0, v1, :cond_0",
			expected: true,
		},
		{
			name:     "valid invoke",
			line:     "invoke-virtual {p0}, Lcom/example/Test;->method()V",
			expected: true,
		},
		{
			name:     "unknown opcode",
			line:     "unknown-opcode v0",
			expected: true, // We don't fail on unknown opcodes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.validateInstruction(tt.line)
			if result != tt.expected {
				t.Errorf("Expected validateInstruction(%q) = %v, got %v", tt.line, tt.expected, result)
			}
		})
	}
}

func TestSmaliValidator_ValidateControlFlow(t *testing.T) {
	validator := NewSmaliValidator()

	tests := []struct {
		name     string
		code     string
		expected bool
	}{
		{
			name: "has return",
			code: `.method public test()V
    return-void
.end method`,
			expected: true,
		},
		{
			name: "has return v0",
			code: `.method public test()Z
    const/4 v0, 0x1
    return v0
.end method`,
			expected: true,
		},
		{
			name: "no return",
			code: `.method public test()V
    const/4 v0, 0x1
.end method`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lines := strings.Split(tt.code, "\n")
			result := validator.validateControlFlow(lines)
			if result != tt.expected {
				t.Errorf("Expected validateControlFlow = %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestSmaliValidator_ReturnTypeCompatibility(t *testing.T) {
	validator := NewSmaliValidator()
	invalid := `.method public name()Ljava/lang/String;
    .registers 1
    const/4 v0, 0x0
    return v0
.end method`

	result := validator.Validate(invalid)
	if result.Valid {
		t.Fatal("expected invalid return opcode for object return")
	}
	if len(result.Errors) == 0 || result.Errors[0].Code != ErrInvalidReturn {
		t.Fatalf("expected ErrInvalidReturn, got %+v", result.Errors)
	}

	valid := `.method public name()Ljava/lang/String;
    .registers 1
    const/4 v0, 0x0
    return-object v0
.end method`
	if result := validator.Validate(valid); !result.Valid {
		t.Fatalf("expected valid object return, got %+v", result.Errors)
	}
}

func TestSmaliValidator_LocalsLabelsAndTryCatchWarning(t *testing.T) {
	validator := NewSmaliValidator()
	code := `.method public check()Z
    .locals 1
    :try_start_0
    const/4 v0, 0x1
    goto :done
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :done
    :done
    return v0
.end method`

	result := validator.Validate(code)
	if !result.Valid {
		t.Fatalf("expected valid method, got %+v", result.Errors)
	}
	found := false
	for _, warning := range result.Warnings {
		if strings.Contains(warning, "try/catch") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected try/catch warning, got %+v", result.Warnings)
	}
}

func TestSmaliValidator_MissingBranchLabel(t *testing.T) {
	validator := NewSmaliValidator()
	code := `.method public check()Z
    .registers 1
    goto :missing
    const/4 v0, 0x1
    return v0
.end method`

	result := validator.Validate(code)
	if result.Valid {
		t.Fatal("expected missing label to invalidate method")
	}
	found := false
	for _, err := range result.Errors {
		if err.Code == ErrMissingLabel {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ErrMissingLabel, got %+v", result.Errors)
	}
}

func TestValidationError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      ValidationError
		expected string
	}{
		{
			name: "with line number",
			err: ValidationError{
				Line:    5,
				Message: "Register overflow",
				Code:    ErrRegisterOverflow,
			},
			expected: "line 5: Register overflow (REGISTER_OVERFLOW)",
		},
		{
			name: "without line number",
			err: ValidationError{
				Message: "Missing end method",
				Code:    ErrMissingEndMethod,
			},
			expected: "Missing end method (MISSING_END_METHOD)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Expected error string %q, got %q", tt.expected, result)
			}
		})
	}
}

// Benchmark tests
func BenchmarkSmaliValidator_Validate(b *testing.B) {
	validator := NewSmaliValidator()

	code := `.method public isRooted()Z
    .registers 2

    const/4 v0, 0x1
    return v0
.end method`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.Validate(code)
	}
}

func BenchmarkSmaliValidator_CalculateMinRegisters(b *testing.B) {
	validator := NewSmaliValidator()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.CalculateMinRegisters(PatchReturnTrue, false)
	}
}
