package apkloader

import (
	"strings"
	"testing"
)

// TestPseudocodeGeneratorBasic tests basic pseudocode generation.
func TestPseudocodeGeneratorBasic(t *testing.T) {
	// Create a simple CFG with one block
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 1),
	}

	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind:     MIR_CONST,
				Dst:      0,
				Imm:      42,
				DataType: TypeInt,
			},
		},
	}
	cfg.Blocks[0] = block
	cfg.Entry = block

	// Create SSA form
	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 1),
		VarByID:   make(map[int16]*SSAVariable),
	}

	variable := &SSAVariable{
		ID:           0,
		OrigRegister: 0,
		Definitions:  make([]SSADef, 0),
		Uses:         make([]SSAUse, 0),
	}
	ssa.Variables[0] = variable
	ssa.VarByID[0] = variable

	// Create method signature
	methodSig := &MethodSignature{
		ClassName:      "TestClass",
		MethodName:     "testMethod",
		ReturnType:     TypeInfo{BaseType: "void"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
		IsStatic:       false,
	}

	// Create generator
	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)

	// Generate pseudocode
	pseudocode := gen.Generate()

	// Verify output
	if !strings.Contains(pseudocode, "testMethod") {
		t.Errorf("Expected method name in pseudocode, got: %s", pseudocode)
	}

	if !strings.Contains(pseudocode, "v0 = 42") {
		t.Errorf("Expected const assignment in pseudocode, got: %s", pseudocode)
	}
}

// TestPseudocodeGeneratorMethodSignature tests method signature generation.
func TestPseudocodeGeneratorMethodSignature(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 0)}
	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 0),
		VarByID:   make(map[int16]*SSAVariable),
	}

	methodSig := &MethodSignature{
		ClassName:  "TestClass",
		MethodName: "calculate",
		ReturnType: TypeInfo{BaseType: "int"},
		ParameterTypes: []TypeInfo{
			{BaseType: "int"},
			{BaseType: "String"},
		},
		ParameterNames: []string{"x", "name"},
		IsStatic:       true,
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	pseudocode := gen.Generate()

	if !strings.Contains(pseudocode, "static") {
		t.Errorf("Expected 'static' modifier in pseudocode")
	}

	if !strings.Contains(pseudocode, "int calculate") {
		t.Errorf("Expected return type and method name in pseudocode")
	}

	if !strings.Contains(pseudocode, "int x") {
		t.Errorf("Expected parameter 'int x' in pseudocode")
	}

	if !strings.Contains(pseudocode, "String name") {
		t.Errorf("Expected parameter 'String name' in pseudocode")
	}
}

// TestPseudocodeGeneratorArithmeticOperations tests arithmetic operation generation.
func TestPseudocodeGeneratorArithmeticOperations(t *testing.T) {
	tests := []struct {
		name     string
		kind     MIROpKind
		expected string
	}{
		{"add", MIR_ADD, "+"},
		{"sub", MIR_SUB, "-"},
		{"mul", MIR_MUL, "*"},
		{"div", MIR_DIV, "/"},
		{"rem", MIR_REM, "%"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
			block := &BasicBlock{
				ID:    0,
				Start: 0,
				End:   1,
				Insns: []MIRInsn{
					{
						Kind:     tt.kind,
						Dst:      0,
						Src1:     1,
						Src2:     2,
						DataType: TypeInt,
					},
				},
			}
			cfg.Blocks[0] = block
			cfg.Entry = block

			ssa := &SSAForm{
				CFG:       cfg,
				Variables: make([]*SSAVariable, 3),
				VarByID:   make(map[int16]*SSAVariable),
			}

			for i := 0; i < 3; i++ {
				v := &SSAVariable{ID: int16(i), OrigRegister: int16(i)}
				ssa.Variables[i] = v
				ssa.VarByID[int16(i)] = v
			}

			methodSig := &MethodSignature{
				ClassName:      "Test",
				MethodName:     "test",
				ReturnType:     TypeInfo{BaseType: "void"},
				ParameterTypes: make([]TypeInfo, 0),
				ParameterNames: make([]string, 0),
			}

			gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
			pseudocode := gen.Generate()

			if !strings.Contains(pseudocode, tt.expected) {
				t.Errorf("Expected operator '%s' in pseudocode, got: %s", tt.expected, pseudocode)
			}
		})
	}
}

// TestPseudocodeGeneratorBitwiseOperations tests bitwise operation generation.
func TestPseudocodeGeneratorBitwiseOperations(t *testing.T) {
	tests := []struct {
		name     string
		kind     MIROpKind
		expected string
	}{
		{"and", MIR_AND, "&"},
		{"or", MIR_OR, "|"},
		{"xor", MIR_XOR, "^"},
		{"shl", MIR_SHL, "<<"},
		{"shr", MIR_SHR, ">>"},
		{"ushr", MIR_USHR, ">>>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
			block := &BasicBlock{
				ID:    0,
				Start: 0,
				End:   1,
				Insns: []MIRInsn{
					{
						Kind:     tt.kind,
						Dst:      0,
						Src1:     1,
						Src2:     2,
						DataType: TypeInt,
					},
				},
			}
			cfg.Blocks[0] = block
			cfg.Entry = block

			ssa := &SSAForm{
				CFG:       cfg,
				Variables: make([]*SSAVariable, 3),
				VarByID:   make(map[int16]*SSAVariable),
			}

			for i := 0; i < 3; i++ {
				v := &SSAVariable{ID: int16(i), OrigRegister: int16(i)}
				ssa.Variables[i] = v
				ssa.VarByID[int16(i)] = v
			}

			methodSig := &MethodSignature{
				ClassName:      "Test",
				MethodName:     "test",
				ReturnType:     TypeInfo{BaseType: "void"},
				ParameterTypes: make([]TypeInfo, 0),
				ParameterNames: make([]string, 0),
			}

			gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
			pseudocode := gen.Generate()

			if !strings.Contains(pseudocode, tt.expected) {
				t.Errorf("Expected operator '%s' in pseudocode, got: %s", tt.expected, pseudocode)
			}
		})
	}
}

// TestPseudocodeGeneratorFieldAccess tests field access generation.
func TestPseudocodeGeneratorFieldAccess(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind:      MIR_FIELD_GET,
				Dst:       0,
				Src1:      1,
				RefIdx:    42,
				FieldKind: FieldInstance,
			},
		},
	}
	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 2),
		VarByID:   make(map[int16]*SSAVariable),
	}

	for i := 0; i < 2; i++ {
		v := &SSAVariable{ID: int16(i), OrigRegister: int16(i)}
		ssa.Variables[i] = v
		ssa.VarByID[int16(i)] = v
	}

	methodSig := &MethodSignature{
		ClassName:      "Test",
		MethodName:     "test",
		ReturnType:     TypeInfo{BaseType: "void"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	pseudocode := gen.Generate()

	if !strings.Contains(pseudocode, "v0 = v1.field_42") {
		t.Errorf("Expected field access in pseudocode, got: %s", pseudocode)
	}
}

// TestPseudocodeGeneratorArrayAccess tests array access generation.
func TestPseudocodeGeneratorArrayAccess(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind:   MIR_ARRAY_GET,
				Dst:    0,
				Src1:   1,
				Src2:   2,
				RefIdx: 0,
			},
		},
	}
	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 3),
		VarByID:   make(map[int16]*SSAVariable),
	}

	for i := 0; i < 3; i++ {
		v := &SSAVariable{ID: int16(i), OrigRegister: int16(i)}
		ssa.Variables[i] = v
		ssa.VarByID[int16(i)] = v
	}

	methodSig := &MethodSignature{
		ClassName:      "Test",
		MethodName:     "test",
		ReturnType:     TypeInfo{BaseType: "void"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	pseudocode := gen.Generate()

	if !strings.Contains(pseudocode, "v0 = v1[v2]") {
		t.Errorf("Expected array access in pseudocode, got: %s", pseudocode)
	}
}

// TestPseudocodeGeneratorNewInstance tests new instance generation.
func TestPseudocodeGeneratorNewInstance(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind:   MIR_NEW_INSTANCE,
				Dst:    0,
				RefIdx: 123,
			},
		},
	}
	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 1),
		VarByID:   make(map[int16]*SSAVariable),
	}

	v := &SSAVariable{ID: 0, OrigRegister: 0}
	ssa.Variables[0] = v
	ssa.VarByID[0] = v

	methodSig := &MethodSignature{
		ClassName:      "Test",
		MethodName:     "test",
		ReturnType:     TypeInfo{BaseType: "void"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	pseudocode := gen.Generate()

	if !strings.Contains(pseudocode, "new Class_123") {
		t.Errorf("Expected new instance in pseudocode, got: %s", pseudocode)
	}
}

// TestPseudocodeGeneratorReturnStatement tests return statement generation.
func TestPseudocodeGeneratorReturnStatement(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind:     MIR_RETURN,
				Src1:     0,
				DataType: TypeInt,
			},
		},
	}
	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 1),
		VarByID:   make(map[int16]*SSAVariable),
	}

	v := &SSAVariable{ID: 0, OrigRegister: 0}
	ssa.Variables[0] = v
	ssa.VarByID[0] = v

	methodSig := &MethodSignature{
		ClassName:      "Test",
		MethodName:     "test",
		ReturnType:     TypeInfo{BaseType: "int"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	pseudocode := gen.Generate()

	if !strings.Contains(pseudocode, "return v0") {
		t.Errorf("Expected return statement in pseudocode, got: %s", pseudocode)
	}
}

// TestPseudocodeGeneratorReturnVoid tests void return statement generation.
func TestPseudocodeGeneratorReturnVoid(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind:     MIR_RETURN,
				Src1:     -1,
				DataType: TypeVoid,
			},
		},
	}
	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 0),
		VarByID:   make(map[int16]*SSAVariable),
	}

	methodSig := &MethodSignature{
		ClassName:      "Test",
		MethodName:     "test",
		ReturnType:     TypeInfo{BaseType: "void"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	pseudocode := gen.Generate()

	if !strings.Contains(pseudocode, "return;") {
		t.Errorf("Expected void return statement in pseudocode, got: %s", pseudocode)
	}
}

// TestPseudocodeGeneratorInstanceOf tests instanceof generation.
func TestPseudocodeGeneratorInstanceOf(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind:   MIR_INSTANCE_OF,
				Dst:    0,
				Src1:   1,
				RefIdx: 456,
			},
		},
	}
	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 2),
		VarByID:   make(map[int16]*SSAVariable),
	}

	for i := 0; i < 2; i++ {
		v := &SSAVariable{ID: int16(i), OrigRegister: int16(i)}
		ssa.Variables[i] = v
		ssa.VarByID[int16(i)] = v
	}

	methodSig := &MethodSignature{
		ClassName:      "Test",
		MethodName:     "test",
		ReturnType:     TypeInfo{BaseType: "void"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	pseudocode := gen.Generate()

	if !strings.Contains(pseudocode, "instanceof") {
		t.Errorf("Expected instanceof in pseudocode, got: %s", pseudocode)
	}
}

// TestPseudocodeGeneratorFormatType tests type formatting.
func TestPseudocodeGeneratorFormatType(t *testing.T) {
	tests := []struct {
		name     string
		typeInfo TypeInfo
		expected string
	}{
		{"int", TypeInfo{BaseType: "int"}, "int"},
		{"String", TypeInfo{BaseType: "String"}, "String"},
		{"int array", TypeInfo{BaseType: "int", IsArray: true}, "int[]"},
		{"Object array", TypeInfo{BaseType: "Object", IsArray: true}, "Object[]"},
	}

	cfg := &CFG{Blocks: make([]*BasicBlock, 0)}
	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 0),
		VarByID:   make(map[int16]*SSAVariable),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gen.formatType(tt.typeInfo)
			if result != tt.expected {
				t.Errorf("formatType(%v) = %s, want %s", tt.typeInfo, result, tt.expected)
			}
		})
	}
}

// TestPseudocodeGeneratorFormatConstantValue tests constant value formatting.
func TestPseudocodeGeneratorFormatConstantValue(t *testing.T) {
	tests := []struct {
		name     string
		value    int64
		dataType MIRDataType
		expected string
	}{
		{"int 42", 42, TypeInt, "42"},
		{"long 42", 42, TypeLong, "42L"},
		{"boolean true", 1, TypeBoolean, "true"},
		{"boolean false", 0, TypeBoolean, "false"},
	}

	cfg := &CFG{Blocks: make([]*BasicBlock, 0)}
	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 0),
		VarByID:   make(map[int16]*SSAVariable),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, nil)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := gen.formatConstantValue(tt.value, tt.dataType)
			if result != tt.expected {
				t.Errorf("formatConstantValue(%d, %d) = %s, want %s", tt.value, tt.dataType, result, tt.expected)
			}
		})
	}
}

// TestPseudocodeGeneratorIndentation tests proper indentation.
func TestPseudocodeGeneratorIndentation(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind:     MIR_CONST,
				Dst:      0,
				Imm:      42,
				DataType: TypeInt,
			},
		},
	}
	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 1),
		VarByID:   make(map[int16]*SSAVariable),
	}

	v := &SSAVariable{ID: 0, OrigRegister: 0}
	ssa.Variables[0] = v
	ssa.VarByID[0] = v

	methodSig := &MethodSignature{
		ClassName:      "Test",
		MethodName:     "test",
		ReturnType:     TypeInfo{BaseType: "void"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	pseudocode := gen.Generate()

	lines := strings.Split(pseudocode, "\n")
	if len(lines) < 3 {
		t.Errorf("Expected at least 3 lines, got %d", len(lines))
	}

	// Check that method body is indented
	if !strings.HasPrefix(lines[1], "    ") {
		t.Errorf("Expected indented method body, got: %s", lines[1])
	}
}

// TestPseudocodeGeneratorNilMethodSignature tests handling of nil method signature.
func TestPseudocodeGeneratorNilMethodSignature(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 0)}
	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 0),
		VarByID:   make(map[int16]*SSAVariable),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, nil)
	pseudocode := gen.Generate()

	// Should not panic and should return empty or minimal output
	if pseudocode == "" {
		t.Logf("Generated empty pseudocode for nil method signature")
	}
}

// TestPseudocodeGeneratorEmptyMethod tests empty method generation.
func TestPseudocodeGeneratorEmptyMethod(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 0)}
	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 0),
		VarByID:   make(map[int16]*SSAVariable),
	}

	methodSig := &MethodSignature{
		ClassName:      "Test",
		MethodName:     "empty",
		ReturnType:     TypeInfo{BaseType: "void"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	pseudocode := gen.Generate()

	if !strings.Contains(pseudocode, "empty") {
		t.Errorf("Expected method name in pseudocode")
	}

	if !strings.Contains(pseudocode, "{") || !strings.Contains(pseudocode, "}") {
		t.Errorf("Expected braces in pseudocode")
	}
}

// TestPseudocodeGeneratorVariableDeclarations tests variable declaration generation.
func TestPseudocodeGeneratorVariableDeclarations(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   0,
		Insns: make([]MIRInsn, 0),
	}
	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 2),
		VarByID:   make(map[int16]*SSAVariable),
	}

	for i := 0; i < 2; i++ {
		v := &SSAVariable{ID: int16(i), OrigRegister: int16(i)}
		ssa.Variables[i] = v
		ssa.VarByID[int16(i)] = v
	}

	methodSig := &MethodSignature{
		ClassName:      "Test",
		MethodName:     "test",
		ReturnType:     TypeInfo{BaseType: "void"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	gen.TypeInfo[0] = TypeInfo{BaseType: "int"}
	gen.TypeInfo[1] = TypeInfo{BaseType: "String"}

	pseudocode := gen.Generate()

	if !strings.Contains(pseudocode, "int v0") {
		t.Errorf("Expected 'int v0' declaration in pseudocode")
	}

	if !strings.Contains(pseudocode, "String v1") {
		t.Errorf("Expected 'String v1' declaration in pseudocode")
	}
}

// TestPseudocodeGeneratorRecoveredNames tests recovered name usage.
func TestPseudocodeGeneratorRecoveredNames(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind:     MIR_CONST,
				Dst:      0,
				Imm:      42,
				DataType: TypeInt,
			},
		},
	}
	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 1),
		VarByID:   make(map[int16]*SSAVariable),
	}

	v := &SSAVariable{ID: 0, OrigRegister: 0}
	ssa.Variables[0] = v
	ssa.VarByID[0] = v

	methodSig := &MethodSignature{
		ClassName:      "Test",
		MethodName:     "test",
		ReturnType:     TypeInfo{BaseType: "void"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	gen.RecoveredNames[0] = "count"

	pseudocode := gen.Generate()

	if !strings.Contains(pseudocode, "count = 42") {
		t.Errorf("Expected recovered name 'count' in pseudocode, got: %s", pseudocode)
	}
}

// TestPseudocodeGeneratorThrowStatement tests throw statement generation.
func TestPseudocodeGeneratorThrowStatement(t *testing.T) {
	cfg := &CFG{Blocks: make([]*BasicBlock, 1)}
	block := &BasicBlock{
		ID:    0,
		Start: 0,
		End:   1,
		Insns: []MIRInsn{
			{
				Kind:   MIR_THROW,
				Src1:   0,
				RefIdx: 0,
			},
		},
	}
	cfg.Blocks[0] = block
	cfg.Entry = block

	ssa := &SSAForm{
		CFG:       cfg,
		Variables: make([]*SSAVariable, 1),
		VarByID:   make(map[int16]*SSAVariable),
	}

	v := &SSAVariable{ID: 0, OrigRegister: 0}
	ssa.Variables[0] = v
	ssa.VarByID[0] = v

	methodSig := &MethodSignature{
		ClassName:      "Test",
		MethodName:     "test",
		ReturnType:     TypeInfo{BaseType: "void"},
		ParameterTypes: make([]TypeInfo, 0),
		ParameterNames: make([]string, 0),
	}

	gen := NewPseudocodeGenerator(cfg, ssa, nil, nil, nil, methodSig)
	pseudocode := gen.Generate()

	if !strings.Contains(pseudocode, "throw v0") {
		t.Errorf("Expected throw statement in pseudocode, got: %s", pseudocode)
	}
}
