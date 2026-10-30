package apkloader

import (
	"strings"
	"testing"
)

// TestNewPrettySmaliGenerator tests the creation of a new Pretty Smali generator.
func TestNewPrettySmaliGenerator(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)

	if psg == nil {
		t.Fatal("Expected non-nil generator")
	}
	if psg.CFG != cfg {
		t.Error("CFG not set correctly")
	}
	if psg.SSA != ssa {
		t.Error("SSA not set correctly")
	}
	if !psg.IncludeConfidenceScore {
		t.Error("IncludeConfidenceScore should be true by default")
	}
	if !psg.IncludeOriginalNames {
		t.Error("IncludeOriginalNames should be true by default")
	}
	if !psg.IncludeObfuscationInfo {
		t.Error("IncludeObfuscationInfo should be true by default")
	}
	if psg.MinConfidenceThreshold != 50 {
		t.Error("MinConfidenceThreshold should be 50 by default")
	}
}

// TestSetVariableRecovery tests setting variable recovery results.
func TestSetVariableRecovery(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{}
	psg := NewPrettySmaliGenerator(cfg, ssa)

	vr := &VariableRecovery{
		Results: make(map[int16]*VariableRecoveryResult),
	}

	psg.SetVariableRecovery(vr)

	if psg.VariableRecovery != vr {
		t.Error("Variable recovery not set correctly")
	}
}

// TestAddMethodRecovery tests adding method recovery results.
func TestAddMethodRecovery(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{}
	psg := NewPrettySmaliGenerator(cfg, ssa)

	result := &MethodRecoveryResult{
		MethodName: "isLicensed",
		Confidence: 85,
		Rationale:  "Override detection",
	}

	psg.AddMethodRecovery("a", result)

	if len(psg.MethodRecovery) != 1 {
		t.Error("Method recovery not added")
	}
	if psg.MethodRecovery["a"] != result {
		t.Error("Method recovery result not stored correctly")
	}
}

// TestAddConstantValue tests adding constant values.
func TestAddConstantValue(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{}
	psg := NewPrettySmaliGenerator(cfg, ssa)

	psg.AddConstantValue(0, int64(42))
	psg.AddConstantValue(1, "hello")

	if len(psg.ConstantPropagation) != 2 {
		t.Error("Constants not added")
	}
	if psg.ConstantPropagation[0] != int64(42) {
		t.Error("Constant value not stored correctly")
	}
	if psg.ConstantPropagation[1] != "hello" {
		t.Error("String constant not stored correctly")
	}
}

// TestAddDetectedObfuscation tests adding detected obfuscation techniques.
func TestAddDetectedObfuscation(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{}
	psg := NewPrettySmaliGenerator(cfg, ssa)

	psg.AddDetectedObfuscation("String Encryption")
	psg.AddDetectedObfuscation("Control Flow Flattening")

	if len(psg.DetectedObfuscations) != 2 {
		t.Error("Obfuscations not added")
	}
	if psg.DetectedObfuscations[0] != "String Encryption" {
		t.Error("Obfuscation not stored correctly")
	}
}

// TestGenerateSmaliBasic tests basic Smali generation.
func TestGenerateSmaliBasic(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)
	output := psg.GenerateSmali()

	if output == nil {
		t.Fatal("Expected non-nil output")
	}
	if output.Code == "" {
		t.Error("Expected non-empty code")
	}
	if !strings.Contains(output.Code, "PRETTY SMALI OUTPUT") {
		t.Error("Expected header in output")
	}
}

// TestGenerateSmaliWithVariableRecovery tests Smali generation with variable recovery.
func TestGenerateSmaliWithVariableRecovery(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
		VarByID:   make(map[int16]*SSAVariable),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)

	// Create a variable recovery result
	vr := &VariableRecovery{
		Results: make(map[int16]*VariableRecoveryResult),
	}

	variable := &SSAVariable{
		ID:           0,
		OrigRegister: 0,
	}

	result := &VariableRecoveryResult{
		Variable:       variable,
		SelectedName:   "key",
		Confidence:     85,
		Rationale:      "API pattern match",
		CandidateNames: []NameCandidate{},
	}

	vr.Results[0] = result
	psg.SetVariableRecovery(vr)

	output := psg.GenerateSmali()

	if !strings.Contains(output.Code, "VARIABLE RECOVERY") {
		t.Error("Expected VARIABLE RECOVERY section")
	}
	if !strings.Contains(output.Code, "key") {
		t.Error("Expected recovered variable name in output")
	}
	if !strings.Contains(output.Code, "85%") {
		t.Error("Expected confidence score in output")
	}
}

// TestGenerateSmaliWithMethodRecovery tests Smali generation with method recovery.
func TestGenerateSmaliWithMethodRecovery(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)

	result := &MethodRecoveryResult{
		MethodName: "isLicensed",
		Confidence: 90,
		Rationale:  "Override detection",
		Signals: []RecoverySignal{
			{
				Type:     "override",
				Evidence: "Matches LicenseChecker.isLicensed",
				Weight:   100,
			},
		},
	}

	psg.AddMethodRecovery("a", result)

	output := psg.GenerateSmali()

	if !strings.Contains(output.Code, "METHOD RECOVERY") {
		t.Error("Expected METHOD RECOVERY section")
	}
	if !strings.Contains(output.Code, "isLicensed") {
		t.Error("Expected recovered method name in output")
	}
	if !strings.Contains(output.Code, "90%") {
		t.Error("Expected confidence score in output")
	}
}

// TestGenerateSmaliWithObfuscationInfo tests Smali generation with obfuscation info.
func TestGenerateSmaliWithObfuscationInfo(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)
	psg.AddDetectedObfuscation("String Encryption")
	psg.AddDetectedObfuscation("Control Flow Flattening")

	output := psg.GenerateSmali()

	if !strings.Contains(output.Code, "DETECTED OBFUSCATION TECHNIQUES") {
		t.Error("Expected obfuscation section")
	}
	if !strings.Contains(output.Code, "String Encryption") {
		t.Error("Expected obfuscation technique in output")
	}
	if !strings.Contains(output.Code, "Control Flow Flattening") {
		t.Error("Expected second obfuscation technique in output")
	}
}

// TestGenerateSmaliWithConstants tests Smali generation with constant propagation.
func TestGenerateSmaliWithConstants(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)
	psg.AddConstantValue(0, int64(42))
	psg.AddConstantValue(1, "hello")

	output := psg.GenerateSmali()

	if !strings.Contains(output.Code, "CONSTANT PROPAGATION") {
		t.Error("Expected constant propagation section")
	}
	if !strings.Contains(output.Code, "42") {
		t.Error("Expected constant value in output")
	}
	if !strings.Contains(output.Code, "hello") {
		t.Error("Expected string constant in output")
	}
}

// TestGenerateSmaliWithCFG tests Smali generation with CFG structure.
func TestGenerateSmaliWithCFG(t *testing.T) {
	block1 := &BasicBlock{
		ID:          0,
		IsReachable: true,
	}
	block2 := &BasicBlock{
		ID:          1,
		IsReachable: true,
	}
	block3 := &BasicBlock{
		ID:          2,
		IsReachable: false,
	}

	cfg := &CFG{
		Blocks:        []*BasicBlock{block1, block2, block3},
		Entry:         block1,
		HandlerBlocks: make([]*BasicBlock, 0),
	}

	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)
	output := psg.GenerateSmali()

	if !strings.Contains(output.Code, "CONTROL FLOW GRAPH STRUCTURE") {
		t.Error("Expected CFG structure section")
	}
	if !strings.Contains(output.Code, "Total Basic Blocks: 3") {
		t.Error("Expected total blocks count")
	}
	if !strings.Contains(output.Code, "Reachable Blocks: 2") {
		t.Error("Expected reachable blocks count")
	}
	if !strings.Contains(output.Code, "Unreachable Blocks: 1") {
		t.Error("Expected unreachable blocks count")
	}
}

// TestFormatInstruction tests instruction formatting.
func TestFormatInstruction(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{}
	psg := NewPrettySmaliGenerator(cfg, ssa)

	insn := &MIRInsn{
		Kind: MIR_MOVE,
		Dst:  0,
		Src1: 1,
	}

	formatted := psg.FormatInstruction(insn)

	if !strings.Contains(formatted, "move") {
		t.Error("Expected 'move' in formatted instruction")
	}
	if !strings.Contains(formatted, "v0") {
		t.Error("Expected destination register in formatted instruction")
	}
	if !strings.Contains(formatted, "v1") {
		t.Error("Expected source register in formatted instruction")
	}
}

// TestFormatInstructionWithRecoveredName tests instruction formatting with recovered names.
func TestFormatInstructionWithRecoveredName(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
		VarByID:   make(map[int16]*SSAVariable),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)

	vr := &VariableRecovery{
		Results: make(map[int16]*VariableRecoveryResult),
	}

	variable := &SSAVariable{
		ID:           0,
		OrigRegister: 0,
	}

	result := &VariableRecoveryResult{
		Variable:       variable,
		SelectedName:   "key",
		Confidence:     85,
		Rationale:      "API pattern match",
		CandidateNames: []NameCandidate{},
	}

	vr.Results[0] = result
	psg.SetVariableRecovery(vr)

	insn := &MIRInsn{
		Kind: MIR_CONST,
		Dst:  0,
		Imm:  42,
	}

	formatted := psg.FormatInstruction(insn)

	if !strings.Contains(formatted, "key") {
		t.Error("Expected recovered name in formatted instruction")
	}
	if !strings.Contains(formatted, "85%") {
		t.Error("Expected confidence score in formatted instruction")
	}
}

// TestIndentation tests indentation functionality.
func TestIndentation(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{}
	psg := NewPrettySmaliGenerator(cfg, ssa)

	if psg.IndentLevel != 0 {
		t.Error("Initial indent level should be 0")
	}

	psg.Indent()
	if psg.IndentLevel != 1 {
		t.Error("Indent level should be 1 after Indent()")
	}

	psg.Indent()
	if psg.IndentLevel != 2 {
		t.Error("Indent level should be 2 after second Indent()")
	}

	psg.Dedent()
	if psg.IndentLevel != 1 {
		t.Error("Indent level should be 1 after Dedent()")
	}

	psg.Dedent()
	if psg.IndentLevel != 0 {
		t.Error("Indent level should be 0 after second Dedent()")
	}

	// Test that dedent doesn't go below 0
	psg.Dedent()
	if psg.IndentLevel != 0 {
		t.Error("Indent level should not go below 0")
	}
}

// TestGetIndentString tests getting the indentation string.
func TestGetIndentString(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{}
	psg := NewPrettySmaliGenerator(cfg, ssa)

	if psg.GetIndentString() != "" {
		t.Error("Initial indent string should be empty")
	}

	psg.Indent()
	if psg.GetIndentString() != "    " {
		t.Error("Indent string should be 4 spaces")
	}

	psg.Indent()
	if psg.GetIndentString() != "        " {
		t.Error("Indent string should be 8 spaces")
	}
}

// TestRecoveryStats tests recovery statistics calculation.
func TestRecoveryStats(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)

	vr := &VariableRecovery{
		Results: make(map[int16]*VariableRecoveryResult),
	}

	// Add some variable recovery results
	for i := 0; i < 3; i++ {
		variable := &SSAVariable{
			ID:           int16(i),
			OrigRegister: int16(i),
		}

		confidence := 60 + i*10 // 60, 70, 80
		result := &VariableRecoveryResult{
			Variable:       variable,
			SelectedName:   "var" + string(rune(i)),
			Confidence:     confidence,
			Rationale:      "test",
			CandidateNames: []NameCandidate{},
		}

		vr.Results[int16(i)] = result
	}

	psg.SetVariableRecovery(vr)
	psg.AddMethodRecovery("method1", &MethodRecoveryResult{
		MethodName: "isLicensed",
		Confidence: 85,
		Rationale:  "test",
	})
	psg.AddDetectedObfuscation("String Encryption")

	stats := psg.calculateRecoveryStats()

	if stats.VariablesRecovered != 3 {
		t.Error("Expected 3 variables recovered")
	}
	if stats.VariablesWithHighConf != 1 {
		t.Error("Expected 1 variable with high confidence (80+)")
	}
	if stats.AverageVariableConfidence != 70 {
		t.Error("Expected average confidence of 70")
	}
	if stats.MethodsRecovered != 1 {
		t.Error("Expected 1 method recovered")
	}
	if stats.MethodsWithHighConf != 1 {
		t.Error("Expected 1 method with high confidence")
	}
	if len(stats.ObfuscationTechniques) != 1 {
		t.Error("Expected 1 obfuscation technique")
	}
}

// TestFormattingMetrics tests formatting metrics calculation.
func TestFormattingMetrics(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{}
	psg := NewPrettySmaliGenerator(cfg, ssa)

	output := psg.GenerateSmali()

	if output.FormattingMetrics.TotalLines == 0 {
		t.Error("Expected non-zero total lines")
	}
	if output.FormattingMetrics.CommentLines == 0 {
		t.Error("Expected non-zero comment lines")
	}
	if output.FormattingMetrics.CodeLines < 0 {
		t.Error("Code lines should not be negative")
	}
}

// TestMinConfidenceThreshold tests minimum confidence threshold filtering.
func TestMinConfidenceThreshold(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
		VarByID:   make(map[int16]*SSAVariable),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)
	psg.MinConfidenceThreshold = 80

	vr := &VariableRecovery{
		Results: make(map[int16]*VariableRecoveryResult),
	}

	// Add low confidence result
	variable1 := &SSAVariable{
		ID:           0,
		OrigRegister: 0,
	}
	result1 := &VariableRecoveryResult{
		Variable:       variable1,
		SelectedName:   "lowConfVar",
		Confidence:     40,
		Rationale:      "low confidence",
		CandidateNames: []NameCandidate{},
	}
	vr.Results[0] = result1

	// Add high confidence result
	variable2 := &SSAVariable{
		ID:           1,
		OrigRegister: 1,
	}
	result2 := &VariableRecoveryResult{
		Variable:       variable2,
		SelectedName:   "highConfVar",
		Confidence:     90,
		Rationale:      "high confidence",
		CandidateNames: []NameCandidate{},
	}
	vr.Results[1] = result2

	psg.SetVariableRecovery(vr)

	output := psg.GenerateSmali()

	// Low confidence variable should not appear
	if strings.Contains(output.Code, "lowConfVar") {
		t.Error("Low confidence variable should not appear in output")
	}

	// High confidence variable should appear
	if !strings.Contains(output.Code, "highConfVar") {
		t.Error("High confidence variable should appear in output")
	}
}

// TestDisableFeatures tests disabling various features.
func TestDisableFeatures(t *testing.T) {
	cfg := &CFG{}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
		VarByID:   make(map[int16]*SSAVariable),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)

	vr := &VariableRecovery{
		Results: make(map[int16]*VariableRecoveryResult),
	}

	variable := &SSAVariable{
		ID:           0,
		OrigRegister: 0,
	}

	result := &VariableRecoveryResult{
		Variable:       variable,
		SelectedName:   "key",
		Confidence:     85,
		Rationale:      "API pattern match",
		CandidateNames: []NameCandidate{},
	}

	vr.Results[0] = result
	psg.SetVariableRecovery(vr)

	// Disable confidence score display
	psg.IncludeConfidenceScore = false
	output := psg.GenerateSmali()
	if strings.Contains(output.Code, "85%") {
		t.Error("Confidence score should not appear when disabled")
	}

	// Disable original names
	psg.IncludeConfidenceScore = true
	psg.IncludeOriginalNames = false
	output = psg.GenerateSmali()
	if strings.Contains(output.Code, "[ORIGINAL: v0]") {
		t.Error("Original names should not appear when disabled")
	}

	// Disable obfuscation info
	psg.IncludeOriginalNames = true
	psg.IncludeObfuscationInfo = false
	psg.AddDetectedObfuscation("String Encryption")
	output = psg.GenerateSmali()
	if strings.Contains(output.Code, "DETECTED OBFUSCATION") {
		t.Error("Obfuscation info should not appear when disabled")
	}
}

// TestEmptyCFG tests generation with empty CFG.
func TestEmptyCFG(t *testing.T) {
	cfg := &CFG{
		Blocks: make([]*BasicBlock, 0),
	}
	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)
	output := psg.GenerateSmali()

	if output == nil {
		t.Fatal("Expected non-nil output")
	}
	if output.Code == "" {
		t.Error("Expected non-empty code")
	}
	if !strings.Contains(output.Code, "PRETTY SMALI OUTPUT") {
		t.Error("Expected header in output")
	}
}

// TestComplexScenario tests a complex scenario with multiple features.
func TestComplexScenario(t *testing.T) {
	// Create CFG with multiple blocks
	block1 := &BasicBlock{
		ID:          0,
		IsReachable: true,
	}
	block2 := &BasicBlock{
		ID:           1,
		IsReachable:  true,
		IsLoopHeader: true,
	}
	block3 := &BasicBlock{
		ID:          2,
		IsReachable: false,
	}

	cfg := &CFG{
		Blocks:        []*BasicBlock{block1, block2, block3},
		Entry:         block1,
		HandlerBlocks: make([]*BasicBlock, 0),
	}

	ssa := &SSAForm{
		Variables: make([]*SSAVariable, 0),
		VarByID:   make(map[int16]*SSAVariable),
	}

	psg := NewPrettySmaliGenerator(cfg, ssa)

	// Add variable recovery
	vr := &VariableRecovery{
		Results: make(map[int16]*VariableRecoveryResult),
	}

	for i := 0; i < 2; i++ {
		variable := &SSAVariable{
			ID:           int16(i),
			OrigRegister: int16(i),
		}

		result := &VariableRecoveryResult{
			Variable:       variable,
			SelectedName:   "var" + string(rune('a'+i)),
			Confidence:     75 + i*10,
			Rationale:      "test",
			CandidateNames: []NameCandidate{},
		}

		vr.Results[int16(i)] = result
	}

	psg.SetVariableRecovery(vr)

	// Add method recovery
	psg.AddMethodRecovery("method1", &MethodRecoveryResult{
		MethodName: "isLicensed",
		Confidence: 85,
		Rationale:  "Override detection",
		Signals: []RecoverySignal{
			{
				Type:     "override",
				Evidence: "Matches LicenseChecker.isLicensed",
				Weight:   100,
			},
		},
	})

	// Add constants
	psg.AddConstantValue(0, int64(42))
	psg.AddConstantValue(1, "secret")

	// Add obfuscation techniques
	psg.AddDetectedObfuscation("String Encryption")
	psg.AddDetectedObfuscation("Control Flow Flattening")

	output := psg.GenerateSmali()

	// Verify all sections are present
	if !strings.Contains(output.Code, "PRETTY SMALI OUTPUT") {
		t.Error("Expected header")
	}
	if !strings.Contains(output.Code, "DETECTED OBFUSCATION TECHNIQUES") {
		t.Error("Expected obfuscation section")
	}
	if !strings.Contains(output.Code, "VARIABLE RECOVERY") {
		t.Error("Expected variable recovery section")
	}
	if !strings.Contains(output.Code, "METHOD RECOVERY") {
		t.Error("Expected method recovery section")
	}
	if !strings.Contains(output.Code, "CONSTANT PROPAGATION") {
		t.Error("Expected constant propagation section")
	}
	if !strings.Contains(output.Code, "CONTROL FLOW GRAPH STRUCTURE") {
		t.Error("Expected CFG structure section")
	}

	// Verify statistics
	if output.RecoveryStats.VariablesRecovered != 2 {
		t.Error("Expected 2 variables recovered")
	}
	if output.RecoveryStats.MethodsRecovered != 1 {
		t.Error("Expected 1 method recovered")
	}
	if output.RecoveryStats.ConstantsRecovered != 2 {
		t.Error("Expected 2 constants recovered")
	}
	if len(output.RecoveryStats.ObfuscationTechniques) != 2 {
		t.Error("Expected 2 obfuscation techniques")
	}

	// Verify formatting metrics
	if output.FormattingMetrics.TotalLines == 0 {
		t.Error("Expected non-zero total lines")
	}
	if output.FormattingMetrics.CommentLines == 0 {
		t.Error("Expected non-zero comment lines")
	}
}
