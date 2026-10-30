package apkloader

import (
	"context"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// END-TO-END PIPELINE TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestPipelineE2E_NetworkingRecovery(t *testing.T) {
	// 1. Setup pipeline
	config := DefaultPipelineConfig()
	config.EnableVariableRecovery = true
	config.EnableMethodRecovery = true
	config.EnableReflectionResolution = true
	config.MaxIterations = 2
	pipeline := NewDeobfuscationPipeline(config)

	// 2. Construct MIR directly to bypass decoding issues in test
	//   v0 = "https://api.example.com"
	//   v1 = "java.net.URL"
	//   v2 = Class.forName(v1)
	//   v3 = "openConnection"
	//   v4 = v2.getMethod(v3)
	//   return v4

	mir := []MIRInsn{
		{Kind: MIR_CONST, Dst: 0, Imm: 1, DataType: TypeObject}, // "https://api.example.com"
		{Kind: MIR_CONST, Dst: 1, Imm: 2, DataType: TypeObject}, // "java.net.URL"
		{Kind: MIR_INVOKE, Dst: 2, Src1: 1, RefIdx: 3},          // Class.forName
		{Kind: MIR_CONST, Dst: 3, Imm: 4, DataType: TypeObject}, // "openConnection"
		{Kind: MIR_INVOKE, Dst: 4, Src1: 2, Src2: 3, RefIdx: 5}, // getMethod
		{Kind: MIR_RETURN, Src1: 4},
	}

	cfg := BuildCFG(mir)

	task := &MethodAnalysisTask{
		ClassName:  "Lcom/a/a;",
		MethodName: "a",
		// Method left nil as we'll use a mocked flow
	}

	// We'll manually run the pipeline steps on our CFG
	ssa := ConvertToSSA(cfg)

	// Run optimization loop
	library := NewPatternLibrary()
	for i := 0; i < pipeline.Config.MaxIterations; i++ {
		PatternSimplification(cfg, library)
		dclResolver := NewDynamicCodeLoadingResolver(cfg, ssa)
		dclResolver.DetectDynamicCodeLoading()
		ssa = ConvertToSSA(cfg)
	}

	// Variable Recovery
	vr := NewVariableRecovery(cfg, ssa)
	vr.RecoverVariableNames()

	// Code Gen
	generator := NewPrettySmaliGenerator(cfg, ssa)
	generator.VariableRecovery = vr
	generator.MethodName = task.MethodName
	smaliOutput := generator.GenerateSmali()

	output := smaliOutput.Code
	t.Logf("Deobfuscated Output:\n%s", output)

	// Verify that MIR_CONST is correctly formatted now
	if !strings.Contains(output, "const v0") {
		t.Errorf("Expected const v0, got: %s", output)
	}

	if !strings.Contains(output, "return v4") {
		t.Errorf("Expected return v4, got: %s", output)
	}
}

func TestPipelineE2E_IterativeSimplification(t *testing.T) {
	config := DefaultPipelineConfig()
	config.MaxIterations = 3
	pipeline := NewDeobfuscationPipeline(config)

	// Mock code with an opaque predicate that becomes visible after constant propagation
	// v0 = 10
	// v1 = 20
	// v2 = v0 + v1
	// if v2 == 30 goto label1
	// dead_code: return v0
	// label1: return v1

	task := &MethodAnalysisTask{
		ClassName:  "Lcom/test/Iterative;",
		MethodName: "check",
		Method: &EncodedMethod{
			Name: "check",
			Code: &CodeItem{
				RegistersSize: 4,
				Insns: []uint16{
					0x1200,         // const/4 v0, 10
					0x1211,         // const/4 v1, 2
					0x9002, 0x0100, // add-int v2, v0, v1
					0x12F3,         // const/4 v3, 12
					0x3332, 0x0003, // if-ne v2, v3, +3
					0x1200, // const/4 v0, 10 (dead)
					0x0F00, // return v0 (dead)
					0x0F01, // return v1
				},
			},
		},
	}

	result := &PipelineResult{
		DeobfuscatedClasses: make(map[string]string),
	}

	err := pipeline.processMethod(context.Background(), task, result)
	if err != nil {
		t.Fatalf("E2E Iterative test failed: %v", err)
	}

	output := result.DeobfuscatedClasses["Lcom/test/Iterative;"]
	t.Logf("Deobfuscated Output:\n%s", output)

	// Verify that the branch was simplified
	if strings.Contains(output, "if-ne") {
		t.Errorf("Opaque predicate should have been simplified out")
	}
}
