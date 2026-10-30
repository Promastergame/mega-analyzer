package apkloader

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDeobfuscationPipeline_Integration(t *testing.T) {
	// 1. Initialize pipeline
	config := DefaultPipelineConfig()
	config.MaxIterations = 2
	pipeline := NewDeobfuscationPipeline(config)

	// 2. Setup mock method analysis task
	task := &MethodAnalysisTask{
		ClassName:  "Lcom/example/Test;",
		MethodName: "testMethod",
		Method: &EncodedMethod{
			Name: "testMethod",
			Code: &CodeItem{
				RegistersSize: 4,
				Insns: []uint16{
					0x1200,         // const/4 v0, 0
					0x1211,         // const/4 v1, 1
					0x3210, 0x0002, // if-eq v0, v1, +2
					0x0000, // nop
					0x0000, // nop
					0x0E00, // return-void
				},
			},
		},
	}

	result := &PipelineResult{
		DeobfuscatedClasses: make(map[string]string),
	}

	// 3. Run processMethod
	err := pipeline.processMethod(context.Background(), task, result)
	if err != nil {
		t.Fatalf("processMethod failed: %v", err)
	}

	// 4. Verify results
	output := result.DeobfuscatedClasses["Lcom/example/Test;"]
	if output == "" {
		t.Fatal("Output is empty")
	}

	if !strings.Contains(output, ".method") {
		t.Errorf("Output missing .method directive: %s", output)
	}

	t.Logf("Generated Smali:\n%s", output)
}

func TestPipeline_EndToEndPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	config := DefaultPipelineConfig()
	pipeline := NewDeobfuscationPipeline(config)

	start := time.Now()
	methodsCount := 100

	// Create multiple tasks
	var tasks []*MethodAnalysisTask
	for i := 0; i < methodsCount; i++ {
		tasks = append(tasks, &MethodAnalysisTask{
			ClassName:  "Lcom/example/Class;",
			MethodName: "method",
			Method: &EncodedMethod{
				Name: "method",
				Code: &CodeItem{
					RegistersSize: 2,
					Insns:         []uint16{0x1200, 0x0E00},
				},
			},
		})
	}

	result := &PipelineResult{
		DeobfuscatedClasses: make(map[string]string),
	}

	err := pipeline.Coordinator.AnalyzeMethodsOptimized(tasks, func(task *MethodAnalysisTask) error {
		return pipeline.processMethod(context.Background(), task, result)
	})

	if err != nil {
		t.Fatalf("Pipeline performance test failed: %v", err)
	}

	duration := time.Since(start)
	t.Logf("Processed %d methods in %v", methodsCount, duration)
	t.Logf("Throughput: %.2f methods/sec", float64(methodsCount)/duration.Seconds())
}

func TestDeobfuscationPipeline_ComplexObfuscation(t *testing.T) {
	// 1. Initialize pipeline
	config := DefaultPipelineConfig()
	config.MaxIterations = 3
	pipeline := NewDeobfuscationPipeline(config)

	// 2. Setup mock method with multiple layers of obfuscation:
	//   v0 = 1
	//   v1 = 1
	//   v2 = v0 ^ v0 (identity -> const 0)
	//   v3 = v1 + 0  (dead arithmetic -> move v1)
	//   v4 = v2 & 0  (redundant boolean -> const 0)
	//   goto label1  (redundant jump)
	//   label1:
	//   return-void

	task := &MethodAnalysisTask{
		ClassName:  "Lcom/obfuscated/Test;",
		MethodName: "complex",
		Method: &EncodedMethod{
			Name: "complex",
			Code: &CodeItem{
				RegistersSize: 5,
				Insns: []uint16{
					0x1200,         // const/4 v0, 1
					0x1211,         // const/4 v1, 1
					0x9200, 0x0000, // xor-int v2, v0, v0
					0xD803, 0x0100, // add-int/lit8 v3, v1, 0
					0xD004, 0x0200, // and-int/lit16 v4, v2, 0
					0x2800, // goto +0 (redundant)
					0xB032, // add-int/2addr v2, v3
					0x0F02, // return v2
				},
			},
		},
	}

	result := &PipelineResult{
		DeobfuscatedClasses: make(map[string]string),
	}

	// 3. Run pipeline
	err := pipeline.processMethod(context.Background(), task, result)
	if err != nil {
		t.Fatalf("processMethod failed: %v", err)
	}

	// 4. Verify results
	output := result.DeobfuscatedClasses["Lcom/obfuscated/Test;"]

	// Check for simplifications in Smali output
	// XOR-self (v2 = v0 ^ v0) should be const 0
	if !strings.Contains(output, "const/4 v2, 0x0") {
		// Note: MIR_CONST might be emitted as const/4 or const depending on generator logic
		// If it's not simplified, it would stay as xor-int
		if strings.Contains(output, "xor-int") {
			t.Errorf("XOR-self not simplified: %s", output)
		}
	}

	// ADD-zero (v3 = v1 + 0) should be simplified to MOVE or similar
	if strings.Contains(output, "add-int/lit8") && strings.Contains(output, "0x0") {
		t.Errorf("ADD-zero not simplified: %s", output)
	}

	// Redundant jump (goto +0) should be removed
	if strings.Contains(output, "goto") {
		t.Errorf("Redundant jump not removed: %s", output)
	}

	t.Logf("Deobfuscated Smali:\n%s", output)
}
