// program_arrays_test.go — array aget/aput propagation and exception precision.
package dataflow

import (
	"context"
	"testing"
)

func TestArrays_TaintThroughAputAgetToExec(t *testing.T) {
	program := NewProgram(DefaultConfig())
	// Intent extra → stored into String[] via aput-object → read back via
	// aget-object → Runtime.exec. Must surface as command_injection.
	addMethod(program, "Lapp/Runner;", "run", "", "V", false,
		".method public run()V",
		"invoke-virtual {p0, v9}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
		"move-result-object v0",
		"new-array v1, v8, [Ljava/lang/String;",
		"aput-object v0, v1, v8",
		"aget-object v2, v1, v8",
		"invoke-virtual {v3, v2}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if !hasCategory(result, "command_injection") {
		t.Fatalf("expected command_injection through aput/aget, got %v", findingCategories(result))
	}
	// Array reads are imprecise (merged elements) → ViaField confidence
	// penalty must apply.
	for _, f := range result.Findings {
		if f.Category == "command_injection" && f.Confidence >= 0.9 {
			t.Errorf("aget flow should carry the ViaField penalty, confidence=%v", f.Confidence)
		}
	}
}

func TestArrays_MoveExceptionDoesNotInventInput(t *testing.T) {
	program := NewProgram(DefaultConfig())
	addMethod(program, "Lapp/Handler;", "handle", "", "V", false,
		".method public handle()V",
		"move-exception v0",
		"invoke-virtual {v1, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if hasCategory(result, "command_injection") {
		t.Fatalf("move-exception must not be seeded as attacker input, got %v", findingCategories(result))
	}
}

func TestArrays_UntaintedArrayNoFinding(t *testing.T) {
	program := NewProgram(DefaultConfig())
	// Constant-derived value stored in an array: no labels, no params →
	// no finding must be emitted (precision guard against the coarse
	// array model).
	addMethod(program, "Lapp/Runner;", "safe", "", "V", false,
		".method public safe()V",
		"const/4 v0, 0x1",
		"new-array v1, v8, [Ljava/lang/String;",
		"aput-object v0, v1, v8",
		"aget-object v2, v1, v8",
		"invoke-virtual {v3, v2}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;",
		"return-void", ".end method")

	result := program.Analyze(context.Background())
	if hasCategory(result, "command_injection") {
		t.Fatalf("untainted array element must not produce a finding, got %v", findingCategories(result))
	}
}
