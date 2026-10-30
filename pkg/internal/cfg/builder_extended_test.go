package cfg

import (
	"testing"
)

func TestDefaultBuildOptionsExtended(t *testing.T) {
	opts := DefaultBuildOptions()

	if !opts.SplitCriticalEdges {
		t.Error("SplitCriticalEdges should be true by default")
	}

	if !opts.DetectUnreachable {
		t.Error("DetectUnreachable should be true by default")
	}
}

func TestNewCFGBuilder(t *testing.T) {
	builder := NewCFGBuilder()

	if builder == nil {
		t.Fatal("NewCFGBuilder returned nil")
	}
}

func TestNewCFGBuilderWithOptions(t *testing.T) {
	opts := BuildOptions{
		SplitCriticalEdges: true,
		DetectUnreachable:  false,
	}

	builder := NewCFGBuilderWithOptions(opts)

	if builder == nil {
		t.Fatal("NewCFGBuilderWithOptions returned nil")
	}

	if builder.opts.DetectUnreachable {
		t.Error("DetectUnreachable should be false")
	}
}

func TestCFGBuilder_Build(t *testing.T) {
	builder := NewCFGBuilder()

	input := BuildInput{
		MethodName: "testMethod",
		Instructions: []Instruction{
			{Opcode: "nop"},
			{Opcode: "return"},
		},
	}

	cfg := builder.Build(input)

	if cfg == nil {
		t.Fatal("Build returned nil")
	}

	if cfg.MethodName != "testMethod" {
		t.Errorf("MethodName = %q, want testMethod", cfg.MethodName)
	}

	if len(cfg.Nodes) == 0 {
		t.Error("CFG should have nodes")
	}
}

func TestCFGBuilder_BuildEmpty(t *testing.T) {
	builder := NewCFGBuilder()

	input := BuildInput{
		MethodName:   "emptyMethod",
		Instructions: []Instruction{},
	}

	cfg := builder.Build(input)

	if cfg != nil {
		t.Fatal("Build should return nil for empty input")
	}
}

func TestCFGBuilder_Reset(t *testing.T) {
	builder := NewCFGBuilder()

	// Build something
	input := BuildInput{
		MethodName: "method1",
		Instructions: []Instruction{
			{Opcode: "nop"},
		},
	}
	builder.Build(input)

	// Reset
	builder.reset()

	// Build again
	input2 := BuildInput{
		MethodName: "method2",
		Instructions: []Instruction{
			{Opcode: "return"},
		},
	}
	cfg := builder.Build(input2)

	if cfg.MethodName != "method2" {
		t.Errorf("After reset, MethodName = %q, want method2", cfg.MethodName)
	}
}

// Benchmark tests
func BenchmarkDefaultBuildOptions(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DefaultBuildOptions()
	}
}

func BenchmarkNewCFGBuilder(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewCFGBuilder()
	}
}

func BenchmarkCFGBuilder_Build(b *testing.B) {
	builder := NewCFGBuilder()
	input := BuildInput{
		MethodName: "testMethod",
		Instructions: []Instruction{
			{Opcode: "nop"},
			{Opcode: "return"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder.Build(input)
	}
}
