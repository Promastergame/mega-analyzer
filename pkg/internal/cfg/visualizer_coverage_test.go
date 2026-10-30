package cfg

import (
	"testing"
)

func TestVisualizer_Coverage(t *testing.T) {
	instructions := []Instruction{
		{Line: 1, Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0x1"},
		{Line: 2, Index: 1, Opcode: "if-eqz", Raw: "if-eqz v0, :label_1"},
		{Line: 3, Index: 2, Opcode: "const/4", Raw: "const/4 v0, 0x2"},
		{Line: 4, Index: 3, Opcode: ":label_1"},
		{Line: 5, Index: 4, Opcode: "return-void", Raw: "return-void"},
	}

	builder := NewCFGBuilder()
	res := builder.BuildEx(BuildInput{Instructions: instructions})
	cfg := res.CFG

	viz := NewVisualizer(cfg)

	// Test DOT
	dot := viz.ExportDOT(DefaultDOTOptions())
	if dot == "" {
		t.Error("DOT should not be empty")
	}

	// Test ASCII
	ascii := viz.ExportASCII()
	if ascii == "" {
		t.Error("ASCII should not be empty")
	}

	// Test Custom
	opts := DefaultDOTOptions()
	opts.ColorScheme = "dark"
	opts.ShowInstructions = true
	viz.ExportDOT(opts)
}
