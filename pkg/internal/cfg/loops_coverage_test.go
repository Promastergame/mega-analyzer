package cfg

import (
	"testing"
)

func TestLoopAnalyzer_Coverage(t *testing.T) {
	// A simple loop: v0 = 0; while (v0 < 10) { v0++; }
	instructions := []Instruction{
		{Line: 1, Index: 0, Opcode: "const/4", Raw: "const/4 v1, 10", Operands: []string{"v1", "10"}},
		{Line: 2, Index: 1, Opcode: "const/4", Raw: "const/4 v0, 0", Operands: []string{"v0", "0"}},
		{Line: 3, Index: 2, Opcode: "if-ge", Raw: "if-ge v0, v1, :loop_exit", Operands: []string{"v0", "v1", ":loop_exit"}},
		{Line: 4, Index: 3, Opcode: "add-int/lit8", Raw: "add-int/lit8 v0, v0, 1", Operands: []string{"v0", "v0", "1"}},
		{Line: 5, Index: 4, Opcode: "goto", Raw: "goto :loop_header", Operands: []string{":loop_header"}},
		{Line: 6, Index: 5, Opcode: "return-void", Raw: "return-void"},
	}

	labels := []Label{
		{Name: ":loop_header", Line: 2},
		{Name: ":loop_exit", Line: 5},
	}

	builder := NewCFGBuilder()
	res := builder.BuildEx(BuildInput{Instructions: instructions, Labels: labels})
	cfg := res.CFG

	analyzer := NewLoopAnalyzer(cfg)
	loops := analyzer.FindLoops()

	if len(loops) == 0 {
		t.Error("Should find at least one loop")
	} else {
		loop := loops[0]
		_ = loop.ID
		_ = loop.Depth
	}
}

func TestLoopAnalyzer_EdgeCases(t *testing.T) {
	analyzer := NewLoopAnalyzer(nil)
	analyzer.FindLoops()

	analyzer2 := NewLoopAnalyzer(&ControlFlowGraph{Nodes: []*CFGNode{}})
	analyzer2.FindLoops()
}
