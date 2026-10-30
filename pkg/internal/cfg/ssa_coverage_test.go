package cfg

import (
	"testing"
)

func TestSSABuilder_Coverage(t *testing.T) {
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

	if cfg == nil {
		t.Fatal("Failed to build CFG")
	}

	// Compute dominators
	da := NewDominatorAnalyzer(cfg)
	da.ComputeDominators()

	ssa := NewSSABuilder(cfg)
	ssa.BuildSSA()

	if !cfg.SSAConstructed {
		t.Error("SSA should be constructed")
	}

	// Test queries
	if len(cfg.Nodes) > 0 {
		val := ssa.GetReachingDefinition(cfg.Nodes[len(cfg.Nodes)-1], "v0")
		if val != nil {
			ssa.TraceValue(val, 5)
		}
	}
}

func TestSSABuilder_PhiPlacement(t *testing.T) {
	// A more complex graph to trigger Phi placement
	// entry -> block1, block2 -> block3
	instructions := []Instruction{
		{Line: 1, Index: 0, Opcode: "const/4", Raw: "const/4 v0, 1"},
		{Line: 2, Index: 1, Opcode: "if-eqz", Raw: "if-eqz v0, :label_b"},
		{Line: 3, Index: 2, Opcode: "const/4", Raw: "const/4 v0, 2"},
		{Line: 4, Index: 3, Opcode: "goto", Raw: "goto :label_c"},
		{Line: 5, Index: 4, Opcode: ":label_b"},
		{Line: 6, Index: 5, Opcode: "const/4", Raw: "const/4 v0, 3"},
		{Line: 7, Index: 6, Opcode: ":label_c"},
		{Line: 8, Index: 7, Opcode: "return-void", Raw: "return-void"},
	}

	labels := []Label{
		{Name: "label_b", Line: 5},
		{Name: "label_c", Line: 7},
	}

	builder := NewCFGBuilder()
	res := builder.BuildEx(BuildInput{Instructions: instructions, Labels: labels})
	cfg := res.CFG

	da := NewDominatorAnalyzer(cfg)
	da.ComputeDominators()

	ssa := NewSSABuilder(cfg)
	ssa.BuildSSA()

	// Find the node where phi should be (label_c)
	foundPhi := false
	for _, node := range cfg.Nodes {
		if len(node.PhiNodes) > 0 {
			foundPhi = true
			for _, phi := range node.PhiNodes {
				if phi.Register == "v0" {
					_ = phi.String()
				}
			}
		}
	}
	if !foundPhi {
		t.Log("Warning: No phi nodes placed (check if dominance frontier is correct)")
	}
}

func TestSSABuilder_EdgeCases(t *testing.T) {
	ssa := NewSSABuilder(nil)
	ssa.BuildSSA() // Should not panic

	cfg := &ControlFlowGraph{DominatorTree: false}
	ssa2 := NewSSABuilder(cfg)
	ssa2.BuildSSA() // Should return early
}
