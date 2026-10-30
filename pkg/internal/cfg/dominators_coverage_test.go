package cfg

import (
	"testing"
)

func TestDominatorAnalyzer_Coverage(t *testing.T) {
	instructions := []Instruction{
		{Line: 1, Index: 0, Opcode: "const/4", Raw: "const/4 v0, 0x1"},
		{Line: 2, Index: 1, Opcode: "if-eqz", Raw: "if-eqz v0, :label_1"},
		{Line: 3, Index: 2, Opcode: "const/4", Raw: "const/4 v1, 0x2"},
		{Line: 4, Index: 3, Opcode: ":label_1"},
		{Line: 5, Index: 4, Opcode: "return-void", Raw: "return-void"},
	}

	builder := NewCFGBuilder()
	res := builder.BuildEx(BuildInput{Instructions: instructions})
	cfg := res.CFG

	da := NewDominatorAnalyzer(cfg)
	da.ComputeDominators()

	if !cfg.DominatorTree {
		t.Error("DominatorTree should be true")
	}

	// Test queries
	if len(cfg.Nodes) >= 2 {
		nodeA := cfg.Nodes[0]
		nodeB := cfg.Nodes[len(cfg.Nodes)-1]
		da.Dominates(nodeA, nodeB)
		da.StrictlyDominates(nodeA, nodeB)
		da.FindNearestCommonDominator(nodeA, nodeB)
		da.DominatedBy(nodeA)
		da.DomTreePreorder()
		da.DomTreePostorder()
	}

	// Post-dominators
	da.ComputePostDominators()
	if !cfg.PostDomTree {
		t.Error("PostDomTree should be true")
	}

	// Control dependence
	da.ComputeControlDependence()
	da.ComputeControlDependencies()
	if len(cfg.Nodes) > 0 {
		da.GetControllers(cfg.Nodes[0])
		da.GetDependents(cfg.Nodes[0])
		da.GetControlledNodes(cfg.Nodes[0])
	}
}

func TestDominatorAnalyzer_EdgeCases(t *testing.T) {
	da := NewDominatorAnalyzer(nil)
	da.ComputeDominators()
	da.ComputePostDominators()
	da.ComputeControlDependencies()

	da2 := NewDominatorAnalyzer(&ControlFlowGraph{Nodes: []*CFGNode{}})
	da2.ComputeDominators()
	da2.ComputePostDominators()
}
