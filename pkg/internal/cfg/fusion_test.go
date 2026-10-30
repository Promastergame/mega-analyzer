package cfg

import (
	"testing"
)

func TestCFGFusionIntegration(t *testing.T) {
	// Build a simple CFG node graph
	n0 := &CFGNode{ID: 0, Type: NodeTypeEntry, RPONumber: 0}
	n1 := &CFGNode{ID: 1, Type: NodeTypeCondition, RPONumber: 1}
	n2 := &CFGNode{ID: 2, Type: NodeTypeBasic, RPONumber: 2}
	n3 := &CFGNode{ID: 3, Type: NodeTypeReturn, RPONumber: 3}

	n0.Successors = []*CFGNode{n1}
	n1.Predecessors = []*CFGNode{n0}
	n1.Successors = []*CFGNode{n2, n3}
	n2.Predecessors = []*CFGNode{n1}
	n2.Successors = []*CFGNode{n3}
	n3.Predecessors = []*CFGNode{n1, n2}

	g := &ControlFlowGraph{
		Entry: n0,
		Nodes: []*CFGNode{n0, n1, n2, n3},
	}

	metrics := NewMetrics(g)
	summary := metrics.UltimateSummary()

	if summary.FusionIntelligence == nil {
		t.Fatal("expected non-nil FusionIntelligence attached to UltimateSummary")
	}

	fi := summary.FusionIntelligence
	if fi.Decision.Explanation == "" {
		t.Error("expected explanation in fusion report")
	}
	if fi.SampleID == "" {
		t.Error("expected sample ID in fusion report")
	}
}
