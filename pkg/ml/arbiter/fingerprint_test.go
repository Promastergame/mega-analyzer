package arbiter

import (
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

func linearGraph(instrSets ...[]string) *cfg.ControlFlowGraph {
	nodes := make([]*cfg.CFGNode, 0, len(instrSets))
	for i, instrs := range instrSets {
		nodes = append(nodes, mkNode(i, instrs...))
	}
	for i := 0; i+1 < len(nodes); i++ {
		nodes[i].Successors = []*cfg.CFGNode{nodes[i+1]}
		nodes[i+1].Predecessors = []*cfg.CFGNode{nodes[i]}
	}
	return &cfg.ControlFlowGraph{MethodName: "test", ClassName: "LTest;", Nodes: nodes}
}

func TestWLFingerprint_EmptyGraph(t *testing.T) {
	empty := WLFingerprint(&cfg.ControlFlowGraph{})
	zero := WLFingerprint(nil)
	if empty != zero {
		t.Errorf("expected nil and empty-graph fingerprints to both be the zero vector")
	}
}

func TestWLFingerprint_IdenticalStructureSameLabel(t *testing.T) {
	g1 := linearGraph(
		[]string{"const/4 v0, 0x0"},
		[]string{"invoke-virtual {v0}, Ljava/lang/String;->length()"},
	)
	g2 := linearGraph(
		[]string{"const/4 v1, 0x1"},
		[]string{"invoke-virtual {v1}, Ljava/lang/String;->length()"},
	)

	v1 := WLFingerprint(g1)
	v2 := WLFingerprint(g2)

	sim := v1.Sim(v2)
	if sim < 0.99 {
		t.Errorf("expected near-identical WL fingerprints for structurally identical graphs, got sim=%.4f", sim)
	}
}

func TestWLFingerprint_DifferentStructureDiffers(t *testing.T) {
	simple := linearGraph(
		[]string{"const/4 v0, 0x0"},
	)
	complex := linearGraph(
		[]string{"const/4 v0, 0x0"},
		[]string{"invoke-virtual {v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)"},
		[]string{"if-eqz v0, :label"},
		[]string{"throw v0"},
	)

	v1 := WLFingerprint(simple)
	v2 := WLFingerprint(complex)

	sim := v1.Sim(v2)
	if sim > 0.95 {
		t.Errorf("expected clearly different WL fingerprints for structurally different graphs, got sim=%.4f", sim)
	}
}
