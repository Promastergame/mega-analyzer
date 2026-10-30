package analysis

import (
	"testing"

	"mega-analyzer/pkg/binzap/ir"
)

func TestBuildCFGAndReachable(t *testing.T) {
	// Empty method
	emptyM := &ir.Method{}
	cfgEmpty := BuildCFG(emptyM)
	if len(cfgEmpty.Reachable()) != 0 {
		t.Error("expected 0 reachable nodes for empty CFG")
	}

	// Method with blocks and successors
	b1 := &ir.Block{Label: "b1"}
	b2 := &ir.Block{Label: "b2"}
	b3 := &ir.Block{Label: "b3"} // unreachable block
	b1.Succs = []*ir.Block{b2}

	m := &ir.Method{
		Blocks: []*ir.Block{b1, b2, b3},
	}

	cfg := BuildCFG(m)
	if len(cfg.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(cfg.Nodes))
	}

	reachable := cfg.Reachable()
	if !reachable[0] || !reachable[1] {
		t.Error("expected node 0 and 1 reachable")
	}
}
