package evidencegraph

import (
	"fmt"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestQueryDoesNotExpandThroughSharedTarget(t *testing.T) {
	graph := Build(&types.AnalysisResult{
		TargetDir: "app",
		Hotspots:  []types.Hotspot{{Path: "a.smali"}, {Path: "b.smali"}},
	})
	chain, err := Query(graph, "", "a.smali")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.Nodes) != 3 || len(chain.Edges) != 2 {
		t.Fatalf("want target, file and its hotspot with 2 edges, got %+v", chain)
	}
	var targetID string
	for _, n := range chain.Nodes {
		if n.Path == "b.smali" {
			t.Fatalf("unrelated evidence leaked into the chain: %+v", n)
		}
		if n.Kind == "target" {
			targetID = n.ID
		}
	}
	whole, err := Query(graph, targetID, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(whole.Nodes) != len(graph.Nodes) || len(whole.Edges) != len(graph.Edges) {
		t.Fatalf("explicit target query must still include both branches: %+v", whole)
	}
}

func TestQueryPreservesCrossFileEvidence(t *testing.T) {
	graph := Build(&types.AnalysisResult{
		TargetDir:    "app",
		Hotspots:     []types.Hotspot{{Path: "a.smali"}, {Path: "b.smali"}},
		Correlations: []types.Correlation{{Type: types.CorrelationDataFlow, Files: []string{"a.smali", "b.smali"}}},
	})
	chain, err := Query(graph, "", "a.smali")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.Nodes) != len(graph.Nodes) || len(chain.Edges) != len(graph.Edges) {
		t.Fatalf("a real correlation must connect the two files exactly once: %+v", chain)
	}
	assertChainIntegrity(t, chain)
}

func TestQueryLimitsNeverProduceDanglingEdges(t *testing.T) {
	graph := &types.EvidenceGraph{Nodes: []types.EvidenceNode{{ID: "root", Kind: "target"}}}
	for i := 0; i < maxChainNodes+20; i++ {
		id := fmt.Sprintf("file-%03d", i)
		graph.Nodes = append(graph.Nodes, types.EvidenceNode{ID: id, Kind: "file"})
		edge := types.EvidenceEdge{ID: "edge-" + id, From: "root", To: id, Relation: "contains"}
		graph.Edges = append(graph.Edges, edge, edge)
	}
	graph.Edges = append(graph.Edges, types.EvidenceEdge{ID: "dangling", From: "root", To: "missing"})
	chain, err := Query(graph, "root", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.Nodes) != maxChainNodes || len(chain.Edges) != maxChainNodes-1 {
		t.Fatalf("wrong bounded chain size: %d nodes, %d edges", len(chain.Nodes), len(chain.Edges))
	}
	assertChainIntegrity(t, chain)
}

func assertChainIntegrity(t *testing.T, chain *types.EvidenceChain) {
	t.Helper()
	nodes, edges := map[string]bool{}, map[string]bool{}
	for _, n := range chain.Nodes {
		nodes[n.ID] = true
	}
	for _, e := range chain.Edges {
		if edges[e.ID] {
			t.Errorf("duplicate edge %s", e.ID)
		}
		edges[e.ID] = true
		if !nodes[e.From] || !nodes[e.To] {
			t.Errorf("dangling edge %+v", e)
		}
	}
}
