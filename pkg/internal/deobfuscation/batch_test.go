package deobfuscation

import (
	"context"
	"testing"

	"mega-analyzer/pkg/internal/cfg"
)

func makeDeadCodeGraph(id int) *cfg.ControlFlowGraph {
	entry := &cfg.CFGNode{ID: 0, Type: cfg.NodeTypeEntry}
	reachable := &cfg.CFGNode{ID: 1, Type: cfg.NodeTypeBasic}
	dead := &cfg.CFGNode{ID: 2, Type: cfg.NodeTypeBasic}
	entry.Successors = []*cfg.CFGNode{reachable}
	reachable.Predecessors = []*cfg.CFGNode{entry}
	return &cfg.ControlFlowGraph{
		MethodName: "m",
		Entry:      entry,
		Nodes:      []*cfg.CFGNode{entry, reachable, dead},
	}
}

func TestAnalyzeAll_OrderAndResults(t *testing.T) {
	e := NewDefaultEngine()
	graphs := make([]*cfg.ControlFlowGraph, 50)
	for i := range graphs {
		graphs[i] = makeDeadCodeGraph(i)
	}
	results := e.AnalyzeAll(context.Background(), graphs)
	if len(results) != len(graphs) {
		t.Fatalf("got %d results, want %d", len(results), len(graphs))
	}
	for i, r := range results {
		if r == nil {
			t.Fatalf("result %d is nil", i)
		}
		if r.DeadNodesFound != 1 {
			t.Errorf("result %d: dead nodes = %d, want 1", i, r.DeadNodesFound)
		}
	}
}

func TestAnalyzeAll_Empty(t *testing.T) {
	e := NewDefaultEngine()
	if got := e.AnalyzeAll(context.Background(), nil); len(got) != 0 {
		t.Errorf("expected empty result slice, got %d", len(got))
	}
}

func TestAnalyzeAll_NilGraphs(t *testing.T) {
	e := NewDefaultEngine()
	graphs := []*cfg.ControlFlowGraph{nil, makeDeadCodeGraph(1), nil}
	results := e.AnalyzeAll(context.Background(), graphs)
	if len(results) != 3 {
		t.Fatalf("got %d results", len(results))
	}
	for i, r := range results {
		if r == nil {
			t.Fatalf("result %d nil", i)
		}
	}
	if results[1].DeadNodesFound != 1 {
		t.Errorf("middle graph should have 1 dead node")
	}
}

func TestAnalyzeAll_Cancelled(t *testing.T) {
	e := NewDefaultEngine()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	graphs := make([]*cfg.ControlFlowGraph, 20)
	for i := range graphs {
		graphs[i] = makeDeadCodeGraph(i)
	}
	results := e.AnalyzeAll(ctx, graphs)
	// Every slot must still be a non-nil result even when work was skipped.
	if len(results) != len(graphs) {
		t.Fatalf("got %d results", len(results))
	}
	for i, r := range results {
		if r == nil {
			t.Fatalf("result %d nil after cancellation", i)
		}
	}
}

func TestAnalyzeAll_SingleWorkerInline(t *testing.T) {
	e := NewDefaultEngine()
	graphs := []*cfg.ControlFlowGraph{makeDeadCodeGraph(0)}
	results := e.AnalyzeAll(context.Background(), graphs)
	if len(results) != 1 || results[0].DeadNodesFound != 1 {
		t.Fatalf("single-graph batch failed: %+v", results)
	}
}
