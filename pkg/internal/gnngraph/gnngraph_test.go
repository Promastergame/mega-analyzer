package gnngraph

import (
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/ml/gnn"
)

func TestBuildProducesAlignedCSRWithSelfLoops(t *testing.T) {
	entry := &cfg.CFGNode{ID: 7, Type: cfg.NodeTypeEntry}
	catch := &cfg.CFGNode{ID: 7, Type: cfg.NodeTypeCatch}
	external := &cfg.CFGNode{ID: 99, Type: cfg.NodeTypeBasic}
	entry.Successors = []*cfg.CFGNode{catch, catch, entry, nil, external}
	catch.Predecessors = []*cfg.CFGNode{entry}
	for i := 0; i < 10; i++ {
		entry.Instructions = append(entry.Instructions, cfg.InstructionRef{
			Opcode: "add-int",
			Raw:    "add-int v0, v1",
		})
	}

	graph := Build(&cfg.ControlFlowGraph{Nodes: []*cfg.CFGNode{entry, catch, nil}, Entry: entry})
	if graph == nil {
		t.Fatal("Build returned nil")
	}
	if got, want := graph.RowPtrs, []uint64{0, 3, 4, 5}; !reflect.DeepEqual(got, want) {
		t.Fatalf("row pointers = %v, want %v", got, want)
	}
	if got, want := graph.ColIndices, []uint64{0, 0, 1, 1, 2}; !reflect.DeepEqual(got, want) {
		t.Fatalf("column indices = %v, want %v", got, want)
	}
	if got, want := graph.EdgeTypes, []uint32{
		gnn.EdgeControlFlow, gnn.EdgeSelfLoop, gnn.EdgeControlFlow,
		gnn.EdgeSelfLoop, gnn.EdgeSelfLoop,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("edge types = %v, want %v", got, want)
	}

	for row := 0; row < int(graph.NumNodes); row++ {
		found := false
		for edge := graph.RowPtrs[row]; edge < graph.RowPtrs[row+1]; edge++ {
			if graph.ColIndices[edge] == uint64(row) && graph.EdgeTypes[edge] == gnn.EdgeSelfLoop {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("row %d has no explicit self-loop", row)
		}
	}
}

func TestExtractFeaturesMatchesTrainingSchema(t *testing.T) {
	entry := &cfg.CFGNode{
		Type:       cfg.NodeTypeEntry,
		LoopDepth:  20,
		Dominators: make([]*cfg.CFGNode, 9),
	}
	for i := 0; i < 12; i++ {
		entry.Instructions = append(entry.Instructions, cfg.InstructionRef{
			Opcode: "invoke-static",
			Raw:    "invoke-static v0, target",
		})
	}
	features := ExtractFeatures(entry, 3)
	if len(features) != FeatureDim {
		t.Fatalf("feature dimensions = %d, want %d", len(features), FeatureDim)
	}
	if features[4] != 1 || features[18] != 1 {
		t.Fatalf("invoke features are wrong: opcode=%v is_call=%v", features[4], features[18])
	}
	if features[16] != 1 {
		t.Fatalf("operand normalization = %v, want capped value 1", features[16])
	}
	if features[24] != 1 || features[25] != 1 {
		t.Fatalf("bounded structural features are wrong: loop=%v dominance=%v", features[24], features[25])
	}
	if features[26] != 0 || features[27] != 1 {
		t.Fatalf("entry/error slots are wrong: error=%v entry=%v", features[26], features[27])
	}

	errorNode := &cfg.CFGNode{Type: cfg.NodeTypeThrow}
	errorFeatures := ExtractFeatures(errorNode, 1)
	if errorFeatures[26] != 1 || errorFeatures[27] != 0 {
		t.Fatalf("throw features are wrong: error=%v entry=%v", errorFeatures[26], errorFeatures[27])
	}
}

func TestBuildRejectsEmptyGraphs(t *testing.T) {
	if graph := Build(nil); graph != nil {
		t.Fatalf("nil CFG produced graph: %+v", graph)
	}
	if graph := Build(&cfg.ControlFlowGraph{}); graph != nil {
		t.Fatalf("empty CFG produced graph: %+v", graph)
	}
}

// TestBuilderReuseDoesNotLeakState verifies that reusing one Builder across
// different graphs yields exactly the same tensors as fresh builds.
func TestBuilderReuseDoesNotLeakState(t *testing.T) {
	makeGraph := func(n int, loop bool) *cfg.ControlFlowGraph {
		nodes := make([]*cfg.CFGNode, n)
		for i := range nodes {
			nodes[i] = &cfg.CFGNode{ID: i, Type: cfg.NodeTypeBasic}
			nodes[i].Instructions = []cfg.InstructionRef{{Opcode: "invoke-virtual", Raw: "invoke-virtual v0, v1"}}
		}
		for i := 0; i+1 < n; i++ {
			nodes[i].Successors = append(nodes[i].Successors, nodes[i+1])
			nodes[i+1].Predecessors = append(nodes[i+1].Predecessors, nodes[i])
		}
		if loop && n > 1 {
			nodes[n-1].Successors = append(nodes[n-1].Successors, nodes[0], nodes[n-1])
		}
		return &cfg.ControlFlowGraph{Nodes: nodes, Entry: nodes[0]}
	}

	graphs := []*cfg.ControlFlowGraph{makeGraph(5, true), makeGraph(3, false), makeGraph(8, true)}
	shared := &Builder{}
	for gi, g := range graphs {
		reused := shared.Build(g)
		fresh := Build(g)
		if !reflect.DeepEqual(reused, fresh) {
			t.Fatalf("graph %d: reused builder output differs from fresh build\nreused: %+v\nfresh:  %+v", gi, reused, fresh)
		}
	}
}
