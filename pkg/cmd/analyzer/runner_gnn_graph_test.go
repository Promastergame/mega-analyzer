package main

import (
	"reflect"
	"testing"

	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/ml/gnn"
)

func TestBuildGNNGraphProducesAlignedCSRWithSelfLoops(t *testing.T) {
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

	graph := buildGNNGraph(&cfg.ControlFlowGraph{Nodes: []*cfg.CFGNode{entry, catch, nil}, Entry: entry})
	if graph == nil {
		t.Fatal("buildGNNGraph returned nil")
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

func TestExtractGNNFeaturesMatchesTrainingSchema(t *testing.T) {
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
	features := extractFeaturesGo(entry, 3)
	if len(features) != gnnFeatureDim {
		t.Fatalf("feature dimensions = %d, want %d", len(features), gnnFeatureDim)
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
	errorFeatures := extractFeaturesGo(errorNode, 1)
	if errorFeatures[26] != 1 || errorFeatures[27] != 0 {
		t.Fatalf("throw features are wrong: error=%v entry=%v", errorFeatures[26], errorFeatures[27])
	}
}

func TestBuildGNNGraphRejectsEmptyGraphs(t *testing.T) {
	if graph := buildGNNGraph(nil); graph != nil {
		t.Fatalf("nil CFG produced graph: %+v", graph)
	}
	if graph := buildGNNGraph(&cfg.ControlFlowGraph{}); graph != nil {
		t.Fatalf("empty CFG produced graph: %+v", graph)
	}
}

func TestGNNGraphWithinBudget(t *testing.T) {
	within := &gnn.Graph{NumNodes: gnnMaxGraphNodes, FeatureDim: gnnFeatureDim}
	if !gnnGraphWithinBudget(within) {
		t.Fatal("graph at configured node limit must be accepted")
	}

	overNodes := &gnn.Graph{NumNodes: gnnMaxGraphNodes + 1, FeatureDim: gnnFeatureDim}
	if gnnGraphWithinBudget(overNodes) {
		t.Fatal("graph above node limit must be rejected")
	}

	overEdges := &gnn.Graph{
		NumNodes:   3,
		FeatureDim: gnnFeatureDim,
		ColIndices: make([]uint64, gnnMaxGraphEdges+1),
	}
	if gnnGraphWithinBudget(overEdges) {
		t.Fatal("graph above edge limit must be rejected")
	}
}
