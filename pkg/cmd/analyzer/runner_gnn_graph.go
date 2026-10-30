package main

import (
	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/gnngraph"
	"mega-analyzer/pkg/ml/gnn"
)

// gnnFeatureDim is the per-node feature vector width expected by the model.
const gnnFeatureDim = gnngraph.FeatureDim

const (
	// Large methods are not useful GNN candidates: their generic graph shape
	// dilutes the classification signal while creating enormous temporary tensors.
	gnnMaxMethodInstructions = 16 * 1024
	gnnMaxGraphNodes         = 8 * 1024
	gnnMaxGraphEdges         = 128 * 1024
	gnnMaxFeatureValues      = gnnMaxGraphNodes * gnnFeatureDim
)

// gnnGraphWithinBudget reports whether a graph is worth classifying: non-empty
// and inside the tensor budget above. A zero NumNodes or FeatureDim means the
// builder produced nothing usable, so it is rejected rather than handed to the
// model.
func gnnGraphWithinBudget(graph *gnn.Graph) bool {
	if graph == nil || graph.NumNodes == 0 || graph.FeatureDim == 0 {
		return false
	}
	return graph.NumNodes <= gnnMaxGraphNodes &&
		uint64(len(graph.ColIndices)) <= gnnMaxGraphEdges &&
		uint64(len(graph.Features)) <= gnnMaxFeatureValues
}

// buildGNNGraph converts a control-flow graph into a deterministic CSR
// tensor. The implementation lives in pkg/internal/gnngraph so it can be
// tested and benchmarked outside this externally-dependent package; hot
// loops (the GNN worker pool) should hold a per-goroutine gnngraph.Builder
// instead to reuse scratch buffers between graphs.
func buildGNNGraph(gCFG *cfg.ControlFlowGraph) *gnn.Graph {
	return gnngraph.Build(gCFG)
}

// extractFeaturesGo mirrors Rust FeatureExtractor exactly. Keeping training
// and serving normalization identical is part of the on-disk model contract.
func extractFeaturesGo(node *cfg.CFGNode, numNodes int) []float32 {
	return gnngraph.ExtractFeatures(node, numNodes)
}
