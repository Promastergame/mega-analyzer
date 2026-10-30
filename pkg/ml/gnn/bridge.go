//go:build cgo && omnisec_ml_gnn

package gnn

// #cgo CFLAGS: -I../../../rust/crates/omnisec-ml-gnn/include
// #cgo LDFLAGS: -L${SRCDIR}/../../../rust/target/release -lomnisec_ml_gnn
// #include "omnisec_ml_gnn.h"
// #include <stdlib.h>
import "C"
import (
	"fmt"
	"math"
	"unsafe"
)

// Model represents a loaded GNN model.
type Model struct {
	ptr unsafe.Pointer
	// dummy marks randomly initialized ("__dummy__") weights. Dummy output
	// is noise: callers must never let it drive automatic verdicts or patch
	// planning — see IsDummy.
	dummy bool
}

// LoadModel loads a pretrained GNN model from a JSON weight file.
// Pass "__dummy__" to create a model with Xavier-initialized weights.
func LoadModel(path string) (*Model, error) {
	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	ptr := C.gnn_model_load(cPath)
	if ptr == nil {
		return nil, fmt.Errorf("failed to load GNN model from %s", path)
	}

	return &Model{ptr: ptr, dummy: path == "__dummy__"}, nil
}

// LoadDummyModel creates a model with Xavier-initialized weights (no file needed).
//
// The result is flagged as dummy (IsDummy) because its predictions are random
// outputs of a random network: they must only be used for plumbing tests,
// never for automatic verdicts or patch planning.
func LoadDummyModel() (*Model, error) {
	return LoadModel("__dummy__")
}

// IsDummy reports whether this model holds random dummy weights instead of
// trained ones. Dummy inference output must not feed automatic verdicts or
// patch planning.
func (m *Model) IsDummy() bool { return m.dummy }

// Close frees the model resources.
func (m *Model) Close() {
	if m.ptr != nil {
		C.gnn_model_free(m.ptr)
		m.ptr = nil
	}
}

// Infer runs the graph through the GNN and returns vulnerability probabilities.
func (m *Model) Infer(g *Graph) (*Prediction, error) {
	if m.ptr == nil {
		return nil, fmt.Errorf("model is closed")
	}
	if g == nil || g.NumNodes == 0 || g.FeatureDim == 0 || len(g.RowPtrs) == 0 || len(g.Features) == 0 {
		return nil, fmt.Errorf("empty graph")
	}
	maxInt := uint64(^uint(0) >> 1)
	if g.NumNodes >= maxInt || g.FeatureDim > maxInt || g.NumNodes > maxInt/g.FeatureDim {
		return nil, fmt.Errorf("feature matrix dimensions overflow: %d x %d", g.NumNodes, g.FeatureDim)
	}
	if uint64(len(g.RowPtrs)) != g.NumNodes+1 {
		return nil, fmt.Errorf("invalid CSR row_ptrs length: got %d want %d", len(g.RowPtrs), g.NumNodes+1)
	}
	expectedFeatures := g.NumNodes * g.FeatureDim
	if uint64(len(g.Features)) != expectedFeatures {
		return nil, fmt.Errorf("invalid feature matrix length: got %d want %d", len(g.Features), expectedFeatures)
	}
	if g.RowPtrs[0] != 0 || g.RowPtrs[len(g.RowPtrs)-1] != uint64(len(g.ColIndices)) {
		return nil, fmt.Errorf("CSR row_ptrs must span exactly %d column indices", len(g.ColIndices))
	}
	if len(g.EdgeTypes) > 0 && len(g.EdgeTypes) != len(g.ColIndices) {
		return nil, fmt.Errorf("invalid edge types length: got %d want %d", len(g.EdgeTypes), len(g.ColIndices))
	}
	// Per-element validation (row_ptr monotonicity, column bounds, finite
	// features, edge-type range) is intentionally NOT duplicated on the Go
	// side: Rust re-validates the entire tensor in prepare_graph_tensor
	// before touching it, and running the same O(nodes+edges) scans on both
	// sides of the FFI doubled the per-graph validation cost for well-formed
	// tensors from buildGNNGraph. Malformed tensors are still rejected — they
	// surface as an inference error from the native call below.

	// Copy every tensor array into C-allocated buffers: no Go pointers end
	// up inside C memory (or vice versa), so the GC can reclaim or scan
	// nothing behind the FFI's back while rayon threads read the tensors.
	cRowPtrs := (*C.uint64_t)(C.malloc(C.size_t(len(g.RowPtrs)) * C.size_t(unsafe.Sizeof(C.uint64_t(0)))))
	if cRowPtrs == nil {
		return nil, fmt.Errorf("out of memory")
	}
	copy(unsafe.Slice((*uint64)(unsafe.Pointer(cRowPtrs)), len(g.RowPtrs)), g.RowPtrs)
	defer C.free(unsafe.Pointer(cRowPtrs))

	var cColIndices *C.uint64_t
	if len(g.ColIndices) > 0 {
		cColIndices = (*C.uint64_t)(C.malloc(C.size_t(len(g.ColIndices)) * C.size_t(unsafe.Sizeof(C.uint64_t(0)))))
		if cColIndices == nil {
			return nil, fmt.Errorf("out of memory")
		}
		copy(unsafe.Slice((*uint64)(unsafe.Pointer(cColIndices)), len(g.ColIndices)), g.ColIndices)
		defer C.free(unsafe.Pointer(cColIndices))
	}

	cFeatures := (*C.float)(C.malloc(C.size_t(len(g.Features)) * C.size_t(unsafe.Sizeof(C.float(0)))))
	if cFeatures == nil {
		return nil, fmt.Errorf("out of memory")
	}
	copy(unsafe.Slice((*float32)(unsafe.Pointer(cFeatures)), len(g.Features)), g.Features)
	defer C.free(unsafe.Pointer(cFeatures))

	var cEdgeTypes *C.uint32_t
	if len(g.EdgeTypes) > 0 {
		cEdgeTypes = (*C.uint32_t)(C.malloc(C.size_t(len(g.EdgeTypes)) * C.size_t(unsafe.Sizeof(C.uint32_t(0)))))
		if cEdgeTypes == nil {
			return nil, fmt.Errorf("out of memory")
		}
		copy(unsafe.Slice((*uint32)(unsafe.Pointer(cEdgeTypes)), len(g.EdgeTypes)), g.EdgeTypes)
		defer C.free(unsafe.Pointer(cEdgeTypes))
	}

	// Allocate the struct in C memory to avoid Go cgo pointer-passing check panics
	cGraphPtr := (*C.ffi_graph_tensor_t)(C.malloc(C.size_t(unsafe.Sizeof(C.ffi_graph_tensor_t{}))))
	if cGraphPtr == nil {
		return nil, fmt.Errorf("out of memory")
	}
	defer C.free(unsafe.Pointer(cGraphPtr))

	cGraphPtr.row_ptrs = cRowPtrs
	cGraphPtr.row_ptrs_len = C.uint64_t(len(g.RowPtrs))
	cGraphPtr.col_indices = cColIndices
	cGraphPtr.col_indices_len = C.uint64_t(len(g.ColIndices))
	cGraphPtr.edge_types = cEdgeTypes
	cGraphPtr.edge_types_len = C.uint64_t(len(g.EdgeTypes))
	cGraphPtr.node_features = cFeatures
	cGraphPtr.num_nodes = C.uint64_t(g.NumNodes)
	cGraphPtr.feature_dim = C.uint64_t(g.FeatureDim)

	var outClasses C.uint64_t
	resultPtr := C.gnn_model_infer(m.ptr, cGraphPtr, &outClasses)
	if resultPtr == nil {
		return nil, fmt.Errorf("GNN inference failed")
	}

	defer C.gnn_free_result(resultPtr)

	classes := int(outClasses)
	if classes != NumVulnClasses {
		return nil, fmt.Errorf("GNN returned invalid class count %d, want %d", classes, NumVulnClasses)
	}
	resultSlice := (*[1 << 30]float32)(unsafe.Pointer(resultPtr))[:classes:classes]

	probs := make([]float32, classes)
	copy(probs, resultSlice)
	var probabilitySum float64
	for i, probability := range probs {
		if probability < 0 || probability > 1 || math.IsNaN(float64(probability)) || math.IsInf(float64(probability), 0) {
			return nil, fmt.Errorf("GNN returned invalid probability %v for class %d", probability, i)
		}
		probabilitySum += float64(probability)
	}
	if math.Abs(probabilitySum-1) > 1e-3 {
		return nil, fmt.Errorf("GNN returned probabilities summing to %.8f, want 1", probabilitySum)
	}

	// Find top class
	bestIdx := 0
	bestProb := probs[0]
	for i := 1; i < len(probs); i++ {
		if probs[i] > bestProb {
			bestProb = probs[i]
			bestIdx = i
		}
	}

	return &Prediction{
		ClassProbs:     probs,
		PredictedClass: VulnClass(bestIdx),
		Confidence:     bestProb,
	}, nil
}
