//go:build cgo && omnisec_ml_gnn

// Tests are gated behind the `omnisec_ml_gnn` build tag because they
// require the Rust `omnisec-ml-gnn` cdylib to be present in
// `rust/target/release/`. CI without the cdylib should run `go test`
// without `-tags omnisec_ml_gnn` and skip this file entirely.
package gnn

import "testing"

func TestLoadModelMissingFile(t *testing.T) {
	if _, err := LoadModel("definitely-missing-model.bin"); err == nil {
		t.Error("LoadModel must surface error on missing path")
	}
}

func TestModelCloseSafeOnNil(t *testing.T) {
	m := &Model{}
	m.Close() // must not panic
}

func TestVulnClassName(t *testing.T) {
	tests := []struct {
		class VulnClass
		want  string
	}{
		{VulnBenign, "benign"},
		{VulnLicenseCheck, "license-check"},
		{VulnLicenseBypass, "license-bypass"},
		{VulnSignatureSpoof, "signature-spoof"},
		{VulnIntegrityTamper, "integrity-tamper"},
		{VulnRepackMarker, "repack-marker"},
		{VulnNativeBridge, "native-bridge"},
		{VulnDynamicLoad, "dynamic-load"},
		{VulnClass(99), "unknown"},
	}
	for _, tt := range tests {
		if got := VulnClassName(tt.class); got != tt.want {
			t.Errorf("VulnClassName(%d) = %q, want %q", tt.class, got, tt.want)
		}
	}
}

func TestDummyModelInfer(t *testing.T) {
	model, err := LoadDummyModel()
	if err != nil {
		t.Fatalf("failed to load dummy model: %v", err)
	}
	defer model.Close()

	// Create a simple graph: 3 nodes (0 -> 1 -> 2)
	// Node features dimension must match the Rust default model input
	// (36 since the v3 semantic slots were added).
	graph := &Graph{
		RowPtrs:    []uint64{0, 1, 2, 2},  // CSR row ptrs
		ColIndices: []uint64{1, 2},        // CSR column indices
		Features:   make([]float32, 3*36), // 3 nodes, 36 dims
		NumNodes:   3,
		FeatureDim: 36,
	}

	// Initialize features with some values
	for i := range graph.Features {
		graph.Features[i] = float32(i) * 0.01
	}

	pred, err := model.Infer(graph)
	if err != nil {
		t.Fatalf("inference failed: %v", err)
	}

	if len(pred.ClassProbs) != NumVulnClasses {
		t.Errorf("expected %d class probs, got %d", NumVulnClasses, len(pred.ClassProbs))
	}

	if pred.Confidence <= 0.0 || pred.Confidence > 1.0 {
		t.Errorf("invalid confidence: %f", pred.Confidence)
	}
}
