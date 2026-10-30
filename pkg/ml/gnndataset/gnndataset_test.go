package gnndataset

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWriterBasicRoundtrip writes one example and verifies it is readable.
func TestWriterBasicRoundtrip(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()

	ex := &Example{
		GraphHash:      "deadbeef",
		APKPath:        "test.apk",
		MethodName:     "Lcom/Foo;->bar()V",
		ScannedAt:      time.Now().UTC().Format(time.RFC3339),
		NumNodes:       3,
		FeatureDim:     2,
		RowPtrs:        []uint64{0, 1, 2, 3},
		ColIndices:     []uint64{1, 2, 0},
		EdgeTypes:      []uint32{0, 0, 0},
		Features:       [][]float32{{0.1, 0.2}, {0.3, 0.4}, {0.5, 0.6}},
		PredictedLabel: 2,
		LabelName:      "overflow",
		Confidence:     0.87,
		ClassProbs:     []float32{0.01, 0.05, 0.87, 0.02, 0.01, 0.01, 0.02, 0.01},
		LabelConfirmed: false,
	}
	if err := w.Append(ex); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected 1 shard file, got %v: %v", len(entries), err)
	}

	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var got Example
	if err := json.Unmarshal(data[:len(data)-1], &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.GraphHash != ex.GraphHash {
		t.Errorf("GraphHash mismatch: got %q want %q", got.GraphHash, ex.GraphHash)
	}
	if got.PredictedLabel != ex.PredictedLabel {
		t.Errorf("PredictedLabel mismatch: got %d want %d", got.PredictedLabel, ex.PredictedLabel)
	}
	if got.LabelName != ex.LabelName {
		t.Errorf("LabelName mismatch: got %q want %q", got.LabelName, ex.LabelName)
	}
}

// TestFlattenFeatures verifies the helper.
func TestFlattenFeatures(t *testing.T) {
	flat := []float32{1, 2, 3, 4, 5, 6}
	got := FlattenFeatures(flat, 3, 2)
	if got == nil {
		t.Fatal("FlattenFeatures returned nil")
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(got))
	}
	if got[1][0] != 3 || got[1][1] != 4 {
		t.Errorf("unexpected row 1: %v", got[1])
	}
	if FlattenFeatures(flat, 2, 2) != nil {
		t.Error("expected nil for dimension mismatch")
	}
}

// TestWriterShardsRotate verifies that a new shard is opened after the soft cap.
func TestWriterShardsRotate(t *testing.T) {
	dir := t.TempDir()
	w, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer w.Close()

	// Open the first shard before poking the counter: openShard resets
	// w.written to the on-disk size, so setting it on a closed writer was
	// silently clobbered and no rotation ever happened.
	seed := &Example{GraphHash: "seed", PredictedLabel: 0, LabelName: "other"}
	if err := w.Append(seed); err != nil {
		t.Fatalf("Append (seed): %v", err)
	}

	// Force rotation immediately by setting written just below cap.
	w.written = maxShardBytes - 1

	ex := &Example{GraphHash: "aa", PredictedLabel: 0, LabelName: "other"}
	if err := w.Append(ex); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// The second append should have triggered rotation.
	entries, _ := os.ReadDir(dir)
	if len(entries) < 2 {
		t.Errorf("expected 2 shards after rotation, got %d", len(entries))
	}
}
