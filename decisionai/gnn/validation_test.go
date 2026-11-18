package gnn

import (
	"encoding/json"
	"math"
	"testing"
)

func TestLoadedGNNHasValidatedShapesAndExactIdentity(t *testing.T) {
	m := New([]string{"a", "b"}, 16, 4, 2, 1, 11)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(b)
	if err != nil || len(loaded.SHA256()) != 64 {
		t.Fatalf("valid model rejected: %v", err)
	}
	loaded.Wr[0] = loaded.Wr[0][:1]
	if loaded.Validate() == nil {
		t.Fatal("truncated layer accepted")
	}
	m.Bo[0] = math.Inf(1)
	if m.Validate() == nil {
		t.Fatal("non-finite weights accepted")
	}
	m.Bo[0] = 0
	m.Classes[1] = m.Classes[0]
	if m.Validate() == nil {
		t.Fatal("duplicate class accepted")
	}
	if _, err := Load([]byte("{}")); err == nil {
		t.Fatal("missing tensors accepted")
	}
}
