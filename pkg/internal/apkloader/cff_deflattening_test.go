package apkloader

import (
	"encoding/json"
	"testing"
)

func buildMinimalCFG(blockCount int) *CFG {
	cfg := &CFG{Blocks: make([]*BasicBlock, blockCount)}
	for i := range blockCount {
		cfg.Blocks[i] = &BasicBlock{ID: i}
	}
	if blockCount > 0 {
		cfg.Entry = cfg.Blocks[0]
	}
	return cfg
}

func TestCFFSkipsSmallCFG(t *testing.T) {
	cfg := buildMinimalCFG(3)
	mir := []MIRInsn{}
	result, ok := OffloadCFFDeflattening(cfg, mir)
	if ok || result != nil {
		t.Fatalf("Expected (nil, false) for small CFG, got (%v, %v)", result, ok)
	}
}

func TestCFFDeflattening_StructFields(t *testing.T) {
	jsonData := `{
		"dispatcher_block_id": 1,
		"state_var": 2,
		"proven_edges": [[1, 2], [2, 3]],
		"uncertain_blocks": [4, 5],
		"confidence": 95,
		"applied": true,
		"trace": ["note 1"]
	}`

	var cff CFFDeflattening
	if err := json.Unmarshal([]byte(jsonData), &cff); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if cff.DispatcherBlockID != 1 || cff.StateVar != 2 || cff.Confidence != 95 || !cff.Applied {
		t.Errorf("Unmarshaled data mismatch: %+v", cff)
	}
	if len(cff.ProvenEdges) != 2 || len(cff.UncertainBlocks) != 2 || len(cff.Trace) != 1 {
		t.Errorf("Unmarshaled slices mismatch: %+v", cff)
	}
}

func TestCFFDeflattening_NilCFG(t *testing.T) {
	result, ok := OffloadCFFDeflattening(nil, nil)
	if ok || result != nil {
		t.Fatalf("Expected (nil, false) for nil CFG, got (%v, %v)", result, ok)
	}
}

func TestCFFDeflattening_RustNotLinked(t *testing.T) {
	cfg := buildMinimalCFG(5)
	mir := []MIRInsn{}
	result, ok := OffloadCFFDeflattening(cfg, mir)
	if ok || result != nil {
		t.Fatalf("Expected (nil, false) when Rust is not linked, got (%v, %v)", result, ok)
	}
}
