package apkloader

import (
	"testing"
)

// Plan v11.0 task #3: validate the high-level offload wrappers.
//
// These tests deliberately do **not** require the Rust DLLs to be linked.
// The contract is: when Rust is unavailable (or returns nothing useful)
// the offload helpers must report `ok=false` instead of crashing, so the
// caller can fall back to the in-process Go pipeline.

func TestOffloadBuildCFG_EmptyInput(t *testing.T) {
	got, ok := OffloadBuildCFG(nil)
	if got != nil {
		t.Fatalf("expected nil CFG on empty input, got %#v", got)
	}
	if ok {
		t.Fatalf("expected ok=false on empty input")
	}
}

func TestOffloadBuildCFG_FallbackSafe(t *testing.T) {
	// Even with a real MIR slice the Rust path may be unavailable
	// (build tag, missing DLL, decode failure). The contract is: never
	// panic, return ok=false on failure.
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_RETURN, Offset: 1, Src1: 0},
	}
	cfg, ok := OffloadBuildCFG(mir)
	if !ok {
		// Rust path unavailable — that is exactly the case we are
		// validating. Just ensure we got a clean nil back.
		if cfg != nil {
			t.Fatalf("ok=false but cfg=%#v", cfg)
		}
		return
	}
	// Rust *is* available — sanity check the shape.
	if cfg == nil || cfg.BlockCount == 0 {
		t.Fatalf("ok=true but cfg is empty: %#v", cfg)
	}
	if len(cfg.Blocks) != cfg.BlockCount {
		t.Fatalf("block_count=%d but len(Blocks)=%d", cfg.BlockCount, len(cfg.Blocks))
	}
}

func TestOffloadSymbolicExecute_NilCFG(t *testing.T) {
	snap, ok := OffloadSymbolicExecute(nil, nil, 0, 0)
	if ok || snap != nil {
		t.Fatalf("expected (nil,false) for nil CFG, got (%v,%v)", snap, ok)
	}
}

func TestOffloadDetectVirtualization_NilCFG(t *testing.T) {
	snap, ok := OffloadDetectVirtualization(nil, 50)
	if ok || snap != nil {
		t.Fatalf("expected (nil,false) for nil CFG, got (%v,%v)", snap, ok)
	}
}

func TestOffloadSymbolicExecute_FallbackSafe(t *testing.T) {
	// Build a tiny CFG by hand so we don't depend on BuildCFG's quirks
	// for switch / branch handling in this test.
	b := &BasicBlock{
		ID: 0,
		Insns: []MIRInsn{
			{Kind: MIR_CONST, Dst: 0, Imm: 42},
			{Kind: MIR_RETURN, Src1: 0},
		},
	}
	cfg := &CFG{Blocks: []*BasicBlock{b}, Entry: b}
	ssa := &SSAForm{OriginalRegCount: 4}

	snap, ok := OffloadSymbolicExecute(cfg, ssa, 10, 64)
	if !ok {
		// Rust path off — make sure we got a clean refusal.
		if snap != nil {
			t.Fatalf("ok=false but snap=%#v", snap)
		}
		return
	}
	if snap == nil {
		t.Fatalf("ok=true but snap is nil")
	}
}

func TestOffloadDetectVirtualization_FallbackSafe(t *testing.T) {
	b := &BasicBlock{
		ID:    0,
		Insns: []MIRInsn{{Kind: MIR_SWITCH, Src1: 0}},
	}
	cfg := &CFG{Blocks: []*BasicBlock{b}, Entry: b}

	snap, ok := OffloadDetectVirtualization(cfg, 50)
	if !ok {
		if snap != nil {
			t.Fatalf("ok=false but snap=%#v", snap)
		}
		return
	}
	if snap == nil {
		t.Fatalf("ok=true but snap is nil")
	}
}

func TestCfgToFfiBlocks_StableIDs(t *testing.T) {
	b0 := &BasicBlock{ID: 0, Insns: []MIRInsn{{Kind: MIR_GOTO, Imm: 1}}}
	b1 := &BasicBlock{ID: 1, Insns: []MIRInsn{{Kind: MIR_RETURN}}}
	b0.Succs = []*BasicBlock{b1}
	cfg := &CFG{Blocks: []*BasicBlock{b0, b1}, Entry: b0}

	got := cfgToFfiBlocks(cfg)
	if len(got) != 2 {
		t.Fatalf("expected 2 FFI blocks, got %d", len(got))
	}
	// IDs must be remapped to 1..N (0 reserved as "no block").
	if got[0].ID == 0 || got[1].ID == 0 {
		t.Fatalf("FFI IDs must be > 0, got %v", []uint32{got[0].ID, got[1].ID})
	}
	if got[0].ID == got[1].ID {
		t.Fatalf("FFI IDs must be unique, both = %d", got[0].ID)
	}
	// b0's only successor must point to b1's remapped ID.
	if len(got[0].Succs) != 1 || got[0].Succs[0] != got[1].ID {
		t.Fatalf("expected b0.Succs=[%d], got %v", got[1].ID, got[0].Succs)
	}
}
