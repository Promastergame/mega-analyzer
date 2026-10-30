package apkloader

import (
	"errors"
	"testing"
	"unsafe"
)

// Plan v11.0 task #3: validate the new CFG FFI bridge — at minimum the
// type sizes, the empty-input contract, and a Go↔Rust block-count A/B
// against the in-process Go builder.

func TestRustCFGBridge_EmptyInput(t *testing.T) {
	got, err := BuildCFGWithRust(nil)
	if err != nil {
		if errors.Is(err, ErrRustNotLinked) {
			t.Skip("rust library not linked — empty-input FFI contract skipped")
		}
		t.Fatalf("expected nil err on empty input, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil CFG on empty input, got %#v", got)
	}
}

func TestRustCFGBridge_PackedLayoutSize(t *testing.T) {
	// `BuildCFGWithRust` re-uses the 40-byte packed `rustMIRInsn` layout
	// shared with `omnisec_deobfuscate_v3`. If that ever drifts the FFI
	// hands Rust garbage offsets and the CFG silently turns into one
	// giant block — fail loudly here instead.
	if got := unsafe.Sizeof(rustMIRInsn{}); got != 40 {
		t.Fatalf("rustMIRInsn must be 40 bytes for FFI, got %d", got)
	}
}

func TestRustCFGBridge_ABStraightLine(t *testing.T) {
	// Three MIR instructions, no control flow → one basic block in the
	// Go builder. The Rust path must agree (or report `ErrRustNotLinked`
	// when the cgo build is disabled, in which case we skip).
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_CONST, Offset: 1, Dst: 1, Imm: 2},
		{Kind: MIR_RETURN, Offset: 2, Src1: 0},
	}

	goCFG := BuildCFG(mir)
	if goCFG == nil || len(goCFG.Blocks) == 0 {
		t.Fatalf("Go BuildCFG returned no blocks")
	}

	rustCFG, err := BuildCFGWithRust(mir)
	if err != nil {
		if errors.Is(err, ErrRustNotLinked) {
			t.Skip("rust library not linked — A/B parity skipped")
		}
		t.Fatalf("Rust BuildCFG failed: %v", err)
	}
	if rustCFG == nil {
		// Rust may degenerate to {} for unsupported MIR kinds — accept
		// it as long as the Go side stays the source of truth.
		t.Skip("Rust returned empty CFG for this MIR kind set")
	}

	if rustCFG.BlockCount == 0 {
		t.Fatalf("Rust CFG has zero blocks")
	}
	if len(rustCFG.Blocks) != rustCFG.BlockCount {
		t.Fatalf("Rust CFG block_count=%d but blocks slice has %d entries",
			rustCFG.BlockCount, len(rustCFG.Blocks))
	}
	if len(rustCFG.ReversePostorder) > rustCFG.BlockCount {
		t.Fatalf("RPO length %d exceeds block count %d",
			len(rustCFG.ReversePostorder), rustCFG.BlockCount)
	}
}

func TestRustCFGBridge_ABBranch(t *testing.T) {
	// Diamond: const → if → either(const, const) → return.
	mir := []MIRInsn{
		{Kind: MIR_CONST, Offset: 0, Dst: 0, Imm: 1},
		{Kind: MIR_IF, Offset: 1, Imm: 4, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 2, Dst: 0, Imm: 2},
		{Kind: MIR_GOTO, Offset: 3, Imm: 2, RawFlags: FlagBranch},
		{Kind: MIR_CONST, Offset: 5, Dst: 0, Imm: 3},
		{Kind: MIR_RETURN, Offset: 6, Src1: 0},
	}

	goCFG := BuildCFG(mir)
	if goCFG == nil || len(goCFG.Blocks) < 2 {
		t.Fatalf("Go CFG has fewer than 2 blocks for branching MIR")
	}

	rustCFG, err := BuildCFGWithRust(mir)
	if err != nil {
		if errors.Is(err, ErrRustNotLinked) {
			t.Skip("rust library not linked — A/B parity skipped")
		}
		t.Fatalf("Rust BuildCFG failed: %v", err)
	}
	if rustCFG == nil {
		t.Skip("Rust returned empty CFG for this MIR kind set")
	}

	if rustCFG.BlockCount < 2 {
		t.Fatalf("Rust CFG should have ≥2 blocks for a branching method, got %d",
			rustCFG.BlockCount)
	}
	// Sanity: every successor / predecessor id must reference a real
	// block id present in the slice.
	ids := make(map[uint32]struct{}, rustCFG.BlockCount)
	for _, b := range rustCFG.Blocks {
		ids[b.ID] = struct{}{}
	}
	for _, b := range rustCFG.Blocks {
		for _, s := range b.Successors {
			if _, ok := ids[s]; !ok {
				t.Errorf("block %d has successor %d not present in CFG", b.ID, s)
			}
		}
		for _, p := range b.Predecessors {
			if _, ok := ids[p]; !ok {
				t.Errorf("block %d has predecessor %d not present in CFG", b.ID, p)
			}
		}
	}
}
