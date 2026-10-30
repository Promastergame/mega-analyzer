package apkloader

import (
	"encoding/json"
	"errors"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RUST FFI OFFLOAD LAYER (plan_dex_loader v11.0 task #3)
// ═══════════════════════════════════════════════════════════════════════════════
//
// High-level, production-safe wrappers around the low-level Rust FFI shims
// in `rust_bridge.go` / `rust_bridge_stub.go`. These helpers:
//
//   • Translate Go-side analysis structures (CFG, MIR) into the packed FFI
//     layouts expected by the Rust crates.
//   • Always return successfully even when the Rust libraries are not linked
//     (the cgo build tag is off, or the DLL is missing) — `ok=false` signals
//     that callers should fall back to the in-process Go pipeline.
//   • Never panic. Malformed Rust output, decode errors, and `ErrRustNotLinked`
//     are all flattened to `ok=false`.
//
// The deobfuscation pipeline opts into these via the new `UseRustCFG`,
// `UseRustSymbolic`, and `UseRustVirtDetection` config flags. Tests / tools
// can also call them directly.

// RustSymbolicSnapshot is the lightweight JSON shape produced by the
// `omnisec-analysis-symbolic` crate. Only the fields actually consumed
// downstream are listed — extra keys are ignored.
type RustSymbolicSnapshot struct {
	PathCount   int      `json:"path_count"`
	PrunedPaths int      `json:"pruned_paths"`
	MaxDepth    int      `json:"max_depth"`
	Constraints int      `json:"constraints"`
	Notes       []string `json:"notes,omitempty"`
	Error       string   `json:"error,omitempty"`
	// Raw is the original JSON, retained so callers can pass it through to
	// reports without forcing this Go side to mirror the entire schema.
	Raw json.RawMessage `json:"-"`
}

// RustVirtSnapshot mirrors the public surface of
// `omnisec-analysis-virt`'s detection report.
type RustVirtSnapshot struct {
	Stats struct {
		Dispatcher  int `json:"dispatcher"`
		Interpreter int `json:"interpreter"`
		CustomVM    int `json:"custom_vm"`
	} `json:"stats"`
	Patterns []struct {
		Kind       string `json:"kind"`
		BlockID    uint32 `json:"block_id"`
		Confidence int    `json:"confidence"`
	} `json:"patterns"`
	Error string          `json:"error,omitempty"`
	Raw   json.RawMessage `json:"-"`
}

// OffloadBuildCFG hands `mir` to the Rust CFG builder. The second return
// value is `false` whenever the Go pipeline should fall back to its own
// `BuildCFG` — this includes `ErrRustNotLinked`, empty Rust output, and
// any decode failure.
func OffloadBuildCFG(mir []MIRInsn) (*RustCFG, bool) {
	if len(mir) == 0 {
		return nil, false
	}
	cfg, err := BuildCFGWithRust(mir)
	if err != nil {
		return nil, false
	}
	if cfg == nil || cfg.BlockCount == 0 || len(cfg.Blocks) == 0 {
		return nil, false
	}
	return cfg, true
}

// OffloadSymbolicExecute converts a Go CFG into the FFI block layout and
// runs symbolic execution in Rust. Limits default to the same values as
// `NewSymbolicExecutor`; callers can override with the optional args.
//
// Returns `(snapshot, true)` only if Rust produced parseable JSON without
// an error key. `(nil, false)` is the universal "fall back to Go" signal.
func OffloadSymbolicExecute(cfg *CFG, ssa *SSAForm, maxDepth, maxPaths int) (*RustSymbolicSnapshot, bool) {
	if cfg == nil || len(cfg.Blocks) == 0 || cfg.Entry == nil {
		return nil, false
	}
	if maxDepth <= 0 {
		maxDepth = 10
	}
	if maxPaths <= 0 {
		maxPaths = 100
	}

	blocks := cfgToFfiBlocks(cfg)
	if len(blocks) == 0 {
		return nil, false
	}

	regCount := uint32(16)
	if ssa != nil && ssa.OriginalRegCount > 0 {
		regCount = uint32(ssa.OriginalRegCount)
	}

	raw, err := SymbolicExecuteWithRust(blocks, uint32(cfg.Entry.ID), regCount, uint32(maxDepth), uint32(maxPaths))
	if err != nil {
		if errors.Is(err, ErrRustNotLinked) {
			return nil, false
		}
		return nil, false
	}
	if len(raw) == 0 {
		return nil, false
	}

	var snap RustSymbolicSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, false
	}
	if snap.Error != "" {
		return nil, false
	}
	snap.Raw = raw
	return &snap, true
}

// OffloadDetectVirtualization runs the Rust virtualization detector
// against the Go CFG. `confidenceThreshold` mirrors the Go detector's
// `ConfidenceThreshold` (0–100).
func OffloadDetectVirtualization(cfg *CFG, confidenceThreshold uint8) (*RustVirtSnapshot, bool) {
	if cfg == nil || len(cfg.Blocks) == 0 {
		return nil, false
	}

	blocks := cfgToFfiVirtBlocks(cfg)
	if len(blocks) == 0 {
		return nil, false
	}

	raw, err := DetectVirtualizationWithRust(blocks, confidenceThreshold)
	if err != nil {
		return nil, false
	}
	if len(raw) == 0 {
		return nil, false
	}

	var snap RustVirtSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, false
	}
	if snap.Error != "" {
		return nil, false
	}
	snap.Raw = raw
	return &snap, true
}

// cfgToFfiBlocks projects a Go CFG onto the symbolic FFI layout. Block
// IDs are remapped from Go's slice index to a uint32 starting at 1 so
// that 0 stays reserved as "no block".
func cfgToFfiBlocks(cfg *CFG) []FfiBlock {
	if cfg == nil || len(cfg.Blocks) == 0 {
		return nil
	}
	idMap := make(map[*BasicBlock]uint32, len(cfg.Blocks))
	for i, b := range cfg.Blocks {
		if b == nil {
			continue
		}
		idMap[b] = uint32(i + 1)
	}

	out := make([]FfiBlock, 0, len(cfg.Blocks))
	for _, b := range cfg.Blocks {
		if b == nil {
			continue
		}
		insns := make([]FfiMirInsn, 0, len(b.Insns))
		for _, m := range b.Insns {
			insns = append(insns, FfiMirInsn{
				Kind:   uint8(m.Kind),
				Cond:   uint8(m.Cond),
				Dst:    m.Dst,
				Src1:   m.Src1,
				Src2:   m.Src2,
				Imm:    m.Imm,
				RefIdx: m.RefIdx,
			})
		}
		succs := make([]uint32, 0, len(b.Succs))
		for _, s := range b.Succs {
			if id, ok := idMap[s]; ok {
				succs = append(succs, id)
			}
		}
		out = append(out, FfiBlock{
			ID:    idMap[b],
			Insns: insns,
			Succs: succs,
		})
	}
	return out
}

// cfgToFfiVirtBlocks is the virt-detection variant — the FFI insn layout
// drops the `Cond` byte but is otherwise the same shape.
func cfgToFfiVirtBlocks(cfg *CFG) []FfiVirtBlock {
	if cfg == nil || len(cfg.Blocks) == 0 {
		return nil
	}
	idMap := make(map[*BasicBlock]uint32, len(cfg.Blocks))
	for i, b := range cfg.Blocks {
		if b == nil {
			continue
		}
		idMap[b] = uint32(i + 1)
	}

	out := make([]FfiVirtBlock, 0, len(cfg.Blocks))
	for _, b := range cfg.Blocks {
		if b == nil {
			continue
		}
		insns := make([]FfiVirtInsn, 0, len(b.Insns))
		for _, m := range b.Insns {
			insns = append(insns, FfiVirtInsn{
				Kind:   uint8(m.Kind),
				Dst:    m.Dst,
				Src1:   m.Src1,
				Src2:   m.Src2,
				Imm:    m.Imm,
				RefIdx: m.RefIdx,
			})
		}
		succs := make([]uint32, 0, len(b.Succs))
		for _, s := range b.Succs {
			if id, ok := idMap[s]; ok {
				succs = append(succs, id)
			}
		}
		out = append(out, FfiVirtBlock{
			ID:    idMap[b],
			Insns: insns,
			Succs: succs,
		})
	}
	return out
}
