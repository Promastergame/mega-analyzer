package apkloader

import "encoding/json"

// CFFDeflattening holds the result of a proof-based control-flow deflattening
// attempt on one method. It is returned by OffloadCFFDeflattening.
type CFFDeflattening struct {
	// DispatcherBlockID is the block index identified as the CFF dispatcher.
	DispatcherBlockID int `json:"dispatcher_block_id"`
	// StateVar is the register used as the state variable.
	StateVar int `json:"state_var"`
	// ProvenEdges lists directly proven (from_block_id, to_block_id) pairs.
	ProvenEdges [][2]int `json:"proven_edges"`
	// UncertainBlocks lists case-block IDs whose successors could not be proven.
	UncertainBlocks []int `json:"uncertain_blocks"`
	// Confidence is 0–100; rewrite is applied only when ≥ 90.
	Confidence int `json:"confidence"`
	// Applied is true when the CFG was actually rewritten.
	Applied bool `json:"applied"`
	// Trace contains human-readable analysis notes.
	Trace []string `json:"trace,omitempty"`
}

// OffloadCFFDeflattening sends the given CFG to the Rust deobfuscator's
// proof-based CFF deflattening pass. The second return value is false whenever
// the Rust library is unavailable or returns no useful result — callers should
// treat this as a no-op.
//
// When Applied is false but Confidence > 0, the caller can inspect ProvenEdges
// and UncertainBlocks for partial recovery evidence without applying rewrites.
func OffloadCFFDeflattening(cfg *CFG, mir []MIRInsn) (*CFFDeflattening, bool) {
	if cfg == nil || len(cfg.Blocks) < 4 {
		// Too small to be CFF — no dispatcher can have ≥3 successors meaningfully.
		return nil, false
	}
	// Pack the CFG into the JSON layout that DeobfuscateWithRust understands.
	// We reuse the existing DeobfuscateWithRust FFI (which runs all passes
	// including ControlFlowDeflattening) and extract the CFF stats from the
	// stats JSON. A future dedicated FFI call can replace this.
	rawJSON, err := DeobfuscateWithRustCFF(mir)
	if err != nil || len(rawJSON) == 0 {
		return nil, false
	}
	var result CFFDeflattening
	if err := json.Unmarshal(rawJSON, &result); err != nil {
		return nil, false
	}
	if result.Confidence == 0 && !result.Applied {
		return nil, false
	}
	return &result, true
}

// DeobfuscateWithRustCFF invokes the Rust CFF deflattening pass on the given
// MIR and returns the serialized CFFDeflattening JSON.
// Returns (nil, ErrRustNotLinked) when the native library is not available.
func DeobfuscateWithRustCFF(mir []MIRInsn) ([]byte, error) {
	// This calls through the same Rust FFI bridge used by DeobfuscateWithRust.
	// Stub: returns not-linked until the Rust side exports a dedicated symbol.
	return nil, ErrRustNotLinked
}
