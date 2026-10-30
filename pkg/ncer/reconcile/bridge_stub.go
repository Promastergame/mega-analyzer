//go:build !cgo || !omnisec_ncer_reconcile_ffi

// Package reconcile exposes the NCER causal reconciliation pipeline to Go.
// This file is the stub that compiles when the native library is absent or
// cgo is disabled.  All functions return ErrRustNotLinked so callers can
// detect and gracefully skip the native path.
package reconcile

import (
	"fmt"
	"time"
)

// Result is the typed Go equivalent of the Rust ReconcileResult.
// JSON field names match the Rust serde output exactly.
// The struct is present in the stub so callers can reference the type
// unconditionally regardless of the build tag. See the real bridge's
// (bridge.go) doc comment for why there are no evidence fields here, and for
// the DConsequence/DNovelty note.
type Result struct {
	// BoundCount is the number of (request, response) pairs successfully
	// bound to each other.
	BoundCount int `json:"bound_count"`
	// UnboundCount is the number of effects (responses) with no matching
	// cause within the binding window.
	UnboundCount int `json:"unbound_count"`
	// OrphanCount is the number of requests that never got a matching
	// response within the window.
	OrphanCount int `json:"orphan_count"`
	// TotalEvents is the total number of TypedEvents produced by the parse step.
	TotalEvents int `json:"total_events"`
	// DCausal is the causal discrepancy score in [0.0, 1.0]: 0.0 means every
	// effect was explained, 1.0 means nothing was explained.
	DCausal float32 `json:"d_causal"`
	// CoverageQuality is the fraction of effects that had a matching cause,
	// in [0.0, 1.0].
	CoverageQuality float32 `json:"coverage_quality"`
	// DAuthority is the fraction of observed sensitive actions with no
	// corresponding granted permission, in [0.0, 1.0].
	DAuthority float32 `json:"d_authority"`
	// DInformation is the fraction of DNS resolutions with no matching
	// outbound flow within the binding window, in [0.0, 1.0].
	DInformation float32 `json:"d_information"`
	// DCapability is the fraction of granted permissions never exercised by
	// any observed action, in [0.0, 1.0].
	DCapability float32 `json:"d_capability"`
	// DConsequence is always 0 from Rust; see the Collector's own scoring.
	DConsequence float32 `json:"d_consequence"`
	// DNovelty is always 0 from Rust; see the Collector's own scoring.
	DNovelty float32 `json:"d_novelty"`
}

// ErrRustNotLinked is returned when the native Rust library is not linked.
// Callers should check errors.Is(err, ErrRustNotLinked) to detect this case
// and fall back gracefully.
var ErrRustNotLinked = fmt.Errorf("rust library not linked: rebuild with -tags 'cgo omnisec_ncer_reconcile_ffi'")

// RunReconcile is a stub that always returns ErrRustNotLinked.
// Build with -tags 'cgo omnisec_ncer_reconcile_ffi' to use the real bridge.
func RunReconcile(_ []byte) (*Result, error) {
	return nil, ErrRustNotLinked
}

// RunReconcileWindowed is a stub that always returns ErrRustNotLinked.
func RunReconcileWindowed(_ []byte, _ time.Duration) (*Result, error) {
	return nil, ErrRustNotLinked
}
