//go:build cgo && omnisec_ncer_reconcile_ffi

// Package reconcile exposes the NCER causal reconciliation pipeline to Go via
// the omnisec-ncer-reconcile-ffi Rust shared library.
//
// Build with:
//
//	go build -tags 'cgo omnisec_ncer_reconcile_ffi' ./...
package reconcile

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../rust/target/release -lomnisec_ncer_reconcile_ffi
#include <stdint.h>
#include <stdlib.h>

// Run the full NCER causal reconciliation pipeline on a JSON-encoded MitmCapture.
// Returns 0 on success; negative on error.  On success *out is a heap-allocated
// null-terminated JSON string; the caller must free it with
// omnisec_ncer_reconcile_free.
extern int32_t omnisec_ncer_reconcile(const char* capture_json, char** out);

// Free a string previously returned by omnisec_ncer_reconcile.
extern void omnisec_ncer_reconcile_free(char* ptr);

// Run the full NCER pipeline with a caller-specified binding window.
// window_ms <= 0 falls back to the Rust-side DEFAULT_WINDOW (5 s).
extern int32_t omnisec_ncer_reconcile_windowed(const char* capture_json, int64_t window_ms, char** out);
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"time"
	"unsafe"
)

// Result is the typed Go equivalent of the Rust ReconcileResult struct.
// JSON field names match the Rust serde output exactly.
//
// The Rust FFI does not report evidence: omnisec_ncer_reconcile never calls
// into omnisec-ncer-evidence, so there are no evidence_refs/evidence_verified/
// evidence_count fields to decode here. Evidence tracking for the result the
// caller ultimately sees ([types.NcerCausalResult]) is computed independently
// by [Collector]'s own EvidenceStore in pkg/ncer/collect.go.
//
// As of v2.0 all seven DiscrepancyVector sub-dimensions are present.
// DAuthority/DCapability come from the Rust authority binder, DInformation
// from the Rust DNS/flow binder; DConsequence/DNovelty always decode as 0
// here because Rust never computes them — [Collector.Reconcile] overwrites
// them with values computed from Go-only data (AnomalyFinding severity, a
// fingerprint baseline) after decoding this struct.
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

// ErrRustNotLinked is returned by the stub when the native library is absent.
// Defined here so it is available in both the real bridge and in tests that
// check errors without linking the library.
var ErrRustNotLinked = fmt.Errorf("rust library not linked: rebuild with -tags 'cgo omnisec_ncer_reconcile_ffi'")

// RunReconcile serialises captureJSON (a JSON-encoded MitmCapture), calls the
// Rust reconciliation pipeline through the FFI, and returns a decoded Result.
//
// captureJSON must be a valid JSON object; RunReconcile returns an error for
// null inputs, invalid UTF-8, JSON decode failures, and any non-zero Rust
// status code.
func RunReconcile(captureJSON []byte) (*Result, error) {
	if len(captureJSON) == 0 {
		return nil, fmt.Errorf("ncer/reconcile: empty capture JSON")
	}

	cInput := C.CString(string(captureJSON))
	defer C.free(unsafe.Pointer(cInput))

	var cOut *C.char
	rc := C.omnisec_ncer_reconcile(cInput, &cOut)
	if rc != 0 {
		return nil, fmt.Errorf("ncer/reconcile: Rust returned status %d", rc)
	}
	defer C.omnisec_ncer_reconcile_free(cOut)

	jsonBytes := C.GoString(cOut)

	var r Result
	if err := json.Unmarshal([]byte(jsonBytes), &r); err != nil {
		return nil, fmt.Errorf("ncer/reconcile: decode result JSON: %w", err)
	}
	return &r, nil
}

// RunReconcileWindowed is like RunReconcile but uses the caller-supplied
// binding window instead of the Rust-side DEFAULT_WINDOW (5 s). A window of
// zero or negative falls back to the Rust default.
func RunReconcileWindowed(captureJSON []byte, window time.Duration) (*Result, error) {
	if len(captureJSON) == 0 {
		return nil, fmt.Errorf("ncer/reconcile: empty capture JSON")
	}

	cInput := C.CString(string(captureJSON))
	defer C.free(unsafe.Pointer(cInput))

	windowMS := window.Milliseconds()

	var cOut *C.char
	rc := C.omnisec_ncer_reconcile_windowed(cInput, C.int64_t(windowMS), &cOut)
	if rc != 0 {
		return nil, fmt.Errorf("ncer/reconcile: Rust returned status %d", rc)
	}
	defer C.omnisec_ncer_reconcile_free(cOut)

	jsonBytes := C.GoString(cOut)

	var r Result
	if err := json.Unmarshal([]byte(jsonBytes), &r); err != nil {
		return nil, fmt.Errorf("ncer/reconcile: decode result JSON: %w", err)
	}
	return &r, nil
}
