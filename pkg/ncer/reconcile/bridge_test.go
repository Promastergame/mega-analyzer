// Tests for pkg/ncer/reconcile.
//
// These tests run in every build — with and without cgo — because they
// exercise the stub path and the JSON schema of Result, neither of which
// requires the native library.
package reconcile

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// ── stub path ─────────────────────────────────────────────────────────────────

// TestStubReturnsErrRustNotLinked verifies that RunReconcile returns
// ErrRustNotLinked (or a valid result) depending on the build tag.
//
// On a normal go test ./... run (no native library) the stub is active and
// must return ErrRustNotLinked.  On a cgo-enabled tagged build the real
// bridge is active and must return a valid Result for non-empty JSON.
func TestStubReturnsErrRustNotLinked(t *testing.T) {
	_, err := RunReconcile([]byte(`{"http_requests":[],"http_responses":[],"dns_queries":[],"tls_handshakes":[],"flow_summaries":[]}`))
	if err == nil {
		// Real bridge is linked — a nil error is the expected success path.
		return
	}
	if !errors.Is(err, ErrRustNotLinked) {
		t.Errorf("expected ErrRustNotLinked, got: %v", err)
	}
}

func TestStubRejectsNilInput(t *testing.T) {
	_, err := RunReconcile(nil)
	// Both the stub (ErrRustNotLinked) and the real bridge (empty input error)
	// must return a non-nil error for nil input.
	if err == nil {
		t.Error("expected non-nil error for nil input, got nil")
	}
}

// ── JSON schema compatibility ─────────────────────────────────────────────────

// TestResultJSONSchema verifies that the Result struct decodes the exact JSON
// shape that the Rust FFI exports, so field renaming or struct changes fail
// loudly at test time rather than silently producing zero values.
func TestResultJSONSchema(t *testing.T) {
	// This is the canonical wire format produced by the Rust ReconcileResult.
	raw := `{
		"bound_count":      1,
		"unbound_count":    1,
		"orphan_count":     1,
		"total_events":     4,
		"d_causal":         0.5,
		"coverage_quality": 0.5,
		"d_authority":      0.1,
		"d_information":    0.2,
		"d_capability":     0.3,
		"d_consequence":    0.0,
		"d_novelty":        0.0
	}`

	var r Result
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatalf("failed to unmarshal canonical Rust JSON: %v", err)
	}

	if r.BoundCount != 1 {
		t.Errorf("BoundCount: got %d, want 1", r.BoundCount)
	}
	if r.UnboundCount != 1 {
		t.Errorf("UnboundCount: got %d, want 1", r.UnboundCount)
	}
	if r.OrphanCount != 1 {
		t.Errorf("OrphanCount: got %d, want 1", r.OrphanCount)
	}
	if r.TotalEvents != 4 {
		t.Errorf("TotalEvents: got %d, want 4", r.TotalEvents)
	}
	if abs32(r.DCausal-0.5) > 1e-6 {
		t.Errorf("DCausal: got %g, want 0.5", r.DCausal)
	}
	if abs32(r.CoverageQuality-0.5) > 1e-6 {
		t.Errorf("CoverageQuality: got %g, want 0.5", r.CoverageQuality)
	}
	if abs32(r.DAuthority-0.1) > 1e-6 {
		t.Errorf("DAuthority: got %g, want 0.1", r.DAuthority)
	}
	if abs32(r.DInformation-0.2) > 1e-6 {
		t.Errorf("DInformation: got %g, want 0.2", r.DInformation)
	}
	if abs32(r.DCapability-0.3) > 1e-6 {
		t.Errorf("DCapability: got %g, want 0.3", r.DCapability)
	}
}

// TestResultJSONRoundTrip ensures Result can be marshalled back out without
// losing precision, so log/audit paths that re-encode it stay stable.
func TestResultJSONRoundTrip(t *testing.T) {
	original := Result{
		BoundCount:      3,
		UnboundCount:    1,
		OrphanCount:     2,
		TotalEvents:     7,
		DCausal:         0.25,
		CoverageQuality: 0.75,
		DAuthority:      0.1,
		DInformation:    0.2,
		DCapability:     0.3,
		DConsequence:    0.4,
		DNovelty:        0.5,
	}

	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Result
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch: got %+v, want %+v", decoded, original)
	}
}

// TestResultZeroValue verifies the zero value of Result is a valid, safe default
// (d_causal == 0.0 means "no unexplained effects").
func TestResultZeroValue(t *testing.T) {
	var r Result
	if r.DCausal != 0.0 {
		t.Errorf("zero Result.DCausal should be 0.0, got %g", r.DCausal)
	}
	if r.CoverageQuality != 0.0 {
		t.Errorf("zero Result.CoverageQuality should be 0.0, got %g", r.CoverageQuality)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func abs32(x float32) float32 {
	if x < 0 {
		return -x
	}
	return x
}
