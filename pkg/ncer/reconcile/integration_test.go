//go:build cgo && omnisec_ncer_reconcile_ffi

// End-to-end integration test: exercises the Go→Rust FFI round-trip with a
// synthetic MitmCapture that has known, deterministic counts.
//
// Run with:
//
//	go test -tags 'cgo omnisec_ncer_reconcile_ffi' ./pkg/ncer/reconcile/...
//
// Prerequisites:
//
//	cd rust && cargo build -p omnisec-ncer-reconcile-ffi --release
package reconcile

import (
	"errors"
	"testing"
)

// syntheticCapture is a MitmCapture JSON string with:
//
//   - 2 HTTP requests
//   - 2 HTTP responses
//   - resp-a answers req-a (same method+url, within 5 s window) → 1 bound pair
//   - resp-b has no matching request → 1 unbound effect
//   - req-b never gets a response → 1 orphan request
//   - 0 DNS queries, 0 TLS handshakes, 0 flow summaries → 4 total events
//
// Expected scores:
//
//	effect_count     = bound(1) + unbound(1) = 2
//	d_causal         = 1/2 = 0.5
//	coverage_quality = 1/2 = 0.5
const syntheticCapture = `{
	"http_requests": [
		{
			"timestamp_ms": 1000,
			"method": "GET",
			"url": "/index.html",
			"headers": {}
		},
		{
			"timestamp_ms": 2000,
			"method": "POST",
			"url": "/login",
			"headers": {}
		}
	],
	"http_responses": [
		{
			"timestamp_ms": 1200,
			"status": 200,
			"headers": {},
			"request_method": "GET",
			"request_url": "/index.html"
		},
		{
			"timestamp_ms": 3500,
			"status": 404,
			"headers": {},
			"request_method": "GET",
			"request_url": "/missing.js"
		}
	],
	"dns_queries":    [],
	"tls_handshakes": [],
	"flow_summaries": []
}`

// TestIntegration_RunReconcile_SyntheticCapture exercises the full Go→Rust
// pipeline and verifies the returned counts and discrepancy scores against the
// known expected values of the syntheticCapture fixture.
func TestIntegration_RunReconcile_SyntheticCapture(t *testing.T) {
	result, err := RunReconcile([]byte(syntheticCapture))
	if err != nil {
		if errors.Is(err, ErrRustNotLinked) {
			t.Skip("native library not linked; skipping integration test")
		}
		t.Fatalf("RunReconcile failed: %v", err)
	}
	if result == nil {
		t.Fatal("RunReconcile returned nil result without error")
	}

	// Counts.
	if result.BoundCount != 1 {
		t.Errorf("BoundCount: got %d, want 1", result.BoundCount)
	}
	if result.UnboundCount != 1 {
		t.Errorf("UnboundCount: got %d, want 1", result.UnboundCount)
	}
	if result.OrphanCount != 1 {
		t.Errorf("OrphanCount: got %d, want 1 (POST /login has no response)", result.OrphanCount)
	}
	if result.TotalEvents != 4 {
		t.Errorf("TotalEvents: got %d, want 4 (2 requests + 2 responses)", result.TotalEvents)
	}

	// Discrepancy scores.
	const eps = float32(1e-5)
	if abs32(result.DCausal-0.5) > eps {
		t.Errorf("DCausal: got %g, want 0.5", result.DCausal)
	}
	if abs32(result.CoverageQuality-0.5) > eps {
		t.Errorf("CoverageQuality: got %g, want 0.5", result.CoverageQuality)
	}

	// Invariant: d_causal + coverage_quality == 1.0 when effect_count > 0.
	if abs32(result.DCausal+result.CoverageQuality-1.0) > eps {
		t.Errorf(
			"d_causal (%g) + coverage_quality (%g) should equal 1.0",
			result.DCausal, result.CoverageQuality,
		)
	}
}

// TestIntegration_EmptyCapture verifies that an empty MitmCapture returns
// all-zero counts and scores (the safe zero-value state).
func TestIntegration_EmptyCapture(t *testing.T) {
	const emptyCapture = `{"http_requests":[],"http_responses":[],"dns_queries":[],"tls_handshakes":[],"flow_summaries":[]}`

	result, err := RunReconcile([]byte(emptyCapture))
	if err != nil {
		if errors.Is(err, ErrRustNotLinked) {
			t.Skip("native library not linked; skipping integration test")
		}
		t.Fatalf("RunReconcile failed: %v", err)
	}

	if result.BoundCount != 0 || result.UnboundCount != 0 || result.OrphanCount != 0 {
		t.Errorf("expected all-zero counts for empty capture, got %+v", result)
	}
	if result.DCausal != 0.0 || result.CoverageQuality != 0.0 {
		t.Errorf("expected zero scores for empty capture, got d_causal=%g coverage=%g",
			result.DCausal, result.CoverageQuality)
	}
}

// TestIntegration_AuthorityEvents_ScoreDAuthorityAndDCapability exercises the
// flattened authority_events field end to end: an unauthorized observed
// action alongside an unused grant, both for the same subject, so
// d_authority and d_capability are both nonzero and independently
// verifiable against known counts.
func TestIntegration_AuthorityEvents_ScoreDAuthorityAndDCapability(t *testing.T) {
	const captureWithAuthority = `{
		"http_requests": [],
		"http_responses": [],
		"dns_queries": [],
		"tls_handshakes": [],
		"flow_summaries": [],
		"authority_events": [
			{
				"id": "grant-camera",
				"sensor_id": "manifest",
				"kind": "authority_grant",
				"observed_at_ms": 0,
				"subjects": ["com.example.app"],
				"description": "granted CAMERA",
				"score": 0.0,
				"attributes": {
					"subject_id": "com.example.app",
					"permission": "android.permission.CAMERA"
				},
				"evidence_refs": []
			},
			{
				"id": "obs-network",
				"sensor_id": "sandbox",
				"kind": "authority_observed",
				"observed_at_ms": 1000,
				"subjects": ["com.example.app"],
				"description": "network_connect",
				"score": 0.0,
				"attributes": {
					"subject_id": "com.example.app",
					"required_permission": "android.permission.INTERNET"
				},
				"evidence_refs": []
			}
		]
	}`

	result, err := RunReconcile([]byte(captureWithAuthority))
	if err != nil {
		if errors.Is(err, ErrRustNotLinked) {
			t.Skip("native library not linked; skipping integration test")
		}
		t.Fatalf("RunReconcile failed: %v", err)
	}

	// The grant is for CAMERA; the observed action requires INTERNET — no
	// overlap, so the action is fully unauthorized and the grant fully unused.
	if result.DAuthority != 1.0 {
		t.Errorf("DAuthority: got %g, want 1.0 (observed action had no matching grant)", result.DAuthority)
	}
	if result.DCapability != 1.0 {
		t.Errorf("DCapability: got %g, want 1.0 (grant was never exercised)", result.DCapability)
	}
	if result.TotalEvents != 2 {
		t.Errorf("TotalEvents: got %d, want 2 (1 grant + 1 observed action)", result.TotalEvents)
	}
}
