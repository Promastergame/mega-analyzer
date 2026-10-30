//! C FFI surface for the NCER causal reconciliation pipeline.
//!
//! Exported functions:
//!
//! * [`omnisec_ncer_reconcile`] — accepts a JSON-serialised `ReconcileInput`
//!   (a [`MitmCapture`] flattened with an optional `authority_events` array;
//!   plain `MitmCapture` JSON still decodes, with `authority_events`
//!   defaulting to empty), runs `run_pipeline` — [`from_mitm_capture`]
//!   plus `authority_events` fed through `bind_effects`, `bind_authority`,
//!   and `bind_dns_flow`, combined by `score_all` — and returns a
//!   JSON-encoded [`ReconcileResult`] carrying all five Rust-computed
//!   `DiscrepancyVector` dimensions. The caller must free the returned
//!   string with [`omnisec_ncer_reconcile_free`]. Uses `DEFAULT_WINDOW`
//!   (5s) for both the causal and DNS/flow binding windows.
//!
//! * [`omnisec_ncer_reconcile_windowed`] — identical to
//!   [`omnisec_ncer_reconcile`] but takes an explicit `window_ms`;
//!   `window_ms <= 0` falls back to `DEFAULT_WINDOW`.
//!
//! * [`omnisec_ncer_reconcile_free`] — deallocates a string previously
//!   returned by this library.
//!
//! # Status codes
//!
//! Functions that can fail return an `i32`:
//!
//! | value | meaning |
//! |---|---|
//! | `0` | success (output pointer is valid JSON) |
//! | `-1` | null input pointer |
//! | `-2` | invalid UTF-8 in input |
//! | `-3` | JSON deserialisation error |
//! | `-4` | output could not be encoded |

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::Duration;

use omnisec_json::{FromJson, ToJson};
use omnisec_mitm::capture::MitmCapture;
use omnisec_ncer_parse_net::from_mitm_capture;
use omnisec_ncer_reconcile::{
    BindingResult, DiscrepancyVector, bind_authority, bind_dns_flow, bind_effects, score_all,
};
use omnisec_ncer_types::TypedEvent;

/// JSON input accepted by [`omnisec_ncer_reconcile`] and
/// [`omnisec_ncer_reconcile_windowed`].
///
/// `MitmCapture`'s fields (`http_requests`, `http_responses`, `dns_queries`,
/// `tls_handshakes`, `flow_summaries`) are flattened to the top level so
/// existing capture-only callers need no wrapper object at all — the
/// optional `authority_events` field (populated by
/// `pkg/ncer.FromAuthorityContext`'s per-action variant, see
/// `pkg/ncer/authority.go`) simply defaults to empty when absent, which is
/// exactly the v1.0 wire shape. A v1.0 caller therefore keeps working
/// unmodified; it just gets `d_authority`/`d_capability` fixed at `0.0`
/// (no authority events to bind) instead of "always zero by design".
#[derive(Debug, FromJson)]
struct ReconcileInput {
    #[json(flatten)]
    capture: MitmCapture,
    #[json(default)]
    authority_events: Vec<TypedEvent>,
}

// ─── Default binding window ────────────────────────────────────────────────
//
// Five seconds covers normal HTTP round-trips measured in `omnisec-mitm`'s
// test suite. Callers that need a different window can be given a separate
// entry-point in a future revision.
const DEFAULT_WINDOW: Duration = Duration::from_secs(5);

// ─── Wire result type ──────────────────────────────────────────────────────

/// JSON-encoded result returned by [`omnisec_ncer_reconcile`].
///
/// Field names are snake_case to match `BindingResult` and
/// `DiscrepancyVector`'s serde output so downstream Go structs can embed the
/// same tags without any renaming.
///
/// As of v2.0, all seven [`DiscrepancyVector`] sub-dimensions cross the FFI
/// boundary: `d_authority`/`d_capability` come from the authority binder
/// (see `omnisec-ncer-reconcile::authority_binder`), `d_information` from the
/// DNS/flow binder (`omnisec-ncer-reconcile::dns_flow_binder`), and
/// `d_consequence`/`d_novelty` are always `0.0` here because they are
/// computed on the Go side from data (`AnomalyFinding` severity, a
/// per-target fingerprint baseline) that never crosses into Rust — see
/// `pkg/ncer/consequence.go` and `pkg/ncer/novelty.go`.
#[derive(Debug, ToJson, FromJson)]
pub struct ReconcileResult {
    /// Number of `(request_id, response_id)` pairs that were successfully
    /// bound to each other.
    pub bound_count: usize,
    /// Number of effects (responses) that had no matching cause within the
    /// binding window.
    pub unbound_count: usize,
    /// Number of requests that never got a matching response within the window.
    pub orphan_count: usize,
    /// Total number of [`TypedEvent`]s produced by the parse step.
    pub total_events: usize,
    /// Causal discrepancy score in `[0.0, 1.0]`.  `0.0` means every effect
    /// was explained; `1.0` means nothing was explained.
    pub d_causal: f32,
    /// Fraction of effects that had a matching cause, in `[0.0, 1.0]`.
    pub coverage_quality: f32,
    /// Authority discrepancy: fraction of observed sensitive actions that had
    /// no corresponding granted permission. `0.0` when no authority events
    /// were present in the capture.
    pub d_authority: f32,
    /// Information discrepancy: fraction of DNS resolutions that had no
    /// matching outbound flow within the binding window (a resolved host
    /// that was never actually connected to, or vice versa).
    pub d_information: f32,
    /// Capability discrepancy: fraction of granted permissions that were
    /// never exercised by any observed action (excess/unused authority).
    pub d_capability: f32,
    /// Consequence discrepancy — always `0.0` from Rust; computed on the Go
    /// side from `AnomalyFinding` severity (see module doc).
    pub d_consequence: f32,
    /// Novelty discrepancy — always `0.0` from Rust; computed on the Go side
    /// from a fingerprint baseline (see module doc).
    pub d_novelty: f32,
}

impl ReconcileResult {
    fn from_parts(
        binding: &BindingResult,
        scores: &DiscrepancyVector,
        total_events: usize,
    ) -> Self {
        Self {
            bound_count: binding.bound_pairs.len(),
            unbound_count: binding.unbound_effects.len(),
            orphan_count: binding.orphan_requests.len(),
            total_events,
            d_causal: scores.d_causal,
            coverage_quality: scores.coverage_quality,
            d_authority: scores.d_authority,
            d_information: scores.d_information,
            d_capability: scores.d_capability,
            d_consequence: scores.d_consequence,
            d_novelty: scores.d_novelty,
        }
    }
}

// ─── Internal helpers ──────────────────────────────────────────────────────

/// Convert a Rust-owned `String` into a `*mut c_char` that the C caller owns.
///
/// Returns `null` only if the string contains interior NUL bytes (should
/// never happen for serde_json output).
fn into_raw(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => {
            // Fall back to a safe error payload.
            match CString::new("{\"error\":\"nul_in_output\"}") {
                Ok(c) => c.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
    }
}

// ─── Exported C API ────────────────────────────────────────────────────────

/// Run the full NCER causal reconciliation pipeline on a JSON-serialised
/// `MitmCapture`.
///
/// # Parameters
///
/// * `capture_json` — pointer to a null-terminated UTF-8 string containing a
///   JSON-encoded `MitmCapture`.  Must not be NULL.
/// * `out` — on success (`return value == 0`) this is set to a pointer to a
///   null-terminated JSON string encoding a `ReconcileResult`.  The caller
///   **must** free it with [`omnisec_ncer_reconcile_free`].
///   On failure this is set to NULL.
///
/// # Return value
///
/// `0` on success; one of the negative status codes listed in the module doc
/// on failure.
///
/// # Safety
///
/// `capture_json` must be either NULL or a valid pointer to a null-terminated
/// C string for the duration of this call.  `out` must be a valid non-NULL
/// pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_ncer_reconcile(
    capture_json: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    // Safety: caller contract requires out to be non-NULL.
    unsafe {
        *out = std::ptr::null_mut();
    }

    if capture_json.is_null() {
        return -1;
    }

    let json_str = match unsafe { CStr::from_ptr(capture_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let input: ReconcileInput = match omnisec_json::from_json_str(json_str) {
        Ok(c) => c,
        Err(_) => return -3,
    };

    let result = run_pipeline(input, DEFAULT_WINDOW);

    let json_out = omnisec_json::to_json_string(&result);

    unsafe {
        *out = into_raw(json_out);
    }
    0
}

/// Run the full NCER causal reconciliation pipeline with a caller-specified
/// binding window.
///
/// # Parameters
///
/// * `capture_json` — pointer to a null-terminated UTF-8 string containing a
///   JSON-encoded `MitmCapture`.  Must not be NULL.
/// * `window_ms` — binding window in milliseconds.  Values ≤ 0 fall back to
///   `DEFAULT_WINDOW` (5 s).  Capped at `u64::MAX / 1_000_000` ns to avoid
///   overflow when converting to `Duration`.
/// * `out` — on success set to a heap-allocated JSON string; the caller must
///   free it with [`omnisec_ncer_reconcile_free`].  NULL on failure.
///
/// # Return value
///
/// Same status codes as [`omnisec_ncer_reconcile`].
///
/// # Safety
///
/// Same contract as [`omnisec_ncer_reconcile`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_ncer_reconcile_windowed(
    capture_json: *const c_char,
    window_ms: i64,
    out: *mut *mut c_char,
) -> i32 {
    unsafe {
        *out = std::ptr::null_mut();
    }

    if capture_json.is_null() {
        return -1;
    }

    let window = if window_ms <= 0 {
        DEFAULT_WINDOW
    } else {
        Duration::from_millis(window_ms as u64)
    };

    let json_str = match unsafe { CStr::from_ptr(capture_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let input: ReconcileInput = match omnisec_json::from_json_str(json_str) {
        Ok(c) => c,
        Err(_) => return -3,
    };

    let result = run_pipeline(input, window);

    let json_out = omnisec_json::to_json_string(&result);

    unsafe {
        *out = into_raw(json_out);
    }
    0
}

/// Below this many total events, `run_pipeline` binds serially rather than
/// spawning a thread per binder. Measured on `BenchmarkReconciliation_Combined_*`
/// in `pkg/ncer/bench_test.go` (see docs/benchmarks/ncer_performance.md):
/// `bind_effects` does the bulk of the work in a typical capture (it handles
/// the HTTP causal events, usually the largest share), so the other two
/// threads finish early and the win is bounded by how much `bind_effects`
/// alone can be overlapped with them. At 1,000 events parallel bind lost to
/// serial by ~10-15%; at 10,000 and 30,000 events the two were within noise
/// of each other; at 100,000 events parallel won by ~8-10%. 50,000 sits in
/// the untested gap between the last wash and the first clear win — picked
/// as a conservative midpoint rather than the true crossover, which wasn't
/// pinned down further.
const PARALLEL_BINDER_THRESHOLD: usize = 50_000;

/// Runs `from_mitm_capture` → the three binders → `score_all` for a decoded
/// [`ReconcileInput`], returning the combined [`ReconcileResult`]. Shared by
/// [`omnisec_ncer_reconcile`] and [`omnisec_ncer_reconcile_windowed`] so both
/// entry points stay consistent as new binders are added.
///
/// The three binders (`bind_effects`, `bind_authority`, `bind_dns_flow`) each
/// take only a shared `&[TypedEvent]` and touch disjoint `EventKind`
/// subsets, so they have no data dependency on each other. Once a capture is
/// large enough (see [`PARALLEL_BINDER_THRESHOLD`]), running them on separate
/// threads via `std::thread::scope` overlaps their work and wins overall;
/// below that size the fixed cost of spawning three threads exceeds what
/// overlapping saves, so binding stays serial.
fn run_pipeline(input: ReconcileInput, window: Duration) -> ReconcileResult {
    let mut events = from_mitm_capture(&input.capture);
    let total_events = events.len() + input.authority_events.len();
    events.extend(input.authority_events);

    let (causal, authority, dns_flow) = if total_events >= PARALLEL_BINDER_THRESHOLD {
        std::thread::scope(|scope| {
            let causal_handle = scope.spawn(|| bind_effects(&events, window));
            let authority_handle = scope.spawn(|| bind_authority(&events));
            let dns_flow_handle = scope.spawn(|| bind_dns_flow(&events, window));

            (
                causal_handle.join().expect("bind_effects panicked"),
                authority_handle.join().expect("bind_authority panicked"),
                dns_flow_handle.join().expect("bind_dns_flow panicked"),
            )
        })
    } else {
        (
            bind_effects(&events, window),
            bind_authority(&events),
            bind_dns_flow(&events, window),
        )
    };

    let scores = score_all(&causal, &authority, &dns_flow, total_events);

    ReconcileResult::from_parts(&causal, &scores, total_events)
}

/// Free a string previously returned by [`omnisec_ncer_reconcile`].
///
/// # Safety
///
/// `ptr` must be either NULL or a pointer previously returned by
/// [`omnisec_ncer_reconcile`].  Calling this function twice on the same
/// pointer is undefined behaviour.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omnisec_ncer_reconcile_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    // ── helpers ──────────────────────────────────────────────────────────────

    /// Minimal `MitmCapture` JSON with one matched request+response pair and
    /// one orphan request and one unbound response.  The request and response
    /// share the same method+url so they should bind; timestamps are within
    /// DEFAULT_WINDOW.
    fn sample_capture_json() -> CString {
        CString::new(
            r#"{
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
                        "timestamp_ms": 5000,
                        "status": 404,
                        "headers": {},
                        "request_method": "GET",
                        "request_url": "/missing.js"
                    }
                ],
                "dns_queries": [],
                "tls_handshakes": [],
                "flow_summaries": []
            }"#,
        )
        .unwrap()
    }

    fn empty_capture_json() -> CString {
        CString::new(
            r#"{"http_requests":[],"http_responses":[],"dns_queries":[],"tls_handshakes":[],"flow_summaries":[]}"#,
        )
        .unwrap()
    }

    /// Same shape as `empty_capture_json` plus one unauthorized
    /// `authority_events` entry, to exercise the flattened input schema and
    /// the authority binder end to end through the FFI boundary.
    fn capture_with_unauthorized_authority_event() -> CString {
        CString::new(
            r#"{
                "http_requests": [],
                "http_responses": [],
                "dns_queries": [],
                "tls_handshakes": [],
                "flow_summaries": [],
                "authority_events": [
                    {
                        "id": "obs-1",
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
            }"#,
        )
        .unwrap()
    }

    // ── null pointer guard ────────────────────────────────────────────────────

    #[test]
    fn null_input_returns_minus_one() {
        let mut out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { omnisec_ncer_reconcile(std::ptr::null(), &raw mut out) };
        assert_eq!(rc, -1);
        assert!(out.is_null());
    }

    // ── happy path ────────────────────────────────────────────────────────────

    #[test]
    fn valid_capture_returns_zero_and_valid_json() {
        let input = sample_capture_json();
        let mut out: *mut c_char = std::ptr::null_mut();

        let rc = unsafe { omnisec_ncer_reconcile(input.as_ptr(), &raw mut out) };
        assert_eq!(rc, 0, "expected success status code");
        assert!(!out.is_null(), "output pointer must not be null on success");

        let json_str = unsafe { CStr::from_ptr(out).to_str().unwrap() };
        let result: ReconcileResult = omnisec_json::from_json_str(json_str)
            .expect("returned string must be valid ReconcileResult JSON");

        // One matched pair (GET /index.html).
        assert_eq!(result.bound_count, 1, "one pair should bind");
        // One unbound response (GET /missing.js has no request).
        assert_eq!(result.unbound_count, 1, "one response is unbound");
        // One orphan (POST /login never gets a response).
        assert_eq!(result.orphan_count, 1, "one request is an orphan");
        // Two requests + two responses + zero dns/tls/flow = 4 events.
        assert_eq!(result.total_events, 4);
        // effect_count = bound(1) + unbound(1) = 2; d_causal = 0.5.
        assert!(
            (result.d_causal - 0.5).abs() < f32::EPSILON,
            "d_causal should be 0.5, got {}",
            result.d_causal
        );
        assert!(
            (result.coverage_quality - 0.5).abs() < f32::EPSILON,
            "coverage_quality should be 0.5, got {}",
            result.coverage_quality
        );

        unsafe { omnisec_ncer_reconcile_free(out) };
    }

    #[test]
    fn empty_capture_returns_zero_scores() {
        let input = empty_capture_json();
        let mut out: *mut c_char = std::ptr::null_mut();

        let rc = unsafe { omnisec_ncer_reconcile(input.as_ptr(), &raw mut out) };
        assert_eq!(rc, 0);
        assert!(!out.is_null());

        let json_str = unsafe { CStr::from_ptr(out).to_str().unwrap() };
        let result: ReconcileResult = omnisec_json::from_json_str(json_str).unwrap();

        assert_eq!(result.bound_count, 0);
        assert_eq!(result.unbound_count, 0);
        assert_eq!(result.orphan_count, 0);
        assert_eq!(result.total_events, 0);
        assert_eq!(result.d_causal, 0.0);
        assert_eq!(result.coverage_quality, 0.0);

        unsafe { omnisec_ncer_reconcile_free(out) };
    }

    #[test]
    fn authority_events_cross_the_ffi_boundary_and_score_d_authority() {
        let input = capture_with_unauthorized_authority_event();
        let mut out: *mut c_char = std::ptr::null_mut();

        let rc = unsafe { omnisec_ncer_reconcile(input.as_ptr(), &raw mut out) };
        assert_eq!(rc, 0);
        assert!(!out.is_null());

        let json_str = unsafe { CStr::from_ptr(out).to_str().unwrap() };
        let result: ReconcileResult = omnisec_json::from_json_str(json_str).unwrap();

        // One authority_observed event with no matching grant -> fully
        // unauthorized -> d_authority = 1.0. total_events counts the
        // authority event alongside the (zero) capture-derived events.
        assert_eq!(result.total_events, 1);
        assert_eq!(result.d_authority, 1.0);
        assert_eq!(result.d_capability, 0.0);

        unsafe { omnisec_ncer_reconcile_free(out) };
    }

    #[test]
    fn missing_authority_events_field_defaults_to_empty() {
        // v1.0 callers never send authority_events at all; confirm the
        // field's absence doesn't break deserialization.
        let input = empty_capture_json();
        let mut out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { omnisec_ncer_reconcile(input.as_ptr(), &raw mut out) };
        assert_eq!(rc, 0);
        unsafe { omnisec_ncer_reconcile_free(out) };
    }

    // ── malformed input ───────────────────────────────────────────────────────

    #[test]
    fn invalid_json_returns_minus_three() {
        let bad = CString::new("this is not json").unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { omnisec_ncer_reconcile(bad.as_ptr(), &raw mut out) };
        assert_eq!(rc, -3);
        assert!(out.is_null());
    }

    // ── free ──────────────────────────────────────────────────────────────────

    #[test]
    fn free_null_is_safe() {
        // Must not panic or crash.
        unsafe { omnisec_ncer_reconcile_free(std::ptr::null_mut()) };
    }

    // ── output JSON has expected field names ──────────────────────────────────

    #[test]
    fn output_json_has_expected_field_names() {
        let input = empty_capture_json();
        let mut out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { omnisec_ncer_reconcile(input.as_ptr(), &raw mut out) };
        assert_eq!(rc, 0);

        let json_str = unsafe { CStr::from_ptr(out).to_str().unwrap() };
        let value: omnisec_json::JsonValue = omnisec_json::from_json_str(json_str).unwrap();
        let obj = value.as_object().unwrap();

        let expected = [
            "bound_count",
            "unbound_count",
            "orphan_count",
            "total_events",
            "d_causal",
            "coverage_quality",
            "d_authority",
            "d_information",
            "d_capability",
            "d_consequence",
            "d_novelty",
        ];
        for key in expected {
            assert!(
                obj.iter().any(|(k, _)| k == key),
                "missing expected field: {key}"
            );
        }
        // Exact count: pkg/ncer/reconcile.Result on the Go side hand-mirrors
        // this shape with no compile-time link to it. A field silently added
        // here would decode as a Go zero-value forever unless someone
        // remembers to update bridge.go/bridge_stub.go by hand — catch that
        // at test time instead.
        assert_eq!(
            obj.len(),
            expected.len(),
            "ReconcileResult gained or lost a field; update pkg/ncer/reconcile's \
             Result struct (bridge.go and bridge_stub.go) to match, then update \
             this test's expected field list"
        );

        unsafe { omnisec_ncer_reconcile_free(out) };
    }

    #[test]
    fn windowed_with_zero_ms_uses_default_window() {
        let input = sample_capture_json();
        let mut out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { omnisec_ncer_reconcile_windowed(input.as_ptr(), 0, &raw mut out) };
        assert_eq!(rc, 0);
        assert!(!out.is_null());
        let json_str = unsafe { CStr::from_ptr(out).to_str().unwrap() };
        let result: ReconcileResult = omnisec_json::from_json_str(json_str).unwrap();
        // Same binding as default: GET /index.html binds.
        assert_eq!(result.bound_count, 1);
        unsafe { omnisec_ncer_reconcile_free(out) };
    }

    #[test]
    #[test]
    fn windowed_with_1ms_prevents_binding() {
        // 1ms window: response at t=1200ms is too far from request at t=1000ms.
        let input = sample_capture_json();
        let mut out: *mut c_char = std::ptr::null_mut();
        let rc = unsafe { omnisec_ncer_reconcile_windowed(input.as_ptr(), 1, &raw mut out) };
        assert_eq!(rc, 0);
        assert!(!out.is_null());
        let json_str = unsafe { CStr::from_ptr(out).to_str().unwrap() };
        let result: ReconcileResult = omnisec_json::from_json_str(json_str).unwrap();
        // No binding possible with 1ms window.
        assert_eq!(result.bound_count, 0);
        unsafe { omnisec_ncer_reconcile_free(out) };
    }
}
