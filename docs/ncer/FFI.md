# Go bridge

The optional bridge uses the existing `omnisec_ncer_reconcile` C ABI. Build it only when the Rust shared library is available:

```sh
cargo build --release -p omnisec-ncer-reconcile-ffi
CGO_ENABLED=1 go build -tags 'cgo omnisec_ncer_reconcile_ffi' ./...
```

```go
result, err := reconcile.RunReconcile(captureJSON)
```

Without that build tag, `RunReconcile` returns `ErrRustNotLinked`; `Collector.Reconcile` converts this expected deployment state into a nil result. `ReconcileResult`'s JSON fields are `bound_count`, `unbound_count`, `orphan_count`, `total_events`, `d_causal`, `coverage_quality`, `d_authority`, `d_information`, `d_capability`, `d_consequence`, and `d_novelty` — all eleven cross the FFI boundary. Rust computes real values for the first nine; `d_consequence`/`d_novelty` are always `0.0` placeholders in the Rust struct (kept in the wire format for schema stability), which `Collector.Reconcile` overwrites on the decoded `types.NcerCausalResult` from sandbox finding severities and the novelty baseline respectively — see [Reconciliation.md](Reconciliation.md).

### Sending authority events across the boundary

`omnisec_ncer_reconcile[_windowed]` accepts a `ReconcileInput`: a `MitmCapture` (flattened via `#[serde(flatten)]`, so its fields sit at the JSON top level) plus an optional `authority_events: Vec<TypedEvent>` sibling array. Plain `MitmCapture` JSON — the shape every caller sent before authority events existed — still decodes correctly, with `authority_events` defaulting to empty. `Collector.buildReconcileInput()` (Go) constructs this shape from whatever was passed to `ObserveAuthority`; callers that only ever called `ObserveHTTP`/`ObserveDNS`/`ObserveFlow` get the same JSON as before authority support was added.

## Configurable binding window

`omnisec_ncer_reconcile` always runs with a hardcoded 5-second binding window (`DEFAULT_WINDOW` in `rust/crates/omnisec-ncer-reconcile-ffi/src/lib.rs`). To use a different window without recompiling the native library, use the windowed variants:

```go
// Go high-level API — recommended
result, err := collector.ReconcileWithWindow(2 * time.Second)

// Go low-level API — for callers that manage capture JSON directly
result, err := reconcile.RunReconcileWindowed(captureJSON, 2*time.Second)
```

Both call the `omnisec_ncer_reconcile_windowed` Rust FFI export, which accepts a `window_ms: i64` parameter. A value of `0` or negative falls back to `DEFAULT_WINDOW`. The original `omnisec_ncer_reconcile` / `RunReconcile` / `Reconcile` remain unchanged and always use 5 s.

## Exported Rust symbols (omnisec-ncer-reconcile-ffi)

| Symbol | Description |
|---|---|
| `omnisec_ncer_reconcile(capture_json, out)` | Pipeline with hardcoded 5 s window |
| `omnisec_ncer_reconcile_windowed(capture_json, window_ms, out)` | Pipeline with caller-supplied window (ms); ≤ 0 → default |
| `omnisec_ncer_reconcile_free(ptr)` | Free string returned by either reconcile function |

## Exported Rust symbols (omnisec-mitm)

| Symbol | Description |
|---|---|
| `omnisec_mitm_take_capture()` | Drain live-capture `CAPTURE_STORE`; returns JSON `MitmCapture` C string |
| `omnisec_mitm_free_str(ptr)` | Free string returned by `omnisec_mitm_take_capture` |
