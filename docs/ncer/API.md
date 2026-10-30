# API

## Rust

- `omnisec_ncer_types::TypedEvent`, `EventKind`: stable cross-language event envelope. `EventKind` includes `HttpRequest`/`HttpResponse`/`DnsQuery`/`FlowSummary`/`TlsHandshake` (from captures) and `AuthorityGrant`/`AuthorityObserved` (from `authority_events`, see below).
- `omnisec_mitm::capture::MitmCapture` and its five item types (`HttpRequestCapture`, `HttpResponseCapture`, `DnsQueryCapture`, `TlsHandshakeCapture`, `FlowSummaryCapture`): the capture schema `from_mitm_capture` consumes. Both the Rust live-capture path (ssl/dns/obfs proxies → `CAPTURE_STORE`) and the Go telemetry-replay path produce this type — see [Architecture.md](Architecture.md).
- `omnisec_ncer_evidence::EvidenceStore`: content-addressed evidence access. Not called by the FFI entry point — see [Evidence.md](Evidence.md).
- `omnisec_ncer_parse_net::from_mitm_capture`: capture-to-event conversion.
- `omnisec_ncer_reconcile::bind_effects`, `bind_authority`, `bind_dns_flow`: the three independent binders, returning `BindingResult`, `AuthorityBindingResult`, `DnsFlowBindingResult` respectively.
- `omnisec_ncer_reconcile::score_causal`, `score_authority`, `score_dns_flow`, `score_all`: scoring functions. `score_causal` computes just `d_causal`/`coverage_quality` from a `BindingResult`; `score_all` combines all three binders' results into a full `DiscrepancyVector` (5 of 7 fields — `d_consequence`/`d_novelty` are Go-only). See [Reconciliation.md](Reconciliation.md).
- `omnisec_ncer_reconcile_ffi::omnisec_ncer_reconcile` / `omnisec_ncer_reconcile_windowed` / `omnisec_ncer_reconcile_free`: the C ABI surface, both entry points running `run_pipeline` (all three binders + `score_all`). `omnisec_ncer_reconcile` uses a hardcoded 5 s window; `omnisec_ncer_reconcile_windowed` accepts a caller-supplied `window_ms` (≤ 0 falls back to default) — see [FFI.md](FFI.md).
- `omnisec_mitm::omnisec_mitm_take_capture` / `omnisec_mitm_free_str`: drain the live-capture `CAPTURE_STORE` as a JSON `MitmCapture` C string — see [Architecture.md](Architecture.md).

## Go

- `ncer.OpenEvidenceStore`, `(*EvidenceStore).Store`, `Retrieve`, `Verify`.
- `ncer.FromCorrelations`, `ncer.FromAuthorityContext`, `ncer.FromAuthorityContextGranular`.
- `ncer.NewCollector`, `ObserveHTTP`, `ObserveHTTPResponse`, `ObserveAuthority`, `ObserveDNS`, `ObserveFlow`, `MergeMitmCaptureJSON`, `SetEvidenceStore`, `SetAnomalyFindings`, `SetBaselineDir`, `Len`, `Reconcile`, and `ReconcileWithWindow`.
- `ncer.ConsequenceScore`: standalone Go-side `d_consequence` computation from `[]types.AnomalyFinding`, also used internally by `Collector.Reconcile`.
- `ncer.ActionToPermission` (`pkg/ncer/authority_mapping.go`): the action→Android-permission heuristic table `FromAuthorityContextGranular` uses to classify observed actions.
- `mitmbridge.TakeCapture`: cgo bridge draining the Rust `CAPTURE_STORE` (build tag `cgo && omnisec_mitm_ffi`; stub returns `ErrRustNotLinked` otherwise).
- `reconcile.RunReconcile` and `reconcile.RunReconcileWindowed` for callers that explicitly manage native capture JSON.

All serialized field names use snake_case and are regression-tested. Map-backed Rust attributes use `BTreeMap`; Go JSON encoding provides stable map-key order.
