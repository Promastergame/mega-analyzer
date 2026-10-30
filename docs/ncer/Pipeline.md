# Pipeline

1. A `ReconcileInput` (a `MitmCapture` plus authority events) is assembled by `Collector.buildReconcileInput`, fed by four converging sources — see the diagram below.
2. `omnisec-ncer-parse-net::from_mitm_capture` creates deterministic `TypedEvent` values from the `MitmCapture` half, one per captured item; the authority events are appended as-is.
3. `run_pipeline` (`omnisec-ncer-reconcile-ffi`) runs three independent binders over the combined `TypedEvent` slice — `bind_effects` (HTTP causal), `bind_authority` (permission grants vs. observed actions), `bind_dns_flow` (DNS resolutions vs. network flows) — then `score_all` combines their results into a `DiscrepancyVector`. The causal and DNS/flow binders share a five-second default window (`DEFAULT_WINDOW`), configurable per call via `omnisec_ncer_reconcile_windowed` / `reconcile.RunReconcileWindowed` / `collector.ReconcileWithWindow`; `bind_authority` has no time window since grants are standing, not time-scoped. See [Reconciliation.md](Reconciliation.md) for each dimension's formula.
4. The Rust FFI (`omnisec_ncer_reconcile`) returns a JSON `ReconcileResult` carrying five of the seven dimensions (`d_consequence`/`d_novelty` are always `0.0` from Rust).
5. Go maps this to `types.NcerCausalResult`, then fills in `d_consequence` (`Collector.scoreConsequence`, from sandbox finding severities) and `d_novelty` (`Collector.scoreNovelty`, from the cross-session fingerprint baseline) locally before returning it.
6. Existing JSON, SARIF, HTML, and CLI reporting consume the completed `types.NcerCausalResult`.

Empty captures and builds without the native library are safe no-result paths in Go.

## Diagram

```text
  ┌───────────────────────────────────────────────────────────────────────┐
  │ Rust live-capture path                                                │
  │                                                                         │
  │  live proxy traffic --> capture.rs structs   --> CAPTURE_STORE         │
  │  (ssl.rs / dns.rs /     (HttpRequestCapture,     Arc<Mutex<MitmCapture>>│
  │   obfs.rs)               HttpResponseCapture,    (drained at session   │
  │                          DnsQueryCapture,          end via              │
  │                          FlowSummaryCapture)       omnisec_mitm_        │
  │                                                    take_capture FFI)    │
  │                                                          │              │
  └──────────────────────────────────────────────────────────┼─────────────┘
                                                              │
                              mitmbridge.TakeCapture (cgo, omnisec_mitm_ffi tag)
                                                              │
                                                              v
                              feedNcerMitmCapture --> Collector.MergeMitmCaptureJSON
                              (pkg/cmd/analyzer/ncer_mitm_capture.go)   (verbatim merge,
                                                              │          no re-pairing —
                                                              │          bind_effects pairs
                                                              │          method+url downstream)
  ┌───────────────────────────────────────────────────────────────────────┐
  │ Go telemetry-replay path — real timestamps, no synthetic RTT          │
  │                                                                         │
  │  sandbox/monitor    TelemetryEvent{Type:"http"}   Collector            │
  │  goroutines     -->  stream                   -->  .ObserveHTTP()      │
  │  (live_mitm.go,      (runner_stream.go)             (responseTS =      │
  │   live_pcapdroid.go,                                 requestTS when     │
  │   report replay)                                     both known;        │
  │                                                       no +200ms offset)  │
  └──────────────────────────────────────────────────────────┼─────────────┘
                                                              │
                              feedNcerAuthority / feedNcerDNSFlow / feedNcerConsequence
                              (pkg/cmd/analyzer/ncer_{authority,dns_flow,consequence}.go)
                              — sandbox report's permissions, DNS records, flow summaries,
                                and behavior indicators, via Collector.Observe{Authority,DNS,Flow}
                                and SetAnomalyFindings
                                                              │
                                                              v
                                          Collector.buildReconcileInput()
                                          (MitmCapture + authority_events)
                                                              │
                             == Go -> Rust FFI: omnisec_ncer_reconcile[_windowed] ==
                                      (reconcile.RunReconcile, CGO)
                                                              │
                                                              v
                            from_mitm_capture (omnisec-ncer-parse-net)
                                                              │
                                                              v
                                TypedEvent[] (omnisec-ncer-types, HTTP + authority + DNS + flow)
                                                              │
                             ┌────────────────────────────────┼────────────────────────────────┐
                             v                                v                                v
                       bind_effects                     bind_authority                   bind_dns_flow
                  (omnisec-ncer-reconcile)            (omnisec-ncer-reconcile)         (omnisec-ncer-reconcile)
                             │                                │                                │
                             └────────────────────────────────┼────────────────────────────────┘
                                                              v
                                    score_all --> DiscrepancyVector (5 of 7 dims: d_causal,
                                                    coverage_quality, d_authority, d_information,
                                                    d_capability; d_consequence/d_novelty stay 0.0)
                                                              │
                                                              v
                       ReconcileResult JSON == Rust -> Go FFI ==> types.NcerCausalResult
                                                              │
                                     Collector.scoreConsequence / scoreNovelty fill in the
                                     remaining 2 dims from sandbox findings / fingerprint baseline
                                                              │
                                                              v
                         JSON / SARIF / HTML / CLI reports (pkg/internal/report, pkg/cmd/analyzer)
```

The Rust live-capture path and the Go telemetry-replay path both feed the same `Collector`: `feedNcerMitmCapture` drains `CAPTURE_STORE` and merges it in verbatim (`MergeMitmCaptureJSON`), while telemetry-replay populates the collector incrementally via `ObserveHTTP`/`ObserveAuthority`/`ObserveDNS`/`ObserveFlow` as the sandbox run streams events. Both contribute to the single `buildReconcileInput()` call that crosses the FFI boundary — `runner_stream.go`'s `runSandboxStreamSink` calls all four `feedNcer*` helpers, then `Reconcile`, in that order, after the sandbox report is available.
