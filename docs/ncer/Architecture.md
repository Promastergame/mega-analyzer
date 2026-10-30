# NCER architecture

NCER reconciles observed network effects (HTTP, DNS, flow) against their likely causes and against the permissions that authorized them, producing a seven-dimension `DiscrepancyVector` — see [Reconciliation.md](Reconciliation.md).

```text
MITM capture -> typed events -> three binders -> discrepancy vector
                (HTTP, DNS,      (causal,           |
                 flow, authority) authority,          |
                                  dns_flow)           |
                                      |                |
                                      +---- Go bridge --+-> JSON/SARIF/HTML/CLI
                                                                    ^
                                                    consequence/novelty scored in Go
                                                    from sandbox findings, merged in
```

Rust owns the canonical typed-event schema, capture parser, the three binders (`bind_effects`, `bind_authority`, `bind_dns_flow`), scoring, and native bridge. Go adapts analyzer correlations, feeds authority/DNS/flow/consequence observations, stores evidence, invokes the linked bridge, computes `d_consequence`/`d_novelty` locally, and exposes results through existing reports.

## Two capture pipelines (both now wired)

The diagram above shows the unified path. There are two separate ways a `MitmCapture` gets built, and both now converge at `from_mitm_capture`:

1. **Rust live capture — now wired.** `rust/crates/omnisec-mitm/src/{ssl,dns,obfs}.rs` each construct real capture structs from live proxy traffic: `HttpRequestCapture`/`HttpResponseCapture` in `ssl::run_ssl_strip_proxy`, `DnsQueryCapture` in `dns::run_dns_spoof_server`, `FlowSummaryCapture` in `obfs::run_obfuscated_proxy` (types defined in `rust/crates/omnisec-mitm/src/capture.rs`). All three runners now receive a shared `Arc<Mutex<MitmCapture>>` accumulator (`CAPTURE_STORE` in `lib.rs`) and push every observed capture into it instead of dropping after `tracing::debug!`. The accumulated data can be drained at session end via the new `omnisec_mitm_take_capture` FFI export, which atomically takes the current store contents and returns them as a JSON C string (freeable with `omnisec_mitm_free_str`).

2. **Go telemetry-replay — real timestamps, no synthetic RTT.** `pkg/cmd/analyzer/runner_stream.go` streams `TelemetryEvent{Type: "http"}` values from several sandbox/monitoring goroutines (e.g. `live_mitm.go`, `live_pcapdroid.go`, and sandbox report replay) into `ncer.Collector.ObserveHTTP` (`pkg/ncer/collect.go`). `Collector.buildCapture()` converts each observed request into a request entry. When the event already carries a status code (e.g. from mitmproxy which delivers request and response in one event), a real response entry is emitted with the **same timestamp** as the request — no artificial `+200ms` RTT offset. When a status code is learned later (e.g. from the Rust live-capture side via `omnisec_mitm_take_capture`), `Collector.ObserveHTTPResponse` can be called to back-fill the response onto an existing orphan request with the actual response timestamp. Requests that never receive a status code remain true orphans. This synthesised `MitmCapture` JSON is what crosses the Go→Rust FFI boundary (`reconcile.RunReconcile` → `omnisec_ncer_reconcile`) and reaches `from_mitm_capture`, `bind_effects`, and `score_causal`.

## No TLS interception

`ssl.rs`'s `CONNECT` handler returns `501 Not Implemented` for every `CONNECT` request — the proxy only ever sees plaintext HTTP, never TLS-wrapped traffic. `EventKind::TlsHandshake` and `TlsHandshakeCapture` exist so the wire schema is stable, but no live code path in this repository constructs one; they are schema-only today. `capture.rs`'s module doc states this explicitly: "this crate does not parse TLS ClientHello/SNI/cipher suites/certificates anywhere today."
