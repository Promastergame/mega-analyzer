# Integration

Create one `ncer.Collector` per analysis session, feed it observations, optionally attach an `EvidenceStore` and baseline directory, then call `Reconcile` at session end.

```go
collector := ncer.NewCollector(time.Now())
collector.SetEvidenceStore(store)
collector.SetBaselineDir(filepath.Join(outputDir, "ncer_baseline"))
collector.ObserveHTTP("GET", "https://api.example.test/v1", "200", "api.example.test", "12:00:00.000")
result, err := collector.Reconcile()
```

The existing report builder carries a non-nil result to JSON, SARIF, HTML, and CLI output. Integration tests cover the collector and report serializations; native bridge integration additionally requires the FFI build tag and library.

## What runner_stream.go actually wires up

`pkg/cmd/analyzer/runner_stream.go`'s `runSandboxStreamSink` calls `ObserveHTTP` incrementally as telemetry streams in during the run, then — once the sandbox report is available — calls four `feedNcer*` helpers before `Reconcile`:

```go
feedNcerAuthority(ncerCollector, res.report)   // permissions -> ObserveAuthority
feedNcerDNSFlow(ncerCollector, res.report)     // DNS/flow records -> ObserveDNS / ObserveFlow
feedNcerMitmCapture(ncerCollector, emit)       // drains Rust CAPTURE_STORE -> MergeMitmCaptureJSON
feedNcerConsequence(ncerCollector, res.report) // behavior indicators -> SetAnomalyFindings

result, err := ncerCollector.Reconcile()
```

Each helper lives in `pkg/cmd/analyzer/ncer_{authority,dns_flow,mitm_capture,consequence}.go` and is a safe no-op when its input source is absent (nil report, no `BehaviorAnalysis`, `mitmbridge` not linked, etc.) — see each file's doc comment for its exact no-op conditions.

`ObserveHTTP` records method, URL, status, and timestamp — it never receives real response headers/bodies, because the live caller has none to give it; the sandbox/monitoring goroutines that feed it emit request-observed and status-observed telemetry, not full HTTP exchanges. When a status code is already known at observe-time (e.g. mitmproxy reports request and response in a single JSON line), `ObserveHTTP` records the response at the **same timestamp** as the request — no artificial `+200 ms` RTT offset. `ObserveHTTPResponse(method, url, status, timestampStr)` exists to back-fill a response onto an existing orphan request from a separately-arriving event, but no production caller uses it today — the Rust live-capture path converges via `feedNcerMitmCapture`/`MergeMitmCaptureJSON` instead, which merges drained request/response entries verbatim rather than re-pairing them in Go (`bind_effects` does that pairing downstream). Requests that never receive a status code remain true orphans and do not inflate `d_causal`.

## Authority, DNS/flow, and consequence observations

```go
collector.ObserveAuthority(ncer.FromAuthorityContextGranular(ctx, sensorID, observedAtMs))
collector.ObserveDNS("example.com", 1 /* A record */, []string{"93.184.216.34"}, "12:00:00.000")
collector.ObserveFlow("192.168.1.2", 51234, "93.184.216.34", 443, 4096, 250, "tcp", "12:00:00.100")
collector.SetAnomalyFindings(findings) // []types.AnomalyFinding, drives d_consequence
```

`ObserveAuthority` takes pre-built `TypedEvent`s (`AuthorityGrant`/`AuthorityObserved` kinds) rather than raw data, since `FromAuthorityContextGranular` already knows how to map a sandbox's declared/granted permissions and observed actions (via `ActionToPermission`) into that shape — see [Reconciliation.md](Reconciliation.md) for what each dimension does with these.

To use a custom binding window (default is 5 s on the Rust side, applies to both the causal and DNS/flow binders):

```go
result, err := collector.ReconcileWithWindow(2 * time.Second)
```

See [Architecture.md](Architecture.md) for the full picture of both capture pipelines, and [Pipeline.md](Pipeline.md) for the end-to-end data flow diagram.

