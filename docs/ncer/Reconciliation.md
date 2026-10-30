# Causal reconciliation

`bind_effects` handles HTTP request/response pairs. A response binds when `method` and `url` match a request at or before the response time and inside the configured window. Each request binds once.

`d_causal = unbound_effects / (bound_pairs + unbound_effects)`.

- `0.0`: all observed effects were explained.
- `1.0`: no observed effects were explained.
- `coverage_quality` is the complementary bound-effect ratio.

Orphan requests are reported but do not increase `d_causal`, because they are causes without a known effect.

## All 7 `DiscrepancyVector` dimensions are computed

`omnisec-ncer-reconcile::scoring::DiscrepancyVector` has seven fields: `d_causal`, `coverage_quality`, `d_authority`, `d_information`, `d_capability`, `d_consequence`, `d_novelty`. `run_pipeline` (`omnisec-ncer-reconcile-ffi`) computes five of them Rust-side via `score_all`; `d_consequence` and `d_novelty` are computed Go-side and merged in after decoding the `ReconcileResult`. All seven cross the Go/Rust FFI boundary and all seven are surfaced by `Collector.Reconcile` on `types.NcerCausalResult`.

| Dimension | Computed by | Binder / data source |
| :--- | :--- | :--- |
| `d_causal`, `coverage_quality` | `score_causal` / `score_all` (Rust) | `bind_effects` — HTTP request/response pairs |
| `d_authority` | `score_authority` (Rust) | `bind_authority` — observed actions vs. permission grants (`AuthorityGrant`/`AuthorityObserved` events) |
| `d_capability` | `score_authority` (Rust) | `bind_authority` — grants never exercised |
| `d_information` | `score_dns_flow` (Rust) | `bind_dns_flow` — network flows vs. DNS resolutions (`DnsQuery`/`FlowSummary` events) |
| `d_consequence` | `ncer.ConsequenceScore` (Go, `pkg/ncer/consequence.go`) | sandbox `BehaviorAnalysis` indicator severities, fed via `feedNcerConsequence` |
| `d_novelty` | Go, `pkg/ncer/novelty.go` | cross-session fingerprint baseline (`baseline.json` under the collector's baseline dir) |

### `d_authority` / `d_capability` (`bind_authority`)

An `AuthorityGrant` event records a permission the app declared or was granted (e.g. `android.permission.INTERNET`). An `AuthorityObserved` event records an action actually taken (e.g. a `network_connect`), mapped to the permission it requires via `pkg/ncer/authority_mapping.go`'s `ActionToPermission` table. `bind_authority` (no time window — grants are standing, not time-scoped) matches observed actions against grants by `subject_id` + required permission:

- `d_authority = unauthorized_observed / classifiable_observed` — the fraction of classifiable observed actions with no matching grant. `0.0` when there are no classifiable observed actions (including the common case of no authority events at all).
- `d_capability = unused_grants / (used_grants ∪ unused_grants)` — the fraction of granted permissions never exercised. Deduplicated by grant id, so one grant backing several observed actions counts once, not once per action.

### `d_information` (`bind_dns_flow`)

`bind_dns_flow` matches each `FlowSummary` event's destination IP against `DnsQuery` events' resolved IPs, within the same binding window as `bind_effects` (default 5s, or the caller-supplied `window_ms`). `d_information = unbound_flows / (bound_pairs + unbound_flows)` — the fraction of observed flows with no explaining DNS resolution. `0.0` when no flows were observed. A high value flags traffic to IPs the sandbox never saw resolved (hardcoded IPs, DNS-over-HTTPS bypassing the visible resolver, etc.).

### `d_consequence` (Go)

`ncer.ConsequenceScore` takes the sandbox's `[]types.AnomalyFinding` (populated by `feedNcerConsequence` from `sandbox.Report.BehaviorAnalysis.Indicators`) and returns the mean of `max(severityWeight, finding.Score)` per finding, clamped to `[0.0, 1.0]`. Severity weights: Critical=1.0, High=0.75, Medium=0.4, Low=0.15. `0.0` when there's no `BehaviorAnalysis` or no indicators.

### `d_novelty` (Go)

Each session's observed fingerprints — one SHA-256-hashed fingerprint per distinct HTTP `(method, url)` pair plus one per distinct DNS query name (see `pkg/ncer/novelty.go`'s `sessionFingerprints`) — are compared against a persisted baseline (`<baselineDir>/baseline.json`, set via `Collector.SetBaselineDir`). `d_novelty` is the fraction of this session's fingerprints not already present in the baseline; the baseline is then merged with this session's fingerprints and rewritten (read-merge-write, temp file + rename). First run against an empty/missing baseline scores everything as novel (`d_novelty = 1.0` if any fingerprints exist). A missing/unset `baselineDir` is a safe no-op — `d_novelty` stays `0.0`, treated as "not configured" rather than a genuine zero-novelty measurement.

## Configurable binding window

`bind_effects` takes a `window: Duration` parameter. The default entry point `omnisec_ncer_reconcile` always passes `DEFAULT_WINDOW = Duration::from_secs(5)`, which covers normal HTTP round-trips measured in `omnisec-mitm`'s test suite.

To use a different window **without recompiling the native library**, use the new windowed variants:

| Layer | API |
|---|---|
| Rust FFI | `omnisec_ncer_reconcile_windowed(capture_json, window_ms, out)` — `window_ms ≤ 0` falls back to `DEFAULT_WINDOW` |
| Go low-level | `reconcile.RunReconcileWindowed(captureJSON, window time.Duration)` |
| Go high-level | `collector.ReconcileWithWindow(window time.Duration)` |

The original `omnisec_ncer_reconcile` / `RunReconcile` / `Reconcile` are unchanged and still use 5 s.
