# labkit — Autonomous Local Network-Analysis Lab (Explainer)

> Explainer for the PR **“Create autonomous local network-analysis lab (labkit) and harden privserver.”** Authorized, local-only defensive tooling.

## Background

### For newcomers (skip if you know the repo)

`mega-analyzer` is a security-analysis toolkit. Two areas matter here:

- **`pkg/internal/privserver`** — despite the name, this is *not* a running server. It is a **code generator**: it scans an APK/DEX/directory for address-like strings, transport hints (HTTP/WebSocket/TCP), and SSL-pinning references, produces a structured `Plan`, and emits an **Elixir/OTP mock-backend skeleton** plus a readiness report. It never touches the network; everything is computed from bytes already inside the target. It is wired into the CLI via `pkg/cmd/analyzer/make_server_runner.go` (`Discover → Generate → WritePlan → WriteReadiness`).
- **`labs/servers`** — a directory of *intentionally vulnerable* local fixtures (hardcoded backdoors, SQLi, JWT `alg=none`, …) that exist to give the repo's own interceptor/MITM pipeline real, exploitable traffic to observe. Each is its own standalone module; none imports `pkg/internal/*`.

### Narrow background for this change

The request was to (1) turn `privserver` into an “elite local network-analysis subsystem” and (2) build `labs/servers` into an **autonomous, self-contained testing platform** that must not import internal production packages and must run locally only.

Two hard constraints shaped the design:

- **Isolation is a requirement, not a nicety.** The lab platform must be a standalone module with zero coupling to `mega-analyzer` internals.
- **Toolchain reality.** The repo pins `go 1.26.5`; only `go 1.24.7` is available in the build sandbox and the 1.26 toolchain download is blocked. So new lab code targets `go 1.24` (a strict subset of 1.26), which lets it actually build, vet, race-test and benchmark. `privserver` was verified by temporarily lowering the module's `go` directive locally (never committed).

## Intuition

The core idea of **labkit** is a single small binary that can stand up several protocols at once, each with *repeatable, injectable behaviour* and *built-in observability*.

Concretely, imagine you're debugging a client's retry logic. You want a server that answers most requests normally, then fails 1 in 4 with a 503, adds 5–15 ms of latency, and occasionally just drops the connection — and you want that sequence to be **identical** every run so a failing test is reproducible. labkit expresses exactly that as data:

```jsonc
{"scenario": {"fixed_latency": "5ms", "jitter_latency": "10ms",
  "error_rate": 0.25, "error_status": 503,
  "timeout_rate": 0.05, "timeout_duration": "2s", "seed": 42}}
```

Because the fault sequence is driven by a **seeded** PRNG, `seed: 42` makes the errors land on the same requests every time. Drop the seed and it's random again. That determinism is the difference between a research instrument and a toy.

The second idea is **honest observability**: every request is a structured JSON log line and a metric, exposed live at `/_metrics`. You never have to guess what the server did.

## Code

### New module: `labs/servers/labkit` (module `labs-labkit`, stdlib-only)

**Primitives**

- `logger.go` — level-filtered structured JSON logger; `With(Fields)` returns an isolated child so components can't leak fields into each other.
- `metrics.go` — `Metrics` registry of atomic counters + a `Latency` recorder backed by a fixed histogram. The hot path is a single atomic bucket increment (0 allocs), and `Snapshot()` yields `p50/p90/p99`.
- `scenario.go` — `Scenario` turns a `ScenarioConfig` into per-request `Outcome{Latency, Fault}` decisions from a mutex-guarded seeded source (`math/rand/v2` PCG).
- `config.go` — declarative `Config`/`ServerConfig`, a human-friendly `Duration` (`"200ms"`), strict JSON decoding, and the **loopback-only guard** in `Validate()`.

**Lifecycle**

- `server.go` — the `Service` interface (`Name/Addr/Start/Close`) and a `Manager` that builds services from config, **rolls back** already-started services on a partial failure, and shuts everything down on a deadline (`errors.Join` of per-service errors).

**Protocols**

- `httpserver.go` + `middleware.go` — `net/http` with a composable pipeline (`recovery → requestLogger → scenario`) and built-ins `/_health`, `/_echo`, `/_metrics`.
- `websocket.go` — a hand-written **RFC 6455** handshake + frame codec on top of `http.Hijacker`; no third-party WebSocket dependency. Masking, 7/16/64-bit lengths, ping/pong/close, and a 1 MiB payload bound.
- `tcpserver.go` — bounded-concurrency acceptor (semaphore + refuse-when-full), `line`/`length`/`raw` framing, idle deadlines, graceful drain then forced close.
- `udpserver.go` — datagram echo/discard with a bounded read buffer.
- `cmd/labkit/main.go` — CLI: `-config` or quick `-http/-tcp/-udp`, signal-driven graceful shutdown.

### Hardened: `pkg/internal/privserver` (public API unchanged)

```go
// Discover: fail fast and namespace errors instead of failing silently.
if strings.TrimSpace(target) == "" {
    return nil, fmt.Errorf("privserver: target is empty ...")
}
// ... wrap load error: fmt.Errorf("privserver: load target %q: %w", target, err)

// Resource limit: cap retained endpoints, and record the truncation.
if len(endpointSet) >= maxEndpoints { endpointsTruncated = true; continue }

// New structural check, called from Generate for early diagnostics.
func (p *Plan) Validate() error { /* module, ports, protocol sanity */ }
```

`Discover`, `Generate`, `WritePlan`, `WriteReadiness` keep identical signatures, so the CLI runner compiles unchanged.

## Verification

- **labkit**: `go build ./...`, `go vet ./...`, `gofmt -l` (clean), `go test -race ./...` (pass), and benchmarks.
  - `BenchmarkScenarioRoll` ~22 ns/op, 0 allocs; `BenchmarkMetricsObserve` ~88 ns/op, 0 allocs; `BenchmarkFrameRoundTrip`; `BenchmarkHTTPHealth` ~113 µs/op over loopback.
  - WebSocket verified against the RFC 6455 accept-key example (`s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`) plus a real hijacked-socket echo integration test.
  - CLI smoke-tested: a 4-server config booted, served `/api/teapot`, `/_echo`, `/_metrics`, TCP line-echo, and shut down cleanly on SIGINT.
- **privserver**: `gofmt`, `go vet`, and `go test` all pass (via a local, uncommitted `go 1.24` downgrade, since the 1.26 toolchain is unavailable in the sandbox).

**Manual QA**

```bash
cd labs/servers/labkit
go test ./... && go vet ./...
go run ./cmd/labkit -config examples/full-lab.json &
curl -s http://127.0.0.1:18101/api/teapot; echo
curl -s http://127.0.0.1:18101/_metrics | head
kill %1   # graceful shutdown
```

## Alternatives

**1. Extend an existing lab module instead of a new `labkit` module**

| Pros | Cons |
| --- | --- |
| Fewer modules in `go.work` | Muddles the “intentionally vulnerable” fixtures with clean defensive tooling |
| Reuses existing scaffolding | Risks accidental coupling to fixture code; weaker isolation story |

**2. Pull in `gorilla/websocket` / a router library rather than hand-rolling**

| Pros | Cons |
| --- | --- |
| Less protocol code to maintain | Breaks the “standalone, stdlib-only, no external deps” requirement |
| Battle-tested framing | A hand-written codec is itself a useful protocol-analysis artifact and keeps the module hermetic |

## Suggested people to talk to

- **Promaster / Promastergame** (`semenoviosif6@gmail.com`) — author of essentially all recent `labs/servers` and surrounding pipeline work (NCER authority, netproxy/MITM recording, lab servers). Best person for how the lab traffic is meant to feed the interceptor pipeline and for the `privserver` generator's intent. (Recent `privserver` touches were only automated badge-coverage bumps, so there's no other human owner to loop in there.)

## Quiz

<details>
<summary>1. Why does new labkit code target <code>go 1.24</code> when the repo pins <code>go 1.26.5</code>?</summary>

- **A. The framework needs a 1.24-only feature.** Incorrect — it uses none.
- **B. The 1.26 toolchain can't be fetched in the sandbox, so 1.24 (a subset) is what can actually build/test the code.** ✅ Correct.
- **C. To force a downgrade of the whole repo.** Incorrect — the root module still pins 1.26.5; only the standalone lab module differs.

</details>

<details>
<summary>2. What makes the scenario engine's fault sequence reproducible?</summary>

- **A. It records and replays outcomes to disk.** Incorrect.
- **B. A mutex-guarded, seeded PRNG (fixed <code>seed</code> ⇒ identical sequence regardless of goroutine timing).** ✅ Correct.
- **C. It disables concurrency.** Incorrect — servers stay concurrent; only the RNG draw is serialized.

</details>

<details>
<summary>3. How does labkit implement WebSocket without a third-party library?</summary>

- **A. It shells out to a proxy.** Incorrect.
- **B. It computes the RFC 6455 accept key, hijacks the <code>net/http</code> connection, and reads/writes frames with a hand-written codec.** ✅ Correct.
- **C. It uses <code>net/http</code>'s built-in WebSocket support.** Incorrect — the stdlib has none.

</details>

<details>
<summary>4. Why were <code>privserver</code>'s exported function signatures left unchanged?</summary>

- **A. Laziness.** Incorrect.
- **B. The CLI runner depends on them and could not be compile-verified in the sandbox, so keeping signatures stable guarantees it still builds.** ✅ Correct.
- **C. Go forbids changing exported signatures.** Incorrect.

</details>

<details>
<summary>5. What happens when the TCP server hits its <code>max_conns</code> limit?</summary>

- **A. New connections queue unboundedly.** Incorrect — that's the failure mode being avoided.
- **B. The new connection is refused/closed and a <code>tcp.rejected</code> metric is incremented.** ✅ Correct.
- **C. The server panics.** Incorrect — panics in HTTP handlers are recovered; the TCP path simply refuses.

</details>
