# labkit — autonomous local test-server framework

> **Defensive, local-only research tooling.** Unlike the intentionally
> vulnerable fixtures elsewhere under `labs/servers/`, `labkit` is a *clean*
> platform: a research-grade framework for exercising, observing and
> stress-testing network software you own or are authorized to test. Every
> listener binds to loopback by default and the config layer refuses a
> non-loopback bind unless you explicitly opt in.

`labkit` is a **standalone Go module** (`module labs-labkit`). It has no
dependency on the parent `mega-analyzer` module and imports nothing from
`pkg/internal/*`; it uses only the Go standard library. Copy the `labkit/`
directory anywhere and it still builds and runs.

## Why it exists

A single binary that can stand up HTTP, WebSocket, TCP and UDP endpoints with
**repeatable, injectable behaviour** (latency, errors, timeouts) and
**built-in observability** (structured logs + metrics). It's the fixture you
reach for when you need to:

- reproduce a client's retry/timeout logic against a server that fails on cue,
- measure how an app behaves under injected latency,
- analyze a custom TCP/length-framed protocol locally,
- smoke-test a WebSocket client without pulling in a third-party library,
- generate real local traffic for a network-analysis pipeline.

## Quick start

```bash
cd labs/servers/labkit

# Run tests, vet, benchmarks
go test ./...
go vet ./...
go test -run='^$' -bench=. -benchmem ./...

# Quick single servers (loopback only)
go run ./cmd/labkit -http 127.0.0.1:8080 -tcp 127.0.0.1:8081 -udp 127.0.0.1:8082

# Or a full declarative lab
go run ./cmd/labkit -config examples/full-lab.json
```

Then:

```bash
curl -s http://127.0.0.1:8080/_health
curl -s -X POST -d 'hello' http://127.0.0.1:8080/_echo
curl -s http://127.0.0.1:8080/_metrics
printf 'ping\n' | nc 127.0.0.1 8081
```

## Built-in HTTP routes

| Route       | Purpose                                                    |
| :---------- | :--------------------------------------------------------- |
| `/_health`  | Liveness probe (`{"status":"ok"}`).                        |
| `/_echo`    | Reflects the request method, path, headers and body.       |
| `/_metrics` | JSON snapshot of all counters and latency summaries.       |

User routes and a WebSocket echo endpoint are declared in config.

## Configuration

A lab is a JSON document (see [`examples/`](examples/)). Durations accept
human strings like `"200ms"` or `"1.5s"`.

```jsonc
{
  "log_level": "info",
  "servers": [
    {
      "name": "api",
      "kind": "http",                 // http | tcp | udp
      "addr": "127.0.0.1:18101",      // empty host => 127.0.0.1
      "scenario": {                    // repeatable fault injection
        "fixed_latency": "5ms",
        "jitter_latency": "10ms",
        "error_rate": 0.25,            // probability of an injected error
        "error_status": 503,
        "timeout_rate": 0.05,          // probability of a hung/dropped conn
        "timeout_duration": "2s",
        "seed": 42                     // fixed seed => deterministic sequence
      },
      "http": {
        "routes": [
          {"path": "/api/status", "status": 200, "body": "{\"ok\":true}"},
          {"path": "/ws", "websocket": true}
        ]
      }
    }
  ]
}
```

TCP servers support `line`, `length` (4-byte big-endian prefix) and `raw`
framing, bounded concurrency (`max_conns`), and idle read timeouts. UDP servers
echo or discard datagrams with a bounded read buffer.

## Architecture

```
Config ──► Manager ──► [ Service ... ]
                         │  HTTPServer ── middleware pipeline (recovery │ logging │ scenario) ── mux
                         │                 └─ WebSocket echo (RFC 6455, stdlib hijack)
                         │  TCPServer  ── bounded acceptor + framing codec
                         │  UDPServer  ── datagram loop
                         └─ shared Logger + Metrics + per-server Scenario
```

- **Logger** — structured JSON, level-filtered, safe for concurrent use.
- **Metrics** — lock-free counters and a histogram-backed latency summary
  (`p50/p90/p99`); the hot path is a single atomic increment (0 allocs).
- **Scenario** — deterministic (seedable) latency/error/timeout injection.
- **Manager** — starts every service, rolls back on partial failure, and shuts
  them all down on a deadline (graceful drain, then forced close).

## Safety

- Loopback-enforced by default; `allow_non_loopback` must be set explicitly.
- Payload/size bounds on every protocol (WebSocket frames, TCP messages, UDP
  datagrams, HTTP headers) so a misbehaving client can't exhaust memory.
- Panics in HTTP handlers are recovered into 500s.
- Nothing here is a network client to third-party services; it only *listens*.
