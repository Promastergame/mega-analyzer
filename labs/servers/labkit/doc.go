// Package labkit is a self-contained, research-grade local test-server
// framework for network analysis, protocol experiments, and application
// debugging.
//
// # Scope and safety
//
// labkit is a standalone Go module (module path "labs-labkit"). It has ZERO
// dependencies on the parent mega-analyzer module and imports nothing from
// mega-analyzer/pkg/internal/*. It uses only the Go standard library. This
// keeps the lab hermetic: you can copy the labkit/ directory anywhere and it
// still builds and runs on its own.
//
// Every server in labkit binds to the loopback interface by default and the
// configuration layer REFUSES to bind a non-loopback address unless the
// operator explicitly opts in (see Config.AllowNonLoopback). The framework is
// intended for legal, defensive work only: local integration testing,
// protocol analysis, service simulation, latency/error/timeout injection, and
// reliability experiments against software you own or are authorized to test.
//
// # Building blocks
//
//   - Logger    — a small structured (JSON) logger with levels and fields.
//   - Metrics   — lock-friendly counters plus a streaming latency summary.
//   - Scenario  — deterministic latency/error/timeout injection + canned
//     responses, so experiments are repeatable.
//   - Manager   — lifecycle supervisor that starts a set of Services and
//     shuts them all down gracefully on a deadline.
//
// # Protocol services
//
//   - HTTPServer — net/http with a composable middleware pipeline and a set
//     of built-in introspection routes (/_health, /_metrics, /_echo).
//   - WebSocketHandler — an RFC 6455 upgrade + frame codec built directly on
//     top of net/http hijacking (no third-party WebSocket library).
//   - TCPServer — a bounded-concurrency TCP acceptor with pluggable framing
//     (line-delimited or length-prefixed) and connection statistics.
//   - UDPServer — a datagram service with a bounded read buffer.
//
// All four implement the Service interface and can be supervised together by
// a Manager, or driven directly from tests.
package labkit
