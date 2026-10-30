# Next-Generation Network Interception — Implementation Explainer

> **Scope.** This change rebuilds the foundation of `mega-analyzer`'s network‑interception
> subsystem across the Rust engine and the Go orchestration layer. It introduces a
> zero‑copy capture/reassembly crate, gives the long‑dead `TlsHandshakeCapture` a real
> live producer, extends the NCER typed‑event schema, and adds a Wireshark‑style
> display‑filter engine plus WebSocket/HTTP‑2 decoders on the Go side. Everything here is
> covered by unit tests and builds offline with no new heavyweight dependencies.

---

## Background

### For the newcomer

`mega-analyzer` is an offline, CPU‑only, single‑binary defensive analysis platform. Its
network‑interception capability historically lived in three loosely‑coupled places:

- **Go `pkg/internal/netproxy`** — a per‑connection TCP relay that sniffs the first few
  bytes (TLS? HTTP/2 preface? "custom binary"?), records packets as JSONL, and can rewrite
  JavaScript bundles on the fly.
- **Rust `omnisec-mitm`** — std blocking-socket proxies (SSL‑strip, DNS‑spoof, rogue DHCP, obfuscated
  proxy) exposed to Go over a C FFI. Its capture structs feed the NCER pipeline.
- **NCER** ("Network Claim‑Evidence Reconciliation") — a typed‑event correlation engine,
  half in Rust (`omnisec-ncer-*`) and half mirrored in Go (`pkg/ncer`), that binds effects
  (HTTP responses, DNS resolutions) back to the causes that produced them and scores the
  leftovers as findings.

> [!NOTE]
> **Typed events.** Every sensor in NCER normalizes its output into a single `TypedEvent`
> envelope — an id, a `kind`, subjects, a score, and opaque attributes. The Rust and Go
> definitions are mirrored field‑for‑field and cross the FFI boundary as JSON, so keeping
> them in sync is load‑bearing.

### The specific gaps this change targets

A prior architecture review found, among other things: there was **no real packet capture**
(everything was an application‑layer relay, no `.pcap` ingest, no flow table, no
reassembly); **TLS interception was unimplemented** (the `CONNECT` handler answered
`501 Not Implemented`, the generated CA was unused, and `TlsHandshakeCapture` had *no live
producer anywhere in the tree*); protocol detection was a **five‑byte sniff**; and there was
no filtering/rule language. This change attacks the foundation‑level items first, because
almost everything else depends on them.

---

## Intuition

The core move is to stop treating a captured connection as an opaque pair of byte pipes and
start treating it as **flows made of frames**.

Concretely, imagine three packets arrive (possibly out of order):

```
seq=101 "GET / HTTP/1.1\r\n"      (client → server)
seq=118 "Host: x\r\n\r\n"          (client → server)
seq=901 "HTTP/1.1 200 OK\r\n\r\n"  (server → client)
```

The new `omnisec-capture` crate hashes the 5‑tuple into a **direction‑independent
`FlowKey`**, so a packet and its reply land in the same bucket. A per‑direction reassembler
orders segments by TCP sequence number — trimming retransmitted overlaps and holding
out‑of‑order segments until the gap fills — and produces two clean streams:

```
client → server:  "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
server → client:  "HTTP/1.1 200 OK\r\n\r\n..."
```

A **port‑independent classifier** then looks at the *bytes*, not the port, and labels the
flow `http1` (or `tls`, `http2`, `websocket`, `dns`, `ssh`). If it's TLS, we parse the
ClientHello for the SNI and a JA3 fingerprint whose MD5 is byte‑for‑byte identical to the
existing Go `netproxy.JA3`.

The same idea drives the TLS interception fix: when a client sends `CONNECT host:port`, we
no longer bail with `501`. We accept the tunnel, **dissect the ClientHello** (SNI, cipher
suites, ALPN, JA3), record a real `TlsHandshakeCapture`, and then transparently relay the
encrypted bytes upstream. That single change turns a dead struct into live evidence that
flows all the way through NCER scoring.

---

## Code

### 1. New crate: `rust/crates/omnisec-capture`

A dependency‑light (`bytes`, `serde`, `sha2`, `md-5`), `#![forbid(unsafe_code)]` crate that
is the new capture foundation.

- **`frame.rs`** — the zero‑copy model. `Frame` carries a `bytes::Bytes` payload (a slice of
  the source buffer, not a copy) and a canonical `FlowKey`:

  ```rust
  let (flow, direction) =
      FlowKey::from_endpoints(Transport::Tcp, src_ip, src_port, dst_ip, dst_port);
  // Both directions of a conversation produce the same `flow`.
  ```

- **`pcap.rs`** — a hand‑rolled `.pcap` reader/writer (both endiannesses, µs/ns magic) plus
  L2→L4 decode for Ethernet / raw IP / BSD loopback / Linux SLL, IPv4+IPv6, TCP+UDP — all
  as zero‑copy `Bytes` slices. No `libpcap` link, so the single‑binary guarantee holds.

- **`flow.rs`** — the `FlowTable` and the TCP reassembler. Sequence math uses RFC‑1982
  serial arithmetic so wraparound is handled:

  ```rust
  fn seq_lt(a: u32, b: u32) -> bool { (a.wrapping_sub(b) as i32) < 0 }
  ```

  It reconstructs owned `Session`s (base64‑encoded streams so binary survives JSON).

- **`classify.rs`** — nDPI‑style `classify(payload, transport) -> Protocol`.

- **`tls.rs`** — `parse_client_hello` → SNI, cipher suites, extensions, curves, ALPN, and a
  JA3 string + MD5 hash matching the Go implementation (same GREASE filtering per RFC 8701).

- **`lib.rs`** — the `PacketSource` trait, an `InMemorySource`, the `CaptureEngine`
  (`ingest_pcap` / `ingest_source` → `sessions()`), and a content‑addressed `session_id`.

### 2. Live TLS handshake capture: `omnisec-mitm`

`TlsHandshakeCapture` gained `ja3`, `ja3_hash`, and `alpn` (all `#[serde(default)]`, so old
capture JSON still deserializes). The new `tls.rs` module does the work:

```rust
pub fn intercept_connect(client, target, sink) {
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    let client_hello = read_tls_record(&mut client)?;
    if let Some(cap) = build_tls_capture(&client_hello, unix_epoch_ms()) {
        sink.lock()?.tls_handshakes.push(cap);        // <-- the dead struct, now alive
    }
    // forward the buffered ClientHello, then splice both directions
    upstream.write_all(&client_hello)?;
    copy_bidirectional(&mut client, &mut upstream)?; // std threads + half-close
}
```

`ssl.rs`'s `CONNECT` branch now calls this behind the existing `host_allowed` allowlist
(loopback/private/`OMNISEC_MITM_ALLOWED_DOMAINS`) instead of returning `501`.
`omnisec-ncer-parse-net` surfaces the JA3/ALPN attributes on the emitted `tls_handshake`
event.

### 3. Extended typed‑event schema

`EventKind` (Rust) and its Go mirror gained `SessionSummary`, `WebSocketMessage`,
`Http2Stream`, `DnsAnswer`, `TcpSegment`, and `QuicEvent`. All existing NCER uses are
equality filters, so adding variants is backward‑compatible; the schema parity tests stay
green.

### 4. End‑to‑end TLS through the Go collector: `pkg/ncer/collect.go`

`mitmCapture.TLSHandshakes` changed from `[]struct{}` (decoded‑and‑ignored) to a real
`[]mitmTLSHandshake`. A new `ObserveTLS(...)` method and TLS handling in
`MergeMitmCaptureJSON` / `buildCapture` carry handshakes all the way into the reconcile
input, so a live SNI/JA3 observation now participates in scoring.

### 5. New Go package: `pkg/internal/netflow`

- **`classify.go`** — the Go twin of the Rust classifier, plus `TLSSNI`.
- **`flow.go`** — a concurrent `FlowTable` that reassembles per‑direction streams and
  classifies flows.
- **`filter.go`** — a **Wireshark‑style display‑filter DSL** (lexer → recursive‑descent
  parser → evaluator):

  ```text
  proto == tls and port == 443
  (proto == http1 or proto == http2) and payload contains "password"
  ip == 10.0.0.5 and not sni matches "\.ads\."
  websocket            # bare protocol name shorthand
  ```

  Fields: `proto`, `ip[.src|.dst]`, `port[.src|.dst]`, `len`, `dir`, `sni`, `payload`.
  Operators: `== != > < >= <= contains matches`. Logic: `and/&& or/|| not/! ( )`.

### 6. WebSocket & HTTP/2 decoders: `pkg/internal/netproxy`

`ws.go` decodes RFC 6455 frames (opcode, FIN, mask, 7/16/64‑bit length) and unmasks client
frames. `http2.go` splits an HTTP/2 stream into its 9‑byte‑header frames (type, flags,
stream id, payload) and strips the connection preface. Both are stream‑oriented, returning
the count of trailing incomplete bytes to prepend to the next read.

---

## Verification

All changes are unit‑tested and were run locally.

- **Rust** (`cargo test`, toolchain 1.96):
  - `omnisec-capture` — **29 tests** (pcap round‑trip, out‑of‑order reassembly, retransmit
    overlap trimming, classification per protocol, ClientHello/JA3/SNI parsing, engine +
    session reconstruction, content‑addressed ids).
  - `omnisec-mitm` — 18 tests incl. new `build_tls_capture` / `parse_connect_target` and a
    legacy‑JSON back‑compat test for the extended `TlsHandshakeCapture`.
  - `omnisec-ncer-types`, `-parse-net`, `-reconcile`, `-reconcile-ffi`, `-evidence` — all
    green after the schema extension.
- **Go** (`go test`, toolchain 1.25.1 with `GOTOOLCHAIN=local`):
  - `go build ./...` clean; `go vet` on touched packages clean.
  - `pkg/ncer/...`, `pkg/internal/netflow/`, `pkg/internal/netproxy/` all pass, including
    new TLS‑collector, display‑filter, and WS/HTTP‑2 tests.
  - Full `./pkg/...` and `./cmd/...` suites pass.

> [!IMPORTANT]
> **Toolchain note.** `go.mod` pins Go 1.27.1. Use that toolchain for local verification
> and CI; `go.mod` is intentionally kept at the project version. No Go 1.27‑specific
> language features are used by
> these changes.

### Manual QA

1. `cd rust && cargo test -p omnisec-capture -p omnisec-mitm` — confirm green.
2. Build a `.pcap` (or use one you own) and feed it through `CaptureEngine::ingest_pcap`;
   inspect `engine.sessions()` — each flow should be classified and, for TLS, carry an SNI.
3. In Go, compile a filter (`netflow.Compile("proto == tls and port == 443")`) and run it
   over a `FlowTable` populated from a captured session.
4. Point an HTTPS client at the SSL‑strip proxy with `OMNISEC_MITM_ALLOWED_DOMAINS` set to a
   domain you own; a `CONNECT` should now yield a `tls_handshake` capture (SNI + JA3) rather
   than a `501`.

---

## Alternatives

**Packet capture: hand‑rolled `.pcap` parser vs. linking `libpcap`.**

| Hand‑rolled (chosen) | Link `libpcap` |
| --- | --- |
| ✅ Keeps the offline, single‑static‑binary guarantee | ✅ Battle‑tested, handles every link type |
| ✅ Zero new system dependencies | ❌ Adds a C dependency + build/runtime coupling |
| ✅ Zero‑copy slices over `bytes::Bytes` | ❌ Copies through the C buffer API |
| ❌ We maintain the format/decode code | ✅ Someone else maintains it |

**TLS interception: metadata‑capturing passthrough vs. full termination.**

| Passthrough + capture (chosen) | Full MITM termination |
| --- | --- |
| ✅ No leaf‑cert minting, trust model unchanged | ✅ Sees decrypted application bytes |
| ✅ Deterministic, easy to test offline | ❌ Needs rustls re‑encryption + minted certs per SNI |
| ✅ Immediately gives NCER real handshake evidence | ❌ Larger, flakier to test without a live TLS peer |
| ❌ Does not decrypt payloads (yet) | ✅ Enables payload‑level analysis |

The passthrough path is deliberately layered so full termination can be added *on top of*
the same ClientHello‑capture step later, reusing the already‑generated root CA.

---

## Suggested people to talk to

Git history for the touched files (`pkg/ncer/collect.go`, `rust/crates/omnisec-mitm/src/*`,
`omnisec-ncer-types`) attributes them to **Promastergame `<semenoviosif6@gmail.com>`** —
effectively the sole author of the network‑interception and NCER code in this repository, so
they are the person to review the FFI‑boundary and NCER‑schema aspects of this change. Note
that the repository was imported as a squashed initial commit, so per‑line authorship signal
is limited; treat this as "the owner of this subsystem" rather than a fine‑grained blame.

---

## Quiz

<details>
<summary>1. Why can a packet and its reply be looked up under the same <code>FlowKey</code>?</summary>

**Because `FlowKey::from_endpoints` sorts the two endpoints into a canonical order.** The
smaller `(ip, port)` becomes side "a", the larger side "b", regardless of which was the
observed source — so `(client→server)` and `(server→client)` hash identically. The function
*also* returns the `Direction` the observed packet travelled, so orientation isn't lost.
(Answer "because both use the same source IP" is wrong — the source differs by direction.)
</details>

<details>
<summary>2. What does the reassembler do with a segment whose sequence number is <em>behind</em> the next expected byte?</summary>

**It treats it as a retransmission and trims the already‑seen overlap.** If `seq < next_seq`,
it computes `overlap = next_seq - seq` and appends only `data[overlap..]` (dropping the
segment entirely if it's fully old). Future segments (`seq > next_seq`) are instead buffered
in a `BTreeMap` until the intervening gap fills.
</details>

<details>
<summary>3. Why was extending <code>TlsHandshakeCapture</code> with <code>ja3</code>/<code>alpn</code> safe for the Go boundary?</summary>

**Because the new fields carry `#[serde(default)]` and the Go side decodes `tls_handshakes`
without requiring them.** Old capture JSON that lacks the fields still deserializes (they
default to empty), and Go's `encoding/json` ignores unknown/extra fields. A regression test
(`tls_handshake_capture_decodes_legacy_json_without_ja3_fields`) locks this in.
</details>

<details>
<summary>4. In the display‑filter DSL, what does <code>ip != 10.0.0.5</code> match?</summary>

**Flows where <em>neither</em> endpoint is `10.0.0.5`.** For the unqualified `ip` field, `==`
means "either side equals" (an OR), so its negation `!=` must mean "neither side equals" (an
AND of both `!=`). Evaluating `!=` as a simple OR would incorrectly match a flow where the
other endpoint equals the value.
</details>

<details>
<summary>5. Why does the classifier check the HTTP/2 preface before the HTTP/1 methods?</summary>

**Because the HTTP/2 preface begins with <code>"PRI "</code>, which also looks like the start
of an HTTP/1 request line.** `PRI` is a real (rarely used) HTTP method token, so checking
HTTP/1 first would misclassify the preface as HTTP/1. The classifier matches the fixed
24‑byte preface first, then falls through to the HTTP/1 method/status‑line check.
</details>
