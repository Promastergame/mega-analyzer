# Evidence

Evidence is append-only and content-addressed by lowercase SHA-256 hex.

```text
<root>/<first-two-hex>/<remaining-62-hex>
```

Both implementations validate references before resolving paths, deduplicate identical bytes, and verify stored content by rehashing it. A finding is marked `evidence_verified` only when all of its references verify. Neither implementation signs evidence or provides a retention policy.

The Go implementation additionally keeps an in-memory cache of hashes it has already confirmed on disk this process (`EvidenceStore.known` in `pkg/ncer/evidence.go`), so a repeat `Store` call for identical bytes — common within a single sandbox run, where the same request or response body is often observed more than once — returns without touching the filesystem at all, not just without rewriting the file. See [`docs/benchmarks/ncer_performance.md`](../benchmarks/ncer_performance.md) for the rationale.

## Two independent `EvidenceStore` implementations

`rust/crates/omnisec-ncer-evidence` (`EvidenceStore`) and `pkg/ncer/evidence.go` (`ncer.EvidenceStore`) are two separate implementations, not FFI-bound to each other — Go does not call into the Rust crate to store or retrieve evidence, and vice versa. They agree byte-for-byte on the on-disk layout (SHA-256 hex digest, git-object-style sharding: `<root>/<first-two-hex>/<remaining-62-hex>`), so evidence written by one is readable by the other if pointed at the same root — but nothing in this repository does that today.

The Go implementation is the one actually wired into the live CLI: `pkg/cmd/analyzer/runner_stream.go` opens one via `ncer.OpenEvidenceStore` and attaches it to the `ncer.Collector`, and `Collector.Reconcile` stores the capture JSON there. The Rust implementation is exercised by its own unit tests and by `omnisec-ncer-reconcile::evidence::store_and_verify`, but `omnisec_ncer_reconcile` — the only FFI entry point Go calls — does not use it; reconciliation results returned across the FFI boundary carry no evidence references from the Rust side.

This duplication is intentional, not an oversight: the Rust store exists so the reconciliation crate's evidence helper (`store_and_verify`) has something to test against, and the two on-disk layouts were deliberately kept identical so the two implementations stay interchangeable. Do not "clean this up" by deleting one implementation without first confirming whether `omnisec_ncer_reconcile` has been changed to call into the Rust store — as of this writing it has not.

> **Note:** `feedNcerMitmCapture` (`pkg/cmd/analyzer/ncer_mitm_capture.go`) drains real MITM captures from the Rust proxy runners via `omnisec_mitm_take_capture` and merges them into the `Collector` (`Collector.MergeMitmCaptureJSON`) alongside Go-synthesised events. Both feed the same `buildCapture`/`buildReconcileInput` path, so `Collector.Reconcile` stores the combined JSON — Rust-originated and Go-synthesised together — in the Go `EvidenceStore` the same way it always has. The Rust `EvidenceStore` would only become relevant if `omnisec_ncer_reconcile` itself were extended to persist its inputs, which it still does not.

## Go example

```go
store, _ := ncer.OpenEvidenceStore("./evidence")
hash, _ := store.Store([]byte("capture payload"))
ok, _ := store.Verify(hash) // true
```
