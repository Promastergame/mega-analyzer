# NCER performance

## Methodology

All numbers below were measured with the real Rust FFI linked, not the
no-op stub:

```sh
cd rust && cargo build --release -p omnisec-ncer-reconcile-ffi
LD_LIBRARY_PATH=$(pwd)/rust/target/release CGO_ENABLED=1 \
  go test -tags 'cgo omnisec_ncer_reconcile_ffi' -bench . -benchmem -run '^$' ./pkg/ncer/...
```

Without that build (plain `go test -bench . ./pkg/ncer/...`), `RunReconcile`
hits the stub and returns `ErrRustNotLinked` immediately — the benchmarks
still run, but they measure an early-return error path, not reconciliation
work. That distinction matters: an earlier version of this document reported
`BenchmarkReconciliation_*` numbers in the 0.36 ns/op / 0 B/op / tens-to-
thousands of GB/s range, which is the signature of the stub's immediate
error return, not real FFI dispatch. Re-run the command above before trusting
any reconciliation-throughput number in this file.

Environment: Linux ARM64, `go test`'s default `-benchtime` (≈1s per
benchmark), 3 repetitions to confirm stability. `BenchmarkReconciliation_*`
numbers include full round-trip cost: Go-side JSON marshal of the capture,
the cgo call, Rust-side JSON decode, `from_mitm_capture` → `bind_effects` →
`score_causal`, JSON re-encode, and the cgo call back — not just Rust-internal
work.

## Results

| Benchmark | ns/op | B/op | allocs/op | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `BenchmarkEventParsing` (100 events) | ~750,000 | ~56,900 | ~1,012 | Go-only: `Collector.ObserveHTTP` + `buildCapture`, no FFI |
| `BenchmarkReconciliation_100` | ~2,600,000 | ~22,300 | 9 | full FFI round trip, 100 events |
| `BenchmarkReconciliation_1000` | ~23,700,000 | ~221,800 | 9 | full FFI round trip, 1,000 events |
| `BenchmarkReconciliation_10000` | ~236,000,000 | ~2,180,000 | 9–10 | full FFI round trip, 10,000 events |
| `BenchmarkEvidenceStorage_New` | ~1,000,000–1,400,000 | 625 | 5 | Go `EvidenceStore.Store`, new content |
| `BenchmarkEvidenceStorage_Verify` | ~1,300,000–1,450,000 | 1,256 | 8 | Go `EvidenceStore.Verify` |
| `BenchmarkEndToEndPipeline` | ~7,200,000–18,300,000 | ~138,000–156,000 | ~1,040–1,050 | 100 events: observe → build capture → reconcile → store |

`BenchmarkReconciliation_*` scales close to linearly with event count
(100 → 1,000 is ~9x, 1,000 → 10,000 is ~10x), which is expected after the
`bind_effects` fix described below.

## `bind_effects` was quadratic; now it's `O(n log n)`

While regenerating these numbers, `BenchmarkReconciliation_10000` initially
measured **29.7 seconds per op** — three orders of magnitude worse than
`BenchmarkReconciliation_1000`'s 269 ms, instead of the ~10x a linear
algorithm would show. The cause: `bind_effects`
(`rust/crates/omnisec-ncer-reconcile/src/effect_binder.rs`) matched each
response against every unbound request with a linear scan
(`requests.iter().filter(...).filter(...).filter(...).max_by(...)`), making
the whole function `O(requests × responses)`.

It's now indexed: requests are grouped by `(method, url)` into a
`BTreeMap<timestamp, {ids}>` per key, and each response resolves its
nearest-preceding-within-window candidate via a single predecessor lookup
(`BTreeMap::range(..=response_time).next_back()`) instead of a full scan,
making the function `O(n log n)`. Binding semantics — nearest preceding
request within the window, ties broken by the lexicographically greatest id,
each request binds at most once — are unchanged and covered by the existing
`effect_binder` test suite plus two new tests
(`same_timestamp_candidates_tie_break_by_greatest_id`,
`large_capture_across_many_keys_binds_correctly`). Before/after, same
`BenchmarkReconciliation_10000` fixture:

| | before | after |
| :--- | :--- | :--- |
| 10,000 events | ~29.7 s/op | ~236 ms/op |

## Other hot paths

- `omnisec-ncer-parse-net::from_mitm_capture` preallocates its output
  `Vec` from the capture's item counts, so it never reallocates while
  converting.
- `Collector.buildCapture` (`pkg/ncer/collect.go`) preallocates its request/
  response slices from the accumulated event count and copies the event
  slice under a short mutex hold rather than holding the lock while building
  JSON.
- `EvidenceStore.Store` (both languages) is a no-op after the first write for
  a given hash — it checks whether the content-addressed path already exists
  before writing.

Benchmarks live in `pkg/ncer/bench_test.go`. Re-run them (with the FFI tag)
after changing any of the above; correctness and deterministic output take
precedence over micro-optimizations.

## `run_pipeline`'s three binders: parallel only pays off at scale

v2.0 added two more binders (`bind_authority`, `bind_dns_flow`) alongside
`bind_effects`, all invoked from `run_pipeline`
(`rust/crates/omnisec-ncer-reconcile-ffi/src/lib.rs`). They read the same
`&[TypedEvent]` slice and touch disjoint `EventKind` subsets, so there's no
data dependency between them — a natural fit for `std::thread::scope`.

Naively parallelizing unconditionally was tried first and measured against
serial execution with `BenchmarkReconciliation_Combined_1000/30000/100000`
(`pkg/ncer/bench_test.go`), each built from `Collector.buildReconcileInput`
so all three binders see real work (HTTP causal events, DNS/flow pairs, and
authority grants together, not just one binder's slice populated and the
other two empty):

| combined event count | serial | parallel (unconditional) |
| :--- | :--- | :--- |
| 1,000 | ~15–17 ms/op | ~17–18 ms/op (parallel **loses**, ~10–15%) |
| 10,000 | ~150–159 ms/op | ~159–210 ms/op (within noise) |
| 30,000 | ~492–535 ms/op | ~479–522 ms/op (within noise) |
| 100,000 | ~1.95–2.22 s/op | ~1.71–1.79 s/op (parallel **wins**, ~8–10%) |

`bind_effects` (HTTP causal binding) does the bulk of the work in a typical
capture, so the other two threads finish early — the achievable overlap is
bounded by how much of `bind_effects` alone can run concurrently with the
smaller two, not a clean 3x. At small scale, three `std::thread::scope`
spawns cost more than they save; only once each binder has enough work does
the overlap pay for itself.

`run_pipeline` now switches on `total_events`: below
`PARALLEL_BINDER_THRESHOLD` (50,000, a conservative pick from the untested
gap between the 30,000 wash and the 100,000 win — the true crossover wasn't
pinned down further) it binds serially; at or above it, it uses
`std::thread::scope` as before. This keeps the common case (small-to-medium
captures from a single sandbox run) on the faster serial path while still
gaining at the sizes where parallelism actually helps (aggregated/batched
reconciliation, high-traffic captures).

## `EvidenceStore.Store`: in-memory dedup cache, and a concurrency fix found along the way

`EvidenceStore.Store` was already a no-op after the first write for a given
hash (`os.Stat` before writing), but that still cost one syscall per call
even for content already known to be on disk — and a sandbox run's evidence
is dominated by duplicates (the same request retried, the same response body
observed more than once; see `TestValidation_DuplicateEvidenceRatio` in
`ncer_validation_test.go`). `EvidenceStore` now keeps an in-memory
`known map[string]struct{}` of hashes it has confirmed on disk this process;
a repeat `Store` call for identical bytes returns straight from that map,
skipping the `os.Stat` entirely
(`TestEvidenceStore_RepeatedStoreSkipsDiskAfterFirstWrite` in
`evidence_test.go` proves this by deleting the underlying file between two
`Store` calls and confirming the second call doesn't recreate it).

Writing a concurrency test for the new cache
(`TestEvidenceStore_StoreIsRaceFree`) surfaced a pre-existing bug unrelated
to the cache itself: concurrent `Store` calls for identical content shared
the same temp filename (`path + ".tmp"`), so whichever goroutine renamed
first deleted the temp file out from under the other's `os.Rename`, which
then failed with `ENOENT`. Fixed by using `os.CreateTemp` for a unique temp
name per call; concurrent renames to the same final path now race safely
(POSIX `rename(2)` is an atomic replace, and the content is identical either
way since it's keyed by hash).
