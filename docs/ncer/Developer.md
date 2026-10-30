# Developer guide

Run from the repository root:

```sh
(cd rust && cargo fmt --check)
(cd rust && cargo clippy --workspace)
(cd rust && cargo test --workspace)
gofmt -w ./pkg/ncer
go vet ./...
go test ./...
```

The commands above build and test everything *except* the real FFI path — `pkg/ncer/reconcile` and `pkg/ncer/mitmbridge` fall back to stub implementations (`ErrRustNotLinked`) without cgo and the right build tags. Before trusting a change to `run_pipeline`, `bind_authority`, `bind_dns_flow`, or any scoring function, also run against the real linked library:

```sh
(cd rust && cargo build --release -p omnisec-ncer-reconcile-ffi)
LD_LIBRARY_PATH=$(pwd)/rust/target/release CGO_ENABLED=1 \
  go test -tags 'cgo omnisec_ncer_reconcile_ffi omnisec_mitm_ffi' ./pkg/ncer/... ./pkg/cmd/analyzer/...
```

If a cgo-linked test crashes with a segfault inside the Rust call and the Rust-side unit tests pass fine on their own, suspect a stale/partially-written `.so` from an interrupted or concurrent build before suspecting a real bug — `cargo clean -p omnisec-ncer-reconcile-ffi --release && cargo build --release -p omnisec-ncer-reconcile-ffi` has resolved this every time it's come up.

Keep Rust and Go event/result JSON schemas synchronized. Add compatibility tests before changing field names, event kinds, evidence layout, or reconciliation ordering.

## Reading JSON results

A result such as `{"d_causal":0.25,"coverage_quality":0.75,"d_authority":0.0,"d_information":0.5,"d_capability":0.1,"d_consequence":0.0,"d_novelty":0.0}` means: one quarter of observed HTTP effects were unbound within the causal window, half of observed network flows had no explaining DNS resolution, one tenth of granted permissions went unused, no unauthorized actions were observed, and no sandbox findings or novelty baseline were attached to this run (`d_consequence`/`d_novelty` are Go-computed and stay `0.0` unless `SetAnomalyFindings`/`SetBaselineDir` were called — see [Reconciliation.md](Reconciliation.md)).
