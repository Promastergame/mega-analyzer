# Performance & scalability (INC9)

## Parallelism

`RunScanDirectory(ctx, dir, ScanOptions{Workers: n})` processes files with a
bounded worker pool (default `runtime.NumCPU()`). Each file is lexed, lowered
and analyzed independently, so throughput scales with cores.

## Memory efficiency

- Files are read and analyzed one at a time per worker; only findings are
  retained, not token streams or IR.
- The IR is intentionally small (linear instruction list + one block per
  method for the intra-procedural pass).

## Cancellation & progress

- Pass a `context.Context`; cancellation stops feeding new files and returns
  `ctx.Err()`.
- `ScanOptions.Progress(done, total)` is invoked as files complete (guarded by
  a mutex; safe to update a UI/CLI progress bar).

## Incremental scanning

Use a `Baseline` to suppress previously-seen findings so CI-style repeat scans
surface only new issues. Fingerprints exclude line numbers, so edits above a
finding do not churn results.

## Determinism

Results are de-duplicated by fingerprint and sorted by (severity, file, line),
producing stable output suitable for diffing between runs.
