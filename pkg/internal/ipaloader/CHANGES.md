# ipaloader — refactor changelog

This package was reworked to production-grade quality. **CI intentionally omitted** per request.

> ⚠️ I could not compile/run these in the delivery sandbox (no Go toolchain, network disabled).
> Run in your repo: `go test ./... -race` and `go test -run=x -fuzz=Fuzz... -fuzztime=30s`.

## Breaking API change

- `CrackPointsForIPA(appDir, bundleID)` → `CrackPointsForIPA(ctx context.Context, appDir, bundleID)`.
  Update every caller to pass a `context.Context` (use `context.Background()` if you have none).
- New: `CrackPointsForIPAWithClassifier(ctx, appDir, bundleID, SecretClassifier)` for dependency injection.

## crackpoints.go

1. **Fat/universal Mach-O support.** `macho.NewFatFile` is tried first and every architecture
   slice is inspected for imported symbols, linked libraries and FairPlay `cryptid`. Previously
   fat binaries silently fell back to the raw-string path only (major recall loss).
2. **Single-pass string extraction.** Strings are extracted once per binary and shared by the
   symbol path (minLen 5) and the secret path (minLen 12) — the previous code scanned twice.
   Extraction is now capped (`MaxStringsPerBinary`) to bound memory.
3. **Concurrent scanning + context.** Binaries are scanned with a bounded worker pool
   (`ScanConcurrency`, default `NumCPU`); the whole scan honours `ctx` cancellation. Each
   goroutine uses its own `crackpoint.Finder` to avoid shared mutable state.
4. **Pluggable secret classifier.** `SecretClassifier` interface decouples scanning from the
   `llmkeys` engine (mockable in tests). The default adapter serializes cache access with a mutex
   for concurrency safety.
5. **Bounded reads.** `MaxBinarySize` caps how much of a binary is read; oversized binaries emit a
   coverage finding instead of exhausting memory.
6. **Silent truncation fixed.** Hitting `MaxBinaries` now emits a coverage finding.
7. **Entitlement filtering.** `entitlementKeys` now keeps only real-looking entitlements
   (dotted keys + a small dotless allow-list), removing false positives from arbitrary `<key>`s.
8. **Hardened secret masking** (`first2 + … + last1`) and raw values are dropped right after use.
9. **Deterministic output.** Crack points and findings are sorted before returning.

## loader.go

1. **Real XML plist parsing** via `encoding/xml` streaming decoder (handles entities, multiline
   values, nested dicts) instead of per-key regex compiled on every call.
2. **Real binary plist (bplist00) parsing** — proper trailer/offset-table/object decode with a
   tolerant heuristic fallback for malformed/synthetic payloads.
3. **Anti-zip-bomb extraction:** per-file size cap, total-size budget, compression-ratio guard,
   symlink-entry skipping (in addition to the existing zip-slip guard).
4. **Tightened extraction surface** (`shouldExtract`) so framework asset files are no longer
   written to disk.
5. **Deterministic permission audit** (sorted keys) + placeholder-description detection.
6. **Capped plist reads** (`MaxPlistSize`).

## Tests added

- `fuzz_test.go`: fuzz targets for string extraction, bplist decode, heuristic scan, XML parse.
- `security_test.go`: zip-bomb rejection, total-budget abort, extraction-surface, DI with a stub
  classifier, masking policy.
- `bench_test.go`: benchmarks for string extraction and full scan.
- `crackpoints_test.go`: updated for the `ctx` signature; added cancellation + entitlement-filter tests.

## Not done (by request)

- CI / linters / scanners (`golangci-lint`, `gosec`, `govulncheck`, coverage gates).
- SARIF export + data-driven rule catalog (larger, touches the internal `crackpoint`/`types`
  packages that were not part of these files) — left as a follow-up PR.
- UTF-16 string extraction (kept ASCII-only to stay low-risk); noted as a future enhancement.

## Review round (2026-09)

`loader.go`

1. **Plist routing by document start.** `ParseInfoPlist` routed on a substring match, so a
   binary plist containing `<?xml`/`<plist` inside a stored string was fed to the XML parser
   (silent empty result). Binary prefix is now authoritative; the substring check survives
   only as a fallback for exotic XML with leading comments. BOM + leading whitespace handled.
2. **XML depth cap** (`maxXMLPlistDepth = 64`): the bplist parser had a recursion guard,
   the XML one did not — hostile nesting is now cut to nil past the cap, top-level keys
   still resolve.
3. **Modern privacy keys**: ATT/tracking, local network, health share/update, calendars,
   reminders, motion, photo-add, music, Siri, video-subscriber, NFC, legacy location/BT.

`crackpoints.go`

4. **fat64 magics** (`0xCAFEBABF`/`0xBFBAFECA`) recognized; `.class` files skipped (their
   `CAFEBABE` collides with the fat magic).
5. **Entitlements scoped to `__TEXT,__entitlements`** (thin + all fat slices, slice-relative
   offsets rebased) with whole-data fallback for non-Mach-O input — dotted `<key>`s from
   embedded non-entitlement plists no longer leak in.
6. **Triage sort**: findings order most-severe-first via the ordered `types.Severity`
   (was alphabetical accident + a Sprintf per comparison).

Deliberately not changed: `DetectIPA` stays loose (an existing test pins detection of
`Payload/*.app/` without `Info.plist` — routing-only cost, no analysis impact).

Tests: `ipaloader_review_test.go` (7 tests: routing, depth cap, privacy keys, fat64,
.class skip, section scoping on a hand-built Mach-O, sort order).
