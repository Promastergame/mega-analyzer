# BinZAP Changelog

## 2.0.0 — Production-grade static security analyzer

This release upgrades BinZAP from a pattern matcher with a randomized "active
fuzzer" into a real static-analysis engine. Mapping to the engineering spec
(INC1–INC13):

### INC1 — Correctness & foundations
- Fixed the x86 lexer: quoted strings now tokenize as `LiteralString`;
  call/branch targets as `MethodRef`; comment stripping is quote-aware.
  Preserved existing contracts (`mov eax, myLabel` → Unknown; `nop ; comment`
  → single token).
- `finding.go`: additive enriched fields (CWE, RuleName, Column, Category,
  Remediation, Exploitability, DataSource, AttackPath, Fingerprint) with JSON
  tags; `ComputeFingerprint`, `SortFindings`, `DedupeFindings`.
- Removed import-time filesystem side effects from the dynamic rule store; it
  now loads lazily via `sync.Once` and persists atomically (temp + rename).
- Introduced `version.go` (`BinZAPVersion`).

### INC2/INC3 — IR & abstract representation
- New `ir` package: dialect-neutral IR, `LowerTokens`, register recovery,
  method segmentation, `move-result` linking, basic-block construction.

### INC4 — Real active analysis (taint) + secrets integration
- New `analysis` package: source/sink catalog, CFG, intra-procedural taint
  engine with full attack paths.
- `RunActiveAnalysis` / `RunActiveFile` replace the randomized fuzzer, which is
  now quarantined behind the `legacy_fuzzer` build tag.
- `secrets_taint.go` reuses the EXISTING `secrets.DetectProviders` to seed
  credential taint (no second secret scanner was built).

### INC5 — Vulnerability engine
- CWE-mapped detections with severity, confidence, evidence, remediation,
  exploitability and attack path (CWE-78/89/22/502/918/470/327/798/532).

### INC6 — Mobile analysis
- `mobile_rules.go`: WebView JS bridge/config, insecure IPC/Intent, broken TLS
  validation, dangerous permission/device-data access.

### INC7 — Malware behavior
- `malware_rules.go`: weighted indicators (obfuscation, anti-analysis, dynamic
  loading, execution, exfiltration, SMS fraud) with an aggregate score.

### INC8 — Rule system redesign
- `registry.go`: explicit registration with metadata, packs, profiles,
  per-rule overrides, duplicate-ID rejection (no global init registration).

### INC9 — Performance
- `RunScanDirectory`: bounded worker pool, `context` cancellation, progress
  callback, memory-efficient per-file processing, deterministic merge.

### INC10 — Reporting
- Markdown, JSON, SARIF 2.1.0 and self-contained HTML; fingerprints, dedup,
  baseline suppression, false-positive rule suppression.

### INC11 — Code quality
- Removed global mutable state and import-time FS mutations; DI-friendly
  registry; report-injection hardening (pipe/fence/HTML escaping).

### INC12 — Testing
- Unit + integration + regression tests for ir, analysis, registry, baseline,
  reporter, mobile and malware packs, including negative cases.

### INC13 — Documentation
- `docs/ARCHITECTURE.md`, `RULE_DEVELOPMENT.md`, `THREAT_MODEL.md`,
  `PERFORMANCE.md`, `USAGE.md`.

### Migration notes
- The old `ActiveFuzzer` API and its tests now require `-tags legacy_fuzzer`.
  If other packages (e.g. `cmd/`) referenced the fuzzer directly, switch them
  to `RunActiveAnalysis` / `RunActiveFile`.
