# Code Review Standard and Process

## 1. Purpose

Code review exists to prevent defects from reaching `main`, preserve Mega-Analyzer's security and offline guarantees, and keep a large multi-language codebase understandable for a solo maintainer.

This is a **risk-control mechanism**, not a style ceremony. Automated formatters own formatting. Review effort goes to correctness, security, compatibility, performance, tests, and truthful product behavior.

Because Mega-Analyzer is solo-maintained and does not accept pull requests, "review" normally means a structured self-review of a branch or commit range before merge or release. A second human or AI reviewer is useful for high-risk changes, but is not required for routine work.

## 2. Non-negotiable principles

1. **Review a diff, not an intention.** Inspect the complete change, including tests, generated artifacts, configuration, dependencies, build tags, and error paths.
2. **Prove important claims.** "Works" requires a test, reproducible command, sample result, or explicit reasoning when execution is unavailable.
3. **Risk determines depth.** A parser or sandbox change receives more scrutiny than a documentation correction.
4. **No silent degradation.** Optional native functionality may report that it is unavailable, but must not pretend to have run successfully.
5. **Preserve product invariants.** Samples stay local, servers bind safely, untrusted input is bounded, reports are deterministic, and findings are not silently lost.
6. **Fix the cause, not the symptom.** A regression test should fail before the fix when practical and pass afterward.
7. **Keep review local and affordable.** Use existing local commands first. External or paid infrastructure is not a prerequisite.

## 3. Scope

Review source and configuration owned by Mega-Analyzer, including:

- Go code under `cmd/` and `pkg/`
- Rust workspace code under `rust/crates/`
- Zig code under `zig/`
- Elixir application code under `server/lib/`, `server/config/`, and `server/test/`
- Build, packaging, database, container, and workflow files
- User-visible rules, reports, schemas, defaults, CLI flags, API contracts, and documentation

Do not spend line-by-line review time on generated or third-party content unless the change intentionally updates it:

- `rust/target/`, `_build/`, `server/deps/`, `deps/`, `node_modules/`
- `analysis_output/`, `test_out/`, `bin/`, `bin_backups/`, `dist/`
- binaries, archives, logs, caches, coverage output, and generated reports
- `.claude/worktrees/` or equivalent secondary worktrees

Generated artifacts still require a provenance check: identify the source change and command that produced them, and verify that no secret, sample, or machine-specific path was embedded.

## 4. Change risk classification

Classify the change before reviewing it. When several classes apply, use the highest.

| Risk | Typical changes | Required depth |
|---|---|---|
| **R0 — Trivial** | Comments, spelling, non-behavioral docs | Diff review; validate links/commands affected |
| **R1 — Routine** | Isolated refactor, internal helper, additive rule, small UI behavior | Focused tests, formatter/static checks for touched language, contract review |
| **R2 — Significant** | Pipeline ordering, concurrency, caching, CLI/API schema, report format, database behavior, FFI/build tags, dependency update | Regression tests, adjacent integration tests, failure-path review, compatibility and performance checks |
| **R3 — Critical** | Untrusted binary/archive parsers, sandbox execution, proxy/DNS/HTTP listeners, path handling, credential or telemetry logic, cryptography, updater/package signing, unsafe/native boundary, ML verdict semantics, release build | Threat-focused review, adversarial tests or fuzz corpus, race/resource-limit checks, end-to-end evidence, explicit rollback plan; independent second-pass review strongly recommended |

A large diff is not automatically high risk, but it is harder to review reliably. Split unrelated concerns. For R2/R3 changes, prefer review units under roughly 400 changed source lines; if that is impractical, provide a file-by-file review map.

## 5. Finding severity

Every actionable review comment gets one severity.

### 🔴 Blocker — must resolve before merge

Use for behavior that can cause:

- security vulnerability, sample escape, outbound communication, or non-local binding
- path traversal, arbitrary write, destructive overwrite, data corruption, or secret exposure
- race, deadlock, unbounded resource consumption, or parser panic on realistic untrusted input
- broken CLI/API/report contract without migration or release note
- a feature, flag, stage, or check reporting success while doing nothing or failing
- materially wrong detection verdict, evidence, precision/recall behavior, or cryptographic result
- critical paths that ignore errors or have no meaningful validation

### 🟡 Suggestion — should resolve or record a reason

Use for:

- missing boundary validation or important regression test
- unclear ownership, state transition, or lifecycle
- avoidable performance cost on common analysis paths
- duplicated logic likely to diverge
- insufficient observability or diagnostics
- maintainability problems that make the next defect likely

### 💭 Nit — optional improvement

Use for small naming, documentation, or readability improvements not enforced by tooling. Nits never block a merge.

### Questions

Use **❓ Question** when intent is unclear. A question becomes a blocker only after the answer establishes a concrete risk.

## 6. Review comment standard

A useful comment contains location, impact, reasoning, and a practical suggestion.

```text
🔴 **Correctness: stage reports success after a failed check**
`cicd.ps1:254-265` catches formatter and Clippy failures as warnings, while the
stage is later recorded as Passed.

Why: a release can be presented as quality-checked even when the checks failed.

Suggestion: collect each exit status and mark the stage failed; keep a separate
explicit best-effort mode if warning-only behavior is desired.
```

Avoid comments such as "bad code", "needs cleanup", or "add tests" without naming the missing behavior.

## 7. Universal review checklist

### Correctness

- [ ] The implementation matches the stated behavior and all affected call sites are connected.
- [ ] Success, empty input, malformed input, partial failure, cancellation, timeout, and retry paths make sense.
- [ ] Errors are propagated or deliberately handled; logs do not substitute for control flow.
- [ ] State transitions and ordering are valid. Results are consumed by the next stage rather than computed and discarded.
- [ ] Defaults, flags, configuration fields, and build tags reach the implementation they claim to control.
- [ ] No integer boundary, Unicode/encoding, endianness, signedness, or truncation mistake is apparent.
- [ ] Output is deterministic where users, baselines, caches, or tests rely on it.
- [ ] Existing CLI, API, JSON/SARIF/report, database, and file-format contracts remain compatible or are intentionally versioned.

### Security and privacy

- [ ] All file, archive, network, and model inputs are treated as hostile.
- [ ] Parsing has size, count, depth, recursion, allocation, and timeout limits.
- [ ] Archive extraction and report writing prevent `..`, absolute-path, symlink, device-name, and overwrite attacks.
- [ ] Executed commands avoid shell interpolation; arguments are separated and executable paths are controlled.
- [ ] HTTP/API routes enforce method, content type, body limit, authentication/authorization where applicable, and safe error responses.
- [ ] Servers and proxies default to loopback; broader binding is explicit and visibly warned.
- [ ] No telemetry, update check, DNS leak, or outbound call violates offline operation.
- [ ] Logs and reports redact credentials, tokens, private keys, sample contents, and sensitive host paths.
- [ ] Temporary files have safe permissions, unpredictable names, cleanup, and no unsafe reuse.
- [ ] FFI/NIF/cgo boundaries validate pointer, length, ownership, lifetime, panic/unwind, and error conversion.
- [ ] New dependencies and copied code are compatible with BSD-3-Clause OR GPL-2.0-only and have an understood provenance; preserve their own licenses and notices.

### Concurrency and lifecycle

- [ ] Shared mutable state is synchronized or immutable.
- [ ] Goroutines, processes, ports, files, sockets, timers, tasks, and NIF resources are closed on every path.
- [ ] Cancellation propagates; background work cannot outlive its owner unexpectedly.
- [ ] Locks are not held across slow I/O or callbacks; lock order is consistent.
- [ ] Caches have safe keys, invalidation, bounds, and concurrent behavior.
- [ ] Parallel execution does not make ML/model state, reports, or ordering nondeterministic without intent.

### Performance and resilience

- [ ] The hot path does not introduce accidental quadratic scans, repeated parsing, excessive copies, or per-item process creation.
- [ ] Memory use is bounded for malicious and very large samples.
- [ ] Expensive optional analysis is gated and reports capability accurately.
- [ ] Benchmarks or before/after measurements accompany material hot-path changes.
- [ ] Failure of an optional component does not corrupt or mislabel the core result.

### Maintainability

- [ ] Names describe domain intent; comments explain constraints and reasoning, not syntax.
- [ ] One source of truth exists for flags, schemas, rule metadata, and configuration.
- [ ] New abstractions reduce coupling rather than merely moving code.
- [ ] Dead-looking branches, stubs, or compatibility code are explicitly marked with their contract and removal condition.
- [ ] User-visible behavior and operator commands are documented in the same change.

### Tests and evidence

- [ ] A regression test covers each fixed defect when practical.
- [ ] Tests verify outputs and side effects, not only that code returned no error.
- [ ] Negative/adversarial cases are present for parsers, security boundaries, and detectors.
- [ ] Tests avoid false confidence from mocks that bypass the behavior under review.
- [ ] Detection changes include representative true positives and true negatives.
- [ ] Concurrency changes run under the race detector where supported.
- [ ] Test data is legal to distribute, minimal, deterministic, and free of real secrets.

## 8. Mega-Analyzer risk checklists

### Parsers, loaders, unpackers, and deobfuscation

- Never trust offsets, lengths, counts, section tables, archive names, compression ratios, recursion, or declared encodings.
- Validate before slicing or allocating. Prefer checked arithmetic.
- A malformed sample must produce a bounded error, not a panic, hang, host write, or process execution.
- Transformations must preserve semantics or attach evidence explaining intentional uncertainty.
- Unicode tests must include non-ASCII text; byte heuristics must not accidentally classify UTF-8 as encrypted or binary.
- Deobfuscation results must feed the stages and report fields that claim to use them. A counter alone does not prove a transformation occurred.

### Detection rules, evidence, and ML/GNN

- Every detector change defines expected severity, confidence, rule ID, evidence location, and suppression behavior.
- Add at least one positive and one confusing negative fixture.
- Do not silently delete low-confidence findings; demotion and suppression must be explicit and testable.
- Precision/recall changes require the local evaluation gate or a documented targeted substitute.
- Features must be populated in production data flow, not only unit tests. Verify non-empty input at the integration boundary.
- Model/version mismatch, missing weights, unsupported CPU, or unavailable native runtime must be diagnosed explicitly.
- Do not replace or downgrade the GNN as a code-review shortcut; review its wiring, contracts, evidence, and fallback behavior.

### CLI, API, Web UI, proxy, and sandbox

- CLI flags need parser tests plus a test showing the resulting configuration affects runtime behavior.
- API changes define status codes, body limits, validation, cancellation, and compatibility.
- HTML and report rendering escape untrusted sample-derived values in the correct context.
- File download and artifact endpoints canonicalize paths and enforce an allowed root.
- SSE/WebSocket clients have disconnect cleanup and bounded queues.
- Sandbox commands use argument arrays, restricted working directories, timeouts, and cleanup.
- Listeners bind to `127.0.0.1`/`::1` by default. Any LAN exposure is explicit and documented.

### Build, FFI, packaging, and release

- Review all feature tags and platform-specific files together with their stubs.
- Build scripts must stop on failed quality checks unless the user selected an explicit best-effort mode.
- A lint/check command must not silently modify the working tree.
- Produced binaries and native libraries agree on ABI, architecture, version, and runtime location.
- Release archives contain only intended files; hashes/signatures are generated from final artifacts.
- Toolchain/documentation versions agree, or the difference is intentional and tested.

## 9. Review process

### Step 1 — Define the change

Before coding or at review start, write a short change brief:

```text
Goal:
User-visible behavior:
Risk class: R0 / R1 / R2 / R3
Affected surfaces:
Invariants that must remain true:
Validation plan:
Rollback:
```

For defect fixes, include the reproduction and expected result. For R2/R3, identify trust boundaries and failure modes.

### Step 2 — Prepare a reviewable diff

- Keep one behavioral purpose per branch or commit series.
- Remove unrelated formatting and generated churn.
- Review `git diff --check`, the changed-file list, and the complete diff from the chosen base.
- Mark generated files and explain their regeneration command.
- If the diff is large, add a review map: entry points → core logic → outputs → tests.

### Step 3 — Author self-review

Read the final diff as if it were unfamiliar code:

1. Trace the data from input to observable output.
2. Trace at least one failure path.
3. Search for every caller, configuration field, build-tag sibling, and output consumer affected.
4. Confirm that tests would fail if the new logic were disconnected or reverted.
5. Add findings to a review record; fix blockers before requesting another pass.

### Step 4 — Run proportionate local checks

Run checks for touched components first. Use the matrix in section 10. For R2/R3, add integration, race, evaluation, adversarial, or release-build evidence as applicable.

Record exact commands and outcomes. "Not run" is acceptable only with a reason and an explicit residual risk.

### Step 5 — Independent second pass

Use a second human or an independent AI review for:

- every R3 change
- R2 changes involving concurrency, FFI, public contracts, pipeline ordering, model features, or destructive file behavior
- changes whose author found a blocker during self-review
- releases after substantial cross-language integration

The second pass receives the change brief, diff, test evidence, and known limitations. It should not be asked merely "does this look good?"; ask it to challenge specific risks.

### Step 6 — Resolve findings

- **Blocker:** fix and re-run affected evidence.
- **Suggestion:** fix, or record a concise reason for deferral and create a tracked follow-up when risk remains.
- **Nit:** optional; do not let nits obscure important findings.
- Do not resolve a finding merely because the line changed. Verify the risk is gone.

After substantial fixes, review the delta since the prior review and re-check the complete final diff to catch interactions.

### Step 7 — Merge decision

A change is ready only when:

- no blockers remain
- required checks for its risk class pass
- required tests and evidence are recorded
- public behavior and compatibility are documented
- residual risks and deferred suggestions are explicit
- the final diff contains no unintended artifact or unrelated change

For an urgent security fix, a narrow change may merge with incomplete non-critical checks only when the reason, compensating test, rollback, and follow-up are recorded. Security boundaries themselves are never waived.

### Step 8 — Post-merge validation

For R2/R3 or release changes:

- run a smoke test on the produced artifact, not only package tests
- verify capability/status output is truthful
- inspect one representative report or API response
- monitor for regression reports and keep rollback straightforward

## 10. Local validation matrix

Commands are examples; narrow them to touched packages/crates during development and run broader checks before high-risk merge or release.

| Area | Fast check | Stronger evidence for R2/R3 |
|---|---|---|
| Go | `gofmt -l <changed.go files>`; `go vet <touched packages>`; `go test <touched packages> -count=1` | `go test ./... -count=1`; targeted `go test -race ...`; `go run ./cmd/eval -min-precision 0.90 -min-recall 0.90` for detection changes |
| Rust | from `rust/`: `cargo fmt --all -- --check`; `cargo clippy -p <crate> --all-targets -- -D warnings`; `cargo test -p <crate>` | `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo test --workspace --all-targets --locked` |
| Zig | from `zig/`: `zig fmt --check build.zig src`; targeted test/build | `zig build test` and the relevant native integration build |
| Elixir | from `server/`: `mix format --check-formatted`; targeted `mix test path/to/test.exs` | `mix test`; `mix credo --strict` when available; exercise affected NIF path |
| Build/release | build touched target and inspect exit status | run the produced analyzer on `demo/vulnerable-app`; verify report, version, optional capability status, and packaged files |
| Security parser/path | targeted regression test | malformed corpus/fuzz case, size/depth limit test, timeout test, and host-file safety check |

Do not use `cicd.ps1 -Stage Lint` as sole merge evidence until its warning-only behavior is corrected: its current lint stage catches some failures, may auto-format Go files, and still records the stage as passed.

## 11. Review record template

Keep this in the issue, commit notes, or a temporary review note. A permanent new document is unnecessary for every small change.

```text
# Review record

Change:
Base..head:
Risk class:
Reviewer/pass:

## Behavior and invariants
- Goal:
- Must remain true:
- Compatibility impact:

## Evidence
- [ ] Command — result
- [ ] Regression/adversarial case — result
- [ ] Produced-artifact smoke test — result / not applicable

## Findings
- Blockers: 0
- Suggestions open/deferred:
- Residual risks:

## Decision
READY / NOT READY
Reason:
Rollback:
```

## 12. Lightweight operating cadence

For a solo project, use three levels rather than creating process overhead:

- **Every meaningful commit:** classify risk, self-review the diff, run touched-component checks.
- **Before merging R2/R3 work:** complete a review record and independent second pass.
- **Before a release:** review the cumulative release diff, run full applicable checks, smoke-test packaged artifacts, and inspect user-visible capability/report output.
- **Monthly or after a serious escaped defect:** sample recent changes and update this standard only when a recurring failure mode appears.

Useful metrics are intentionally few:

1. blockers found before merge
2. defects found after merge, grouped by missed checklist category
3. changes merged with skipped evidence and why
4. flaky or misleading quality checks

Do not optimize for comment count, review speed, or coverage percentage alone. Those are easy to game and weak proxies for correctness.

## 13. Initial adoption plan

1. Use this document for the next five meaningful changes without adding new infrastructure.
2. Correct the local lint stage so failed checks fail the stage and check mode never edits files.
3. Add a small local `doctor`/capability check that reports available toolchains, build tags, native libraries, model weights, and skipped checks without claiming success.
4. Add focused review prompts/checklists to high-risk directories when a recurring defect pattern is observed; avoid duplicating this whole standard.
5. After five reviews, remove checklist items that produced no useful signal and add any category that caught an escaped defect.
