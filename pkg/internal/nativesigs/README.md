# nativesigs

Generic ELF / `.so` fingerprinting data for Mega-Analyzer.

`native_lib_signatures.json` is a **vendor-agnostic** signature database for native
Android and Linux libraries. It deliberately does not encode a single app family:
every rule is either a broad ecosystem signature (engine, audio, crypto, crash SDK,
packer, hooking framework) or a **structural heuristic** that works without any
allowlist of names or domains.

## Why data-driven

This package follows the convention already used by `pkg/internal/sastrules`,
`pkg/internal/trackers`, `pkg/internal/niap` and `pkg/internal/configs`: a JSON
blob next to a tiny `embed.go`. Rules can be extended without touching Go code,
and the file stays reviewable in a diff.

## Schema

Top level:

| Key | Meaning |
| --- | --- |
| `schema_version` | Bump on breaking changes. |
| `match_fields` | Inline documentation of the matcher semantics. |
| `categories` | Allowed values for `category`. |
| `signatures` | String / symbol / soname matchers. |
| `structural_heuristics` | ELF-shape rules evaluated in code, not by substring. |

A signature fires when at least `min_hits` (default `1`) distinct items across
`any_soname`, `any_needed`, `any_symbols` and `any_strings` match. All matching is
case-insensitive substring matching, so no regex engine is required.

### Extraction without regex

`extract` pulls a value out of the first matching string using backslash-free
slicing, which keeps the JSON safe to hand-edit:

```json
"extract": [{ "field": "dart_version", "after": "Dart VM version: ", "until": " (" }]
```

That turns `Dart VM version: 3.4.0 (stable) (Mon May 6 ...)` into
`dart_version = 3.4.0`, which in turn pins the Flutter minor release.

## Severity contract

`severity` describes what a hit *means*, not how bad the app is:

- `info` — identification only (engine, runtime, toolchain).
- `low` / `medium` — hygiene or hardening observations.
- `high` — tampering / repack / instrumentation surface.

Confidence is additive and the caller aggregates; a single `high` hit is a lead,
not a verdict. In particular `HOOK_FRIDA_CORE` (Frida *shipped inside* an app) and
`ANTI_INSTRUMENTATION_STRINGS` (app *looking for* Frida) are separate rules on
purpose — the existing `pkg/ml` signal `VulnFridaArtifacts` covers the second case.

## Wiring it up

Mirror `pkg/internal/sastrules/embed.go`:

```go
package nativesigs

import _ "embed"

//go:embed native_lib_signatures.json
var nativeLibSignaturesJSON []byte
```

Then decode into the matcher types and feed each `.so` found in an APK's `lib/`
directory through it. Useful inputs per library: `DT_SONAME`, `DT_NEEDED`, dynamic
symbol names, extracted ASCII strings, section count, segment flags, per-segment
entropy, and the notes present in `NT_GNU_BUILD_ID`.

## Validating an edit

```bash
jq -e '.signatures | length' pkg/internal/nativesigs/native_lib_signatures.json
jq -e '[.signatures[].id] | (length == (unique | length))' pkg/internal/nativesigs/native_lib_signatures.json
jq -e '[.structural_heuristics[].id] | (length == (unique | length))' pkg/internal/nativesigs/native_lib_signatures.json
```

All three must print a truthy value. Category values should stay inside the
top-level `categories` list.

## Worked example

`demo/nulls_brawl_so_diff.md` walks a real official-versus-repack comparison and
notes which rule in this file catches each difference. It is a test case for the
ruleset, not the reason the ruleset exists.
