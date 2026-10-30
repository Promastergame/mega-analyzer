# arscsigs

Data-driven rules for Android **resource containers**:

| Target | What it is |
| --- | --- |
| `resources.arsc` | Binary `ResTable` chunk tree (string pools, packages, types, entries) |
| `manifest` | Binary `AndroidManifest.xml` (AXML) |
| `apk_container` | Zip-level artifacts: signing block, `META-INF` signature files |

Companion to `pkg/internal/nativesigs`, which covers ELF and `.so` payloads. The two are
meant to be run together: the resource layer tells you *what the build claims to be*, the
native layer tells you *what it actually loads*. Contradictions between them are the
highest-value findings.

## Wiring

Follows the existing convention (`pkg/internal/sastrules/embed.go`,
`pkg/internal/trackers/embed.go`, `pkg/internal/niap/embed.go`):

```go
package arscsigs

import _ "embed"

//go:embed android_resource_rules.json
var AndroidResourceRulesJSON []byte
```

## File layout

```
schema_version        int
name, updated, notes  string
categories            []string   // closed vocabulary; every rule must use one of these
targets               []string   // resources.arsc | manifest | apk_container
rules                 []Rule
structural_heuristics []Heuristic
baselines             []Baseline
```

### Rule

| Field | Meaning |
| --- | --- |
| `id` | Stable upper-snake identifier. Never reuse or renumber. |
| `target` | Which artifact the rule is evaluated against. |
| `category` | One of `categories`. |
| `label` | Short human-readable finding name. |
| `confidence` | `low` / `medium` / `high` — how sure the match is. |
| `severity` | `info` / `low` / `medium` / `high` — how much it should matter. |
| `any_string` | Match against the global value pool (or AXML string pool). |
| `any_resource_key` | Match against the package key string pool (resource *names*). |
| `any_package_name` | Match against the `ResTable_package` name. |
| `any_res_path` | Match against `res/...` file path strings. |
| `any_type_name` | Match against the type string pool. |
| `min_hits` | How many distinct matches are required to fire. |
| `extract` | Value extraction, see below. |
| `requires_baseline` | Rule is a comparison and cannot fire on a single file. |
| `notes` | Why this matters and how to avoid a false positive. |

`confidence` and `severity` are deliberately separate. `SIGN_V1_SIGNATURE_STRIPPED` is
high confidence and only medium severity, because a modern build legitimately looks that way.

### Heuristic

Shape-based checks that need no signature list:

| Field | Meaning |
| --- | --- |
| `signal` | Named measurement the analyzer computes. |
| `operator` | `eq` / `gt` / `lt` / `not_in`. |
| `threshold` / `threshold_set` | Comparison operand. |

### Extraction, and why there is no regex

Versions and identifiers are pulled with plain substring bounds:

```json
{ "field": "firebase_project", "after": "https://", "until": ".firebaseio.com" }
```

`after` is optional (omit it to start at the beginning of the matched token). This keeps the
file completely free of backslash escapes, so it can be hand-edited without escaping bugs and
diffs stay readable.

## Computing the signals

All offsets are little-endian, relative to the start of the chunk. Chunk header is always
`type:u16, headerSize:u16, size:u32`.

| Signal | Where it comes from |
| --- | --- |
| `file_size_minus_restable_size` | root chunk `size` at offset 4 vs actual file length |
| `package_count` | root header, offset 8 |
| `global_pool.*` | first `0x0001` chunk: `count` at 8, `flags` at 16 (bit 0 = sorted, bit 8 = UTF-8) |
| `package.id` | `0x0200` chunk, offset 8 |
| `package.name` | offset 12, 128 UTF-16 code units, NUL-terminated |
| `package.last_public_*` | offsets 272 and 280 |
| `type_pool` / `key_pool` | pools at the offsets stored at 268 and 276 |
| `type.*` | `0x0201` chunks: `id` at 8, `flags` at 9 (bit 0 sparse, bit 1 offset16), `entryCount` at 12, `entriesStart` at 16, config at 20 |
| `locale_count` | distinct language/region pairs across all `0x0201` configs (config offset 8 and 10, high bit means a packed 3-letter code) |
| `library_chunk_count` | `0x0203` chunks |
| `label.*` | resolve the `app_name` entry per locale: `ResTable_entry` `size:u16, flags:u16, key:u32`, then `Res_value` where `dataType == 0x03` indexes the global pool |

## Validating a change

No Go toolchain is required to sanity-check the data file:

```sh
jq -e '.rules | length' android_resource_rules.json
jq -e '[.rules[].id] | length == (unique | length)' android_resource_rules.json
jq -e '(([.rules[].category] - .categories) | length) == 0' android_resource_rules.json
jq -e '(([.rules[].target] - .targets) | length) == 0' android_resource_rules.json
```

A reference parser used to derive and verify the current rules lives in `demo/tools/`.

## Baselines

`baselines` holds **measured** values from real builds, not invented ones. They exist so
thresholds can be justified and so comparison rules have something to compare against. The
four current entries cover a standard ad-supported release build, an engine game that keeps
localization out of resources, a path-shortened indie build, and a confirmed repack of that
same indie build. See `demo/arsc_fingerprints.md` for the full derivation.

When adding a baseline, record what you actually measured and leave unknown fields out
rather than guessing.

## AXML signals

Binary `AndroidManifest.xml` uses the same chunk header as `resources.arsc`
(`type:u16, headerSize:u16, size:u32`). Root type is `0x0003`.

| Chunk | Meaning |
| --- | --- |
| `0x0001` | string pool (same layout as in `resources.arsc`) |
| `0x0180` | resource map: `u32` framework resource id per attribute index |
| `0x0100` / `0x0101` | namespace start / end: `prefix:u32, uri:u32` |
| `0x0102` | element start |
| `0x0103` | element end: `ns:u32, name:u32` |
| `0x0104` | character data |

Every node chunk begins with `lineNumber:u32, comment:u32`. For an element start, the
`attrExt` struct begins at `chunk + headerSize`:

| Offset in `attrExt` | Field |
| --- | --- |
| 0 | `ns:u32` (`0xFFFFFFFF` when absent) |
| 4 | `name:u32` |
| 8 | `attributeStart:u16` (relative to `attrExt`) |
| 10 | `attributeSize:u16` (normally 20) |
| 12 | `attributeCount:u16` |
| 14 / 16 / 18 | `idIndex` / `classIndex` / `styleIndex` |

Each attribute is `ns:u32, name:u32, rawValue:u32, Res_value`. In `Res_value` the `dataType`
byte sits at +3 and the payload `u32` at +4. Relevant data types: `0x03` string (index into
the pool), `0x12` boolean, `0x01` reference, `0x10` decimal int, `0x11` hex int, `0x04` float.

| Signal | Where it comes from |
| --- | --- |
| `axml.file_size_minus_declared_size` | root chunk `size` at offset 4 vs file length |
| `axml.pool.*` | first `0x0001` chunk, `flags` at offset 16 |
| `axml.resource_map_entries` | `(chunk size - headerSize) / 4` of the `0x0180` chunk |
| `axml.namespace_count` | number of `0x0100` chunks |
| `manifest.package` | `package` attribute on the `manifest` element |
| `manifest.target_sdk_minus_min_sdk` | `uses-sdk` attributes, both hex ints |

### A note on reusing resources.arsc thresholds

Do **not** copy thresholds between the two targets. `ARSC_STRING_POOL_DUPLICATES` fires above
zero because aapt2 fully deduplicates the value pool of a resource table. The AXML pool is
not deduplicated the same way: a measured clean manifest already contains one duplicate,
because element names, attribute names and raw attribute values all share a single pool.
`AXML_POOL_DUPLICATES` therefore uses a threshold of 1. Thresholds are per target and each
one must be justified by a baseline.
