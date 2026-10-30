# Eval corpus (`corpus.json`)

Ground-truth regression corpus for the Mega-Analyzer static pipeline.
Run it with:

```powershell
go run ./cmd/eval                         # default corpus path
go run ./cmd/eval -min-precision 0.95 -min-recall 0.9   # CI gate
```

The harness (`pkg/evalrunner`) writes every case's `files` into a temp
directory, injects a stub `AndroidManifest.xml` when the case provides none,
and runs the **real** pipeline (dataflow enabled; call graph, deobfuscation
and content caches disabled). Detection is measured at **category level**:
for each category in the corpus-wide universe (the union of every case's
`expected` + `forbidden`), a case contributes TP / FN / FP, and `cmd/eval`
aggregates per-rule precision / recall / F1 plus a micro average.

## Case schema

```jsonc
{
  "version": 2,                 // corpus schema version; must be > 0
  "cases": [
    {
      "id": "unique-case-id",   // unique, human-readable
      "files": {                // relative path -> full file content
        "smali/eval/app/Foo.smali": ".class public Leval/app/Foo;\n..."
      },
      "expected": ["category_a"],     // categories that MUST fire
      "forbidden": ["category_b"],    // categories that MUST NOT fire (optional)

      // Optional: pin findings to a location. Every assertion must be
      // satisfied by at least one finding of that category. `file` is
      // matched against the finding's file path; `line_min`/`line_max`
      // bound the finding line (1-based; 0 = any line). A category that
      // fires only OUTSIDE the asserted location is scored as not
      // detected (the would-be TP becomes an FN). Backward compatible:
      // cases without this field behave exactly as before.
      "locations": [
        { "category": "category_a", "file": "smali/eval/app/Foo.smali",
          "line_min": 5, "line_max": 9 }
      ],

      // Optional: documents a known detection gap (expected-fail entry).
      // The case is still executed and reported under "known_gaps" in the
      // output, but it is EXCLUDED from precision/recall metrics. When the
      // gap is ever fixed, the harness reports the case as "resolved" and
      // the marker should be removed.
      "known_gap": "short rationale: why the engine cannot detect this yet"
    }
  ]
}
```

### Semantics

- **Universe is global.** A category fired by case X but absent from case Y's
  `expected` counts as a false positive of that category on case Y. Keep each
  case focused on one vulnerability family, or list every legitimately
  co-firing category in `expected`.
- **Unknown fields are ignored** — old cases with only `id`/`files`/
  `expected`/`forbidden` remain valid unchanged.
- **Category strings** are the pipeline's category vocabulary
  (`pkg/internal/types/categories.go` for registry categories; dataflow
  categories such as `sql_injection`, `intent_redirection`,
  `path_traversal`, `reflection_injection`, `log_data_exposure`,
  `webview_injection`, `dynamic_code_loading` are defined in
  `pkg/internal/dataflow/models.go`).
- **smali cases**: files under `smali/eval/app/` are treated as app code and
  parsed into the smali AST; method bodies need `.method ... / .end method`
  blocks. Ordinary method parameters remain symbolic until bound to a
  caller; recognized IPC callbacks also receive source labels. Positive
  cases should use a modeled source API or an IPC entry point. Negative
  cases should establish why the sink input is safe (a constant, a bound
  SQL parameter, a definite overwrite, or a recognized sanitizer).
- **Manifest cases**: provide `AndroidManifest.xml` in `files`; otherwise the
  harness injects an empty stub manifest.

### Line numbers for `locations`

- smali AST detectors report the physical source line of the call site
  (`.method` line + offset inside the method body).
- Byte-pattern detectors (manifest, secrets) report the line of the pattern
  match.
- Dataflow findings report the sink call site line.

## Known gaps

Cases marked `known_gap` are detection gaps found while building this corpus
(see the `known_gaps` section of the eval output). They must not be deleted:
they pin the ground truth so a future detector fix flips them to "resolved".

Baseline snapshot (corpus v2, 70 cases, 62 scored): micro precision 1.00,
recall 1.00, F1 1.00, with the eight documented gaps below. The current v5
corpus has grown to 97 cases, all scored with no `known_gap` entries: the
full corpus passes at micro precision 1.00 / recall 1.00. Historical gap
list from the v2 baseline (all resolved since):

| case | gap class | symptom |
| --- | --- | --- |
| `weak-ecb-cipher` | recall | ECB transformation in a class field initializer invisible to the AST crypto detector (no field-constant tracking) |
| `wv-js-bridge-local`, `wv-js-disabled-trap`, `wv-js-unresolved-param` | precision | presence-based `SignalWebViewJSInterface` threat signal emits `WEBVIEW_REMOTE_JS` on the bare textual `addJavascriptInterface`, bypassing the AST detector's JS-enabled/URL-provenance analysis |
| `d-private-path-trap` | precision | presence-based `SignalDexClassLoader` threat signal emits `DYNAMIC_LOAD` on the bare textual `Ldalvik/system/DexClassLoader;` reference, bypassing the AST detector's private-path exemption |
| `d-inmemory-dex` | recall | dataflow never taints the `InMemoryDexClassLoader` constructor sink (`new-instance` clears the receiver; ByteBuffer params untracked) |
| `df-log-pii` | recall | `EditText.getText` carries only `LabelUserInput`; `Log.*` sinks require PII/credential/location labels (PII-labeled variant `df-log-clipboard` passes) |
| `n-localhost-trap` | precision | cleartext-traffic loopback exemption misses the quoted `"http://` AC variant, so `http://localhost` URLs are flagged |

The 23 `arrays-*` cases added in v5 cover whole-array sinks, element
projections, aliases, CFG joins, definite overwrites, helper calls, IPC array
sources and SQL sanitizer preservation. Positive cases pin the sink line.
See [quality evaluation](../../docs/QUALITY_EVALUATION.md) for the model's
scope and analysis-budget behavior.
