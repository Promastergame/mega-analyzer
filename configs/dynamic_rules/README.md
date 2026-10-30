# Dynamic rules

This directory holds user-editable, hot-reloadable rule sets. Each file starts
as an empty JSON array (`[]`) and is loaded at process start (and re-saved
atomically whenever a rule is added/updated/removed through the REST API or
the Go helper functions in the corresponding package). They are intentionally
left as bare `[]` in the repo — JSON has no comment syntax, and a real example
entry here would silently become an *active* detection/fuzz rule the first
time the analyzer runs. This file documents the schema for each one instead,
so you can hand-edit them (or drive them through the API) with a template to
copy from.

After editing one of these files by hand, restart the analyzer (or call the
corresponding reload/add endpoint) to pick up the change — each file is only
read once per process, then cached in memory and rewritten atomically on every
mutation.

---

## `binzap_rules.json`

Loaded by `pkg/binzap/dynamic_binzap.go` (`DynamicBinzapRule`). Each rule is a
sequence of bytecode-matcher steps run against the Smali/DEX token stream.

```json
[
  {
    "id": "custom-runtime-exec",
    "name": "Runtime.exec via reflection",
    "severity": "high",
    "pattern_steps": [
      { "type": "string_contains", "value": "Ljava/lang/Runtime;" },
      { "type": "any_register" },
      { "type": "method_ref_contains", "value": "exec" }
    ]
  }
]
```

Fields:

| Field | Type | Notes |
| :--- | :--- | :--- |
| `id` | string | Unique, non-empty. Adding a duplicate `id` via the API is rejected. |
| `name` | string | Human-readable finding name. |
| `severity` | string | One of `critical`, `high`, `medium`, `low`. |
| `pattern_steps` | array | Ordered list of steps, matched contiguously against the token stream. |

Each `pattern_steps[i]` is `{ "type": "...", "value": "..." }`, where `type` is
one of:

- `opcode` — matches a specific Smali opcode (`value` = opcode name).
- `any_register` — matches any single register token (`value` unused).
- `string_contains` — matches a token whose text contains `value`.
- `string_equals` — matches a token whose text equals `value` exactly.
- `any_method_ref` — matches any method-reference token (`value` unused).
- `method_ref_contains` — matches a method-reference token containing `value`.

## `ml_patterns.json`

Loaded by `pkg/ml/dynamic_ml.go` (`VulnerablePattern`, defined in
`pkg/ml/patch_patterns.go`). Each pattern describes a "patchable" method the
ML patch predictor should recognize.

```json
[
  {
    "id": "custom-license-check",
    "category": "license_check",
    "description": "Custom license validation gate that should return true",
    "method_names": ["isLicensed", "checkLicenseValid"],
    "class_patterns": ["com/example/app/LicenseManager"],
    "required_calls": [],
    "string_patterns": ["license_invalid"],
    "return_type": "Z",
    "patch_type": "return_true",
    "weight": 1.0,
    "min_match_score": 1.0
  }
]
```

Fields:

| Field | Type | Notes |
| :--- | :--- | :--- |
| `id` | string | Unique, non-empty. |
| `category` | string | One of the `PatchCat*` category strings in `pkg/ml/patch_patterns.go` (e.g. `license_check`, `billing`, `premium_check`, `root_detection`, `ssl_pinning`, ...). |
| `description` | string | Human-readable summary. |
| `method_names` | array of string | Any method name match counts as a hit. |
| `class_patterns` | array of string | Any class/path substring match counts as a hit. |
| `required_calls` | array of string | Invocations that must appear in the method body. |
| `string_patterns` | array of string | Literal strings (`const-string`) that must appear in the method body. |
| `return_type` | string | Smali return type shorthand: `Z` (boolean), `V` (void), `I` (int), etc. |
| `patch_type` | string | One of `return_true`, `return_false`, `return_void`, `return_max_int`, `nop`, `remove_check`. |
| `weight` | number | Relative weight in the overall match score (`1.0` = standard). |
| `min_match_score` | number | Minimum accumulated score required before the pattern is considered a match. |

## `web_rules.json`

Loaded by `pkg/vulnscan/dynamic_web.go` (`DynamicWebRule`). Each rule is one
of three kinds, selected by `type`: `fuzz` (active payload injection),
`regex_passive` (passive response-body scan), or `header_check` (security
header audit).

```json
[
  {
    "id": "custom-debug-endpoint",
    "name": "Debug endpoint exposed",
    "description": "A /__debug endpoint that should never be reachable in production",
    "severity": "medium",
    "mitigation": "Remove or gate the debug endpoint behind authentication.",
    "type": "regex_passive",
    "regex_pattern": "__debug__|X-Debug-Token"
  }
]
```

Common fields (all rule types):

| Field | Type | Notes |
| :--- | :--- | :--- |
| `id` | string | Unique, non-empty. |
| `name` | string | Human-readable finding name. |
| `description` | string | Finding description. |
| `severity` | string | One of `critical`, `high`, `medium`, `low`. |
| `mitigation` | string | Suggested fix, shown in the report. |
| `type` | string | `fuzz`, `regex_passive`, or `header_check`. |

Type-specific fields:

- `type: "fuzz"` — `payloads` (array of injected strings), `match_type`
  (`contains` / `regex` / `sql_error` / `lfi_success` / `status_code`), and
  `match_value` (the substring/regex/status-code to look for; unused for
  `sql_error` and `lfi_success`, which use built-in heuristics).
- `type: "regex_passive"` — `regex_pattern` (Go regexp, matched against the
  raw response body).
- `type: "header_check"` — `header_name`, `header_check`
  (`missing` / `contains` / `equals`), and `header_value`.
