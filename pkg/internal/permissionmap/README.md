# permissionmap — permission-to-code mapping

Maps Android manifest-declared permissions to actual API usage in
decompiled code (`.smali`, `.java`, `.kt`), flags over-privilege and
hidden functionality, and scores the result.

## Usage

```go
rep, err := permissionmap.Analyze(extractedDir, declaredPermissions)
md := rep.RenderMarkdown()   // human-readable
js, _ := rep.RenderJSON()    // machine-readable
```

## Semantics

Each declared permission gets a tri-state `status`:

| status | meaning | score impact |
|---|---|---|
| `used` | detection pattern matched in code | 0 |
| `unused` | patterns exist, nothing matched (over-privilege) | +15 dangerous / +5 other |
| `unknown` | no detection patterns for this permission | 0 (never penalized) |

Extra findings:

- **Deprecated permissions** (e.g. `WRITE_EXTERNAL_STORAGE` since API 30,
  `BLUETOOTH` since API 31, `USE_FINGERPRINT` since API 28): +3 each,
  noted in `api_level`.
- **Used but not declared** (`missing_permissions`): dangerous APIs
  detected in code without the corresponding manifest declaration —
  crash risk or hidden functionality: +8 each. Only checked for
  permissions with low-false-positive patterns (`sendTextMessage`,
  overlay windows, install packages, device IDs, call log, …).

Verdicts: `ok` (0) / `low` (≤15) / `medium` (≤40) / `high` (>40).
Score is clamped to 100.

## Knowledge base

~40 permissions with smali + java/kotlin patterns, protection levels
(`normal` / `dangerous` / `signature`) and deprecation metadata,
including modern ones: `POST_NOTIFICATIONS`, `READ_MEDIA_*`,
`BLUETOOTH_CONNECT/SCAN`, `QUERY_ALL_PACKAGES`,
`REQUEST_INSTALL_PACKAGES`, `ACCESS_BACKGROUND_LOCATION`.

## Performance

- `filepath.WalkDir` (no extra stat calls)
- plain substring matching — no regex compilation in the hot loop
- files > 8 MiB skipped, evidence capped at 5 sites per permission

## Compatibility

Public API is backward compatible: `Analyze`, `Report`,
`PermissionUsage.Used`, `UsageSites` (legacy string format) are
preserved. New: `Status`, `Sites` (structured), `Protection`,
`APILevel`, `MissingPermissions`, `RenderJSON`.

Behavioral change: permissions absent from the knowledge base are now
`unknown` and no longer counted as unused / penalized.
