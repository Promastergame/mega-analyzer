# nsc — Android Network Security Config auditor

Parses and audits Android `network_security_config.xml`
(res/xml) files: cleartext policy, trust anchors, certificate
pinning quality, debug overrides. Pure Go (`encoding/xml`), no
Python needed.

## Library

```go
report, err := nsc.AuditDir("./extracted_apk")   // locates NSC automatically
report, err := nsc.AuditFile("myapp", "res/xml/network_security_config.xml")
report, err := nsc.AuditBytes("myapp", xmlBytes)

md := nsc.RenderMarkdown(report)   // human-readable report
js, _ := nsc.RenderJSON(report)    // machine-readable report
```

## CLI

```sh
go build ./cmd/nsc-audit
./nsc-audit res/xml/network_security_config.xml
./nsc-audit -json ./extracted_apk
./nsc-audit -strict app/  # exit code 2 if verdict is weak/dangerous
```

## Checks

| id | severity | what |
|---|---|---|
| `nsc_base_cleartext_permitted` | high | base config allows plain HTTP |
| `nsc_base_user_trust_anchors` | high | base config trusts user CAs (MITM enabler) |
| `nsc_domain_cleartext_permitted` | medium | per-domain cleartext whitelist |
| `nsc_domain_user_trust` | high | per-domain user CA trust |
| `nsc_domain_override_pins` | high | `overridePins="true"` bypasses pinning |
| `nsc_debug_overrides_present` | medium | `<debug-overrides>` shipped in production |
| `nsc_debug_overrides_user_trust` | low | debug overrides trust user CAs |
| `nsc_pin_set_expired` | high | pin-set expiration passed — Android silently disables pinning |
| `nsc_pin_set_expires_soon` | low | pin-set expires within 90 days |
| `nsc_pin_set_bad_expiration` | low | expiration attr is not `yyyy-MM-dd` |
| `nsc_pin_set_no_backup` | low | single pin, no backup pin |
| `nsc_pin_unknown_digest` | medium | non-SHA-256 digest is ignored by Android |
| `nsc_domain_no_hosts` | info | `<domain-config>` with no hosts (dead config) |
| `nsc_manifest_cleartext_override` | high | `usesCleartextTraffic="true"` in the manifest permits HTTP app-wide regardless of the NSC |
| `nsc_duplicate_domain` | low | host listed in multiple domain-configs |
| `nsc_domain_pinning_present` | secure | pinning configured (reduces score) |
| `nsc_base_hardened` | secure | default-deny base config (reduces score) |

Score is 0–100 (higher = weaker); verdicts: `hardened`, `ok`, `weak`,
`dangerous`, `absent`.

## Notes

- `Locate` checks the standard `res/xml` layouts first, then falls back to
  one bounded filename walk (covers jadx `resources/`, nested modules).
- `AuditDir` also locates the sibling `AndroidManifest.xml` when present:
  `android:debuggable="true"` suppresses the debug-overrides finding (dev
  build, not a finding), and `android:usesCleartextTraffic="true"` raises
  `nsc_manifest_cleartext_override` even next to a hardened NSC — the
  manifest flag wins over the config. Binary (AXML) manifests are unreadable
  here and keep the previous conservative behavior. Explicit signals via
  `AuditDirEx` / `AuditFileEx` / `AuditBytesEx`.

## Testing

```sh
go vet ./... && go test ./...
```
