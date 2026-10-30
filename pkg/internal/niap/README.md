# niap — NIAP compliance scanner

Scans decompiled Android apps (apktool output directory or a zip of
decompiled sources) against automatable checks derived from the NIAP
Application Software Protection Profile, plus explicit
`manual_review` markers for requirements that cannot be checked
statically.

## Usage

```go
rep, err := niap.Analyze(targetDirOrZip)           // embedded rules
rep, err  = niap.AnalyzeWithRules(target, rules)   // custom rules
md  := rep.RenderMarkdown()
js, _ := rep.RenderJSON()
```

## Rule semantics

- Patterns are Go regexes evaluated **per line** of `.smali`, `.java`,
  `.kt` files (and text `AndroidManifest.xml` for `type: manifest`).
- AND within a choice group; groups combined with OR (default) or AND
  (`choice_type: "and"`/`"all"`).
- Lines matching any `exclude` regex are ignored (e.g. XML namespace
  `http://schemas.android.com/...` does not count as cleartext traffic).
- `polarity: "negative"` = anti-pattern: match → FAIL (e.g. AES-ECB,
  trust-all TLS, weak RSA).
- `manual: true` or non-automatable rules → `manual_review`, never
  counted as failed.
- Binary (AXML) manifests are detected by magic bytes and routed to
  `manual_review` instead of being regex-scanned as garbage.

## Built-in checks

| Rule | Kind | What it detects |
|---|---|---|
| FCS_RBG_EXT.1.1 | positive | SecureRandom used |
| FCS_RBG_EXT.1.1-weak-rng | anti | java.util.Random |
| FCS_STO_EXT.1.1 | positive | AndroidKeyStore / EncryptedSharedPreferences |
| FCS_STO_EXT.1.1-plaintext-secrets | anti | passwords/tokens in SharedPreferences |
| FCS_CKM.1.1(1)-weak-rsa | anti | RSA 512/768/1024 |
| FCS_COP.1.1(1)-aes-ecb | anti | AES-ECB (incl. default `"AES"`) |
| FCS_COP.1.1(2)-weak-hash | anti | MD5 / SHA-1 hashing |
| FCS_COP.1.1(4)-hmac-md5 | anti | HMAC-MD5 |
| FCS_HTTPS_EXT.1.1 | positive | HTTPS/TLS stack |
| FTP_DIT_EXT.1.1-cleartext-http | anti | cleartext http:// (namespaces excluded) |
| FTP_DIT_EXT.1.1-tls-bypass | anti | trust-all / allow-all-hostname TLS |
| FIA_X509_EXT.2.2 | positive (AND) | checkValidity + expiry exceptions |
| FDP_DEC_EXT.1.1 | manifest | declared platform-resource permissions |
| FDP_DAR / FMT_MEC / FPT_TUD / FCS_CKM_EXT | manual | not automatable |

## Scoring

Failed rule adds its `severity` (default 4), capped at 100. The verdict
follows the severity-weighted score, not the fail count: `compliant`
(score 0) / `mostly compliant` (score ≤ 6) / `non-compliant` (score > 6) /
`unknown` (no rules). Counting fails instead would call a single TLS bypass
(weight 12) "mostly compliant" — the one critical finding alone must fail
the target. `manual_review` rules do not affect the score.

## Notes

- Files > 8 MiB are skipped; zip entries are size-capped (zip-bomb safe).
- Scanning is streaming — one file in memory at a time, with early
  exit once every pattern has been seen.
- `FCS_RBG_EXT.1.1-weak-rng` can flag legitimate non-crypto uses of
  java.util.Random — treat it as a lead, not a conviction.
