# OMNISEC / Mega Analyzer - v1.0.0-beta.9

## New: data/ forensics detectors (born from real Unity runtime data analysis)

beta.9 adds three detectors that inspect the app's *runtime data directory*
(`data/`) - files that ship next to the binary but are normally ignored by
APK scanners. Validated on **Fowlst 2** (`com.dvdfu.chicken2`, Unity 6000.0.58f2 / IL2CPP).

### 1. Unencrypted IL2CPP Metadata (`il2cpp_metadata`, Security, medium)
- Flags `global-metadata.dat` shipped in cleartext (magic `0xFAB11BAF`).
- Confirms Unity type/method/field names + string literals are readable ->
  trivial reverse engineering, cheating and asset extraction.
- Fowlst 2: 9.5 MB metadata, unencrypted.

### 2. Weak Save-File Integrity (`weak_save_integrity`, Security, high/medium)
- Inspects `save.dat` / `*.sav` / `*.save`.
- HIGH  -> plaintext (>85%% printable, JSON/kv markers): freely tampered (CWE-312).
- MEDIUM -> reversible obfuscation (entropy < 7.0 bits/byte): XOR/base64/custom,
  not authenticated encryption (CWE-311).
- Fowlst 2: `save.dat` (1147 B) => reversible obfuscation (medium).

### 3. Plaintext Data Identifier (`data_plaintext_id`, Security, low)
- Cleartext persistent IDs (`$userId` / `cloudId` / `deviceId`) in app data (CWE-359).
- Analytics tracking enabled-by-default (`limit_user_tracking=false` /
  `player_opted_out=false`).
- Fowlst 2: `CloudLocalCache.json` -> `$userId`; `Analytics/config` -> tracking on by default.

## Pipeline change: forensic data files are now analyzed
- Previously the walker dropped every `FileTypeUnknown` file (incl. `.dat` /
  `.sav` / `.save` / extensionless analytics stores) before analysis, so these
  files were never seen.
- Now a narrow allow-list (`isForensicDataFile`) admits exactly these targets.

## False-positive safety (important)
- Admitted forensic blobs are binary; running the generic pattern-matcher and
  generic detectors on them produced junk hits (e.g. .NET framework strings like
  "Valid XML name is expected", format placeholders `{0}: {1}` matched as
  PURCHASE_VERIFY / SUBSCRIPTION / ENCRYPTED_DATA).
- Fix: for forensic files ONLY the three dedicated data/ detectors run; the
  generic matcher and all non-file-type-aware detectors are skipped.
- Result on Fowlst 2: 4 findings, 0 false positives (down from 21 hits / 11 bogus criticals).

## HTML report
- Still SVG-only: verified `emoji in HTML: 0`, 150 inline SVG icons.
