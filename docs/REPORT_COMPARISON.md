# Comparing analysis runs

The JSON report includes typed findings, their fingerprints, evidence and
provenance, coverage, data-flow limits and the analyzer's build identity in
`report_metadata`. Empty `findings: []` is explicit. Reports from older versions
that omitted this contract must be regenerated before comparison.

CLI reports also record `run`: the profile, effective core limits and switches,
timeout, and any early stop reason. Credentials and full CLI arguments are not
included. Changing these recorded settings makes the comparison inconclusive.

Run two analyses with the same build and settings, into separate directories:

```sh
./analyzer -t before-app -o runs/before -report all -no-profile
./analyzer -t after-app -o runs/after -report all -no-profile
python scripts/compare_reports.py runs/before/analysis.json runs/after/analysis.json --output runs/diff.json --fail-on-new high
```

On Windows use `./analyzer.exe`. The comparison helper needs Python 3.12+ and
uses only the standard library. It is included in the source repository.

The diff lists added, removed and changed typed findings. It uses rule IDs and
fingerprints, so moving a finding to another line does not make it new. Changes
to severity, confidence, occurrences or explanation appear under `changed`.
Input SHA-256 hashes and build metadata identify the reports being compared.
There are no network requests, and the input reports are never rewritten.

| Exit code | Meaning |
| --- | --- |
| 0 | Comparison completed; no configured regression threshold was crossed |
| 1 | A new finding meets `--fail-on-new`, or an existing finding increased across that threshold |
| 2 | Invalid/unreadable input, an older report contract, or an output error |
| 3 | Missing/incomplete coverage, interrupted analysis, different recorded scan settings, or mismatched application packages; inspect the saved diff |

`removed` means absent from the second report. It does **not** establish that a
vulnerability was fixed. Size/file limits, parser failures and cancellation
produce warnings and exit 3. Version/commit changes also produce warnings:
detectors may have changed. Use the same profile, custom rules, build and target
layout to make results comparable. Custom rules, models and optional modules
are not fully described by the core settings; retain their versions separately.

The scope is the normalized `findings` collection. Raw `rule_matches` and
separate native/network/toolkit reports are preserved in JSON but are not merged
into this comparison. Dummy model results remain explicitly marked in their
own collection. A clean comparison is not proof that an application is secure.

`--version-diff old.apk new.apk` is a separate, existing input comparison mode
for permissions, endpoints, trackers, native libraries and signing metadata.
It now returns an error when an input is truncated, unreadable or corrupt,
instead of comparing partial hashes as if they covered complete files. Its
current load limits are 16 MiB per entry, 256 MiB total and 4,096 entries; for
larger applications, compare the full analysis reports above.

## По-русски

Сохраняйте два запуска в разные каталоги и сравнивайте `analysis.json` командой
выше. В `diff.json` будут новые (`added`), исчезнувшие (`removed`) и изменившиеся
(`changed`) находки, контрольные суммы исходных отчётов и предупреждения.

Код 1 подходит для CI: появилась новая находка заданной серьёзности либо
серьёзность существующей перешла порог. Код 3 означает неполное покрытие или
несопоставимые приложения; исчезнувшую находку нельзя автоматически считать
исправленной. Используйте одинаковые настройки и версию анализатора.
