# Mega-Analyzer 1.0.0-beta.1

These notes describe preparation of the public beta from the current lineage.
Test and CI changes keep the existing version; they do not create a new release.
The core package contains the
standalone Go core; optional Rust/Zig/GNN libraries and the native APK editor
remain separate builds.

- REST API rejects unexpected Host headers on every route, including reads.
- Web UI bounds active scans and queued uploads, supports cancelling waiting
  jobs, and reports queued/running states.
- API reference and request console work offline with embedded assets.
- CLI, API, OpenAPI and metrics share version metadata; archives include
  `BUILD.json` with the source commit, build date and target architecture.
- The bundled demonstration uses the documented `demo/vulnerable-app` path.
  Archives contain concise English/Russian instructions, Quick Start and the
  native APK sample project. Every packaged Markdown file's relative links are
  checked against the unpacked archive.
- In-house sources and binaries use BSD-3-Clause OR GPL-2.0-only, at the user's
  option; third-party notices and license texts are preserved separately.
- JSON exports preserve typed findings, evidence, coverage and build metadata.
  HTML/Markdown/JSON/SARIF reports replace earlier files only after a successful
  write; failed exports keep the previous report. SARIF paths are URI-escaped.
- `scripts/compare_reports.py` compares saved findings by stable identity and
  supports regression thresholds with an explicit incomplete-coverage status.
- Public source exports verify their manifest before packaging/building. CI
  checks that the exported core builds without private files or Git history.
- Publication waits for Go tests, race checks, detection evaluation, fuzz smoke
  and checks of the downloaded `amd64` release archives on Windows, Linux and
  macOS. The shared core smoke job currently covers Linux only.

Known limits: this is a beta; native engines and Android device execution are
not covered by the core release smoke checks. Release smoke hosts use `amd64`;
ARM64 archives are cross-compiled without runtime tests. Reports and
workspace data are retained until the user removes them.

For a first run, unpack and execute:

```sh
./analyzer -t demo/vulnerable-app -report all -sarif
```

Windows PowerShell: use `./analyzer.exe`. Open `analysis_output/REPORT.html`.
