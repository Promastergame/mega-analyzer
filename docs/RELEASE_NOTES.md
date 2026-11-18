False-positive cleanup across the board, a faster quick profile, WASM release infrastructure and the project site at [mega-analyzer.lol](https://mega-analyzer.lol).

- Engine: quick profile honors module switches — flag defaults no longer re-enable data-flow, crack points and anomaly detection (fast triage is ~15 seconds quicker).
- False positives on clean APKs: `setAccessible` custom-keyword boilerplate suppressed, vendored Play Billing SDK internals counted as library code, native artifact findings deduplicated across ABI copies, inventory-grade numeric literals no longer raise a Derived Exploit Payload.
- Reports: the coverage-limitation banner is gone from HTML/Markdown (the data stays in `analysis.json`).
- Web UI: the report iframe gets a dark background (no more white scrollbar strip below reports) and the app declares its color scheme.
- Branding: favicon.ico/PNG + apple-touch-icon everywhere, an inline favicon for REPORT tabs and the red bug emblem as the sidebar logo.
- Site: [mega-analyzer.lol](https://mega-analyzer.lol) — the sidebar footer links to the source catalog at mrbeast.art.
- Infra: `scripts/build_web_site.py` builds the WASM site (bridge/worker/pool/memfs/GNN, GOOS=js targets) and copies the icons; version bumped to 1.0.0-beta.2.

For a first run, unpack and execute:

```sh
./analyzer -t demo/vulnerable-app -report all -sarif
```

Windows PowerShell: use `./analyzer.exe`. Open `analysis_output/REPORT.html`.
