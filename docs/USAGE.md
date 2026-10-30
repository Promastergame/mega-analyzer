# Usage & flags cheat sheet

[Русский](USAGE.ru.md)

Full flag reference: [`FlagiFiles.md`](../FlagiFiles.md)

## Three ways to run

| Command | What you get |
| :--- | :--- |
| `analyzer -t app.apk` | **Direct CLI** — the default. Prints results, writes reports. |
| `analyzer -tui -t app.apk` | **Interactive TUI** wizard. |
| `analyzer -web` | **Browser dashboard** at `http://localhost:7474`. |

## One-liners

```bash
# Analyze an APK, all report formats
analyzer -t app.apk -report all

# Zero-setup demo — real findings in seconds
analyzer -t demo/vulnerable-app -report all -sarif

# Quick pass vs. heaviest pass
analyzer -t app.apk -p quick
analyzer -t app.apk -p paranoid -report full

# CI — SARIF for code scanning
analyzer -t app.apk -sarif -o ./analysis_output

# Native binary (auto-routes by extension too)
analyzer --scan-native -t libnative.so -o ./out
analyzer -t malware.exe

# Decode → edit smali → rebuild (no apktool)
analyzer -decode -t app.apk -o ./work --copy-original
analyzer -build  -t ./work  -o ./patched.apk

# Detonate
analyzer -t malware.exe -sandbox --sandbox-duration 120
analyzer -t app.apk -android-sandbox

# Find patch points
analyzer -t app.apk -ml-patch
analyzer -t app.apk -ml-patch -ml-patch-fix
```

## Core flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-t`, `-target <path>` | — | Folder, APK, DEX, PE, ELF, Mach-O |
| `-o`, `-output <dir>` | `analysis_output` | Output directory |
| `-p`, `-profile <name>` | `balanced` | `quick` · `balanced` · `deep` · `paranoid` |
| `-report <preset>` | `default` | `short` · `default` · `full` · `all` |
| `-sarif` | off | Write `analysis.sarif` |
| `-json` | off | JSON to stdout |
| `-q` | off | Quiet mode |
| `-tui` | off | Interactive TUI |
| `-callgraph` / `-correlations` | off | Call graph / cross-file correlations |
| `-web` | off | Browser dashboard |

## Profiles

| Profile | Use for |
| :--- | :--- |
| `quick` | Fast first look |
| `balanced` | Everyday default |
| `deep` | Call graph, correlations, heavier passes |
| `paranoid` | Most thorough — for high-stakes targets |

## CI / GitHub Actions

```bash
analyzer -t app-release.apk -report full -sarif -o results
```

Upload `results/analysis.sarif` with `github/codeql-action/upload-sarif`. See [CODE_SCANNING.md](CODE_SCANNING.md).

> Fresh custom `-o` dirs need a `.omnisec-output` marker. The Action creates it automatically.

## Web vulnerability scanner

```bash
# One binary: low-impact availability check (exactly one GET)
analyzer --web-scan --web-scan-target https://example.test --web-scan-mode status

# Passive audit of one response (no fuzzing, payloads, or endpoint probes)
analyzer --web-scan --web-scan-target https://example.test --web-scan-mode passive

# Full active vulnscan — only against a target you own/are authorised to test
analyzer --web-scan --web-scan-target https://example.test --web-scan-mode active --i-own-this-target
```

`status` reports the site as healthy only for HTTP 200, while any HTTP response
is considered reachable. `passive` sends one GET and inspects headers, cookies,
and the response body. Only `active` runs the crawler/fuzzer and requires
`--i-own-this-target`.

The old `cmd/vulnscan` entry point remains a compatibility wrapper for local
development; releases build a single `analyzer` binary.

Full check list in [`FlagiFiles.md` §11](../FlagiFiles.md#11-web-vulnerability-scanner--дополнительные-cli-точки-входа-cmd).

## Bytecode and native-binary analysis

```bash
# APK / Smali / ASM
analyzer --scan-bytecode -t app.apk -o results

# Deeper offline taint/dataflow pass (the target is not executed)
analyzer --scan-bytecode-deep -t decoded-smali -o results

# PE / ELF / .so: Rust scan-native through the library FFI backend
analyzer --scan-native -t libgame.so -o results
```

`--scan-bytecode*` uses BinZAP for bytecode/textual ASM, while `--scan-native`
uses Rust OmniSec for native PE/ELF. Reports show the selected engine, but users
choose the understandable input type.
