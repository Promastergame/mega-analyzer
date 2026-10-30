# Building Mega-Analyzer

[Русский](BUILD.ru.md)

Mega-Analyzer ships as two distinct builds. Pick the one that matches what you
need — most users only ever need the **core build**.

| Build | What you get | What you need |
| :--- | :--- | :--- |
| **Core** (default) | The full Go analyzer: APK/DEX/Smali, manifest audit, secret triage, PE/ELF hardening checks, all reports (HTML/MD/JSON/SARIF). 100% pure Go, no cgo. | Go 1.27.3+ only |
| **Full native** | Core **plus** the OmniSec native engine (Rust: CFG/SSA/dataflow/symbolic), the Zig SIMD ML runtime, and the GNN classifier. Enabled via cgo build tags. | Go + Rust 1.96.1+ + Zig 0.17.0+ (and a C toolchain) |

> The headline native engines (OmniSec, Zig ML, GNN) are **opt-in** and gated
> behind cgo build tags. A plain `go build` gives you the core analyzer, which is
> already a complete, self-contained tool. You do **not** need Rust or Zig unless
> you specifically want the native machine-code analysis path.

---

## Core build (cross-platform, pure Go)

Works on Linux, Windows and macOS with nothing but a Go toolchain:

```bash
# Release artifact: one binary containing the Go analyzer, BinZAP routing,
# website vulnscan modes, and the native backend when tags are enabled.
go build -trimpath -ldflags "-s -w" -o analyzer ./pkg/cmd/analyzer
```

The same artifact provides every runtime surface:

```bash
analyzer --help                 # CLI / scanners
analyzer --web                 # local browser UI
analyzer --api --api-port 5000 # REST API (formerly analyzer-api)
```

Inject version metadata for a release build:

```bash
go build -trimpath \
  -ldflags "-s -w -X main.Version=v1.0.0-beta.1 -X main.CommitHash=$(git rev-parse --short HEAD)" \
  -o analyzer ./pkg/cmd/analyzer
```

## Full native build (OmniSec + Zig + GNN)

The native engines are compiled as libraries and linked into the Go binary via
cgo; the analyzer calls the Rust API directly and never starts the separate
`omnisec` CLI. The relevant build tags are `omnisec_rust_ffi`,
`omnisec_ml_gnn`, and friends.

This is a compile-time choice, not a runtime one:
- Build **without** these tags (the default, and what prebuilt releases ship)
  and you get the core binary: pure Go, no cgo, nothing native to load.
- Build **with** these tags and you get the full-native binary, dynamically
  linked against the Rust/Zig `.dll` / `.so` / `.dylib` files. That binary
  **requires** those shared libraries to be present at runtime (next to the
  executable, or on `PATH` / `LD_LIBRARY_PATH`) — if they're missing, it will
  not start. There is no silent runtime fallback between the two builds; see
  [FAQ.md](FAQ.md#core-build-vs-full-native--whats-the-difference) for the
  full core-vs-full-native breakdown.

### Windows

```powershell
# Builds Rust DLLs → Zig DLLs → links the Go binary with cgo
.\cicd.ps1 -Stage Build
```

### Linux (via Docker — core image)

```bash
docker build -t mega-analyzer .
```

The default Docker image is the lean, fully static **core** build (CGO disabled),
so it runs on any glibc/musl Linux without extra runtime libraries.

### CI/CD orchestrator (Windows)

The `cicd.ps1` script runs individual release stages:

```powershell
.\cicd.ps1 -Stage Lint      # code quality checks
.\cicd.ps1 -Stage Test      # unit tests
.\cicd.ps1 -Stage Package   # full release build and packaging
```

---

## Testing

```bash
# Go core
go test ./pkg/...

# Rust native engine
cd rust && cargo test --release
```

## Toolchain versions

| Component | Version | Required for |
| :--- | :--- | :--- |
| Go | 1.27.3+ | Core analyzer + API server (always) |
| Rust | 1.96.1+ | OmniSec native engine (optional) |
| Zig | 0.17.0+ | SIMD ML runtime + sandbox (optional) |
| Elixir / Er/OTP | 1.20.0+ / 28+ | Distributed server (optional) |
