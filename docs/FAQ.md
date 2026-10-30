# FAQ

[Русский](FAQ.ru.md)

- [The project](#the-project)
- [Dependencies and build](#dependencies-and-build)
- [Running it](#running-it)
- [Reading a report](#reading-a-report)
- [Sandbox and safety](#sandbox-and-safety)
- [License and contributions](#license-and-contributions)

---

## The project

### Is one person really behind all of this?

**Yes — one maintainer, plus AI tools as part of the daily workflow.** Both halves of that sentence matter, so here is the split:

- **Human:** the architecture, the Hyperion IR design, every detection rule and its taxonomy, the threat model, the offline guarantee, what ships and what doesn't — and the final read on every diff before it lands on `main`.
- **AI tools:** a force multiplier — boilerplate, test scaffolding, a second pair of eyes during self-review, doc translation passes, and the grind work that comes with a multi-language codebase and no team to split it across.

[CODE_REVIEW.md](CODE_REVIEW.md) describes the review process. Test, coverage and packaged-release evidence is attached to the corresponding CI run; see [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md). Check the commit recorded in that run when assessing a release.

### Is the APK Editor IDE yours, or a reskin of something?

Mine, both versions, written from scratch:

- **Desktop** — `apk-editor/src/`, 62 Zig source files. Zig + the raw Win32 API + GDI, compiled to a single native `.exe`. No Electron, no embedded browser, no third-party GUI toolkit, no runtime to install.
- **Android** — `apk-editor/android/`, 48 Java files under `lab.apked`. A real port rather than a wrapper: its own editor pane, tab manager, file tree, autocompletion, find/replace, undo history, grapheme-aware text handling and APK packaging.

Both open a decoded APK/XAPK/ZIP project folder, edit Smali and resources, and drive the same JSON patch workflow the analyzer emits. Details: [APK Editor](APK_EDITOR.md).

### Is it a fork of MobSF, apktool, or jadx?

No, and it contains no code from any of them. The APK/DEX/ARSC parsers, the Smali printer, the decode/rebuild path and the report pipeline are all in-tree. For an honest capability comparison rather than a lineage claim, see [COMPARISON.md](COMPARISON.md).

### Why six languages? Isn't that over-engineering?

Each one is there for exactly one reason:

| Language | Role | Why it, specifically |
| :--- | :--- | :--- |
| **Go** | Analyzer core, CLI/TUI, web UI, report pipeline | Cross-compiles to one static binary with no runtime to ship; stdlib covers zip, crypto, HTTP and templating |
| **Rust** | OmniSec — machine code, IR, emulation, symbolic execution (52 crates) | Memory safety while parsing hostile binaries. This is the code most likely to be attacked, so it is the code that must not have a heap overflow |
| **Zig** | SIMD ML runtime, APK Editor desktop | Direct control over SIMD and Win32 with no runtime and no libc baggage |
| **Java** | APK Editor Android port (48 files), plus the demo test app (18 files) | It targets Android. That is the platform's language — anything else would mean shipping a runtime onto the device |
| **Elixir** | Optional distributed server (OTP) | Supervision trees and fault isolation for long-running batch jobs, essentially for free |
| **Python** | Tooling scripts (5) and the Django vulnerability labs (86 files) | Glue and disposable test targets. None of it is shipped in the binary or required to run the analyzer |

The core `go build` needs none of the others — see [Core build vs full native](#core-build-vs-full-native--whats-the-difference).

---

## Dependencies and build

### "Zero dependencies" — but `third-party/iced-x86` exists. Explain.

Two separate questions: why there are no dependencies at all, and why this one still got in.

**Why no dependencies.** I don't like dragging other people's code into my project, or the credits list that comes with it. I want everything native as far as I can take it, I like building things from scratch, and I want the result to be fast and to run on a microwave running Linux. That constraint is also what keeps the binaries small — the whole APK Editor IDE is 30 MB, and 28 MB of that is the core.

In practice that means the build never contacts a package registry. `go.mod` is two lines — `module mega-analyzer` and `go 1.27.3` — with no `require` block at all. `rust/Cargo.lock` holds 54 packages and **zero** `source = "registry+…"` entries: 52 are the in-tree `omnisec-*` crates, one is `nifshim` (also in-tree, at `server/native/nifshim`), and one is `iced-x86`.

**Why iced-x86 is the exception.** Version 1.21.0, vendored verbatim into `third-party/iced-x86/` under its MIT license, patched once, and wired in through `[patch.crates-io]` so every workspace member resolves to the local path.

The reason is simple: it decodes x86/x86-64, and x86 has a huge number of opcodes — each with its own encodings, prefixes and legacy corners. There is no point writing that from scratch; I would just burn time for nothing. The best possible outcome is a decoder that produces exactly the same output as one that already exists and already works. No gain, so I didn't do it.

Even as an exception it plays by the same rules:

- **Vendored, not fetched.** The bytes live in the tree and show up in the diff. Pulling the network cable changes nothing.
- **Made dependency-free too.** Upstream pulls in `lazy_static`; this fork rewrites all 21 `lazy_static!` blocks across 19 files to `std::sync::LazyLock` and drops the dependency from its `Cargo.toml`. So it brings no transitive dependencies of its own.
- **Reproducible patch.** `third-party/iced-x86/lazylock_patch.py` regenerates the tree byte-for-byte from pristine upstream 1.21.0, so an upstream bump is a rerun, not a manual re-merge.
- **Credited properly anyway.** The full MIT text travels with the copy, and the provenance — upstream repo, version, exact git commit — is written down in [`third-party/iced-x86/README.md`](../third-party/iced-x86/README.md).

So the accurate phrasing is **"no dependency management"**, not "not one line written by anyone else."

### Do I need Docker, JDK, Android SDK, or apktool?

No. A plain `go build` produces one self-contained binary that parses APK/DEX directly and has its own decode/rebuild path. Docker is one deployment option, not a requirement — see [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md).

### Core build vs full native — what's the difference?

Two separate binaries chosen at compile time, not a runtime switch:

- **Core** (`go build ./pkg/cmd/analyzer`): APK/DEX/Smali, manifest audit, secret triage, PE/ELF checks, every report format. Pure Go, no cgo, no shared libraries needed.
- **Full native** (via `cicd.ps1` or the cgo build tags): adds OmniSec (Rust), the Zig SIMD ML runtime and the GNN. This binary **requires** its `.dll` / `.so` / `.dylib` files at runtime — if they are missing it refuses to start rather than silently degrading.

Prebuilt releases ship the core binary. See [BUILD.md](BUILD.md).

### Do I need Rust or Zig installed?

Only to build the **full native** binary yourself. Core-binary users never need them.

### What hardware does it need?

A 2012-era quad-core with 8 GB RAM, CPU only. Peak RAM ~1.5–2 GB, typical runs 500–800 MB. No GPU, no CUDA.

---

## Running it

### Do I need `-no-tui`?

Usually not. Direct CLI analysis is the **default**: `analyzer -t app.apk` runs and writes reports with no extra flag. The interactive TUI is opt-in via `-tui`.

`-no-tui` is still accepted and useful in two cases:

- **Scripts and CI**, where you want headless output guaranteed regardless of future default changes.
- **Overriding an earlier `-tui`** in a generated command line — last intent wins, so `-tui -no-tui` runs headless.

The built-in web UI passes `-no-tui` to every analysis it spawns for exactly this reason. The old `-notui` alias was removed in beta.10.

### Reports won't write into a fresh custom `-o` directory. Why?

A custom output directory must contain a `.omnisec-output` marker file — a guard against clobbering unrelated folders. Fix: use the default `analysis_output`, or `touch <dir>/.omnisec-output` first. The GitHub Action does this automatically.

### Where's the complete flag reference?

[`FlagiFiles.md`](../FlagiFiles.md) — every flag, env var and build command. Curated cheat sheet: [USAGE.md](USAGE.md).

---

## Reading a report

### The report says HIGH risk but only 23% "Analysis Confidence". Which do I believe?

Both — they measure different things, and the label is the confusing part.

**"Analysis Confidence" is the mean confidence across detected hotspots**, not a confidence level for the verdict (`pkg/internal/report/score.go`). A sample with many low-certainty hotspots and a handful of critical ones lands exactly here: high risk, low mean hotspot confidence.

The risk score itself is a transparent four-bucket sum, capped at 100:

| Bucket | Weight | Cap |
| :--- | :--- | :--- |
| Pattern matches | ×2 each | 30 |
| Critical findings | ×5 each | 30 |
| Piracy indicators | ×8 each | 25 |
| Confidence boost | mean hotspot confidence × 15 | 15 |

So low mean confidence *lowers* the score rather than contradicting it. Read the verdict from the critical findings, and read the confidence figure as "how certain the engine is about the individual hotspots it flagged."

### Does it use an LLM, or send anything to an AI service at runtime?

No. The shipped analyzer contains no LLM and makes no network calls. ML is classical and local: HDC, GNN, gradient-boosted trees, random forest, logistic regression — all CPU, all offline.

This is separate from [AI tools being used to *write* the project](#is-one-person-really-behind-all-of-this). Development-time tooling and runtime behavior are different things: nothing you analyze is ever seen by a model that isn't on your machine.

### How do I know a detection rule actually works?

There is a checked-in evaluation corpus of paired vulnerable and benign fixtures:

```bash
go run ./cmd/eval -min-precision 0.80 -min-recall 0.80
```

It emits per-rule and micro-averaged precision, recall and F1. Every detector change is expected to add both a minimal positive fixture and a confusing benign one. See [QUALITY_EVALUATION.md](QUALITY_EVALUATION.md).

### Is it really 100% offline?

Yes. No external API calls, telemetry or update checks. Every built-in proxy, DNS and server binds to `localhost` only. Pull the network cable and run a full analysis — it completes normally.

---

## Sandbox and safety

### What do I need for the dynamic sandbox?

Windows detonation: just Windows (kernel/WFP monitors are optional). Android detonation: ADB plus a real device or emulator. Nothing is uploaded in either case.

### Is it safe to detonate real malware on my own machine?

**Treat this as a research sandbox, not a containment boundary.** Windows detonation runs the sample on the Windows host you launch it from, and Android detonation runs it on the device or emulator ADB is attached to. There is no hypervisor isolation between the sample and that machine.

For untrusted samples: use a disposable VM with no host folder sharing and no credentials, or a wiped dedicated device. Snapshot before, revert after.

---

## License and contributions

### Can I use it at work or commercially?

Yes. Mega-Analyzer is dual-licensed under [BSD-3-Clause](../LICENSE) OR
[GPLv2](../COPYING), at your option. Commercial use, modification and
redistribution are allowed under the terms of the license you choose.
Third-party components retain their own licenses, listed in [NOTICE.txt](../NOTICE.txt).

### Why aren't pull requests accepted?

Solo project by design. Keeping the codebase under one author's control is what keeps the architecture coherent and the security surface auditable. A well-written issue is genuinely valuable and will be read:

- **Bug** → [bug report](https://github.com/Promastergame/mega-analyzer/issues/new?template=bug_report.yml)
- **Idea** → [suggestion](https://github.com/Promastergame/mega-analyzer/issues/new?template=suggestion.yml)
- **Security vulnerability** → [private advisory](https://github.com/Promastergame/mega-analyzer/security/advisories/new), never a public issue
