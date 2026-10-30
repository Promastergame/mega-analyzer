# Mega-Analyzer architecture (v1.0.0-beta.1)

**🇬🇧 English** · [🇷🇺 Русский](ARCHITECTURE.ru.md)

Mega-Analyzer is designed as a high-performance, extensible platform for static and
dynamic analysis. It combines components in four languages (Go, Rust, Zig, Elixir)
to maximize speed, safety, and flexibility.

---

## High-level diagram

```text
                        ┌──────────────────────────────┐
                        │     Mega-Analyzer CLI        │
                        │ analyzer.exe / Rust CLI      │
                        └───────────────┬──────────────┘
                                        │
        ┌───────────────────────────────┼───────────────────────────────┐
        ▼                               ▼                               ▼
┌───────────────────┐           ┌───────────────────┐           ┌───────────────────┐
│ Android / Bytecode│           │ OmniSec native    │           │ Dynamic / Sandbox │
│ APK / DEX / Smali │           │ PE / ELF / DEX    │           │ Windows local     │
└─────────┬─────────┘           └─────────┬─────────┘           └─────────┬─────────┘
          │                               │                               │
          ▼                               ▼                               ▼
┌───────────────────┐           ┌───────────────────┐           ┌───────────────────┐
│ Pipeline detectors│           │ OmniIR / CFG / SSA│           │ FS/Reg/API/Net    │
│ Rules / Matcher   │           │ Dataflow / PDG    │           │ Behavior evidence │
└─────────┬─────────┘           └─────────┬─────────┘           └─────────┬─────────┘
          │                               │                               │
          └───────────────────────────────┼───────────────────────────────┘
                                          ▼
                               ┌───────────────────────┐
                               │ Reports + Correlation │
                               │ HTML / MD / JSON      │
                               └───────────────────────┘
```

> **Note:** the Zig static library `omnisec-ml-runtime` provides SIMD-optimized
> XNOR-GEMM / Hamming kernels for the hot paths of HDC (Hyperdimensional Computing).

---

## Smart scheduling: the Adaptive Worker Scheduler

Unlike fixed thread pools that can cause memory pressure, Mega-Analyzer uses an
adaptive scheduler (`Scheduler[T, R]`). It tracks system load and dynamically
scales the worker pool.

```text
┌─────────────────────────────────────────┐
│  Adaptive Scheduler                     │
│                                         │
│  Monitors:                              │
│    • CPU pressure (scheduling latency)  │
│    • Heap pressure (GC overhead)        │
│    • Queue depth (backpressure)         │
│    • GC pause time (STW impact)         │
│    • Allocation rate                    │
│                                         │
│  Actions:                               │
│    • Scale UP when idle + queue full    │
│    • Scale DOWN when GC/heap stressed   │
│    • Cooldown between decisions         │
│    • Workers self-terminate gracefully  │
└─────────────────────────────────────────┘
```

### Scheduler parameters

* `MinWorkers` (default: 2) — lower bound of the pool.
* `MaxWorkers` (default: `NumCPU * 2`) — upper bound of the pool.
* `CPUHighThreshold` (default: 0.85) — CPU-load threshold for scaling down.
* `HeapHighThreshold` (default: 0.80) — heap-usage threshold for releasing memory.
* `QueueDepthThreshold` (default: 32) — queue depth at which workers are added.
* `GCPauseThreshold` (default: 5ms) — GC-pause threshold that triggers scale-down.
* `CooldownTime` (default: 500ms) — wait time between pool-resize decisions.

---

## Core modules

### 1. Go CLI & core (`pkg/`)
* **Go CLI / TUI (`pkg/cmd/analyzer`)** — the command-line interface and text UI.
* **APK/DEX loader (`pkg/internal/apkloader`)** — parses APK and DEX structure without any external Java libraries.
* **SIMD ULEB128 (`pkg/internal/apkloader/simdleb`)** — a native assembly batch decoder that speeds up DEX parsing (+30%).
* **Pipeline (`pkg/internal/pipeline`)** — dispatch and execution of checks.
* **Content cache (`pkg/internal/contentcache`)** — a content-addressable incremental analysis cache.
* **Dataflow / Taint engine (`pkg/internal/dataflow`)** — interprocedural dataflow and taint analysis engine.
* **SMT solver (`pkg/internal/smt`)** — branch-condition parsing and symbolic evaluation on a DPLL SAT core.
* **Deobf metrics (`pkg/internal/deobfmetrics`)** — quantitative scoring of deobfuscation quality.
* **SSA IR (`pkg/internal/ssair`)** — a custom SSA intermediate representation for code optimization.

### 2. Rust core (`rust/crates/`)
A workspace of 39 specialized crates:
* `omnisec-core` — base types and data structures.
* `omnisec-loader-*` — ELF, PE, MachO, and DEX format parsers.
* `omnisec-ir`, `omnisec-cfg`, `omnisec-ssa` — control-flow graph and SSA construction.
* `omnisec-dataflow`, `omnisec-callgraph` — call-graph and data-flow analysis.
* `omnisec-deobfuscator` — deobfuscation modules.
* `omnisec-ml-gnn` — a Graph Neural Network for classifying vulnerability types (UAF, buffer overflow, race conditions, etc.).
* `omnisec-emu-x86` — an emulator for safely unpacking crypto routines and strings.
* `omnisec-ebpf` — a Linux/Android kernel syscall monitor.

### 3. Zig ML runtime & sandbox (`zig/`)
* **SIMD ML runtime (`zig/src/`)** — optimized linear-algebra and sparse-compute kernels in Zig for running ML models locally.
* **Windows sandbox (`zig/sandbox/`)** — an isolated Windows sandbox for monitoring the behavior of binaries under test.

### 4. Elixir/Phoenix server (`server/`)
* **Phoenix web server** — interface for distributed task processing, caching, and debugger control.
* **Rust NIFs** — high-performance Rust bridge functions for signal processing and fast model inference.
