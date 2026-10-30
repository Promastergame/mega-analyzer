# OmniSec — Rust workspace

Universal binary analysis & exploit platform. Heavy lifting (loaders, IR,
disassembly, vulndisc, exploit engine) lives here in Rust; the historical
APK / DEX-specific analysis and BinZAP remain in the parent Go module
(`mega-analyzer`). The release product is the single Go `analyzer` binary: it
routes native PE/ELF work to these Rust crates through the FFI library API and
does not spawn the standalone `omnisec` CLI. The Rust CLI is retained only for
crate development and focused native-engine diagnostics.

### BinZAP and OmniSec are complementary

| Engine | Input | Strength | Unified binary role |
| --- | --- | --- | --- |
| Go BinZAP | Smali, x86 ASM, APK-extracted trees | bytecode lexing, taint paths, mobile rules | APK/Smali/ASM path |
| Rust OmniSec | PE, ELF, native `.so`/`.dll` | loader/IR, disassembly, hardening and native findings | machine-code path |

They intentionally are not merged into one parser: their file formats and
finding models differ. `analyzer` is the orchestration layer that selects the
right library backend and combines reports, so users ship one executable.

## Crates

|| Crate                  | Purpose                                                    | Status |
|| ---------------------- | ---------------------------------------------------------- | ------ |
|| `omnisec-core`         | Format / Arch / Endian enums, magic-byte detection, errors | ✅ Phase 1 |
|| `omnisec-loader`       | `Loader` trait + `LoaderRegistry` dispatch                 | ✅ Phase 1 |
|| `omnisec-loader-pe`    | PE / .NET-PE parser (in-house `peparse`, zero-dep)        | ✅ Phase 1 |
|| `omnisec-loader-elf`   | ELF parser (in-house `elfparse`, zero-dep)                | ✅ Phase 1 |
|| `omnisec-ir`           | OmniIR — universal intermediate representation             | ✅ Phase 1 |
|| `omnisec-disasm`       | x86 / x86_64 lifter to OmniIR (via `iced-x86`)             | ✅ Phase 1 |
|| `omnisec-cfg`          | CFG construction, dominators, loops, DOT export            | ✅ Phase 2 |
|| `omnisec-dataflow`     | Generic dataflow analysis framework                        | 🚧 In Progress |
|| `omnisec-ssa`           | SSA form construction (Cytron algorithm)                   | ⏳ Pending |
|| `omnisec-callgraph`     | Inter-procedural call graph                               | ⏳ Pending |
|| `omnisec-metrics`      | Code metrics (McCabe, Halstead, cognitive)                 | 🚧 In Progress |
|| `omnisec-disasm-arm64`  | ARM64 lifter to OmniIR (via in-house `omnisec-arm64-decode`, zero-dep) | ⏳ Pending |
|| `omnisec-cli`          | `omnisec` binary                                           | ✅ Phase 1 |
|| `omnisec-smt`          | SMT-LIB style solver (DPLL + Linear Theory)                | ✅ Phase 3 |
|| `omnisec-analysis-symbolic` | Concolic (concrete + symbolic) executor             | ✅ Phase 3 |
|| `omnisec-hdc`          | Hyperdimensional Computing (HDC) engine for scanning       | ✅ Phase 3 |
|| `omnisec-pdg`          | Program Dependence Graph (PDG) construction                | ✅ Phase 3 |
|| `omnisec-ipdg`         | Inter-Process Dependency Graph (Cross-Boundary Taint)      | ✅ v11.0 |
|| `omnisec-scan-native`  | ML-Aetrium scan pipeline (HDC + Concolic)                  | 🚧 Phase 3 |

## Phase Status

### ✅ Phase 1: Foundation (Complete)
- Universal Loader (PE, ELF)
- OmniIR universal intermediate representation
- x86/x86_64 disassembly and lifting
- CLI skeleton with info/disasm/version commands
- ~3700 LOC, 51/51 tests passing, clippy clean

### 🚧 Phase 2: Analysis Core (In Progress)
**Completed:**
- CFG construction from OmniIR instructions
- Dominator tree (Cooper-Harvey-Kennedy iterative)
- Dominance frontier computation
- Loop detection (back edges, natural loops)
- Graphviz DOT export for visualization
- McCabe cyclomatic complexity

**In Progress:**
- Generic dataflow analysis framework
- Halstead metrics
- Cognitive complexity

**Pending:**
- SSA form construction (Cytron algorithm)
- Inter-procedural call graph
- ARM64 disassembly and lifting
- CLI integration (cfg, analyze commands)

### ✅ Phase 3: Vulnerability Scanning & Weaponization (NEW)
- **ML-Aetrium Engine**: Zero-float Graph ML engine using 2048-bit sparse HyperVectors for structural motif matching.
- **Custom SMT Solver**: Linear-arithmetic SMT solver with DPLL SAT engine and interval-based theory propagation.
- **Concolic Executor**: Integrated path exploration and branch flipping for automated payload synthesis.
- **Payload Witness Synthesis**: Automated derivation of concrete input witnesses for high-confidence vulnerability anchors.
- **PDG-Guided Taint Analysis**: Structural and data-flow validation of vulnerability paths.

### ✅ Phase 1 (v11.0): Omni-Graph Cross-Boundary Taint
- **IPDG Engine**: Inter-Process Dependency Graph builder for multi-component analysis.
- **Boundary Modeling**: 16 types of process boundaries (JNI, Syscall, IOCTL, Binder, etc.).
- **Cross-Boundary Taint**: Automated taint tracking across process and privilege boundaries.
- **Global Anchors**: Context-sensitive signatures that span multiple components.

## Build & test

```bash
cd rust
cargo build --workspace
cargo test --workspace
cargo clippy --workspace
```

## Run

```bash
cargo run --bin omnisec -- info path/to/binary
cargo run --bin omnisec -- disasm path/to/binary --limit 32
cargo run --bin omnisec -- version
```

## Lints

The whole workspace runs under `forbid(unsafe_code)`, `deny(missing_docs)`,
and `clippy::pedantic` / `clippy::nursery`. Format-specific raw parsers
(`elfparse`, `peparse`) are in-house, bounds-checked and `unsafe`-free.

## Roadmap

See `OMNISEC_PROJECT_PLAN.md` in the repository root.
