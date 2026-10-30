//! # OmniSec Deobfuscation Engine 🦀
//!
//! A multi-pass, iterative deobfuscation engine that operates on OmniIR.
//! It is architecture-agnostic: the same passes work on x86, ARM, Dalvik,
//! JVM, WASM — anything that has been lifted to OmniIR.
//!
//! ## Architecture
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────────────┐
//!  │                   DeobfuscationPipeline                        │
//!  │                                                                │
//!  │  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌─────────┐  │
//!  │  │ConstProp  │──▶│DeadCode   │──▶│Opaque     │──▶│Pattern  │  │
//!  │  │           │   │Elim       │   │Predicate  │   │Simplify │  │
//!  │  └───────────┘   └───────────┘   └───────────┘   └─────────┘  │
//!  │       │                                               │       │
//!  │       ▼                                               ▼       │
//!  │  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌─────────┐  │
//!  │  │String     │──▶│Reflection │──▶│Control    │──▶│MBA      │  │
//!  │  │Decrypt    │   │Resolve    │   │Flow Defl  │   │Simplify │  │
//!  │  └───────────┘   └───────────┘   └───────────┘   └─────────┘  │
//!  │                                                                │
//!  │              ◀── iterate until fixed-point ──▶                 │
//!  └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Passes
//!
//! | Pass | Description |
//! |------|-------------|
//! | **Constant Propagation** | Tracks constant values through registers, folds arithmetic |
//! | **Dead Code Elimination** | Removes unreachable blocks and unused instructions |
//! | **Opaque Predicate Removal** | Detects always-true/false branches, simplifies CFG |
//! | **Pattern Simplification** | Matches 50+ known obfuscation idioms and replaces them |
//! | **String Decryption** | Emulates XOR/RC4/AES string decryption routines |
//! | **Reflection Resolution** | Resolves `Class.forName` / `getMethod` chains |
//! | **Control Flow Deflattening** | Recovers original control flow from dispatcher loops |
//! | **MBA Simplification** | Simplifies Mixed Boolean-Arithmetic expressions |

pub mod emulator;
pub mod lattice;
pub mod passes;
pub mod patterns;
pub mod pipeline;
pub mod runtime;
pub mod stats;

pub use pipeline::{DeobfuscationPipeline, PipelineConfig, PipelineResult};
pub use runtime::{
    MemoryPermissions, MemoryRegion, RuntimeCodeDump, RuntimeMutationAnalyzer,
    RuntimeMutationConfig, RuntimeMutationFinding, RuntimeMutationKind, RuntimeMutationReport,
    RuntimeSnapshot,
};
pub use stats::DeobfuscationStats;
