//! # OmniSec Forge — Phase 4: Payload Synthesis & Witness Forge
//!
//! `omnisec-forge` is the **fourth and final** phase of the OmniSec autonomous
//! security-research pipeline. It is **not** a separate ML black box and it
//! does **not** call out to any cloud service or load any neural-network
//! weights. Everything here is pure-Rust, CPU-only, deterministic
//! bit-vector and constraint-satisfaction work — every input produces a
//! single byte-exact output, and the same `(ForgeConfig,
//! VulnerabilityPrimitive)` always produces the same `SynthesizedPayload`.
//!
//! ## Where it sits in the pipeline
//!
//! ```text
//!   ┌─────────────────────────────────────────────────────────────────────┐
//!   │ Phase 1: omnisec-hdc        → MatchResult { jaccard, severity, … } │
//!   │ Phase 2: omnisec-pdg/ipdg   → TaintPath  { source → … → sink     } │
//!   │ Phase 3: omnisec-analysis-  → SMT Model  { v1 = 0xdead_beef, …   } │
//!   │          symbolic / -smt                                            │
//!   └────────────────────────────────────┬────────────────────────────────┘
//!                                        ▼
//!                          ┌──────────────────────────────┐
//!                          │     Phase 4: omnisec-forge   │
//!                          │                              │
//!                          │  VulnerabilityPrimitive ─┐   │
//!                          │           ▼              │   │
//!                          │     ForgeEngine          │   │
//!                          │     ├─ chains/  (BGAT)   │   │
//!                          │     ├─ arch/    emitters │   │
//!                          │     ├─ mitigation/ pass  │   │
//!                          │     ├─ dop/  data graph  │   │
//!                          │     ├─ encoding/ XOR/SMT │   │
//!                          │     └─ oracle/  verify   │   │
//!                          │           ▼              │   │
//!                          │  SynthesizedPayload  ────┘   │
//!                          │   • payload bytes            │
//!                          │   • witness assignments      │
//!                          │   • gadget chain trace       │
//!                          └──────────────────────────────┘
//! ```
//!
//! ## Determinism guarantees
//!
//! - All randomness (gadget shuffling, encoder key search, complexity
//!   tie-breaking) is driven by the [`ForgeConfig::seed`] field via a
//!   xorshift64\* generator that lives in [`util::Prng`]. Identical seeds
//!   produce identical PRNG streams.
//! - Iteration order over `BTreeMap`/`Vec` is preserved end-to-end; we
//!   never depend on `HashMap` insertion order in produced output.
//! - SMT queries are sent to [`omnisec_smt::Solver`] which itself returns
//!   the canonical lower-bound witness for each variable, so the same
//!   constraint set always returns the same model.
//!
//! ## What Forge intentionally does *not* do
//!
//! - Run any model inference (no PyTorch, no TensorFlow, no LLM).
//! - Talk to any network service.
//! - Allocate GPU memory or require CUDA.
//! - Generate non-deterministic output.
//!
//! ## Top-level entry points
//!
//! - [`Forge`] — convenience wrapper that owns a [`ForgeConfig`] and exposes
//!   `synthesize(primitive)` returning a [`SynthesizedPayload`].
//! - [`compiler::ForgeEngine`] — the lower-level translator if you want to
//!   plug in your own per-stage strategies.
//! - [`benchmarks`] — pre-canned [`VulnerabilityPrimitive`] profiles for the
//!   2025-2026 threat landscape (React2Shell, GhostWrite, PAC timing,
//!   MTE intra-object, Clawdbot).

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod arch;
pub mod benchmarks;
pub mod chains;
pub mod compiler;
pub mod complexity;
pub mod config;
pub mod dop;
pub mod encoding;
pub mod error;
pub mod mitigation;
pub mod oracle;
pub mod payload;
pub mod pipeline;
pub mod primitive;
pub mod util;

pub use compiler::{ForgeEngine, ForgeStage, ForgeStageReport};
pub use complexity::ComplexityScore;
pub use config::{ForgeConfig, MitigationProfile};
pub use error::{ForgeError, Result};
pub use oracle::{ChildProcessOracle, MockOracle, Oracle, OracleVerdict, ProcessVerdict};
pub use payload::{Artifact, SynthesizedPayload, Witness, WitnessValue};
pub use pipeline::PipelineInput;
pub use primitive::{PrimitiveKind, VulnerabilityPrimitive};

use omnisec_core::Arch;

/// High-level wrapper around [`ForgeEngine`] that bundles a [`ForgeConfig`]
/// with a target [`Arch`] and exposes a one-call API.
///
/// ```ignore
/// use omnisec_forge::{Forge, ForgeConfig, benchmarks};
///
/// let cfg = ForgeConfig::for_arch(omnisec_core::Arch::Arm64);
/// let primitive = benchmarks::pac_timing();
/// let payload = Forge::new(cfg).synthesize(&primitive)?;
/// assert!(!payload.payload.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct Forge {
    cfg: ForgeConfig,
}

impl Forge {
    /// Build a Forge from an explicit config.
    #[must_use]
    pub fn new(cfg: ForgeConfig) -> Self {
        Self { cfg }
    }

    /// Build a Forge with default config for `arch`.
    #[must_use]
    pub fn for_arch(arch: Arch) -> Self {
        Self::new(ForgeConfig::for_arch(arch))
    }

    /// Borrow the underlying config.
    #[must_use]
    pub fn config(&self) -> &ForgeConfig {
        &self.cfg
    }

    /// Drive the full Phase-4 synthesis on a vulnerability primitive.
    ///
    /// Returns a fully-realised [`SynthesizedPayload`] containing payload
    /// bytes, witness assignments, and a per-stage report.
    pub fn synthesize(&self, primitive: &VulnerabilityPrimitive) -> Result<SynthesizedPayload> {
        ForgeEngine::new(self.cfg.clone()).run(primitive)
    }
}
