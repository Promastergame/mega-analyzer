//! Deobfuscation passes — the core transformation engine.
//!
//! Each pass implements the [`DeobfuscationPass`] trait and operates on a
//! [`ControlFlowGraph`]. Passes are composed by the [`super::pipeline`].

pub mod cff_proof;
pub mod constant_propagation;
pub mod control_flow_deflattening;
pub mod dead_code_elimination;
pub mod mba_simplification;
pub mod opaque_predicates;
pub mod pattern_simplification;
pub mod string_decryption;

use omnisec_cfg::ControlFlowGraph;

use crate::stats::PassStats;

/// Trait that every deobfuscation pass must implement.
pub trait DeobfuscationPass: Send + Sync {
    /// Human-readable name of this pass.
    fn name(&self) -> &str;

    /// Run the pass on the CFG, mutating it in place.
    /// Returns statistics about what was changed.
    fn run(&self, cfg: &mut ControlFlowGraph) -> PassStats;

    /// Whether this pass should run in the current iteration.
    /// Passes can opt out if they detect they have no more work.
    fn should_run(&self, _iteration: usize) -> bool {
        true
    }
}
