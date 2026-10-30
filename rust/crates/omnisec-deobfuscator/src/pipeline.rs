//! **Deobfuscation Pipeline** — the main orchestrator.
//!
//! Composes all passes into an iterative fixed-point loop:
//!
//! ```text
//! repeat {
//!     ConstantPropagation → changes₁
//!     DeadCodeElimination → changes₂
//!     OpaquePredicateRemoval → changes₃
//!     PatternSimplification → changes₄
//!     StringDecryption → changes₅
//!     ControlFlowDeflattening → changes₆
//!     MBASimplification → changes₇
//! } until changes₁ + ... + changes₇ == 0 || max_iterations reached
//! ```
//!
//! The pipeline also supports parallel processing of multiple functions via
//! Rayon, making it scale linearly with the number of CPU cores.

use std::time::Instant;

use omnisec_cfg::ControlFlowGraph;
use omnisec_json::{FromJson, ToJson};

use crate::passes::DeobfuscationPass;
use crate::passes::constant_propagation::ConstantPropagationPass;
use crate::passes::control_flow_deflattening::ControlFlowDeflattening;
use crate::passes::dead_code_elimination::DeadCodeEliminationPass;
use crate::passes::mba_simplification::MbaSimplificationPass;
use crate::passes::opaque_predicates::OpaquePredicatePass;
use crate::passes::pattern_simplification::PatternSimplificationPass;
use crate::passes::string_decryption::StringDecryptionPass;
use crate::stats::DeobfuscationStats;

/// Pipeline configuration.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct PipelineConfig {
    /// Maximum number of fixed-point iterations.
    pub max_iterations: usize,

    // ── Per-pass toggles ──────────────────────────────────────────
    /// Enable constant propagation and folding.
    pub enable_constant_propagation: bool,
    /// Enable dead code elimination.
    pub enable_dead_code_elimination: bool,
    /// Enable opaque predicate detection and removal.
    pub enable_opaque_predicates: bool,
    /// Enable pattern-based simplification.
    pub enable_pattern_simplification: bool,
    /// Enable string decryption via emulation.
    pub enable_string_decryption: bool,
    /// Enable control flow deflattening.
    pub enable_control_flow_deflattening: bool,
    /// Enable mixed boolean-arithmetic simplification.
    pub enable_mba_simplification: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10,
            enable_constant_propagation: true,
            enable_dead_code_elimination: true,
            enable_opaque_predicates: true,
            enable_pattern_simplification: true,
            enable_string_decryption: true,
            enable_control_flow_deflattening: true,
            enable_mba_simplification: true,
        }
    }
}

impl PipelineConfig {
    /// Preset: maximum deobfuscation power (all passes, more iterations).
    #[must_use]
    pub fn aggressive() -> Self {
        Self {
            max_iterations: 20,
            ..Default::default()
        }
    }

    /// Preset: fast mode (fewer passes, fewer iterations).
    #[must_use]
    pub fn fast() -> Self {
        Self {
            max_iterations: 3,
            enable_string_decryption: false,
            enable_control_flow_deflattening: false,
            enable_mba_simplification: false,
            ..Default::default()
        }
    }
}

/// Result of running the deobfuscation pipeline on one function.
#[derive(Debug, Clone)]
pub struct PipelineResult {
    /// Statistics and metrics.
    pub stats: DeobfuscationStats,
    /// Whether the pipeline reached a fixed point (no more changes).
    pub converged: bool,
}

/// The deobfuscation pipeline itself.
pub struct DeobfuscationPipeline {
    config: PipelineConfig,
    passes: Vec<Box<dyn DeobfuscationPass>>,
}

impl DeobfuscationPipeline {
    /// Create a new pipeline with the given configuration.
    #[must_use]
    pub fn new(config: PipelineConfig) -> Self {
        let mut passes: Vec<Box<dyn DeobfuscationPass>> = Vec::new();

        // Passes are ordered strategically:
        // 1. ConstProp first (resolves values for everything else)
        // 2. Opaque predicates (needs constant info)
        // 3. DCE (removes code killed by opaque pred removal)
        // 4. Pattern simplification (peephole)
        // 5. MBA (complex expression simplification)
        // 6. String decryption (uses emulator)
        // 7. CFF (structural recovery — once)

        if config.enable_constant_propagation {
            passes.push(Box::new(ConstantPropagationPass));
        }
        if config.enable_opaque_predicates {
            passes.push(Box::new(OpaquePredicatePass));
        }
        if config.enable_dead_code_elimination {
            passes.push(Box::new(DeadCodeEliminationPass));
        }
        if config.enable_pattern_simplification {
            passes.push(Box::new(PatternSimplificationPass::new()));
        }
        if config.enable_mba_simplification {
            passes.push(Box::new(MbaSimplificationPass));
        }
        if config.enable_string_decryption {
            passes.push(Box::new(StringDecryptionPass::new()));
        }
        if config.enable_control_flow_deflattening {
            passes.push(Box::new(ControlFlowDeflattening::default()));
        }

        Self { config, passes }
    }

    /// Create a pipeline with default settings.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(PipelineConfig::default())
    }

    /// Run the pipeline on a single function's CFG.
    pub fn run(&self, cfg: &mut ControlFlowGraph) -> PipelineResult {
        let pipeline_start = Instant::now();
        let mut stats = DeobfuscationStats {
            instructions_before: count_instructions(cfg),
            blocks_before: cfg.block_count(),
            ..Default::default()
        };

        let mut converged = false;

        for iteration in 0..self.config.max_iterations {
            let mut iteration_changes = 0;

            for pass in &self.passes {
                if !pass.should_run(iteration) {
                    continue;
                }

                omnisec_log::debug!("Iteration {iteration}: running pass '{}'", pass.name());

                let pass_stats = pass.run(cfg);
                let changes = pass_stats.total_changes();
                iteration_changes += changes;

                if changes > 0 {
                    omnisec_log::info!("  {} made {} changes", pass.name(), changes);
                }

                stats.record_pass(iteration, pass_stats);
            }

            stats.iterations = iteration + 1;

            if iteration_changes == 0 {
                omnisec_log::info!("Pipeline converged after {} iterations", iteration + 1);
                converged = true;
                break;
            }

            omnisec_log::debug!("Iteration {iteration}: {iteration_changes} total changes");
        }

        // Record "after" metrics
        stats.instructions_after = count_instructions(cfg);
        stats.blocks_after = cfg.block_count();
        stats.total_duration = pipeline_start.elapsed();

        PipelineResult { stats, converged }
    }

    /// Run the pipeline on multiple functions in parallel using a
    /// scoped thread pool from the standard library.
    ///
    /// Splits the CFG slice into roughly even chunks (one per CPU core,
    /// capped at the number of CFGs) and runs each chunk on a worker
    /// thread. Each function's CFG is processed independently, making this
    /// embarrassingly parallel — and dependency-free now that we no
    /// longer reach for `rayon`.
    pub fn run_parallel(&self, cfgs: &mut [ControlFlowGraph]) -> Vec<PipelineResult>
    where
        Self: Sync,
    {
        let n = cfgs.len();
        if n == 0 {
            return Vec::new();
        }
        let workers = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .min(n);
        if workers <= 1 {
            return cfgs.iter_mut().map(|cfg| self.run(cfg)).collect();
        }

        // Pre-size the result vector and split the CFG slice into mutable
        // sub-slices we can hand to scoped threads. Indexing back into the
        // result vector via the sub-slice's offset keeps the output order
        // stable, which downstream callers depend on.
        let chunk = n.div_ceil(workers);
        let mut results: Vec<Option<PipelineResult>> = (0..n).map(|_| None).collect();

        std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(workers);
            // Track the result slice in lockstep with the CFG chunks so
            // workers don't share writable state.
            let mut cfg_slice: &mut [ControlFlowGraph] = cfgs;
            let mut res_slice: &mut [Option<PipelineResult>] = &mut results;
            while !cfg_slice.is_empty() {
                let take = chunk.min(cfg_slice.len());
                let (cfg_head, cfg_rest) = cfg_slice.split_at_mut(take);
                let (res_head, res_rest) = res_slice.split_at_mut(take);
                cfg_slice = cfg_rest;
                res_slice = res_rest;
                handles.push(s.spawn(move || {
                    for (i, cfg) in cfg_head.iter_mut().enumerate() {
                        res_head[i] = Some(self.run(cfg));
                    }
                }));
            }
            for h in handles {
                let _ = h.join();
            }
        });

        results.into_iter().map(Option::unwrap).collect()
    }
}

/// Count total instructions across all blocks in a CFG.
fn count_instructions(cfg: &ControlFlowGraph) -> usize {
    cfg.iter_blocks().map(|b| b.instructions.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_cfg::block::{BasicBlock, BlockKind};
    use omnisec_core::Arch;
    use omnisec_ir::operand::{Register, RegisterClass};
    use omnisec_ir::{Instruction, OpCode, Operand};

    fn make_reg(id: u32) -> Register {
        Register {
            arch: Arch::X86_64,
            class: RegisterClass::GeneralPurpose,
            native_id: id,
            bit_width: 64,
            name: format!("r{id}"),
        }
    }

    #[test]
    fn pipeline_folds_constant_chain() {
        // Build a CFG with one block:
        //   mov r0, 10
        //   add r0, r0, 20
        //   add r0, r0, 12
        //   return r0
        // After constant propagation: r0 should be 42
        let r0 = make_reg(0);
        let insns = vec![
            Instruction::new(OpCode::Move, 0, 4, Arch::X86_64)
                .with_dst([Operand::Register(r0.clone())])
                .with_src([Operand::Immediate(10)]),
            Instruction::new(OpCode::Add, 4, 4, Arch::X86_64)
                .with_dst([Operand::Register(r0.clone())])
                .with_src([Operand::Register(r0.clone()), Operand::Immediate(20)]),
            Instruction::new(OpCode::Add, 8, 4, Arch::X86_64)
                .with_dst([Operand::Register(r0.clone())])
                .with_src([Operand::Register(r0.clone()), Operand::Immediate(12)]),
            Instruction::new(OpCode::Return, 12, 1, Arch::X86_64)
                .with_src([Operand::Register(r0.clone())]),
        ];

        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(BasicBlock {
            id: 0,
            start_address: 0,
            end_address: 16,
            instructions: insns,
            kind: BlockKind::Entry,
        });

        let pipeline = DeobfuscationPipeline::new(PipelineConfig::fast());
        let result = pipeline.run(&mut cfg);

        assert!(result.stats.total_constants_resolved > 0);
        assert!(result.stats.reduction_percent() >= 0.0);
    }

    #[test]
    fn pipeline_removes_nop_slides() {
        let r0 = make_reg(0);
        let mut insns: Vec<Instruction> = (0..10)
            .map(|i| Instruction::new(OpCode::Nop, i, 1, Arch::X86_64))
            .collect();
        insns.push(
            Instruction::new(OpCode::Return, 10, 1, Arch::X86_64).with_src([Operand::Register(r0)]),
        );

        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(BasicBlock {
            id: 0,
            start_address: 0,
            end_address: 11,
            instructions: insns,
            kind: BlockKind::Entry,
        });

        let pipeline = DeobfuscationPipeline::new(PipelineConfig::fast());
        let result = pipeline.run(&mut cfg);

        assert!(result.stats.total_patterns_applied > 0);
    }

    #[test]
    fn config_presets() {
        let aggressive = PipelineConfig::aggressive();
        assert_eq!(aggressive.max_iterations, 20);
        assert!(aggressive.enable_mba_simplification);

        let fast = PipelineConfig::fast();
        assert_eq!(fast.max_iterations, 3);
        assert!(!fast.enable_string_decryption);
        assert!(!fast.enable_control_flow_deflattening);
    }
}
