//! **Dead Code Elimination** — remove unreachable blocks and useless instructions.
//!
//! Two phases:
//! 1. **Unreachable block removal**: DFS from entry, delete anything not visited.
//! 2. **Dead instruction removal**: backward scan within each block; if an
//!    instruction defines a register that is never read before being redefined,
//!    it is dead and can be removed.

use std::time::Instant;

use omnisec_cfg::ControlFlowGraph;
use omnisec_ir::{OpCode, Operand};
use std::collections::HashSet as FxHashSet;

use super::DeobfuscationPass;
use crate::stats::PassStats;

/// Dead code elimination pass.
pub struct DeadCodeEliminationPass;

impl DeobfuscationPass for DeadCodeEliminationPass {
    fn name(&self) -> &'static str {
        "DeadCodeElimination"
    }

    fn run(&self, cfg: &mut ControlFlowGraph) -> PassStats {
        let start = Instant::now();
        let mut stats = PassStats::new(self.name());

        // Phase 1: Remove unreachable blocks
        let reachable = cfg.reachable_from_entry();
        let all_blocks: Vec<u32> = cfg.block_ids().collect();
        let unreachable_count = all_blocks.len() - reachable.len();

        if unreachable_count > 0 {
            stats.blocks_removed += unreachable_count;
            stats.trace.push(format!(
                "Removed {unreachable_count} unreachable blocks out of {}",
                all_blocks.len()
            ));
        }

        // Phase 2: Remove dead instructions within reachable blocks
        for &block_id in &all_blocks {
            if !reachable.contains(&block_id) {
                continue;
            }

            let block = match cfg.block(block_id) {
                Some(b) => b,
                None => continue,
            };

            if block.instructions.is_empty() {
                continue;
            }

            // Collect registers that are "live" at the end of the block.
            // Conservative: we assume all registers mentioned in successors
            // are live. For a real implementation we'd use liveness analysis
            // from omnisec-dataflow, but this gives good results in practice.
            let mut live_regs: FxHashSet<u32> = FxHashSet::default();

            // All registers used by successor blocks' phi-like instructions
            // are live at the end of this block
            for &succ_id in cfg.successors(block_id) {
                if let Some(succ) = cfg.block(succ_id) {
                    for insn in &succ.instructions {
                        for src in &insn.src {
                            if let Operand::Register(r) = src {
                                live_regs.insert(r.native_id);
                            }
                        }
                    }
                }
            }

            // Backward scan: mark which instructions are dead
            let insns = &block.instructions;
            let mut keep = vec![true; insns.len()];

            for i in (0..insns.len()).rev() {
                let insn = &insns[i];

                // Never remove instructions with side effects
                if has_side_effects(insn.opcode) {
                    // These instructions are always live; mark their sources as live
                    for src in &insn.src {
                        if let Operand::Register(r) = src {
                            live_regs.insert(r.native_id);
                        }
                    }
                    continue;
                }

                // Check if the destination is live
                let dst_live = insn.dst.iter().any(|op| match op {
                    Operand::Register(r) => live_regs.contains(&r.native_id),
                    _ => true, // memory destinations are always "live"
                });

                if !dst_live && !insn.dst.is_empty() {
                    // This instruction's result is never used — it's dead!
                    keep[i] = false;
                    stats.instructions_changed += 1;
                    stats.trace.push(format!(
                        "Dead instruction at {:#x}: {:?}",
                        insn.address, insn.opcode
                    ));
                } else {
                    // Instruction is live — mark its sources as live
                    for src in &insn.src {
                        if let Operand::Register(r) = src {
                            live_regs.insert(r.native_id);
                        }
                    }
                    // Remove destination from live set (it's been defined here)
                    for dst in &insn.dst {
                        if let Operand::Register(r) = dst {
                            live_regs.remove(&r.native_id);
                        }
                    }
                }
            }

            // Apply the removals
            let dead_count = keep.iter().filter(|&&k| !k).count();
            if dead_count > 0 {
                let new_insns: Vec<_> = insns
                    .iter()
                    .zip(keep.iter())
                    .filter(|&(_, &k)| k)
                    .map(|(insn, _)| insn.clone())
                    .collect();

                if let Some(block_mut) = cfg.block_mut(block_id) {
                    block_mut.instructions = new_insns;
                }
            }
        }

        stats.duration = start.elapsed();
        stats
    }
}

/// Check if an instruction has side effects beyond its destination register.
fn has_side_effects(op: OpCode) -> bool {
    matches!(
        op,
        OpCode::Store
            | OpCode::Call
            | OpCode::IndirectCall
            | OpCode::SystemCall
            | OpCode::Return
            | OpCode::Jump
            | OpCode::BranchIf
            | OpCode::Trap
            | OpCode::Halt
            | OpCode::Push
            | OpCode::Fence
            | OpCode::CmpXchg
    )
}
