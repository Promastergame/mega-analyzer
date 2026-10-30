//! CFF state-variable proof engine.
//!
//! Separate from the rewriting logic in `control_flow_deflattening.rs`,
//! this module drives the forward analysis that proves which block each
//! case block transitions to.

use omnisec_cfg::ControlFlowGraph;
use omnisec_ir::{OpCode, Operand};
use std::collections::HashMap as FxHashMap;

/// Evidence gathered during Control Flow Deflattening proof analysis.
pub struct CffEvidence {
    pub dispatcher_id: u32,
    pub state_reg: u32,
    /// Directly proven (case_block → target_block) edges
    pub proven_edges: Vec<(u32, u32)>,
    /// Blocks where we could not determine the next state
    pub uncertain_blocks: Vec<u32>,
    /// 0–100 confidence score = proven_edges / (proven_edges + uncertain)
    pub confidence: u8,
}

pub fn prove_cff(cfg: &ControlFlowGraph, dispatcher_id: u32, state_reg: u32) -> CffEvidence {
    let case_blocks = cfg.successors(dispatcher_id).to_vec();
    let mut next_state_map = FxHashMap::new();

    // 1. For each case block, find the last assignment to state_reg with an immediate value.
    for &cb in &case_blocks {
        if let Some(block) = cfg.block(cb) {
            let mut found_val = None;
            for inst in block.instructions.iter().rev() {
                if inst.opcode == OpCode::Move {
                    if let Some(Operand::Register(dst_reg)) = inst.dst.first() {
                        if dst_reg.native_id == state_reg {
                            if let Some(Operand::Immediate(val)) = inst.src.first() {
                                found_val = Some(*val);
                                break;
                            }
                        }
                    }
                }
            }
            if let Some(val) = found_val {
                next_state_map.insert(cb, val);
            }
        }
    }

    let mut proven_edges = Vec::new();
    let mut uncertain_blocks = Vec::new();

    // 2. Resolve edges
    for &cb in &case_blocks {
        if let Some(&next_val) = next_state_map.get(&cb) {
            let mut target = None;
            let mut matches = 0;

            for &cand in &case_blocks {
                if let Some(block) = cfg.block(cand) {
                    let mut has_match = false;
                    // Check top 3 instructions for the next_val
                    for inst in block.instructions.iter().take(3) {
                        for src in &inst.src {
                            if let Operand::Immediate(v) = src {
                                if *v == next_val {
                                    has_match = true;
                                    break;
                                }
                            }
                        }
                        for dst in &inst.dst {
                            if let Operand::Immediate(v) = dst {
                                if *v == next_val {
                                    has_match = true;
                                    break;
                                }
                            }
                        }
                        if has_match {
                            break;
                        }
                    }
                    if has_match {
                        target = Some(cand);
                        matches += 1;
                    }
                }
            }

            if matches == 1 {
                if let Some(t) = target {
                    proven_edges.push((cb, t));
                }
            } else {
                uncertain_blocks.push(cb);
            }
        } else {
            uncertain_blocks.push(cb);
        }
    }

    let total = proven_edges.len() + uncertain_blocks.len();
    let confidence = if total > 0 {
        ((proven_edges.len() * 100) / total) as u8
    } else {
        0
    };

    CffEvidence {
        dispatcher_id,
        state_reg,
        proven_edges,
        uncertain_blocks,
        confidence,
    }
}
