//! Control Flow Deflattening pass.
//!
//! Uses a proof-based engine to recover original control flow structures
//! from flattened control flow graphs.

use std::time::Instant;

use omnisec_cfg::ControlFlowGraph;
use omnisec_ir::Operand;
use std::collections::{HashMap as FxHashMap, HashSet as FxHashSet};

use crate::passes::DeobfuscationPass;
use crate::stats::PassStats;

use super::cff_proof::prove_cff;

/// Pass that reverses control flow flattening obfuscation.
#[derive(Default)]
pub struct ControlFlowDeflattening;

impl DeobfuscationPass for ControlFlowDeflattening {
    fn name(&self) -> &str {
        "ControlFlowDeflattening"
    }

    fn should_run(&self, iteration: usize) -> bool {
        iteration < 3
    }

    fn run(&self, cfg: &mut ControlFlowGraph) -> PassStats {
        let start = Instant::now();
        let mut stats = PassStats::new(self.name());

        // 1. Find dispatcher block (most successors, >= 3)
        let block_ids: Vec<u32> = cfg.block_ids().collect();
        let mut max_succs = 0;
        let mut candidate_dispatcher = None;

        for &id in &block_ids {
            let succs = cfg.successors(id);
            if succs.len() >= 3 && succs.len() > max_succs {
                max_succs = succs.len();
                candidate_dispatcher = Some(id);
            }
        }

        let Some(dispatcher_id) = candidate_dispatcher else {
            stats.duration = start.elapsed();
            return stats;
        };

        // 2. Verify dominance
        // Compute dominators for cases. We do a simple iterative dominator solver.
        let rpo = cfg.reverse_postorder();
        let mut doms: FxHashMap<u32, FxHashSet<u32>> = FxHashMap::default();
        let all_nodes: FxHashSet<u32> = block_ids.iter().copied().collect();

        if let Some(&entry) = rpo.first() {
            let mut entry_set = FxHashSet::default();
            entry_set.insert(entry);
            doms.insert(entry, entry_set);

            for &n in rpo.iter().skip(1) {
                doms.insert(n, all_nodes.clone());
            }

            let mut changed = true;
            while changed {
                changed = false;
                for &n in rpo.iter().skip(1) {
                    let preds = cfg.predecessors(n);
                    if preds.is_empty() {
                        continue;
                    }

                    // Intersection of all predecessors' dominators
                    let mut new_dom: Option<FxHashSet<u32>> = None;
                    for &p in preds {
                        if let Some(p_doms) = doms.get(&p) {
                            match new_dom.as_mut() {
                                Some(d) => {
                                    d.retain(|x| p_doms.contains(x));
                                }
                                None => {
                                    new_dom = Some(p_doms.clone());
                                }
                            }
                        }
                    }

                    let mut next_dom = new_dom.unwrap_or_default();
                    next_dom.insert(n);

                    if let Some(old_dom) = doms.get(&n) {
                        if old_dom != &next_dom {
                            doms.insert(n, next_dom);
                            changed = true;
                        }
                    }
                }
            }
        }

        let dispatcher_succs = cfg.successors(dispatcher_id);
        let mut dominated_count = 0;
        for &succ in dispatcher_succs {
            if let Some(d) = doms.get(&succ) {
                if d.contains(&dispatcher_id) {
                    dominated_count += 1;
                }
            }
        }

        if dominated_count < dispatcher_succs.len() / 2 {
            stats.trace.push(format!(
                "Dispatcher candidate {} failed dominance check",
                dispatcher_id
            ));
            stats.duration = start.elapsed();
            return stats;
        }

        // Try to identify state register from dispatcher block
        let mut state_reg = None;
        if let Some(d_block) = cfg.block(dispatcher_id) {
            // Find a branch/switch condition on a register, or simple heuristic: look for last read register
            if let Some(term) = d_block.terminator() {
                for src in &term.src {
                    if let Operand::Register(r) = src {
                        state_reg = Some(r.native_id);
                        break;
                    }
                }
            }
            if state_reg.is_none() {
                // heuristic: last instruction's first register source
                if let Some(last) = d_block.instructions.last() {
                    for src in &last.src {
                        if let Operand::Register(r) = src {
                            state_reg = Some(r.native_id);
                            break;
                        }
                    }
                }
            }
        }

        let Some(s_reg) = state_reg else {
            stats.trace.push(format!(
                "Could not identify state register for dispatcher {}",
                dispatcher_id
            ));
            stats.duration = start.elapsed();
            return stats;
        };

        // 3. Prove CFF edges
        let evidence = prove_cff(cfg, dispatcher_id, s_reg);

        // 4. Check confidence
        if evidence.confidence < 90 {
            stats.trace.push(format!(
                "Partial CFF recovery: Dispatcher={}, Confidence={}% (proven={}, uncertain={})",
                dispatcher_id,
                evidence.confidence,
                evidence.proven_edges.len(),
                evidence.uncertain_blocks.len()
            ));
        } else {
            // 5. Apply rewrite
            stats.trace.push(format!(
                "Applying CFF rewrite: Dispatcher={}, Confidence={}%",
                dispatcher_id, evidence.confidence
            ));

            for &(from, to) in &evidence.proven_edges {
                cfg.add_edge(from, to);
            }
            stats.instructions_changed += evidence.proven_edges.len();
        }

        stats.duration = start.elapsed();
        stats
    }
}
