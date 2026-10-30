//! Cognitive complexity.

use omnisec_cfg::dominators::DominatorTree;
use omnisec_cfg::ControlFlowGraph;
use std::collections::HashSet as FxHashSet;

/// Cognitive complexity metric.
#[derive(Debug, Clone, Copy)]
pub struct CognitiveComplexity {
    /// The cognitive complexity value.
    pub value: usize,
}

impl CognitiveComplexity {
    /// Compute cognitive complexity from a CFG.
    ///
    /// This uses a graph-theoretic approximation of cognitive complexity:
    /// 1. Identifies natural loops using the dominator tree (back-edges).
    /// 2. Calculates loop nesting depth for each block.
    /// 3. Increments complexity for every branching node (successors > 1),
    ///    adding a penalty based on its loop nesting depth.
    #[must_use]
    pub fn from_cfg(cfg: &ControlFlowGraph) -> Self {
        let dt = DominatorTree::compute(cfg);
        let mut natural_loops: Vec<FxHashSet<u32>> = Vec::new();

        // 1. Find all back-edges and compute natural loops
        for a in cfg.block_ids() {
            for &b in cfg.successors(a) {
                // A back-edge is an edge A -> B where B dominates A
                if dt.dominates(b, a) {
                    let mut loop_nodes = FxHashSet::default();
                    loop_nodes.insert(b);
                    loop_nodes.insert(a);

                    let mut worklist = vec![a];
                    while let Some(n) = worklist.pop() {
                        if n == b {
                            continue;
                        }
                        for &p in cfg.predecessors(n) {
                            if loop_nodes.insert(p) {
                                worklist.push(p);
                            }
                        }
                    }
                    natural_loops.push(loop_nodes);
                }
            }
        }

        let mut total_complexity = 0;

        // 2. Compute complexity: branches + loop nesting penalties
        for block_id in cfg.block_ids() {
            let succs = cfg.successors(block_id).len();

            // Only structural breaks (branches, loops, switches) add to cognitive complexity
            if succs > 1 {
                // Calculate loop nesting depth for this block
                let mut nesting_depth = 0;
                for lp in &natural_loops {
                    if lp.contains(&block_id) {
                        nesting_depth += 1;
                    }
                }

                // Base cost of 1 for the branch, plus nesting penalty
                total_complexity += 1 + nesting_depth;
            }
        }

        Self {
            value: total_complexity,
        }
    }
}

/// Compute cognitive complexity for a CFG.
#[must_use]
pub fn compute_cognitive(cfg: &ControlFlowGraph) -> CognitiveComplexity {
    CognitiveComplexity::from_cfg(cfg)
}
