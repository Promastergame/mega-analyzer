//! Dominator tree and dominance frontier computation.
//!
//! We implement the classic Cooper-Harvey-Kennedy iterative algorithm for
//! dominators, and then compute dominance frontiers (needed for SSA phi
//! placement).

use std::collections::{HashMap as FxHashMap, HashSet as FxHashSet};

use crate::block::BlockId;
use crate::graph::ControlFlowGraph;

/// A node `d` *dominates* node `n` if every path from the entry to `n`
/// passes through `d`. The entry dominates every node (including itself).
///
/// A node `d` *strictly dominates* `n` if `d` dominates `n` and `d ≠ n`.
///
/// A node `d` is the *immediate dominator* of `n` (written `idom(n)`) if:
///   (a) `d` strictly dominates `n`, and
///   (b) no node strictly between `d` and `n` dominates `n`.
///
/// The immediate dominator relation forms a tree rooted at the entry.
/// Dominator tree for a CFG.
#[derive(Debug, Clone)]
pub struct DominatorTree {
    /// For each node, its immediate dominator. The entry maps to `None`.
    idom: FxHashMap<BlockId, Option<BlockId>>,
    /// For each node, the set of nodes it dominates (including itself).
    doms: FxHashMap<BlockId, FxHashSet<BlockId>>,
}

impl DominatorTree {
    /// Compute the dominator tree for `cfg` using the Cooper-Harvey-Kennedy
    /// iterative algorithm.
    #[must_use]
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let entry = cfg.entry();
        let all_nodes: FxHashSet<BlockId> = cfg.block_ids().collect();

        // Initialize: doms[entry] = {entry}, doms[other] = all_nodes.
        let mut doms: FxHashMap<BlockId, FxHashSet<BlockId>> = FxHashMap::default();
        for &n in &all_nodes {
            if n == entry {
                doms.insert(n, FxHashSet::from_iter([entry]));
            } else {
                doms.insert(n, all_nodes.clone());
            }
        }

        let rpo = cfg.reverse_postorder();
        let mut changed = true;
        while changed {
            changed = false;
            // Process nodes in reverse postorder, skipping entry.
            for &n in rpo.iter().skip(1) {
                let preds = cfg.predecessors(n);
                if preds.is_empty() {
                    // Unreachable node (shouldn't happen in a well-formed CFG).
                    continue;
                }

                // doms[n] = {n} ∩ (∩_{p in preds(n)} doms[p])
                let mut new_dom = FxHashSet::from_iter([n]);
                for (i, &p) in preds.iter().enumerate() {
                    if i == 0 {
                        new_dom.extend(doms[&p].iter().copied());
                    } else {
                        new_dom = new_dom.intersection(&doms[&p]).copied().collect();
                    }
                }

                if new_dom != doms[&n] {
                    doms.insert(n, new_dom);
                    changed = true;
                }
            }
        }

        // Compute immediate dominators.
        let mut idom: FxHashMap<BlockId, Option<BlockId>> = FxHashMap::default();
        idom.insert(entry, None);
        for n in cfg.block_ids().collect::<Vec<_>>() {
            if n == entry {
                continue;
            }
            let doms_n = &doms[&n];
            // idom(n) is the unique d in doms(n) \ {n} such that
            // there is no other d' in doms(n) \ {n} with d' in doms(d).
            let mut immediate: Option<BlockId> = None;
            for &d in doms_n.iter().filter(|&&x| x != n) {
                let mut is_idom = true;
                for &d2 in doms_n.iter().filter(|&&x| x != n) {
                    if d2 != d && doms[&d2].contains(&d) {
                        is_idom = false;
                        break;
                    }
                }
                if is_idom {
                    immediate = Some(d);
                    break;
                }
            }
            idom.insert(n, immediate);
        }

        Self { idom, doms }
    }

    /// Does `d` dominate `n`?
    #[must_use]
    pub fn dominates(&self, d: BlockId, n: BlockId) -> bool {
        self.doms.get(&n).is_some_and(|set| set.contains(&d))
    }

    /// Does `d` strictly dominate `n`?
    #[must_use]
    pub fn strictly_dominates(&self, d: BlockId, n: BlockId) -> bool {
        d != n && self.dominates(d, n)
    }

    /// Immediate dominator of `n`. Returns `None` for the entry.
    #[must_use]
    pub fn immediate_dominator(&self, n: BlockId) -> Option<BlockId> {
        self.idom.get(&n).copied().flatten()
    }

    /// Children of `n` in the dominator tree (i.e. nodes for which `n` is
    /// the immediate dominator).
    #[must_use]
    pub fn children(&self, n: BlockId) -> Vec<BlockId> {
        self.idom
            .iter()
            .filter(|&(_, &opt_idom)| opt_idom == Some(n))
            .map(|(&child, _)| child)
            .collect()
    }

    /// All nodes dominated by `n` (including `n` itself).
    #[must_use]
    pub fn dominated_by(&self, n: BlockId) -> FxHashSet<BlockId> {
        self.doms
            .iter()
            .filter_map(|(&node, dominators)| dominators.contains(&n).then_some(node))
            .collect()
    }
}

/// Post-dominator tree for a CFG.
///
/// A node `p` *post-dominates* `n` if every path from `n` to the exit passes
/// through `p`.
#[derive(Debug, Clone)]
pub struct PostDominatorTree {
    /// For each node, its immediate post-dominator.
    ipdom: FxHashMap<BlockId, Option<BlockId>>,
    /// For each node, the set of nodes it post-dominates.
    pdoms: FxHashMap<BlockId, FxHashSet<BlockId>>,
}

impl PostDominatorTree {
    /// Compute the post-dominator tree for `cfg`.
    #[must_use]
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        // To compute post-dominators, we reverse the CFG and compute dominators.
        // We need a single exit node.
        let mut reversed_cfg = cfg.reverse();

        // Find all exit nodes (nodes with no successors in the original CFG).
        let exits: Vec<BlockId> = cfg
            .block_ids()
            .filter(|&id| cfg.successors(id).is_empty())
            .collect();

        // If there are multiple exits, add a virtual exit node.
        let virtual_exit = if exits.len() > 1 {
            let id = u32::MAX; // Use a special ID for the virtual exit
            reversed_cfg.add_virtual_entry(id, &exits);
            Some(id)
        } else {
            exits.first().copied()
        };

        if let Some(exit_node) = virtual_exit {
            reversed_cfg.set_entry(exit_node);
            let dt = DominatorTree::compute(&reversed_cfg);

            Self {
                ipdom: dt.idom,
                pdoms: dt.doms,
            }
        } else {
            Self {
                ipdom: FxHashMap::default(),
                pdoms: FxHashMap::default(),
            }
        }
    }

    /// Does `p` post-dominate `n`?
    #[must_use]
    pub fn post_dominates(&self, p: BlockId, n: BlockId) -> bool {
        self.pdoms.get(&n).is_some_and(|set| set.contains(&p))
    }

    /// Does `p` strictly post-dominate `n`?
    #[must_use]
    pub fn strictly_post_dominates(&self, p: BlockId, n: BlockId) -> bool {
        p != n && self.post_dominates(p, n)
    }

    /// Immediate post-dominator of `n`.
    #[must_use]
    pub fn immediate_post_dominator(&self, n: BlockId) -> Option<BlockId> {
        self.ipdom.get(&n).copied().flatten()
    }
}

/// Dominance frontier: the set of nodes where a definition of a variable
/// in `n` would need a phi node to dominate all uses.
///
/// Formally, DF[n] = {y | ∃x: n dominates x but not strictly, and edge
/// x->y exists}. Intuitively: the first nodes where control flow leaves
/// the region dominated by `n`.
#[derive(Debug, Clone)]
pub struct DominanceFrontiers {
    /// For each node, its dominance frontier.
    frontiers: FxHashMap<BlockId, FxHashSet<BlockId>>,
}

impl DominanceFrontiers {
    /// Compute dominance frontiers from a dominator tree and CFG.
    #[must_use]
    pub fn compute(cfg: &ControlFlowGraph, domtree: &DominatorTree) -> Self {
        let mut df: FxHashMap<BlockId, FxHashSet<BlockId>> = FxHashMap::default();

        for n in cfg.block_ids().collect::<Vec<_>>() {
            df.insert(n, FxHashSet::default());
        }

        for b in cfg.block_ids().collect::<Vec<_>>() {
            if cfg.predecessors(b).len() < 2 {
                continue;
            }

            let stop = domtree.immediate_dominator(b);
            for &predecessor in cfg.predecessors(b) {
                let mut runner = Some(predecessor);
                while runner != stop {
                    let Some(runner_id) = runner else {
                        break;
                    };
                    df.get_mut(&runner_id).unwrap().insert(b);
                    runner = domtree.immediate_dominator(runner_id);
                }
            }
        }

        Self { frontiers: df }
    }

    /// Dominance frontier of `n`.
    #[must_use]
    pub fn frontier(&self, n: BlockId) -> FxHashSet<BlockId> {
        self.frontiers.get(&n).cloned().unwrap_or_default()
    }

    /// Iteration over all (node, frontier) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (BlockId, &FxHashSet<BlockId>)> + '_ {
        self.frontiers.iter().map(|(&n, f)| (n, f))
    }
}

#[cfg(test)]
mod tests {
    use crate::block::{BasicBlock, BlockKind};

    use super::*;

    fn make_block(id: BlockId) -> BasicBlock {
        BasicBlock {
            id,
            start_address: id as u64 * 0x10,
            end_address: id as u64 * 0x10,
            instructions: vec![],
            kind: BlockKind::Normal,
        }
    }

    #[test]
    fn entry_dominates_all() {
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0));
        cfg.insert_block(make_block(1));
        cfg.insert_block(make_block(2));
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);

        let dt = DominatorTree::compute(&cfg);
        assert!(dt.dominates(0, 0));
        assert!(dt.dominates(0, 1));
        assert!(dt.dominates(0, 2));
        assert!(dt.strictly_dominates(0, 1));
        assert!(dt.strictly_dominates(0, 2));
    }

    #[test]
    fn immediate_dominators_in_chain() {
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0));
        cfg.insert_block(make_block(1));
        cfg.insert_block(make_block(2));
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);

        let dt = DominatorTree::compute(&cfg);
        assert_eq!(dt.immediate_dominator(0), None);
        assert_eq!(dt.immediate_dominator(1), Some(0));
        assert_eq!(dt.immediate_dominator(2), Some(1));
    }

    #[test]
    fn diamond_immediate_dominators() {
        //   0
        //  / \
        // 1   2
        //  \ /
        //   3
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0));
        cfg.insert_block(make_block(1));
        cfg.insert_block(make_block(2));
        cfg.insert_block(make_block(3));
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 3);

        let dt = DominatorTree::compute(&cfg);
        assert_eq!(dt.immediate_dominator(0), None);
        assert_eq!(dt.immediate_dominator(1), Some(0));
        assert_eq!(dt.immediate_dominator(2), Some(0));
        assert_eq!(dt.immediate_dominator(3), Some(0));
    }

    #[test]
    fn dominance_frontier_in_diamond() {
        //   0
        //  / \
        // 1   2
        //  \ /
        //   3
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0));
        cfg.insert_block(make_block(1));
        cfg.insert_block(make_block(2));
        cfg.insert_block(make_block(3));
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 3);

        let dt = DominatorTree::compute(&cfg);
        let df = DominanceFrontiers::compute(&cfg, &dt);

        // DF[1] should contain 3 (edge 1->3, and idom(3)=0 != 1).
        assert!(df.frontier(1).contains(&3));
        // DF[2] should contain 3.
        assert!(df.frontier(2).contains(&3));
        assert!(df.frontier(0).is_empty());
    }

    #[test]
    fn children_in_dominator_tree() {
        //   0
        //  / \
        // 1   2
        //  \ /
        //   3
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0));
        cfg.insert_block(make_block(1));
        cfg.insert_block(make_block(2));
        cfg.insert_block(make_block(3));
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 3);

        let dt = DominatorTree::compute(&cfg);
        let children_0 = dt.children(0);
        assert!(children_0.contains(&1));
        assert!(children_0.contains(&2));
        // In a diamond, the join node (3) is also a child of the entry (0)
        // because the entry is the immediate dominator of all three other nodes.
        assert!(children_0.contains(&3));
    }

    #[test]
    fn dominated_by_returns_dominator_subtree() {
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0));
        cfg.insert_block(make_block(1));
        cfg.insert_block(make_block(2));
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);

        let dt = DominatorTree::compute(&cfg);
        let dominated = dt.dominated_by(1);

        assert!(!dominated.contains(&0));
        assert!(dominated.contains(&1));
        assert!(dominated.contains(&2));
    }
}
