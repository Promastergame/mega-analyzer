//! Loop detection: back edges, natural loops, and irreducibility.

use std::collections::{HashMap as FxHashMap, HashSet as FxHashSet};

use crate::block::BlockId;
use crate::dominators::DominatorTree;
use crate::graph::ControlFlowGraph;

/// A natural loop identified by its back edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaturalLoop {
    /// The header of the loop (the target of the back edge).
    pub header: BlockId,
    /// The set of blocks in the loop body (including the header).
    pub body: FxHashSet<BlockId>,
    /// The back edge that defines this loop (source -> header).
    pub back_edge: (BlockId, BlockId),
}

/// Kind of loop structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopKind {
    /// Reducible loop (has a natural loop structure).
    Reducible,
    /// Irreducible loop (multiple entry points, no single header).
    Irreducible,
}

/// Loop information for a CFG.
#[derive(Debug, Clone)]
pub struct LoopInfo {
    /// All natural loops in the CFG.
    pub loops: Vec<NaturalLoop>,
    /// Whether the CFG contains irreducible loops.
    pub has_irreducible: bool,
}

/// Detect all loops in a CFG.
#[must_use]
pub fn detect_loops(cfg: &ControlFlowGraph, domtree: &DominatorTree) -> LoopInfo {
    LoopInfo::detect(cfg, domtree)
}

impl LoopInfo {
    /// Detect all loops in the CFG.
    #[must_use]
    pub fn detect(cfg: &ControlFlowGraph, domtree: &DominatorTree) -> Self {
        // Step 1: find all back edges (edges where target dominates source).
        let back_edges = find_back_edges(cfg, domtree);

        // Step 2: for each back edge, compute the natural loop.
        let mut natural_loops: Vec<NaturalLoop> = Vec::new();
        for (src, dst) in back_edges {
            let loop_body = compute_loop_body(cfg, dst, src);
            natural_loops.push(NaturalLoop {
                header: dst,
                body: loop_body,
                back_edge: (src, dst),
            });
        }

        // Step 3: detect irreducible loops.
        // A CFG is irreducible if there exists a cycle without a single entry
        // header. We use a simple heuristic: if there are multiple back edges
        // to the same header, it might indicate irreducibility.
        let has_irreducible = detect_irreducibility(cfg, &natural_loops);

        Self {
            loops: natural_loops,
            has_irreducible,
        }
    }

    /// Get all loops that contain a given block.
    #[must_use]
    pub fn loops_containing(&self, block: BlockId) -> Vec<&NaturalLoop> {
        self.loops
            .iter()
            .filter(|l| l.body.contains(&block))
            .collect()
    }

    /// Get the innermost loop containing a block (if any).
    #[must_use]
    pub fn innermost_loop_containing(&self, block: BlockId) -> Option<&NaturalLoop> {
        let containing = self.loops_containing(block);
        // The innermost loop is the one with the smallest body.
        containing.into_iter().min_by_key(|l| l.body.len())
    }
}

/// Find all back edges in the CFG.
///
/// A back edge is an edge `n -> m` where `m` dominates `n`.
fn find_back_edges(cfg: &ControlFlowGraph, domtree: &DominatorTree) -> Vec<(BlockId, BlockId)> {
    let mut back_edges = Vec::new();
    for src in cfg.block_ids().collect::<Vec<_>>() {
        for &dst in cfg.successors(src) {
            if domtree.dominates(dst, src) {
                back_edges.push((src, dst));
            }
        }
    }
    back_edges
}

/// Compute the body of a natural loop given its back edge.
///
/// The loop body consists of all nodes that can reach the back edge source
/// without passing through the loop header.
fn compute_loop_body(
    cfg: &ControlFlowGraph,
    header: BlockId,
    back_edge_src: BlockId,
) -> FxHashSet<BlockId> {
    let mut body = FxHashSet::new();
    body.insert(header);

    // Perform a backward traversal from back_edge_src, stopping when we
    // reach the header.
    let mut worklist = vec![back_edge_src];
    let mut visited = FxHashSet::new();

    while let Some(n) = worklist.pop() {
        if !visited.insert(n) {
            continue;
        }
        if n == header {
            continue;
        }
        body.insert(n);
        for &pred in cfg.predecessors(n) {
            if !visited.contains(&pred) && pred != header {
                worklist.push(pred);
            }
        }
    }

    body
}

/// Detect whether the CFG contains irreducible loops.
///
/// We use a simple heuristic: if there are multiple back edges to the same
/// header, it might indicate irreducibility (though this is not always true).
/// A proper irreducibility test requires more sophisticated analysis.
fn detect_irreducibility(_cfg: &ControlFlowGraph, loops: &[NaturalLoop]) -> bool {
    // Count back edges per header.
    let mut back_edges_per_header: FxHashMap<BlockId, usize> = FxHashMap::new();
    for loop_ in loops {
        *back_edges_per_header.entry(loop_.header).or_insert(0) += 1;
    }

    // If any header has multiple back edges, it might be irreducible.
    // This is a conservative heuristic - it may flag some reducible loops.
    back_edges_per_header.values().any(|&count| count > 1)
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
    fn simple_while_loop() {
        // 0 -> 1 -> 2 (back edge 2->1)
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0));
        cfg.insert_block(make_block(1));
        cfg.insert_block(make_block(2));
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(2, 1); // back edge

        let dt = DominatorTree::compute(&cfg);
        let loop_info = LoopInfo::detect(&cfg, &dt);

        assert!(!loop_info.has_irreducible);
        assert_eq!(loop_info.loops.len(), 1);
        let loop_ = &loop_info.loops[0];
        assert_eq!(loop_.header, 1);
        assert!(loop_.body.contains(&1));
        assert!(loop_.body.contains(&2));
        assert!(!loop_.body.contains(&0));
    }

    #[test]
    fn nested_loops() {
        // 0 -> 1 -> 2 -> 3 (back edge 3->2)
        //           \-> 4 -> 5 (back edge 5->1)
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0));
        cfg.insert_block(make_block(1));
        cfg.insert_block(make_block(2));
        cfg.insert_block(make_block(3));
        cfg.insert_block(make_block(4));
        cfg.insert_block(make_block(5));
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);
        cfg.add_edge(1, 4);
        cfg.add_edge(2, 3);
        cfg.add_edge(3, 2); // inner loop back edge
        cfg.add_edge(4, 5);
        cfg.add_edge(5, 1); // outer loop back edge

        let dt = DominatorTree::compute(&cfg);
        let loop_info = LoopInfo::detect(&cfg, &dt);

        assert_eq!(loop_info.loops.len(), 2);
        assert!(!loop_info.has_irreducible);
    }

    #[test]
    fn no_loops_in_straight_line() {
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0));
        cfg.insert_block(make_block(1));
        cfg.insert_block(make_block(2));
        cfg.add_edge(0, 1);
        cfg.add_edge(1, 2);

        let dt = DominatorTree::compute(&cfg);
        let loop_info = LoopInfo::detect(&cfg, &dt);

        assert!(loop_info.loops.is_empty());
        assert!(!loop_info.has_irreducible);
    }
}
