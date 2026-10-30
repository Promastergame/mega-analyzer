//! [`ControlFlowGraph`] — storage + traversal.

use omnisec_collections::IndexMap;
use omnisec_json::{FromJson, ToJson};
use std::collections::{HashMap as FxHashMap, HashSet as FxHashSet};

use crate::block::{BasicBlock, BlockId};

/// Container for one function's basic blocks and the edges between them.
///
/// Blocks live in an [`IndexMap`] keyed by [`BlockId`], so iteration order
/// is the order in which the builder discovered them (= roughly program
/// order). Successor / predecessor maps are sibling structures — *never*
/// modify them by hand: use the public mutators on [`ControlFlowGraph`]
/// itself so the two stay consistent.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct ControlFlowGraph {
    blocks: IndexMap<BlockId, BasicBlock>,
    entry: BlockId,
    successors: FxHashMap<BlockId, Vec<BlockId>>,
    predecessors: FxHashMap<BlockId, Vec<BlockId>>,
    /// Map from instruction address to the block that contains it.
    /// Populated for the *first* instruction of each block; for now we
    /// don't index addresses inside a block.
    addr_to_block: FxHashMap<u64, BlockId>,
}

impl ControlFlowGraph {
    /// Build an empty CFG with no blocks. Reserved for callers — most users
    /// should go through [`crate::build_cfg`].
    #[must_use]
    pub fn empty(entry: BlockId) -> Self {
        Self {
            blocks: IndexMap::new(),
            entry,
            successors: FxHashMap::default(),
            predecessors: FxHashMap::default(),
            addr_to_block: FxHashMap::default(),
        }
    }

    /// Insert (or replace) a basic block.
    pub fn insert_block(&mut self, block: BasicBlock) {
        let id = block.id;
        let start = block.start_address;
        self.blocks.insert(id, block);
        self.successors.entry(id).or_default();
        self.predecessors.entry(id).or_default();
        self.addr_to_block.insert(start, id);
    }

    /// Add a directed edge `from -> to`.
    pub fn add_edge(&mut self, from: BlockId, to: BlockId) {
        let succ = self.successors.entry(from).or_default();
        if !succ.contains(&to) {
            succ.push(to);
        }
        let pred = self.predecessors.entry(to).or_default();
        if !pred.contains(&from) {
            pred.push(from);
        }
    }

    /// Block this CFG starts at.
    #[must_use]
    pub fn entry(&self) -> BlockId {
        self.entry
    }

    /// Look up a block by id.
    #[must_use]
    pub fn block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.get(&id)
    }

    /// Mutable access to a block (e.g. to update its kind after construction).
    pub fn block_mut(&mut self, id: BlockId) -> Option<&mut BasicBlock> {
        self.blocks.get_mut(&id)
    }

    /// Direct outgoing edges of `id`.
    #[must_use]
    pub fn successors(&self, id: BlockId) -> &[BlockId] {
        self.successors.get(&id).map_or(&[], Vec::as_slice)
    }

    /// Direct incoming edges of `id`.
    #[must_use]
    pub fn predecessors(&self, id: BlockId) -> &[BlockId] {
        self.predecessors.get(&id).map_or(&[], Vec::as_slice)
    }

    /// Total number of blocks.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Total number of directed edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.successors.values().map(Vec::len).sum()
    }

    /// Iterate over blocks in insertion order.
    pub fn iter_blocks(&self) -> impl Iterator<Item = &BasicBlock> + '_ {
        self.blocks.values()
    }

    /// Iterate over `(block_id, block)` pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (BlockId, &BasicBlock)> + '_ {
        self.blocks.iter().map(|(&k, v)| (k, v))
    }

    /// Iterate block ids in insertion order.
    pub fn block_ids(&self) -> impl Iterator<Item = BlockId> + '_ {
        self.blocks.keys().copied()
    }

    /// Find the block whose first instruction lives at `addr`.
    #[must_use]
    pub fn block_at_address(&self, addr: u64) -> Option<BlockId> {
        self.addr_to_block.get(&addr).copied()
    }

    /// Compute reverse postorder traversal from the entry. The result is a
    /// `Vec<BlockId>` where each block appears after all of its
    /// predecessors (modulo back edges). Used by dominator construction
    /// and many dataflow analyses.
    #[must_use]
    pub fn reverse_postorder(&self) -> Vec<BlockId> {
        let mut postorder = Vec::with_capacity(self.blocks.len());
        let mut visited = FxHashSet::default();
        self.dfs_postorder(self.entry, &mut visited, &mut postorder);
        postorder.reverse();
        postorder
    }

    /// DFS postorder traversal helper.
    fn dfs_postorder(&self, b: BlockId, visited: &mut FxHashSet<BlockId>, out: &mut Vec<BlockId>) {
        if !visited.insert(b) {
            return;
        }
        for &s in self.successors(b) {
            self.dfs_postorder(s, visited, out);
        }
        out.push(b);
    }

    /// Set of blocks reachable from the entry. Useful for dropping
    /// dead / unreachable code before further analysis.
    #[must_use]
    pub fn reachable_from_entry(&self) -> FxHashSet<BlockId> {
        let mut visited = FxHashSet::default();
        self.dfs_collect_reachable(self.entry, &mut visited);
        visited
    }

    fn dfs_collect_reachable(&self, b: BlockId, visited: &mut FxHashSet<BlockId>) {
        if !visited.insert(b) {
            return;
        }
        for &s in self.successors(b) {
            self.dfs_collect_reachable(s, visited);
        }
    }

    /// Create a new CFG with all edges reversed.
    #[must_use]
    pub fn reverse(&self) -> Self {
        let mut rev = Self::empty(self.entry);
        for block in self.blocks.values() {
            rev.insert_block(block.clone());
        }
        for (&from, succs) in &self.successors {
            for &to in succs {
                rev.add_edge(to, from);
            }
        }
        rev
    }

    /// Set the entry block ID.
    pub fn set_entry(&mut self, entry: BlockId) {
        self.entry = entry;
    }

    /// Add a virtual entry node that connects to the given targets.
    /// Useful for computing post-dominators when there are multiple exits.
    pub fn add_virtual_entry(&mut self, id: BlockId, targets: &[BlockId]) {
        self.insert_block(BasicBlock {
            id,
            start_address: 0,
            end_address: 0,
            instructions: vec![],
            kind: crate::block::BlockKind::Normal,
        });
        for &target in targets {
            self.add_edge(id, target);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::block::{BasicBlock, BlockKind};

    use super::*;

    fn make_block(id: BlockId, addr: u64) -> BasicBlock {
        BasicBlock {
            id,
            start_address: addr,
            end_address: addr,
            instructions: vec![],
            kind: BlockKind::Normal,
        }
    }

    #[test]
    fn rpo_on_diamond() {
        // 0 -> 1 -> 3
        // 0 -> 2 -> 3
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0, 0x100));
        cfg.insert_block(make_block(1, 0x110));
        cfg.insert_block(make_block(2, 0x120));
        cfg.insert_block(make_block(3, 0x130));
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 2);
        cfg.add_edge(1, 3);
        cfg.add_edge(2, 3);

        let rpo = cfg.reverse_postorder();
        assert_eq!(rpo[0], 0);
        assert_eq!(*rpo.last().unwrap(), 3);
        // 1 and 2 must come strictly between 0 and 3.
        let p1 = rpo.iter().position(|&x| x == 1).unwrap();
        let p2 = rpo.iter().position(|&x| x == 2).unwrap();
        assert!(p1 > 0 && p1 < 3);
        assert!(p2 > 0 && p2 < 3);
    }

    #[test]
    fn reachable_skips_dead_block() {
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0, 0x100));
        cfg.insert_block(make_block(1, 0x110));
        cfg.insert_block(make_block(2, 0x120)); // dead
        cfg.add_edge(0, 1);
        let reach = cfg.reachable_from_entry();
        assert!(reach.contains(&0));
        assert!(reach.contains(&1));
        assert!(!reach.contains(&2));
    }

    #[test]
    fn duplicate_edge_is_idempotent() {
        let mut cfg = ControlFlowGraph::empty(0);
        cfg.insert_block(make_block(0, 0));
        cfg.insert_block(make_block(1, 0));
        cfg.add_edge(0, 1);
        cfg.add_edge(0, 1);
        assert_eq!(cfg.successors(0), &[1]);
        assert_eq!(cfg.predecessors(1), &[0]);
        assert_eq!(cfg.edge_count(), 1);
    }
}
