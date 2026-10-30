//! Call graph data structures.
//!
//! A call graph is a directed multigraph where nodes are functions
//! (identified by entry address + canonical name) and edges represent
//! call relationships (direct, indirect, import, syscall).
//!
//! The graph is **bidirectionally indexed**: `callees(f)` and `callers(g)`
//! are both `O(1)` lookups. This is critical for the inter-procedural
//! taint analysis in `omnisec-pdg`'s Inter-Process Dependence Graph (IPDG)
//! roadmap.

use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap as FxHashMap;

/// Node identifier in the call graph.
pub type CallNodeId = u32;

/// Kind of call edge.
///
/// We distinguish kinds because the taint propagation model differs:
/// direct calls always recurse, indirect calls may need points-to
/// approximation, and imports terminate the trace at the library boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "snake_case")]
pub enum CallKind {
    /// Direct call to a known function address.
    Direct,
    /// Indirect call through register / memory.
    Indirect,
    /// Call into an imported symbol (PLT / IAT entry).
    Import,
    /// `syscall` / `int 0x80` / `svc #0` style transition into the kernel.
    Syscall,
}

/// A node in the call graph (a function).
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct CallNode {
    /// Unique node identifier (assigned by the builder).
    pub id: CallNodeId,
    /// Entry-point virtual address.
    pub address: u64,
    /// Canonical (demangled) symbol name, or a synthetic `sub_<addr>`.
    pub name: String,
    /// Whether this node represents an imported / external symbol.
    pub is_import: bool,
}

/// An edge in the call graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub struct CallEdge {
    /// Caller node id.
    pub from: CallNodeId,
    /// Callee node id.
    pub to: CallNodeId,
    /// Kind of call.
    pub kind: CallKind,
    /// Call-site virtual address (the `CALL`/`BL` instruction).
    pub site: u64,
}

/// Inter-procedural call graph.
///
/// Stores nodes by id, plus dual adjacency lists for fast forward and
/// reverse traversal.
#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct CallGraph {
    nodes: FxHashMap<CallNodeId, CallNode>,
    out_edges: FxHashMap<CallNodeId, Vec<CallEdge>>,
    in_edges: FxHashMap<CallNodeId, Vec<CallEdge>>,
    by_address: FxHashMap<u64, CallNodeId>,
}

impl CallGraph {
    /// Create an empty call graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function node. Idempotent on `node.id`.
    pub fn add_node(&mut self, node: CallNode) {
        let id = node.id;
        let address = node.address;
        self.nodes.insert(id, node);
        self.out_edges.entry(id).or_default();
        self.in_edges.entry(id).or_default();
        self.by_address.insert(address, id);
    }

    /// Add a typed call edge.
    pub fn add_edge(&mut self, edge: CallEdge) {
        self.out_edges.entry(edge.from).or_default().push(edge);
        self.in_edges.entry(edge.to).or_default().push(edge);
    }

    /// Legacy / convenience: add a `Direct` edge with no site address.
    pub fn add_call(&mut self, from: CallNodeId, to: CallNodeId) {
        self.add_edge(CallEdge {
            from,
            to,
            kind: CallKind::Direct,
            site: 0,
        });
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges (sum of out-degrees).
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.out_edges.values().map(Vec::len).sum()
    }

    /// Get a node by id.
    #[must_use]
    pub fn node(&self, id: CallNodeId) -> Option<&CallNode> {
        self.nodes.get(&id)
    }

    /// Get a node by entry address.
    #[must_use]
    pub fn node_by_address(&self, address: u64) -> Option<&CallNode> {
        let id = *self.by_address.get(&address)?;
        self.nodes.get(&id)
    }

    /// Iterate over all nodes.
    pub fn nodes(&self) -> impl Iterator<Item = &CallNode> {
        self.nodes.values()
    }

    /// Iterate over all edges.
    pub fn edges(&self) -> impl Iterator<Item = &CallEdge> {
        self.out_edges.values().flatten()
    }

    /// Outgoing edges from a node.
    #[must_use]
    pub fn outgoing(&self, id: CallNodeId) -> &[CallEdge] {
        self.out_edges.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Incoming edges to a node.
    #[must_use]
    pub fn incoming(&self, id: CallNodeId) -> &[CallEdge] {
        self.in_edges.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Direct callees of a node (just the target ids, no edge metadata).
    #[must_use]
    pub fn callees(&self, id: CallNodeId) -> Vec<CallNodeId> {
        self.outgoing(id).iter().map(|e| e.to).collect()
    }

    /// Direct callers of a node.
    #[must_use]
    pub fn callers(&self, id: CallNodeId) -> Vec<CallNodeId> {
        self.incoming(id).iter().map(|e| e.from).collect()
    }

    /// Compute the transitive closure of callees starting from `root`.
    ///
    /// Useful for the IPDG: given an entry point (e.g. a JNI bridge),
    /// what is the set of all native functions reachable from it?
    #[must_use]
    pub fn reachable_from(&self, root: CallNodeId) -> Vec<CallNodeId> {
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![root];
        let mut out = Vec::new();
        while let Some(n) = stack.pop() {
            if !seen.insert(n) {
                continue;
            }
            out.push(n);
            for e in self.outgoing(n) {
                if !seen.contains(&e.to) {
                    stack.push(e.to);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(id: CallNodeId, addr: u64, name: &str) -> CallNode {
        CallNode {
            id,
            address: addr,
            name: name.into(),
            is_import: false,
        }
    }

    #[test]
    fn add_node_records_address_index() {
        let mut g = CallGraph::new();
        g.add_node(n(1, 0x1000, "main"));
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.node_by_address(0x1000).unwrap().name, "main");
        assert!(g.node_by_address(0xdead).is_none());
    }

    #[test]
    fn edges_are_bidirectionally_indexed() {
        let mut g = CallGraph::new();
        g.add_node(n(1, 0x1000, "main"));
        g.add_node(n(2, 0x2000, "helper"));
        g.add_edge(CallEdge {
            from: 1,
            to: 2,
            kind: CallKind::Direct,
            site: 0x1010,
        });
        assert_eq!(g.callees(1), vec![2]);
        assert_eq!(g.callers(2), vec![1]);
        assert_eq!(g.callees(2), Vec::<CallNodeId>::new());
        assert_eq!(g.edge_count(), 1);
    }

    #[test]
    fn reachable_from_handles_cycles() {
        let mut g = CallGraph::new();
        g.add_node(n(1, 0x1000, "a"));
        g.add_node(n(2, 0x2000, "b"));
        g.add_node(n(3, 0x3000, "c"));
        g.add_call(1, 2);
        g.add_call(2, 3);
        g.add_call(3, 1); // back-edge / recursion
        let mut r = g.reachable_from(1);
        r.sort_unstable();
        assert_eq!(r, vec![1, 2, 3]);
    }
}
