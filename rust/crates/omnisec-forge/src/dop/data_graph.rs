//! `DataGraph` — directed graph of attacker-reachable data writes / reads.
//!
//! Nodes are concrete memory locations or named program globals. Edges
//! describe the dependency: a [`DataEdgeKind::ReadOf`] edge from
//! `A → B` means "value at A is read by the code that subsequently
//! writes B".
//!
//! The graph is built deterministically from the
//! [`crate::primitive::VulnerabilityPrimitive::notes`] map and from any
//! [`crate::ipdg`-equivalent] pre-computed analyses passed in via the
//! `with_edges` builder. We then do a BFS from the *attacker-controlled
//! sources* to the *witness goal node* to produce a write sequence that
//! mutates program state into the configuration the goal requires.
//!
//! Pure CPU. Pure deterministic. No graph neural nets, no random walks.

use omnisec_graph::EdgeRef;
use omnisec_graph::{DiGraph, NodeIndex};
use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap as FxHashMap;
use std::collections::VecDeque;

/// What a data graph node represents.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum DataNode {
    /// Concrete memory location.
    Memory {
        /// Address.
        addr: u64,
    },
    /// Named global / object field.
    Symbol {
        /// Symbol name.
        name: String,
    },
    /// Synthetic "attacker source" node — represents the
    /// [`crate::primitive::VulnerabilityPrimitive`]'s controlled bytes.
    AttackerSource,
}

/// What a data graph edge means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum DataEdgeKind {
    /// `A → B`: writing `A` enables a subsequent write to `B`.
    EnablesWriteTo,
    /// `A → B`: a read of `A` precedes a write to `B`.
    ReadOf,
    /// `A → B`: aliasing — both refer to the same physical location.
    Alias,
}

/// Directed data graph used for DOP planning.
#[derive(Debug, Default, Clone)]
pub struct DataGraph {
    pub(crate) graph: DiGraph<DataNode, DataEdgeKind>,
    by_node: FxHashMap<DataNode, NodeIndex>,
}

impl DataGraph {
    /// Empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node, idempotently. Returns the existing index when the
    /// node was already present.
    pub fn add_node(&mut self, node: DataNode) -> NodeIndex {
        if let Some(&idx) = self.by_node.get(&node) {
            return idx;
        }
        let idx = self.graph.add_node(node.clone());
        self.by_node.insert(node, idx);
        idx
    }

    /// Add a directed edge.
    pub fn add_edge(&mut self, from: DataNode, to: DataNode, kind: DataEdgeKind) {
        let a = self.add_node(from);
        let b = self.add_node(to);
        self.graph.add_edge(a, b, kind);
    }

    /// `true` if a path exists from `from` to `to`.
    #[must_use]
    pub fn reaches(&self, from: &DataNode, to: &DataNode) -> bool {
        let Some(&start) = self.by_node.get(from) else {
            return false;
        };
        let Some(&goal) = self.by_node.get(to) else {
            return false;
        };
        self.bfs_path(start, goal).is_some()
    }

    /// BFS shortest-path from the attacker source node to `goal`.
    ///
    /// Returns the path as a list of [`DataNode`]s in execution order.
    /// Iteration is BTreeMap-ordered — deterministic.
    #[must_use]
    pub fn plan_writes(&self, goal: &DataNode) -> Option<Vec<DataNode>> {
        let &source = self.by_node.get(&DataNode::AttackerSource)?;
        let &goal_idx = self.by_node.get(goal)?;
        let path = self.bfs_path(source, goal_idx)?;
        Some(path.into_iter().map(|i| self.graph[i].clone()).collect())
    }

    fn bfs_path(&self, source: NodeIndex, goal: NodeIndex) -> Option<Vec<NodeIndex>> {
        let mut queue = VecDeque::new();
        let mut visited: FxHashMap<NodeIndex, Option<NodeIndex>> = FxHashMap::default();
        visited.insert(source, None);
        queue.push_back(source);

        while let Some(cur) = queue.pop_front() {
            if cur == goal {
                let mut path = vec![cur];
                let mut walk = cur;
                while let Some(Some(prev)) = visited.get(&walk).copied() {
                    path.push(prev);
                    walk = prev;
                }
                path.reverse();
                return Some(path);
            }

            // Collect & sort neighbours for determinism.
            let mut nbrs: Vec<NodeIndex> = self.graph.edges(cur).map(|e| e.target()).collect();
            nbrs.sort_unstable_by_key(|n| n.index());
            for n in nbrs {
                if let std::collections::hash_map::Entry::Vacant(e) = visited.entry(n) {
                    e.insert(Some(cur));
                    queue.push_back(n);
                }
            }
        }
        None
    }

    /// Number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DataGraph {
        let mut g = DataGraph::new();
        g.add_edge(
            DataNode::AttackerSource,
            DataNode::Memory { addr: 0x0060_1000 },
            DataEdgeKind::EnablesWriteTo,
        );
        g.add_edge(
            DataNode::Memory { addr: 0x0060_1000 },
            DataNode::Symbol {
                name: "is_admin".into(),
            },
            DataEdgeKind::EnablesWriteTo,
        );
        g
    }

    #[test]
    fn bfs_reaches_through_chain() {
        let g = sample();
        assert!(g.reaches(
            &DataNode::AttackerSource,
            &DataNode::Symbol {
                name: "is_admin".into()
            }
        ));
    }

    #[test]
    fn plan_writes_returns_path() {
        let g = sample();
        let path = g
            .plan_writes(&DataNode::Symbol {
                name: "is_admin".into(),
            })
            .unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(path[0], DataNode::AttackerSource);
    }

    #[test]
    fn plan_writes_is_deterministic() {
        let a = sample().plan_writes(&DataNode::Symbol {
            name: "is_admin".into(),
        });
        let b = sample().plan_writes(&DataNode::Symbol {
            name: "is_admin".into(),
        });
        assert_eq!(a, b);
    }
}
