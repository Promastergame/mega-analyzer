//! DOP-based CFI bypass planner.
//!
//! Consumes a [`super::DataGraph`] and a target [`DataNode`] and returns
//! a write sequence that moves program state into the desired
//! configuration without touching the control-flow graph.
//!
//! When no path exists in the graph, the planner returns `None` so the
//! [`crate::compiler::ForgeEngine`] can decide to fall back to a
//! conventional ROP/JOP chain.

use super::data_graph::{DataGraph, DataNode};

/// Output of [`DopCfiPlanner::plan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DopPlan {
    /// Ordered list of `DataNode` writes leading from
    /// [`DataNode::AttackerSource`] to the target.
    pub writes: Vec<DataNode>,
}

/// Stateless planner type — it just borrows the graph and computes a path.
#[derive(Debug, Default, Clone, Copy)]
pub struct DopCfiPlanner;

impl DopCfiPlanner {
    /// New planner.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Plan a write sequence reaching `target`. Returns `None` when no
    /// path exists from the attacker source to `target`.
    pub fn plan(&self, graph: &DataGraph, target: &DataNode) -> Option<DopPlan> {
        let writes = graph.plan_writes(target)?;
        Some(DopPlan { writes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dop::data_graph::DataEdgeKind;

    #[test]
    fn plan_returns_none_on_disconnected_target() {
        let g = DataGraph::new();
        let plan = DopCfiPlanner::new().plan(
            &g,
            &DataNode::Symbol {
                name: "missing".into(),
            },
        );
        assert!(plan.is_none());
    }

    #[test]
    fn plan_returns_full_path() {
        let mut g = DataGraph::new();
        g.add_edge(
            DataNode::AttackerSource,
            DataNode::Memory { addr: 0x600 },
            DataEdgeKind::EnablesWriteTo,
        );
        g.add_edge(
            DataNode::Memory { addr: 0x600 },
            DataNode::Symbol { name: "uid".into() },
            DataEdgeKind::EnablesWriteTo,
        );
        let plan = DopCfiPlanner::new()
            .plan(&g, &DataNode::Symbol { name: "uid".into() })
            .unwrap();
        assert_eq!(plan.writes.len(), 3);
    }
}
