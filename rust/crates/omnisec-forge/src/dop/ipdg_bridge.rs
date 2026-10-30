//! Build a [`DataGraph`] from an [`Ipdg`](omnisec_ipdg::Ipdg).
//!
//! The bridge translates IPDG nodes + edges into DOP-friendly
//! [`DataNode`]s and [`DataEdgeKind`]s, then plants an explicit
//! `AttackerSource → <first-source-node>` edge so the DOP planner's
//! BFS has a starting point.
//!
//! ## Mapping rules
//!
//! | IPDG concept          | DOP representation                            |
//! |-----------------------|-----------------------------------------------|
//! | `IpdgNode` with address | [`DataNode::Memory`] keyed by that address    |
//! | `IpdgNode` w/o address | [`DataNode::Symbol`] keyed by function name   |
//! | `is_source = true`    | Inbound edge from [`DataNode::AttackerSource`] |
//! | `EdgeKind::Data`      | [`DataEdgeKind::EnablesWriteTo`]              |
//! | `EdgeKind::HeapAlias` | [`DataEdgeKind::Alias`]                       |
//! | `EdgeKind::Control`   | skipped (DOP is explicitly non-control-flow)  |
//! | `EdgeKind::CrossBoundary` | [`DataEdgeKind::EnablesWriteTo`]           |
//!
//! The translation is lossless for data and aliasing concerns and lossy
//! for control flow (by design — DOP discards control-flow reasoning).

use omnisec_graph::EdgeRef;
use omnisec_ipdg::{EdgeKind, Ipdg};

use super::data_graph::{DataEdgeKind, DataGraph, DataNode};

/// Translate an [`Ipdg`] into a DOP-friendly [`DataGraph`].
///
/// Every IPDG node becomes a `DataNode`; every data / cross-boundary /
/// heap-alias edge becomes the corresponding `DataEdgeKind`. Source
/// nodes are wired to a synthetic [`DataNode::AttackerSource`] so the
/// DOP planner's BFS from the attacker source always has a starting
/// point.
#[must_use]
pub fn from_ipdg(ipdg: &Ipdg) -> DataGraph {
    let mut out = DataGraph::new();

    // Map IPDG node index → DataNode for edge wiring below.
    let as_data = |node: &omnisec_ipdg::IpdgNode| -> DataNode {
        match node.address {
            Some(addr) => DataNode::Memory { addr },
            None => DataNode::Symbol {
                name: format!("{}::{}", node.component.0, node.function),
            },
        }
    };

    // First pass: add every node and wire attacker-source edges.
    for node_idx in ipdg.graph.node_indices() {
        let node = &ipdg.graph[node_idx];
        let dnode = as_data(node);
        out.add_node(dnode.clone());
        if node.is_source {
            out.add_edge(
                DataNode::AttackerSource,
                dnode,
                DataEdgeKind::EnablesWriteTo,
            );
        }
    }

    // Second pass: translate edges.
    for edge in ipdg.graph.edge_references() {
        let src = &ipdg.graph[edge.source()];
        let dst = &ipdg.graph[edge.target()];
        let kind = match edge.weight().kind {
            EdgeKind::Data | EdgeKind::CrossBoundary => DataEdgeKind::EnablesWriteTo,
            EdgeKind::HeapAlias => DataEdgeKind::Alias,
            // Control / Call / Return are intentionally discarded: DOP
            // is a non-control-flow realisation strategy.
            EdgeKind::Control | EdgeKind::Call | EdgeKind::Return => continue,
        };
        out.add_edge(as_data(src), as_data(dst), kind);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnisec_ipdg::{
        Component, ComponentId, ComponentKind, IpdgBuilder, IpdgEdge, IpdgNode, NodeType,
    };

    fn sample_ipdg() -> Ipdg {
        let mut builder = IpdgBuilder::new();
        let cid = ComponentId(1);
        builder.add_component(Component::new(
            cid,
            ComponentKind::NativeExecutable,
            "app".into(),
        ));

        let source = IpdgNode {
            component: cid,
            function: "read_input".into(),
            address: Some(0x4000),
            source_location: None,
            is_source: true,
            is_sink: false,
            node_type: NodeType::Regular,
        };
        let intermediate = IpdgNode {
            component: cid,
            function: "copy_buffer".into(),
            address: Some(0x5000),
            source_location: None,
            is_source: false,
            is_sink: false,
            node_type: NodeType::Regular,
        };
        let sink = IpdgNode {
            component: cid,
            function: "is_admin".into(),
            address: Some(0x6000),
            source_location: None,
            is_source: false,
            is_sink: true,
            node_type: NodeType::Sensitive,
        };

        let n_src = builder.add_node(source);
        let n_mid = builder.add_node(intermediate);
        let n_sink = builder.add_node(sink);

        // Data flow from source → intermediate → sink.
        builder.add_edge(n_src, n_mid, data_edge());
        builder.add_edge(n_mid, n_sink, data_edge());
        // Control edge (should be dropped by the bridge).
        builder.add_edge(n_src, n_sink, control_edge());

        builder.build()
    }

    fn data_edge() -> IpdgEdge {
        IpdgEdge {
            kind: EdgeKind::Data,
            boundary: None,
            is_tainted: true,
            confidence: 1.0,
        }
    }

    fn control_edge() -> IpdgEdge {
        IpdgEdge {
            kind: EdgeKind::Control,
            boundary: None,
            is_tainted: false,
            confidence: 1.0,
        }
    }

    #[test]
    fn bridge_produces_reachable_target() {
        let ipdg = sample_ipdg();
        let graph = from_ipdg(&ipdg);
        assert!(graph.reaches(
            &DataNode::AttackerSource,
            &DataNode::Memory { addr: 0x6000 },
        ));
    }

    #[test]
    fn bridge_drops_control_edges() {
        let ipdg = sample_ipdg();
        let graph = from_ipdg(&ipdg);
        // 2 data edges + 1 AttackerSource → source wire = 3. The control
        // edge must not contribute.
        assert_eq!(graph.edge_count(), 3);
    }

    #[test]
    fn bridge_is_deterministic() {
        let a = from_ipdg(&sample_ipdg());
        let b = from_ipdg(&sample_ipdg());
        let path_a = a.plan_writes(&DataNode::Memory { addr: 0x6000 });
        let path_b = b.plan_writes(&DataNode::Memory { addr: 0x6000 });
        assert_eq!(path_a, path_b);
    }

    #[test]
    fn empty_ipdg_yields_empty_datagraph() {
        let ipdg = IpdgBuilder::new().build();
        let graph = from_ipdg(&ipdg);
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }
}
