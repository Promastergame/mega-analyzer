//! IPDG graph structure and builder.

use omnisec_graph::EdgeRef;
use omnisec_graph::{DiGraph, NodeIndex};
use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap as FxHashMap;
use std::fmt;

use crate::{Boundary, BoundaryEdge, Component, ComponentId, IpdgError, Result};

/// Node in the IPDG — represents a location within a component.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct IpdgNode {
    /// Component this node belongs to
    pub component: ComponentId,

    /// Function or method name
    pub function: String,

    /// Address or offset within the function
    pub address: Option<u64>,

    /// Source code location (if available)
    pub source_location: Option<String>,

    /// Whether this node is a source of taint
    pub is_source: bool,

    /// Whether this node is a sink for taint
    pub is_sink: bool,

    /// Node type
    pub node_type: NodeType,
}

/// Type of node in the IPDG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
pub enum NodeType {
    /// Entry point of a component
    Entry,

    /// Exit point of a component
    Exit,

    /// Boundary crossing point
    Boundary,

    /// Regular instruction or statement
    Regular,

    /// Allocation site
    Allocation,

    /// Free/deallocation site
    Free,

    /// Sensitive operation (crypto, auth, etc.)
    Sensitive,
}

/// Edge in the IPDG.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct IpdgEdge {
    /// Edge type
    pub kind: EdgeKind,

    /// Optional boundary information (for cross-component edges)
    pub boundary: Option<BoundaryEdge>,

    /// Whether taint flows through this edge
    pub is_tainted: bool,

    /// Confidence score
    pub confidence: f32,
}

/// Type of edge in the IPDG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
pub enum EdgeKind {
    /// Control flow edge (within component)
    Control,

    /// Data dependency edge (within component)
    Data,

    /// Call edge (within component)
    Call,

    /// Return edge (within component)
    Return,

    /// Cross-boundary edge (between components)
    CrossBoundary,

    /// Heap alias edge
    HeapAlias,
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control => write!(f, "Control"),
            Self::Data => write!(f, "Data"),
            Self::Call => write!(f, "Call"),
            Self::Return => write!(f, "Return"),
            Self::CrossBoundary => write!(f, "CrossBoundary"),
            Self::HeapAlias => write!(f, "HeapAlias"),
        }
    }
}

/// Inter-Process Dependency Graph.
///
/// A unified graph that combines multiple component-level PDGs with
/// cross-boundary edges representing inter-process communication.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Ipdg {
    /// The underlying directed graph
    pub graph: DiGraph<IpdgNode, IpdgEdge>,

    /// Components in the graph
    components: FxHashMap<ComponentId, Component>,

    /// Boundaries between components
    boundaries: Vec<Boundary>,

    /// Mapping from component ID to node indices
    component_nodes: FxHashMap<ComponentId, Vec<NodeIndex>>,

    /// Entry nodes for each component
    entry_nodes: FxHashMap<ComponentId, Vec<NodeIndex>>,

    /// Exit nodes for each component
    exit_nodes: FxHashMap<ComponentId, Vec<NodeIndex>>,
}

impl Ipdg {
    /// Create a new empty IPDG.
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            components: FxHashMap::default(),
            boundaries: Vec::new(),
            component_nodes: FxHashMap::default(),
            entry_nodes: FxHashMap::default(),
            exit_nodes: FxHashMap::default(),
        }
    }

    /// Add a component to the graph.
    pub fn add_component(&mut self, component: Component) {
        let id = component.id;
        self.components.insert(id, component);
        self.component_nodes.entry(id).or_default();
        self.entry_nodes.entry(id).or_default();
        self.exit_nodes.entry(id).or_default();
    }

    /// Add a boundary between components.
    pub fn add_boundary(&mut self, boundary: Boundary) -> Result<()> {
        // Verify that both components exist
        if !self.components.contains_key(&boundary.source) {
            return Err(IpdgError::ComponentNotFound(format!("{}", boundary.source)));
        }
        if !self.components.contains_key(&boundary.dest) {
            return Err(IpdgError::ComponentNotFound(format!("{}", boundary.dest)));
        }

        self.boundaries.push(boundary);
        Ok(())
    }

    /// Add a node to the graph.
    pub fn add_node(&mut self, node: IpdgNode) -> NodeIndex {
        let component_id = node.component;
        let node_type = node.node_type;
        let idx = self.graph.add_node(node);

        // Track node by component
        self.component_nodes
            .entry(component_id)
            .or_default()
            .push(idx);

        // Track entry/exit nodes
        match node_type {
            NodeType::Entry => {
                self.entry_nodes.entry(component_id).or_default().push(idx);
            }
            NodeType::Exit => {
                self.exit_nodes.entry(component_id).or_default().push(idx);
            }
            _ => {}
        }

        idx
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: IpdgEdge) {
        self.graph.add_edge(from, to, edge);
    }

    /// Get a component by ID.
    pub fn get_component(&self, id: ComponentId) -> Option<&Component> {
        self.components.get(&id)
    }

    /// Get all components.
    pub fn components(&self) -> impl Iterator<Item = &Component> {
        self.components.values()
    }

    /// Get all boundaries.
    pub fn boundaries(&self) -> &[Boundary] {
        &self.boundaries
    }

    /// Get nodes for a specific component.
    pub fn component_nodes(&self, id: ComponentId) -> Option<&[NodeIndex]> {
        self.component_nodes.get(&id).map(Vec::as_slice)
    }

    /// Get entry nodes for a component.
    pub fn entry_nodes(&self, id: ComponentId) -> Option<&[NodeIndex]> {
        self.entry_nodes.get(&id).map(Vec::as_slice)
    }

    /// Get exit nodes for a component.
    pub fn exit_nodes(&self, id: ComponentId) -> Option<&[NodeIndex]> {
        self.exit_nodes.get(&id).map(Vec::as_slice)
    }

    /// Get a node by index.
    pub fn node(&self, idx: NodeIndex) -> Option<&IpdgNode> {
        self.graph.node_weight(idx)
    }

    /// Get an edge by indices.
    pub fn edge(&self, from: NodeIndex, to: NodeIndex) -> Option<&IpdgEdge> {
        self.graph
            .find_edge(from, to)
            .and_then(|e| self.graph.edge_weight(e))
    }

    /// Get all cross-boundary edges.
    pub fn cross_boundary_edges(&self) -> Vec<(NodeIndex, NodeIndex, &IpdgEdge)> {
        self.graph
            .edge_references()
            .filter(|e| e.weight().kind == EdgeKind::CrossBoundary)
            .map(|e| (e.source(), e.target(), e.weight()))
            .collect()
    }

    /// Get all tainted paths in the graph.
    pub fn tainted_paths(&self) -> Vec<Vec<NodeIndex>> {
        let mut paths = Vec::new();

        // Find all source nodes
        let sources: Vec<_> = self
            .graph
            .node_indices()
            .filter(|&idx| self.graph[idx].is_source)
            .collect();

        // Find all sink nodes
        let sinks: Vec<_> = self
            .graph
            .node_indices()
            .filter(|&idx| self.graph[idx].is_sink)
            .collect();

        // For each source-sink pair, find tainted paths
        for source in &sources {
            for sink in &sinks {
                if let Some(path) = self.find_tainted_path(*source, *sink) {
                    paths.push(path);
                }
            }
        }

        paths
    }

    /// Find a tainted path between two nodes.
    fn find_tainted_path(&self, from: NodeIndex, to: NodeIndex) -> Option<Vec<NodeIndex>> {
        // Simple DFS to find a path where all edges are tainted
        let mut visited = std::collections::HashSet::default();
        let mut path = Vec::new();

        if self.dfs_tainted(from, to, &mut visited, &mut path) {
            Some(path)
        } else {
            None
        }
    }

    fn dfs_tainted(
        &self,
        current: NodeIndex,
        target: NodeIndex,
        visited: &mut std::collections::HashSet<NodeIndex>,
        path: &mut Vec<NodeIndex>,
    ) -> bool {
        if current == target {
            path.push(current);
            return true;
        }

        if visited.contains(&current) {
            return false;
        }

        visited.insert(current);
        path.push(current);

        for neighbor in self.graph.neighbors(current) {
            if let Some(edge) = self.edge(current, neighbor)
                && edge.is_tainted
                && self.dfs_tainted(neighbor, target, visited, path)
            {
                return true;
            }
        }

        path.pop();
        false
    }

    /// Get statistics about the graph.
    pub fn stats(&self) -> IpdgStats {
        let cross_boundary_count = self.cross_boundary_edges().len();
        let tainted_edge_count = self
            .graph
            .edge_references()
            .filter(|e| e.weight().is_tainted)
            .count();

        IpdgStats {
            component_count: self.components.len(),
            boundary_count: self.boundaries.len(),
            node_count: self.graph.node_count(),
            edge_count: self.graph.edge_count(),
            cross_boundary_edge_count: cross_boundary_count,
            tainted_edge_count,
        }
    }
}

impl Default for Ipdg {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about an IPDG.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct IpdgStats {
    /// Number of components
    pub component_count: usize,

    /// Number of boundaries
    pub boundary_count: usize,

    /// Total number of nodes
    pub node_count: usize,

    /// Total number of edges
    pub edge_count: usize,

    /// Number of cross-boundary edges
    pub cross_boundary_edge_count: usize,

    /// Number of tainted edges
    pub tainted_edge_count: usize,
}

/// Builder for constructing an IPDG.
pub struct IpdgBuilder {
    ipdg: Ipdg,
}

impl IpdgBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self { ipdg: Ipdg::new() }
    }

    /// Add a component.
    pub fn add_component(&mut self, component: Component) -> &mut Self {
        self.ipdg.add_component(component);
        self
    }

    /// Add a boundary.
    pub fn add_boundary(&mut self, boundary: Boundary) -> Result<&mut Self> {
        self.ipdg.add_boundary(boundary)?;
        Ok(self)
    }

    /// Add a node.
    pub fn add_node(&mut self, node: IpdgNode) -> NodeIndex {
        self.ipdg.add_node(node)
    }

    /// Add an edge.
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, edge: IpdgEdge) -> &mut Self {
        self.ipdg.add_edge(from, to, edge);
        self
    }

    /// Build the final IPDG.
    pub fn build(self) -> Ipdg {
        self.ipdg
    }
}

impl Default for IpdgBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BoundaryKind, ComponentKind};

    #[test]
    fn test_ipdg_construction() {
        let mut builder = IpdgBuilder::new();

        // Add components
        let app = Component::new(
            ComponentId(1),
            ComponentKind::AndroidApp,
            "com.example.app".to_string(),
        );
        let lib = Component::new(
            ComponentId(2),
            ComponentKind::NativeLibrary,
            "libvuln.so".to_string(),
        );

        builder.add_component(app);
        builder.add_component(lib);

        // Add boundary
        let boundary = Boundary::new(BoundaryKind::Jni, ComponentId(1), ComponentId(2));
        builder.add_boundary(boundary).unwrap();

        let ipdg = builder.build();

        assert_eq!(ipdg.components().count(), 2);
        assert_eq!(ipdg.boundaries().len(), 1);
    }

    #[test]
    fn test_cross_boundary_tracking() {
        let mut ipdg = Ipdg::new();

        let comp1 = Component::new(ComponentId(1), ComponentKind::AndroidApp, "app".to_string());
        let comp2 = Component::new(
            ComponentId(2),
            ComponentKind::NativeLibrary,
            "lib".to_string(),
        );

        ipdg.add_component(comp1);
        ipdg.add_component(comp2);

        // Add nodes
        let node1 = IpdgNode {
            component: ComponentId(1),
            function: "main".to_string(),
            address: Some(0x1000),
            source_location: None,
            is_source: true,
            is_sink: false,
            node_type: NodeType::Regular,
        };

        let node2 = IpdgNode {
            component: ComponentId(2),
            function: "vulnerable".to_string(),
            address: Some(0x2000),
            source_location: None,
            is_source: false,
            is_sink: true,
            node_type: NodeType::Regular,
        };

        let idx1 = ipdg.add_node(node1);
        let idx2 = ipdg.add_node(node2);

        // Add cross-boundary edge
        let edge = IpdgEdge {
            kind: EdgeKind::CrossBoundary,
            boundary: None,
            is_tainted: true,
            confidence: 0.9,
        };

        ipdg.add_edge(idx1, idx2, edge);

        let stats = ipdg.stats();
        assert_eq!(stats.component_count, 2);
        assert_eq!(stats.node_count, 2);
        assert_eq!(stats.cross_boundary_edge_count, 1);
        assert_eq!(stats.tainted_edge_count, 1);
    }
}
