//! Cross-boundary taint tracking implementation.

use omnisec_graph::NodeIndex;
use omnisec_json::{FromJson, ToJson};
use std::collections::VecDeque;
use std::collections::{HashMap as FxHashMap, HashSet as FxHashSet};

use crate::component::ComponentId;
use crate::graph::{EdgeKind, Ipdg, IpdgNode};

/// Source of taint in the system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum TaintSource {
    /// User input (keyboard, touch, etc.)
    UserInput,

    /// Network data
    Network,

    /// File system
    FileSystem,

    /// Environment variables
    Environment,

    /// Command line arguments
    CommandLine,

    /// IPC message
    IpcMessage,

    /// Database query result
    Database,

    /// Sensor data
    Sensor,

    /// Custom source
    Custom(String),
}

/// Sink for taint (potentially vulnerable operation).
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum TaintSink {
    /// Memory operation (malloc, free, memcpy, etc.)
    Memory,

    /// System call
    Syscall,

    /// File operation
    FileOperation,

    /// Network operation
    NetworkOperation,

    /// Command execution
    CommandExecution,

    /// SQL query
    SqlQuery,

    /// Cryptographic operation
    Crypto,

    /// Authentication/Authorization
    Auth,

    /// Custom sink
    Custom(String),
}

/// A path through the IPDG where taint flows from source to sink.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct TaintPath {
    /// Source of the taint
    pub source: TaintSource,

    /// Sink where taint reaches
    pub sink: TaintSink,

    /// Nodes in the path
    pub nodes: Vec<NodeIndex>,

    /// Components involved in the path
    pub components: Vec<ComponentId>,

    /// Number of boundary crossings
    pub boundary_crossings: usize,

    /// Whether the path crosses privilege boundaries
    pub crosses_privilege_boundary: bool,

    /// Confidence score (0.0 = uncertain, 1.0 = certain)
    pub confidence: f32,

    /// Risk score (0.0 = low risk, 1.0 = high risk)
    pub risk_score: f32,
}

impl TaintPath {
    /// Check if this path represents a critical vulnerability.
    pub fn is_critical(&self) -> bool {
        self.crosses_privilege_boundary
            && self.boundary_crossings > 0
            && self.confidence > 0.7
            && self.risk_score > 0.8
    }

    /// Get a human-readable description of the path.
    pub fn description(&self) -> String {
        format!(
            "{:?} → {:?} (crossings: {}, confidence: {:.2}, risk: {:.2})",
            self.source, self.sink, self.boundary_crossings, self.confidence, self.risk_score
        )
    }
}

/// Taint tracker for cross-boundary analysis.
pub struct TaintTracker<'a> {
    ipdg: &'a Ipdg,

    /// Taint sources (node index → source type)
    pub sources: FxHashMap<NodeIndex, TaintSource>,

    /// Taint sinks (node index → sink type)
    pub sinks: FxHashMap<NodeIndex, TaintSink>,

    /// Taint propagation rules
    propagation_rules: PropagationRules,
}

impl<'a> TaintTracker<'a> {
    /// Create a new taint tracker.
    pub fn new(ipdg: &'a Ipdg) -> Self {
        Self {
            ipdg,
            sources: FxHashMap::default(),
            sinks: FxHashMap::default(),
            propagation_rules: PropagationRules::default(),
        }
    }

    /// Register a taint source.
    pub fn add_source(&mut self, node: NodeIndex, source: TaintSource) {
        self.sources.insert(node, source);
    }

    /// Register a taint sink.
    pub fn add_sink(&mut self, node: NodeIndex, sink: TaintSink) {
        self.sinks.insert(node, sink);
    }

    /// Automatically detect sources and sinks based on node properties.
    pub fn auto_detect_sources_and_sinks(&mut self) {
        for idx in self.ipdg.graph.node_indices() {
            if let Some(node) = self.ipdg.node(idx) {
                // Detect sources
                if node.is_source {
                    self.detect_source_type(idx, node);
                }

                // Detect sinks
                if node.is_sink {
                    self.detect_sink_type(idx, node);
                }
            }
        }
    }

    fn detect_source_type(&mut self, idx: NodeIndex, node: &IpdgNode) {
        // Heuristic-based source detection
        let func_lower = node.function.to_lowercase();

        let source = if func_lower.contains("read") || func_lower.contains("recv") {
            if func_lower.contains("socket") || func_lower.contains("net") {
                TaintSource::Network
            } else if func_lower.contains("file") {
                TaintSource::FileSystem
            } else {
                TaintSource::UserInput
            }
        } else if func_lower.contains("getenv") {
            TaintSource::Environment
        } else if func_lower.contains("argv") || func_lower.contains("getopt") {
            TaintSource::CommandLine
        } else {
            TaintSource::Custom(node.function.clone())
        };

        self.sources.insert(idx, source);
    }

    fn detect_sink_type(&mut self, idx: NodeIndex, node: &IpdgNode) {
        // Heuristic-based sink detection
        let func_lower = node.function.to_lowercase();

        let sink = if func_lower.contains("malloc")
            || func_lower.contains("free")
            || func_lower.contains("memcpy")
            || func_lower.contains("strcpy")
        {
            TaintSink::Memory
        } else if func_lower.contains("syscall") || func_lower.contains("ioctl") {
            TaintSink::Syscall
        } else if func_lower.contains("exec")
            || func_lower.contains("system")
            || func_lower.contains("popen")
        {
            TaintSink::CommandExecution
        } else if func_lower.contains("sql") || func_lower.contains("query") {
            TaintSink::SqlQuery
        } else if func_lower.contains("crypt") || func_lower.contains("hash") {
            TaintSink::Crypto
        } else if func_lower.contains("auth") || func_lower.contains("login") {
            TaintSink::Auth
        } else {
            TaintSink::Custom(node.function.clone())
        };

        self.sinks.insert(idx, sink);
    }

    /// Find all taint paths from sources to sinks.
    pub fn find_taint_paths(&self) -> Vec<TaintPath> {
        let mut paths = Vec::new();

        for (&source_idx, source_type) in &self.sources {
            for (&sink_idx, sink_type) in &self.sinks {
                if let Some(node_path) = self.find_path(source_idx, sink_idx) {
                    let path = self.analyze_path(source_type.clone(), sink_type.clone(), node_path);
                    paths.push(path);
                }
            }
        }

        paths
    }

    /// Find a path between two nodes using BFS.
    fn find_path(&self, from: NodeIndex, to: NodeIndex) -> Option<Vec<NodeIndex>> {
        let mut queue = VecDeque::new();
        let mut visited = FxHashSet::new();
        let mut parent = FxHashMap::new();

        queue.push_back(from);
        visited.insert(from);

        while let Some(current) = queue.pop_front() {
            if current == to {
                // Reconstruct path
                let mut path = Vec::new();
                let mut node = to;

                while node != from {
                    path.push(node);
                    node = *parent.get(&node)?;
                }

                path.push(from);
                path.reverse();
                return Some(path);
            }

            for neighbor in self.ipdg.graph.neighbors(current) {
                if !visited.contains(&neighbor) {
                    visited.insert(neighbor);
                    parent.insert(neighbor, current);
                    queue.push_back(neighbor);
                }
            }
        }

        None
    }

    /// Analyze a path to compute its properties.
    fn analyze_path(
        &self,
        source: TaintSource,
        sink: TaintSink,
        nodes: Vec<NodeIndex>,
    ) -> TaintPath {
        let mut components = FxHashSet::new();
        let mut boundary_crossings = 0;
        let mut crosses_privilege_boundary = false;
        let mut confidence: f32 = 1.0;
        let mut risk_score: f32 = 0.0;

        // Analyze each edge in the path
        for window in nodes.windows(2) {
            let from = window[0];
            let to = window[1];

            if let Some(from_node) = self.ipdg.node(from) {
                components.insert(from_node.component);
            }

            if let Some(edge) = self.ipdg.edge(from, to) {
                // Count boundary crossings
                if edge.kind == EdgeKind::CrossBoundary {
                    boundary_crossings += 1;

                    // Check if crossing privilege boundary
                    if let Some(boundary_edge) = &edge.boundary {
                        if boundary_edge.boundary.kind == crate::BoundaryKind::Syscall
                            || boundary_edge.boundary.kind == crate::BoundaryKind::Ioctl
                        {
                            crosses_privilege_boundary = true;
                        }

                        // Update risk score based on boundary risk
                        risk_score = risk_score.max(boundary_edge.boundary.risk_score());
                    }
                }

                // Update confidence based on edge confidence
                confidence *= edge.confidence;
            }
        }

        // Adjust risk score based on source and sink types
        risk_score += match (&source, &sink) {
            (TaintSource::Network, TaintSink::CommandExecution) => 0.9,
            (TaintSource::Network, TaintSink::Memory) => 0.8,
            (TaintSource::UserInput, TaintSink::SqlQuery) => 0.85,
            (TaintSource::FileSystem, TaintSink::Memory) => 0.7,
            _ => 0.5,
        };

        risk_score = risk_score.clamp(0.0, 1.0);

        TaintPath {
            source,
            sink,
            nodes,
            components: components.into_iter().collect(),
            boundary_crossings,
            crosses_privilege_boundary,
            confidence,
            risk_score,
        }
    }

    /// Find critical vulnerabilities (high-risk cross-boundary taint flows).
    pub fn find_critical_vulnerabilities(&self) -> Vec<TaintPath> {
        self.find_taint_paths()
            .into_iter()
            .filter(TaintPath::is_critical)
            .collect()
    }
}

/// Rules for taint propagation.
#[derive(Debug, Clone)]
struct PropagationRules {
    /// Whether to propagate through control flow edges
    propagate_control: bool,

    /// Whether to propagate through data flow edges
    propagate_data: bool,

    /// Whether to propagate through call edges
    propagate_call: bool,

    /// Whether to propagate across boundaries
    propagate_cross_boundary: bool,
}

impl Default for PropagationRules {
    fn default() -> Self {
        Self {
            propagate_control: false,
            propagate_data: true,
            propagate_call: true,
            propagate_cross_boundary: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Boundary, BoundaryEdge, BoundaryKind, Component, ComponentKind, IpdgEdge, NodeType,
    };

    #[test]
    fn test_taint_tracking() {
        let mut ipdg = Ipdg::new();

        // Create components
        let app = Component::new(ComponentId(1), ComponentKind::AndroidApp, "app".to_string());
        let lib = Component::new(
            ComponentId(2),
            ComponentKind::NativeLibrary,
            "lib".to_string(),
        );

        ipdg.add_component(app);
        ipdg.add_component(lib);

        // Create nodes
        let source_node = IpdgNode {
            component: ComponentId(1),
            function: "readInput".to_string(),
            address: Some(0x1000),
            source_location: None,
            is_source: true,
            is_sink: false,
            node_type: NodeType::Regular,
        };

        let sink_node = IpdgNode {
            component: ComponentId(2),
            function: "memcpy".to_string(),
            address: Some(0x2000),
            source_location: None,
            is_source: false,
            is_sink: true,
            node_type: NodeType::Regular,
        };

        let source_idx = ipdg.add_node(source_node);
        let sink_idx = ipdg.add_node(sink_node);

        // Create cross-boundary edge
        let boundary = Boundary::new(BoundaryKind::Jni, ComponentId(1), ComponentId(2));

        let edge = IpdgEdge {
            kind: EdgeKind::CrossBoundary,
            boundary: Some(BoundaryEdge::new(boundary).with_taint(true)),
            is_tainted: true,
            confidence: 0.9,
        };

        ipdg.add_edge(source_idx, sink_idx, edge);

        // Track taint
        let mut tracker = TaintTracker::new(&ipdg);
        tracker.add_source(source_idx, TaintSource::UserInput);
        tracker.add_sink(sink_idx, TaintSink::Memory);

        let paths = tracker.find_taint_paths();
        assert_eq!(paths.len(), 1);

        let path = &paths[0];
        assert_eq!(path.boundary_crossings, 1);
        assert!(path.risk_score > 0.5);
    }

    #[test]
    fn test_auto_detection() {
        let mut ipdg = Ipdg::new();

        let comp = Component::new(
            ComponentId(1),
            ComponentKind::NativeExecutable,
            "app".to_string(),
        );
        ipdg.add_component(comp);

        let node = IpdgNode {
            component: ComponentId(1),
            function: "recv_socket".to_string(),
            address: Some(0x1000),
            source_location: None,
            is_source: true,
            is_sink: false,
            node_type: NodeType::Regular,
        };

        let idx = ipdg.add_node(node);

        let mut tracker = TaintTracker::new(&ipdg);
        tracker.auto_detect_sources_and_sinks();

        assert!(tracker.sources.contains_key(&idx));
        assert_eq!(tracker.sources[&idx], TaintSource::Network);
    }
}
