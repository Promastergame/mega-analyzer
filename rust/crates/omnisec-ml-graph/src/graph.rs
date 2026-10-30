//! Heterogeneous graph representation for cross-modal analysis

use omnisec_graph::{DiGraph, NodeIndex};
use omnisec_json::{FromJson, ToJson};
use std::collections::HashMap;

/// Types of nodes in the heterogeneous graph
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum NodeType {
    /// Permission node (from AndroidManifest.xml)
    Permission,
    /// API call node
    APICall,
    /// Native symbol node
    NativeSymbol,
    /// String constant node
    StringConstant,
    /// DNS endpoint node
    DNSEndpoint,
    /// MITM endpoint node
    MITMEndpoint,
    /// Runtime event node
    RuntimeEvent,
    /// Application package node
    Package,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Permission => "permission",
            Self::APICall => "api_call",
            Self::NativeSymbol => "native_symbol",
            Self::StringConstant => "string_constant",
            Self::DNSEndpoint => "dns_endpoint",
            Self::MITMEndpoint => "mitm_endpoint",
            Self::RuntimeEvent => "runtime_event",
            Self::Package => "package",
        };
        f.write_str(name)
    }
}

impl std::str::FromStr for NodeType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "permission" => Self::Permission,
            "api_call" => Self::APICall,
            "native_symbol" => Self::NativeSymbol,
            "string_constant" => Self::StringConstant,
            "dns_endpoint" => Self::DNSEndpoint,
            "mitm_endpoint" => Self::MITMEndpoint,
            "runtime_event" => Self::RuntimeEvent,
            "package" => Self::Package,
            other => return Err(format!("unknown node type: {other}")),
        })
    }
}

/// Types of edges in the heterogeneous graph
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum EdgeType {
    /// Permission is used by API call
    PermissionUsage,
    /// API call invokes another API call
    APIInvocation,
    /// API call accesses string constant
    StringAccess,
    /// API call connects to endpoint
    EndpointConnection,
    /// Runtime event triggers action
    EventTrigger,
    /// Data flow between nodes
    DataFlow,
    /// Control flow between nodes
    ControlFlow,
}

/// A node in the heterogeneous graph
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct GraphNode {
    /// Unique identifier
    pub id: String,
    /// Node type
    pub node_type: NodeType,
    /// Node label/name
    pub label: String,
    /// Node features
    pub features: Vec<f32>,
    /// Risk score (0.0 - 1.0)
    pub risk_score: f32,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// An edge in the heterogeneous graph
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct GraphEdge {
    /// Source node ID
    pub source: String,
    /// Target node ID
    pub target: String,
    /// Edge type
    pub edge_type: EdgeType,
    /// Edge weight (0.0 - 1.0)
    pub weight: f32,
    /// Timestamp of edge creation
    pub timestamp: u64,
}

/// Heterogeneous graph for cross-modal vulnerability detection
pub struct HeterogeneousGraph {
    /// Internal graph representation
    graph: DiGraph<GraphNode, GraphEdge>,
    /// Mapping from node ID to node index
    node_index_map: HashMap<String, NodeIndex>,
    /// Nodes by type
    nodes_by_type: HashMap<NodeType, Vec<String>>,
}

impl HeterogeneousGraph {
    /// Create a new heterogeneous graph
    pub fn new() -> Self {
        HeterogeneousGraph {
            graph: DiGraph::new(),
            node_index_map: HashMap::new(),
            nodes_by_type: HashMap::new(),
        }
    }

    /// Add a node to the graph
    pub fn add_node(&mut self, node: GraphNode) -> Result<(), String> {
        if self.node_index_map.contains_key(&node.id) {
            return Err(format!("Node {} already exists", node.id));
        }

        let node_type = node.node_type;
        let idx = self.graph.add_node(node.clone());
        self.node_index_map.insert(node.id.clone(), idx);

        self.nodes_by_type
            .entry(node_type)
            .or_insert_with(Vec::new)
            .push(node.id);

        Ok(())
    }

    /// Add an edge to the graph
    pub fn add_edge(&mut self, edge: GraphEdge) -> Result<(), String> {
        let source_idx = self
            .node_index_map
            .get(&edge.source)
            .ok_or_else(|| format!("Source node {} not found", edge.source))?;

        let target_idx = self
            .node_index_map
            .get(&edge.target)
            .ok_or_else(|| format!("Target node {} not found", edge.target))?;

        self.graph.add_edge(*source_idx, *target_idx, edge);
        Ok(())
    }

    /// Get a node by ID
    pub fn get_node(&self, id: &str) -> Option<&GraphNode> {
        self.node_index_map
            .get(id)
            .and_then(|idx| self.graph.node_weight(*idx))
    }

    /// Get all nodes of a specific type
    pub fn get_nodes_by_type(&self, node_type: NodeType) -> Vec<&GraphNode> {
        self.nodes_by_type
            .get(&node_type)
            .map(|ids| ids.iter().filter_map(|id| self.get_node(id)).collect())
            .unwrap_or_default()
    }

    /// Get neighbors of a node
    pub fn get_neighbors(&self, node_id: &str) -> Vec<&GraphNode> {
        self.get_successors(node_id)
            .into_iter()
            .chain(self.get_predecessors(node_id))
            .collect::<Vec<_>>()
    }

    /// Get outgoing neighbors (successors) of a node.
    pub fn get_successors(&self, node_id: &str) -> Vec<&GraphNode> {
        self.node_index_map
            .get(node_id)
            .map(|idx| {
                self.graph
                    .neighbors_directed(*idx, omnisec_graph::Direction::Outgoing)
                    .filter_map(|neighbor_idx| self.graph.node_weight(neighbor_idx))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get incoming neighbors (predecessors) of a node.
    pub fn get_predecessors(&self, node_id: &str) -> Vec<&GraphNode> {
        self.node_index_map
            .get(node_id)
            .map(|idx| {
                self.graph
                    .neighbors_directed(*idx, omnisec_graph::Direction::Incoming)
                    .filter_map(|neighbor_idx| self.graph.node_weight(neighbor_idx))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Out-degree (number of outgoing edges) of a node.
    pub fn out_degree(&self, node_id: &str) -> usize {
        self.get_successors(node_id).len()
    }

    /// In-degree (number of incoming edges) of a node.
    pub fn in_degree(&self, node_id: &str) -> usize {
        self.get_predecessors(node_id).len()
    }

    /// Ids of all nodes in the graph.
    pub fn node_ids(&self) -> Vec<String> {
        self.node_index_map.keys().cloned().collect()
    }

    /// Breadth-first distances from `source_id` to every reachable node
    /// (in edges). Unreachable nodes are absent from the map.
    pub fn bfs_distances(&self, source_id: &str) -> std::collections::HashMap<String, usize> {
        use std::collections::VecDeque;
        let mut dist = std::collections::HashMap::new();
        let Some(&start) = self.node_index_map.get(source_id) else {
            return dist;
        };
        let mut queue = VecDeque::from([start]);
        dist.insert(source_id.to_string(), 0);
        while let Some(current) = queue.pop_front() {
            let d = self
                .graph
                .node_weight(current)
                .and_then(|n| dist.get(&n.id).copied())
                .unwrap_or(0);
            for next in self
                .graph
                .neighbors_directed(current, omnisec_graph::Direction::Outgoing)
            {
                if let Some(node) = self.graph.node_weight(next) {
                    if !dist.contains_key(&node.id) {
                        dist.insert(node.id.clone(), d + 1);
                        queue.push_back(next);
                    }
                }
            }
        }
        dist
    }

    /// Find paths between two nodes
    pub fn find_paths(
        &self,
        source_id: &str,
        target_id: &str,
        max_depth: usize,
    ) -> Vec<Vec<String>> {
        let mut paths = Vec::new();
        let mut current_path = Vec::new();

        if let (Some(source_idx), Some(target_idx)) = (
            self.node_index_map.get(source_id),
            self.node_index_map.get(target_id),
        ) {
            self.dfs_paths(
                *source_idx,
                *target_idx,
                &mut current_path,
                &mut paths,
                max_depth,
            );
        }

        paths
    }

    /// Depth-first search for paths
    fn dfs_paths(
        &self,
        current: NodeIndex,
        target: NodeIndex,
        path: &mut Vec<String>,
        paths: &mut Vec<Vec<String>>,
        depth: usize,
    ) {
        if depth == 0 {
            return;
        }

        if let Some(node) = self.graph.node_weight(current) {
            path.push(node.id.clone());

            if current == target {
                paths.push(path.clone());
            } else {
                for neighbor in self.graph.neighbors(current) {
                    self.dfs_paths(neighbor, target, path, paths, depth - 1);
                }
            }

            path.pop();
        }
    }

    /// Get graph statistics
    pub fn get_statistics(&self) -> GraphStatistics {
        let node_count = self.graph.node_count();
        let edge_count = self.graph.edge_count();

        let mut nodes_by_type_count = HashMap::new();
        for (node_type, nodes) in &self.nodes_by_type {
            nodes_by_type_count.insert(*node_type, nodes.len());
        }

        GraphStatistics {
            total_nodes: node_count,
            total_edges: edge_count,
            nodes_by_type: nodes_by_type_count,
            average_degree: if node_count > 0 {
                (edge_count as f32) / (node_count as f32)
            } else {
                0.0
            },
        }
    }
}

impl Default for HeterogeneousGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the graph
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct GraphStatistics {
    /// Total number of nodes
    pub total_nodes: usize,
    /// Total number of edges
    pub total_edges: usize,
    /// Number of nodes by type
    pub nodes_by_type: HashMap<NodeType, usize>,
    /// Average degree of nodes
    pub average_degree: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graph_creation() {
        let mut graph = HeterogeneousGraph::new();

        let node1 = GraphNode {
            id: "perm_1".to_string(),
            node_type: NodeType::Permission,
            label: "INTERNET".to_string(),
            features: vec![1.0, 0.0, 0.0],
            risk_score: 0.5,
            metadata: HashMap::new(),
        };

        let node2 = GraphNode {
            id: "api_1".to_string(),
            node_type: NodeType::APICall,
            label: "HttpURLConnection.connect".to_string(),
            features: vec![0.0, 1.0, 0.0],
            risk_score: 0.7,
            metadata: HashMap::new(),
        };

        assert!(graph.add_node(node1).is_ok());
        assert!(graph.add_node(node2).is_ok());

        assert_eq!(graph.get_statistics().total_nodes, 2);
    }

    #[test]
    fn test_edge_addition() {
        let mut graph = HeterogeneousGraph::new();

        let node1 = GraphNode {
            id: "perm_1".to_string(),
            node_type: NodeType::Permission,
            label: "INTERNET".to_string(),
            features: vec![1.0, 0.0, 0.0],
            risk_score: 0.5,
            metadata: HashMap::new(),
        };

        let node2 = GraphNode {
            id: "api_1".to_string(),
            node_type: NodeType::APICall,
            label: "HttpURLConnection.connect".to_string(),
            features: vec![0.0, 1.0, 0.0],
            risk_score: 0.7,
            metadata: HashMap::new(),
        };

        graph.add_node(node1).unwrap();
        graph.add_node(node2).unwrap();

        let edge = GraphEdge {
            source: "perm_1".to_string(),
            target: "api_1".to_string(),
            edge_type: EdgeType::PermissionUsage,
            weight: 0.8,
            timestamp: 0,
        };

        assert!(graph.add_edge(edge).is_ok());
        assert_eq!(graph.get_statistics().total_edges, 1);
    }
}
