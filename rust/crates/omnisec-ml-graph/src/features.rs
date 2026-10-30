//! Feature extraction from heterogeneous graphs

use crate::graph::{EdgeType, HeterogeneousGraph, NodeType};
use omnisec_json::{FromJson, ToJson};

/// Feature vector for a node or graph
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct FeatureVector {
    /// Feature values
    pub values: Vec<f32>,
    /// Feature names
    pub names: Vec<String>,
}

/// Feature extractor for heterogeneous graphs
pub struct FeatureExtractor;

impl FeatureExtractor {
    /// Extract features from a node
    pub fn extract_node_features(
        graph: &HeterogeneousGraph,
        node_id: &str,
    ) -> crate::Result<FeatureVector> {
        let node = graph
            .get_node(node_id)
            .ok_or_else(|| crate::Error::FeatureError(format!("Node {} not found", node_id)))?;

        let mut features = vec![];
        let mut names = vec![];

        // Node type features (one-hot encoding)
        let node_type_features = Self::encode_node_type(node.node_type);
        features.extend(&node_type_features);
        names.extend(vec![
            "node_type_permission".to_string(),
            "node_type_api_call".to_string(),
            "node_type_native_symbol".to_string(),
            "node_type_string_constant".to_string(),
            "node_type_dns_endpoint".to_string(),
            "node_type_mitm_endpoint".to_string(),
            "node_type_runtime_event".to_string(),
            "node_type_package".to_string(),
        ]);

        // Risk score
        features.push(node.risk_score);
        names.push("risk_score".to_string());

        // Node degree features
        let degree_features = Self::extract_degree_features(graph, node_id);
        features.extend(&degree_features);
        names.extend(vec![
            "in_degree".to_string(),
            "out_degree".to_string(),
            "total_degree".to_string(),
        ]);

        // Centrality features
        let centrality_features = Self::extract_centrality_features(graph, node_id);
        features.extend(&centrality_features);
        names.extend(vec![
            "betweenness_centrality".to_string(),
            "closeness_centrality".to_string(),
        ]);

        Ok(FeatureVector {
            values: features,
            names,
        })
    }

    /// Extract graph-level features
    pub fn extract_graph_features(graph: &HeterogeneousGraph) -> crate::Result<FeatureVector> {
        let stats = graph.get_statistics();

        let mut features = vec![];
        let mut names = vec![];

        // Basic statistics
        features.push(stats.total_nodes as f32);
        names.push("total_nodes".to_string());

        features.push(stats.total_edges as f32);
        names.push("total_edges".to_string());

        features.push(stats.average_degree);
        names.push("average_degree".to_string());

        // Node type distribution
        for node_type in &[
            NodeType::Permission,
            NodeType::APICall,
            NodeType::NativeSymbol,
            NodeType::StringConstant,
            NodeType::DNSEndpoint,
            NodeType::MITMEndpoint,
            NodeType::RuntimeEvent,
            NodeType::Package,
        ] {
            let count = stats.nodes_by_type.get(node_type).copied().unwrap_or(0);
            features.push(count as f32);
            names.push(format!("count_{:?}", node_type));
        }

        Ok(FeatureVector {
            values: features,
            names,
        })
    }

    /// Encode node type as one-hot vector
    fn encode_node_type(node_type: NodeType) -> Vec<f32> {
        let mut encoding = vec![0.0; 8];
        let idx = match node_type {
            NodeType::Permission => 0,
            NodeType::APICall => 1,
            NodeType::NativeSymbol => 2,
            NodeType::StringConstant => 3,
            NodeType::DNSEndpoint => 4,
            NodeType::MITMEndpoint => 5,
            NodeType::RuntimeEvent => 6,
            NodeType::Package => 7,
        };
        encoding[idx] = 1.0;
        encoding
    }

    /// Extract degree-based features
    fn extract_degree_features(graph: &HeterogeneousGraph, node_id: &str) -> Vec<f32> {
        let in_degree = graph.in_degree(node_id) as f32;
        let out_degree = graph.out_degree(node_id) as f32;
        let total_degree = in_degree + out_degree;

        vec![in_degree, out_degree, total_degree]
    }

    /// Extract centrality-based features: degree centrality (normalized by
    /// graph size) and closeness centrality from BFS distances.
    fn extract_centrality_features(graph: &HeterogeneousGraph, node_id: &str) -> Vec<f32> {
        let stats = graph.get_statistics();
        let out_degree = graph.out_degree(node_id) as f32;
        let degree_centrality = if stats.total_nodes > 1 {
            out_degree / (stats.total_nodes - 1) as f32
        } else {
            0.0
        };

        let distances = graph.bfs_distances(node_id);
        // Closeness = (reachable) / (sum of distances); isolated nodes score 0.
        let closeness = if distances.len() > 1 {
            let sum: usize = distances.values().sum();
            if sum > 0 {
                (distances.len() - 1) as f32 / sum as f32
            } else {
                0.0
            }
        } else {
            0.0
        };

        vec![degree_centrality, closeness]
    }

    /// Normalize feature vector
    pub fn normalize(features: &mut FeatureVector) {
        let max = features
            .values
            .iter()
            .fold(f32::NEG_INFINITY, |a, &b| a.max(b));
        let min = features.values.iter().fold(f32::INFINITY, |a, &b| a.min(b));

        let range = max - min;
        if range > 0.0 {
            for value in &mut features.values {
                *value = (*value - min) / range;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::GraphNode;
    use std::collections::HashMap;

    #[test]
    fn test_feature_extraction() {
        let mut graph = HeterogeneousGraph::new();

        let node = GraphNode {
            id: "test_node".to_string(),
            node_type: NodeType::APICall,
            label: "test".to_string(),
            features: vec![],
            risk_score: 0.5,
            metadata: HashMap::new(),
        };

        graph.add_node(node).unwrap();

        let features = FeatureExtractor::extract_node_features(&graph, "test_node");
        assert!(features.is_ok());

        let features = features.unwrap();
        assert!(!features.values.is_empty());
        assert_eq!(features.values.len(), features.names.len());
    }
}
