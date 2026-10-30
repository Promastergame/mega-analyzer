//! Inference engine with explainability

use crate::graph::HeterogeneousGraph;
use crate::model::{CrossModalGNN, Prediction};
use omnisec_json::{FromJson, ToJson};

/// Threat level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, ToJson, FromJson)]
pub enum ThreatLevel {
    /// No threat detected
    None,
    /// Low threat
    Low,
    /// Medium threat
    Medium,
    /// High threat
    High,
    /// Critical threat
    Critical,
}

impl ThreatLevel {
    /// Get threat level from confidence score
    pub fn from_confidence(confidence: f32) -> Self {
        match confidence {
            c if c < 0.2 => ThreatLevel::None,
            c if c < 0.4 => ThreatLevel::Low,
            c if c < 0.6 => ThreatLevel::Medium,
            c if c < 0.8 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }
}

/// Inference result with explanation
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct InferenceResult {
    /// Threat level
    pub threat_level: ThreatLevel,
    /// Confidence score
    pub confidence: f32,
    /// Predicted vulnerability type
    pub vulnerability_type: String,
    /// Explanation paths in the graph
    pub explanation_paths: Vec<ExplanationPath>,
    /// Contributing factors
    pub contributing_factors: Vec<ContributingFactor>,
}

/// Path in the graph that explains the prediction
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct ExplanationPath {
    /// Nodes in the path
    pub nodes: Vec<String>,
    /// Path weight/importance
    pub weight: f32,
    /// Description of the path
    pub description: String,
}

/// Factor that contributes to the prediction
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct ContributingFactor {
    /// Factor name
    pub name: String,
    /// Factor importance (0.0 - 1.0)
    pub importance: f32,
    /// Factor description
    pub description: String,
}

/// Inference engine
pub struct InferenceEngine {
    model: CrossModalGNN,
    graph: HeterogeneousGraph,
}

impl InferenceEngine {
    /// Create a new inference engine
    pub fn new(model: CrossModalGNN, graph: HeterogeneousGraph) -> Self {
        InferenceEngine { model, graph }
    }

    /// Run inference on a node in the graph
    pub fn infer(&self, node_id: &str) -> crate::Result<InferenceResult> {
        // Get node features
        let node = self
            .graph
            .get_node(node_id)
            .ok_or_else(|| crate::Error::InferenceError(format!("Node {} not found", node_id)))?;

        // Extract features
        let mut features = node.features.clone();
        if features.is_empty() {
            features = vec![0.5; 28]; // Default feature vector
        }

        // Run prediction
        let prediction = self.model.predict(&features)?;

        // Generate explanation
        let explanation_paths = self.generate_explanation_paths(node_id, &prediction)?;
        let contributing_factors = self.extract_contributing_factors(&prediction);

        // Determine threat level
        let threat_level = ThreatLevel::from_confidence(prediction.confidence);

        // Map predicted class to vulnerability type
        let vulnerability_type = self.map_class_to_vulnerability(prediction.predicted_class);

        Ok(InferenceResult {
            threat_level,
            confidence: prediction.confidence,
            vulnerability_type,
            explanation_paths,
            contributing_factors,
        })
    }

    /// Generate explanation paths: BFS from the queried node towards the
    /// highest-risk reachable nodes (up to 3), so each path shows a
    /// concrete threat-propagation trail instead of a self-loop.
    fn generate_explanation_paths(
        &self,
        node_id: &str,
        prediction: &Prediction,
    ) -> crate::Result<Vec<ExplanationPath>> {
        let mut candidates: Vec<(String, f32)> = self
            .graph
            .node_ids()
            .iter()
            .filter_map(|id| self.graph.get_node(id).map(|n| (id.clone(), n.risk_score)))
            .collect();
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut paths = Vec::new();
        for (target, risk) in candidates.iter().take(5) {
            if paths.len() >= 3 {
                break;
            }
            if target == node_id {
                continue;
            }
            let trail = self.graph.find_paths(node_id, target, 5);
            if let Some(path) = trail.into_iter().next() {
                let weight = (prediction.confidence + risk) / 2.0;
                let description = format!(
                    "Threat propagation path (risk {risk:.2}): {}",
                    path.join(" -> ")
                );
                paths.push(ExplanationPath {
                    nodes: path,
                    weight,
                    description,
                });
            }
        }
        // Fallback: at least describe the queried node itself.
        if paths.is_empty() {
            paths.push(ExplanationPath {
                nodes: vec![node_id.to_string()],
                weight: prediction.confidence,
                description: "No multi-hop threat path; node assessed in isolation".to_string(),
            });
        }
        Ok(paths)
    }

    /// Extract contributing factors
    fn extract_contributing_factors(&self, prediction: &Prediction) -> Vec<ContributingFactor> {
        let mut factors = Vec::new();

        // Top contributing classes
        for (idx, &prob) in prediction.class_probs.iter().enumerate() {
            if prob > 0.1 {
                let factor_name = self.map_class_to_vulnerability(idx);
                factors.push(ContributingFactor {
                    name: factor_name.clone(),
                    importance: prob,
                    description: format!("Probability of {}: {:.2}%", factor_name, prob * 100.0),
                });
            }
        }

        // Sort by importance
        factors.sort_by(|a, b| b.importance.partial_cmp(&a.importance).unwrap());

        factors
    }

    /// Map class index to vulnerability type
    fn map_class_to_vulnerability(&self, class_idx: usize) -> String {
        match class_idx {
            0 => "Use-After-Free".to_string(),
            1 => "Buffer Overflow".to_string(),
            2 => "SQL Injection".to_string(),
            3 => "Weak Cryptography".to_string(),
            4 => "Race Condition".to_string(),
            5 => "Format String".to_string(),
            6 => "Path Traversal".to_string(),
            7 => "Command Injection".to_string(),
            8 => "XXE Attack".to_string(),
            9 => "SSRF".to_string(),
            _ => "Unknown".to_string(),
        }
    }

    /// Batch inference on multiple nodes
    pub fn infer_batch(&self, node_ids: &[&str]) -> crate::Result<Vec<InferenceResult>> {
        let mut results = Vec::new();

        for node_id in node_ids {
            match self.infer(node_id) {
                Ok(result) => results.push(result),
                Err(e) => {
                    eprintln!("Inference failed for node {}: {}", node_id, e);
                }
            }
        }

        Ok(results)
    }

    /// Get graph statistics for analysis
    pub fn get_graph_stats(&self) -> crate::Result<GraphAnalysisStats> {
        let stats = self.graph.get_statistics();

        Ok(GraphAnalysisStats {
            total_nodes: stats.total_nodes,
            total_edges: stats.total_edges,
            average_degree: stats.average_degree,
            high_risk_nodes: self.count_high_risk_nodes(),
        })
    }

    /// Count high-risk nodes in the graph (risk_score > 0.7).
    fn count_high_risk_nodes(&self) -> usize {
        self.graph
            .node_ids()
            .iter()
            .filter_map(|id| self.graph.get_node(id))
            .filter(|n| n.risk_score > 0.7)
            .count()
    }
}

/// Graph analysis statistics
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct GraphAnalysisStats {
    /// Total number of nodes
    pub total_nodes: usize,
    /// Total number of edges
    pub total_edges: usize,
    /// Average node degree
    pub average_degree: f32,
    /// Number of high-risk nodes
    pub high_risk_nodes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphNode, NodeType};
    use crate::model::GNNConfig;
    use std::collections::HashMap;

    #[test]
    fn test_threat_level_classification() {
        assert_eq!(ThreatLevel::from_confidence(0.1), ThreatLevel::None);
        assert_eq!(ThreatLevel::from_confidence(0.3), ThreatLevel::Low);
        assert_eq!(ThreatLevel::from_confidence(0.5), ThreatLevel::Medium);
        assert_eq!(ThreatLevel::from_confidence(0.7), ThreatLevel::High);
        assert_eq!(ThreatLevel::from_confidence(0.9), ThreatLevel::Critical);
    }

    #[test]
    fn test_inference_engine() {
        let mut graph = HeterogeneousGraph::new();

        let node = GraphNode {
            id: "test_node".to_string(),
            node_type: NodeType::APICall,
            label: "test".to_string(),
            features: vec![0.5; 28],
            risk_score: 0.7,
            metadata: HashMap::new(),
        };

        graph.add_node(node).unwrap();

        let model = CrossModalGNN::new(GNNConfig::default());
        let engine = InferenceEngine::new(model, graph);

        let result = engine.infer("test_node");
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
    }
}
