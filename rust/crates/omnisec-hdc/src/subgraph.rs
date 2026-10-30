//! Topology-aware subgraph encoding via **Edge Binding**.
//!
//! The naive approach of `bundle(all node HVs)` loses graph structure —
//! two graphs with the same node set but different edges produce the same HV.
//!
//! We fix this by encoding edges as:
//!
//! ```text
//! EdgeHV = bind(NodeA_HV, ρ_edge_type(NodeB_HV))
//! ```
//!
//! Then the subgraph HV is:
//!
//! ```text
//! SubgraphHV = bundle(all_node_HVs ++ all_edge_HVs)
//! ```
//!
//! This preserves:
//! - **Which nodes exist** (from node HVs)
//! - **How nodes connect** (from edge HVs)
//! - **What kind of edge** (data vs control) via different permutation slots

use crate::HyperVector;
use crate::permutation::PermutationTable;

/// Deterministic seed for data-dependency edge permutation.
const PERM_SEED_DATA: u64 = 0x0A7A_ED6E_0000_0001;
/// Deterministic seed for control-dependency edge permutation.
const PERM_SEED_CTRL: u64 = 0x0C71_ED6E_0000_0002;
/// Deterministic seed for heap-alias edge permutation.
const PERM_SEED_HEAP: u64 = 0x0EA9_A115_0000_0003;

/// Edge type for topology encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeType {
    /// Data dependency (def-use chain).
    Data,
    /// Control dependency.
    Control,
    /// Heap alias (two pointers may reference the same allocation).
    /// **Strongest signal** for UAF / DoubleFree detection.
    HeapAlias,
    /// Sequential execution order within a block.
    Sequential,
}

/// Deterministic seed for sequential edge permutation.
const PERM_SEED_SEQ: u64 = 0x05E9_A115_0000_0004;

impl EdgeType {
    /// Default confidence weight for each edge type.
    ///
    /// Higher weight = more votes in the majority bundle = more influence
    /// on the final subgraph HV.
    ///
    /// - Control = weak (1×) — many instructions are control-dependent, low signal.
    /// - Data = strong (2×) — def-use chains are structurally informative.
    /// - HeapAlias = very strong (4×) — directly encodes the aliasing that
    ///   causes memory corruption bugs.
    #[must_use]
    pub const fn default_weight(self) -> usize {
        match self {
            Self::Control | Self::Sequential => 1,
            Self::Data => 2,
            Self::HeapAlias => 4,
        }
    }
}

/// Topology-aware subgraph encoder.
///
/// Encodes a subgraph (set of node HVs + edges) into a single HV that
/// preserves both the node content AND the graph structure.
pub struct SubgraphEncoder {
    /// Permutation for data edges.
    data_perm: PermutationTable,
    /// Permutation for control edges.
    ctrl_perm: PermutationTable,
    /// Permutation for heap alias edges.
    heap_perm: PermutationTable,
    /// Permutation for sequential edges.
    seq_perm: PermutationTable,
}

impl SubgraphEncoder {
    /// Create a new subgraph encoder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data_perm: PermutationTable::from_seed(PERM_SEED_DATA),
            ctrl_perm: PermutationTable::from_seed(PERM_SEED_CTRL),
            heap_perm: PermutationTable::from_seed(PERM_SEED_HEAP),
            seq_perm: PermutationTable::from_seed(PERM_SEED_SEQ),
        }
    }

    /// Encode a single edge: `bind(src_hv, ρ_type(dst_hv))`.
    ///
    /// The permutation is chosen by edge type, so a data edge A→B produces
    /// a different HV than a control edge A→B.
    #[must_use]
    pub fn encode_edge(
        &self,
        src_hv: &HyperVector,
        dst_hv: &HyperVector,
        edge_type: EdgeType,
    ) -> HyperVector {
        let perm = match edge_type {
            EdgeType::Data => &self.data_perm,
            EdgeType::Control => &self.ctrl_perm,
            EdgeType::HeapAlias => &self.heap_perm,
            EdgeType::Sequential => &self.seq_perm,
        };
        src_hv.bind(perm.apply(dst_hv))
    }

    /// Encode a full subgraph into a single topology-preserving HV.
    ///
    /// # Arguments
    /// - `node_hvs`: HVs for each node in the subgraph.
    /// - `edges`: List of `(src_index, dst_index, edge_type)` where indices
    ///   refer to positions in `node_hvs`.
    ///
    /// # Returns
    /// A single HV that captures both content and topology.
    #[must_use]
    pub fn encode_subgraph(
        &self,
        node_hvs: &[HyperVector],
        edges: &[(usize, usize, EdgeType)],
    ) -> HyperVector {
        if node_hvs.is_empty() {
            return HyperVector::zero();
        }

        // Collect all component HVs: nodes + edges.
        let mut all_hvs: Vec<HyperVector> = Vec::with_capacity(node_hvs.len() + edges.len());

        // 1. Add all node HVs.
        all_hvs.extend_from_slice(node_hvs);

        // 2. Add edge HVs (topology encoding).
        for &(src, dst, etype) in edges {
            if src < node_hvs.len() && dst < node_hvs.len() {
                let edge_hv = self.encode_edge(&node_hvs[src], &node_hvs[dst], etype);
                all_hvs.push(edge_hv);
            }
        }

        // 3. Bundle everything together.
        HyperVector::bundle(&all_hvs)
    }

    /// Encode a subgraph with **weighted bundling**: edges count more than nodes.
    ///
    /// This gives topology extra weight in the final HV, which is important
    /// because vulnerability patterns are primarily defined by how data flows
    /// (edges) rather than what individual instructions do (nodes).
    ///
    /// Each edge HV is included `edge_weight` times in the bundle.
    #[must_use]
    pub fn encode_subgraph_weighted(
        &self,
        node_hvs: &[HyperVector],
        edges: &[(usize, usize, EdgeType)],
        edge_weight: usize,
    ) -> HyperVector {
        if node_hvs.is_empty() {
            return HyperVector::zero();
        }

        let edge_weight = edge_weight.max(1);

        let mut all_hvs: Vec<HyperVector> =
            Vec::with_capacity(node_hvs.len() + edges.len() * edge_weight);

        // Nodes (weight 1).
        all_hvs.extend_from_slice(node_hvs);

        // Edges (weight N — they vote N times in the majority).
        for &(src, dst, etype) in edges {
            if src < node_hvs.len() && dst < node_hvs.len() {
                let edge_hv = self.encode_edge(&node_hvs[src], &node_hvs[dst], etype);
                for _ in 0..edge_weight {
                    all_hvs.push(edge_hv);
                }
            }
        }

        HyperVector::bundle(&all_hvs)
    }

    /// Encode a subgraph with **per-edge-type confidence weights**.
    ///
    /// Each edge type has a different default weight:
    /// - Control = 1× (weak — high fanout, low signal)
    /// - Data = 2× (strong — structural def-use chains)
    /// - HeapAlias = 4× (very strong — pointer aliasing = root cause of memory bugs)
    ///
    /// This is the recommended encoding for vulnerability detection.
    #[must_use]
    pub fn encode_subgraph_confidence(
        &self,
        node_hvs: &[HyperVector],
        edges: &[(usize, usize, EdgeType)],
    ) -> HyperVector {
        if node_hvs.is_empty() {
            return HyperVector::zero();
        }

        // Estimate capacity.
        let edge_votes: usize = edges.iter().map(|&(_, _, e)| e.default_weight()).sum();
        let mut all_hvs: Vec<HyperVector> = Vec::with_capacity(node_hvs.len() + edge_votes);

        // Nodes (weight 1).
        all_hvs.extend_from_slice(node_hvs);

        // Edges with per-type confidence weights.
        for &(src, dst, etype) in edges {
            if src < node_hvs.len() && dst < node_hvs.len() {
                let edge_hv = self.encode_edge(&node_hvs[src], &node_hvs[dst], etype);
                let weight = etype.default_weight();
                for _ in 0..weight {
                    all_hvs.push(edge_hv);
                }
            }
        }

        HyperVector::bundle(&all_hvs)
    }
}

impl Default for SubgraphEncoder {
    fn default() -> Self {
        Self::new()
    }
}
impl std::fmt::Debug for SubgraphEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubgraphEncoder").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_nodes_different_edges_produce_different_hvs() {
        let enc = SubgraphEncoder::new();

        let a = HyperVector::sparse(100);
        let b = HyperVector::sparse(200);
        let c = HyperVector::sparse(300);
        let nodes = [a, b, c];

        // Graph 1: A → B → C (linear chain)
        let edges1 = vec![(0, 1, EdgeType::Data), (1, 2, EdgeType::Data)];

        // Graph 2: A → C, B → C (fan-in)
        let edges2 = vec![(0, 2, EdgeType::Data), (1, 2, EdgeType::Data)];

        let hv1 = enc.encode_subgraph(&nodes, &edges1);
        let hv2 = enc.encode_subgraph(&nodes, &edges2);

        // Same nodes, different topology → different HVs.
        assert_ne!(hv1, hv2);
        // They should share some similarity (same nodes) but not too much.
        let j = hv1.jaccard(hv2);
        assert!(j < 0.8, "topology change should reduce similarity, got {j}");
    }

    #[test]
    fn data_vs_control_edges_produce_different_hvs() {
        let enc = SubgraphEncoder::new();

        let a = HyperVector::sparse(100);
        let b = HyperVector::sparse(200);
        let nodes = [a, b];

        let data_graph = vec![(0, 1, EdgeType::Data)];
        let ctrl_graph = vec![(0, 1, EdgeType::Control)];

        let hv_data = enc.encode_subgraph(&nodes, &data_graph);
        let hv_ctrl = enc.encode_subgraph(&nodes, &ctrl_graph);

        assert_ne!(hv_data, hv_ctrl);
    }

    #[test]
    fn edge_binding_is_asymmetric() {
        let enc = SubgraphEncoder::new();

        let a = HyperVector::sparse(100);
        let b = HyperVector::sparse(200);

        // A → B vs B → A should produce different edge HVs.
        let ab = enc.encode_edge(&a, &b, EdgeType::Data);
        let ba = enc.encode_edge(&b, &a, EdgeType::Data);

        assert_ne!(ab, ba);
    }

    #[test]
    fn similar_topologies_are_similar() {
        let enc = SubgraphEncoder::new();

        // Two very similar graphs: same structure, slightly different node C.
        let a = HyperVector::sparse(100);
        let b = HyperVector::sparse(200);
        let c1 = HyperVector::sparse(300);
        let c2 = HyperVector::sparse(301); // Very slightly different seed

        let edges = vec![(0, 1, EdgeType::Data), (1, 2, EdgeType::Data)];

        let hv1 = enc.encode_subgraph(&[a, b, c1], &edges);
        let hv2 = enc.encode_subgraph(&[a, b, c2], &edges);
        let hv_random = enc.encode_subgraph(
            &[
                HyperVector::sparse(9000),
                HyperVector::sparse(9001),
                HyperVector::sparse(9002),
            ],
            &edges,
        );

        // Similar graphs should be more similar to each other than to random.
        assert!(
            hv1.jaccard(hv2) > hv1.jaccard(hv_random),
            "similar graphs should cluster: sim={:.3}, random={:.3}",
            hv1.jaccard(hv2),
            hv1.jaccard(hv_random),
        );
    }

    #[test]
    fn weighted_encoding_emphasizes_edges() {
        let enc = SubgraphEncoder::new();

        let a = HyperVector::sparse(100);
        let b = HyperVector::sparse(200);
        let nodes = [a, b];
        let edges = vec![(0, 1, EdgeType::Data)];

        let hv_w1 = enc.encode_subgraph_weighted(&nodes, &edges, 1);
        let hv_w3 = enc.encode_subgraph_weighted(&nodes, &edges, 3);

        // Both should be valid HVs.
        assert!(hv_w1.popcount() > 0);
        assert!(hv_w3.popcount() > 0);

        // They should differ because the edge has more "vote" in w3.
        assert_ne!(hv_w1, hv_w3);
    }
}
