//! Graph tensor (CSR) representation and the ONE canonical normalised
//! adjacency builder shared by inference and training.

use omnisec_json::{FromJson, ToJson};

use crate::error::{GnnError, Result};
use crate::layer::edge_type_scale;

/// Type of edge in the code graph. Discriminants are the wire codes used by
/// the FFI and the JSONL dataset.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum EdgeType {
    ControlFlow = 0,
    DataDependency = 1,
    Call = 2,
    Return = 3,
    SelfLoop = 4,
}

impl EdgeType {
    pub const ALL: [EdgeType; 5] = [
        Self::ControlFlow,
        Self::DataDependency,
        Self::Call,
        Self::Return,
        Self::SelfLoop,
    ];

    #[must_use]
    pub const fn code(self) -> u32 {
        self as u32
    }

    #[must_use]
    pub const fn from_code(code: u32) -> Option<Self> {
        match code {
            0 => Some(Self::ControlFlow),
            1 => Some(Self::DataDependency),
            2 => Some(Self::Call),
            3 => Some(Self::Return),
            4 => Some(Self::SelfLoop),
            _ => None,
        }
    }
}

/// Adjacency normalisation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "lowercase")]
pub enum Normalization {
    /// Legacy (v1): Â[i,j] = w(i,j) / |N(i)|, |N(i)| = number of distinct neighbours.
    Row,
    /// GCN-style: Â[i,j] = w(i,j) / sqrt(deg_i · deg_j), deg = row sum of merged
    /// coefficients. **Note:** rows are out-edges of a directed graph, so this is
    /// `D_out^{-1/2} · A · D_out^{-1/2}` — not a symmetric matrix. It is the
    /// definition all shipped v2/v3 weights were trained with and must not change.
    Symmetric,
}

impl Normalization {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Row => "row",
            Self::Symmetric => "symmetric",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "row" => Some(Self::Row),
            "symmetric" => Some(Self::Symmetric),
            _ => None,
        }
    }
}

impl std::fmt::Display for Normalization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-node feature vector. Layout is a wire contract with the Go extractor
/// (`pkg/internal/gnngraph`, slots documented there): 16 opcode buckets,
/// 12 structural scalars, then 8 v3 semantic API/string flags.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct NodeFeatures {
    pub opcode_category: [f32; 16],
    pub operand_count: f32,
    pub is_branch: f32,
    pub is_call: f32,
    pub is_memory_access: f32,
    pub is_comparison: f32,
    pub in_degree: f32,
    pub out_degree: f32,
    pub block_size: f32,
    pub loop_depth: f32,
    pub dominance_score: f32,
    pub is_error_path: f32,
    pub is_entry: f32,
    /// invoke -> *licens* / *billing* (slot 28).
    pub api_license: f32,
    /// invoke -> reflection APIs (slot 29).
    pub api_reflection: f32,
    /// invoke -> class loaders / DexFile (slot 30).
    pub api_dynload: f32,
    /// invoke -> javax/crypto, java/security (slot 31).
    pub api_crypto: f32,
    /// package-signature reads (slot 32).
    pub api_pkg_sig: f32,
    /// System/Runtime.loadLibrary/load (slot 33).
    pub api_native: f32,
    /// const-string with a URI scheme (slot 34).
    pub str_url: f32,
    /// const-string with a license keyword (slot 35).
    pub str_license_kw: f32,
}

impl NodeFeatures {
    /// Total number of features per node (16 opcode buckets + 12 structural
    /// scalars + 8 v3 semantic flags).
    pub const DIMS: usize = 36;

    pub fn write_into(&self, out: &mut Vec<f32>) {
        out.extend_from_slice(&self.opcode_category);
        out.extend_from_slice(&[
            self.operand_count,
            self.is_branch,
            self.is_call,
            self.is_memory_access,
            self.is_comparison,
            self.in_degree,
            self.out_degree,
            self.block_size,
            self.loop_depth,
            self.dominance_score,
            self.is_error_path,
            self.is_entry,
            self.api_license,
            self.api_reflection,
            self.api_dynload,
            self.api_crypto,
            self.api_pkg_sig,
            self.api_native,
            self.str_url,
            self.str_license_kw,
        ]);
    }

    #[must_use]
    pub fn to_vec(&self) -> Vec<f32> {
        let mut v = Vec::with_capacity(Self::DIMS);
        self.write_into(&mut v);
        v
    }
}

/// A code graph in CSR form.
///
/// Row `i` holds the **out-edges** of node `i` (columns = successors). The
/// propagation `out[i] = Σ_j Â[i,j]·h[j]` therefore lets a node aggregate from
/// its successors (against the control-flow direction). This is a deliberate,
/// trained-in property of the shipped weights.
///
/// Stored edge weights are not part of the format: the propagation matrix is
/// recomputed by [`build_normalized_csr`], so callers cannot skew inference.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct GraphTensor {
    pub num_nodes: usize,
    /// CSR row pointers (length = num_nodes + 1, first = 0, non-decreasing).
    pub row_ptr: Vec<u32>,
    /// CSR column indices (length = num_edges, each < num_nodes).
    pub col_idx: Vec<u32>,
    /// Edge types aligned with `col_idx`.
    pub edge_types: Vec<EdgeType>,
    /// Node features, num_nodes × feature_dims, row-major, all finite.
    pub node_features: Vec<f32>,
    pub feature_dims: usize,
}

impl GraphTensor {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            num_nodes: 0,
            row_ptr: vec![0],
            col_idx: Vec::new(),
            edge_types: Vec::new(),
            node_features: Vec::new(),
            feature_dims: NodeFeatures::DIMS,
        }
    }

    #[must_use]
    pub fn num_edges(&self) -> usize {
        self.col_idx.len()
    }

    /// Build from node features and `(src, dst, type)` edges. Edges that
    /// reference nodes outside `features` are dropped. Self-loops are NOT
    /// inserted here — [`build_normalized_csr`] guarantees them.
    #[must_use]
    pub fn from_edges(features: &[NodeFeatures], edges: &[(u32, u32, EdgeType)]) -> Self {
        let n = features.len();
        let mut adj: Vec<Vec<(u32, EdgeType)>> = vec![Vec::new(); n];
        for &(src, dst, et) in edges {
            if (src as usize) < n && (dst as usize) < n {
                adj[src as usize].push((dst, et));
            }
        }
        let mut row_ptr = Vec::with_capacity(n + 1);
        let mut col_idx = Vec::with_capacity(edges.len());
        let mut edge_types = Vec::with_capacity(edges.len());
        row_ptr.push(0u32);
        for neighbours in &mut adj {
            neighbours.sort_by_key(|&(c, et)| (c, et.code()));
            for &(c, et) in neighbours.iter() {
                col_idx.push(c);
                edge_types.push(et);
            }
            row_ptr.push(col_idx.len() as u32);
        }
        let mut node_features = Vec::with_capacity(n * NodeFeatures::DIMS);
        for f in features {
            f.write_into(&mut node_features);
        }
        Self {
            num_nodes: n,
            row_ptr,
            col_idx,
            edge_types,
            node_features,
            feature_dims: NodeFeatures::DIMS,
        }
    }

    /// Check every structural invariant. Called by `predict`, `fit` and the
    /// FFI before any indexing happens.
    pub fn validate(&self) -> Result<()> {
        let n = self.num_nodes;
        let err = |m: String| Err(GnnError::InvalidGraph(m));
        if n > u32::MAX as usize {
            return err(format!("num_nodes {n} exceeds u32 range"));
        }
        if self.row_ptr.len() != n + 1 {
            return err(format!(
                "row_ptr length {} != num_nodes + 1 = {}",
                self.row_ptr.len(),
                n + 1
            ));
        }
        if self.row_ptr[0] != 0 {
            return err(format!("row_ptr[0] must be 0, got {}", self.row_ptr[0]));
        }
        if let Some(pos) = self.row_ptr.windows(2).position(|w| w[0] > w[1]) {
            return err(format!("row_ptr not monotonic at index {pos}"));
        }
        if self.row_ptr[n] as usize != self.col_idx.len() {
            return err(format!(
                "row_ptr tail {} != col_idx length {}",
                self.row_ptr[n],
                self.col_idx.len()
            ));
        }
        if self.edge_types.len() != self.col_idx.len() {
            return err(format!(
                "edge_types length {} != col_idx length {}",
                self.edge_types.len(),
                self.col_idx.len()
            ));
        }
        if let Some(&c) = self.col_idx.iter().find(|&&c| c as usize >= n) {
            return err(format!("column index {c} out of range (num_nodes = {n})"));
        }
        if n > 0 && self.feature_dims == 0 {
            return err("feature_dims must be > 0".to_string());
        }
        let expected = n
            .checked_mul(self.feature_dims)
            .ok_or_else(|| GnnError::InvalidGraph("feature matrix size overflow".to_string()))?;
        if self.node_features.len() != expected {
            return err(format!(
                "node_features length {} != {n} × {} = {expected}",
                self.node_features.len(),
                self.feature_dims
            ));
        }
        if let Some(pos) = self.node_features.iter().position(|v| !v.is_finite()) {
            return err(format!("non-finite feature at flat index {pos}"));
        }
        Ok(())
    }
}

/// Normalised propagation matrix Â in flat CSR form.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Csr {
    pub row_ptr: Vec<u32>,
    pub col_idx: Vec<u32>,
    pub values: Vec<f32>,
}

/// Borrowed view of a [`Csr`] — the shape the SpMM kernels consume.
#[derive(Debug, Clone, Copy)]
pub struct CsrView<'a> {
    pub row_ptr: &'a [u32],
    pub col_idx: &'a [u32],
    pub values: &'a [f32],
}

impl Csr {
    #[must_use]
    pub fn view(&self) -> CsrView<'_> {
        CsrView {
            row_ptr: &self.row_ptr,
            col_idx: &self.col_idx,
            values: &self.values,
        }
    }

    #[must_use]
    pub fn num_rows(&self) -> usize {
        self.row_ptr.len().saturating_sub(1)
    }

    #[must_use]
    pub fn nnz(&self) -> usize {
        self.col_idx.len()
    }

    /// Rebuild Â for `g` in place, reusing this struct's buffers.
    ///
    /// Semantics (frozen — shipped weights depend on them):
    /// * parallel edges between the same `(i, j)` are merged by SUMMING their
    ///   edge-type scales;
    /// * a self-loop with `edge_type_scale(SelfLoop)` is added when the row has
    ///   no `(i, i)` entry of ANY type;
    /// * columns are sorted; input order does not matter;
    /// * normalisation per [`Normalization`].
    ///
    /// `g` must be valid (`GraphTensor::validate`); out-of-range columns are
    /// skipped defensively in release builds.
    pub fn build_into(&mut self, g: &GraphTensor, normalization: Normalization) {
        debug_assert!(
            g.validate().is_ok(),
            "build_into called with an invalid graph"
        );
        let n = g.num_nodes;
        self.row_ptr.clear();
        self.col_idx.clear();
        self.values.clear();
        self.row_ptr.reserve(n + 1);
        self.col_idx.reserve(g.col_idx.len() + n);
        self.values.reserve(g.col_idx.len() + n);
        self.row_ptr.push(0);

        let symmetric = normalization == Normalization::Symmetric;
        let mut deg: Vec<f32> = if symmetric {
            Vec::with_capacity(n)
        } else {
            Vec::new()
        };
        let mut row: Vec<(u32, f32)> = Vec::new();

        for i in 0..n {
            let start = g.row_ptr[i] as usize;
            let end = g.row_ptr[i + 1] as usize;
            row.clear();
            for k in start..end {
                let col = g.col_idx[k];
                if (col as usize) < n {
                    row.push((col, edge_type_scale(g.edge_types[k])));
                }
            }
            let self_col = i as u32;
            if !row.iter().any(|&(c, _)| c == self_col) {
                row.push((self_col, edge_type_scale(EdgeType::SelfLoop)));
            }
            row.sort_unstable_by_key(|&(c, _)| c);

            let row_start = self.col_idx.len();
            for &(c, s) in &row {
                if self.col_idx.len() > row_start && *self.col_idx.last().unwrap() == c {
                    *self.values.last_mut().unwrap() += s;
                } else {
                    self.col_idx.push(c);
                    self.values.push(s);
                }
            }
            if symmetric {
                deg.push(self.values[row_start..].iter().sum());
            }
            self.row_ptr.push(self.col_idx.len() as u32);
        }

        if symmetric {
            let inv_sqrt: Vec<f32> = deg
                .iter()
                .map(|&d| if d > 0.0 { 1.0 / d.sqrt() } else { 0.0 })
                .collect();
            for i in 0..n {
                let (s, e) = (self.row_ptr[i] as usize, self.row_ptr[i + 1] as usize);
                for k in s..e {
                    self.values[k] *= inv_sqrt[i] * inv_sqrt[self.col_idx[k] as usize];
                }
            }
        } else {
            for i in 0..n {
                let (s, e) = (self.row_ptr[i] as usize, self.row_ptr[i + 1] as usize);
                if s < e {
                    let inv = 1.0 / (e - s) as f32;
                    for v in &mut self.values[s..e] {
                        *v *= inv;
                    }
                }
            }
        }
    }
}

/// Build Â for `g`. See [`Csr::build_into`] for the exact semantics.
#[must_use]
pub fn build_normalized_csr(g: &GraphTensor, normalization: Normalization) -> Csr {
    let mut csr = Csr::default();
    csr.build_into(g, normalization);
    csr
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feats(n: usize) -> Vec<NodeFeatures> {
        vec![
            NodeFeatures {
                opcode_category: [0.0; 16],
                operand_count: 0.2,
                is_branch: 0.0,
                is_call: 0.0,
                is_memory_access: 0.0,
                is_comparison: 0.0,
                in_degree: 0.1,
                out_degree: 0.1,
                block_size: 0.5,
                loop_depth: 0.0,
                dominance_score: 0.5,
                is_error_path: 0.0,
                is_entry: 0.0,
                api_license: 0.0,
                api_reflection: 0.0,
                api_dynload: 0.0,
                api_crypto: 0.0,
                api_pkg_sig: 0.0,
                api_native: 0.0,
                str_url: 0.0,
                str_license_kw: 0.0,
            };
            n
        ]
    }

    #[test]
    fn empty_graph_is_valid() {
        let g = GraphTensor::empty();
        assert!(g.validate().is_ok());
        assert_eq!(g.num_edges(), 0);
    }

    #[test]
    fn validate_catches_every_structural_fault() {
        let ok = GraphTensor::from_edges(&feats(3), &[(0, 1, EdgeType::ControlFlow)]);
        assert!(ok.validate().is_ok());

        let mut g = ok.clone();
        g.row_ptr = vec![0, 2, 1, 1];
        assert!(g.validate().is_err(), "non-monotonic row_ptr");

        let mut g = ok.clone();
        g.row_ptr[0] = 1;
        assert!(g.validate().is_err(), "row_ptr[0] != 0");

        let mut g = ok.clone();
        g.col_idx[0] = 7;
        assert!(g.validate().is_err(), "column out of range");

        let mut g = ok.clone();
        g.edge_types.pop();
        assert!(g.validate().is_err(), "edge_types misaligned");

        let mut g = ok.clone();
        g.node_features[3] = f32::NAN;
        assert!(g.validate().is_err(), "NaN feature");

        let mut g = ok;
        g.feature_dims = 27;
        assert!(g.validate().is_err(), "feature length mismatch");
    }

    #[test]
    fn parallel_edges_merge_and_self_loops_are_added() {
        let g = GraphTensor::from_edges(
            &feats(2),
            &[
                (0, 1, EdgeType::ControlFlow),
                (0, 1, EdgeType::DataDependency),
            ],
        );
        let adj = build_normalized_csr(&g, Normalization::Symmetric);
        assert_eq!(adj.row_ptr, vec![0, 2, 3]);
        // deg0 = 1.05 (self) + 2.2 (merged), deg1 = 1.05 (self only)
        let expected = 2.2 / (3.25_f32 * 1.05).sqrt();
        assert!((adj.values[1] - expected).abs() < 1e-6);
    }

    #[test]
    fn unsorted_input_matches_sorted_input() {
        let sorted = GraphTensor::from_edges(
            &feats(4),
            &[
                (0, 1, EdgeType::Call),
                (0, 2, EdgeType::ControlFlow),
                (0, 2, EdgeType::DataDependency),
                (0, 3, EdgeType::Return),
            ],
        );
        let mut unsorted = sorted.clone();
        unsorted.col_idx = vec![3, 2, 1, 2];
        unsorted.edge_types = vec![
            EdgeType::Return,
            EdgeType::DataDependency,
            EdgeType::Call,
            EdgeType::ControlFlow,
        ];
        for norm in [Normalization::Row, Normalization::Symmetric] {
            assert_eq!(
                build_normalized_csr(&sorted, norm),
                build_normalized_csr(&unsorted, norm)
            );
        }
    }

    #[test]
    fn row_mode_divides_by_distinct_neighbours() {
        let g = GraphTensor::from_edges(
            &feats(3),
            &[
                (0, 1, EdgeType::ControlFlow),
                (0, 1, EdgeType::Call),
                (0, 2, EdgeType::ControlFlow),
            ],
        );
        let adj = build_normalized_csr(&g, Normalization::Row);
        // row 0: {0: 1.05 self, 1: 1.0 + 1.1, 2: 1.0} / 3 distinct
        assert_eq!(adj.row_ptr[1], 3);
        assert!((adj.values[1] - 2.1 / 3.0).abs() < 1e-6);
        assert!((adj.values[2] - 1.0 / 3.0).abs() < 1e-6);
    }

    #[test]
    fn explicit_cf_self_edge_is_not_doubled() {
        // A block that jumps to itself: (i, i) of type ControlFlow — must count
        // as the self entry (scale 1.0), not 1.0 + 1.05.
        let g = GraphTensor::from_edges(&feats(1), &[(0, 0, EdgeType::ControlFlow)]);
        let adj = build_normalized_csr(&g, Normalization::Symmetric);
        assert_eq!(adj.nnz(), 1);
        assert!((adj.values[0] - 1.0).abs() < 1e-6); // 1.0 / sqrt(1.0 · 1.0)
    }
}
