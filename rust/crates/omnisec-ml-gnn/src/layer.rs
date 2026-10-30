//! A single GNN layer: Â · (H · W) + b → optional LayerNorm → activation.

use omnisec_json::{FromJson, ToJson};

use crate::error::{GnnError, Result};
use crate::graph_tensor::{CsrView, EdgeType};

/// Epsilon used by LayerNorm.
pub const LN_EPS: f32 = 1e-5;

/// Relative importance of each edge type. Consumed ONLY by
/// `build_normalized_csr`, which bakes it into Â for both training and
/// inference.
#[must_use]
pub fn edge_type_scale(edge_type: EdgeType) -> f32 {
    match edge_type {
        EdgeType::ControlFlow => 1.00,
        EdgeType::DataDependency => 1.20,
        EdgeType::Call => 1.10,
        EdgeType::Return => 0.90,
        EdgeType::SelfLoop => 1.05,
    }
}

/// Activation function. Both `apply` and `deriv` live here so the trainer
/// can never disagree with inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
pub enum Activation {
    ReLU,
    LeakyReLU,
    None,
}

impl Activation {
    #[inline]
    #[must_use]
    pub fn apply(self, x: f32) -> f32 {
        match self {
            Self::ReLU => x.max(0.0),
            Self::LeakyReLU => {
                if x > 0.0 {
                    x
                } else {
                    0.01 * x
                }
            }
            Self::None => x,
        }
    }

    /// Derivative evaluated at the pre-activation `x`.
    #[inline]
    #[must_use]
    pub fn deriv(self, x: f32) -> f32 {
        match self {
            Self::ReLU => {
                if x > 0.0 {
                    1.0
                } else {
                    0.0
                }
            }
            Self::LeakyReLU => {
                if x > 0.0 {
                    1.0
                } else {
                    0.01
                }
            }
            Self::None => 1.0,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReLU => "ReLU",
            Self::LeakyReLU => "LeakyReLU",
            Self::None => "None",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ReLU" => Some(Self::ReLU),
            "LeakyReLU" => Some(Self::LeakyReLU),
            "None" => Some(Self::None),
            _ => None,
        }
    }
}

/// Configuration of one layer.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct LayerConfig {
    pub features_in: usize,
    pub features_out: usize,
    pub activation: Activation,
    /// Dropout rate in [0, 1) — training only.
    pub dropout: f32,
}

impl LayerConfig {
    pub fn validate(&self, index: usize) -> Result<()> {
        if self.features_in == 0 || self.features_out == 0 {
            return Err(GnnError::InvalidConfig(format!(
                "layer {index} has a zero feature dimension"
            )));
        }
        self.features_in
            .checked_mul(self.features_out)
            .ok_or_else(|| GnnError::InvalidConfig(format!("layer {index} dimensions overflow")))?;
        if !self.dropout.is_finite() || !(0.0..1.0).contains(&self.dropout) {
            return Err(GnnError::InvalidConfig(format!(
                "layer {index} has invalid dropout {}",
                self.dropout
            )));
        }
        Ok(())
    }
}

/// Mean and (biased) variance of one feature row — shared by inference and
/// the trainer's forward pass.
#[inline]
pub(crate) fn layer_norm_stats(row: &[f32]) -> (f32, f32) {
    let d = row.len() as f32;
    let mean = row.iter().sum::<f32>() / d;
    let var = row.iter().map(|v| (v - mean) * (v - mean)).sum::<f32>() / d;
    (mean, var)
}

/// A message-passing layer with learned weights.
///
/// `H' = act( LN( Â · (H · W) + b ) )`, where LN is applied only when
/// `norm_gamma`/`norm_beta` are present (v1 weights have none).
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct GnnLayer {
    pub config: LayerConfig,
    /// features_in × features_out, row-major.
    pub weights: Vec<f32>,
    pub bias: Vec<f32>,
    #[json(default)]
    pub norm_gamma: Option<Vec<f32>>,
    #[json(default)]
    pub norm_beta: Option<Vec<f32>>,
}

impl GnnLayer {
    /// Zero-initialised layer (weights are expected to be filled in).
    #[must_use]
    pub fn new(config: LayerConfig) -> Self {
        Self {
            weights: vec![0.0; config.features_in * config.features_out],
            bias: vec![0.0; config.features_out],
            norm_gamma: None,
            norm_beta: None,
            config,
        }
    }

    #[must_use]
    pub fn has_layer_norm(&self) -> bool {
        self.norm_gamma.is_some() && self.norm_beta.is_some()
    }

    /// Allocating forward pass; see [`GnnLayer::forward_into`].
    #[must_use]
    pub fn forward(&self, adj: CsrView<'_>, h_in: &[f32], nodes: usize) -> Vec<f32> {
        let mut out = Vec::new();
        let mut scratch = Vec::new();
        self.forward_into(adj, h_in, nodes, &mut out, &mut scratch);
        out
    }

    /// Allocation-free forward pass. `h_out` receives nodes × features_out;
    /// `scratch` is reused for the dense transform.
    pub fn forward_into(
        &self,
        adj: CsrView<'_>,
        h_in: &[f32],
        nodes: usize,
        h_out: &mut Vec<f32>,
        scratch: &mut Vec<f32>,
    ) {
        let fin = self.config.features_in;
        let fout = self.config.features_out;
        debug_assert_eq!(h_in.len(), nodes * fin, "h_in shape");
        debug_assert_eq!(adj.row_ptr.len(), nodes + 1, "row_ptr shape");
        debug_assert_eq!(adj.col_idx.len(), adj.values.len(), "csr shape");
        debug_assert_eq!(self.weights.len(), fin * fout, "weight shape");

        // 1. Dense transform T = H · W, one pass over every node.
        scratch.clear();
        scratch.resize(nodes * fout, 0.0);
        for (n, out_row) in scratch.chunks_exact_mut(fout).enumerate() {
            let in_row = &h_in[n * fin..(n + 1) * fin];
            for (f_i, &x) in in_row.iter().enumerate() {
                if x == 0.0 {
                    continue; // post-ReLU inputs are sparse
                }
                let w_row = &self.weights[f_i * fout..(f_i + 1) * fout];
                for (o, w) in out_row.iter_mut().zip(w_row) {
                    *o += x * w;
                }
            }
        }
        let transformed = &*scratch;

        // 2. Sparse aggregation, bias, LayerNorm, activation — per node.
        h_out.clear();
        h_out.resize(nodes * fout, 0.0);
        let ln = match (&self.norm_gamma, &self.norm_beta) {
            (Some(g), Some(b)) => Some((g.as_slice(), b.as_slice())),
            _ => None,
        };
        for (i, out_row) in h_out.chunks_exact_mut(fout).enumerate() {
            let (s, e) = (adj.row_ptr[i] as usize, adj.row_ptr[i + 1] as usize);
            for k in s..e {
                let col = adj.col_idx[k] as usize;
                let scale = adj.values[k];
                let src = &transformed[col * fout..(col + 1) * fout];
                for (o, v) in out_row.iter_mut().zip(src) {
                    *o += scale * v;
                }
            }
            for (o, b) in out_row.iter_mut().zip(&self.bias) {
                *o += b;
            }
            if let Some((gamma, beta)) = ln {
                let (mean, var) = layer_norm_stats(out_row);
                let inv_std = 1.0 / (var + LN_EPS).sqrt();
                for ((o, g), b) in out_row.iter_mut().zip(gamma).zip(beta) {
                    *o = (*o - mean) * inv_std * g + b;
                }
            }
            for o in out_row.iter_mut() {
                *o = self.config.activation.apply(*o);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_tensor::Csr;

    fn single_node_adj(w: f32) -> Csr {
        Csr {
            row_ptr: vec![0, 1],
            col_idx: vec![0],
            values: vec![w],
        }
    }

    #[test]
    fn forward_pass_single_node() {
        let mut layer = GnnLayer::new(LayerConfig {
            features_in: 2,
            features_out: 1,
            activation: Activation::None,
            dropout: 0.0,
        });
        layer.weights = vec![1.0, 1.0];
        layer.bias = vec![0.5];
        let adj = single_node_adj(1.0);
        let out = layer.forward(adj.view(), &[3.0, 4.0], 1);
        assert!((out[0] - 7.5).abs() < 1e-5);
    }

    #[test]
    fn layernorm_zero_means_features_and_handles_width_one() {
        let mut layer = GnnLayer::new(LayerConfig {
            features_in: 1,
            features_out: 2,
            activation: Activation::None,
            dropout: 0.0,
        });
        layer.weights = vec![1.0, 3.0];
        layer.norm_gamma = Some(vec![1.0, 1.0]);
        layer.norm_beta = Some(vec![0.0, 0.0]);
        let out = layer.forward(single_node_adj(1.0).view(), &[2.0], 1);
        assert!((out[0] + out[1]).abs() < 1e-4);

        let mut one = GnnLayer::new(LayerConfig {
            features_in: 1,
            features_out: 1,
            activation: Activation::None,
            dropout: 0.0,
        });
        one.weights = vec![5.0];
        one.norm_gamma = Some(vec![2.0]);
        one.norm_beta = Some(vec![0.25]);
        let out = one.forward(single_node_adj(1.0).view(), &[9.0], 1);
        assert!(out[0].is_finite());
        assert!((out[0] - 0.25).abs() < 1e-6, "var = 0 ⇒ output = β");
    }

    #[test]
    fn activation_apply_and_deriv_agree() {
        for act in [Activation::ReLU, Activation::LeakyReLU, Activation::None] {
            for x in [-2.0_f32, -0.5, 0.5, 3.0] {
                let h = 1e-3;
                let numeric = (act.apply(x + h) - act.apply(x - h)) / (2.0 * h);
                assert!((numeric - act.deriv(x)).abs() < 1e-3, "{act:?} at {x}");
            }
        }
    }
}
