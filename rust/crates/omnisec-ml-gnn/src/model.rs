//! Stacked GNN layers + readout + classifier.

use omnisec_json::{FromJson, ToJson};

use crate::error::{GnnError, Result};
use crate::graph_tensor::{GraphTensor, Normalization, build_normalized_csr};
use crate::layer::{Activation, GnnLayer, LayerConfig};

/// Graph readout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToJson, FromJson)]
#[json(rename_all = "lowercase")]
pub enum Readout {
    Mean,
    Max,
    /// concat[mean ‖ max] — embedding width doubles.
    MeanMax,
}

impl Readout {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mean => "mean",
            Self::Max => "max",
            Self::MeanMax => "meanmax",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mean" => Some(Self::Mean),
            "max" => Some(Self::Max),
            "meanmax" => Some(Self::MeanMax),
            _ => None,
        }
    }

    #[must_use]
    pub const fn width_multiplier(self) -> usize {
        match self {
            Self::MeanMax => 2,
            _ => 1,
        }
    }
}

fn legacy_normalization() -> Normalization {
    // v1 weight files predate the field and were trained with row mode.
    Normalization::Row
}

/// Model architecture.
#[derive(Debug, Clone, PartialEq, ToJson, FromJson)]
pub struct ModelConfig {
    pub layers: Vec<LayerConfig>,
    pub num_classes: usize,
    pub readout: Readout,
    #[json(default = "legacy_normalization")]
    pub normalization: Normalization,
    /// Residual skips between equal-width consecutive HIDDEN layers (li > 0).
    #[json(default)]
    pub residual: bool,
}

impl Default for ModelConfig {
    /// Inference default "v2": 36 → 128 → 128 → 64, LN, residual, symmetric, meanmax.
    fn default() -> Self {
        Self {
            layers: vec![
                LayerConfig {
                    features_in: 36,
                    features_out: 128,
                    activation: Activation::ReLU,
                    dropout: 0.1,
                },
                LayerConfig {
                    features_in: 128,
                    features_out: 128,
                    activation: Activation::ReLU,
                    dropout: 0.1,
                },
                LayerConfig {
                    features_in: 128,
                    features_out: 64,
                    activation: Activation::ReLU,
                    dropout: 0.0,
                },
            ],
            num_classes: crate::taxonomy::NUM_CLASSES,
            readout: Readout::MeanMax,
            normalization: Normalization::Symmetric,
            residual: true,
        }
    }
}

impl ModelConfig {
    /// Training default "v3": 36 → 128 → 128 → 128 → 96 (embedding 192).
    #[must_use]
    pub fn dex_v3() -> Self {
        Self {
            layers: vec![
                LayerConfig {
                    features_in: 36,
                    features_out: 128,
                    activation: Activation::ReLU,
                    dropout: 0.15,
                },
                LayerConfig {
                    features_in: 128,
                    features_out: 128,
                    activation: Activation::ReLU,
                    dropout: 0.15,
                },
                LayerConfig {
                    features_in: 128,
                    features_out: 128,
                    activation: Activation::ReLU,
                    dropout: 0.10,
                },
                LayerConfig {
                    features_in: 128,
                    features_out: 96,
                    activation: Activation::ReLU,
                    dropout: 0.0,
                },
            ],
            num_classes: crate::taxonomy::NUM_CLASSES,
            readout: Readout::MeanMax,
            normalization: Normalization::Symmetric,
            residual: true,
        }
    }

    #[must_use]
    pub fn input_dims(&self) -> usize {
        self.layers.first().map_or(0, |l| l.features_in)
    }

    #[must_use]
    pub fn last_hidden_dims(&self) -> usize {
        self.layers.last().map_or(0, |l| l.features_out)
    }

    /// Width of the graph embedding fed into the classifier.
    #[must_use]
    pub fn embedding_dims(&self) -> usize {
        self.last_hidden_dims() * self.readout.width_multiplier()
    }

    /// Does layer `li` add the output of layer `li - 1`? Shared by trainer and
    /// inference — the ONLY definition of the residual topology.
    #[must_use]
    pub fn has_residual(&self, li: usize) -> bool {
        self.residual
            && li > 0
            && li < self.layers.len()
            && self.layers[li].features_out == self.layers[li - 1].features_out
    }

    pub fn validate(&self) -> Result<()> {
        if self.layers.is_empty() {
            return Err(GnnError::InvalidConfig(
                "model must contain at least one layer".into(),
            ));
        }
        if self.num_classes == 0 {
            return Err(GnnError::InvalidConfig("num_classes must be > 0".into()));
        }
        for (i, l) in self.layers.iter().enumerate() {
            l.validate(i)?;
            if i > 0 && l.features_in != self.layers[i - 1].features_out {
                return Err(GnnError::InvalidConfig(format!(
                    "layer {i} input {} != previous output {}",
                    l.features_in,
                    self.layers[i - 1].features_out
                )));
            }
        }
        self.embedding_dims()
            .checked_mul(self.num_classes)
            .ok_or_else(|| GnnError::InvalidConfig("classifier dimensions overflow".into()))?;
        Ok(())
    }
}

/// Inference result.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct Prediction {
    pub class_probs: Vec<f32>,
    pub predicted_class: usize,
    pub confidence: f32,
    /// L2 norm of each node's final features (empty when not requested).
    pub node_attention: Vec<f32>,
}

/// Read-only, `Send + Sync` model — concurrent `predict` calls are safe.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct GnnModel {
    pub config: ModelConfig,
    pub layers: Vec<GnnLayer>,
    /// embedding_dims × num_classes, row-major.
    pub classifier_weights: Vec<f32>,
    pub classifier_bias: Vec<f32>,
}

impl GnnModel {
    /// Deterministic (non-trained) model for tests and smoke runs. The result
    /// is only valid if `config` is — invalid configs return `Err` instead of
    /// panicking.
    pub fn new(config: ModelConfig) -> Result<Self> {
        crate::weights::WeightStore::dummy(config).to_model()
    }

    /// Run inference. Errors on structurally invalid graphs, empty graphs and
    /// feature-width mismatches instead of panicking or returning garbage.
    pub fn predict(&self, graph: &GraphTensor) -> Result<Prediction> {
        self.predict_impl(graph, true)
    }

    /// Like [`GnnModel::predict`] without per-node attention (FFI hot path).
    pub fn predict_no_attention(&self, graph: &GraphTensor) -> Result<Prediction> {
        self.predict_impl(graph, false)
    }

    fn predict_impl(&self, graph: &GraphTensor, want_attention: bool) -> Result<Prediction> {
        graph.validate()?;
        let n = graph.num_nodes;
        if n == 0 {
            return Err(GnnError::InvalidGraph(
                "cannot classify an empty graph".into(),
            ));
        }
        let in_dims = self.config.input_dims();
        if graph.feature_dims != in_dims {
            return Err(GnnError::InvalidGraph(format!(
                "graph feature_dims {} != model input {in_dims}",
                graph.feature_dims
            )));
        }

        let adj = build_normalized_csr(graph, self.config.normalization);
        let view = adj.view();

        let mut h: Vec<f32> = Vec::new();
        let mut out_buf: Vec<f32> = Vec::new();
        let mut scratch: Vec<f32> = Vec::new();
        for (li, layer) in self.layers.iter().enumerate() {
            let input: &[f32] = if li == 0 { &graph.node_features } else { &h };
            layer.forward_into(view, input, n, &mut out_buf, &mut scratch);
            if self.config.has_residual(li) {
                for (o, p) in out_buf.iter_mut().zip(input) {
                    *o += *p;
                }
            }
            std::mem::swap(&mut h, &mut out_buf);
        }
        let dims = self.config.last_hidden_dims();

        let node_attention = if want_attention {
            h.chunks_exact(dims)
                .map(|r| r.iter().map(|x| x * x).sum::<f32>().sqrt())
                .collect()
        } else {
            Vec::new()
        };

        let mut embedding = Vec::with_capacity(self.config.embedding_dims());
        readout_into(self.config.readout, &h, n, dims, &mut embedding, None);
        let mut logits = Vec::with_capacity(self.config.num_classes);
        logits_into(
            &embedding,
            &self.classifier_weights,
            &self.classifier_bias,
            self.config.num_classes,
            &mut logits,
        );
        let class_probs = softmax(&logits);
        let predicted_class = argmax(&class_probs);
        let confidence = class_probs.get(predicted_class).copied().unwrap_or(0.0);

        Ok(Prediction {
            class_probs,
            predicted_class,
            confidence,
            node_attention,
        })
    }
}

/// Index of the maximum (first on ties; 0 for empty).
#[must_use]
pub(crate) fn argmax(v: &[f32]) -> usize {
    v.iter()
        .enumerate()
        .fold((0, f32::NEG_INFINITY), |(bi, bv), (i, &x)| {
            if x > bv { (i, x) } else { (bi, bv) }
        })
        .0
}

/// Pool node features into a graph embedding. `argmax` (if given) receives the
/// node index that produced each max — needed by the trainer's backward pass.
pub(crate) fn readout_into(
    readout: Readout,
    h: &[f32],
    nodes: usize,
    dims: usize,
    out: &mut Vec<f32>,
    mut argmax: Option<&mut Vec<usize>>,
) {
    out.clear();
    if matches!(readout, Readout::Mean | Readout::MeanMax) {
        let start = out.len();
        out.resize(start + dims, 0.0);
        for row in h.chunks_exact(dims) {
            for (o, v) in out[start..].iter_mut().zip(row) {
                *o += v;
            }
        }
        let inv = 1.0 / nodes.max(1) as f32;
        for o in &mut out[start..] {
            *o *= inv;
        }
    }
    if matches!(readout, Readout::Max | Readout::MeanMax) {
        let start = out.len();
        out.resize(start + dims, f32::NEG_INFINITY);
        if let Some(am) = argmax.as_mut() {
            am.clear();
            am.resize(dims, 0);
        }
        for (i, row) in h.chunks_exact(dims).enumerate() {
            for (d, &v) in row.iter().enumerate() {
                if v > out[start + d] {
                    out[start + d] = v;
                    if let Some(am) = argmax.as_mut() {
                        am[d] = i;
                    }
                }
            }
        }
    }
}

/// `out = emb · W + b`.
pub(crate) fn logits_into(emb: &[f32], w: &[f32], b: &[f32], classes: usize, out: &mut Vec<f32>) {
    out.clear();
    out.extend_from_slice(b);
    for (f, &e) in emb.iter().enumerate() {
        if e == 0.0 {
            continue;
        }
        let row = &w[f * classes..(f + 1) * classes];
        for (o, wv) in out.iter_mut().zip(row) {
            *o += e * wv;
        }
    }
}

/// Numerically stable softmax that never produces NaN: `+inf` logits split the
/// mass, an all-non-finite input degrades to uniform.
#[must_use]
pub(crate) fn softmax(logits: &[f32]) -> Vec<f32> {
    if logits.is_empty() {
        return Vec::new();
    }
    let infs = logits.iter().filter(|v| **v == f32::INFINITY).count();
    if infs > 0 {
        let share = 1.0 / infs as f32;
        return logits
            .iter()
            .map(|v| if *v == f32::INFINITY { share } else { 0.0 })
            .collect();
    }
    let max = logits
        .iter()
        .copied()
        .filter(|v| v.is_finite())
        .fold(f32::NEG_INFINITY, f32::max);
    if !max.is_finite() {
        return vec![1.0 / logits.len() as f32; logits.len()];
    }
    let exps: Vec<f32> = logits
        .iter()
        .map(|&x| if x.is_finite() { (x - max).exp() } else { 0.0 })
        .collect();
    let sum: f32 = exps.iter().sum();
    if !sum.is_finite() || sum <= 0.0 {
        return vec![1.0 / logits.len() as f32; logits.len()];
    }
    exps.iter().map(|&e| e / sum).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::float_cmp)]
    use super::*;
    use crate::graph_tensor::{EdgeType, NodeFeatures};

    pub(crate) fn small_graph() -> GraphTensor {
        let features = vec![
            NodeFeatures {
                opcode_category: [0.1; 16],
                operand_count: 0.5,
                is_branch: 0.0,
                is_call: 1.0,
                is_memory_access: 0.0,
                is_comparison: 0.0,
                in_degree: 0.2,
                out_degree: 0.2,
                block_size: 0.3,
                loop_depth: 0.0,
                dominance_score: 0.5,
                is_error_path: 0.0,
                is_entry: 1.0,
                api_license: 0.0,
                api_reflection: 0.0,
                api_dynload: 0.0,
                api_crypto: 0.0,
                api_pkg_sig: 0.0,
                api_native: 0.0,
                str_url: 0.0,
                str_license_kw: 0.0,
            };
            4
        ];
        GraphTensor::from_edges(
            &features,
            &[
                (0, 1, EdgeType::ControlFlow),
                (1, 2, EdgeType::DataDependency),
                (2, 3, EdgeType::Call),
            ],
        )
    }

    #[test]
    fn default_and_v3_configs_are_valid() {
        assert!(ModelConfig::default().validate().is_ok());
        assert!(ModelConfig::dex_v3().validate().is_ok());
        let m = GnnModel::new(ModelConfig::default()).unwrap();
        assert_eq!(m.classifier_weights.len(), 128 * 8);
    }

    #[test]
    fn invalid_config_is_err_not_panic() {
        let mut cfg = ModelConfig::default();
        cfg.layers.clear();
        assert!(GnnModel::new(cfg).is_err());
        let mut cfg = ModelConfig::default();
        cfg.layers[1].features_in += 1;
        assert!(GnnModel::new(cfg).is_err());
    }

    #[test]
    fn predict_rejects_empty_and_mismatched_graphs() {
        let model = GnnModel::new(ModelConfig::default()).unwrap();
        assert!(model.predict(&GraphTensor::empty()).is_err());
        let mut g = small_graph();
        g.feature_dims = 27;
        g.node_features.truncate(4 * 27);
        assert!(model.predict(&g).is_err());
        let mut g = small_graph();
        g.col_idx[0] = 99;
        assert!(model.predict(&g).is_err());
    }

    #[test]
    fn predict_produces_valid_distribution() {
        for cfg in [ModelConfig::default(), ModelConfig::dex_v3()] {
            let model = GnnModel::new(cfg).unwrap();
            let pred = model.predict(&small_graph()).unwrap();
            assert_eq!(pred.class_probs.len(), 8);
            let sum: f32 = pred.class_probs.iter().sum();
            assert!((sum - 1.0).abs() < 1e-4);
            assert!(pred.class_probs.iter().all(|p| p.is_finite()));
            assert_eq!(pred.node_attention.len(), 4);
            assert!(
                model
                    .predict_no_attention(&small_graph())
                    .unwrap()
                    .node_attention
                    .is_empty()
            );
        }
    }

    #[test]
    fn residual_never_applies_to_first_layer() {
        let cfg = ModelConfig {
            layers: vec![
                LayerConfig {
                    features_in: 36,
                    features_out: 36,
                    activation: Activation::ReLU,
                    dropout: 0.0,
                },
                LayerConfig {
                    features_in: 36,
                    features_out: 36,
                    activation: Activation::ReLU,
                    dropout: 0.0,
                },
            ],
            residual: true,
            ..ModelConfig::default()
        };
        assert!(!cfg.has_residual(0));
        assert!(cfg.has_residual(1));
        assert!(!cfg.has_residual(2));
    }

    #[test]
    fn config_serde_is_backward_compatible_with_v1_json() {
        let v1 = r#"{"layers":[{"features_in":28,"features_out":16,"activation":"ReLU","dropout":0.0}],
                     "num_classes":8,"readout":"mean"}"#;
        let cfg: ModelConfig = omnisec_json::from_json_str(v1).unwrap();
        assert_eq!(cfg.normalization, Normalization::Row);
        assert!(!cfg.residual);
        assert_eq!(cfg.readout, Readout::Mean);
        let v2 = omnisec_json::to_json_string(&ModelConfig::default());
        assert!(v2.contains("\"meanmax\"") && v2.contains("\"symmetric\""));
    }

    #[test]
    fn softmax_edge_cases() {
        assert_eq!(
            softmax(&[f32::NAN, f32::NEG_INFINITY, 2.0]),
            vec![0.0, 0.0, 1.0]
        );
        assert_eq!(
            softmax(&[f32::INFINITY, 1.0, f32::INFINITY]),
            vec![0.5, 0.0, 0.5]
        );
        assert_eq!(softmax(&[f32::NAN, f32::NEG_INFINITY]), vec![0.5, 0.5]);
        let s: f32 = softmax(&[2.0, 1.0, 0.1, -3.0, 5.0]).iter().sum();
        assert!((s - 1.0).abs() < 1e-5);
    }

    #[test]
    fn readout_meanmax_reports_argmax() {
        let h = [1.0, 5.0, 3.0, 2.0, 0.0, 9.0]; // 3 nodes × 2 dims
        let mut out = Vec::new();
        let mut am = Vec::new();
        readout_into(Readout::MeanMax, &h, 3, 2, &mut out, Some(&mut am));
        assert_eq!(out, vec![4.0 / 3.0, 16.0 / 3.0, 3.0, 9.0]);
        assert_eq!(am, vec![1, 2]);
    }
}
