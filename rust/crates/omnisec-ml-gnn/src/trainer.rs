//! GNN trainer — supervised back-propagation for the OmniSec GNN engine.
//!
//! The inference path (`model.rs`, `layer.rs`) is read-only: it loads pretrained
//! [`WeightStore`] weights and runs a forward pass. This module adds the
//! *learning* half so the same model architecture can be trained end-to-end from
//! a labelled graph dataset and exported straight back into a [`WeightStore`].
//!
//! The forward maths is identical to [`GnnModel::predict`]:
//!
//! ```text
//! per layer:   H' = act( LN( A_hat . (H . W) + b ) )   (+ residual, + dropout)
//! readout:     g  = concat[mean_pool, max_pool](H_last)   (or mean / max)
//! classifier:  logits = g . Wc + bc ; probs = softmax(logits)
//! ```
//!
//! `A_hat` follows `ModelConfig::normalization`: "row" reproduces the legacy
//! row-normalised, type-scaled adjacency; "symmetric" applies the standard GCN
//! rule D^-1/2 . Â . D^-1/2 with the edge-type scale baked in, exactly like
//! `GnnModel::predict`. Because the forward pass matches, weights trained here
//! reproduce identical predictions once serialised and reloaded through
//! [`WeightStore::to_model`].
//!
//! Training upgrades over the v1 trainer:
//! - **LayerNorm** is trained on every layer (γ/β exported per layer);
//! - **residual connections** between equal-width layers (per config);
//! - **dropout** on hidden activations (inverted dropout, per-layer rate);
//! - **focal loss** (γ configurable) with **inverse-frequency class weights**
//!   so rare vulnerability classes are not drowned out by the "other" class;
//! - **AdamW** with decoupled weight decay, **linear warmup + cosine decay**,
//!   and **global gradient-norm clipping**;
//! - **early stopping** on validation macro-F1 with best-weights restore.

use omnisec_json::{FromJson, ToJson};

use crate::graph_tensor::{GraphTensor, Normalization, build_normalized_csr};
use crate::layer::{Activation, LN_EPS};
use crate::model::{GnnModel, ModelConfig};
use crate::weights::{
    LayerWeights, FEATURE_SCHEMA_VERSION, WEIGHT_FORMAT_VERSION, WeightMetadata, WeightStore,
};

/// One labelled training example: a graph and its ground-truth vulnerability
/// class index (0..num_classes).
#[derive(Debug, Clone)]
pub struct Example {
    pub graph: GraphTensor,
    pub label: usize,
}

fn default_focal_gamma() -> f32 {
    2.0
}
fn default_warmup_epochs() -> usize {
    5
}
fn default_grad_clip() -> f32 {
    5.0
}
fn default_patience() -> usize {
    12
}
fn default_class_weighting() -> bool {
    true
}
fn default_shuffle_split() -> bool {
    true
}
fn default_explicit_val() -> usize {
    0
}

/// Hyper-parameters for a training run.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct TrainConfig {
    pub epochs: usize,
    pub batch_size: usize,
    pub learning_rate: f32,
    pub weight_decay: f32,
    pub val_fraction: f32,
    pub seed: u64,
    /// Focal-loss focusing parameter; 0.0 degrades to plain cross-entropy.
    #[json(default = "default_focal_gamma")]
    pub focal_gamma: f32,
    /// Linear LR warmup epochs before cosine decay begins.
    #[json(default = "default_warmup_epochs")]
    pub warmup_epochs: usize,
    /// Global gradient-norm clip; 0.0 disables clipping.
    #[json(default = "default_grad_clip")]
    pub grad_clip: f32,
    /// Stop after this many epochs without validation macro-F1 improvement;
    /// 0 disables early stopping.
    #[json(default = "default_patience")]
    pub early_stop_patience: usize,
    /// Weight the loss by inverse class frequency (mean-normalised).
    #[json(default = "default_class_weighting")]
    pub class_weighting: bool,
    /// Shuffle examples before the train/val split. Set false when the caller
    /// has already ordered examples (e.g. a by-APK grouped split) and wants the
    /// first `explicit_val` examples used verbatim as validation.
    #[json(default = "default_shuffle_split")]
    pub shuffle_split: bool,
    /// If > 0, use exactly this many leading examples as validation instead of
    /// `val_fraction`. Pair with `shuffle_split=false` for a grouped split.
    #[json(default = "default_explicit_val")]
    pub explicit_val: usize,
}

impl Default for TrainConfig {
    fn default() -> Self {
        Self {
            epochs: 60,
            batch_size: 16,
            learning_rate: 5e-3,
            weight_decay: 1e-4,
            val_fraction: 0.2,
            seed: 1337,
            focal_gamma: default_focal_gamma(),
            warmup_epochs: default_warmup_epochs(),
            grad_clip: default_grad_clip(),
            early_stop_patience: default_patience(),
            class_weighting: default_class_weighting(),
            shuffle_split: default_shuffle_split(),
            explicit_val: default_explicit_val(),
        }
    }
}

/// Per-epoch metrics.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct EpochStat {
    pub epoch: usize,
    pub train_loss: f32,
    pub train_acc: f32,
    pub val_acc: f32,
    /// Macro-averaged F1 over the validation split.
    #[json(default)]
    pub val_macro_f1: f32,
    /// Learning rate used for this epoch (after warmup / cosine schedule).
    #[json(default)]
    pub lr: f32,
}

/// Result of a [`Trainer::fit`] run.
///
/// The `best_*` fields describe the epoch whose weights were RESTORED into
/// the trainer (highest validation macro-F1) — use these for exported weight
/// metadata. The last entry of `stats` may be a later, worse epoch.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct FitReport {
    /// Per-epoch statistics, in training order.
    pub stats: Vec<EpochStat>,
    /// 1-based epoch number of the restored weights (0 if no epoch ran).
    pub best_epoch: usize,
    /// Validation accuracy at `best_epoch`.
    pub best_val_acc: f32,
    /// Validation macro-F1 at `best_epoch`.
    pub best_val_macro_f1: f32,
    /// Number of training examples (validation split excluded).
    pub train_examples: usize,
    /// Number of validation examples.
    pub val_examples: usize,
}

/// Sparse normalised adjacency — the same `A_hat` the inference forward pass
/// aggregates over, in either "row" or "symmetric" mode.
struct Adjacency {
    n: usize,
    /// rows[i] = list of (col, weight) contributing to node i.
    rows: Vec<Vec<(usize, f32)>>,
}

impl Adjacency {
    fn from_graph(g: &GraphTensor, normalization: Normalization) -> Self {
        // Delegate to the ONE canonical builder shared with
        // `GnnModel::predict` — multi-edge merging, self-loops and
        // normalisation live in a single place, so training and inference
        // can never diverge again.
        let csr = build_normalized_csr(g, normalization);
        let n = g.num_nodes;
        let mut rows: Vec<Vec<(usize, f32)>> = vec![Vec::new(); n];
        for i in 0..n {
            let (s, e) = (csr.row_ptr[i] as usize, csr.row_ptr[i + 1] as usize);
            for k in s..e {
                rows[i].push((csr.col_idx[k] as usize, csr.values[k]));
            }
        }
        Self { n, rows }
    }

    /// out[i] = sum_j A[i,j] * x[j]  (row-major x is n x dims).
    fn matvec(&self, x: &[f32], dims: usize) -> Vec<f32> {
        let mut out = vec![0.0_f32; self.n * dims];
        for i in 0..self.n {
            for &(col, w) in &self.rows[i] {
                for d in 0..dims {
                    out[i * dims + d] += w * x[col * dims + d];
                }
            }
        }
        out
    }

    /// out[j] = sum_i A[i,j] * x[i]  (transpose product, for the backward pass).
    fn matvec_t(&self, x: &[f32], dims: usize) -> Vec<f32> {
        let mut out = vec![0.0_f32; self.n * dims];
        for i in 0..self.n {
            for &(col, w) in &self.rows[i] {
                for d in 0..dims {
                    out[col * dims + d] += w * x[i * dims + d];
                }
            }
        }
        out
    }
}

// Dense matmul helper (row-major). A: rows x k, B: k x cols.
fn matmul(a: &[f32], b: &[f32], rows: usize, k: usize, cols: usize) -> Vec<f32> {
    let mut out = vec![0.0_f32; rows * cols];
    for r in 0..rows {
        for kk in 0..k {
            let av = a[r * k + kk];
            if av == 0.0 {
                continue;
            }
            for c in 0..cols {
                out[r * cols + c] += av * b[kk * cols + c];
            }
        }
    }
    out
}

fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|&x| (x - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    exps.iter().map(|&e| e / sum).collect()
}

/// Learnable parameters, laid out to match [`WeightStore`] exactly.
#[derive(Clone)]
struct Params {
    layer_w: Vec<Vec<f32>>, // [layer][fin*fout], row-major (fin-major)
    layer_b: Vec<Vec<f32>>, // [layer][fout]
    norm_g: Vec<Vec<f32>>,  // [layer][fout] LayerNorm gamma
    norm_b: Vec<Vec<f32>>,  // [layer][fout] LayerNorm beta
    clf_w: Vec<f32>,        // [emb*num_classes], row-major (emb-major)
    clf_b: Vec<f32>,        // [num_classes]
}

impl Params {
    fn zeros_like(cfg: &ModelConfig) -> Self {
        let mut layer_w = Vec::new();
        let mut layer_b = Vec::new();
        let mut norm_g = Vec::new();
        let mut norm_b = Vec::new();
        for l in &cfg.layers {
            layer_w.push(vec![0.0; l.features_in * l.features_out]);
            layer_b.push(vec![0.0; l.features_out]);
            norm_g.push(vec![0.0; l.features_out]);
            norm_b.push(vec![0.0; l.features_out]);
        }
        let emb = cfg.embedding_dims();
        Self {
            layer_w,
            layer_b,
            norm_g,
            norm_b,
            clf_w: vec![0.0; emb * cfg.num_classes],
            clf_b: vec![0.0; cfg.num_classes],
        }
    }

    /// Reset all values to zero (reused batch accumulator).
    fn zero(&mut self) {
        self.for_each_slice_mut(|v| {
            for x in v.iter_mut() {
                *x = 0.0;
            }
        });
    }

    /// Multiply every value in place (batch averaging without a copy).
    fn scale(&mut self, s: f32) {
        self.for_each_slice_mut(|v| {
            for x in v.iter_mut() {
                *x *= s;
            }
        });
    }

    fn for_each_slice_mut(&mut self, mut f: impl FnMut(&mut Vec<f32>)) {
        for v in self
            .layer_w
            .iter_mut()
            .chain(self.layer_b.iter_mut())
            .chain(self.norm_g.iter_mut())
            .chain(self.norm_b.iter_mut())
        {
            f(v);
        }
        f(&mut self.clf_w);
        f(&mut self.clf_b);
    }

    fn grad_norm(&mut self) -> f32 {
        let mut total = 0.0_f64;
        self.for_each_slice_mut(|v| {
            for x in v.iter() {
                total += f64::from(*x) * f64::from(*x);
            }
        });
        total.sqrt() as f32
    }

    fn clip_global_norm(&mut self, max_norm: f32) {
        if max_norm <= 0.0 {
            return;
        }
        let norm = self.grad_norm();
        if norm > max_norm {
            let s = max_norm / (norm + 1e-12);
            self.for_each_slice_mut(|v| {
                for x in v.iter_mut() {
                    *x *= s;
                }
            });
        }
    }
}

/// AdamW optimiser state mirroring `Params` shapes (decoupled weight decay).
struct Adam {
    wd: f32,
    b1: f32,
    b2: f32,
    eps: f32,
    t: i32,
    m: Params,
    v: Params,
}

impl Adam {
    fn new(cfg: &ModelConfig, tc: &TrainConfig) -> Self {
        Self {
            wd: tc.weight_decay,
            b1: 0.9,
            b2: 0.999,
            eps: 1e-8,
            t: 0,
            m: Params::zeros_like(cfg),
            v: Params::zeros_like(cfg),
        }
    }

    fn step(&mut self, p: &mut Params, g: &Params, lr: f32) {
        self.t += 1;
        let (b1, b2) = (self.b1, self.b2);
        let bc1 = 1.0 - b1.powi(self.t);
        let bc2 = 1.0 - b2.powi(self.t);
        let (wd, eps) = (self.wd, self.eps);
        let upd = |pv: &mut [f32], gv: &[f32], mv: &mut [f32], vv: &mut [f32], decay: f32| {
            for i in 0..pv.len() {
                let grad = gv[i];
                mv[i] = b1 * mv[i] + (1.0 - b1) * grad;
                vv[i] = b2 * vv[i] + (1.0 - b2) * grad * grad;
                let mhat = mv[i] / bc1;
                let vhat = vv[i] / bc2;
                // Decoupled decay (AdamW): applied directly to the parameter.
                pv[i] -= lr * (mhat / (vhat.sqrt() + eps) + decay * pv[i]);
            }
        };
        for l in 0..p.layer_w.len() {
            upd(
                &mut p.layer_w[l],
                &g.layer_w[l],
                &mut self.m.layer_w[l],
                &mut self.v.layer_w[l],
                wd,
            );
            upd(
                &mut p.layer_b[l],
                &g.layer_b[l],
                &mut self.m.layer_b[l],
                &mut self.v.layer_b[l],
                0.0,
            );
            // No decay on LayerNorm parameters (standard practice).
            upd(
                &mut p.norm_g[l],
                &g.norm_g[l],
                &mut self.m.norm_g[l],
                &mut self.v.norm_g[l],
                0.0,
            );
            upd(
                &mut p.norm_b[l],
                &g.norm_b[l],
                &mut self.m.norm_b[l],
                &mut self.v.norm_b[l],
                0.0,
            );
        }
        upd(
            &mut p.clf_w,
            &g.clf_w,
            &mut self.m.clf_w,
            &mut self.v.clf_w,
            wd,
        );
        upd(
            &mut p.clf_b,
            &g.clf_b,
            &mut self.m.clf_b,
            &mut self.v.clf_b,
            0.0,
        );
    }
}

// Tiny deterministic PRNG (xorshift64*) so training needs no external rand crate.
pub(crate) struct Rng(u64);
impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    pub(crate) fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub(crate) fn next_f32(&mut self) -> f32 {
        (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32
    }
    /// Standard-normal via Box-Muller.
    pub(crate) fn normal(&mut self) -> f32 {
        let u1 = self.next_f32().max(1e-7);
        let u2 = self.next_f32();
        (-2.0 * u1.ln()).sqrt() * (std::f32::consts::TAU * u2).cos()
    }
    pub(crate) fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = (self.next_u64() % (i as u64 + 1)) as usize;
            v.swap(i, j);
        }
    }
}

/// The trainer owns the parameters and the model configuration.
pub struct Trainer {
    cfg: ModelConfig,
    params: Params,
    acts: Vec<Activation>,
}

struct ForwardCache {
    /// inputs[l] = input to layer l (inputs[0] = node features).
    inputs: Vec<Vec<f32>>,
    /// Post-bias, pre-LayerNorm aggregation per layer.
    agg: Vec<Vec<f32>>,
    /// Per-node LayerNorm mean / variance per layer.
    mu: Vec<Vec<f32>>,
    var: Vec<Vec<f32>>,
    /// Normalised (pre-affine) values per layer.
    zc: Vec<Vec<f32>>,
    /// Post-activation(+residual+dropout) output per layer.
    outputs: Vec<Vec<f32>>,
    /// Inverted-dropout masks per layer (empty = no dropout applied).
    drop: Vec<Vec<f32>>,
    /// Argmax node per feature of the final layer (for max-pool backward).
    mx_arg: Vec<usize>,
    g: Vec<f32>,
    probs: Vec<f32>,
    n: usize,
}

impl Trainer {
    /// Initialise with Xavier/Glorot random weights for the given config.
    /// LayerNorm is always trained (γ = 1, β = 0 at init) and exported.
    pub fn new(cfg: ModelConfig, seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let mut layer_w = Vec::new();
        let mut layer_b = Vec::new();
        let mut norm_g = Vec::new();
        let mut norm_b = Vec::new();
        let mut acts = Vec::new();
        for l in &cfg.layers {
            let scale = (2.0 / (l.features_in + l.features_out) as f32).sqrt();
            layer_w.push(
                (0..l.features_in * l.features_out)
                    .map(|_| rng.normal() * scale)
                    .collect(),
            );
            layer_b.push(vec![0.0; l.features_out]);
            norm_g.push(vec![1.0; l.features_out]);
            norm_b.push(vec![0.0; l.features_out]);
            acts.push(l.activation);
        }
        let emb = cfg.embedding_dims();
        let cscale = (2.0 / (emb + cfg.num_classes) as f32).sqrt();
        let clf_w = (0..emb * cfg.num_classes)
            .map(|_| rng.normal() * cscale)
            .collect();
        let clf_b = vec![0.0; cfg.num_classes];
        Self {
            params: Params {
                layer_w,
                layer_b,
                norm_g,
                norm_b,
                clf_w,
                clf_b,
            },
            acts,
            cfg,
        }
    }

    fn apply_act(act: Activation, z: f32) -> f32 {
        match act {
            Activation::ReLU => z.max(0.0),
            Activation::LeakyReLU => {
                if z > 0.0 {
                    z
                } else {
                    0.01 * z
                }
            }
            Activation::None => z,
        }
    }

    fn act_deriv(act: Activation, z: f32) -> f32 {
        match act {
            Activation::ReLU => {
                if z > 0.0 {
                    1.0
                } else {
                    0.0
                }
            }
            Activation::LeakyReLU => {
                if z > 0.0 {
                    1.0
                } else {
                    0.01
                }
            }
            Activation::None => 1.0,
        }
    }

    /// Does layer `li` receive a residual connection from layer `li - 1`?
    fn has_residual(&self, li: usize) -> bool {
        self.cfg.residual
            && li > 0
            && self.cfg.layers[li].features_out == self.cfg.layers[li - 1].features_out
    }

    fn forward(&self, adj: &Adjacency, x: &[f32], rng: Option<&mut Rng>) -> ForwardCache {
        let n = adj.n;
        let mut rng = rng;
        let mut cache = ForwardCache {
            inputs: Vec::new(),
            agg: Vec::new(),
            mu: Vec::new(),
            var: Vec::new(),
            zc: Vec::new(),
            outputs: Vec::new(),
            drop: Vec::new(),
            mx_arg: Vec::new(),
            g: Vec::new(),
            probs: Vec::new(),
            n,
        };
        let mut cur = x.to_vec();
        for (li, lc) in self.cfg.layers.iter().enumerate() {
            let fin = lc.features_in;
            let fout = lc.features_out;
            cache.inputs.push(cur.clone());
            let t = matmul(&cur, &self.params.layer_w[li], n, fin, fout); // H.W
            let mut agg = adj.matvec(&t, fout); // A_hat.(H.W)
            for i in 0..n {
                for f in 0..fout {
                    agg[i * fout + f] += self.params.layer_b[li][f];
                }
            }
            // LayerNorm over the feature dimension, per node.
            let mut mu = vec![0.0_f32; n];
            let mut var = vec![0.0_f32; n];
            let mut zc = vec![0.0_f32; n * fout];
            let mut out = vec![0.0_f32; n * fout];
            for i in 0..n {
                let row = &agg[i * fout..(i + 1) * fout];
                let m = row.iter().sum::<f32>() / fout as f32;
                let v = row.iter().map(|x| (x - m) * (x - m)).sum::<f32>() / fout as f32;
                mu[i] = m;
                var[i] = v;
                let inv_std = 1.0 / (v + LN_EPS).sqrt();
                for f in 0..fout {
                    let c = (row[f] - m) * inv_std;
                    zc[i * fout + f] = c;
                    let zn = c * self.params.norm_g[li][f] + self.params.norm_b[li][f];
                    out[i * fout + f] = Self::apply_act(self.acts[li], zn);
                }
            }
            // Residual: add previous layer's output when widths match.
            if self.has_residual(li) {
                let prev = &cache.outputs[li - 1];
                for (o, p) in out.iter_mut().zip(prev.iter()) {
                    *o += *p;
                }
            }
            // Inverted dropout during training.
            let mut mask = Vec::new();
            if lc.dropout > 0.0
                && let Some(r) = rng.as_deref_mut()
            {
                let keep = 1.0 - lc.dropout;
                mask = (0..out.len())
                    .map(|_| {
                        if r.next_f32() >= lc.dropout {
                            1.0 / keep
                        } else {
                            0.0
                        }
                    })
                    .collect();
                for (o, m) in out.iter_mut().zip(mask.iter()) {
                    *o *= *m;
                }
            }
            cache.agg.push(agg);
            cache.mu.push(mu);
            cache.var.push(var);
            cache.zc.push(zc);
            cache.drop.push(mask);
            cache.outputs.push(out.clone());
            cur = out;
        }

        // Readout.
        let emb_last = self.cfg.layers.last().map_or(0, |l| l.features_out);
        let mut mean = vec![0.0_f32; emb_last];
        let mut mx = vec![f32::NEG_INFINITY; emb_last];
        let mut mx_arg = vec![0usize; emb_last];
        for i in 0..n {
            for f in 0..emb_last {
                let v = cur[i * emb_last + f];
                mean[f] += v;
                if v > mx[f] {
                    mx[f] = v;
                    mx_arg[f] = i;
                }
            }
        }
        for m in &mut mean {
            *m /= n as f32;
        }
        let g = match self.cfg.readout.as_str() {
            "max" => mx.clone(),
            "meanmax" => {
                let mut v = mean.clone();
                v.extend_from_slice(&mx);
                v
            }
            _ => mean.clone(),
        };
        let emb = g.len();
        let mut logits = vec![0.0_f32; self.cfg.num_classes];
        for c in 0..self.cfg.num_classes {
            let mut s = self.params.clf_b[c];
            for f in 0..emb {
                s += g[f] * self.params.clf_w[f * self.cfg.num_classes + c];
            }
            logits[c] = s;
        }
        cache.mx_arg = mx_arg;
        cache.probs = softmax(&logits);
        cache.g = g;
        cache
    }

    /// Focal-loss (with class weight) value and gradient wrt logits.
    ///
    /// L = -w · (1 - p_t)^γ · ln(p_t). The gradient collapses to
    /// dL/dlogit_j = mod · (p_j - 1[j = y]) with
    /// mod = w · (1 - p_t)^(γ-1) · ((1 - p_t) - γ · p_t · ln(p_t)),
    /// which degrades to plain weighted cross-entropy at γ = 0.
    fn focal_terms(probs: &[f32], label: usize, w: f32, gamma: f32) -> (f32, Vec<f32>) {
        let pt = probs[label].max(1e-12);
        // Floor at 1e-6: for γ ∈ (0, 1) the (1 - pt)^(γ-1) gradient factor
        // diverges as pt → 1; the floor keeps gradients finite without
        // measurably changing the loss.
        let one_minus = (1.0 - pt).max(1e-6);
        let loss = -w * one_minus.powf(gamma) * pt.ln();
        let modulation = if gamma == 0.0 {
            w
        } else {
            w * one_minus.powf(gamma - 1.0) * (one_minus - gamma * pt * pt.ln())
        };
        let mut dlogits: Vec<f32> = probs.iter().map(|&p| modulation * p).collect();
        dlogits[label] -= modulation;
        (loss, dlogits)
    }

    /// Accumulate one example's gradients into `grads` (running batch sum)
    /// and return the example loss. Accumulating in place avoids a full
    /// `Params` allocation + add pass per example.
    fn backward(
        &self,
        adj: &Adjacency,
        cache: &ForwardCache,
        label: usize,
        class_w: &[f32],
        gamma: f32,
        grads: &mut Params,
    ) -> f32 {
        let classes = self.cfg.num_classes;
        let n = cache.n;
        let (loss, dlogits) = Self::focal_terms(&cache.probs, label, class_w[label], gamma);

        // Classifier grads: Wc[f*C + c] += g[f] * dlogits[c].
        let emb = cache.g.len();
        for f in 0..emb {
            for c in 0..classes {
                grads.clf_w[f * classes + c] += cache.g[f] * dlogits[c];
            }
        }
        for (a, b) in grads.clf_b.iter_mut().zip(&dlogits) {
            *a += *b;
        }

        // dg[f] = sum_c Wc[f*C+c] * dlogits[c].
        let mut dg = vec![0.0_f32; emb];
        for f in 0..emb {
            let mut s = 0.0;
            for c in 0..classes {
                s += self.params.clf_w[f * classes + c] * dlogits[c];
            }
            dg[f] = s;
        }

        // Readout backward into per-node gradient dh.
        let emb_last = self.cfg.layers.last().map_or(0, |l| l.features_out);
        let mut dh = vec![0.0_f32; n * emb_last];
        match self.cfg.readout.as_str() {
            "max" => {
                for f in 0..emb_last {
                    dh[cache.mx_arg[f] * emb_last + f] += dg[f];
                }
            }
            "meanmax" => {
                for i in 0..n {
                    for f in 0..emb_last {
                        dh[i * emb_last + f] += dg[f] / n as f32;
                    }
                }
                for f in 0..emb_last {
                    dh[cache.mx_arg[f] * emb_last + f] += dg[emb_last + f];
                }
            }
            _ => {
                for i in 0..n {
                    for f in 0..emb_last {
                        dh[i * emb_last + f] += dg[f] / n as f32;
                    }
                }
            }
        }

        // Layer backward.
        let mut d_resid_carry: Option<Vec<f32>> = None;
        for li in (0..self.cfg.layers.len()).rev() {
            let lc = &self.cfg.layers[li];
            let (fin, fout) = (lc.features_in, lc.features_out);

            // Gradient arriving at this layer's output = dh (+ residual skip
            // gradient carried down from layer li + 1, same width).
            if let Some(extra) = d_resid_carry.take() {
                for (a, b) in dh.iter_mut().zip(extra.iter()) {
                    *a += *b;
                }
            }

            // Dropout backward.
            if !cache.drop[li].is_empty() {
                for (a, m) in dh.iter_mut().zip(cache.drop[li].iter()) {
                    *a *= *m;
                }
            }

            // Residual branch bypasses activation/LN of THIS layer: save the
            // post-dropout gradient for layer li - 1's output.
            if self.has_residual(li) {
                d_resid_carry = Some(dh.clone());
            }

            // Activation backward (pre-activation zn = zc*γ + β).
            let zc = &cache.zc[li];
            for i in 0..n {
                for f in 0..fout {
                    let zn =
                        zc[i * fout + f] * self.params.norm_g[li][f] + self.params.norm_b[li][f];
                    dh[i * fout + f] *= Self::act_deriv(self.acts[li], zn);
                }
            }

            // LayerNorm affine grads.
            for i in 0..n {
                for f in 0..fout {
                    grads.norm_g[li][f] += dh[i * fout + f] * zc[i * fout + f];
                    grads.norm_b[li][f] += dh[i * fout + f];
                }
            }

            // LayerNorm normalisation backward → dagg.
            let mu = &cache.mu[li];
            let var = &cache.var[li];
            let agg = &cache.agg[li];
            let mut dagg = vec![0.0_f32; n * fout];
            let dd = fout as f32;
            for i in 0..n {
                let std = (var[i] + LN_EPS).sqrt();
                let inv_std = 1.0 / std;
                let inv_std3 = inv_std * inv_std * inv_std;
                let mut dvar = 0.0_f32;
                let mut dzc_sum = 0.0_f32;
                let mut xmu_sum = 0.0_f32;
                for f in 0..fout {
                    let dzc = dh[i * fout + f] * self.params.norm_g[li][f];
                    let xmu = agg[i * fout + f] - mu[i];
                    dvar += dzc * xmu * -0.5 * inv_std3;
                    dzc_sum += dzc;
                    xmu_sum += xmu;
                }
                let dmu = -dzc_sum * inv_std + dvar * (-2.0 * xmu_sum / dd);
                for f in 0..fout {
                    let dzc = dh[i * fout + f] * self.params.norm_g[li][f];
                    let xmu = agg[i * fout + f] - mu[i];
                    dagg[i * fout + f] = dzc * inv_std + dvar * 2.0 * xmu / dd + dmu / dd;
                }
            }

            // Bias grads.
            for i in 0..n {
                for f in 0..fout {
                    grads.layer_b[li][f] += dagg[i * fout + f];
                }
            }

            // dT = A_hat^T . dagg ; dW = H_in^T . dT ; dH_in = dT . W^T.
            let dt = adj.matvec_t(&dagg, fout);
            let h_in = &cache.inputs[li];
            for a in 0..fin {
                for b in 0..fout {
                    let mut s = 0.0;
                    for i in 0..n {
                        s += h_in[i * fin + a] * dt[i * fout + b];
                    }
                    grads.layer_w[li][a * fout + b] += s;
                }
            }
            let mut dh_prev = vec![0.0_f32; n * fin];
            for i in 0..n {
                for a in 0..fin {
                    let mut s = 0.0;
                    for b in 0..fout {
                        s += dt[i * fout + b] * self.params.layer_w[li][a * fout + b];
                    }
                    dh_prev[i * fin + a] = s;
                }
            }
            dh = dh_prev;
        }
        loss
    }

    fn predict_class(&self, adj: &Adjacency, x: &[f32]) -> usize {
        let c = self.forward(adj, x, None);
        let mut best = 0;
        let mut bv = c.probs[0];
        for i in 1..c.probs.len() {
            if c.probs[i] > bv {
                bv = c.probs[i];
                best = i;
            }
        }
        best
    }

    /// Train on `examples`. Uses warmup + cosine LR, focal loss with optional
    /// class weighting, gradient clipping, and early stopping with
    /// best-weights restore (on validation macro-F1).
    ///
    /// Returns a [`FitReport`]; its `best_*` fields describe the restored
    /// weights and are the values to export as metadata. Errors on empty
    /// datasets, out-of-range labels, and invalid `focal_gamma` instead of
    /// panicking mid-training.
    pub fn fit(&mut self, examples: &[Example], tc: &TrainConfig) -> Result<FitReport, String> {
        if examples.len() < 2 {
            // One example cannot produce both a training and a validation
            // split; the old code accepted it and reported train=0, val=1.
            return Err(format!(
                "fit: need at least 2 examples to train and validate (got {})",
                examples.len()
            ));
        }
        let in_dims = self.cfg.input_dims();
        for (i, e) in examples.iter().enumerate() {
            if e.label >= self.cfg.num_classes {
                return Err(format!(
                    "fit: example {i} has label {} out of range (num_classes = {})",
                    e.label, self.cfg.num_classes
                ));
            }
            // Validate BEFORE building adjacency. The adjacency builder
            // asserts on invalid graphs, so a malformed example used to abort
            // the whole run with a panic instead of a recoverable error.
            e.graph
                .validate()
                .map_err(|err| format!("fit: example {i} has an invalid graph: {err}"))?;
            if e.graph.feature_dims != in_dims {
                return Err(format!(
                    "fit: example {i} has feature width {} but the model expects {in_dims}",
                    e.graph.feature_dims
                ));
            }
        }
        if !tc.focal_gamma.is_finite() || tc.focal_gamma < 0.0 {
            return Err(format!(
                "fit: focal_gamma must be finite and >= 0 (got {})",
                tc.focal_gamma
            ));
        }
        let adjs: Vec<Adjacency> = examples
            .iter()
            .map(|e| Adjacency::from_graph(&e.graph, self.cfg.normalization))
            .collect();
        let mut idx: Vec<usize> = (0..examples.len()).collect();
        let mut rng = Rng::new(tc.seed);
        if tc.shuffle_split {
            rng.shuffle(&mut idx);
        }
        let n_val = if tc.explicit_val > 0 {
            tc.explicit_val
        } else {
            ((examples.len() as f32) * tc.val_fraction).max(1.0) as usize
        };
        let (val_idx, train_idx) = idx.split_at(n_val.min(examples.len().saturating_sub(1)).max(1));

        // Inverse-frequency class weights (mean-normalised).
        let classes = self.cfg.num_classes;
        let mut class_w = vec![1.0_f32; classes];
        if tc.class_weighting {
            let mut counts = vec![0usize; classes];
            for &ei in train_idx {
                if examples[ei].label < classes {
                    counts[examples[ei].label] += 1;
                }
            }
            let total: usize = counts.iter().sum();
            if total > 0 {
                for c in 0..classes {
                    class_w[c] = total as f32 / (classes as f32 * counts[c].max(1) as f32);
                }
                let mean = class_w.iter().sum::<f32>() / classes as f32;
                for w in &mut class_w {
                    *w /= mean;
                }
            }
        }

        let mut opt = Adam::new(&self.cfg, tc);
        // One reusable gradient accumulator — zeroed per batch instead of
        // allocating fresh `Params` per example and per batch.
        let mut grad_accum = Params::zeros_like(&self.cfg);
        let mut stats = Vec::new();
        let mut best_f1 = -1.0_f32;
        let mut best_epoch = 0usize;
        let mut best_val_acc = 0.0_f32;
        let mut best_params: Option<Params> = None;
        let mut bad_epochs = 0usize;

        for epoch in 0..tc.epochs {
            // Linear warmup, then cosine decay.
            let lr = if tc.warmup_epochs > 0 && epoch < tc.warmup_epochs {
                tc.learning_rate * (epoch + 1) as f32 / tc.warmup_epochs as f32
            } else {
                let denom = tc.epochs.saturating_sub(tc.warmup_epochs).max(1) as f32;
                let progress = (epoch - tc.warmup_epochs.min(epoch)) as f32 / denom;
                0.5 * tc.learning_rate * (1.0 + (std::f32::consts::PI * progress).cos())
            };

            let mut order = train_idx.to_vec();
            rng.shuffle(&mut order);
            let mut loss = 0.0;
            let mut correct = 0;
            for chunk in order.chunks(tc.batch_size.max(1)) {
                grad_accum.zero();
                for &ei in chunk {
                    let x = &examples[ei].graph.node_features;
                    let cache = self.forward(&adjs[ei], x, Some(&mut rng));
                    let y = examples[ei].label;
                    let pred = cache
                        .probs
                        .iter()
                        .enumerate()
                        .fold(
                            (0usize, f32::MIN),
                            |(bi, bv), (i, &v)| {
                                if v > bv { (i, v) } else { (bi, bv) }
                            },
                        )
                        .0;
                    if pred == y {
                        correct += 1;
                    }
                    loss += self.backward(
                        &adjs[ei],
                        &cache,
                        y,
                        &class_w,
                        tc.focal_gamma,
                        &mut grad_accum,
                    );
                }
                grad_accum.scale(1.0 / chunk.len() as f32);
                grad_accum.clip_global_norm(tc.grad_clip);
                opt.step(&mut self.params, &grad_accum, lr);
            }

            let (val_acc, val_macro_f1) = self.evaluate(&adjs, examples, val_idx);
            stats.push(EpochStat {
                epoch: epoch + 1,
                train_loss: loss / train_idx.len().max(1) as f32,
                train_acc: correct as f32 / train_idx.len().max(1) as f32,
                val_acc,
                val_macro_f1,
                lr,
            });

            if val_macro_f1 > best_f1 {
                best_f1 = val_macro_f1;
                best_epoch = epoch + 1;
                best_val_acc = val_acc;
                best_params = Some(self.params.clone());
                bad_epochs = 0;
            } else {
                bad_epochs += 1;
                if tc.early_stop_patience > 0 && bad_epochs >= tc.early_stop_patience {
                    break;
                }
            }
        }

        if let Some(best) = best_params {
            self.params = best;
        }
        Ok(FitReport {
            stats,
            best_epoch,
            best_val_acc,
            best_val_macro_f1: best_f1.max(0.0),
            train_examples: train_idx.len(),
            val_examples: val_idx.len(),
        })
    }

    /// Accuracy + macro-F1 over `idx`.
    fn evaluate(&self, adjs: &[Adjacency], examples: &[Example], idx: &[usize]) -> (f32, f32) {
        if idx.is_empty() {
            return (0.0, 0.0);
        }
        let classes = self.cfg.num_classes;
        let mut cm = vec![0usize; classes * classes];
        let mut correct = 0;
        for &ei in idx {
            let pred = self.predict_class(&adjs[ei], &examples[ei].graph.node_features);
            let truth = examples[ei].label.min(classes - 1);
            cm[truth * classes + pred] += 1;
            if pred == truth {
                correct += 1;
            }
        }
        let mut f1_sum = 0.0_f32;
        for c in 0..classes {
            let tp = cm[c * classes + c] as f32;
            let fp: f32 = (0..classes).map(|r| cm[r * classes + c]).sum::<usize>() as f32 - tp;
            let fn_: f32 = (0..classes).map(|k| cm[c * classes + k]).sum::<usize>() as f32 - tp;
            let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
            let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
            if precision + recall > 0.0 {
                f1_sum += 2.0 * precision * recall / (precision + recall);
            }
        }
        (correct as f32 / idx.len() as f32, f1_sum / classes as f32)
    }

    /// Export the trained parameters into a [`WeightStore`] (round-trips through
    /// [`WeightStore::to_model`] and reproduces these predictions in inference).
    pub fn to_weight_store(
        &self,
        train_samples: usize,
        val_accuracy: f32,
        epochs: usize,
    ) -> WeightStore {
        let layer_data = self
            .params
            .layer_w
            .iter()
            .zip(&self.params.layer_b)
            .zip(self.params.norm_g.iter().zip(&self.params.norm_b))
            .map(|((w, b), (g, bt))| LayerWeights {
                weights: w.clone(),
                bias: b.clone(),
                norm_gamma: Some(g.clone()),
                norm_beta: Some(bt.clone()),
            })
            .collect();
        let metadata = WeightMetadata {
            train_samples,
            val_accuracy,
            epochs,
            version: "gnn-trained-v2".to_string(),
            feature_schema_version: FEATURE_SCHEMA_VERSION,
            ..Default::default()
        };
        let metadata = if self.cfg.num_classes == crate::taxonomy::NUM_CLASSES {
            metadata.with_taxonomy()
        } else {
            metadata
        };
        WeightStore {
            format_version: WEIGHT_FORMAT_VERSION,
            config: self.cfg.clone(),
            layer_data,
            classifier_weights: self.params.clf_w.clone(),
            classifier_bias: self.params.clf_b.clone(),
            metadata,
        }
    }

    /// Convenience: build an inference-ready [`GnnModel`] from current params.
    pub fn to_model(&self) -> crate::error::Result<GnnModel> {
        self.to_weight_store(0, 0.0, 0).to_model()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_tensor::{EdgeType, GraphTensor, NodeFeatures};

    fn tiny_graph(bias: f32) -> GraphTensor {
        let feats = vec![
            NodeFeatures {
                opcode_category: [bias; 16],
                operand_count: 0.5,
                is_branch: 0.0,
                is_call: 0.0,
                is_memory_access: 0.0,
                is_comparison: 0.0,
                in_degree: 0.5,
                out_degree: 0.5,
                block_size: 0.2,
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
            3
        ];
        let edges = vec![(0, 1, EdgeType::ControlFlow), (1, 2, EdgeType::ControlFlow)];
        GraphTensor::from_edges(&feats, &edges)
    }

    #[test]
    fn trainer_separates_two_classes() {
        // Class 0 graphs have low opcode bias, class 1 high — trivially separable.
        let mut examples = Vec::new();
        for _ in 0..20 {
            examples.push(Example {
                graph: tiny_graph(0.0),
                label: 0,
            });
            examples.push(Example {
                graph: tiny_graph(1.0),
                label: 1,
            });
        }
        let cfg = ModelConfig {
            num_classes: 2,
            ..ModelConfig::default()
        };
        let mut trainer = Trainer::new(cfg, 7);
        let tc = TrainConfig {
            epochs: 30,
            val_fraction: 0.25,
            ..TrainConfig::default()
        };
        let report = trainer.fit(&examples, &tc).expect("fit succeeds");
        let last = report.stats.last().unwrap();
        assert!(last.train_acc > 0.9, "train_acc={}", last.train_acc);
        // exported weights must be valid and load into a model
        let store = trainer.to_weight_store(
            report.train_examples,
            report.best_val_acc,
            report.best_epoch,
        );
        assert!(store.to_model().is_ok());
    }

    #[test]
    fn trained_weights_roundtrip_through_inference() {
        // Predictions from Trainer::forward must match GnnModel::predict after
        // export — the whole point of keeping the two forward passes in sync.
        let mut examples = Vec::new();
        for _ in 0..10 {
            examples.push(Example {
                graph: tiny_graph(0.0),
                label: 0,
            });
            examples.push(Example {
                graph: tiny_graph(1.0),
                label: 1,
            });
        }
        let cfg = ModelConfig {
            num_classes: 2,
            ..ModelConfig::default()
        };
        let mut trainer = Trainer::new(cfg, 42);
        let tc = TrainConfig {
            epochs: 5,
            ..TrainConfig::default()
        };
        trainer.fit(&examples, &tc).expect("fit succeeds");
        let model = trainer.to_model().expect("valid model");
        for ex in &examples {
            let adj = Adjacency::from_graph(&ex.graph, model.config.normalization);
            let trainer_pred = trainer.predict_class(&adj, &ex.graph.node_features);
            let model_pred = model.predict(&ex.graph).expect("predict").predicted_class;
            assert_eq!(trainer_pred, model_pred);
        }
    }

    #[test]
    fn fit_rejects_a_single_example_instead_of_training_on_none() {
        // One example cannot be split; the trainer used to report
        // train_examples=0, val_examples=1 and still export weights.
        let cfg = ModelConfig {
            num_classes: 2,
            ..ModelConfig::default()
        };
        let mut trainer = Trainer::new(cfg, 7);
        let err = trainer
            .fit(
                &[Example {
                    graph: tiny_graph(0.0),
                    label: 0,
                }],
                &TrainConfig::default(),
            )
            .expect_err("a single example must be rejected");
        assert!(err.contains("at least 2"), "unexpected error: {err}");
    }

    #[test]
    fn fit_reports_invalid_graphs_instead_of_panicking() {
        let cfg = ModelConfig {
            num_classes: 2,
            ..ModelConfig::default()
        };
        let mut trainer = Trainer::new(cfg, 7);
        let mut bad = tiny_graph(0.0);
        bad.row_ptr = vec![0]; // truncated: no longer num_nodes + 1
        let err = trainer
            .fit(
                &[
                    Example {
                        graph: tiny_graph(0.0),
                        label: 0,
                    },
                    Example {
                        graph: bad,
                        label: 1,
                    },
                ],
                &TrainConfig::default(),
            )
            .expect_err("a malformed graph must be an error, not a panic");
        assert!(err.contains("invalid graph"), "unexpected error: {err}");
    }

    #[test]
    fn fit_rejects_mismatched_feature_width() {
        let cfg = ModelConfig {
            num_classes: 2,
            ..ModelConfig::default()
        };
        let mut trainer = Trainer::new(cfg, 7);
        // Structurally consistent, just a different width: validate() must
        // pass so the width check (not the graph check) is what rejects it.
        let mut narrow = tiny_graph(0.0);
        narrow.feature_dims = 16;
        narrow.node_features.truncate(3 * 16);
        let err = trainer
            .fit(
                &[
                    Example {
                        graph: tiny_graph(0.0),
                        label: 0,
                    },
                    Example {
                        graph: narrow,
                        label: 1,
                    },
                ],
                &TrainConfig::default(),
            )
            .expect_err("feature width mismatch must be rejected");
        assert!(err.contains("feature width"), "unexpected error: {err}");
    }

    #[test]
    fn focal_terms_degrade_to_cross_entropy_at_gamma_zero() {
        let probs = vec![0.7, 0.2, 0.1];
        let (loss, dl) = Trainer::focal_terms(&probs, 0, 1.0, 0.0);
        assert!((loss - (-(0.7_f32).ln())).abs() < 1e-5);
        assert!((dl[0] - (0.7 - 1.0)).abs() < 1e-5);
        assert!((dl[1] - 0.2).abs() < 1e-5);
    }

    /// Parallel CF + DD edges between the same node pairs — the exact case
    /// where training and inference used to disagree.
    fn multi_edge_graph(bias: f32) -> GraphTensor {
        let feats = vec![
            NodeFeatures {
                opcode_category: [bias; 16],
                operand_count: 0.5,
                is_branch: 0.0,
                is_call: 0.0,
                is_memory_access: 1.0,
                is_comparison: 0.0,
                in_degree: 0.5,
                out_degree: 0.5,
                block_size: 0.2,
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
        let edges = vec![
            (0, 1, EdgeType::ControlFlow),
            (1, 2, EdgeType::ControlFlow),
            (2, 3, EdgeType::ControlFlow),
            (1, 2, EdgeType::DataDependency), // parallel to the CF edge
            (0, 2, EdgeType::DataDependency),
        ];
        GraphTensor::from_edges(&feats, &edges)
    }

    #[test]
    fn multi_edge_graphs_keep_train_inference_parity() {
        let mut examples = Vec::new();
        for _ in 0..10 {
            examples.push(Example {
                graph: multi_edge_graph(0.0),
                label: 0,
            });
            examples.push(Example {
                graph: multi_edge_graph(1.0),
                label: 1,
            });
        }
        let cfg = ModelConfig {
            num_classes: 2,
            ..ModelConfig::default()
        };
        let mut trainer = Trainer::new(cfg, 42);
        let tc = TrainConfig {
            epochs: 5,
            ..TrainConfig::default()
        };
        trainer.fit(&examples, &tc).expect("fit succeeds");
        let model = trainer.to_model().expect("valid model");
        for ex in &examples {
            let adj = Adjacency::from_graph(&ex.graph, model.config.normalization);
            let trainer_probs = trainer.forward(&adj, &ex.graph.node_features, None).probs;
            let model_probs = model.predict(&ex.graph).expect("predict").class_probs;
            for (a, b) in trainer_probs.iter().zip(&model_probs) {
                assert!((a - b).abs() < 1e-4, "probs diverge: {a} vs {b}");
            }
        }
    }

    #[test]
    fn equal_width_first_layer_keeps_parity() {
        // A 36 → 36 first layer must NOT receive a residual from the raw
        // input in either forward pass.
        let cfg = ModelConfig {
            layers: vec![
                crate::layer::LayerConfig {
                    features_in: 36,
                    features_out: 36,
                    activation: Activation::ReLU,
                    dropout: 0.0,
                },
                crate::layer::LayerConfig {
                    features_in: 36,
                    features_out: 16,
                    activation: Activation::ReLU,
                    dropout: 0.0,
                },
            ],
            num_classes: 2,
            ..ModelConfig::default()
        };
        let trainer = Trainer::new(cfg, 7);
        let model = trainer.to_model().expect("valid model");
        let g = tiny_graph(0.6);
        let adj = Adjacency::from_graph(&g, model.config.normalization);
        let trainer_probs = trainer.forward(&adj, &g.node_features, None).probs;
        let model_probs = model.predict(&g).expect("predict").class_probs;
        for (a, b) in trainer_probs.iter().zip(&model_probs) {
            assert!((a - b).abs() < 1e-4, "probs diverge: {a} vs {b}");
        }
    }

    #[test]
    fn fit_rejects_out_of_range_labels() {
        let examples = vec![
            Example {
                graph: tiny_graph(0.0),
                label: 0,
            },
            Example {
                graph: tiny_graph(1.0),
                label: 99,
            },
        ];
        let cfg = ModelConfig {
            num_classes: 2,
            ..ModelConfig::default()
        };
        let mut trainer = Trainer::new(cfg, 1);
        assert!(trainer.fit(&examples, &TrainConfig::default()).is_err());
    }

    #[test]
    fn focal_terms_stay_finite_for_fractional_gamma() {
        let probs = vec![0.999_999_9, 1e-7];
        let (loss, dl) = Trainer::focal_terms(&probs, 0, 1.0, 0.5);
        assert!(loss.is_finite());
        assert!(dl.iter().all(|d| d.is_finite()));
    }
}
