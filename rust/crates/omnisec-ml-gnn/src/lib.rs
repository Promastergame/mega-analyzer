//! # OmniSec GNN — Graph Neural Network engine (inference + training)
//!
//! ```text
//! CFG/PDG graph → GraphTensor (CSR + 28-dim node features)
//!               → build_normalized_csr (ONE canonical Â for train AND inference)
//!               → GnnLayer × N  (Â·H·W + b → LayerNorm → act, + residual)
//!               → Readout (mean ‖ max) → linear classifier → softmax
//! ```
//!
//! ## Invariants enforced by construction
//! * Every graph entering [`GnnModel::predict`] or [`Trainer::fit`] passes
//!   [`GraphTensor::validate`] and matches the model's input width.
//! * Training and inference share [`build_normalized_csr`], [`Activation`],
//!   the readout and the softmax — parity is tested, not assumed.
//! * Weight files are versioned ([`WEIGHT_FORMAT_VERSION`]) and carry the class
//!   names; a taxonomy drift against [`taxonomy`] is rejected at load time.
//! * The C ABI (`ffi.rs`, `include/omnisec_ml_gnn.h`) never unwinds, reports
//!   errors through `gnn_last_error()` and exposes the class contract
//!   (`gnn_num_classes`, `gnn_class_name`, `gnn_abi_version`).

pub mod dex_synth;
mod error;
mod features;
mod ffi;
mod gnnbuf;
mod graph_tensor;
mod layer;
mod model;
pub mod synth;
pub mod taxonomy;
mod trainer;
mod weights;

pub use error::{GnnError, Result};
pub use features::FeatureExtractor;
pub use gnnbuf::{encode_gnnbuf, load_gnnbuf_file, parse_gnnbuf_bytes};
pub use graph_tensor::{
    Csr, CsrView, EdgeType, GraphTensor, NodeFeatures, Normalization, build_normalized_csr,
};
pub use layer::{Activation, GnnLayer, LN_EPS, LayerConfig, edge_type_scale};
pub use model::{GnnModel, ModelConfig, Prediction, Readout};
pub use taxonomy::{CLASS_NAMES, NUM_CLASSES, VulnClass, class_name};
pub use trainer::{EpochStat, Example, FitReport, TrainConfig, Trainer};
pub use weights::{LayerWeights, WEIGHT_FORMAT_VERSION, WeightMetadata, WeightStore};
