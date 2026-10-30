//! Weight storage: versioned, validated, atomically written.

use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use omnisec_json::{FromJson, ToJson};

use crate::error::{GnnError, Result};
use crate::layer::GnnLayer;
use crate::model::{GnnModel, ModelConfig};
use crate::taxonomy::{CLASS_NAMES, NUM_CLASSES};
use crate::trainer::TrainConfig;

/// Current on-disk schema. v1 = no LN / no normalisation field; v2 = current.
pub const WEIGHT_FORMAT_VERSION: u32 = 2;

/// Feature schema version the node feature extractor implements. Stored in
/// every new weight file so a model trained against a different feature
/// layout is rejected before inference instead of returning garbage.
pub const FEATURE_SCHEMA_VERSION: u32 = 1;

fn legacy_format_version() -> u32 {
    1
}

/// Serializable weight store.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct WeightStore {
    #[json(default = "legacy_format_version")]
    pub format_version: u32,
    pub config: ModelConfig,
    pub layer_data: Vec<LayerWeights>,
    pub classifier_weights: Vec<f32>,
    pub classifier_bias: Vec<f32>,
    pub metadata: WeightMetadata,
}

/// Weights for one layer.
#[derive(Debug, Clone, ToJson, FromJson)]
pub struct LayerWeights {
    pub weights: Vec<f32>,
    pub bias: Vec<f32>,
    #[json(default)]
    pub norm_gamma: Option<Vec<f32>>,
    #[json(default)]
    pub norm_beta: Option<Vec<f32>>,
}

/// Provenance of a training run. Everything needed to reproduce it.
#[derive(Debug, Clone, Default, ToJson, FromJson)]
pub struct WeightMetadata {
    pub train_samples: usize,
    /// Validation accuracy at the restored (best) epoch. NOTE: this is the
    /// split early stopping selected on — an optimistic estimate.
    pub val_accuracy: f32,
    pub epochs: usize,
    pub version: String,
    #[json(default)]
    pub val_macro_f1: f32,
    #[json(default)]
    pub seed: Option<u64>,
    #[json(default)]
    pub train_config: Option<TrainConfig>,
    /// Class names the model was trained for (index-aligned). Empty in legacy
    /// files; when present it is checked against the taxonomy at load time.
    #[json(default)]
    pub class_names: Vec<String>,
    /// Feature schema the node features follow. 0 = legacy file (schema
    /// unverifiable; only the input dimension is checked).
    #[json(default)]
    pub feature_schema_version: u32,
    /// Upper non-conformity quantile from conformal calibration on held-out
    /// data, when calibration was performed. None = uncalibrated.
    #[json(default)]
    pub conformal_q90: Option<f32>,
    /// Out-of-distribution score threshold above which inputs should be
    /// treated as OOD, when an OOD score exists. None = no OOD gating.
    #[json(default)]
    pub ood_threshold: Option<f32>,
}

impl WeightMetadata {
    #[must_use]
    pub fn with_taxonomy(mut self) -> Self {
        self.class_names = CLASS_NAMES.iter().map(|s| (*s).to_string()).collect();
        self
    }
}

impl WeightStore {
    /// Validate shapes, finiteness and the class contract. Weight files are
    /// user input: everything is rejected here, never at inference time.
    pub fn validate(&self) -> Result<()> {
        let bad = |m: String| GnnError::InvalidWeights(m);
        if self.format_version == 0 || self.format_version > WEIGHT_FORMAT_VERSION {
            return Err(bad(format!(
                "unsupported weight format version {} (max {WEIGHT_FORMAT_VERSION})",
                self.format_version
            )));
        }
        self.config.validate()?;
        if self.layer_data.len() != self.config.layers.len() {
            return Err(bad(format!(
                "layer data count {} != config count {}",
                self.layer_data.len(),
                self.config.layers.len()
            )));
        }
        for (i, (lc, lw)) in self.config.layers.iter().zip(&self.layer_data).enumerate() {
            let expected = lc.features_in * lc.features_out;
            if lw.weights.len() != expected {
                return Err(bad(format!(
                    "layer {i} has {} weights, expected {expected}",
                    lw.weights.len()
                )));
            }
            if lw.bias.len() != lc.features_out {
                return Err(bad(format!(
                    "layer {i} has {} bias values, expected {}",
                    lw.bias.len(),
                    lc.features_out
                )));
            }
            if lw.weights.iter().chain(&lw.bias).any(|v| !v.is_finite()) {
                return Err(bad(format!("layer {i} contains non-finite values")));
            }
            match (&lw.norm_gamma, &lw.norm_beta) {
                (None, None) => {}
                (Some(g), Some(b)) => {
                    if g.len() != lc.features_out || b.len() != lc.features_out {
                        return Err(bad(format!(
                            "layer {i} LayerNorm lengths {}/{} != {}",
                            g.len(),
                            b.len(),
                            lc.features_out
                        )));
                    }
                    if g.iter().chain(b).any(|v| !v.is_finite()) {
                        return Err(bad(format!(
                            "layer {i} LayerNorm params contain non-finite values"
                        )));
                    }
                }
                _ => {
                    return Err(bad(format!(
                        "layer {i} must provide both LayerNorm gamma and beta or neither"
                    )));
                }
            }
        }
        let expected_clf = self.config.embedding_dims() * self.config.num_classes;
        if self.classifier_weights.len() != expected_clf {
            return Err(bad(format!(
                "classifier has {} weights, expected {expected_clf}",
                self.classifier_weights.len()
            )));
        }
        if self.classifier_bias.len() != self.config.num_classes {
            return Err(bad(format!(
                "classifier has {} bias values, expected {}",
                self.classifier_bias.len(),
                self.config.num_classes
            )));
        }
        if self
            .classifier_weights
            .iter()
            .chain(&self.classifier_bias)
            .any(|v| !v.is_finite())
        {
            return Err(bad("classifier contains non-finite values".into()));
        }
        // Class contract.
        let names = &self.metadata.class_names;
        if !names.is_empty() {
            if names.len() != self.config.num_classes {
                return Err(bad(format!(
                    "class_names has {} entries, num_classes = {}",
                    names.len(),
                    self.config.num_classes
                )));
            }
            if self.config.num_classes == NUM_CLASSES
                && names.iter().zip(CLASS_NAMES).any(|(a, b)| a != b)
            {
                return Err(bad(format!(
                    "class_names {names:?} do not match the taxonomy {CLASS_NAMES:?} — index-aligned ABI would be violated"
                )));
            }
        }
        Ok(())
    }

    /// Build a validated inference model.
    pub fn to_model(&self) -> Result<GnnModel> {
        self.validate()?;
        let layers = self
            .config
            .layers
            .iter()
            .zip(&self.layer_data)
            .map(|(lc, lw)| {
                let mut layer = GnnLayer::new(lc.clone());
                layer.weights.clone_from(&lw.weights);
                layer.bias.clone_from(&lw.bias);
                layer.norm_gamma.clone_from(&lw.norm_gamma);
                layer.norm_beta.clone_from(&lw.norm_beta);
                layer
            })
            .collect();
        Ok(GnnModel {
            config: self.config.clone(),
            layers,
            classifier_weights: self.classifier_weights.clone(),
            classifier_bias: self.classifier_bias.clone(),
        })
    }

    /// Deterministic pseudo-random weights (tests / smoke runs). The result is
    /// only valid if `config` is — call `validate()`/`to_model()` to find out.
    #[must_use]
    pub fn dummy(config: ModelConfig) -> Self {
        let layer_data = config
            .layers
            .iter()
            .map(|lc| {
                let scale = (2.0 / (lc.features_in + lc.features_out) as f32).sqrt();
                LayerWeights {
                    weights: (0..lc.features_in * lc.features_out)
                        .map(|i| (i as f32 * 0.1).sin() * scale)
                        .collect(),
                    bias: vec![0.01; lc.features_out],
                    norm_gamma: Some(vec![1.0; lc.features_out]),
                    norm_beta: Some(vec![0.0; lc.features_out]),
                }
            })
            .collect();
        let emb = config.embedding_dims();
        let clf: Vec<f32> = (0..emb * config.num_classes)
            .map(|i| (i as f32 * 0.37).cos() * 0.05)
            .collect();
        let metadata = WeightMetadata {
            version: "dummy-v0".into(),
            ..Default::default()
        };
        let metadata = if config.num_classes == NUM_CLASSES {
            metadata.with_taxonomy()
        } else {
            metadata
        };
        Self {
            format_version: WEIGHT_FORMAT_VERSION,
            classifier_weights: clf,
            classifier_bias: vec![0.0; config.num_classes],
            layer_data,
            metadata,
            config,
        }
    }

    /// Load from disk, format chosen by extension (`.gnnbuf` → binary, else JSON).
    pub fn load(path: &str) -> Result<Self> {
        if Path::new(path)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("gnnbuf"))
        {
            Self::load_gnnbuf(path)
        } else {
            Self::load_json(path)
        }
    }

    pub fn load_json(path: &str) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let store: Self = omnisec_json::from_json_str(&data)?;
        store.validate()?;
        Ok(store)
    }

    pub fn save_json(&self, path: &str) -> Result<()> {
        self.validate()?;
        let data = omnisec_json::to_json_pretty(self);
        write_atomic(Path::new(path), data.as_bytes())?;
        Ok(())
    }

    pub fn load_gnnbuf(path: &str) -> Result<Self> {
        crate::gnnbuf::load_gnnbuf_file(path)
    }

    pub fn from_gnnbuf_bytes(bytes: &[u8]) -> Result<Self> {
        crate::gnnbuf::parse_gnnbuf_bytes(bytes)
    }

    /// `quant` ∈ {"f32", "f16", "int8"} — applies to weight matrices only.
    pub fn save_gnnbuf(&self, path: &str, quant: &str) -> Result<()> {
        let bytes = crate::gnnbuf::encode_gnnbuf(self, quant)?; // validates
        write_atomic(Path::new(path), &bytes)?;
        Ok(())
    }
}

/// Write `bytes` to `destination` via a same-directory temp file + fsync +
/// rename. A reader never observes a partial file. `rename` replaces the
/// destination on POSIX and Windows; the fallback covers Windows sharing
/// violations (destination currently open by another process) — during that
/// fallback there is a brief window with no file at `destination`.
pub(crate) fn write_atomic(destination: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = destination.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut tmp_name = destination
        .file_name()
        .map_or_else(|| "weights".into(), |s| s.to_os_string());
    tmp_name.push(format!(".{}.{nonce}.tmp", std::process::id()));
    let temp_path = destination.with_file_name(tmp_name);

    let mut temp = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)?;
    if let Err(e) = temp.write_all(bytes).and_then(|()| temp.sync_all()) {
        drop(temp);
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }
    drop(temp);

    match std::fs::rename(&temp_path, destination) {
        Ok(()) => Ok(()),
        Err(first) => {
            if destination.exists()
                && std::fs::remove_file(destination).is_ok()
                && std::fs::rename(&temp_path, destination).is_ok()
            {
                return Ok(());
            }
            let _ = std::fs::remove_file(&temp_path);
            Err(first)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_tensor::Normalization;

    fn temp_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "omnisec-gnn-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn dummy_weights_load_into_model() {
        let model = WeightStore::dummy(ModelConfig::default())
            .to_model()
            .unwrap();
        assert_eq!(model.layers.len(), 3);
    }

    #[test]
    fn malformed_shapes_and_versions_are_rejected() {
        let mut s = WeightStore::dummy(ModelConfig::default());
        s.layer_data[1].weights.pop();
        assert!(s.to_model().unwrap_err().to_string().contains("layer 1"));

        let mut s = WeightStore::dummy(ModelConfig::default());
        s.config.layers[1].features_in += 1;
        assert!(
            s.to_model()
                .unwrap_err()
                .to_string()
                .contains("previous output")
        );

        let mut s = WeightStore::dummy(ModelConfig::default());
        s.format_version = WEIGHT_FORMAT_VERSION + 1;
        assert!(s.validate().is_err());

        let mut s = WeightStore::dummy(ModelConfig::default());
        s.metadata.class_names[0] = "malware".into();
        assert!(s.validate().unwrap_err().to_string().contains("taxonomy"));

        let mut s = WeightStore::dummy(ModelConfig::default());
        s.metadata.class_names.truncate(3);
        assert!(
            s.validate()
                .unwrap_err()
                .to_string()
                .contains("class_names")
        );
    }

    #[test]
    fn json_roundtrip_atomic_write_and_v1_defaults() {
        let root = temp_root("weights");
        let path = root.join("nested").join("gnn_weights.json");
        let p = path.to_str().unwrap();
        let mut store = WeightStore::dummy(ModelConfig::default());
        store.metadata.train_samples = 1234;
        store.metadata.seed = Some(42);
        store.metadata.val_macro_f1 = 0.875;
        store.save_json(p).unwrap();
        // Overwriting an existing destination must succeed (rename replaces).
        store.metadata.train_samples = 1235;
        store.save_json(p).unwrap();

        let loaded = WeightStore::load_json(p).unwrap();
        assert_eq!(loaded.metadata.train_samples, 1235);
        assert_eq!(loaded.metadata.seed, Some(42));
        assert_eq!(loaded.metadata.val_macro_f1, 0.875);
        assert_eq!(loaded.format_version, WEIGHT_FORMAT_VERSION);
        assert_eq!(loaded.config.layers.len(), store.config.layers.len());

        // A same-directory temp file must never survive the write.
        let leftovers: Vec<String> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );

        // A v1 file: no format_version / normalisation / residual / class_names
        // and no LayerNorm params. All defaults must make it load unchanged.
        // NOTE: `omnisec_json::json!` cannot parse Rust repeat syntax like
        // `[0.1; 12]`, so vectors are built outside the macro.
        let w0 = vec![0.1_f32; 12];
        let b0 = vec![0.0_f32; 3];
        let w1 = vec![0.2_f32; 6];
        let b1 = vec![0.0_f32; 2];
        let clf_w = vec![0.05_f32; 4];
        let clf_b = vec![0.0_f32; 2];
        let v1 = omnisec_json::json!({
            "config": {
                "layers": [
                    {"features_in": 4, "features_out": 3, "activation": "ReLU", "dropout": 0.0},
                    {"features_in": 3, "features_out": 2, "activation": "None", "dropout": 0.0}
                ],
                "num_classes": 2,
                "readout": "mean"
            },
            "layer_data": [
                {"weights": w0, "bias": b0},
                {"weights": w1, "bias": b1}
            ],
            "classifier_weights": clf_w,
            "classifier_bias": clf_b,
            "metadata": {"train_samples": 10, "val_accuracy": 0.5, "epochs": 1, "version": "v1"}
        });
        let v1_store: WeightStore =
            omnisec_json::from_json_value(&v1).expect("v1 store must deserialize");
        v1_store.validate().expect("v1 store must validate");
        assert_eq!(v1_store.format_version, 1);
        assert_eq!(v1_store.config.normalization, Normalization::Row);
        assert!(!v1_store.config.residual);
        assert!(v1_store.layer_data[0].norm_gamma.is_none());
        let v1_model = v1_store.to_model().unwrap();
        assert!(!v1_model.layers[0].has_layer_norm());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gnnbuf_roundtrip_through_weight_store() {
        let root = temp_root("gnnbuf");
        let p = root.join("m.gnnbuf");
        let ps = p.to_str().unwrap();
        let store = WeightStore::dummy(ModelConfig::default());
        store.save_gnnbuf(ps, "f32").unwrap();
        let loaded = WeightStore::load(ps).unwrap();
        assert_eq!(loaded.config.normalization, store.config.normalization);
        assert_eq!(loaded.config.readout, store.config.readout);
        assert_eq!(loaded.metadata.class_names.len(), NUM_CLASSES);
        let _ = std::fs::remove_dir_all(&root);
    }
}
