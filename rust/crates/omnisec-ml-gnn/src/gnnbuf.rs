//! `.gnnbuf` binary weight container: versioned, validated, bounded.
//!
//! The file is fully read into memory and every offset/length is bounds-checked
//! against the actual buffer before any allocation scales with a
//! attacker-chosen count (the parser never trusts `count`/`nbytes` fields from
//! the file). Tensors are decoded lazily — only the ones the model needs — so
//! a 1 MB file cannot force a 100 000-tensor decode amplification.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::error::{GnnError, Result};
use crate::graph_tensor::Normalization;
use crate::layer::{Activation, LayerConfig};
use crate::model::{ModelConfig, Readout};
use crate::taxonomy::{CLASS_NAMES, NUM_CLASSES};
use crate::weights::{LayerWeights, WeightMetadata, WeightStore};

const MAGIC: &[u8; 8] = b"GNNBUF\0\0";
/// v2: writes and verifies `class_names` / `feature_dim`, rejects unknown
/// activations and unknown flag bits. v1 files (everything the pre-audit
/// encoder produced) still parse with their original semantics.
const VERSION: u32 = 2;
/// Versions this parser accepts (v1 = pre-audit files).
const SUPPORTED_VERSIONS: [u32; 2] = [1, 2];
const ALIGN: usize = 32;
/// No flag bits are defined yet — any set bit means a newer writer.
const KNOWN_FLAGS: u32 = 0;

pub const DT_F32: u8 = 0;
pub const DT_F16: u8 = 1;
pub const DT_INT8: u8 = 2;

pub const VT_U32: u8 = 0;
pub const VT_F32: u8 = 1;
pub const VT_STR: u8 = 2;
pub const VT_STRLIST: u8 = 3;

/// Header (32) + the smallest possible tensor descriptor
/// (name_len u32 + dtype u8 + ndims u8 + scale/offset/nbytes 20).
const DESC_MIN_BYTES: usize = 26;
/// Smallest possible metadata entry (klen u32 + vtype u8 + a u32/f32 value).
const META_MIN_BYTES: usize = 9;

/// Convert IEEE 754 float16 bits (u16) to float32 (f32).
#[must_use]
pub fn f16_to_f32(bits: u16) -> f32 {
    let sign = ((bits >> 15) & 0x0001) as u32;
    let exp = ((bits >> 10) & 0x001f) as u32;
    let mant = (bits & 0x03ff) as u32;

    if exp == 0 {
        if mant == 0 {
            f32::from_bits(sign << 31)
        } else {
            // Subnormal f16 = mant × 2^-24. Normalise the 10-bit mantissa so
            // its leading 1 lands on bit 10; the f32 exponent field is then
            // 103 + p (p = highest set bit of mant). Sanity: mant = 0x200
            // (p = 9) → field 112 → 2^-15, exactly mant × 2^-24.
            // NOTE: `mant` is u32, so the bit position is `ilog2`
            // (the old `15 - leading_zeros()` underflowed: a 10-bit value
            // in a u32 has ≥ 22 leading zeros).
            let p = mant.ilog2(); // 0..=9 position, mant > 0
            let shift = 10 - p; // ≥ 1
            let exp_f32 = 103 + p; // 103..=112
            let mant_f32 = ((mant << shift) & 0x03ff) << 13;
            f32::from_bits((sign << 31) | (exp_f32 << 23) | mant_f32)
        }
    } else if exp == 31 {
        if mant == 0 {
            f32::from_bits((sign << 31) | 0x7f80_0000)
        } else {
            f32::from_bits((sign << 31) | 0x7f80_0000 | (mant << 13))
        }
    } else {
        let exp_f32 = exp + 127 - 15;
        let mant_f32 = mant << 13;
        f32::from_bits((sign << 31) | (exp_f32 << 23) | mant_f32)
    }
}

/// Convert float32 (f32) to IEEE 754 float16 bits (u16).
///
/// Subnormals below the f16 range flush to zero, values inside it are
/// truncated (round-toward-zero) — the pairing with [`f16_to_f32`] is
/// bit-exact for every non-NaN pattern (see the exhaustive roundtrip test).
#[must_use]
pub fn f32_to_f16(val: f32) -> u16 {
    let bits = val.to_bits();
    let sign = ((bits >> 31) & 0x0001) as u16;
    let exp = ((bits >> 23) & 0x00ff) as i32;
    let mant = bits & 0x007f_ffff;

    if exp == 255 {
        if mant != 0 {
            0x7e00 // any NaN → the one canonical quiet NaN (sign is dropped)
        } else {
            (sign << 15) | 0x7c00
        }
    } else {
        let new_exp = exp - 127 + 15;
        if new_exp >= 31 {
            (sign << 15) | 0x7c00 // overflow → infinity
        } else if new_exp <= 0 {
            if new_exp < -10 {
                sign << 15 // underflow → zero
            } else {
                let m = (mant | 0x0080_0000) >> (1 - new_exp);
                (sign << 15) | ((m >> 13) as u16)
            }
        } else {
            (sign << 15) | ((new_exp as u16) << 10) | ((mant >> 13) as u16)
        }
    }
}

fn pad_len(n: usize) -> usize {
    (ALIGN - (n % ALIGN)) % ALIGN
}

fn format_err(msg: impl Into<String>) -> GnnError {
    GnnError::Format(msg.into())
}

#[derive(Debug, Clone)]
pub enum MetaValue {
    U32(u32),
    F32(f32),
    Str(String),
    StrList(Vec<String>),
}

#[derive(Debug, Clone)]
pub struct TensorDesc {
    /// Declared shape — the only descriptor field read after decode; dtype,
    /// scale and offsets are validated inline while the payload is decoded.
    pub dims: Vec<u32>,
}

/// Bounds-checked cursor over the raw file bytes. All length arithmetic goes
/// through `checked_add`, so a malformed file can only produce a clean `Err`,
/// never a panic or a wrap on any pointer width.
struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.cursor
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(n)
            .ok_or_else(|| format_err(format!("truncated {what}: length overflow")))?;
        if end > self.bytes.len() {
            return Err(format_err(format!("truncated {what}")));
        }
        let s = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(s)
    }

    fn u8(&mut self, what: &str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }

    fn u32(&mut self, what: &str) -> Result<u32> {
        let b = self.take(4, what)?;
        Ok(u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    fn u64(&mut self, what: &str) -> Result<u64> {
        let b = self.take(8, what)?;
        Ok(u64::from_le_bytes(b.try_into().expect("8 bytes")))
    }

    fn f32(&mut self, what: &str) -> Result<f32> {
        let b = self.take(4, what)?;
        Ok(f32::from_le_bytes(b.try_into().expect("4 bytes")))
    }

    fn string(&mut self, len: usize, what: &str) -> Result<String> {
        let b = self.take(len, what)?;
        std::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|e| format_err(format!("invalid utf-8 in {what}: {e}")))
    }
}

/// Parse `.gnnbuf` from an in-memory byte slice.
pub fn parse_gnnbuf_bytes(bytes: &[u8]) -> Result<WeightStore> {
    if bytes.len() < 32 {
        return Err(format_err("buffer too short for .gnnbuf header"));
    }
    if &bytes[0..8] != MAGIC {
        return Err(format_err("invalid .gnnbuf magic header"));
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
    if !SUPPORTED_VERSIONS.contains(&version) {
        return Err(format_err(format!("unsupported .gnnbuf version {version}")));
    }
    let flags = u32::from_le_bytes(bytes[12..16].try_into().expect("4 bytes"));
    if flags & !KNOWN_FLAGS != 0 {
        return Err(format_err(format!("unknown .gnnbuf flag bits {flags:#x}")));
    }
    let n_meta = u32::from_le_bytes(bytes[16..20].try_into().expect("4 bytes")) as usize;
    let n_tensors = u32::from_le_bytes(bytes[20..24].try_into().expect("4 bytes")) as usize;
    let data_offset = usize::try_from(u64::from_le_bytes(
        bytes[24..32].try_into().expect("8 bytes"),
    ))
    .map_err(|_| format_err("data_offset does not fit the address width"))?;

    // Every metadata entry consumes at least META_MIN_BYTES; every tensor
    // descriptor at least DESC_MIN_BYTES. Reject counts that cannot possibly
    // fit BEFORE iterating, so a crafted 32-byte header cannot drive a huge
    // loop or a huge preallocation.
    if n_meta > (bytes.len().saturating_sub(32)) / META_MIN_BYTES {
        return Err(format_err(format!(
            "metadata count {n_meta} exceeds buffer size"
        )));
    }
    if n_tensors > bytes.len() / DESC_MIN_BYTES {
        return Err(format_err(format!(
            "tensor count {n_tensors} exceeds buffer size"
        )));
    }

    let mut reader = Reader { bytes, cursor: 32 };

    let mut meta: HashMap<String, MetaValue> = HashMap::with_capacity(n_meta);
    for _ in 0..n_meta {
        let klen = reader.u32("metadata key_len")? as usize;
        let key = reader.string(klen, "metadata key")?;
        let vtype = reader.u8("metadata vtype")?;
        let val = match vtype {
            VT_U32 => MetaValue::U32(reader.u32("u32 meta")?),
            VT_F32 => MetaValue::F32(reader.f32("f32 meta")?),
            VT_STR => {
                let vl = reader.u32("str len meta")? as usize;
                MetaValue::Str(reader.string(vl, "str meta")?)
            }
            VT_STRLIST => {
                let count = reader.u32("str list count")? as usize;
                // Each list item needs at least its own 4-byte length prefix.
                if count > reader.remaining() / 4 {
                    return Err(format_err(format!(
                        "str list count {count} exceeds remaining bytes"
                    )));
                }
                let mut list = Vec::with_capacity(count);
                for _ in 0..count {
                    let il = reader.u32("str item len")? as usize;
                    list.push(reader.string(il, "str item")?);
                }
                MetaValue::StrList(list)
            }
            other => return Err(format_err(format!("unknown meta vtype {other}"))),
        };
        meta.insert(key, val);
    }

    let num_layers = match meta.get("num_layers") {
        Some(MetaValue::U32(n)) => *n as usize,
        _ => return Err(format_err("missing or invalid metadata 'num_layers'")),
    };
    let num_classes = match meta.get("num_classes") {
        Some(MetaValue::U32(n)) => *n as usize,
        _ => return Err(format_err("missing or invalid metadata 'num_classes'")),
    };
    if num_layers > n_tensors {
        return Err(format_err(format!(
            "num_layers {num_layers} exceeds the {n_tensors} tensor(s) in the file"
        )));
    }

    let readout = match meta.get("readout") {
        Some(MetaValue::Str(s)) => {
            Readout::parse(s).ok_or_else(|| format_err(format!("unknown readout '{s}'")))?
        }
        _ => Readout::Mean,
    };
    let normalization = match meta.get("normalization") {
        Some(MetaValue::Str(s)) => Normalization::parse(s)
            .ok_or_else(|| format_err(format!("unknown normalization '{s}'")))?,
        _ => Normalization::Row, // v1 default
    };
    let residual = match meta.get("residual") {
        Some(MetaValue::U32(n)) => *n != 0,
        _ => false,
    };
    let activations: Vec<String> = match meta.get("activations") {
        Some(MetaValue::StrList(l)) => l.clone(),
        _ => vec!["ReLU".to_string(); num_layers],
    };

    // Tensor descriptors are scanned first and only the names the model
    // actually references are decoded — a file with 10⁵ descriptors pointing
    // at one region cannot force an equivalent decode.
    let mut needed: HashSet<String> = HashSet::new();
    for i in 0..num_layers {
        needed.insert(format!("layer{i}.weight"));
        needed.insert(format!("layer{i}.bias"));
        needed.insert(format!("layer{i}.norm_gamma"));
        needed.insert(format!("layer{i}.norm_beta"));
    }
    needed.insert("classifier.weight".to_string());
    needed.insert("classifier.bias".to_string());
    needed.insert("config.dropouts".to_string());

    let mut tensors: HashMap<String, (TensorDesc, Vec<f32>)> = HashMap::new();
    let mut seen_names: HashSet<String> = HashSet::new();
    for _ in 0..n_tensors {
        let nlen = reader.u32("tensor name_len")? as usize;
        let name = reader.string(nlen, "tensor name")?;
        let dtype = reader.u8("tensor dtype")?;
        let n_dims = reader.u8("tensor ndims")? as usize;
        let mut dims = Vec::with_capacity(n_dims);
        for _ in 0..n_dims {
            dims.push(reader.u32("tensor dim")?);
        }
        let scale = reader.f32("tensor scale")?;
        if !matches!(dtype, DT_F32 | DT_F16 | DT_INT8) {
            return Err(format_err(format!("tensor {name} unknown dtype {dtype}")));
        }
        if !seen_names.insert(name.clone()) {
            return Err(format_err(format!("duplicate tensor name {name}")));
        }

        let rel_offset = usize::try_from(reader.u64("tensor rel_offset")?)
            .map_err(|_| format_err(format!("tensor {name} offset overflow")))?;
        let nb = usize::try_from(reader.u64("tensor nbytes")?)
            .map_err(|_| format_err(format!("tensor {name} size overflow")))?;
        let abs_off = data_offset
            .checked_add(rel_offset)
            .ok_or_else(|| format_err(format!("tensor {name} offset overflow")))?;
        let end = abs_off
            .checked_add(nb)
            .ok_or_else(|| format_err(format!("tensor {name} size overflow")))?;
        if end > bytes.len() {
            return Err(format_err(format!(
                "tensor {name} data out of bounds ({abs_off}+{nb} > {})",
                bytes.len()
            )));
        }
        if !needed.contains(name.as_str()) {
            continue; // lazy: don't decode tensors this model never reads
        }

        let slice = &bytes[abs_off..end];
        let floats: Vec<f32> = match dtype {
            DT_F32 => {
                if nb % 4 != 0 {
                    return Err(format_err(format!("tensor {name} invalid f32 nbytes {nb}")));
                }
                slice
                    .chunks_exact(4)
                    .map(|c| f32::from_le_bytes(c.try_into().expect("4 bytes")))
                    .collect()
            }
            DT_F16 => {
                if nb % 2 != 0 {
                    return Err(format_err(format!("tensor {name} invalid f16 nbytes {nb}")));
                }
                slice
                    .chunks_exact(2)
                    .map(|c| {
                        let bits = u16::from_le_bytes(c.try_into().expect("2 bytes"));
                        f16_to_f32(bits)
                    })
                    .collect()
            }
            _ => slice.iter().map(|&b| (b as i8 as f32) * scale).collect(), // DT_INT8
        };
        tensors.insert(name, (TensorDesc { dims }, floats));
    }

    let mut layer_configs = Vec::with_capacity(num_layers);
    let mut layer_data = Vec::with_capacity(num_layers);
    for i in 0..num_layers {
        let w_name = format!("layer{i}.weight");
        let b_name = format!("layer{i}.bias");
        let (w_desc, w_vals) = tensors
            .get(&w_name)
            .ok_or_else(|| format_err(format!("missing tensor {w_name}")))?;
        let (_b_desc, b_vals) = tensors
            .get(&b_name)
            .ok_or_else(|| format_err(format!("missing tensor {b_name}")))?;

        if w_desc.dims.len() != 2 {
            return Err(format_err(format!(
                "{w_name} expected 2 dims, got {:?}",
                w_desc.dims
            )));
        }
        let fin = w_desc.dims[0] as usize;
        let fout = w_desc.dims[1] as usize;
        if w_vals.len() != fin * fout || b_vals.len() != fout {
            return Err(format_err(format!(
                "{w_name} payload {} / bias {} do not match dims {fin}×{fout}",
                w_vals.len(),
                b_vals.len()
            )));
        }

        let act_str = activations.get(i).map(String::as_str).unwrap_or("ReLU");
        let act = Activation::parse(act_str)
            .ok_or_else(|| format_err(format!("layer {i}: unknown activation '{act_str}'")))?;

        let norm_gamma = tensors
            .get(&format!("layer{i}.norm_gamma"))
            .map(|(_, f)| f.clone());
        let norm_beta = tensors
            .get(&format!("layer{i}.norm_beta"))
            .map(|(_, f)| f.clone());
        if norm_gamma.is_some() != norm_beta.is_some() {
            return Err(format_err(format!(
                "layer {i} must provide both norm_gamma and norm_beta or neither"
            )));
        }
        if let Some(g) = &norm_gamma {
            if g.len() != fout {
                return Err(format_err(format!(
                    "layer {i} norm_gamma length {} != {fout}",
                    g.len()
                )));
            }
        }

        layer_configs.push(LayerConfig {
            features_in: fin,
            features_out: fout,
            activation: act,
            dropout: 0.0, // real dropouts are filled in below
        });
        layer_data.push(LayerWeights {
            weights: w_vals.clone(),
            bias: b_vals.clone(),
            norm_gamma,
            norm_beta,
        });
    }

    let dropouts = tensors
        .get("config.dropouts")
        .map(|(_, f)| f.clone())
        .unwrap_or_else(|| vec![0.0; num_layers]);
    if dropouts.len() != num_layers {
        return Err(format_err(format!(
            "config.dropouts length {} != num_layers {num_layers}",
            dropouts.len()
        )));
    }
    for (i, lc) in layer_configs.iter_mut().enumerate() {
        let d = dropouts[i];
        if !d.is_finite() || !(0.0..1.0).contains(&d) {
            return Err(format_err(format!("layer {i} invalid dropout {d}")));
        }
        lc.dropout = d;
    }

    let (_wc_desc, wc_vals) = tensors
        .get("classifier.weight")
        .ok_or_else(|| format_err("missing classifier.weight"))?;
    let (_bc_desc, bc_vals) = tensors
        .get("classifier.bias")
        .ok_or_else(|| format_err("missing classifier.bias"))?;
    if bc_vals.len() != num_classes || wc_vals.len() % num_classes != 0 || wc_vals.is_empty() {
        return Err(format_err("classifier payload does not match num_classes"));
    }

    // The config's own contract: consecutive widths must line up.
    let feature_dim = layer_configs.first().map_or(0, |l| l.features_in);
    if let Some(MetaValue::U32(fd)) = meta.get("feature_dim") {
        if *fd as usize != feature_dim {
            return Err(format_err(format!(
                "feature_dim meta {fd} != first layer input {feature_dim}"
            )));
        }
    }
    let class_names = match meta.get("class_names") {
        Some(MetaValue::StrList(l)) => l.clone(),
        _ => Vec::new(),
    };
    if !class_names.is_empty() {
        if class_names.len() != num_classes {
            return Err(format_err(format!(
                "class_names has {} entries, num_classes = {num_classes}",
                class_names.len()
            )));
        }
        if num_classes == NUM_CLASSES && class_names.iter().zip(CLASS_NAMES).any(|(a, b)| a != b) {
            return Err(format_err(format!(
                "class_names {class_names:?} do not match the taxonomy {CLASS_NAMES:?}"
            )));
        }
    }

    let store = WeightStore {
        format_version: match meta.get("weight_format_version") {
            Some(MetaValue::U32(n)) => *n,
            _ => 1,
        },
        config: ModelConfig {
            layers: layer_configs,
            num_classes,
            readout,
            normalization,
            residual,
        },
        layer_data,
        classifier_weights: wc_vals.clone(),
        classifier_bias: bc_vals.clone(),
        metadata: WeightMetadata {
            train_samples: match meta.get("train_samples") {
                Some(MetaValue::U32(n)) => *n as usize,
                _ => 0,
            },
            val_accuracy: match meta.get("val_accuracy") {
                Some(MetaValue::F32(f)) => *f,
                _ => 0.0,
            },
            val_macro_f1: match meta.get("val_macro_f1") {
                Some(MetaValue::F32(f)) => *f,
                _ => 0.0,
            },
            epochs: match meta.get("epochs") {
                Some(MetaValue::U32(n)) => *n as usize,
                _ => 0,
            },
            version: match meta.get("model_version") {
                Some(MetaValue::Str(s)) => s.clone(),
                _ => "1.0.0".to_string(),
            },
            seed: None,
            train_config: None,
            class_names,
            // .gnnbuf carries no feature-schema stamp yet; 0 marks it legacy
            // so the Go pre-load validation falls back to the dimension check.
            feature_schema_version: 0,
            conformal_q90: None,
            ood_threshold: None,
        },
    };

    store.validate()?;
    Ok(store)
}

/// Load `.gnnbuf` from a file path.
pub fn load_gnnbuf_file(path: &str) -> Result<WeightStore> {
    let f = File::open(Path::new(path))?;
    let mut bytes = Vec::new();
    BufReader::new(f).read_to_end(&mut bytes)?;
    parse_gnnbuf_bytes(&bytes)
}

/// One metadata entry accumulated by [`encode_gnnbuf`] — the entry count is
/// derived from the vector length, never hardcoded.
struct MetaEntry {
    key: &'static str,
    value: MetaValue,
}

/// Private helper used only by [`encode_gnnbuf`] to accumulate raw tensor
/// descriptors before the binary layout is finalised.
struct RawTensor {
    name: String,
    dtype: u8,
    dims: Vec<u32>,
    scale: f32,
    raw: Vec<u8>,
}

/// Encode WeightStore to `.gnnbuf` binary bytes. Validates the store first —
/// invalid weights never reach disk.
pub fn encode_gnnbuf(store: &WeightStore, quant: &str) -> Result<Vec<u8>> {
    store.validate()?;

    let mut meta_entries: Vec<MetaEntry> = Vec::new();
    let push_u32 = |entries: &mut Vec<MetaEntry>, key: &'static str, val: u32| {
        entries.push(MetaEntry {
            key,
            value: MetaValue::U32(val),
        });
    };
    let push_f32 = |entries: &mut Vec<MetaEntry>, key: &'static str, val: f32| {
        entries.push(MetaEntry {
            key,
            value: MetaValue::F32(val),
        });
    };
    let push_str = |entries: &mut Vec<MetaEntry>, key: &'static str, val: String| {
        entries.push(MetaEntry {
            key,
            value: MetaValue::Str(val),
        });
    };
    let push_strlist = |entries: &mut Vec<MetaEntry>, key: &'static str, list: Vec<String>| {
        entries.push(MetaEntry {
            key,
            value: MetaValue::StrList(list),
        });
    };

    let acts: Vec<String> = store
        .config
        .layers
        .iter()
        .map(|l| l.activation.as_str().to_string())
        .collect();
    let arch = format!(
        "{}-{}",
        store.config.layers[0].features_in,
        store
            .config
            .layers
            .iter()
            .map(|l| l.features_out.to_string())
            .collect::<Vec<_>>()
            .join("-")
    );
    let class_names: Vec<String> = if store.config.num_classes == NUM_CLASSES {
        CLASS_NAMES.iter().map(|s| (*s).to_string()).collect()
    } else {
        Vec::new()
    };

    push_str(&mut meta_entries, "format", "gnnbuf".to_string());
    push_str(
        &mut meta_entries,
        "model_version",
        store.metadata.version.clone(),
    );
    push_str(
        &mut meta_entries,
        "readout",
        store.config.readout.as_str().to_string(),
    );
    push_str(&mut meta_entries, "quant", quant.to_string());
    push_u32(
        &mut meta_entries,
        "num_classes",
        store.config.num_classes as u32,
    );
    push_u32(
        &mut meta_entries,
        "feature_dim",
        store.config.layers[0].features_in as u32,
    );
    push_u32(
        &mut meta_entries,
        "num_layers",
        store.config.layers.len() as u32,
    );
    push_str(&mut meta_entries, "arch", arch);
    push_strlist(&mut meta_entries, "activations", acts);
    push_strlist(&mut meta_entries, "class_names", class_names);
    push_u32(
        &mut meta_entries,
        "train_samples",
        store.metadata.train_samples as u32,
    );
    push_f32(
        &mut meta_entries,
        "val_accuracy",
        store.metadata.val_accuracy,
    );
    push_f32(
        &mut meta_entries,
        "val_macro_f1",
        store.metadata.val_macro_f1,
    );
    push_u32(&mut meta_entries, "epochs", store.metadata.epochs as u32);
    push_str(
        &mut meta_entries,
        "normalization",
        store.config.normalization.as_str().to_string(),
    );
    push_u32(
        &mut meta_entries,
        "residual",
        u32::from(store.config.residual),
    );
    push_u32(
        &mut meta_entries,
        "weight_format_version",
        store.format_version,
    );

    let mut meta_bytes = Vec::new();
    for entry in &meta_entries {
        let kb = entry.key.as_bytes();
        meta_bytes.extend_from_slice(&(kb.len() as u32).to_le_bytes());
        meta_bytes.extend_from_slice(kb);
        match &entry.value {
            MetaValue::U32(v) => {
                meta_bytes.push(VT_U32);
                meta_bytes.extend_from_slice(&v.to_le_bytes());
            }
            MetaValue::F32(v) => {
                meta_bytes.push(VT_F32);
                meta_bytes.extend_from_slice(&v.to_le_bytes());
            }
            MetaValue::Str(s) => {
                meta_bytes.push(VT_STR);
                let vb = s.as_bytes();
                meta_bytes.extend_from_slice(&(vb.len() as u32).to_le_bytes());
                meta_bytes.extend_from_slice(vb);
            }
            MetaValue::StrList(list) => {
                meta_bytes.push(VT_STRLIST);
                meta_bytes.extend_from_slice(&(list.len() as u32).to_le_bytes());
                for item in list {
                    let ib = item.as_bytes();
                    meta_bytes.extend_from_slice(&(ib.len() as u32).to_le_bytes());
                    meta_bytes.extend_from_slice(ib);
                }
            }
        }
    }
    let n_meta = meta_entries.len();

    let quant_tensor = |name: &str, arr: &[f32], dims: Vec<u32>, is_weight: bool| -> RawTensor {
        let target_quant = if is_weight { quant } else { "f32" };
        match target_quant {
            "f16" => {
                let raw: Vec<u8> = arr
                    .iter()
                    .flat_map(|&v| f32_to_f16(v).to_le_bytes())
                    .collect();
                RawTensor {
                    name: name.to_string(),
                    dtype: DT_F16,
                    dims,
                    scale: 1.0,
                    raw,
                }
            }
            "int8" => {
                // Per-tensor maxabs scale: simple and dependency-free. One
                // outlier shrinks the resolution of the whole tensor — the
                // drift test below pins the resulting accuracy budget.
                let maxabs = arr
                    .iter()
                    .map(|v| v.abs())
                    .fold(0.0_f32, |a, b| if b > a { b } else { a });
                let scale = if maxabs > 0.0 { maxabs / 127.0 } else { 1.0 };
                let raw: Vec<u8> = arr
                    .iter()
                    .map(|&v| {
                        let q = (v / scale).round().clamp(-127.0, 127.0);
                        q as i8 as u8
                    })
                    .collect();
                RawTensor {
                    name: name.to_string(),
                    dtype: DT_INT8,
                    dims,
                    scale,
                    raw,
                }
            }
            _ => {
                let raw: Vec<u8> = arr.iter().flat_map(|&v| v.to_le_bytes()).collect();
                RawTensor {
                    name: name.to_string(),
                    dtype: DT_F32,
                    dims,
                    scale: 1.0,
                    raw,
                }
            }
        }
    };

    let mut tensors = Vec::new();
    for (i, (lc, lw)) in store
        .config
        .layers
        .iter()
        .zip(store.layer_data.iter())
        .enumerate()
    {
        tensors.push(quant_tensor(
            &format!("layer{i}.weight"),
            &lw.weights,
            vec![lc.features_in as u32, lc.features_out as u32],
            true,
        ));
        tensors.push(quant_tensor(
            &format!("layer{i}.bias"),
            &lw.bias,
            vec![lc.features_out as u32],
            false,
        ));
        if let Some(ref g) = lw.norm_gamma {
            tensors.push(quant_tensor(
                &format!("layer{i}.norm_gamma"),
                g,
                vec![lc.features_out as u32],
                false,
            ));
        }
        if let Some(ref b) = lw.norm_beta {
            tensors.push(quant_tensor(
                &format!("layer{i}.norm_beta"),
                b,
                vec![lc.features_out as u32],
                false,
            ));
        }
    }

    let nc = store.config.num_classes as u32;
    let classifier_in = store.config.embedding_dims();
    tensors.push(quant_tensor(
        "classifier.weight",
        &store.classifier_weights,
        vec![classifier_in as u32, nc],
        true,
    ));
    tensors.push(quant_tensor(
        "classifier.bias",
        &store.classifier_bias,
        vec![nc],
        false,
    ));

    let dropouts: Vec<f32> = store.config.layers.iter().map(|l| l.dropout).collect();
    tensors.push(quant_tensor(
        "config.dropouts",
        &dropouts,
        vec![dropouts.len() as u32],
        false,
    ));

    let n_tensors = tensors.len();

    let mut data_blobs = Vec::new();
    let mut descs = Vec::new();
    let mut cursor = 0;

    for t in &tensors {
        cursor += pad_len(cursor);
        let rel_off = cursor as u64;
        let nbytes = t.raw.len() as u64;
        data_blobs.push((rel_off, &t.raw));
        cursor += t.raw.len();

        let mut desc_bytes = Vec::new();
        let nb = t.name.as_bytes();
        desc_bytes.extend_from_slice(&(nb.len() as u32).to_le_bytes());
        desc_bytes.extend_from_slice(nb);
        desc_bytes.push(t.dtype);
        desc_bytes.push(t.dims.len() as u8);
        for &d in &t.dims {
            desc_bytes.extend_from_slice(&d.to_le_bytes());
        }
        desc_bytes.extend_from_slice(&t.scale.to_le_bytes());
        desc_bytes.extend_from_slice(&rel_off.to_le_bytes());
        desc_bytes.extend_from_slice(&nbytes.to_le_bytes());

        descs.push(desc_bytes);
    }

    let header_fixed = 8 + 4 + 4 + 4 + 4 + 8; // magic + version + flags + n_meta + n_tensors + data_offset
    let desc_total: usize = descs.iter().map(Vec::len).sum();
    let pre_data = header_fixed + meta_bytes.len() + desc_total;
    let data_offset = pre_data + pad_len(pre_data);

    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(n_meta as u32).to_le_bytes());
    out.extend_from_slice(&(n_tensors as u32).to_le_bytes());
    out.extend_from_slice(&(data_offset as u64).to_le_bytes());

    out.extend_from_slice(&meta_bytes);
    for d in descs {
        out.extend_from_slice(&d);
    }

    out.resize(data_offset, 0);

    let mut written = 0;
    for (rel_off, raw) in data_blobs {
        let gap = (rel_off as usize) - written;
        if gap > 0 {
            out.resize(out.len() + gap, 0);
            written += gap;
        }
        out.extend_from_slice(raw);
        written += raw.len();
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::float_cmp)]
    use super::*;
    use crate::graph_tensor::{EdgeType, GraphTensor};

    /// v1-style store: row normalization, mean readout, no LayerNorm.
    fn v1_store() -> WeightStore {
        let config = ModelConfig {
            layers: vec![
                LayerConfig {
                    features_in: 28,
                    features_out: 16,
                    activation: Activation::ReLU,
                    dropout: 0.0,
                },
                LayerConfig {
                    features_in: 16,
                    features_out: 8,
                    activation: Activation::ReLU,
                    dropout: 0.0,
                },
            ],
            num_classes: 8,
            readout: Readout::Mean,
            normalization: Normalization::Row,
            residual: false,
        };
        let mut store = WeightStore::dummy(config);
        for layer in &mut store.layer_data {
            layer.norm_gamma = None;
            layer.norm_beta = None;
        }
        store
    }

    #[test]
    fn f16_roundtrip_is_exhaustive_over_all_16_bit_patterns() {
        for bits in 0..=u16::MAX {
            let f = f16_to_f32(bits);
            if f.is_nan() {
                // NaN payloads collapse to the quiet NaN on re-encode.
                assert_eq!(f32_to_f16(f), 0x7e00, "NaN from bits {bits:#06x}");
                continue;
            }
            assert_eq!(f32_to_f16(f), bits, "bits {bits:#06x}");
        }
    }

    #[test]
    fn f16_subnormals_decode_exactly() {
        // mant × 2^-24 for every subnormal — the old decoder was off by a
        // factor of two here (0x200 decoded to 2^-14 instead of 2^-15).
        assert_eq!(f16_to_f32(0x0001), 2.0_f32.powi(-24));
        assert_eq!(f16_to_f32(0x0200), 2.0_f32.powi(-15));
        assert_eq!(f16_to_f32(0x03FF), 1023.0 * 2.0_f32.powi(-24));
        assert_eq!(f16_to_f32(0x8000), -0.0);
    }

    #[test]
    fn encode_and_parse_gnnbuf_v2_roundtrip() {
        let store = WeightStore::dummy(ModelConfig::default());
        let encoded = encode_gnnbuf(&store, "f32").expect("encode v2 f32");
        let decoded = parse_gnnbuf_bytes(&encoded).expect("parse v2 f32");

        assert_eq!(decoded.config.readout, store.config.readout);
        assert_eq!(decoded.config.normalization, store.config.normalization);
        assert_eq!(decoded.config.residual, store.config.residual);
        assert_eq!(decoded.layer_data.len(), store.layer_data.len());
        for (orig, dec) in store.layer_data.iter().zip(decoded.layer_data.iter()) {
            assert_eq!(orig.norm_gamma.is_some(), dec.norm_gamma.is_some());
            assert_eq!(orig.norm_beta.is_some(), dec.norm_beta.is_some());
        }
    }

    #[test]
    fn encode_and_parse_gnnbuf_roundtrip_fp32() {
        let store = v1_store();
        let encoded = encode_gnnbuf(&store, "f32").expect("encode f32");
        let decoded = parse_gnnbuf_bytes(&encoded).expect("parse f32");

        assert_eq!(decoded.config.layers.len(), store.config.layers.len());
        assert_eq!(decoded.config.num_classes, store.config.num_classes);
        assert_eq!(
            decoded.classifier_weights.len(),
            store.classifier_weights.len()
        );
        assert!(decoded.layer_data[0].norm_gamma.is_none());

        for (a, b) in store
            .classifier_weights
            .iter()
            .zip(decoded.classifier_weights.iter())
        {
            assert!((a - b).abs() < 1e-5);
        }
    }

    fn small_graph() -> GraphTensor {
        let features = vec![
            crate::graph_tensor::NodeFeatures {
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

    fn small_config() -> ModelConfig {
        ModelConfig {
            layers: vec![
                LayerConfig {
                    features_in: 36,
                    features_out: 8,
                    activation: Activation::ReLU,
                    dropout: 0.0,
                },
                LayerConfig {
                    features_in: 8,
                    features_out: 8,
                    activation: Activation::ReLU,
                    dropout: 0.0,
                },
            ],
            num_classes: NUM_CLASSES,
            readout: Readout::MeanMax,
            normalization: Normalization::Symmetric,
            residual: false,
        }
    }

    #[test]
    fn encode_and_parse_gnnbuf_roundtrip_int8() {
        let store = v1_store();
        let encoded = encode_gnnbuf(&store, "int8").expect("encode int8");
        let decoded = parse_gnnbuf_bytes(&encoded).expect("parse int8");

        assert_eq!(decoded.config.layers.len(), store.config.layers.len());
        assert_eq!(decoded.config.num_classes, store.config.num_classes);
    }

    /// INT8 weights must not change predictions beyond the accuracy budget:
    /// the same graph through the f32 model and the int8-requantised model
    /// differs by less than 1e-2 per class probability.
    #[test]
    fn int8_quantization_drift_is_bounded() {
        let store = WeightStore::dummy(small_config());
        let f32_model = store.to_model().unwrap();
        let int8_encoded = encode_gnnbuf(&store, "int8").expect("encode int8");
        let int8_model = parse_gnnbuf_bytes(&int8_encoded)
            .expect("parse int8")
            .to_model()
            .unwrap();

        let g = small_graph();
        let a = f32_model.predict(&g).unwrap().class_probs;
        let b = int8_model.predict(&g).unwrap().class_probs;
        for (x, y) in a.iter().zip(&b) {
            assert!((x - y).abs() < 1e-2, "int8 drift {x} vs {y}");
        }
    }

    #[test]
    fn f16_quantization_drift_is_bounded() {
        let store = WeightStore::dummy(small_config());
        let f32_model = store.to_model().unwrap();
        let f16_encoded = encode_gnnbuf(&store, "f16").expect("encode f16");
        let f16_model = parse_gnnbuf_bytes(&f16_encoded)
            .expect("parse f16")
            .to_model()
            .unwrap();

        let g = small_graph();
        let a = f32_model.predict(&g).unwrap().class_probs;
        let b = f16_model.predict(&g).unwrap().class_probs;
        for (x, y) in a.iter().zip(&b) {
            assert!((x - y).abs() < 1e-3, "f16 drift {x} vs {y}");
        }
    }

    /// A malformed `.gnnbuf` file can set `data_offset`/`rel_offset`/`nbytes`
    /// to attacker-chosen values near `u64::MAX`. Parsing must return an
    /// `Err`, never panic (integer overflow / out-of-bounds slice index).
    #[test]
    fn parse_rejects_overflowing_tensor_offsets() {
        let store = v1_store();
        let mut bytes = encode_gnnbuf(&store, "f32").expect("encode f32");

        // data_offset lives at bytes[24..32] (little-endian u64), right
        // after magic(8) + version(4) + flags(4) + n_meta(4) + n_tensors(4).
        let huge = (u64::MAX - 4).to_le_bytes();
        bytes[24..32].copy_from_slice(&huge);

        let result = parse_gnnbuf_bytes(&bytes);
        assert!(
            result.is_err(),
            "overflowing data_offset must be rejected, not panic"
        );
    }

    fn header_with(n_meta: u32, n_tensors: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&VERSION.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&n_meta.to_le_bytes());
        b.extend_from_slice(&n_tensors.to_le_bytes());
        b.extend_from_slice(&32u64.to_le_bytes());
        b
    }

    /// Crafted headers with absurd counts must produce clean `Err`s, never
    /// `handle_alloc_error` aborts (the Go process calls this parser on
    /// untrusted files).
    #[test]
    fn crafted_counts_are_rejected_without_allocating() {
        // n_tensors = u32::MAX on a tiny buffer.
        let err = parse_gnnbuf_bytes(&header_with(0, u32::MAX)).unwrap_err();
        assert!(err.to_string().contains("tensor count"), "{err}");

        // 10⁵ tensor descriptors cannot fit in a 40-byte file.
        let err = parse_gnnbuf_bytes(&header_with(0, 100_000)).unwrap_err();
        assert!(err.to_string().contains("tensor count"), "{err}");

        // n_meta too large for the buffer.
        let err = parse_gnnbuf_bytes(&header_with(u32::MAX, 0)).unwrap_err();
        assert!(err.to_string().contains("metadata count"), "{err}");
    }

    /// `num_layers` larger than the actual tensor count must be rejected
    /// before any per-layer lookups (and before decoding anything).
    #[test]
    fn num_layers_above_tensor_count_is_rejected() {
        let mut b = header_with(2, 0);
        // meta entry 1: klen=10 "num_layers", vtype u32, value u32::MAX
        b.extend_from_slice(&10u32.to_le_bytes());
        b.extend_from_slice(b"num_layers");
        b.push(VT_U32);
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        // meta entry 2: a valid num_classes, so the rejection fires on the
        // num_layers-vs-tensor-count guard (not on a missing num_classes).
        b.extend_from_slice(&11u32.to_le_bytes());
        b.extend_from_slice(b"num_classes");
        b.push(VT_U32);
        b.extend_from_slice(&8u32.to_le_bytes());
        let err = parse_gnnbuf_bytes(&b).unwrap_err();
        assert!(err.to_string().contains("num_layers"), "{err}");
    }

    /// A strlist count of u32::MAX must be rejected against the remaining
    /// bytes instead of `Vec::with_capacity(count)` (~100 GB alloc → abort).
    #[test]
    fn strlist_count_overflow_is_rejected() {
        let mut b = header_with(1, 0);
        // meta entry: klen=1 "t", vtype VT_STRLIST, count = u32::MAX
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(b"t");
        b.push(VT_STRLIST);
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        let err = parse_gnnbuf_bytes(&b).unwrap_err();
        assert!(err.to_string().contains("str list count"), "{err}");
    }

    /// Unknown activation strings must be rejected, not silently mapped to
    /// ReLU. The valid file contains "ReLU" inside the activations meta —
    /// swapping it for a same-length garbage string must fail the parse.
    #[test]
    fn unknown_activation_is_rejected() {
        let store = v1_store();
        let mut bytes = encode_gnnbuf(&store, "f32").expect("encode f32");
        let pos = bytes
            .windows(4)
            .position(|w| w == b"ReLU")
            .expect("activations meta must contain ReLU");
        bytes[pos..pos + 4].copy_from_slice(b"GELU");
        let err = parse_gnnbuf_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("activation"), "{err}");
    }

    /// The written file must be self-describing: class_names are stored and a
    /// tampered list is rejected at load time (taxonomy-drift guard).
    #[test]
    fn class_names_are_written_and_verified() {
        let store = v1_store();
        let mut bytes = encode_gnnbuf(&store, "f32").expect("encode f32");
        let decoded = parse_gnnbuf_bytes(&bytes).expect("parse");
        assert_eq!(decoded.metadata.class_names, CLASS_NAMES.to_vec());

        // Tamper: rename one class inside the strlist meta (same length).
        let pos = bytes
            .windows(6)
            .position(|w| w == b"benign")
            .expect("class_names meta must contain benign");
        bytes[pos..pos + 6].copy_from_slice(b"trojan");
        let err = parse_gnnbuf_bytes(&bytes).unwrap_err();
        assert!(err.to_string().contains("taxonomy"), "{err}");
    }
}
