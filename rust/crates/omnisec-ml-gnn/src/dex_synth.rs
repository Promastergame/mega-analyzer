//! DEX license/piracy domain dataset for the OmniSec GNN.
//!
//! Two sources, one API (mirrors [`crate::synth`]):
//!   * [`build_dataset`] — deterministic synthetic graphs whose structure
//!     encodes the eight DEX license/piracy classes in [`crate::taxonomy`].
//!     Use it ONLY as a bootstrap / smoke-test distribution to exercise the
//!     training loop before you have a real corpus.
//!   * [`load_jsonl_dataset`] — loads REAL labelled graphs exported by the
//!     scanner (`pkg/ml/gnndataset`): the graphs the analyzer already writes
//!     to `~/.analyzer/gnn-dataset/*.jsonl` on every scan. This is the data
//!     that actually makes the model useful.
//!
//! Feature vectors use the exact [`NodeFeatures`] layout (28 dims) and edges
//! use [`EdgeType`], so both sources are wire-compatible with inference.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use omnisec_json::FromJson;

use crate::graph_tensor::{EdgeType, GraphTensor, NodeFeatures};
use crate::taxonomy::{CLASS_NAMES, NUM_CLASSES};
use crate::trainer::Example;

/// Class names for this taxonomy (re-exported for convenience).
#[must_use]
pub fn class_names() -> [&'static str; NUM_CLASSES] {
    CLASS_NAMES
}

/// Node-feature layout this trainer expects. It must stay in sync with
/// `gnngraph.FeatureSchemaID` (Go). Matching feature WIDTH is not enough:
/// v1 counted raw-text commas in feature 16 and never set the comparison
/// flag for `if-*`, so a v1 tensor looks structurally valid while meaning
/// something different. Training on a mix of the two silently corrupts the
/// model.
pub const FEATURE_SCHEMA_ID: &str = "smali-cfg-v3";

// ---- deterministic PRNG (xorshift64*) ----
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn next_f32(&mut self) -> f32 {
        (self.next_u64() >> 40) as f32 / (1u64 << 24) as f32
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u64() % (hi - lo).max(1) as u64) as usize
    }
    fn chance(&mut self, p: f32) -> bool {
        self.next_f32() < p
    }
}

// ---- per-class structural motif ----
struct Motif {
    /// Dominant opcode-histogram bucket (None = flat).
    ///
    /// Bucket indices follow the SERVING extractor
    /// (`pkg/internal/gnngraph`), not the DEX instruction numbering:
    /// 0 = const/field/array reads, 2 = arithmetic, 3 = branches,
    /// 4 = invoke-*, 6 = cmp*. Call-oriented motifs must therefore use 4:
    /// using 6 taught the model that "invocation-dominated" looks like
    /// "comparison-dominated", a pattern inference never produces.
    op: Option<usize>,
    /// Number of call nodes.
    calls: usize,
    /// Number of memory-access nodes.
    mem: usize,
    /// How tightly the memory reads are clustered on one path. Serving has no
    /// data-dependency edge type (the Go builder emits only control flow and
    /// self-loops), so this is expressed as control-flow links between the
    /// memory nodes rather than as `EdgeType::DataDependency`.
    dd: f32,
    /// Extra control-flow branch probability per node.
    branchy: f32,
    /// Per-node error-path probability.
    error_path: f32,
    /// Loop-heavy control flow (back edge + loop depth).
    loop_heavy: bool,
    /// Real gate: a comparison node that branches to a late error node.
    gate: bool,
    /// Dead gate: a comparison node whose guarded branch was removed.
    dead_gate: bool,
    /// One very high-fan-out dispatch node (reflection / PackageManager proxy).
    proxy: bool,
    /// A call node that leaves the graph (JNI leaf, no return edge).
    native: bool,
    /// v3 semantic API flags (slots 28-35), aligned with the serving
    /// extractor so synthetic classes teach the same signals inference sees.
    /// Call-node flags:
    license_calls: bool, // invoke -> licensing/billing (classes 1, 2)
    dynload_calls: bool, // invoke -> class loaders (classes 5, 7)
    native_calls: bool,  // System.loadLibrary leaf (class 6)
    repack_sig: bool,    // package-signature reads (class 5)
    /// Proxy-node flags (reflection / PackageManager dispatch):
    spoof_proxy: bool, // PackageManager proxy (class 3)
    dynload_proxy: bool, // DexClassLoader payload (class 7)
    reflect_proxy: bool, // reflective dispatch (classes 3, 7)
    /// Memory-node flags:
    crypto_mem: bool, // checksum/crypto reads (class 4)
    /// Const-string signal on call nodes:
    license_str: bool, // "license"-like literals (classes 1, 2)
}

fn motif(label: usize) -> Motif {
    match label {
        // 0 benign — low signal.
        0 => Motif {
            op: None,
            calls: 1,
            mem: 0,
            dd: 0.05,
            branchy: 0.15,
            error_path: 0.05,
            loop_heavy: false,
            gate: false,
            dead_gate: false,
            proxy: false,
            native: false,
            license_calls: false,
            dynload_calls: false,
            native_calls: false,
            repack_sig: false,
            spoof_proxy: false,
            dynload_proxy: false,
            reflect_proxy: false,
            crypto_mem: false,
            license_str: false,
        },
        // 1 license-check — call to licensing service + real guard to an error path.
        1 => Motif {
            op: Some(4),
            calls: 3,
            mem: 1,
            dd: 0.30,
            branchy: 0.25,
            error_path: 0.40,
            loop_heavy: false,
            gate: true,
            dead_gate: false,
            proxy: false,
            native: false,
            license_calls: true,
            dynload_calls: false,
            native_calls: false,
            repack_sig: false,
            spoof_proxy: false,
            dynload_proxy: false,
            reflect_proxy: false,
            crypto_mem: false,
            license_str: true,
        },
        // 2 license-bypass — guard present but collapsed to a single successor.
        2 => Motif {
            op: Some(4),
            calls: 2,
            mem: 1,
            dd: 0.20,
            branchy: 0.10,
            error_path: 0.02,
            loop_heavy: false,
            gate: false,
            dead_gate: true,
            proxy: false,
            native: false,
            license_calls: true,
            dynload_calls: false,
            native_calls: false,
            repack_sig: false,
            spoof_proxy: false,
            dynload_proxy: false,
            reflect_proxy: false,
            crypto_mem: false,
            license_str: true,
        },
        // 3 signature-spoof — reflective PackageManager proxy dispatch.
        3 => Motif {
            op: Some(4),
            calls: 4,
            mem: 1,
            dd: 0.40,
            branchy: 0.20,
            error_path: 0.15,
            loop_heavy: false,
            gate: false,
            dead_gate: false,
            proxy: true,
            native: false,
            license_calls: false,
            dynload_calls: false,
            native_calls: false,
            repack_sig: false,
            spoof_proxy: true,
            dynload_proxy: false,
            reflect_proxy: true,
            crypto_mem: false,
            license_str: false,
        },
        // 4 integrity-tamper — reads checksum (mem) but comparison branch removed.
        4 => Motif {
            op: Some(2),
            calls: 2,
            mem: 3,
            dd: 0.45,
            branchy: 0.15,
            error_path: 0.10,
            loop_heavy: false,
            gate: false,
            dead_gate: true,
            proxy: false,
            native: false,
            license_calls: false,
            dynload_calls: false,
            native_calls: false,
            repack_sig: false,
            spoof_proxy: false,
            dynload_proxy: false,
            reflect_proxy: false,
            crypto_mem: true,
            license_str: false,
        },
        // 5 repack-marker — shallow store-attribution / injected loader.
        5 => Motif {
            op: Some(4),
            calls: 2,
            mem: 0,
            dd: 0.10,
            branchy: 0.10,
            error_path: 0.05,
            loop_heavy: false,
            gate: false,
            dead_gate: false,
            proxy: false,
            native: false,
            license_calls: false,
            dynload_calls: false,
            native_calls: false,
            repack_sig: true,
            spoof_proxy: false,
            dynload_proxy: false,
            reflect_proxy: false,
            crypto_mem: false,
            license_str: false,
        },
        // 6 native-bridge — JNI leaf call.
        6 => Motif {
            op: Some(4),
            calls: 2,
            mem: 1,
            dd: 0.20,
            branchy: 0.10,
            error_path: 0.05,
            loop_heavy: false,
            gate: false,
            dead_gate: false,
            proxy: false,
            native: true,
            license_calls: false,
            dynload_calls: false,
            native_calls: true,
            repack_sig: false,
            spoof_proxy: false,
            dynload_proxy: false,
            reflect_proxy: false,
            crypto_mem: false,
            license_str: false,
        },
        // 7 dynamic-load — reflection payload loaded inside a loop.
        _ => Motif {
            op: Some(4),
            calls: 3,
            mem: 1,
            dd: 0.35,
            branchy: 0.20,
            error_path: 0.10,
            loop_heavy: true,
            gate: false,
            dead_gate: false,
            proxy: true,
            native: false,
            license_calls: false,
            dynload_calls: true,
            native_calls: false,
            repack_sig: false,
            spoof_proxy: false,
            dynload_proxy: true,
            reflect_proxy: true,
            crypto_mem: false,
            license_str: false,
        },
    }
}

fn opcode_hist(rng: &mut Rng, dominant: Option<usize>, strength: f32) -> [f32; 16] {
    let mut h = [0.0_f32; 16];
    for v in &mut h {
        *v = rng.next_f32();
    }
    if let Some(d) = dominant {
        h[d] += strength * 16.0;
    }
    let sum: f32 = h.iter().sum();
    if sum > 0.0 {
        for v in &mut h {
            *v /= sum;
        }
    }
    h
}

fn make_graph(rng: &mut Rng, label: usize) -> GraphTensor {
    let m = motif(label);
    let n = rng.range(7, 24);

    let mut mem_nodes: Vec<usize> = Vec::new();
    while mem_nodes.len() < m.mem.min(n) {
        let c = rng.range(0, n);
        if !mem_nodes.contains(&c) {
            mem_nodes.push(c);
        }
    }
    let mut call_nodes: Vec<usize> = Vec::new();
    while call_nodes.len() < m.calls.min(n) {
        let c = rng.range(0, n);
        if !call_nodes.contains(&c) {
            call_nodes.push(c);
        }
    }
    let cmp_node = if m.gate || m.dead_gate {
        Some(rng.range(0, n))
    } else {
        None
    };
    let proxy_node = if m.proxy { Some(rng.range(0, n)) } else { None };

    let mut features = Vec::with_capacity(n);
    for i in 0..n {
        let strength = 0.15 + rng.next_f32() * 0.35;
        let loop_depth = if m.loop_heavy && rng.chance(0.6) {
            rng.range(1, 4) as f32
        } else {
            0.0
        };
        let is_cmp = cmp_node == Some(i);
        let is_call_node = call_nodes.contains(&i) || proxy_node == Some(i);
        let is_proxy = proxy_node == Some(i);
        let is_mem = mem_nodes.contains(&i);
        features.push(NodeFeatures {
            opcode_category: opcode_hist(rng, m.op, strength),
            operand_count: rng.next_f32(),
            is_branch: f32::from(u8::from((m.gate && is_cmp) || rng.chance(m.branchy))),
            is_call: f32::from(u8::from(is_call_node)),
            is_memory_access: f32::from(u8::from(is_mem)),
            is_comparison: f32::from(u8::from(is_cmp || rng.chance(0.2))),
            in_degree: (rng.range(0, 6) as f32 / 20.0).clamp(0.0, 1.0),
            out_degree: (rng.range(0, 6) as f32 / 20.0).clamp(0.0, 1.0),
            block_size: (rng.range(1, 60) as f32 / 100.0).clamp(0.0, 1.0),
            loop_depth: (loop_depth / 10.0).clamp(0.0, 1.0),
            dominance_score: rng.next_f32(),
            is_error_path: f32::from(u8::from(rng.chance(m.error_path))),
            is_entry: f32::from(u8::from(i == 0)),
            // v3 semantic motif flags, aligned with the serving extractor.
            api_license: f32::from(u8::from(m.license_calls && is_call_node)),
            api_reflection: f32::from(u8::from(m.reflect_proxy && is_proxy)),
            api_dynload: f32::from(u8::from(
                (m.dynload_calls && is_call_node) || (m.dynload_proxy && is_proxy),
            )),
            api_crypto: f32::from(u8::from(m.crypto_mem && is_mem)),
            api_pkg_sig: f32::from(u8::from(
                (m.spoof_proxy && is_proxy) || (m.repack_sig && is_call_node),
            )),
            api_native: f32::from(u8::from(m.native_calls && is_call_node)),
            str_url: 0.0,
            str_license_kw: f32::from(u8::from(m.license_str && is_call_node)),
        });
    }

    // Edges use ONLY the two types the serving builder can produce
    // (EdgeType::ControlFlow and EdgeType::SelfLoop, see
    // pkg/internal/gnngraph). Earlier revisions emitted DataDependency,
    // Call and Return edges: those made the classes trivially separable in
    // training while being impossible at inference time, so a good
    // synthetic score said nothing about real Smali.
    let mut edges: Vec<(u32, u32, EdgeType)> = Vec::new();

    // Fall-through chain. A native bridge call is a leaf: it leaves the
    // method, so it gets no forward control-flow successor.
    for i in 0..n.saturating_sub(1) {
        if m.native && call_nodes.contains(&i) {
            continue;
        }
        edges.push((i as u32, (i + 1) as u32, EdgeType::ControlFlow));
    }
    // Extra conditional branches.
    for i in 0..n.saturating_sub(1) {
        if rng.chance(m.branchy) {
            let j = rng.range(0, n) as u32;
            edges.push((i as u32, j, EdgeType::ControlFlow));
        }
    }
    if m.loop_heavy && n > 1 {
        edges.push((
            (n - 1) as u32,
            rng.range(0, (n / 2).max(1)) as u32,
            EdgeType::ControlFlow,
        ));
    }
    // Real gate: comparison branches to a late error node AND to the fall-through.
    if let Some(c) = cmp_node.filter(|_| m.gate) {
        let err = rng.range(n / 2, n) as u32;
        edges.push((c as u32, err, EdgeType::ControlFlow));
        edges.push((c as u32, ((c + 1) % n) as u32, EdgeType::ControlFlow));
    }
    // Dead gate: comparison collapses to a single successor (guard removed).
    if let Some(c) = cmp_node.filter(|_| m.dead_gate) {
        edges.push((c as u32, ((c + 1) % n) as u32, EdgeType::ControlFlow));
    }
    // Memory reads that feed one check cluster on the same path.
    for &a in &mem_nodes {
        for &b in &mem_nodes {
            if a < b && rng.chance(m.dd) {
                edges.push((a as u32, b as u32, EdgeType::ControlFlow));
            }
        }
    }
    // Reflection / PackageManager proxy: very high control-flow fan-out.
    if let Some(p) = proxy_node {
        let fanout = (n / 2).max(3);
        for _ in 0..fanout {
            let tgt = rng.range(0, n) as u32;
            edges.push((p as u32, tgt, EdgeType::ControlFlow));
        }
    }
    // Explicit self-loop per node, exactly like the Go builder emits.
    for i in 0..n {
        edges.push((i as u32, i as u32, EdgeType::SelfLoop));
    }

    GraphTensor::from_edges(&features, &edges)
}

/// Deterministic synthetic dataset with light class imbalance: benign is
/// oversampled, integrity-tamper and native-bridge are rarer — this exercises
/// the trainer's inverse-frequency class weighting and focal loss.
#[must_use]
pub fn build_dataset(n_per_class: usize, seed: u64) -> Vec<Example> {
    let mut rng = Rng::new(seed);
    let mut examples = Vec::new();
    for label in 0..NUM_CLASSES {
        let count = match label {
            0 => n_per_class * 9 / 5,
            4 | 6 => (n_per_class / 2).max(1),
            _ => n_per_class,
        };
        for _ in 0..count.max(1) {
            examples.push(Example {
                graph: make_graph(&mut rng, label),
                label,
            });
        }
    }
    for i in (1..examples.len()).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        examples.swap(i, j);
    }
    examples
}

// ---- real dataset: JSONL shards from pkg/ml/gnndataset ----

/// One JSONL record, matching the field names emitted by
/// `gnndataset.Example` on the Go side. Unknown fields are ignored and
/// missing fields default, so provenance/prediction columns are optional.
#[derive(FromJson)]
struct JsonlRecord {
    #[json(default)]
    num_nodes: u64,
    #[json(default)]
    feature_dim: u64,
    #[json(default)]
    row_ptr: Vec<u64>,
    #[json(default)]
    col_idx: Vec<u64>,
    #[json(default)]
    edge_types: Vec<u32>,
    #[json(default)]
    features: Vec<Vec<f32>>,
    #[json(default)]
    label: i64,
    #[json(default)]
    label_confirmed: bool,
    /// Absolute path / extract dir of the source APK. Used to group graphs by
    /// app so a train/val split never leaks methods of one app across sides.
    #[json(default)]
    apk_path: String,
    /// SHA-256 of the graph tensor; used to collapse duplicate subgraphs.
    #[json(default)]
    graph_hash: String,
    /// Node-feature layout id (Go: `gnngraph.FeatureSchemaID`). `None` for
    /// records written before the field existed — those are legacy and are
    /// reported, not silently trusted.
    #[json(default)]
    feature_schema: Option<String>,
}

fn decode_edge(code: u32) -> Result<EdgeType, String> {
    match code {
        0 => Ok(EdgeType::ControlFlow),
        1 => Ok(EdgeType::DataDependency),
        2 => Ok(EdgeType::Call),
        3 => Ok(EdgeType::Return),
        4 => Ok(EdgeType::SelfLoop),
        other => Err(format!("invalid edge type code {other}")),
    }
}

fn record_to_example(r: JsonlRecord) -> Result<Example, String> {
    let n = usize::try_from(r.num_nodes).map_err(|_| "num_nodes overflow".to_string())?;
    let fdim = usize::try_from(r.feature_dim).map_err(|_| "feature_dim overflow".to_string())?;
    if n == 0 {
        return Err("empty graph".to_string());
    }
    if fdim != NodeFeatures::DIMS {
        return Err(format!("feature_dim {fdim} != {}", NodeFeatures::DIMS));
    }
    if r.features.len() != n {
        return Err(format!(
            "features rows {} != num_nodes {n}",
            r.features.len()
        ));
    }
    if r.row_ptr.len() != n + 1 {
        return Err(format!(
            "row_ptr len {} != num_nodes+1 {}",
            r.row_ptr.len(),
            n + 1
        ));
    }
    let label = usize::try_from(r.label).map_err(|_| "negative label".to_string())?;
    if label >= NUM_CLASSES {
        return Err(format!("label {label} out of range 0..{NUM_CLASSES}"));
    }
    let mut node_features = Vec::with_capacity(n * fdim);
    for row in &r.features {
        if row.len() != fdim {
            return Err(format!("feature row len {} != {fdim}", row.len()));
        }
        if row.iter().any(|v| !v.is_finite()) {
            return Err("non-finite feature".to_string());
        }
        node_features.extend_from_slice(row);
    }
    let row_ptr: Vec<u32> = r.row_ptr.iter().map(|&x| x as u32).collect();
    let col_idx: Vec<u32> = r.col_idx.iter().map(|&x| x as u32).collect();
    if row_ptr.last().copied().unwrap_or(0) as usize != col_idx.len() {
        return Err("row_ptr tail != col_idx length".to_string());
    }
    for &c in &col_idx {
        if c as usize >= n {
            return Err("column index out of range".to_string());
        }
    }
    let edge_types: Vec<EdgeType> = if r.edge_types.is_empty() {
        vec![EdgeType::ControlFlow; col_idx.len()]
    } else {
        if r.edge_types.len() != col_idx.len() {
            return Err("edge_types length != col_idx length".to_string());
        }
        r.edge_types
            .iter()
            .map(|&c| decode_edge(c))
            .collect::<Result<Vec<_>, _>>()?
    };
    Ok(Example {
        graph: GraphTensor {
            num_nodes: n,
            row_ptr,
            col_idx,
            edge_types,
            node_features,
            feature_dims: fdim,
        },
        label,
    })
}

/// Load real labelled graphs from a `.jsonl` file OR a directory of shards
/// produced by the scanner's `gnndataset.Writer`. Malformed lines are skipped
/// (count reported on stderr). When `confirmed_only` is true, rows without
/// `"label_confirmed": true` are ignored so you can train exclusively on
/// human-reviewed labels.
pub fn load_jsonl_dataset(path: &str, confirmed_only: bool) -> Result<Vec<Example>, String> {
    let p = Path::new(path);
    let mut files: Vec<PathBuf> = Vec::new();
    if p.is_dir() {
        let entries = fs::read_dir(p).map_err(|e| format!("read_dir {path}: {e}"))?;
        for entry in entries.flatten() {
            let ep = entry.path();
            if ep
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("jsonl"))
            {
                files.push(ep);
            }
        }
        files.sort();
    } else {
        files.push(p.to_path_buf());
    }
    if files.is_empty() {
        return Err(format!("no .jsonl files found at {path}"));
    }
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for f in &files {
        let content = fs::read_to_string(f).map_err(|e| format!("read {}: {e}", f.display()))?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(rec) = omnisec_json::from_json_str::<JsonlRecord>(line) else {
                skipped += 1;
                continue;
            };
            if confirmed_only && !rec.label_confirmed {
                continue;
            }
            match record_to_example(rec) {
                Ok(ex) => out.push(ex),
                Err(_) => skipped += 1,
            }
        }
    }
    if skipped > 0 {
        eprintln!("load_jsonl_dataset: skipped {skipped} malformed/invalid record(s)");
    }
    if out.is_empty() {
        return Err("no usable examples after loading".to_string());
    }
    Ok(out)
}

/// Like [`load_jsonl_dataset`] but also returns, for each example, the APK it
/// came from (`apk_path`). Callers can then split train/val by APK instead of
/// by graph — the only split that prevents methods of one app leaking from
/// train into validation and inflating the score. Duplicate graphs (identical
/// `graph_hash`) are collapsed to a single example, removing the fan-out
/// inflation caused by repeated subgraphs. Diversity and per-class counts are
/// logged to stderr.
/// Like [`load_jsonl_grouped`] but with explicit control over legacy records.
///
/// `drop_legacy` skips records written before `feature_schema` existed. Keep
/// it false to load them (with a warning) while you are still migrating a
/// corpus; set it true once the dataset has been rebuilt, so a v1 tensor can
/// never again reach a v2 training run.
pub fn load_jsonl_grouped(
    path: &str,
    confirmed_only: bool,
) -> Result<(Vec<Example>, Vec<String>), String> {
    load_jsonl_grouped_ex(path, confirmed_only, false)
}

/// Like [`load_jsonl_grouped`] but with explicit control over legacy records.
///
/// `drop_legacy` skips records written before `feature_schema` existed. Keep
/// it false to load them (with a warning) while you are still migrating a
/// corpus; set it true once the dataset has been rebuilt, so a v1 tensor can
/// never again reach a v2 training run.
pub fn load_jsonl_grouped_ex(
    path: &str,
    confirmed_only: bool,
    drop_legacy: bool,
) -> Result<(Vec<Example>, Vec<String>), String> {
    let p = Path::new(path);
    let mut files: Vec<PathBuf> = Vec::new();
    if p.is_dir() {
        let entries = fs::read_dir(p).map_err(|e| format!("read_dir {path}: {e}"))?;
        for entry in entries.flatten() {
            let ep = entry.path();
            if ep
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("jsonl"))
            {
                files.push(ep);
            }
        }
        files.sort();
    } else {
        files.push(p.to_path_buf());
    }
    if files.is_empty() {
        return Err(format!("no .jsonl files found at {path}"));
    }
    let mut examples: Vec<Example> = Vec::new();
    let mut groups = Vec::new();
    // graph_hash -> position in `examples`. Mapping to an index (not just a
    // set) lets a later reviewed record replace an earlier auto-label.
    let mut seen_hashes: HashMap<String, usize> = HashMap::new();
    let mut confirmed_flags: Vec<bool> = Vec::new();
    let mut apks: HashSet<String> = HashSet::new();
    let mut class_counts = [0usize; NUM_CLASSES];
    let mut skipped = 0usize;
    let mut deduped = 0usize;
    let mut legacy_schema = 0usize;
    let mut foreign_schema = 0usize;
    let mut replaced = 0usize;
    let mut conflicts = 0usize;
    let mut pseudo = 0usize;
    for f in &files {
        let content = fs::read_to_string(f).map_err(|e| format!("read {}: {e}", f.display()))?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Ok(rec) = omnisec_json::from_json_str::<JsonlRecord>(line) else {
                skipped += 1;
                continue;
            };
            // Feature-schema gate. A record from a different extractor is
            // structurally valid but semantically wrong, so it must never be
            // deduplicated against or mixed with this run's examples.
            match rec.feature_schema.as_deref() {
                Some(s) if s != FEATURE_SCHEMA_ID => {
                    foreign_schema += 1;
                    continue;
                }
                None => {
                    legacy_schema += 1;
                    if drop_legacy {
                        continue;
                    }
                }
                Some(_) => {}
            }
            if confirmed_only && !rec.label_confirmed {
                continue;
            }
            let apk = if rec.apk_path.is_empty() {
                "unknown".to_string()
            } else {
                rec.apk_path.clone()
            };
            let hash = rec.graph_hash.clone();
            let confirmed = rec.label_confirmed;
            // Validate BEFORE deduplicating. The old order let a malformed
            // record claim a graph_hash and silently suppress every valid
            // later record with the same hash.
            let ex = match record_to_example(rec) {
                Ok(ex) => ex,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            if !hash.is_empty() {
                if let Some(&idx) = seen_hashes.get(&hash) {
                    deduped += 1;
                    if confirmed && !confirmed_flags[idx] {
                        // A reviewed correction outranks the auto-label that
                        // happened to be written first.
                        class_counts[examples[idx].label] =
                            class_counts[examples[idx].label].saturating_sub(1);
                        class_counts[ex.label] += 1;
                        examples[idx] = ex;
                        groups[idx] = apk;
                        confirmed_flags[idx] = true;
                        replaced += 1;
                    } else if confirmed && confirmed_flags[idx] && examples[idx].label != ex.label {
                        // Two humans, two answers — not something to guess.
                        conflicts += 1;
                    }
                    continue;
                }
                seen_hashes.insert(hash, examples.len());
            }
            if !confirmed {
                pseudo += 1;
            }
            class_counts[ex.label] += 1;
            apks.insert(apk.clone());
            examples.push(ex);
            groups.push(apk);
            confirmed_flags.push(confirmed);
        }
    }
    if skipped > 0 {
        eprintln!("load_jsonl_grouped: skipped {skipped} malformed/invalid record(s)");
    }
    if deduped > 0 {
        eprintln!("load_jsonl_grouped: collapsed {deduped} duplicate graph(s) by graph_hash");
    }
    if replaced > 0 {
        eprintln!("load_jsonl_grouped: {replaced} duplicate(s) relabelled from a reviewed record");
    }
    if conflicts > 0 {
        eprintln!(
            "load_jsonl_grouped: WARNING {conflicts} duplicate(s) carry CONFLICTING reviewed labels; \
             keeping the first — resolve them before trusting this dataset"
        );
    }
    if pseudo > 0 {
        eprintln!(
            "load_jsonl_grouped: WARNING {pseudo} example(s) use the model's own prediction as the \
             label (label_confirmed=false). Scores measured on them are self-referential; pass \
             --confirmed-only for an honest evaluation."
        );
    }
    if foreign_schema > 0 {
        eprintln!(
            "load_jsonl_grouped: skipped {foreign_schema} record(s) whose feature_schema != {FEATURE_SCHEMA_ID}"
        );
    }
    if legacy_schema > 0 {
        eprintln!(
            "load_jsonl_grouped: WARNING {legacy_schema} record(s) predate feature_schema; {}",
            if drop_legacy {
                "dropped (--drop-legacy-features)".to_string()
            } else {
                format!("their features may mean something different from {FEATURE_SCHEMA_ID}")
            }
        );
    }
    if examples.is_empty() {
        return Err("no usable examples after loading".to_string());
    }
    eprintln!(
        "load_jsonl_grouped: {} example(s) from {} distinct APK(s)",
        examples.len(),
        apks.len()
    );
    eprint!("load_jsonl_grouped: per-class counts:");
    for (i, c) in class_counts.iter().enumerate() {
        if *c > 0 {
            eprint!(" {}={}", CLASS_NAMES[i], c);
        }
    }
    eprintln!();
    if apks.len() < 2 {
        eprintln!(
            "load_jsonl_grouped: WARNING only {} APK(s) — a by-APK split cannot hold out an              unseen app; validation will not reflect generalisation. Scan more APKs.",
            apks.len()
        );
    }
    Ok((examples, groups))
}

/// Reorder `examples` so all graphs of the chosen validation APKs come first,
/// returning `(reordered, n_val)`. Whole APKs (sorted for determinism) are
/// assigned to the validation side until at least `val_fraction` of graphs are
/// covered, so no APK straddles the split; at least one APK always stays in
/// train. Feed the result to `Trainer::fit` with `shuffle_split=false` and
/// `explicit_val=n_val`.
#[must_use]
pub fn group_split_by_apk(
    examples: Vec<Example>,
    groups: Vec<String>,
    val_fraction: f32,
) -> (Vec<Example>, usize) {
    assert_eq!(
        examples.len(),
        groups.len(),
        "examples/groups length mismatch"
    );
    let total = examples.len();
    if total == 0 {
        return (examples, 0);
    }
    // Owned key set: all &str borrows of `groups` end inside this block, so
    // `groups.into_iter()` below is legal (fixes E0505).
    let val_apks: HashSet<String> = {
        let mut per_apk: HashMap<&str, usize> = HashMap::new();
        for g in &groups {
            *per_apk.entry(g.as_str()).or_insert(0) += 1;
        }
        let mut keys: Vec<&str> = per_apk.keys().copied().collect();
        keys.sort_unstable();
        let target = ((total as f32) * val_fraction).round() as usize;
        let mut chosen: HashSet<String> = HashSet::new();
        let mut covered = 0usize;
        for k in &keys {
            if covered >= target || chosen.len() + 1 >= keys.len() {
                break;
            }
            chosen.insert((*k).to_string());
            covered += per_apk[*k];
        }
        chosen
    };
    let mut val_ex = Vec::new();
    let mut train_ex = Vec::new();
    for (ex, g) in examples.into_iter().zip(groups) {
        if val_apks.contains(g.as_str()) {
            val_ex.push(ex);
        } else {
            train_ex.push(ex);
        }
    }
    let n_val = val_ex.len();
    let mut out = val_ex;
    out.extend(train_ex);
    (out, n_val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_is_deterministic_and_valid() {
        let a = build_dataset(6, 42);
        let b = build_dataset(6, 42);
        assert_eq!(a.len(), b.len());
        assert!(!a.is_empty());
        for (x, y) in a.iter().zip(&b) {
            assert_eq!(x.label, y.label);
            assert_eq!(x.graph.node_features, y.graph.node_features);
        }
        for ex in &a {
            assert!(ex.label < NUM_CLASSES);
            assert_eq!(
                ex.graph.node_features.len(),
                ex.graph.num_nodes * NodeFeatures::DIMS
            );
            assert!(ex.graph.node_features.iter().all(|v| v.is_finite()));
        }
    }

    /// The serving builder (pkg/internal/gnngraph) can only emit ControlFlow
    /// and SelfLoop edges. Synthetic graphs that use anything else are
    /// learning a signal inference can never see.
    #[test]
    fn synthetic_graphs_use_only_serving_edge_types() {
        let ds = build_dataset(4, 11);
        assert!(!ds.is_empty());
        for ex in &ds {
            for &et in &ex.graph.edge_types {
                assert!(
                    matches!(et, EdgeType::ControlFlow | EdgeType::SelfLoop),
                    "synthetic graph uses {et:?}, which the Go builder never produces"
                );
            }
            // Every node keeps its explicit self-loop, like serving.
            for i in 0..ex.graph.num_nodes {
                let (s, e) = (
                    ex.graph.row_ptr[i] as usize,
                    ex.graph.row_ptr[i + 1] as usize,
                );
                assert!(
                    (s..e).any(|k| ex.graph.col_idx[k] as usize == i),
                    "node {i} has no self-loop"
                );
            }
        }
    }

    /// Call-oriented classes must not present themselves as comparison-heavy:
    /// bucket 4 is invoke-*, bucket 6 is cmp* in the serving extractor.
    #[test]
    fn call_motifs_peak_in_the_invoke_bucket() {
        for label in [1usize, 2, 3, 5, 6, 7] {
            let dominant = motif(label)
                .op
                .expect("call-oriented motif has a dominant bucket");
            assert_eq!(
                dominant, 4,
                "class {label} peaks in opcode bucket {dominant}; serving puts invoke-* in 4"
            );
        }
    }

    /// v3 semantic motif flags: each class must light its serving-aligned
    /// API slot on at least one node, and benign must light none.
    #[test]
    fn motifs_carry_class_semantic_flags() {
        // (label, slot index 28-35 or None for benign)
        for (label, slot) in [
            (1usize, Some(28)), // license-check -> api_license
            (2, Some(28)),      // license-bypass -> api_license
            (3, Some(32)),      // signature-spoof -> api_pkg_sig (proxy)
            (4, Some(31)),      // integrity-tamper -> api_crypto (mem)
            (5, Some(32)),      // repack-marker -> api_pkg_sig (calls)
            (6, Some(33)),      // native-bridge -> api_native
            (7, Some(30)),      // dynamic-load -> api_dynload
        ] {
            let slot = slot.unwrap();
            let mut seen = false;
            for _ in 0..8 {
                let g = make_graph(&mut Rng::new(1000 + label as u64), label);
                assert_eq!(g.node_features.len(), g.num_nodes * NodeFeatures::DIMS);
                for node in g.node_features.chunks_exact(NodeFeatures::DIMS) {
                    if node[slot] == 1.0 {
                        seen = true;
                    }
                    // Slots are binary flags.
                    for v in &node[28..] {
                        assert!(*v == 0.0 || *v == 1.0, "slot must be binary, got {v}");
                    }
                }
                if seen {
                    break;
                }
            }
            assert!(seen, "class {label} never sets v3 slot {slot}");
        }
        // Benign stays silent on all semantic slots.
        for _ in 0..8 {
            let g = make_graph(&mut Rng::new(7), 0);
            for node in g.node_features.chunks_exact(NodeFeatures::DIMS) {
                assert_eq!(&node[28..], &[0.0; 8], "benign must not set v3 slots");
            }
        }
    }

    #[test]
    fn all_classes_present_with_imbalance() {
        let ds = build_dataset(8, 7);
        let mut counts = [0usize; NUM_CLASSES];
        for ex in &ds {
            counts[ex.label] += 1;
        }
        assert!(counts.iter().all(|&c| c > 0));
        assert!(counts[0] >= counts[1], "benign should be oversampled");
    }

    #[test]
    fn jsonl_record_roundtrips() {
        // Mirrors the gnndataset.Example JSON shape (36-dim features).
        let mut feat_row = String::from("[");
        for i in 0..36 {
            if i > 0 {
                feat_row.push(',');
            }
            feat_row.push_str("0.1");
        }
        feat_row.push(']');
        let line = format!(
            "{{\"num_nodes\":2,\"feature_dim\":36,\"row_ptr\":[0,1,2],\"col_idx\":[1,0],\"edge_types\":[0,0],\"features\":[{feat_row},{feat_row}],\"label\":2,\"label_confirmed\":true}}"
        );
        let rec: JsonlRecord = omnisec_json::from_json_str(&line).expect("parse");
        let ex = record_to_example(rec).expect("convert");
        assert_eq!(ex.label, 2);
        assert_eq!(ex.graph.num_nodes, 2);
        assert_eq!(ex.graph.feature_dims, 36);
    }

    /// A record identical to `jsonl_record_roundtrips` plus a schema suffix.
    fn jsonl_line(schema_suffix: &str, graph_hash: &str) -> String {
        let feat_row = (0..36).map(|_| "0.1").collect::<Vec<_>>().join(",");
        let feat_row = format!("[{feat_row}]");
        let hash = if graph_hash.is_empty() {
            String::new()
        } else {
            format!(",\"graph_hash\":\"{graph_hash}\"")
        };
        format!(
            "{{\"num_nodes\":2,\"feature_dim\":36,\"row_ptr\":[0,1,2],\"col_idx\":[1,0],\
             \"edge_types\":[0,0],\"features\":[{feat_row},{feat_row}],\"label\":2,\
             \"label_confirmed\":true,\"apk_path\":\"app\"{hash}{schema_suffix}}}"
        )
    }

    #[test]
    fn foreign_feature_schema_records_are_skipped_not_mixed() {
        let dir = std::env::temp_dir().join(format!("gnn_schema_probe_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("d.jsonl");
        let current = format!(",\"feature_schema\":\"{FEATURE_SCHEMA_ID}\"");
        let foreign = ",\"feature_schema\":\"smali-cfg-v1\"";
        std::fs::write(
            &file,
            format!(
                "{}\n{}\n",
                jsonl_line(&current, "cur"),
                jsonl_line(foreign, "old")
            ),
        )
        .expect("write");

        let (ex, _groups) =
            load_jsonl_grouped_ex(file.to_str().unwrap(), false, false).expect("load");
        // Only the record carrying the current schema survives.
        assert_eq!(ex.len(), 1, "foreign-schema record must not be loaded");

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two records with the same graph_hash: the first is an auto-label, the
    /// second a reviewed correction.
    #[test]
    fn reviewed_label_replaces_an_earlier_auto_label() {
        let dir = std::env::temp_dir().join(format!("gnn_review_probe_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("d.jsonl");
        let auto = jsonl_line("", "dup").replace("\"label\":2", "\"label\":2");
        let reviewed = jsonl_line(",\"feature_schema\":\"smali-cfg-v3\"", "dup")
            .replace("\"label\":2", "\"label\":5");
        // The shared helper marks records confirmed; make the first one not.
        let auto = auto.replace("\"label_confirmed\":true", "\"label_confirmed\":false");
        std::fs::write(&file, format!("{auto}\n{reviewed}\n")).expect("write");
        let path = file.to_str().unwrap();

        let (ex, _groups) = load_jsonl_grouped_ex(path, false, true).expect("load");
        assert_eq!(ex.len(), 1, "duplicate graphs must collapse to one example");
        assert_eq!(
            ex[0].label, 5,
            "the reviewed correction must win over the earlier auto-label"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A malformed record must not claim a graph_hash and suppress the valid
    /// record that follows it.
    #[test]
    fn malformed_duplicate_does_not_suppress_the_valid_record() {
        let dir = std::env::temp_dir().join(format!("gnn_baddup_probe_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("d.jsonl");
        let bad = "{\"num_nodes\":0,\"graph_hash\":\"dup\",\"label\":1}";
        let good = jsonl_line("", "dup");
        std::fs::write(&file, format!("{bad}\n{good}\n")).expect("write");

        let (ex, _groups) = load_jsonl_grouped_ex(file.to_str().unwrap(), false, false)
            .expect("valid record survives a malformed duplicate");
        assert_eq!(ex.len(), 1, "malformed record must not shadow the good one");
        assert_eq!(ex[0].label, 2);

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_records_are_loaded_by_default_and_dropped_on_request() {
        let dir = std::env::temp_dir().join(format!("gnn_legacy_probe_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("d.jsonl");
        std::fs::write(&file, format!("{}\n", jsonl_line("", "legacy"))).expect("write");
        let path = file.to_str().unwrap();

        let kept = load_jsonl_grouped_ex(path, false, false).expect("load");
        assert_eq!(
            kept.0.len(),
            1,
            "legacy records load by default (with a warning)"
        );

        let dropped = load_jsonl_grouped_ex(path, false, true);
        assert!(
            dropped.is_err() || dropped.unwrap().0.is_empty(),
            "--drop-legacy-features must not return legacy examples"
        );

        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
