//! Synthetic labelled CFG/PDG graph generator for GNN training.
//!
//! Produces graphs whose node features use the exact [`NodeFeatures`] layout
//! and whose edges use [`EdgeType`]. Each of the 8 vulnerability classes is
//! associated with a distinct *structural + feature motif* plus additive
//! noise, so the learning problem is non-trivial (a linear bag-of-features
//! model cannot solve it) but genuinely learnable by a message-passing GNN.
//!
//! Deliberate class imbalance ("other" is oversampled, UAF/race are rare)
//! exercises the trainer's class weighting and focal loss.
//!
//! Fully deterministic given a seed. Used by the `gnn-train` binary as a
//! smoke-test dataset and by integration tests; real training data should
//! come from labelled corpora via the JSONL dataset path in `gnn-train`.

use crate::graph_tensor::{EdgeType, GraphTensor, NodeFeatures};
use crate::trainer::Example;

/// Number of vulnerability classes generated (must match `ModelConfig::num_classes`).
pub const NUM_CLASSES: usize = 8;

/// Human-readable class names, aligned with the Go `VulnClass` enum.
pub const CLASS_NAMES: [&str; NUM_CLASSES] = [
    "use-after-free",
    "buffer-overflow",
    "injection",
    "crypto-weakness",
    "race-condition",
    "format-string",
    "path-traversal",
    "other",
];

// Local deterministic PRNG (xorshift64*), independent of the trainer's.
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
    /// Uniform integer in [lo, hi).
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u64() % (hi - lo).max(1) as u64) as usize
    }
    fn chance(&mut self, p: f32) -> bool {
        self.next_f32() < p
    }
}

/// Per-class motif descriptor.
struct Motif {
    /// Dominant opcode category (None = no dominant category).
    op: Option<usize>,
    /// Number of extra memory-access nodes.
    mem: usize,
    /// Probability of data-dependency edges between memory nodes.
    dd: f32,
    /// Loop-heavy control flow (back edges, loop depth).
    loop_heavy: bool,
    /// Call-heavy (call nodes + call/return edges).
    call_heavy: bool,
}

fn motif(label: usize) -> Motif {
    match label {
        // UAF: alloc -> use -> free data-dependency chain.
        0 => Motif {
            op: Some(2),
            mem: 2,
            dd: 0.55,
            loop_heavy: false,
            call_heavy: true,
        },
        // Overflow: memcpy-style memory access in a loop.
        1 => Motif {
            op: Some(4),
            mem: 2,
            dd: 0.25,
            loop_heavy: true,
            call_heavy: false,
        },
        // Injection: string handling + call.
        2 => Motif {
            op: Some(6),
            mem: 1,
            dd: 0.35,
            loop_heavy: false,
            call_heavy: true,
        },
        // Crypto: arithmetic-heavy loop.
        3 => Motif {
            op: Some(9),
            mem: 0,
            dd: 0.15,
            loop_heavy: true,
            call_heavy: true,
        },
        // Race: shared state + loop.
        4 => Motif {
            op: Some(11),
            mem: 1,
            dd: 0.30,
            loop_heavy: true,
            call_heavy: true,
        },
        // Format string: call + comparison.
        5 => Motif {
            op: Some(6),
            mem: 0,
            dd: 0.20,
            loop_heavy: false,
            call_heavy: true,
        },
        // Path traversal: string + filesystem call.
        6 => Motif {
            op: Some(6),
            mem: 2,
            dd: 0.30,
            loop_heavy: false,
            call_heavy: true,
        },
        // Other: low signal.
        _ => Motif {
            op: None,
            mem: 0,
            dd: 0.05,
            loop_heavy: false,
            call_heavy: false,
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
    let n = rng.range(6, 22);

    // Choose memory / call node index sets.
    let mut mem_nodes = Vec::new();
    if m.mem > 0 {
        while mem_nodes.len() < (m.mem + 1).min(n) {
            let c = rng.range(0, n);
            if !mem_nodes.contains(&c) {
                mem_nodes.push(c);
            }
        }
    }
    let mut call_nodes = Vec::new();
    if m.call_heavy {
        let want = (n / 5).max(1);
        while call_nodes.len() < want {
            let c = rng.range(0, n);
            if !call_nodes.contains(&c) {
                call_nodes.push(c);
            }
        }
    }

    let mut features = Vec::with_capacity(n);
    for i in 0..n {
        let strength = 0.15 + rng.next_f32() * 0.35;
        let loop_depth = if m.loop_heavy && rng.chance(0.6) {
            rng.range(1, 4) as f32
        } else {
            0.0
        };
        features.push(NodeFeatures {
            opcode_category: opcode_hist(rng, m.op, strength),
            operand_count: rng.next_f32(),
            is_branch: f32::from(u8::from(rng.chance(if m.loop_heavy { 0.5 } else { 0.3 }))),
            is_call: f32::from(u8::from(call_nodes.contains(&i))),
            is_memory_access: f32::from(u8::from(mem_nodes.contains(&i))),
            is_comparison: f32::from(u8::from(rng.chance(0.35))),
            in_degree: (rng.range(0, 6) as f32 / 20.0).clamp(0.0, 1.0),
            out_degree: (rng.range(0, 6) as f32 / 20.0).clamp(0.0, 1.0),
            block_size: (rng.range(1, 60) as f32 / 100.0).clamp(0.0, 1.0),
            loop_depth: (loop_depth / 10.0).clamp(0.0, 1.0),
            dominance_score: rng.next_f32(),
            is_error_path: f32::from(u8::from(rng.chance(0.2))),
            is_entry: f32::from(u8::from(i == 0)),
            // Generic smoke-test taxonomy: no API semantics.
            api_license: 0.0,
            api_reflection: 0.0,
            api_dynload: 0.0,
            api_crypto: 0.0,
            api_pkg_sig: 0.0,
            api_native: 0.0,
            str_url: 0.0,
            str_license_kw: 0.0,
        });
    }

    // Backbone control-flow chain with occasional extra branches.
    let mut edges: Vec<(u32, u32, EdgeType)> = Vec::new();
    for i in 0..n.saturating_sub(1) {
        edges.push((i as u32, (i + 1) as u32, EdgeType::ControlFlow));
        if rng.chance(0.25) {
            let j = rng.range(0, n) as u32;
            edges.push((i as u32, j, EdgeType::ControlFlow));
        }
    }
    if m.loop_heavy && n > 1 {
        // Back-edge forms a loop.
        edges.push((
            (n - 1) as u32,
            rng.range(0, (n / 2).max(1)) as u32,
            EdgeType::ControlFlow,
        ));
    }

    // Data-dependency edges between memory nodes (the discriminative motif).
    for &a in &mem_nodes {
        for &b in &mem_nodes {
            if a != b && rng.chance(m.dd) {
                edges.push((a as u32, b as u32, EdgeType::DataDependency));
            }
        }
    }
    // Call/return edges out of call nodes.
    for &c in &call_nodes {
        let tgt = rng.range(0, n) as u32;
        edges.push((c as u32, tgt, EdgeType::Call));
        if rng.chance(0.5) {
            edges.push((tgt, c as u32, EdgeType::Return));
        }
    }

    GraphTensor::from_edges(&features, &edges)
}

/// Build a deterministic synthetic dataset with realistic class imbalance:
/// "other" is oversampled (×1.8) while UAF and race are rare (×0.5).
pub fn build_dataset(n_per_class: usize, seed: u64) -> Vec<Example> {
    let mut rng = Rng::new(seed);
    let mut examples = Vec::new();
    for label in 0..NUM_CLASSES {
        let count = match label {
            7 => n_per_class * 9 / 5,
            0 | 4 => n_per_class / 2,
            _ => n_per_class,
        };
        for _ in 0..count.max(1) {
            examples.push(Example {
                graph: make_graph(&mut rng, label),
                label,
            });
        }
    }
    // Deterministic shuffle.
    for i in (1..examples.len()).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        examples.swap(i, j);
    }
    examples
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dataset_is_deterministic_and_valid() {
        let a = build_dataset(4, 99);
        let b = build_dataset(4, 99);
        assert_eq!(a.len(), b.len());
        assert!(!a.is_empty());
        for (x, y) in a.iter().zip(&b) {
            assert_eq!(x.label, y.label);
            assert_eq!(x.graph.num_nodes, y.graph.num_nodes);
            assert_eq!(x.graph.node_features, y.graph.node_features);
        }
        for ex in &a {
            assert!(ex.label < NUM_CLASSES);
            assert!(ex.graph.num_nodes >= 6);
            assert_eq!(
                ex.graph.node_features.len(),
                ex.graph.num_nodes * NodeFeatures::DIMS
            );
            assert!(ex.graph.node_features.iter().all(|v| v.is_finite()));
        }
    }

    #[test]
    fn all_classes_present_with_imbalance() {
        let ds = build_dataset(10, 7);
        let mut counts = [0usize; NUM_CLASSES];
        for ex in &ds {
            counts[ex.label] += 1;
        }
        assert!(counts.iter().all(|&c| c > 0));
        assert!(counts[7] > counts[1], "'other' must be oversampled");
        assert!(counts[0] < counts[1], "UAF must be rare");
    }
}
