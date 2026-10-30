//! Hyperdimensional Computing (HDC) engine — **Sparse VSA Variant**.
//!
//! This crate implements a Vector Symbolic Architecture (VSA) using **sparse**
//! 2048-bit binary hypervectors (~10% density). Sparse representations avoid
//! the "clumping" problem that dense 50%-set HVs have when bundled many times,
//! and they compress better over the wire.
//!
//! # Core Operations
//!
//! | Op         | Symbol  | Implementation                         |
//! |------------|---------|----------------------------------------|
//! | Bind       | ⊕       | XOR (produces dissimilar vector)       |
//! | Bundle     | +       | Thresholded majority vote              |
//! | Permute    | ρ       | Feistel-like bit permutation table     |
//! | Similarity | sim()   | Hamming distance via `POPCNT`           |
//!
//! # Modules
//!
//! - [`hypervector`] — The core 2048-bit sparse binary HV.
//! - [`permutation`] — Feistel-like bijective bit permutation tables.
//! - [`codebook`] — Deterministic HV generation for IR atoms (opcodes, types, etc).
//! - [`subgraph`] — **Topology-preserving** subgraph encoding via edge binding.
//! - [`anchor`] — Vulnerability signature matching (the MVP engine).
//! - [`forge`] — Synthetic vulnerability PDG generation and anchor forging.
//! - [`search`] — Multi-Index Hamming Search (binary FAISS).

#![deny(missing_docs)]
#![deny(unsafe_code)]

mod anchor;
/// Pre-generated codebook of HVs for IR concepts.
pub mod codebook;
/// Synthetic vulnerability anchor generation.
pub mod forge;
/// HDC-based variable and function auto-naming/renaming.
pub mod hdc_namer;
mod hypervector;
/// Indexed anchor store with hint pre-filter and Hamming-index candidate
/// selection. Layered on top of [`anchor::AnchorStore`] for hot paths.
pub mod indexed;
mod permutation;
/// Optional optimized runtime backends.
pub mod runtime;
/// Fast approximate nearest-neighbor search over binary HVs.
pub mod search;
/// Topology-aware subgraph encoding.
pub mod subgraph;

pub use anchor::{
    ANCHOR_STORE_SCHEMA_VERSION, Anchor, AnchorStore, AnchorStoreMetadata, MatchResult,
};
pub use codebook::CodeBook;
pub use forge::{AnchorForge, ForgeConfig, SyntheticBugKind, SyntheticEdge, SyntheticPdg};
pub use hdc_namer::{FunctionContext, HdcNamer, VariableContext, VariableRole, VariableUsage};
pub use hypervector::{BundleAccumulator, HyperVector};
pub use indexed::{HintBundle, HintRule, IndexedAnchorStore};
pub use permutation::PermutationTable;
pub use search::{HammingIndex, SearchResult};
pub use subgraph::{EdgeType, SubgraphEncoder};
