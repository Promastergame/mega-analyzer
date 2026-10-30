//! Control-flow graph (CFG) construction and analysis on OmniIR.
//!
//! This crate is the foundation of every static analysis in OmniSec.
//! Given a flat slice of OmniIR [`omnisec_ir::Instruction`]s and an entry
//! address, [`ControlFlowGraph::build`] segments them into basic blocks and
//! wires up successor / predecessor edges by inspecting branch terminators.
//!
//! On top of the graph we layer:
//!
//! - [`DominatorTree`] — Cooper-Harvey-Kennedy iterative dominators plus
//!   dominance frontier (the input SSA construction needs).
//! - [`detect_loops`] — back-edge driven natural-loop discovery, with an
//!   irreducibility flag for nested non-natural cycles.
//! - [`to_dot`] — a Graphviz DOT renderer for human inspection.
//!
//! ## Design notes
//!
//! - **Block storage** uses an insertion-ordered [`IndexMap`](omnisec_collections::IndexMap)
//!   keyed by [`BlockId`]
//!   so iteration order is the order in which blocks were created (= the
//!   order they appear at their start addresses, which matches a natural
//!   program-order traversal).
//! - **Edges** live in two parallel `HashMap<BlockId, Vec<...>>` maps
//!   (the overwhelming majority of basic blocks have ≤ 2 successors /
//!   predecessors; heap `Vec`s keep the code simple).
//! - **Indirect control flow** (`jmp reg`, `call [mem]`) leaves the source
//!   block with no outgoing edge but a `has_unresolved_exit` flag. That
//!   flag is the seed for future Phase 3+ work on indirect-call resolution.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod block;
pub mod builder;
pub mod dominators;
pub mod dot;
pub mod graph;
pub mod loops;

pub use block::{BasicBlock, BlockId, BlockKind};
pub use builder::{BuildError, build_cfg};
pub use dominators::{DominanceFrontiers, DominatorTree};
pub use dot::to_dot;
pub use graph::ControlFlowGraph;
pub use loops::{LoopInfo, LoopKind, NaturalLoop, detect_loops};
