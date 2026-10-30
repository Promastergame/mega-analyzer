//! Inter-procedural call graph construction.
//!
//! This crate builds a call graph from CFGs, tracking direct calls,
//! indirect calls, and import references.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod builder;
pub mod graph;

pub use builder::{BuildError, CallGraphBuilder};
pub use graph::{CallEdge, CallGraph, CallKind, CallNode, CallNodeId};
