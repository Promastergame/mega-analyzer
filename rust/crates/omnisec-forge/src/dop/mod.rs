//! Data-Oriented Programming (DOP) — non-control-flow strategies.
//!
//! Where ROP/JOP/COP hijack the program counter, DOP hijacks **data**:
//! we leave the control-flow graph untouched and instead drive program
//! state via writes to attacker-reachable memory until the legitimate
//! flow reaches the desired sink.
//!
//! - [`data_graph`] — omnisec-graph-based [`DataGraph`] modelling reachable
//!   data writes/reads as a directed graph.
//! - [`cfi_bypass`] — orchestration helper that consults the data graph
//!   to plan a CFI-respecting payload.

pub mod cfi_bypass;
pub mod data_graph;
pub mod ipdg_bridge;

pub use cfi_bypass::DopCfiPlanner;
pub use data_graph::{DataEdgeKind, DataGraph, DataNode};
pub use ipdg_bridge::from_ipdg;
