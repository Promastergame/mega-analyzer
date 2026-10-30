//! Inter-Process Dependency Graph (IPDG) — Cross-boundary taint tracking.
//!
//! This crate extends the Program Dependence Graph (PDG) to track data flow
//! across process boundaries, enabling detection of multi-stage vulnerabilities
//! that span:
//!
//! - Android App (Java/Kotlin) → JNI → Native `.so` library
//! - User-space application → System call → Kernel driver (IOCTL)
//! - Web server → CGI/FastCGI → Backend process
//! - IPC mechanisms (pipes, sockets, shared memory, message queues)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │   Process A │────▶│  Boundary   │────▶│   Process B │
//! │    (PDG)    │     │   (IPC/JNI) │     │    (PDG)    │
//! └─────────────┘     └─────────────┘     └─────────────┘
//!        │                   │                    │
//!        └───────────────────┴────────────────────┘
//!                      IPDG (unified view)
//! ```
//!
//! # Key Concepts
//!
//! - **Component**: A single executable unit (binary, library, kernel module)
//! - **Boundary**: An inter-process communication mechanism (JNI, syscall, IPC)
//! - **Cross-Boundary Edge**: A data flow edge that crosses component boundaries
//! - **Global Anchor**: A vulnerability signature that spans multiple components

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub(crate) mod anchor;
pub(crate) mod boundary;
pub(crate) mod component;
pub(crate) mod graph;
pub(crate) mod taint;

pub use anchor::{GlobalAnchor, GlobalAnchorMatch, GlobalAnchorStore};
pub use boundary::{Boundary, BoundaryEdge, BoundaryKind};
pub use component::{Component, ComponentId, ComponentKind};
pub use graph::{EdgeKind, Ipdg, IpdgBuilder, IpdgEdge, IpdgNode, NodeType};
pub use taint::{TaintPath, TaintSink, TaintSource, TaintTracker};

/// Errors that can occur during IPDG construction or analysis.
#[derive(Debug)]
pub enum IpdgError {
    /// Component not found in the graph.
    ComponentNotFound(String),

    /// Invalid boundary specification.
    InvalidBoundary(String),

    /// Taint tracking failed.
    TaintTrackingError(String),

    /// Anchor matching failed.
    AnchorMatchingError(String),

    /// Graph construction error.
    GraphConstructionError(String),
}

impl std::fmt::Display for IpdgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ComponentNotFound(msg) => write!(f, "Component not found: {msg}"),
            Self::InvalidBoundary(msg) => write!(f, "Invalid boundary: {msg}"),
            Self::TaintTrackingError(msg) => write!(f, "Taint tracking error: {msg}"),
            Self::AnchorMatchingError(msg) => write!(f, "Anchor matching error: {msg}"),
            Self::GraphConstructionError(msg) => write!(f, "Graph construction error: {msg}"),
        }
    }
}

impl std::error::Error for IpdgError {}

/// Result type for IPDG operations.
pub type Result<T> = std::result::Result<T, IpdgError>;
