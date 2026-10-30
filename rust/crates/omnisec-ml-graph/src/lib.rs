//! Cross-modal Graph Neural Network for vulnerability detection
//!
//! This crate implements a heterogeneous graph neural network that combines
//! multiple data sources:
//! - Manifest permissions
//! - API calls
//! - Native symbols
//! - String constants
//! - DNS/MITM endpoints
//! - Runtime events
//!
//! The graph model enables detection of complex multi-stage attacks and
//! provides explainability through path visualization.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod features;
pub mod graph;
pub mod inference;
pub mod model;

pub use features::{FeatureExtractor, FeatureVector};
pub use graph::{EdgeType, GraphEdge, GraphNode, HeterogeneousGraph, NodeType};
pub use inference::{InferenceEngine, ThreatLevel};
pub use model::{CrossModalGNN, GNNConfig, Prediction};

/// Error type for the crate
#[derive(Debug)]
pub enum Error {
    /// Graph structural error (duplicate node, missing endpoint, ...).
    GraphError(String),

    /// Model error (bad weights, empty features, IO failure, ...).
    ModelError(String),

    /// Feature extraction error (unknown node, inconsistent vector, ...).
    FeatureError(String),

    /// Inference error (missing node, empty graph, ...).
    InferenceError(String),

    /// Invalid model or extractor configuration.
    ConfigError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GraphError(msg) => write!(f, "Graph error: {msg}"),
            Self::ModelError(msg) => write!(f, "Model error: {msg}"),
            Self::FeatureError(msg) => write!(f, "Feature extraction error: {msg}"),
            Self::InferenceError(msg) => write!(f, "Inference error: {msg}"),
            Self::ConfigError(msg) => write!(f, "Invalid configuration: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// Result type for the crate
pub type Result<T> = std::result::Result<T, Error>;
