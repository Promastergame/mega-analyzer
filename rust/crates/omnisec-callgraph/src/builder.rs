//! Call graph builder.

use super::graph::{CallGraph, CallNode};

/// Errors that can occur during call graph construction.
#[derive(Debug)]
pub enum BuildError {
    /// Function not found.
    FunctionNotFound,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FunctionNotFound => write!(f, "function not found"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Build a call graph from CFGs.
pub struct CallGraphBuilder {
    graph: CallGraph,
}

impl CallGraphBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: CallGraph::new(),
        }
    }

    /// Add a function to the graph.
    pub fn add_function(&mut self, node: CallNode) {
        self.graph.add_node(node);
    }

    /// Build the call graph.
    #[must_use]
    pub fn build(self) -> CallGraph {
        self.graph
    }
}

impl Default for CallGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}
