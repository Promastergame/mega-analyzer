//! McCabe cyclomatic complexity.

use omnisec_cfg::ControlFlowGraph;

/// McCabe cyclomatic complexity for a function.
#[derive(Debug, Clone, Copy)]
pub struct CyclomaticComplexity {
    /// The cyclomatic complexity value.
    pub value: usize,
}

impl CyclomaticComplexity {
    /// Compute cyclomatic complexity from a CFG.
    ///
    /// CC = E - N + 2P where:
    ///   E = number of edges
    ///   N = number of nodes (basic blocks)
    ///   P = number of connected components (1 for a function)
    #[must_use]
    pub fn from_cfg(cfg: &ControlFlowGraph) -> Self {
        let e = cfg.edge_count();
        let n = cfg.block_count();
        let p = 1;
        let value = if n > 0 { e - n + 2 * p } else { 0 };
        Self { value }
    }
}

/// Compute cyclomatic complexity for a CFG.
#[must_use]
pub fn compute_cyclomatic(cfg: &ControlFlowGraph) -> CyclomaticComplexity {
    CyclomaticComplexity::from_cfg(cfg)
}
