//! # OmniSec Symbolic Execution Engine
//!
//! Performs intra-procedural symbolic execution with bounded depth.
//! Tracks symbolic values through execution paths, explores multiple paths
//! with pruning, and provides limited constraint solving.
//!
//! ## Improvements over Go version
//!
//! - **Deeper exploration**: Default max depth 30 (vs 10 in Go) with no GC pressure.
//! - **Efficient state cloning**: Uses `SmallVec` for register maps on hot paths.
//! - **Proper constraint solving**: Extensible constraint system.
//! - **FFI bridge**: Callable from Go via CGO.
//!
//! ## Architecture
//!
//! ```text
//!   CFG + SSA ──▶ SymbolicExecutor::execute()
//!                       │
//!                       ▼
//!               Path exploration (BFS/DFS)
//!                       │
//!                       ├── Concrete evaluation
//!                       ├── Symbolic propagation
//!                       └── Constraint accumulation
//!                       │
//!                       ▼
//!               SymbolicExecutionResult (JSON)
//! ```

#![deny(missing_docs)]
#![allow(unsafe_code)]

pub mod concolic;
pub mod constraint;
pub mod executor;
pub mod ffi;
pub mod prioritize;
pub mod state;

pub use concolic::{
    ConcolicBranch, ConcolicExecutor, ConcolicResult, ConcolicSeed, ConcolicTrace, ConcolicValue,
};
pub use constraint::Constraint;
pub use executor::{MirInsn, MirOp, SymBlock, SymbolicExecutor};
pub use prioritize::{
    BranchPriority, MergeReport, MergedPath, PriorityQueue, WorkItem, merge_traces,
};
pub use state::{BranchDecision, ExecutionPath, ExecutionState, SymbolicValue};
