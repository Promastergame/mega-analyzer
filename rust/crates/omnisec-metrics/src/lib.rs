//! Code metrics computation.
//!
//! This crate computes various code metrics including McCabe cyclomatic
//! complexity, Halstead metrics, and cognitive complexity.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod cognitive;
pub mod cyclomatic;
pub mod halstead;

pub use cognitive::{compute_cognitive, CognitiveComplexity};
pub use cyclomatic::{compute_cyclomatic, CyclomaticComplexity};
pub use halstead::{compute_halstead, HalsteadMetrics};
