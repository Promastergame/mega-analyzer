//! Dataflow analysis framework for OmniIR.
//!
//! This crate provides a generic dataflow analysis framework that can be
//! used for forward and backward analyses (live variables, reaching
//! definitions, constant propagation, etc.).

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod analyses;
pub mod framework;

pub use analyses::{
    ConstantPropagation, Definition, IntersectMeet, LiveVariables, ReachingDefinitions, UnionMeet,
};
pub use framework::{AnalysisResult, DataflowAnalysis, Direction, MeetOperator};
