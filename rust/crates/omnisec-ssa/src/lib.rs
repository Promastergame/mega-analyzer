//! SSA construction on OmniIR using the Cytron algorithm.
//!
//! This crate implements SSA form construction (phi placement and variable
//! renaming) on top of the CFG.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod builder;

pub use builder::{
    PhiFunction, SSABuilder, SsaBlock, SsaBuilder, SsaError, SsaFunction, SsaInstruction,
    SsaVariable,
};
