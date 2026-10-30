//! ARM64 disassembly and lifting to OmniIR.
//!
//! This crate implements ARM64 → OmniIR lifting using the dependency-free
//! `omnisec-arm64-decode` decoder.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod lifter;

pub use lifter::{Arm64Lifter, LiftError};
