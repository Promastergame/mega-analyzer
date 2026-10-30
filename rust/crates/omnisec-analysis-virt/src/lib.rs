//! # OmniSec Virtualization Detection Engine
//!
//! Detects code virtualization techniques used for obfuscation:
//!
//! - **Dispatcher patterns**: Switch-based, table-based, computed goto.
//! - **Interpreter loops**: Fetch-decode-execute cycles.
//! - **Obfuscated bytecode**: Dense arithmetic sequences.
//! - **Custom VMs**: Initialization patterns for virtual registers/memory.
//!
//! ## FFI
//!
//! Callable from Go via CGO for integration with the existing pipeline.

#![deny(missing_docs)]
#![allow(unsafe_code)]

pub mod detector;
pub mod ffi;
pub mod patterns;

pub use detector::VirtualizationDetector;
pub use patterns::{VirtualizationPattern, VirtualizationTechnique};
