//! # OmniSec Dalvik Lifter
//!
//! Converts Dalvik bytecode (from Go's `RawInsn` / `MIRInsn`) into OmniIR
//! [`Instruction`]s, builds a [`ControlFlowGraph`], and runs the
//! deobfuscation pipeline.
//!
//! ## Architecture
//!
//! ```text
//!   Go World                    │             Rust World
//!   ───────────────────────────┼────────────────────────────────────
//!   []RawInsn (32-byte each)   │
//!        │                     │
//!        ▼                     │
//!   serialize to []byte        │
//!        │                     │
//!        ├──── C-ABI FFI ──────┤──▶ DalvikLifter::lift_method()
//!        │                     │          │
//!                              │          ▼
//!                              │    Vec<Instruction> (OmniIR)
//!                              │          │
//!                              │          ▼
//!                              │    build_cfg() → ControlFlowGraph
//!                              │          │
//!                              │          ▼
//!                              │    DeobfuscationPipeline::run()
//!                              │          │
//!                              │          ▼
//!                              │    JSON result ◀── serialize back
//! ```

#![allow(unsafe_code)]

pub mod ffi;
pub mod lifter;

pub use lifter::DalvikLifter;
