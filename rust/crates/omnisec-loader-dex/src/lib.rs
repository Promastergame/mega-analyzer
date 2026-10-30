//! # OmniSec DEX Loader
//!
//! High-performance, memory-safe parser for Android DEX (Dalvik Executable)
//! files. Direct Rust port of `dex_parser.go` with significant improvements:
//!
//! - **Zero-copy** where possible (MUTF-8 fast-path for ASCII).
//! - **Parallel section parsing** via `rayon` (strings, types, fields in parallel).
//! - **Robust error handling** — no panics on malformed input.
//! - **FFI bridge** for calling from Go via CGO.
//!
//! ## Architecture
//!
//! ```text
//!   Go World                          │            Rust World
//!   ──────────────────────────────────┼───────────────────────────────
//!   []byte (raw DEX)                  │
//!        │                            │
//!        ├──── C-ABI FFI ─────────────┤──▶ DexParser::parse()
//!        │                            │          │
//!                                     │          ▼
//!                                     │    ParsedDex { strings, types,
//!                                     │       protos, fields, methods,
//!                                     │       classes }
//!                                     │          │
//!                                     │          ▼
//!                                     │    JSON result ◀── serde
//! ```

#![deny(missing_docs)]
// FFI module needs unsafe
#![allow(unsafe_code)]

pub mod error;
pub mod ffi;
pub mod header;
pub mod mutf8;
pub mod parser;
pub mod sections;
pub mod types;

pub use error::{DexError, DexResult};
pub use parser::DexParser;
pub use types::*;
