//! `omnisec-arsc` — fast Android resource decoder.
//!
//! This crate offers a parallel implementation of the AXML and ARSC
//! decoders that the Go side of the analyzer ships in pure Go. The
//! formats are identical, so the Rust side is enabled selectively via
//! the FFI layer for hot paths:
//!
//! - large `resources.arsc` (>1 MiB) where rayon-driven type-chunk
//!   decoding gives a measurable speedup on multi-core machines
//! - bulk decoding of every AXML inside `res/` when a tool needs the
//!   full resource tree
//!
//! The wire format is documented publicly (Android resource framework
//! header constants are part of the platform's public API) and this
//! implementation is written from scratch — no code is adapted from
//! aapt, apktool, or any other third-party tool.
//!
//! API surface:
//!
//! ```ignore
//! let table = omnisec_arsc::parse_arsc(bytes)?;
//! for pkg in &table.packages {
//!     println!("{:#x} {}", pkg.id, pkg.name);
//! }
//! ```

#![allow(clippy::module_name_repetitions)]

pub mod arsc;
pub mod axml;
pub mod chunk;
pub mod ffi;
pub mod string_pool;

pub use arsc::{ResourceEntry, ResourcePackage, ResourceTable, ResourceType, parse_arsc};
pub use axml::{Manifest, decode_axml};

/// Errors surfaced by the decoders.
///
/// Crafted inputs are common (obfuscated apps, packers, malformed but
/// runtime-tolerant chunks), so almost every variant is recoverable
/// upstream — callers typically log and skip the offending chunk
/// rather than aborting decode.
#[derive(Debug)]
pub enum ArscError {
    /// Buffer is too short to hold even a chunk header.
    TooSmall(usize),

    /// Magic bytes don't match the expected chunk type.
    BadMagic(u16, u16),

    /// Declared chunk size disagrees with the surrounding buffer.
    ChunkOverrun { got: u32, at: usize },

    /// String pool refused to decode an entry because the offsets
    /// pointed outside the chunk payload.
    StringPool(&'static str),

    /// Anything else.
    Other(&'static str),
}

impl std::fmt::Display for ArscError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSmall(n) => write!(f, "input too small ({n} bytes)"),
            Self::BadMagic(got, expected) => {
                write!(f, "bad magic 0x{got:04x}, expected 0x{expected:04x}")
            }
            Self::ChunkOverrun { got, at } => {
                write!(f, "chunk size {got} overruns at offset 0x{at:x}")
            }
            Self::StringPool(msg) => write!(f, "string pool: {msg}"),
            Self::Other(msg) => write!(f, "decode failure: {msg}"),
        }
    }
}

impl std::error::Error for ArscError {}
