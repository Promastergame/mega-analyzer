//! Core types and primitives for the OmniSec platform.
//!
//! This crate is the foundation of every other `omnisec-*` crate. It deliberately
//! has zero external dependencies — everything is built on `std` alone.
//!
//! What lives here:
//! - [`Format`] — every binary container OmniSec knows about (PE, ELF, DEX, JVM, ...).
//! - [`Arch`] — every code-generation target we lift to OmniIR.
//! - [`Endian`], [`Bitness`] — endianness and pointer width descriptors.
//! - [`magic`] — magic-byte detection that turns the first few bytes of a file
//!   into a [`Format`].
//! - [`Error`] / [`Result`] — the canonical error type used across crates.
//!
//! Everything here is `no_std`-friendly in spirit but currently uses `std` for
//! ergonomics. We may revisit if/when we target embedded/firmware fuzzing.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod arch;
pub mod error;
pub mod ffi_guard;
pub mod format;
pub mod magic;

pub use arch::{Arch, Bitness, Endian};
pub use error::{Error, Result};
pub use format::Format;
pub use magic::detect_format;
