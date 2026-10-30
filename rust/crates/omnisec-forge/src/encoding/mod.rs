//! Polymorphic encoding — bad-byte avoidance via `omnisec-smt`.
//!
//! When the sink imposes byte-level constraints (e.g. `\x00`, `\x0a`,
//! `\x0d` are illegal because the input is parsed as a NUL-terminated
//! line-oriented string), the raw payload bytes need a small decoder
//! stub that reconstructs them at runtime.
//!
//! - [`xor`] — single-byte XOR encoder; the decoder stub is just two
//!   instructions on every arch we support. The XOR key is found via
//!   the SMT solver: we ask for an `x` such that for every payload byte
//!   `b`, `b ^ x ∉ bad_bytes`.
//! - [`polymorphic`] — multi-pass encoder that combines XOR with
//!   add/sub/rotate transforms when no single XOR key exists.
//!
//! The output is always a [`EncodedPayload`] with both the encoded
//! bytes and a small "decoder recipe" the [`crate::compiler::ForgeEngine`]
//! splices into the final payload.

pub mod polymorphic;
pub mod xor;

pub use polymorphic::PolymorphicEncoder;
pub use xor::{XorEncoder, xor_encode};

use omnisec_json::{FromJson, ToJson};

/// Output of any encoder.
#[derive(Debug, Clone, PartialEq, Eq, ToJson, FromJson)]
pub struct EncodedPayload {
    /// The encoded payload bytes (still need to be passed through the
    /// decoder at runtime).
    pub bytes: Vec<u8>,
    /// Human-readable recipe describing how to decode at runtime.
    /// E.g. `"xor 0xAA"`, `"add 0x01 ; rotr 3"`.
    pub recipe: String,
    /// Bytes the encoded payload now avoids.
    pub bad_bytes_avoided: Vec<u8>,
}
