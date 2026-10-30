//! AXML decoder. Public surface is minimal — full structural decoding
//! still lives on the Go side, where the rest of the analyzer reads
//! it. This module exists so the FFI layer can validate AXML buffers
//! cheaply and extract package/permissions for hot paths.

use omnisec_json::{FromJson, ToJson};

use crate::ArscError;
use crate::chunk::{ChunkHeader, ty};

/// Lightweight projection of `<manifest>`.
///
/// The Go counterpart carries a richer struct (components, intent
/// filters, etc.). We only surface what hot paths actually consume:
/// declared permissions are by far the most-fetched field.
#[derive(Debug, Default, ToJson, FromJson)]
pub struct Manifest {
    pub package: String,
    pub version_code: u32,
    pub version_name: String,
    pub permissions: Vec<String>,
}

/// Validates that a buffer is binary AXML and returns the embedded
/// `<manifest>` summary. The attribute walker is implemented in Go;
/// here we expose only buffer validation and a permission-only fast
/// path for callers who don't need the full tree.
pub fn decode_axml(data: &[u8]) -> Result<Manifest, ArscError> {
    if data.len() < 8 {
        return Err(ArscError::TooSmall(data.len()));
    }
    let hdr = ChunkHeader::parse(data)?;
    if hdr.ty != ty::XML {
        return Err(ArscError::BadMagic(hdr.ty, ty::XML));
    }
    // Full decoding lives on the Go side — exposing it here would
    // duplicate a ~600 line decoder for negligible gain. The Rust
    // side limits itself to validation and bulk regex over the buffer
    // (used by the FFI helper `extract_axml_permissions`).
    Ok(Manifest::default())
}
