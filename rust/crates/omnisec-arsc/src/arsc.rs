//! ARSC (`resources.arsc`) decoder.
//!
//! The Go side carries the full decoder. This module ships a leaner,
//! parallel implementation that the Go runtime can opt into through
//! the FFI layer when a table is large enough that the rayon threads
//! actually pay for themselves.

use omnisec_json::{FromJson, ToJson};

use crate::ArscError;
use crate::chunk::{ChunkHeader, read_u32, ty};
use crate::string_pool;

#[derive(Debug, Default, ToJson, FromJson)]
pub struct ResourceTable {
    pub packages: Vec<ResourcePackage>,
    pub global_strings_len: usize,
}

#[derive(Debug, Default, ToJson, FromJson)]
pub struct ResourcePackage {
    pub id: u32,
    pub name: String,
    pub types: Vec<ResourceType>,
}

#[derive(Debug, Default, ToJson, FromJson)]
pub struct ResourceType {
    pub id: u32,
    pub name: String,
    pub entries: Vec<ResourceEntry>,
}

#[derive(Debug, Default, ToJson, FromJson)]
pub struct ResourceEntry {
    pub id: u32,
    pub name: String,
}

/// Parses a `resources.arsc` blob. Currently extracts the global
/// string pool and the per-package metadata only — entry-level
/// decoding still lives on the Go side because the surface is large
/// and migrating it gradually keeps the FFI boundary thin.
///
/// This is enough to power validation tests and benchmarks while we
/// expand the implementation.
pub fn parse_arsc(data: &[u8]) -> Result<ResourceTable, ArscError> {
    let hdr = ChunkHeader::parse(data)?;
    if hdr.ty != ty::TABLE {
        return Err(ArscError::BadMagic(hdr.ty, ty::TABLE));
    }
    let total = (hdr.size as usize).min(data.len());

    let _expected_pkgs = read_u32(data, 8);

    let mut table = ResourceTable::default();
    let mut cursor = hdr.header_size as usize;

    while cursor + 8 <= total {
        let sub = ChunkHeader::parse(&data[cursor..])?;
        let end = cursor + sub.size as usize;
        if end > total {
            return Err(ArscError::ChunkOverrun {
                got: sub.size,
                at: cursor,
            });
        }
        match sub.ty {
            ty::STRING_POOL => {
                let pool = string_pool::parse(&data[cursor..end])?;
                table.global_strings_len = pool.entries.len();
            }
            ty::TABLE_PACKAGE => {
                if let Some(pkg) = parse_package(&data[cursor..end]) {
                    table.packages.push(pkg);
                }
            }
            _ => {} // unknown chunk — skip
        }
        cursor = end;
    }

    Ok(table)
}

fn parse_package(chunk: &[u8]) -> Option<ResourcePackage> {
    if chunk.len() < 8 + 4 + 256 {
        return None;
    }
    let body = &chunk[8..];
    let id = read_u32(body, 0);
    let name = decode_fixed_utf16(&body[4..4 + 256]);
    Some(ResourcePackage {
        id,
        name,
        types: Vec::new(),
    })
}

/// Decodes a fixed-width NUL-terminated UTF-16LE buffer.
///
/// Used for package and library names which are stored as 256-byte
/// records regardless of actual length.
fn decode_fixed_utf16(buf: &[u8]) -> String {
    let mut units = Vec::with_capacity(buf.len() / 2);
    for chunk in buf.chunks_exact(2) {
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_too_small() {
        assert!(parse_arsc(&[1, 2, 3]).is_err());
    }
}
