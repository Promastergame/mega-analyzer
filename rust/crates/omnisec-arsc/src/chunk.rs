//! Common chunk-header utilities used by both AXML and ARSC.

use crate::ArscError;

/// Chunk type constants for the resource binary format.
///
/// These are part of Android's public ABI and are stable across all
/// supported platform versions. Listed here so the rest of the crate
/// can reference them without magic numbers.
pub mod ty {
    pub const NULL: u16 = 0x0000;
    pub const STRING_POOL: u16 = 0x0001;
    pub const TABLE: u16 = 0x0002;
    pub const XML: u16 = 0x0003;

    pub const XML_START_NS: u16 = 0x0100;
    pub const XML_END_NS: u16 = 0x0101;
    pub const XML_START_ELEMENT: u16 = 0x0102;
    pub const XML_END_ELEMENT: u16 = 0x0103;
    pub const XML_CDATA: u16 = 0x0104;
    pub const XML_RESOURCE_MAP: u16 = 0x0180;

    pub const TABLE_PACKAGE: u16 = 0x0200;
    pub const TABLE_TYPE: u16 = 0x0201;
    pub const TABLE_TYPE_SPEC: u16 = 0x0202;
    pub const TABLE_LIBRARY: u16 = 0x0203;
}

/// String pool flags packed into the chunk-specific header.
pub mod pool_flag {
    pub const SORTED: u32 = 1 << 0;
    pub const UTF8: u32 = 1 << 8;
}

/// Resource value type tags from `Res_value`.
pub mod val {
    pub const NULL: u8 = 0x00;
    pub const REFERENCE: u8 = 0x01;
    pub const ATTRIBUTE: u8 = 0x02;
    pub const STRING: u8 = 0x03;
    pub const FLOAT: u8 = 0x04;
    pub const DIMENSION: u8 = 0x05;
    pub const FRACTION: u8 = 0x06;
    pub const DYNAMIC_REFERENCE: u8 = 0x07;
    pub const DYNAMIC_ATTRIBUTE: u8 = 0x08;
    pub const INT_DEC: u8 = 0x10;
    pub const INT_HEX: u8 = 0x11;
    pub const INT_BOOL: u8 = 0x12;
    pub const COLOR_ARGB8: u8 = 0x1c;
    pub const COLOR_RGB8: u8 = 0x1d;
    pub const COLOR_ARGB4: u8 = 0x1e;
    pub const COLOR_RGB4: u8 = 0x1f;
}

/// Parsed view of the eight-byte chunk header that prefixes every
/// chunk in the resource binary format.
#[derive(Debug, Clone, Copy)]
pub struct ChunkHeader {
    pub ty: u16,
    pub header_size: u16,
    pub size: u32,
}

impl ChunkHeader {
    /// Reads a chunk header from `buf[0..8]`.
    ///
    /// Validates the basic invariants `header_size >= 8` and
    /// `size >= header_size`. Crafted inputs that violate these are
    /// treated as fatal because the rest of the decoder relies on
    /// them to compute offsets.
    pub fn parse(buf: &[u8]) -> Result<Self, ArscError> {
        if buf.len() < 8 {
            return Err(ArscError::TooSmall(buf.len()));
        }
        let ty = u16::from_le_bytes([buf[0], buf[1]]);
        let header_size = u16::from_le_bytes([buf[2], buf[3]]);
        let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if header_size < 8 {
            return Err(ArscError::Other("header size < 8"));
        }
        if size < u32::from(header_size) {
            return Err(ArscError::Other("chunk size < header size"));
        }
        Ok(Self {
            ty,
            header_size,
            size,
        })
    }
}

/// Reads an u16 from `buf[off..off+2]` in little-endian order.
///
/// Bounds-checked: returns `0` for out-of-range offsets so the
/// surrounding parser can keep going on slightly malformed inputs
/// rather than panic. Real corruption is caught by the size checks
/// upstream.
#[inline]
pub fn read_u16(buf: &[u8], off: usize) -> u16 {
    if off + 2 > buf.len() {
        0
    } else {
        u16::from_le_bytes([buf[off], buf[off + 1]])
    }
}

#[inline]
pub fn read_u32(buf: &[u8], off: usize) -> u32 {
    if off + 4 > buf.len() {
        0
    } else {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }
}
