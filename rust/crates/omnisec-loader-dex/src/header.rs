//! DEX header parsing and validation.

use crate::error::{DexError, DexResult};

/// DEX header size (always 0x70 = 112 bytes).
pub const DEX_HEADER_SIZE: u32 = 0x70;
/// Little-endian tag expected in the header.
pub const DEX_ENDIAN_TAG: u32 = 0x1234_5678;
/// Sentinel for "no index" (0xFFFF_FFFF).
pub const DEX_NO_INDEX: u32 = 0xFFFF_FFFF;
/// Maximum number of items in any section (OOM guard).
pub const MAX_SECTION_ITEMS: u32 = 200_000;
/// Maximum string length in UTF-16 units.
pub const MAX_STRING_LEN: u32 = 1_000_000;

/// Parsed DEX header — all offsets and sizes from the 112-byte header.
#[derive(Debug, Clone)]
pub struct DexHeader {
    /// DEX version string (e.g. "035").
    pub version: String,
    /// Total file size declared in header.
    pub file_size: u32,
    /// Header size (must be 0x70).
    pub header_size: u32,
    /// Endian tag (must be 0x12345678).
    pub endian_tag: u32,

    /// String IDs section size and offset.
    pub string_ids_size: u32,
    /// String IDs section file offset.
    pub string_ids_off: u32,
    /// Type IDs section size.
    pub type_ids_size: u32,
    /// Type IDs section file offset.
    pub type_ids_off: u32,
    /// Proto IDs section size.
    pub proto_ids_size: u32,
    /// Proto IDs section file offset.
    pub proto_ids_off: u32,
    /// Field IDs section size.
    pub field_ids_size: u32,
    /// Field IDs section file offset.
    pub field_ids_off: u32,
    /// Method IDs section size.
    pub method_ids_size: u32,
    /// Method IDs section file offset.
    pub method_ids_off: u32,
    /// Class defs section size.
    pub class_defs_size: u32,
    /// Class defs section file offset.
    pub class_defs_off: u32,
}

/// Section definition for validation.
struct SectionDef {
    name: &'static str,
    off: u32,
    count: u32,
    item_size: u32,
    min_item: u32,
}

impl DexHeader {
    /// Parse the 112-byte header from raw data.
    pub fn parse(data: &[u8]) -> DexResult<Self> {
        if data.len() < DEX_HEADER_SIZE as usize {
            return Err(DexError::TooSmall { actual: data.len() });
        }

        // Check magic: "dex\n"
        if data[0] != b'd' || data[1] != b'e' || data[2] != b'x' || data[3] != b'\n' {
            return Err(DexError::BadMagic);
        }

        let version = String::from_utf8_lossy(&data[4..7])
            .trim_end_matches('\0')
            .to_string();

        let header = Self {
            version,
            file_size: le_u32(data, 32),
            header_size: le_u32(data, 36),
            endian_tag: le_u32(data, 40),
            string_ids_size: le_u32(data, 56),
            string_ids_off: le_u32(data, 60),
            type_ids_size: le_u32(data, 64),
            type_ids_off: le_u32(data, 68),
            proto_ids_size: le_u32(data, 72),
            proto_ids_off: le_u32(data, 76),
            field_ids_size: le_u32(data, 80),
            field_ids_off: le_u32(data, 84),
            method_ids_size: le_u32(data, 88),
            method_ids_off: le_u32(data, 92),
            class_defs_size: le_u32(data, 96),
            class_defs_off: le_u32(data, 100),
        };

        header.validate(data.len())?;
        Ok(header)
    }

    /// Validate header consistency.
    fn validate(&self, data_len: usize) -> DexResult<()> {
        if self.header_size != DEX_HEADER_SIZE {
            return Err(DexError::BadHeader {
                detail: format!(
                    "header_size=0x{:x}, expected 0x{:x}",
                    self.header_size, DEX_HEADER_SIZE
                ),
            });
        }
        if self.endian_tag != DEX_ENDIAN_TAG {
            return Err(DexError::BadHeader {
                detail: format!(
                    "endian_tag=0x{:08x}, expected 0x{:08x}",
                    self.endian_tag, DEX_ENDIAN_TAG
                ),
            });
        }
        if self.file_size == 0 {
            return Err(DexError::BadHeader {
                detail: "file_size is zero".into(),
            });
        }
        if self.file_size as usize > data_len {
            return Err(DexError::BadHeader {
                detail: format!("file_size={} > data_len={}", self.file_size, data_len),
            });
        }

        let sections = self.all_sections();
        let data_len_u64 = data_len as u64;

        // Validate each section
        for s in &sections {
            if s.count == 0 {
                continue;
            }
            if s.count > MAX_SECTION_ITEMS {
                return Err(DexError::CountTooLarge {
                    section: s.name,
                    count: s.count,
                });
            }
            // OOM guard
            if u64::from(s.count) * u64::from(s.min_item) > data_len_u64 {
                return Err(DexError::CountTooLarge {
                    section: s.name,
                    count: s.count,
                });
            }
            // Bounds check
            let end = u64::from(s.off) + u64::from(s.count) * u64::from(s.item_size);
            if end > data_len_u64 {
                return Err(DexError::SectionOutOfBounds {
                    section: s.name,
                    offset: u64::from(s.off),
                    end,
                    file_size: data_len_u64,
                });
            }
        }

        // Check for section overlap
        let mut ranges: Vec<(&'static str, u64, u64)> = sections
            .iter()
            .filter(|s| s.count > 0)
            .map(|s| {
                let end = u64::from(s.off) + u64::from(s.count) * u64::from(s.item_size);
                (s.name, u64::from(s.off), end)
            })
            .collect();
        ranges.sort_by_key(|r| r.1);

        for w in ranges.windows(2) {
            if w[0].2 > w[1].1 {
                return Err(DexError::SectionOverlap {
                    a: w[0].0,
                    b: w[1].0,
                });
            }
        }

        Ok(())
    }

    fn all_sections(&self) -> Vec<SectionDef> {
        vec![
            SectionDef {
                name: "string_ids",
                off: self.string_ids_off,
                count: self.string_ids_size,
                item_size: 4,
                min_item: 1,
            },
            SectionDef {
                name: "type_ids",
                off: self.type_ids_off,
                count: self.type_ids_size,
                item_size: 4,
                min_item: 4,
            },
            SectionDef {
                name: "proto_ids",
                off: self.proto_ids_off,
                count: self.proto_ids_size,
                item_size: 12,
                min_item: 12,
            },
            SectionDef {
                name: "field_ids",
                off: self.field_ids_off,
                count: self.field_ids_size,
                item_size: 8,
                min_item: 8,
            },
            SectionDef {
                name: "method_ids",
                off: self.method_ids_off,
                count: self.method_ids_size,
                item_size: 8,
                min_item: 8,
            },
            SectionDef {
                name: "class_defs",
                off: self.class_defs_off,
                count: self.class_defs_size,
                item_size: 32,
                min_item: 32,
            },
        ]
    }
}

/// Read a little-endian u16 from data at offset.
#[inline]
pub fn le_u16(data: &[u8], off: u32) -> u16 {
    let o = off as usize;
    u16::from_le_bytes([data[o], data[o + 1]])
}

/// Read a little-endian u32 from data at offset.
#[inline]
pub fn le_u32(data: &[u8], off: u32) -> u32 {
    let o = off as usize;
    u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]])
}

/// Check if `[offset..offset+size)` is within data bounds.
#[inline]
pub fn bounds_ok(data: &[u8], offset: u32, size: u32) -> bool {
    u64::from(offset) + u64::from(size) <= data.len() as u64
}

/// Read unsigned LEB128 (max 5 bytes). Returns (value, bytes_consumed).
/// Returns (0, 0) on error.
///
/// The cursor is computed in `usize` so a hostile `offset` near `u32::MAX`
/// cannot overflow (which would panic in debug builds and silently wrap in
/// release), and so the comparison against the buffer length stays exact even
/// for buffers larger than `u32::MAX`.
pub fn read_uleb128(data: &[u8], offset: u32) -> (u32, usize) {
    let base = offset as usize;
    let mut result: u32 = 0;
    for i in 0usize..5 {
        let Some(&b) = base.checked_add(i).and_then(|idx| data.get(idx)) else {
            return (0, 0);
        };
        result |= u32::from(b & 0x7F) << (i * 7);
        if b & 0x80 == 0 {
            return (result, i + 1);
        }
    }
    (0, 0)
}

/// Read signed LEB128 (max 5 bytes). Returns (value, bytes_consumed).
///
/// Uses `usize` cursor arithmetic for the same overflow-safety reasons as
/// [`read_uleb128`].
pub fn read_sleb128(data: &[u8], offset: u32) -> (i32, usize) {
    let base = offset as usize;
    let mut result: i32 = 0;
    let mut shift: u32 = 0;
    for i in 0usize..5 {
        let Some(&b) = base.checked_add(i).and_then(|idx| data.get(idx)) else {
            return (0, 0);
        };
        result |= i32::from(b & 0x7F) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 32 && b & 0x40 != 0 {
                result |= -(1 << shift);
            }
            return (result, i + 1);
        }
    }
    (0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_le_u16() {
        let data = [0x34, 0x12, 0x00];
        assert_eq!(le_u16(&data, 0), 0x1234);
    }

    #[test]
    fn test_le_u32() {
        let data = [0x78, 0x56, 0x34, 0x12, 0x00];
        assert_eq!(le_u32(&data, 0), 0x1234_5678);
    }

    #[test]
    fn test_uleb128() {
        // 624485 = 0xE5 0x8E 0x26
        let data = [0xE5, 0x8E, 0x26];
        let (val, n) = read_uleb128(&data, 0);
        assert_eq!(val, 624_485);
        assert_eq!(n, 3);
    }

    #[test]
    fn test_sleb128_negative() {
        // -123456 in signed LEB128
        let data = [0xC0, 0xBB, 0x78];
        let (val, n) = read_sleb128(&data, 0);
        assert_eq!(val, -123_456);
        assert_eq!(n, 3);
    }

    #[test]
    fn test_leb128_offset_out_of_bounds_returns_error() {
        // An offset past the end must report failure, never index or panic.
        let data = [0xE5, 0x8E, 0x26];
        assert_eq!(read_uleb128(&data, 3), (0, 0));
        assert_eq!(read_uleb128(&data, 100), (0, 0));
        assert_eq!(read_sleb128(&data, 3), (0, 0));
        assert_eq!(read_sleb128(&data, 100), (0, 0));
    }

    #[test]
    fn test_leb128_hostile_offset_does_not_overflow() {
        // A near-`u32::MAX` offset previously overflowed the `offset + i`
        // cursor (debug panic / release wrap). It must now fail cleanly.
        let data = [0xE5, 0x8E, 0x26];
        assert_eq!(read_uleb128(&data, u32::MAX), (0, 0));
        assert_eq!(read_uleb128(&data, u32::MAX - 2), (0, 0));
        assert_eq!(read_sleb128(&data, u32::MAX), (0, 0));
        assert_eq!(read_sleb128(&data, u32::MAX - 2), (0, 0));
    }

    #[test]
    fn test_uleb128_truncated_continuation_bit() {
        // Every byte has the continuation bit set but the buffer ends: the
        // reader must give up after the available bytes without panicking.
        let data = [0x80, 0x80];
        assert_eq!(read_uleb128(&data, 0), (0, 0));
    }

    #[test]
    fn test_bad_magic() {
        let data = [0x00u8; 0x70];
        assert!(matches!(DexHeader::parse(&data), Err(DexError::BadMagic)));
    }

    #[test]
    fn test_too_small() {
        let data = [0u8; 16];
        assert!(matches!(
            DexHeader::parse(&data),
            Err(DexError::TooSmall { .. })
        ));
    }
}
