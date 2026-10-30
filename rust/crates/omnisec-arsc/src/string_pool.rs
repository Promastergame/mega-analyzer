//! String pool decoder shared by AXML and ARSC chunks.
//!
//! Both formats use the same RES_STRING_POOL chunk layout. We
//! materialize entries up-front because random access dominates the
//! workload. Encoding selection (UTF-8 vs UTF-16LE) is driven by the
//! `flags` field in the chunk-specific header.

use crate::ArscError;
use crate::chunk::{ChunkHeader, pool_flag, read_u32};

/// Decoded string pool, indexable in O(1) post-parse.
#[derive(Debug, Default)]
pub struct StringPool {
    /// One entry per index. Out-of-range or "absent" entries are
    /// represented by an empty string — callers should not rely on
    /// this to distinguish presence from emptiness; use `has`.
    pub entries: Vec<String>,
    pub flags: u32,
}

impl StringPool {
    /// Convenience accessor that returns `None` for unknown indices.
    #[must_use]
    pub fn get(&self, idx: u32) -> Option<&str> {
        if idx == u32::MAX {
            return None;
        }
        self.entries.get(idx as usize).map(String::as_str)
    }

    /// Tells whether the index is in range.
    #[must_use]
    pub fn has(&self, idx: u32) -> bool {
        (idx as usize) < self.entries.len() && idx != u32::MAX
    }
}

/// Decodes a RES_STRING_POOL chunk into a `StringPool`.
///
/// `chunk` is the entire chunk including the eight-byte generic
/// header.
pub fn parse(chunk: &[u8]) -> Result<StringPool, ArscError> {
    if chunk.len() < 8 + 20 {
        return Err(ArscError::StringPool("chunk too small"));
    }
    let _hdr = ChunkHeader::parse(chunk)?;

    let body = &chunk[8..];
    let string_count = read_u32(body, 0);
    let _style_count = read_u32(body, 4);
    let flags = read_u32(body, 8);
    let strings_start = read_u32(body, 12) as usize;

    if string_count > 4 << 20 {
        return Err(ArscError::StringPool("absurd string count"));
    }

    let offsets_table_start = 20;
    let offsets_table_end = offsets_table_start + (string_count as usize) * 4;
    if offsets_table_end > body.len() {
        return Err(ArscError::StringPool("offsets table truncated"));
    }

    // Pre-read offsets so we can drive entry decoding in parallel
    // when the pool is large. Plain Vec is enough since each entry
    // decode is independent and runs through immutable buffer slices.
    let mut offsets = Vec::with_capacity(string_count as usize);
    for i in 0..string_count {
        offsets.push(read_u32(body, offsets_table_start + (i as usize) * 4));
    }

    let utf8_mode = flags & pool_flag::UTF8 != 0;
    let mut entries = vec![String::new(); string_count as usize];

    // Sequential is faster for small pools (most AXMLs); only switch
    // to rayon for genuinely large ARSC tables. The 4096-entry cutoff
    // came from microbenchmarks on a Ryzen 5950X — below that, the
    // thread-pool dispatch overhead exceeds the parsing work.
    // For large pools the decode work is fanned out across a fixed set of
    // scoped threads (std only); each thread owns a disjoint chunk of slots,
    // so order and results are identical to the sequential path.
    if string_count >= 4096 {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 8);
        let per_thread = entries.len().div_ceil(threads);
        std::thread::scope(|s| {
            for (mut entry_chunk, off_chunk) in entries
                .chunks_mut(per_thread)
                .zip(offsets.chunks(per_thread))
            {
                s.spawn(move || {
                    for (slot, off) in entry_chunk.iter_mut().zip(off_chunk.iter()) {
                        let base = strings_start + (*off as usize);
                        if base >= chunk.len() {
                            continue;
                        }
                        if let Ok(str_val) = decode_entry(&chunk[base..], utf8_mode) {
                            *slot = str_val;
                        }
                    }
                });
            }
        });
    } else {
        for (slot, off) in entries.iter_mut().zip(offsets.iter()) {
            let base = strings_start + (*off as usize);
            if base >= chunk.len() {
                continue;
            }
            if let Ok(s) = decode_entry(&chunk[base..], utf8_mode) {
                *slot = s;
            }
        }
    }

    Ok(StringPool { entries, flags })
}

/// Decodes a single pool entry. The entry is preceded by a length
/// prefix whose width depends on the string length and encoding.
fn decode_entry(buf: &[u8], utf8: bool) -> Result<String, ArscError> {
    if buf.len() < 2 {
        return Err(ArscError::StringPool("entry truncated"));
    }
    if utf8 {
        // u16-or-u8 UTF-16 char count
        let mut off = 1;
        if buf[0] & 0x80 != 0 {
            if buf.len() < 2 {
                return Err(ArscError::StringPool("utf8 char count truncated"));
            }
            off = 2;
        }
        if buf.len() < off + 1 {
            return Err(ArscError::StringPool("utf8 byte count truncated"));
        }
        let first = buf[off];
        let byte_len = if first & 0x80 != 0 {
            if buf.len() < off + 2 {
                return Err(ArscError::StringPool("utf8 long byte count truncated"));
            }
            let n = ((u32::from(first & 0x7F)) << 8) | u32::from(buf[off + 1]);
            off += 2;
            n as usize
        } else {
            off += 1;
            usize::from(first)
        };
        if off + byte_len > buf.len() {
            return Err(ArscError::StringPool("utf8 payload overruns"));
        }
        Ok(decode_modified_utf8(&buf[off..off + byte_len]))
    } else {
        // UTF-16LE
        let first = u16::from_le_bytes([buf[0], buf[1]]);
        let (char_count, mut off) = if first & 0x8000 != 0 {
            if buf.len() < 4 {
                return Err(ArscError::StringPool("utf16 long count truncated"));
            }
            let hi = u32::from(first & 0x7FFF);
            let lo = u32::from(u16::from_le_bytes([buf[2], buf[3]]));
            (((hi << 16) | lo) as usize, 4)
        } else {
            (usize::from(first), 2)
        };

        if off + char_count * 2 > buf.len() {
            return Err(ArscError::StringPool("utf16 payload overruns"));
        }
        let mut units = Vec::with_capacity(char_count);
        for _ in 0..char_count {
            units.push(u16::from_le_bytes([buf[off], buf[off + 1]]));
            off += 2;
        }
        Ok(String::from_utf16_lossy(&units))
    }
}

/// Decodes Android's "modified UTF-8" — bytes are *almost* valid UTF-8,
/// but supplementary code points are encoded as CESU-8 surrogate pairs.
/// Real UTF-8 decoders see those pairs as unpaired surrogates and
/// substitute U+FFFD; we recombine them.
fn decode_modified_utf8(b: &[u8]) -> String {
    // Fast path: if the bytes are valid Go-style UTF-8 *and* contain
    // no 3-byte surrogate triples, we can reuse them directly.
    if let Ok(s) = std::str::from_utf8(b)
        && !contains_surrogate_triplet(b)
    {
        return s.to_owned();
    }
    decode_cesu8(b)
}

fn contains_surrogate_triplet(b: &[u8]) -> bool {
    let mut i = 0;
    while i + 2 < b.len() {
        let c = b[i];
        if (0xE0..0xF0).contains(&c) {
            let r = (u32::from(c & 0x0F) << 12)
                | (u32::from(b[i + 1] & 0x3F) << 6)
                | u32::from(b[i + 2] & 0x3F);
            if (0xD800..=0xDFFF).contains(&r) {
                return true;
            }
            i += 3;
        } else if c < 0x80 {
            i += 1;
        } else if c < 0xC0 {
            i += 1; // continuation byte
        } else if c < 0xE0 {
            i += 2;
        } else {
            i += 4;
        }
    }
    false
}

fn decode_cesu8(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c < 0x80 {
            out.push(c as char);
            i += 1;
            continue;
        }
        if c < 0xC0 {
            out.push(char::REPLACEMENT_CHARACTER);
            i += 1;
            continue;
        }
        if c < 0xE0 && i + 1 < b.len() {
            let r = (u32::from(c & 0x1F) << 6) | u32::from(b[i + 1] & 0x3F);
            out.push(char::from_u32(r).unwrap_or(char::REPLACEMENT_CHARACTER));
            i += 2;
            continue;
        }
        if c < 0xF0 && i + 2 < b.len() {
            let r = (u32::from(c & 0x0F) << 12)
                | (u32::from(b[i + 1] & 0x3F) << 6)
                | u32::from(b[i + 2] & 0x3F);
            // Surrogate pair?
            if (0xD800..=0xDBFF).contains(&r) && i + 5 < b.len() {
                let c2 = b[i + 3];
                if (0xE0..0xF0).contains(&c2) {
                    let r2 = (u32::from(c2 & 0x0F) << 12)
                        | (u32::from(b[i + 4] & 0x3F) << 6)
                        | u32::from(b[i + 5] & 0x3F);
                    if (0xDC00..=0xDFFF).contains(&r2) {
                        let combined = 0x10000 + (((r - 0xD800) << 10) | (r2 - 0xDC00));
                        if let Some(ch) = char::from_u32(combined) {
                            out.push(ch);
                            i += 6;
                            continue;
                        }
                    }
                }
            }
            out.push(char::from_u32(r).unwrap_or(char::REPLACEMENT_CHARACTER));
            i += 3;
            continue;
        }
        if i + 3 < b.len() {
            let r = (u32::from(c & 0x07) << 18)
                | (u32::from(b[i + 1] & 0x3F) << 12)
                | (u32::from(b[i + 2] & 0x3F) << 6)
                | u32::from(b[i + 3] & 0x3F);
            out.push(char::from_u32(r).unwrap_or(char::REPLACEMENT_CHARACTER));
            i += 4;
        } else {
            out.push(char::REPLACEMENT_CHARACTER);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cesu8_supplementary() {
        // U+1F600 → ED A0 BD ED B8 80
        let cesu = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        let s = decode_modified_utf8(&cesu);
        assert_eq!(s, "\u{1F600}");
    }

    #[test]
    fn ascii_fastpath() {
        assert_eq!(decode_modified_utf8(b"hello"), "hello");
    }
}
