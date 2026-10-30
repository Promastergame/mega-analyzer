//! Modified UTF-8 (MUTF-8) decoder — Android's string encoding.
//!
//! Optimized with a fast-path for pure-ASCII strings (zero allocation beyond
//! the final `String`) and a slow-path for multi-byte / CESU-8 surrogate pairs.

use crate::header::{MAX_STRING_LEN, bounds_ok, read_uleb128};

/// Decode a MUTF-8 string starting at `offset` in `data`.
///
/// Returns `(decoded_string, warnings)`. Warnings are non-fatal issues
/// encountered during decoding (truncated strings, missing terminators, etc.).
pub fn decode_mutf8(data: &[u8], offset: u32) -> (String, Vec<String>) {
    let mut warnings = Vec::new();

    if !bounds_ok(data, offset, 1) {
        warnings.push(format!("MUTF-8 at 0x{offset:x}: offset out of bounds"));
        return (String::new(), warnings);
    }

    let (utf16_size, bytes_read) = read_uleb128(data, offset);
    if bytes_read == 0 {
        warnings.push(format!("MUTF-8 at 0x{offset:x}: bad ULEB128 length prefix"));
        return (String::new(), warnings);
    }
    if utf16_size > MAX_STRING_LEN {
        warnings.push(format!(
            "MUTF-8 at 0x{offset:x}: string too long ({utf16_size} utf16 units)"
        ));
        return (String::new(), warnings);
    }

    let cursor = offset + bytes_read as u32;

    if utf16_size == 0 {
        if bounds_ok(data, cursor, 1) && data[cursor as usize] != 0x00 {
            warnings.push(format!(
                "MUTF-8 empty string missing terminator at 0x{cursor:x}"
            ));
        }
        return (String::new(), warnings);
    }

    // Bounds check: at least utf16_size bytes must be available
    if !bounds_ok(data, cursor, utf16_size) {
        warnings.push(format!("MUTF-8 at 0x{offset:x}: data may be truncated"));
    }

    // Fast-path: pure ASCII
    let available = (data.len() as u32).saturating_sub(cursor);
    let scan_len = utf16_size.min(available);

    if scan_len > 0
        && is_ascii(&data[cursor as usize..(cursor + scan_len) as usize])
        && utf16_size <= available
    {
        let raw = &data[cursor as usize..(cursor + utf16_size) as usize];
        let term_pos = cursor + utf16_size;
        if (term_pos as usize) < data.len() && data[term_pos as usize] != 0x00 {
            warnings.push(format!("MUTF-8 missing null terminator at 0x{term_pos:x}"));
        }
        // Safe: we verified all bytes are ASCII
        return (String::from_utf8_lossy(raw).into_owned(), warnings);
    }

    // Slow-path: multi-byte
    let (s, slow_warnings) = decode_mutf8_slow(data, cursor, utf16_size);
    warnings.extend(slow_warnings);
    (s, warnings)
}

/// Check if all bytes are ASCII (< 0x80) and non-null.
/// Processes 8 bytes at a time for speed.
fn is_ascii(b: &[u8]) -> bool {
    const HI_MASK: u64 = 0x8080_8080_8080_8080;
    const ZERO_MASK: u64 = 0x0101_0101_0101_0101;

    let mut i = 0;

    // Process 8 bytes at a time (safe, no unsafe needed)
    while i + 8 <= b.len() {
        let mut word = [0u8; 8];
        word.copy_from_slice(&b[i..i + 8]);
        let w = u64::from_le_bytes(word);
        // High bit set = non-ASCII
        if w & HI_MASK != 0 {
            return false;
        }
        // Zero byte detection
        if (w.wrapping_sub(ZERO_MASK)) & !w & HI_MASK != 0 {
            return false;
        }
        i += 8;
    }

    // Remaining bytes
    for &byte in &b[i..] {
        if byte >= 0x80 || byte == 0x00 {
            return false;
        }
    }

    true
}

/// Slow-path MUTF-8 decoder for multi-byte characters and CESU-8 surrogate pairs.
fn decode_mutf8_slow(data: &[u8], start: u32, utf16_size: u32) -> (String, Vec<String>) {
    let mut warnings = Vec::new();
    let mut buf = String::with_capacity(utf16_size as usize);
    let mut cursor = start as usize;
    let mut utf16_units: u32 = 0;
    let data_len = data.len();

    while utf16_units < utf16_size {
        if cursor >= data_len {
            warnings.push(format!(
                "MUTF-8 truncated at 0x{cursor:x} ({utf16_units}/{utf16_size} units)"
            ));
            break;
        }

        let b1 = data[cursor];
        cursor += 1;

        if b1 == 0x00 {
            warnings.push(format!(
                "MUTF-8 premature null at 0x{:x} ({utf16_units}/{utf16_size} units)",
                cursor - 1
            ));
            break;
        }

        match b1 {
            // 1-byte ASCII
            0x01..=0x7F => {
                buf.push(b1 as char);
                utf16_units += 1;
            }
            // 2-byte sequence
            b if b & 0xE0 == 0xC0 => {
                if cursor >= data_len {
                    buf.push('\u{FFFD}');
                    break;
                }
                let b2 = data[cursor];
                cursor += 1;
                if b2 & 0xC0 != 0x80 {
                    buf.push('\u{FFFD}');
                    utf16_units += 1;
                    continue;
                }
                if b1 == 0xC0 && b2 == 0x80 {
                    buf.push('\0');
                } else {
                    let cp = u32::from(b1 & 0x1F) << 6 | u32::from(b2 & 0x3F);
                    buf.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                }
                utf16_units += 1;
            }
            // 3-byte sequence
            b if b & 0xF0 == 0xE0 => {
                if cursor + 1 >= data_len {
                    buf.push('\u{FFFD}');
                    break;
                }
                let b2 = data[cursor];
                let b3 = data[cursor + 1];
                cursor += 2;
                if b2 & 0xC0 != 0x80 || b3 & 0xC0 != 0x80 {
                    buf.push('\u{FFFD}');
                    utf16_units += 1;
                    continue;
                }
                let ch =
                    u32::from(b1 & 0x0F) << 12 | u32::from(b2 & 0x3F) << 6 | u32::from(b3 & 0x3F);

                // CESU-8 surrogate pair handling
                if (0xD800..=0xDBFF).contains(&ch)
                    && cursor + 2 < data_len
                    && data[cursor] & 0xF0 == 0xE0
                {
                    let b4 = data[cursor];
                    let b5 = data[cursor + 1];
                    let b6 = data[cursor + 2];
                    if b5 & 0xC0 == 0x80 && b6 & 0xC0 == 0x80 {
                        let low = u32::from(b4 & 0x0F) << 12
                            | u32::from(b5 & 0x3F) << 6
                            | u32::from(b6 & 0x3F);
                        if (0xDC00..=0xDFFF).contains(&low) {
                            let cp = 0x10000 + (ch - 0xD800) * 0x400 + (low - 0xDC00);
                            buf.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                            cursor += 3;
                            utf16_units += 2;
                            continue;
                        }
                    }
                }

                if (0xD800..=0xDFFF).contains(&ch) {
                    buf.push('\u{FFFD}');
                } else {
                    buf.push(char::from_u32(ch).unwrap_or('\u{FFFD}'));
                }
                utf16_units += 1;
            }
            // Invalid leading byte
            _ => {
                buf.push('\u{FFFD}');
                utf16_units += 1;
            }
        }
    }

    // Check terminator
    if cursor < data_len && data[cursor] != 0x00 {
        warnings.push(format!(
            "MUTF-8 missing null terminator at 0x{cursor:x} (got 0x{:02x})",
            data[cursor]
        ));
    }

    (buf, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii_string() {
        // ULEB128 length = 5, then "hello\0"
        let data = [0x05, b'h', b'e', b'l', b'l', b'o', 0x00];
        let (s, warnings) = decode_mutf8(&data, 0);
        assert_eq!(s, "hello");
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_empty_string() {
        let data = [0x00, 0x00];
        let (s, warnings) = decode_mutf8(&data, 0);
        assert_eq!(s, "");
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_null_encoding() {
        // MUTF-8 encodes U+0000 as 0xC0 0x80
        let data = [0x01, 0xC0, 0x80, 0x00];
        let (s, _) = decode_mutf8(&data, 0);
        assert_eq!(s, "\0");
    }

    #[test]
    fn test_is_ascii_fast() {
        assert!(is_ascii(b"Hello, World!"));
        assert!(!is_ascii(b"Hello\x80World"));
        assert!(!is_ascii(b"Hello\x00World"));
        assert!(is_ascii(b""));
    }
}
