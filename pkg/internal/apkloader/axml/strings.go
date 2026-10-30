package axml

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// stringPool is a decoded RES_STRING_POOL_TYPE chunk.
//
// The pool stores either UTF-8 or UTF-16LE entries, distinguished by
// flagUTF8 in the header. Every entry is preceded by an inline length
// prefix that varies between encodings. We materialize all entries
// up-front because random access dominates the access pattern in AXML
// and the alternative — re-walking the raw buffer per lookup — is
// O(n²) on hot paths.
type stringPool struct {
	entries []string
	flags   uint32
}

// String returns the entry at idx, or SentinelNoString for invalid
// indices. -1 (0xFFFFFFFF) marks "absent" in AXML and is the most
// common reason for an out-of-range lookup; we surface it as a sentinel
// rather than panic so XML rendering stays infallible.
func (p *stringPool) String(idx uint32) string {
	if p == nil || int(idx) >= len(p.entries) || idx == 0xFFFFFFFF {
		return SentinelNoString
	}
	return p.entries[idx]
}

// Has reports whether idx is a valid pool index.
func (p *stringPool) Has(idx uint32) bool {
	return p != nil && int(idx) < len(p.entries) && idx != 0xFFFFFFFF
}

// Len returns the number of decoded entries.
func (p *stringPool) Len() int {
	if p == nil {
		return 0
	}
	return len(p.entries)
}

// parseStringPool decodes a single RES_STRING_POOL_TYPE chunk.
// The chunk header (8 bytes) has already been consumed by the caller;
// `body` begins at the chunk-specific header (stringCount...).
//
// Layout after the generic chunk header:
//
//	u32 stringCount
//	u32 styleCount
//	u32 flags
//	u32 stringsStart    (offset from chunk start)
//	u32 stylesStart
//	u32 stringOffsets[stringCount]
//	u32 styleOffsets[styleCount]
//	... strings data ...
//	... styles data ...
//
// stringsStart is relative to the chunk start, so we receive `chunk`
// (the entire chunk including its 8-byte header) for offset math.
func parseStringPool(chunk []byte) (*stringPool, error) {
	if len(chunk) < 8+20 {
		return nil, errors.New("string pool: chunk too small")
	}

	body := chunk[8:]
	stringCount := binary.LittleEndian.Uint32(body[0:4])
	styleCount := binary.LittleEndian.Uint32(body[4:8])
	flags := binary.LittleEndian.Uint32(body[8:12])
	stringsStart := binary.LittleEndian.Uint32(body[12:16])
	_ = binary.LittleEndian.Uint32(body[16:20]) // stylesStart, unused

	if stringCount > maxStringPoolEntries {
		return nil, fmt.Errorf("string pool: refusing oversized count %d", stringCount)
	}

	// Offsets table directly follows the chunk-specific header.
	const localHeader = 20
	offsetsTable := body[localHeader:]
	if uint64(stringCount)*4 > uint64(len(offsetsTable)) {
		return nil, errors.New("string pool: offsets table truncated")
	}

	offsets := make([]uint32, stringCount)
	for i := uint32(0); i < stringCount; i++ {
		offsets[i] = binary.LittleEndian.Uint32(offsetsTable[i*4 : i*4+4])
	}
	_ = styleCount // styles aren't useful for our purposes

	pool := &stringPool{
		entries: make([]string, stringCount),
		flags:   flags,
	}

	utf8Mode := flags&flagUTF8 != 0
	for i, off := range offsets {
		// stringsStart is relative to chunk start; offsets are relative
		// to stringsStart. The addition can overflow with crafted input,
		// so we range-check both segments independently.
		base := uint64(stringsStart) + uint64(off)
		if base >= uint64(len(chunk)) {
			pool.entries[i] = ""
			continue
		}
		s, err := decodePoolEntry(chunk[base:], utf8Mode)
		if err != nil {
			pool.entries[i] = ""
			continue
		}
		pool.entries[i] = s
	}

	return pool, nil
}

// decodePoolEntry reads one entry starting at buf[0].
//
// UTF-16: u16 charCount (high bit set means a 2-u16 length prefix where
//
//	the upper u16 is the high half and the lower u16 is the low half),
//	then 2*charCount bytes (LE), then a u16 0x0000 terminator.
//
// UTF-8:  u8/u16 char count, u8/u16 byte count (high bit signals long
//
//	form), then byte_count bytes, then a NUL.
func decodePoolEntry(buf []byte, utf8 bool) (string, error) {
	if len(buf) < 2 {
		return "", errors.New("pool entry: truncated")
	}

	if utf8 {
		// Skip char count — we only need byte count.
		offset := 1
		if buf[0]&0x80 != 0 {
			if len(buf) < 2 {
				return "", errors.New("pool entry: truncated utf8 char count")
			}
			offset = 2
		}
		if len(buf) < offset+1 {
			return "", errors.New("pool entry: truncated utf8 byte count")
		}
		var byteLen int
		first := buf[offset]
		if first&0x80 != 0 {
			if len(buf) < offset+2 {
				return "", errors.New("pool entry: truncated utf8 long byte count")
			}
			byteLen = (int(first&0x7F) << 8) | int(buf[offset+1])
			offset += 2
		} else {
			byteLen = int(first)
			offset++
		}
		if offset+byteLen > len(buf) {
			return "", errors.New("pool entry: utf8 payload overruns buffer")
		}
		return decodeAndroidUTF8(buf[offset : offset+byteLen]), nil
	}

	// UTF-16LE.
	first := binary.LittleEndian.Uint16(buf[0:2])
	offset := 2
	var charCount int
	if first&0x8000 != 0 {
		if len(buf) < 4 {
			return "", errors.New("pool entry: truncated utf16 long char count")
		}
		hi := uint32(first & 0x7FFF)
		lo := uint32(binary.LittleEndian.Uint16(buf[2:4]))
		charCount = int((hi << 16) | lo)
		offset = 4
	} else {
		charCount = int(first)
	}

	if offset+charCount*2 > len(buf) {
		return "", errors.New("pool entry: utf16 payload overruns buffer")
	}

	codeUnits := make([]uint16, charCount)
	for i := 0; i < charCount; i++ {
		codeUnits[i] = binary.LittleEndian.Uint16(buf[offset+i*2 : offset+i*2+2])
	}
	return string(utf16.Decode(codeUnits)), nil
}

// decodeAndroidUTF8 decodes a byte slice that Android labels as "UTF-8"
// in its string pool flags. The data is *almost* valid UTF-8, but the
// runtime encoder emits CESU-8 for any code point in the supplementary
// planes (U+10000…U+10FFFF) — each such code point is written as a
// pair of three-byte sequences encoding the UTF-16 surrogates instead
// of the canonical four-byte UTF-8 form. Standard library decoders see
// these as two unpaired surrogates and replace them with U+FFFD.
//
// We therefore:
//  1. fast-path: if the slice is valid Go UTF-8, use it as-is
//  2. slow-path: scan for surrogate-encoded triplets and recombine them
//
// This mirrors the behaviour the Android resource framework uses
// internally, but is implemented from scratch from a description of
// the encoding (CESU-8 is documented in the Unicode Technical Report
// UTR #26 and is public).
func decodeAndroidUTF8(b []byte) string {
	if utf8.Valid(b) {
		// validate that no surrogate halves slipped in via 3-byte enc
		if !containsSurrogateTriplet(b) {
			return string(b)
		}
	}
	return decodeCESU8(b)
}

// containsSurrogateTriplet reports whether b contains a 3-byte UTF-8
// sequence encoding a value in the surrogate range U+D800..U+DFFF.
// In valid UTF-8 these are forbidden; in CESU-8 they are exactly how
// supplementary code points are spelled.
func containsSurrogateTriplet(b []byte) bool {
	for i := 0; i+2 < len(b); {
		c := b[i]
		switch {
		case c < 0x80:
			i++
		case c < 0xC0:
			i++ // continuation byte without lead — bail; outer fast-path will reject
		case c < 0xE0:
			i += 2
		case c < 0xF0:
			// 3-byte sequence; decode partial to check for surrogate range
			if i+2 >= len(b) {
				return false
			}
			r := (rune(c&0x0F) << 12) | (rune(b[i+1]&0x3F) << 6) | rune(b[i+2]&0x3F)
			if r >= 0xD800 && r <= 0xDFFF {
				return true
			}
			i += 3
		default:
			i += 4
		}
	}
	return false
}

// decodeCESU8 converts an Android "modified" UTF-8 stream into a Go
// string by decoding each 3-byte sequence and pairing surrogate halves.
// Bytes that aren't valid in either encoding are passed through as
// Unicode replacement characters (U+FFFD) — same policy as utf8.Valid
// when it encounters bad data.
func decodeCESU8(b []byte) string {
	out := make([]rune, 0, len(b))
	i := 0
	for i < len(b) {
		c := b[i]
		switch {
		case c < 0x80:
			out = append(out, rune(c))
			i++
		case c < 0xC0:
			out = append(out, utf8.RuneError)
			i++
		case c < 0xE0:
			if i+1 >= len(b) {
				out = append(out, utf8.RuneError)
				i++
				continue
			}
			r := (rune(c&0x1F) << 6) | rune(b[i+1]&0x3F)
			out = append(out, r)
			i += 2
		case c < 0xF0:
			if i+2 >= len(b) {
				out = append(out, utf8.RuneError)
				i++
				continue
			}
			r := (rune(c&0x0F) << 12) | (rune(b[i+1]&0x3F) << 6) | rune(b[i+2]&0x3F)
			// CESU-8 surrogate pair: high half first, low half follows
			if r >= 0xD800 && r <= 0xDBFF && i+5 < len(b) {
				c2 := b[i+3]
				if c2 >= 0xE0 && c2 < 0xF0 {
					r2 := (rune(c2&0x0F) << 12) | (rune(b[i+4]&0x3F) << 6) | rune(b[i+5]&0x3F)
					if r2 >= 0xDC00 && r2 <= 0xDFFF {
						combined := 0x10000 + ((r-0xD800)<<10 | (r2 - 0xDC00))
						out = append(out, combined)
						i += 6
						continue
					}
				}
			}
			out = append(out, r)
			i += 3
		default:
			// 4-byte sequence — accept as canonical UTF-8
			if i+3 >= len(b) {
				out = append(out, utf8.RuneError)
				i++
				continue
			}
			r := (rune(c&0x07) << 18) | (rune(b[i+1]&0x3F) << 12) | (rune(b[i+2]&0x3F) << 6) | rune(b[i+3]&0x3F)
			out = append(out, r)
			i += 4
		}
	}
	return string(out)
}
