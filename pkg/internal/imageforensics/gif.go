package imageforensics

import "bytes"

// ═══════════════════════════════════════════════════════════════════════════════
// GIF PARSER (lightweight block walker)
//
// We don't need full LZW decompression for forensics. Walk the structural
// blocks (header → logical screen descriptor → optional global colour table →
// extensions / image descriptors → trailer) so the trailer byte 0x3B is only
// recognised at end-of-stream and not inside image data or sub-block bytes.
// Falls back to "no trailer" rather than emitting a false positive.
// ═══════════════════════════════════════════════════════════════════════════════

// GIFInfo is the parsed GIF structure.
type GIFInfo struct {
	Valid             bool
	Width, Height     int
	TrailerOffset     int
	TrailingData      []byte
	SuspiciousComment bool
}

// ParseGIF performs a structural walk. Panic-safe.
func ParseGIF(data []byte) (info GIFInfo) {
	defer func() { notePanic("imageforensics.gif", recover()) }()

	if len(data) < 13 {
		return GIFInfo{}
	}
	if !bytes.Equal(data[:6], []byte("GIF87a")) && !bytes.Equal(data[:6], []byte("GIF89a")) {
		return GIFInfo{}
	}
	info.Valid = true
	info.Width = int(data[6]) | int(data[7])<<8
	info.Height = int(data[8]) | int(data[9])<<8

	// Logical Screen Descriptor: bytes 6..12. Packed field at offset 10:
	//   bit 7    : Global Color Table Flag
	//   bits 0-2 : size of GCT (2^(N+1) entries × 3 bytes)
	packed := data[10]
	pos := 13
	if packed&0x80 != 0 {
		gctSize := 3 * (1 << ((packed & 0x07) + 1))
		pos += gctSize
	}
	if pos > len(data) {
		return info
	}

	// Walk blocks.
	for pos < len(data) {
		introducer := data[pos]
		switch introducer {
		case 0x3B: // Trailer
			info.TrailerOffset = pos + 1
			if info.TrailerOffset < len(data) {
				info.TrailingData = data[info.TrailerOffset:]
			}
			return info

		case 0x21: // Extension introducer
			if pos+2 >= len(data) {
				return info
			}
			label := data[pos+1]
			pos += 2
			// Comment extension: aggregate sub-block sizes for size heuristic.
			if label == 0xFE {
				total, next, ok := walkSubBlocks(data, pos)
				if !ok {
					return info
				}
				if total > 1024 {
					info.SuspiciousComment = true
				}
				pos = next
				continue
			}
			// Other extension types: skip block size (label 0xF9 GCE has 4)
			// + sub-blocks. We don't differentiate; just walk the
			// terminator-bounded stream.
			_, next, ok := walkSubBlocks(data, pos)
			if !ok {
				return info
			}
			pos = next

		case 0x2C: // Image Descriptor: 10 bytes, then optional LCT, then LZW data
			if pos+10 > len(data) {
				return info
			}
			imgPacked := data[pos+9]
			pos += 10
			if imgPacked&0x80 != 0 {
				lctSize := 3 * (1 << ((imgPacked & 0x07) + 1))
				pos += lctSize
			}
			if pos+1 > len(data) {
				return info
			}
			// LZW minimum code size byte
			pos++
			_, next, ok := walkSubBlocks(data, pos)
			if !ok {
				return info
			}
			pos = next

		default:
			// Unknown block — bail rather than guess.
			return info
		}
	}
	return info
}

// walkSubBlocks consumes a chain of GIF sub-blocks beginning at pos and ending
// with a 0-length terminator. Returns (total payload bytes, next position,
// ok). ok=false means malformed / truncated.
func walkSubBlocks(data []byte, pos int) (total int, next int, ok bool) {
	for pos < len(data) {
		size := int(data[pos])
		if size == 0 {
			return total, pos + 1, true
		}
		if pos+1+size > len(data) {
			return total, pos, false
		}
		total += size
		pos += 1 + size
	}
	return total, pos, false
}
