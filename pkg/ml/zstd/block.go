package zstd

// ═══════════════════════════════════════════════════════════════════════════
// Blocks and the literals section
// ═══════════════════════════════════════════════════════════════════════════
//
// A compressed block is a literals section followed by a sequences section.
// The literals are the bytes that could not be expressed as a copy of earlier
// output; the sequences say how to interleave them with those copies.
//
// The literals header is four different layouts selected by two bits, and the
// field widths are not byte aligned, so the sizes are pulled out of a 32-bit
// little-endian read. Ports ZSTD_decodeLiteralsBlock.

const (
	litRaw        = 0
	litRLE        = 1
	litCompressed = 2
	litTreeless   = 3

	// A four-stream literals section needs at least six bytes of output,
	// otherwise the fourth stream would be empty.
	minLiteralsFor4Streams = 6

	// A compressed block always has at least a literals header and a sequence
	// count.
	minCompressedBlock = 2
)

// decodeLiterals returns the literals for this block and how many bytes of the
// block the section occupied. The returned slice may alias src, so callers must
// not hold on to it past the block.
func (d *frameDecoder) decodeLiterals(src []byte) ([]byte, int, error) {
	if len(src) < 1 {
		return nil, 0, trunc("literals section is missing")
	}
	b0 := src[0]
	litType := b0 & 3
	sizeFormat := (b0 >> 2) & 3

	if litType == litRaw || litType == litRLE {
		var lh, litSize int
		switch sizeFormat {
		case 0, 2:
			// Size format 2 is a duplicate of 0 for these two types; the
			// format reserves the bit rather than using it.
			lh = 1
			litSize = int(b0 >> 3)
		case 1:
			if len(src) < 2 {
				return nil, 0, trunc("literals size field is truncated")
			}
			lh = 2
			litSize = int((uint32(src[0]) | uint32(src[1])<<8) >> 4)
		default:
			if len(src) < 3 {
				return nil, 0, trunc("literals size field is truncated")
			}
			lh = 3
			litSize = int((uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16) >> 4)
		}
		if litSize > BlockSizeMax {
			return nil, 0, errf("literals section claims %d bytes, above the %d byte block limit", litSize, BlockSizeMax)
		}

		if litType == litRaw {
			if lh+litSize > len(src) {
				return nil, 0, trunc("raw literals run past the end of the block")
			}
			return src[lh : lh+litSize], lh + litSize, nil
		}
		if lh+1 > len(src) {
			return nil, 0, trunc("run-length literal byte is missing")
		}
		buf := d.litBuffer(litSize)
		fill := src[lh]
		for i := range buf {
			buf[i] = fill
		}
		return buf, lh + 1, nil
	}

	// Huffman coded, either with a table in this block or reusing the previous
	// one. Five bytes are readable here because a compressed block is never
	// smaller than that once it has a Huffman section.
	if len(src) < 5 {
		return nil, 0, trunc("compressed literals header is truncated")
	}
	lhc := uint32(src[0]) | uint32(src[1])<<8 | uint32(src[2])<<16 | uint32(src[3])<<24
	var lh, litSize, cSize int
	four := true
	switch sizeFormat {
	case 0:
		// 10 bits each, single stream.
		lh = 3
		litSize = int((lhc >> 4) & 0x3FF)
		cSize = int((lhc >> 14) & 0x3FF)
		four = false
	case 1:
		// Same widths, four streams.
		lh = 3
		litSize = int((lhc >> 4) & 0x3FF)
		cSize = int((lhc >> 14) & 0x3FF)
	case 2:
		// 14 bits each.
		lh = 4
		litSize = int((lhc >> 4) & 0x3FFF)
		cSize = int(lhc >> 18)
	default:
		// 18 bits each, so the compressed size spills into a fifth byte.
		lh = 5
		litSize = int((lhc >> 4) & 0x3FFFF)
		cSize = int(lhc>>22) + int(uint32(src[4])<<10)
	}

	if litSize > BlockSizeMax {
		return nil, 0, errf("literals section claims %d bytes, above the %d byte block limit", litSize, BlockSizeMax)
	}
	if four && litSize > 0 && litSize < minLiteralsFor4Streams {
		return nil, 0, errf("four-stream literals section claims only %d bytes", litSize)
	}
	if lh+cSize > len(src) {
		return nil, 0, trunc("compressed literals run past the end of the block")
	}
	body := src[lh : lh+cSize]

	if litType == litCompressed {
		t, used, err := readHuffTable(body)
		if err != nil {
			return nil, 0, err
		}
		if used > len(body) {
			return nil, 0, trunc("Huffman table runs past the literals section")
		}
		d.huf = t
		body = body[used:]
	} else if d.huf == nil {
		// Treeless literals reuse the table from an earlier block in the same
		// frame. Without one the block is undecodable, which in practice means
		// the stream was cut apart or needs a dictionary.
		return nil, 0, errf("literals section reuses a Huffman table, but none has been sent in this frame")
	}

	if litSize == 0 {
		return nil, lh + cSize, nil
	}
	if len(body) == 0 {
		return nil, 0, trunc("literals section has a table but no bitstream")
	}

	buf := d.litBuffer(litSize)
	if err := d.huf.decompress(buf, body, four); err != nil {
		return nil, 0, err
	}
	return buf, lh + cSize, nil
}

// decodeCompressedBlock handles one bt_compressed block.
func (d *frameDecoder) decodeCompressedBlock(src []byte, blockMax int) error {
	if len(src) < minCompressedBlock {
		return errf("compressed block of %d bytes is too small to hold a header", len(src))
	}
	literals, used, err := d.decodeLiterals(src)
	if err != nil {
		return err
	}
	if used > len(src) {
		return trunc("literals section runs past the end of the block")
	}
	before := len(d.out)
	if err := d.decodeSequences(src[used:], literals); err != nil {
		return err
	}
	if produced := len(d.out) - before; produced > blockMax {
		return errf("block expanded to %d bytes, above this frame's %d byte limit", produced, blockMax)
	}
	return nil
}
