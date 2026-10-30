package zstd

// ═══════════════════════════════════════════════════════════════════════════
// Frames
// ═══════════════════════════════════════════════════════════════════════════
//
// A frame is a header, a run of blocks, and an optional checksum. The header
// is deliberately tiny, which means a handful of bytes can claim a two gigabyte
// window and a sixteen exabyte content size. Nothing here trusts those
// numbers: they size hints only, and the real ceiling is the caller's output
// limit. That matters because this package's whole job is reading files that
// are already suspected of being hostile.
//
// Ports ZSTD_getFrameHeader_advanced and ZSTD_decompressFrame.

// Header describes a frame without decoding its contents.
type Header struct {
	// Offset is where the frame magic starts in the buffer that was parsed.
	Offset int
	// HeaderSize is the number of bytes before the first block.
	HeaderSize int
	// WindowSize is how far back matches may reach. Zero when a single-segment
	// frame declares no content size.
	WindowSize uint64
	// ContentSize is the decompressed length the frame claims, valid only when
	// ContentSizeKnown is set. A streaming compressor usually omits it.
	ContentSize      uint64
	ContentSizeKnown bool
	// DictID names the dictionary the frame was compressed against. This
	// decoder has no dictionary support, so a non-zero value is fatal.
	DictID uint32
	// HasChecksum reports whether a 32-bit content checksum follows the last
	// block.
	HasChecksum bool
	// SingleSegment means the whole frame is one block-sized window, so no
	// window descriptor byte is present.
	SingleSegment bool
	// BlockSizeMax is the largest a single block may expand to in this frame.
	BlockSizeMax int
	// Skippable marks one of the four reserved magic numbers applications use
	// to embed their own metadata inside a zstd stream. The payload is skipped
	// wholesale.
	Skippable     bool
	SkippableSize uint32
}

// TotalSize is the whole frame length for a skippable frame. It is zero for a
// real frame, whose length is only known once the blocks have been walked.
func (h Header) TotalSize() uint64 {
	if !h.Skippable {
		return 0
	}
	return 8 + uint64(h.SkippableSize)
}

func readHeaderAt(src []byte, off int) (Header, error) {
	h := Header{Offset: off}
	if off < 0 || off+4 > len(src) {
		return h, trunc("frame magic is truncated")
	}
	magic := uint32(src[off]) | uint32(src[off+1])<<8 | uint32(src[off+2])<<16 | uint32(src[off+3])<<24

	if magic&skippableMask == skippableLow {
		if off+8 > len(src) {
			return h, trunc("skippable frame header is truncated")
		}
		h.Skippable = true
		h.SkippableSize = uint32(src[off+4]) | uint32(src[off+5])<<8 |
			uint32(src[off+6])<<16 | uint32(src[off+7])<<24
		h.HeaderSize = 8
		return h, nil
	}
	if magic != FrameMagic {
		return h, ErrMagic
	}
	if off+frameHeaderMin > len(src) {
		return h, trunc("frame header descriptor is missing")
	}

	// Frame_Header_Descriptor:
	//   7-6 content size flag   5 single segment   4 unused
	//   3   reserved            2 checksum        1-0 dictionary id flag
	desc := src[off+4]
	if desc&0x08 != 0 {
		return h, errf("frame header has its reserved bit set")
	}
	h.HasChecksum = desc&0x04 != 0
	h.SingleSegment = desc&0x20 != 0
	dictCode := desc & 0x03
	fcsCode := desc >> 6
	p := off + 5

	if !h.SingleSegment {
		if p >= len(src) {
			return h, trunc("window descriptor is missing")
		}
		wl := src[p]
		p++
		// Window size is a power of two plus up to seven eighths of itself,
		// which is how zstd expresses sizes like 1.5 MiB in one byte.
		windowLog := int(wl>>3) + 10
		if windowLog > MaxWindowLog {
			return h, errf("frame asks for a 2^%d byte window, above the %d bit maximum", windowLog, MaxWindowLog)
		}
		w := uint64(1) << uint(windowLog)
		w += (w >> 3) * uint64(wl&7)
		h.WindowSize = w
	}

	switch dictCode {
	case 1:
		if p+1 > len(src) {
			return h, trunc("dictionary id is truncated")
		}
		h.DictID = uint32(src[p])
		p++
	case 2:
		if p+2 > len(src) {
			return h, trunc("dictionary id is truncated")
		}
		h.DictID = uint32(src[p]) | uint32(src[p+1])<<8
		p += 2
	case 3:
		if p+4 > len(src) {
			return h, trunc("dictionary id is truncated")
		}
		h.DictID = uint32(src[p]) | uint32(src[p+1])<<8 |
			uint32(src[p+2])<<16 | uint32(src[p+3])<<24
		p += 4
	}

	switch fcsCode {
	case 0:
		// One byte, but only for a single-segment frame. Otherwise the size is
		// genuinely unknown, which is what a stream looks like.
		if h.SingleSegment {
			if p+1 > len(src) {
				return h, trunc("content size is truncated")
			}
			h.ContentSize = uint64(src[p])
			h.ContentSizeKnown = true
			p++
		}
	case 1:
		if p+2 > len(src) {
			return h, trunc("content size is truncated")
		}
		// The two-byte form is biased by 256, since anything smaller would
		// have used the one-byte form.
		h.ContentSize = uint64(src[p]) | uint64(src[p+1])<<8
		h.ContentSize += 256
		h.ContentSizeKnown = true
		p += 2
	case 2:
		if p+4 > len(src) {
			return h, trunc("content size is truncated")
		}
		h.ContentSize = uint64(src[p]) | uint64(src[p+1])<<8 |
			uint64(src[p+2])<<16 | uint64(src[p+3])<<24
		h.ContentSizeKnown = true
		p += 4
	default:
		if p+8 > len(src) {
			return h, trunc("content size is truncated")
		}
		var v uint64
		for i := 0; i < 8; i++ {
			v |= uint64(src[p+i]) << (8 * uint(i))
		}
		h.ContentSize = v
		h.ContentSizeKnown = true
		p += 8
	}

	if h.SingleSegment {
		h.WindowSize = h.ContentSize
	}
	h.HeaderSize = p - off
	h.BlockSizeMax = BlockSizeMax
	if h.WindowSize > 0 && h.WindowSize < uint64(BlockSizeMax) {
		h.BlockSizeMax = int(h.WindowSize)
	}
	return h, nil
}

// frameDecoder carries the state a frame accumulates: the Huffman and FSE
// tables blocks may reuse, the three repeat offsets, and the output itself.
type frameDecoder struct {
	huf *huffTable
	ll  *seqTable
	of  *seqTable
	ml  *seqTable
	rep [3]uint32

	out        []byte
	frameStart int
	maxOut     int
	lit        []byte
}

// resetFrame clears everything that must not carry across a frame boundary.
// Tables and repeat offsets are per frame; concatenated frames are
// independent, and a match may not reach back into the previous one.
func (d *frameDecoder) resetFrame() {
	d.huf = nil
	d.ll = nil
	d.of = nil
	d.ml = nil
	d.rep = [3]uint32{1, 4, 8}
	d.frameStart = len(d.out)
}

func (d *frameDecoder) litBuffer(n int) []byte {
	if cap(d.lit) < n {
		d.lit = make([]byte, n, n+n/2+64)
	}
	return d.lit[:n]
}

func (d *frameDecoder) checkLimit() error {
	if d.maxOut > 0 && len(d.out) > d.maxOut {
		return tooLarge("decoded %d bytes, past the %d byte limit", len(d.out), d.maxOut)
	}
	return nil
}

// decodeFrame decodes one frame starting at off and returns the offset just
// past it. Skippable frames are stepped over without producing output.
func (d *frameDecoder) decodeFrame(src []byte, off int) (int, error) {
	h, err := readHeaderAt(src, off)
	if err != nil {
		return off, err
	}

	if h.Skippable {
		// Computed in uint64: a skippable frame may claim four gigabytes, which
		// overflows a 32-bit int.
		end := uint64(off) + h.TotalSize()
		if end > uint64(len(src)) {
			return off, trunc("skippable frame of %d bytes runs past the input", h.SkippableSize)
		}
		return int(end), nil
	}
	if h.DictID != 0 {
		return off, dictErr(h.DictID)
	}

	d.resetFrame()
	blockMax := h.BlockSizeMax
	if blockMax <= 0 || blockMax > BlockSizeMax {
		blockMax = BlockSizeMax
	}

	p := off + h.HeaderSize
	for {
		if p+blockHeaderSize > len(src) {
			return p, trunc("block header is truncated")
		}
		// Block_Header: bit 0 last, bits 1-2 type, bits 3-23 size.
		bh := uint32(src[p]) | uint32(src[p+1])<<8 | uint32(src[p+2])<<16
		p += blockHeaderSize
		last := bh&1 != 0
		btype := (bh >> 1) & 3
		bsize := int(bh >> 3)

		switch btype {
		case 0: // raw: the bytes are the content
			if bsize > blockMax {
				return p, errf("raw block of %d bytes exceeds this frame's %d byte limit", bsize, blockMax)
			}
			if p+bsize > len(src) {
				return p, trunc("raw block runs past the input")
			}
			d.out = append(d.out, src[p:p+bsize]...)
			p += bsize
			if err := d.checkLimit(); err != nil {
				return p, err
			}

		case 1: // rle: one byte repeated bsize times
			if bsize > blockMax {
				return p, errf("run-length block of %d bytes exceeds this frame's %d byte limit", bsize, blockMax)
			}
			if p+1 > len(src) {
				return p, trunc("run-length block byte is missing")
			}
			base := len(d.out)
			d.out = extend(d.out, bsize)
			fill := src[p]
			for i := base; i < len(d.out); i++ {
				d.out[i] = fill
			}
			p++
			if err := d.checkLimit(); err != nil {
				return p, err
			}

		case 2: // compressed
			if p+bsize > len(src) {
				return p, trunc("compressed block runs past the input")
			}
			if err := d.decodeCompressedBlock(src[p:p+bsize], blockMax); err != nil {
				return p, err
			}
			p += bsize

		default:
			return p, errf("block uses the reserved type, so this is not a zstd stream")
		}

		if last {
			break
		}
	}

	if h.HasChecksum {
		if p+4 > len(src) {
			return p, trunc("frame checksum is truncated")
		}
		want := uint32(src[p]) | uint32(src[p+1])<<8 |
			uint32(src[p+2])<<16 | uint32(src[p+3])<<24
		p += 4
		// The trailer holds the low 32 bits of the XXH64 of this frame's
		// content only, not of the whole stream.
		got := uint32(xxh64(d.out[d.frameStart:]) & 0xFFFFFFFF)
		if want != got {
			return p, checksumErr(got, want)
		}
	}

	if h.ContentSizeKnown {
		produced := uint64(len(d.out) - d.frameStart)
		if produced != h.ContentSize {
			return p, errf("frame declared %d bytes of content but produced %d", h.ContentSize, produced)
		}
	}
	return p, nil
}
