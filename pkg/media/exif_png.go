package media

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// PNG header (IHDR, CgBI). Chunk walk lives in pngchunks.go.
//
// Split from exif.go: exact code move, no logic changes.

// --- PNG --------------------------------------------------------------------

var pngSignature = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}

// pngHeader is IHDR. Bit depth, color type and interlace were being read past
// and thrown away, and they are forensic fields: a screenshot is 8-bit RGB or
// RGBA non-interlaced, and Adam7 interlacing is a strong "web asset" signal.
type pngHeader struct {
	Width, Height int
	BitDepth      int
	ColorType     int
	Interlace     int
	HasDims       bool
	AppleCgBI     bool // CgBI chunk before IHDR: this is not standard PNG
}

func parsePNGHeader(data []byte, w *warnBag) pngHeader {
	var h pngHeader
	if len(data) < 8 || !bytes.Equal(data[0:8], pngSignature) {
		w.add("png.header", "bad_signature", 0, "")
		return h
	}
	// iOS ships "CgBI" PNGs: a private chunk before IHDR, premultiplied BGRA
	// and raw deflate. A parser that ignores this reports a normal PNG.
	if len(data) >= 16 && string(data[12:16]) == "CgBI" {
		h.AppleCgBI = true
		w.add("png.header", "apple_cgbi", 12, "non-standard iOS PNG")
	}
	off := 8
	for i := 0; i < 4; i++ { // IHDR must be first, but tolerate CgBI
		lenB, ok := sliceOf(data, off, 8)
		if !ok {
			w.add("png.header", "truncated", int64(off), "")
			return h
		}
		clen := int(binary.BigEndian.Uint32(lenB[0:4]))
		ctyp := string(lenB[4:8])
		body, ok := sliceOf(data, off+8, clen)
		if !ok {
			w.add("png.header", "chunk_past_eof", int64(off), ctyp)
			return h
		}
		if ctyp == "IHDR" {
			if clen != 13 {
				w.add("png.header", "bad_ihdr_length", int64(off), fmt.Sprintf("%d", clen))
				return h
			}
			w32 := binary.BigEndian.Uint32(body[0:4])
			h32 := binary.BigEndian.Uint32(body[4:8])
			// The PNG spec caps both dimensions at 2^31-1 and forbids zero.
			if w32 == 0 || h32 == 0 || w32 > 0x7FFFFFFF || h32 > 0x7FFFFFFF {
				w.add("png.header", "implausible_dimensions", int64(off),
					fmt.Sprintf("%dx%d", w32, h32))
				return h
			}
			h.Width, h.Height = int(w32), int(h32)
			h.BitDepth = int(body[8])
			h.ColorType = int(body[9])
			h.Interlace = int(body[12])
			h.HasDims = true
			return h
		}
		off += 8 + clen + 4
	}
	w.add("png.header", "ihdr_not_found", 8, "")
	return h
}

// findPNGDimensions keeps the old signature. Unlike before it validates the
// PNG signature, the IHDR length and the dimension range.
func findPNGDimensions(data []byte) (width, height int, ok bool) {
	h := parsePNGHeader(data, nil)
	return h.Width, h.Height, h.HasDims
}

// findPNGExifTIFF was dead code: PNG goes through walkPNGChunks, which already
// surfaces the eXIf chunk. Deleted rather than left as a second, divergent
// implementation of the same walk.

