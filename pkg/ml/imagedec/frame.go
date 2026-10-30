package imagedec

import (
	"encoding/binary"
	"math"
)

// ═══════════════════════════════════════════════════════════════════════════════
// COMPRESSION FRAME HEADERS
//
// Header parsing only - nothing here decompresses. The Decodable flag says
// whether anything in this repository can inflate the format. The Go standard
// library ships gzip, zlib, flate, bzip2 and lzw; zstd is not among them, so
// pkg/ml/zstd supplies it, which matters because zstd is the format game
// assets actually use. lz4 and xz still have no decoder here and report their
// header only.
//
// Reading the header is useful even when a decoder exists: it reports the
// declared content size before a single byte is inflated, which is how a
// caller decides whether a payload is worth expanding at all.
//
// This generalises what a format-specific reader does by hand. A .sctx texture
// is a small FlatBuffers head followed by one zstd frame; scanning for the
// frame instead of hardcoding its offset works on that file, on the next
// version of that file, and on every other wrapper built the same way.
// ═══════════════════════════════════════════════════════════════════════════════

// SizeUnknown marks a frame whose format does not record the decompressed size.
const SizeUnknown int64 = -1

// Frame is one embedded compression stream.
type Frame struct {
	Format string
	// Offset is where the frame magic begins in the enclosing buffer.
	Offset int
	// DeclaredSize is the decompressed length the frame header claims, or
	// SizeUnknown when the format does not carry one.
	DeclaredSize int64
	// HeaderLen is the number of bytes consumed by the frame header itself.
	HeaderLen int
	// Decodable is true when the Go standard library can inflate this format
	// without any third-party dependency.
	Decodable bool
	Note      string
}

// zstd frame header, RFC 8878 section 3.1.1.1.
//
//	Frame_Header_Descriptor bit layout:
//	  7-6 Frame_Content_Size_flag
//	  5   Single_Segment_flag
//	  4   unused, must be zero
//	  3   reserved, must be zero
//	  2   Content_Checksum_flag
//	  1-0 Dictionary_ID_flag
func parseZstdFrame(data []byte, off int) (Frame, bool) {
	f := Frame{
		Format:       "zstd",
		Offset:       off,
		DeclaredSize: SizeUnknown,
		Decodable:    true,
		Note:         "pkg/ml/zstd can inflate this",
	}
	if off < 0 || off+5 > len(data) {
		return f, false
	}

	desc := data[off+4]
	if desc&0x08 != 0 {
		// Reserved bit set: this is not a zstd frame, it is a coincidence.
		return f, false
	}
	fcsFlag := desc >> 6
	singleSegment := desc&0x20 != 0
	didFlag := desc & 0x03

	p := off + 5
	if !singleSegment {
		p++ // Window_Descriptor
	}
	switch didFlag {
	case 1:
		p++
	case 2:
		p += 2
	case 3:
		p += 4
	}

	fcsSize := 0
	switch fcsFlag {
	case 0:
		if singleSegment {
			fcsSize = 1
		}
	case 1:
		fcsSize = 2
	case 2:
		fcsSize = 4
	case 3:
		fcsSize = 8
	}

	if fcsSize > 0 {
		if p+fcsSize > len(data) {
			return f, false
		}
		var v uint64
		for i := 0; i < fcsSize; i++ {
			v |= uint64(data[p+i]) << (8 * uint(i))
		}
		// A 2-byte Frame_Content_Size is stored biased by 256.
		if fcsSize == 2 {
			v += 256
		}
		if v > uint64(math.MaxInt64) {
			v = uint64(math.MaxInt64)
		}
		f.DeclaredSize = int64(v)
		p += fcsSize
	}

	f.HeaderLen = p - off
	return f, true
}

// gzip records the uncompressed size modulo 2^32 in the final four bytes. That
// is only trustworthy when the frame runs to the end of the buffer, so the
// caller passes the slice it believes the frame occupies.
func parseGzipFrame(data []byte, off int) (Frame, bool) {
	f := Frame{
		Format:       "gzip",
		Offset:       off,
		DeclaredSize: SizeUnknown,
		HeaderLen:    10,
		Decodable:    true,
		Note:         "compress/gzip can inflate this",
	}
	if off < 0 || off+10 > len(data) {
		return f, false
	}
	// Compression method 8 (deflate) is the only one ever deployed.
	if data[off+2] != 8 {
		f.Note = "unexpected gzip compression method"
		return f, false
	}
	if off == 0 && len(data) >= 8 {
		isize := binary.LittleEndian.Uint32(data[len(data)-4:])
		f.DeclaredSize = int64(isize)
		f.Note = "compress/gzip can inflate this; size is ISIZE, modulo 2^32"
	}
	return f, true
}

// zlib headers are two bytes: CMF then FLG, valid when CM is 8 and the pair is
// a multiple of 31. Checking the modulus rejects most of the false positives a
// bare 0x78 byte would produce.
func parseZlibFrame(data []byte, off int) (Frame, bool) {
	f := Frame{
		Format:       "zlib",
		Offset:       off,
		DeclaredSize: SizeUnknown,
		HeaderLen:    2,
		Decodable:    true,
		Note:         "compress/zlib can inflate this",
	}
	if off < 0 || off+2 > len(data) {
		return f, false
	}
	cmf, flg := data[off], data[off+1]
	if cmf&0x0F != 8 {
		return f, false
	}
	if (uint16(cmf)<<8|uint16(flg))%31 != 0 {
		return f, false
	}
	if flg&0x20 != 0 {
		f.HeaderLen = 6 // FDICT adds a 4-byte dictionary id
		f.Note = "compress/zlib can inflate this, but it needs a preset dictionary"
	}
	return f, true
}

// parseFrameAt dispatches on the signature name.
func parseFrameAt(name string, data []byte, off int) (Frame, bool) {
	switch name {
	case "zstd":
		return parseZstdFrame(data, off)
	case "gzip":
		return parseGzipFrame(data, off)
	case "zlib-default", "zlib-best", "zlib-none":
		return parseZlibFrame(data, off)
	case "bzip2":
		return Frame{Format: "bzip2", Offset: off, DeclaredSize: SizeUnknown,
			HeaderLen: 4, Decodable: true, Note: "compress/bzip2 can inflate this"}, true
	case "lz4":
		return Frame{Format: "lz4", Offset: off, DeclaredSize: SizeUnknown,
			HeaderLen: 7, Decodable: false,
			Note: "no lz4 decoder in the standard library; header only"}, true
	case "xz":
		return Frame{Format: "xz", Offset: off, DeclaredSize: SizeUnknown,
			HeaderLen: 12, Decodable: false,
			Note: "no xz decoder in the standard library; header only"}, true
	default:
		return Frame{}, false
	}
}
