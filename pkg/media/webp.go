package media

import (
	"encoding/binary"
)

// ─── WEBP ─────────────────────────────────────────────────────────────────
//
// RIFF container: "RIFF" + size(4 LE) + "WEBP", then a sequence of
// [fourCC(4)][size(4 LE)][payload(size, padded to even)] sub-chunks.
// VP8  = lossy bitstream (dimensions in a 6-byte frame tag)
// VP8L = lossless bitstream (dimensions in the first 5 payload bytes)
// VP8X = extended format: 24-bit width-1/height-1, plus optional EXIF/XMP/
//        ICCP/ANIM sub-chunks alongside it in the same RIFF chunk list.

type webpInfo struct {
	Width, Height int
	HasDims       bool
	Format        string // "VP8", "VP8L", "VP8X"
	EXIFChunk     []byte
	XMPChunk      []byte
}

// parseWEBPInfo walks the RIFF sub-chunk list. Best-effort and defensive:
// any dimension read that looks suspect simply leaves HasDims false rather
// than guessing, since VP8's bitstream frame tag has sign/scale bits this
// function deliberately does not fully decode (pixel-accurate dimensions
// aren't the point here - the presence/detection of the file and any
// embedded EXIF/XMP is).
func parseWEBPInfo(data []byte) (info webpInfo, ok bool) {
	if len(data) < 12 || string(data[0:4]) != "RIFF" || string(data[8:12]) != "WEBP" {
		return webpInfo{}, false
	}

	pos := 12
	for pos+8 <= len(data) {
		fourCC := string(data[pos : pos+4])
		size := int(binary.LittleEndian.Uint32(data[pos+4 : pos+8]))
		payloadStart := pos + 8
		if size < 0 || payloadStart+size > len(data) {
			break
		}
		payload := data[payloadStart : payloadStart+size]

		switch fourCC {
		case "VP8 ":
			if w, h, ok := decodeVP8Dims(payload); ok {
				info.Width, info.Height, info.HasDims, info.Format = w, h, true, "VP8"
			}
		case "VP8L":
			if w, h, ok := decodeVP8LDims(payload); ok {
				info.Width, info.Height, info.HasDims, info.Format = w, h, true, "VP8L"
			}
		case "VP8X":
			if w, h, ok := decodeVP8XDims(payload); ok {
				info.Width, info.Height, info.HasDims, info.Format = w, h, true, "VP8X"
			}
		case "EXIF":
			info.EXIFChunk = append([]byte(nil), payload...)
		case "XMP ":
			info.XMPChunk = append([]byte(nil), payload...)
		}

		// Chunks are padded to an even byte boundary.
		advance := size
		if advance%2 == 1 {
			advance++
		}
		pos = payloadStart + advance
	}

	return info, info.Format != "" || info.EXIFChunk != nil || info.XMPChunk != nil
}

// decodeVP8Dims reads the lossy VP8 bitstream's 6-byte uncompressed frame
// tag: 3 bytes of frame-tag bits, then a 3-byte start code (0x9d 0x01 0x2a),
// then 2x16-bit little-endian width/height, each with the top 2 bits as a
// scale factor this function ignores (returns the base 14-bit dimension).
func decodeVP8Dims(payload []byte) (width, height int, ok bool) {
	if len(payload) < 10 {
		return 0, 0, false
	}
	if payload[3] != 0x9d || payload[4] != 0x01 || payload[5] != 0x2a {
		return 0, 0, false
	}
	w := binary.LittleEndian.Uint16(payload[6:8])
	h := binary.LittleEndian.Uint16(payload[8:10])
	width = int(w & 0x3FFF)
	height = int(h & 0x3FFF)
	if width == 0 || height == 0 {
		return 0, 0, false
	}
	return width, height, true
}

// decodeVP8LDims reads the lossless VP8L bitstream: 1 signature byte
// (0x2F), then 14-bit width-1 and 14-bit height-1 packed across the next 4
// bytes little-endian.
func decodeVP8LDims(payload []byte) (width, height int, ok bool) {
	if len(payload) < 5 || payload[0] != 0x2F {
		return 0, 0, false
	}
	bits := uint32(payload[1]) | uint32(payload[2])<<8 | uint32(payload[3])<<16 | uint32(payload[4])<<24
	width = int(bits&0x3FFF) + 1
	height = int((bits>>14)&0x3FFF) + 1
	return width, height, true
}

// decodeVP8XDims reads the extended-format VP8X chunk: 1 flags byte, 3
// reserved bytes, then 24-bit width-1 and 24-bit height-1, little-endian.
func decodeVP8XDims(payload []byte) (width, height int, ok bool) {
	if len(payload) < 10 {
		return 0, 0, false
	}
	w := uint32(payload[4]) | uint32(payload[5])<<8 | uint32(payload[6])<<16
	h := uint32(payload[7]) | uint32(payload[8])<<8 | uint32(payload[9])<<16
	width = int(w) + 1
	height = int(h) + 1
	return width, height, true
}
