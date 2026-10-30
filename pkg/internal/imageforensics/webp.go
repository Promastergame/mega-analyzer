package imageforensics

import (
	"bytes"
	"encoding/binary"
)

// ═══════════════════════════════════════════════════════════════════════════════
// WEBP PARSER
//
// WEBP is a RIFF container. The total payload length is encoded in the file
// header; anything beyond that offset is suspicious trailing data, and a
// declared size larger than the actual file means the image is truncated or
// otherwise malformed.
// ═══════════════════════════════════════════════════════════════════════════════

// WEBPInfo is the parsed WEBP structure.
type WEBPInfo struct {
	Valid        bool
	TotalSize    int // declared by RIFF header (RIFF length + 8)
	Truncated    bool
	TrailingData []byte
	HasVP8       bool
	HasVP8L      bool
	HasVP8X      bool
}

// ParseWEBP performs a lightweight WEBP scan. Panic-safe.
func ParseWEBP(data []byte) (info WEBPInfo) {
	defer func() { notePanic("imageforensics.webp", recover()) }()

	if len(data) < 12 {
		return WEBPInfo{}
	}
	if !bytes.Equal(data[:4], []byte("RIFF")) || !bytes.Equal(data[8:12], []byte("WEBP")) {
		return WEBPInfo{}
	}
	info.Valid = true

	declaredSize := int(binary.LittleEndian.Uint32(data[4:8])) + 8 // includes RIFF header
	info.TotalSize = declaredSize
	switch {
	case declaredSize < len(data):
		info.TrailingData = data[declaredSize:]
	case declaredSize > len(data):
		info.Truncated = true
	}

	// Detect chunk types in the first 4 KB — sufficient for our purposes.
	limit := len(data)
	if limit > 4096 {
		limit = 4096
	}
	if bytes.Contains(data[:limit], []byte("VP8 ")) {
		info.HasVP8 = true
	}
	if bytes.Contains(data[:limit], []byte("VP8L")) {
		info.HasVP8L = true
	}
	if bytes.Contains(data[:limit], []byte("VP8X")) {
		info.HasVP8X = true
	}
	return info
}
