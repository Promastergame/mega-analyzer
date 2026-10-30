package imageforensics

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PNG PARSER
//
// Parses chunks well enough to locate IEND, detect suspicious tEXt blobs,
// validate per-chunk CRCs and expose trailing data after IEND. Never panics
// on malformed input.
// ═══════════════════════════════════════════════════════════════════════════════

var pngMagic = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

// PNGInfo is the parsed structure for a PNG file.
type PNGInfo struct {
	Valid            bool
	Width, Height    int
	IENDOffset       int // start of IEND chunk header within the file
	TrailingData     []byte
	SuspiciousChunks []string
	BadCRC           []string // chunk types whose CRC failed validation
}

// suspiciousTextChunkSize triggers a SuspiciousChunks entry. base64 payloads
// frequently exceed 1 KiB inside tEXt / iTXt / zTXt.
const suspiciousTextChunkSize = 1024

// ParsePNG scans the provided byte slice. The function is panic-safe.
func ParsePNG(data []byte) (info PNGInfo) {
	defer func() {
		notePanic("imageforensics.png", recover()) // never propagate, but record
	}()

	if len(data) < len(pngMagic)+8 || !bytes.Equal(data[:len(pngMagic)], pngMagic) {
		return PNGInfo{}
	}
	info.Valid = true

	pos := len(pngMagic)
	for pos+8 <= len(data) {
		length := binary.BigEndian.Uint32(data[pos : pos+4])
		ctype := string(data[pos+4 : pos+8])

		dataStart := pos + 8
		dataEnd := dataStart + int(length)
		if dataEnd < dataStart || dataEnd+4 > len(data) {
			// Malformed — stop here, IEND offset stays at the malformed chunk
			info.IENDOffset = pos
			return info
		}

		// Validate CRC (covers chunk type + chunk data).
		expected := binary.BigEndian.Uint32(data[dataEnd : dataEnd+4])
		actual := crc32.ChecksumIEEE(data[pos+4 : dataEnd])
		if expected != actual {
			info.BadCRC = append(info.BadCRC, ctype)
		}

		switch ctype {
		case "IHDR":
			if int(length) >= 8 {
				info.Width = int(binary.BigEndian.Uint32(data[dataStart : dataStart+4]))
				info.Height = int(binary.BigEndian.Uint32(data[dataStart+4 : dataStart+8]))
			}
		case "tEXt", "iTXt", "zTXt":
			if int(length) > suspiciousTextChunkSize {
				info.SuspiciousChunks = append(info.SuspiciousChunks, ctype)
			}
		case "IEND":
			info.IENDOffset = dataEnd + 4 // include CRC
			if info.IENDOffset < len(data) {
				info.TrailingData = data[info.IENDOffset:]
			}
			return info
		}

		pos = dataEnd + 4 // skip CRC
	}

	return info
}
