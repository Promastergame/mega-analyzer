package media

import (
	"encoding/binary"
	"fmt"
)

// PatchResult holds the outcome of a media patch operation
type PatchResult struct {
	Success bool
	Message string
	Data    []byte
}

// ScrubMetadata removes common metadata sections from the file.
// JPEG: removes APP0 (JFIF), APP1 (EXIF), APP2-APP13 non-structural markers.
// PNG: removes entire tEXt/zTXt/iTXt chunks (with correct CRC handling).
func ScrubMetadata(data []byte, format MediaType) PatchResult {
	if format == TypeUnknown || len(data) == 0 {
		return PatchResult{Success: false, Message: "Unsupported or empty file", Data: data}
	}

	switch format {
	case TypeJPEG:
		return scrubJPEG(data)
	case TypePNG:
		return scrubPNG(data)
	default:
		return PatchResult{Success: true, Message: "Format not supported for scrubbing", Data: data}
	}
}

// scrubJPEG removes non-structural APPn segments (EXIF, JFIF, ICC, comments)
// while preserving DQT, DHT, SOF, SOS, DRI and other structural markers.
func scrubJPEG(data []byte) PatchResult {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return PatchResult{Success: false, Message: "Not a valid JPEG", Data: data}
	}

	var out []byte
	out = append(out, data[0:2]...) // SOI

	pos := 2
	scrubCount := 0

	// Structural markers that must NOT be removed
	isStructural := func(marker byte) bool {
		switch {
		case marker == 0xD8: // SOI
			return true
		case marker == 0xD9: // EOI
			return true
		case marker == 0xDA: // SOS
			return true
		case marker >= 0xC0 && marker <= 0xCF: // SOF0-SOF15 (except C4=DHT, C8=JPG, CC=DAC)
			return marker != 0xC4 && marker != 0xC8 && marker != 0xCC
		case marker == 0xC4: // DHT
			return true
		case marker == 0xCC: // DAC
			return true
		case marker == 0xDB: // DQT
			return true
		case marker == 0xDD: // DRI
			return true
		case marker >= 0xD0 && marker <= 0xD7: // RST0-RST7
			return true
		case marker == 0x01: // TEM
			return true
		}
		return false
	}

	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			out = append(out, data[pos])
			pos++
			continue
		}
		marker := data[pos+1]

		// Standalone markers (no length field)
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD9) {
			if marker == 0xD9 { // EOI — copy rest and stop
				out = append(out, data[pos:]...)
				return PatchResult{Success: true, Message: fmt.Sprintf("Scrubbed %d metadata segments", scrubCount), Data: out}
			}
			out = append(out, data[pos], data[pos+1])
			pos += 2
			continue
		}

		if pos+4 > len(data) {
			break
		}
		segLen := int(data[pos+2])<<8 | int(data[pos+3])
		if segLen < 2 || pos+2+segLen > len(data) {
			break
		}

		if isStructural(marker) {
			// Keep structural markers
			out = append(out, data[pos:pos+2+segLen]...)
		} else {
			// Remove metadata marker (APP0/APP1/APP2/.../APP13, COM, etc.)
			scrubCount++
		}
		pos += 2 + segLen
	}

	// If we reached here without finding EOI, copy remaining bytes
	if pos < len(data) {
		out = append(out, data[pos:]...)
	}

	return PatchResult{Success: true, Message: fmt.Sprintf("Scrubbed %d metadata segments", scrubCount), Data: out}
}

// scrubPNG removes entire tEXt/zTXt/iTXt chunks from the PNG, properly
// rebuilding the byte stream without corrupt CRC values.
func scrubPNG(data []byte) PatchResult {
	if len(data) < 8 {
		return PatchResult{Success: false, Message: "PNG too short", Data: data}
	}

	chunksToScrub := map[string]bool{"tEXt": true, "zTXt": true, "iTXt": true}
	var out []byte
	out = append(out, data[0:8]...) // PNG signature

	pos := 8
	scrubCount := 0

	for pos+8 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		typ := string(data[pos+4 : pos+8])
		dataStart := pos + 8
		if length < 0 || dataStart+length+4 > len(data) {
			break
		}
		chunkEnd := dataStart + length + 4

		if chunksToScrub[typ] {
			scrubCount++
			pos = chunkEnd
			continue
		}

		// Keep this chunk as-is
		out = append(out, data[pos:chunkEnd]...)
		pos = chunkEnd
	}

	// Append any remaining bytes after the last valid chunk
	if pos < len(data) {
		out = append(out, data[pos:]...)
	}

	if scrubCount > 0 {
		return PatchResult{Success: true, Message: fmt.Sprintf("Scrubbed %d metadata chunks", scrubCount), Data: out}
	}
	return PatchResult{Success: true, Message: "No metadata chunks found to scrub", Data: out}
}

// NOTE: the offensive payload-injection helpers (InjectPayload / HideStego)
// have been moved OUT of the shipped forensic API. They fabricate malicious
// files and are not part of legitimate analysis, so they now live only in
// the test-only file patcher_inject_test.go, where they are used to generate
// fixtures for regression tests. Do not re-add them to the production API.
