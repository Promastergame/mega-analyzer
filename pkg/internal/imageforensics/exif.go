package imageforensics

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"
)

// ═══════════════════════════════════════════════════════════════════════════════
// EXIF PARSER (lightweight)
//
// Extracts a handful of well-known fields from APP1 / Exif TIFF blocks.
// Returns a string-keyed map for downstream rendering. Never panics.
// ═══════════════════════════════════════════════════════════════════════════════

// Common EXIF tag IDs that we surface.
const (
	tagMake     = 0x010F
	tagModel    = 0x0110
	tagSoftware = 0x0131
	tagDateTime = 0x0132
	tagGPSIFD   = 0x8825
)

// ParseEXIF accepts a raw APP1 segment (or a TIFF block beginning with II/MM)
// and returns a map of recognised tags. Empty map on failure.
func ParseEXIF(data []byte) map[string]string {
	out := make(map[string]string)
	defer func() { notePanic("imageforensics.exif", recover()) }()

	// Strip APP1 "Exif\0\0" prefix when present.
	if len(data) > 6 && bytes.Equal(data[:6], []byte("Exif\x00\x00")) {
		data = data[6:]
	}
	if len(data) < 8 {
		return out
	}

	var bo binary.ByteOrder
	switch {
	case bytes.Equal(data[:2], []byte("II")):
		bo = binary.LittleEndian
	case bytes.Equal(data[:2], []byte("MM")):
		bo = binary.BigEndian
	default:
		return out
	}

	if bo.Uint16(data[2:4]) != 0x002A {
		return out
	}
	ifdOffset := int(bo.Uint32(data[4:8]))
	if ifdOffset < 0 || ifdOffset+2 >= len(data) {
		return out
	}

	count := int(bo.Uint16(data[ifdOffset : ifdOffset+2]))
	entries := ifdOffset + 2
	for i := 0; i < count; i++ {
		off := entries + i*12
		if off+12 > len(data) {
			break
		}
		tag := bo.Uint16(data[off : off+2])
		typ := bo.Uint16(data[off+2 : off+4])
		cnt := int(bo.Uint32(data[off+4 : off+8]))
		// The last 4 bytes are either an offset (for cnt > 4) or the value
		// stored inline (for cnt <= 4 with type ASCII / BYTE).
		valueField := data[off+8 : off+12]
		valOff := bo.Uint32(valueField)

		switch tag {
		case tagMake, tagModel, tagSoftware, tagDateTime:
			if typ == 2 { // ASCII
				val := readEXIFString(data, valueField, int(valOff), cnt)
				if val != "" {
					out[tagName(tag)] = val
				}
			}
		case tagGPSIFD:
			out["GPSIFD"] = "present"
		}
	}
	return out
}

func tagName(tag uint16) string {
	switch tag {
	case tagMake:
		return "Make"
	case tagModel:
		return "Model"
	case tagSoftware:
		return "Software"
	case tagDateTime:
		return "DateTime"
	}
	return ""
}

// readEXIFString returns the trimmed UTF-8 value of an EXIF ASCII field.
// When length <= 4 the value is stored inline in the 4-byte value field
// itself; otherwise it is referenced by offset within the TIFF block.
func readEXIFString(data, valueField []byte, offset, length int) string {
	if length <= 0 {
		return ""
	}

	var raw []byte
	if length <= 4 {
		if length > len(valueField) {
			return ""
		}
		raw = valueField[:length]
	} else {
		if offset < 0 || offset+length > len(data) {
			return ""
		}
		raw = data[offset : offset+length]
	}

	raw = bytes.TrimRight(raw, "\x00")
	if len(raw) == 0 {
		return ""
	}
	if !utf8.Valid(raw) {
		return ""
	}
	return string(raw)
}
