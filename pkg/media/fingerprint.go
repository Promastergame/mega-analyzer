package media

import (
	"fmt"
	"hash/crc32"
)

// EncoderFingerprint identifies the tool that created a media file based
// on subtle format artifacts (quantization table signatures, marker
// ordering, chunk ordering, etc.).
type EncoderFingerprint struct {
	Encoder    string   `json:"encoder"`    // "Adobe Photoshop 25.5", "GIMP 2.10", etc.
	Confidence float64  `json:"confidence"` // 0.0–1.0
	Evidence   []string `json:"evidence"`   // what led to this identification
}

// FingerprintFile dispatches to format-specific fingerprinting.
func FingerprintFile(data []byte, format MediaType) *EncoderFingerprint {
	if len(data) == 0 {
		return nil
	}
	switch format {
	case TypeJPEG:
		return fingerprintJPEG(data)
	case TypePNG:
		return fingerprintPNG(data)
	default:
		return nil
	}
}

// fingerprintJPEG identifies JPEG encoders by marker ordering and content.
func fingerprintJPEG(data []byte) *EncoderFingerprint {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil
	}

	fp := &EncoderFingerprint{Encoder: "Unknown JPEG encoder", Confidence: 0.3}
	var evidence []string

	// Walk markers to detect ordering patterns
	pos := 2
	markers := make([]byte, 0, 16)
	hasAPP0 := false
	hasAdobe := false
	hasPhotoshop := false
	hasExif := false
	var quantTables [][]byte

	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			break
		}
		marker := data[pos+1]
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD9) {
			pos += 2
			continue
		}
		if marker == 0xDA {
			break
		}
		segLen := int(data[pos+2])<<8 | int(data[pos+3])
		if segLen < 2 || pos+2+segLen > len(data) {
			break
		}
		markers = append(markers, marker)

		seg := data[pos+4 : pos+2+segLen]

		switch marker {
		case 0xE0:
			hasAPP0 = true
			if len(seg) >= 5 && string(seg[0:5]) == "JFIF\x00" {
				evidence = append(evidence, "JFIF APP0 marker present")
			}
		case 0xE1:
			if len(seg) >= 6 && string(seg[0:6]) == "Exif\x00\x00" {
				hasExif = true
				evidence = append(evidence, "EXIF APP1 present")
			}
			if len(seg) >= 28 && string(seg[0:28]) == "http://ns.adobe.com/xmp/1.0/" {
				hasAdobe = true
				evidence = append(evidence, "Adobe XMP namespace in APP1")
			}
		case 0xE2:
			if len(seg) >= 12 && string(seg[0:12]) == "ICC_PROFILE\x00" {
				evidence = append(evidence, "ICC profile in APP2")
			}
		case 0xFE:
			if len(seg) > 0 {
				comment := string(seg)
				if containsAny(comment, "Adobe", "Photoshop") {
					hasPhotoshop = true
				}
				if containsAny(comment, "GIMP") {
					evidence = append(evidence, "GIMP comment marker found")
					fp.Encoder = "GIMP"
					fp.Confidence = 0.8
				}
			}
		case 0xDB:
			// DQT — quantization table
			if len(seg) > 0 {
				quantTables = append(quantTables, append([]byte(nil), seg...))
			}
		}
		pos += 2 + segLen
	}

	// Detection heuristics
	if hasPhotoshop {
		fp.Encoder = "Adobe Photoshop"
		fp.Confidence = 0.7
		evidence = append(evidence, "Adobe Photoshop detected via comment marker")
	} else if hasAdobe && hasAPP0 && len(markers) > 0 && markers[0] == 0xE0 {
		// Photoshop: APP0 first, then APP1 with Adobe XMP
		fp.Encoder = "Adobe Photoshop"
		fp.Confidence = 0.6
		evidence = append(evidence, "APP0-first ordering with Adobe XMP (Photoshop pattern)")
	} else if hasExif && !hasAPP0 {
		// Many non-Adobe tools skip APP0 entirely
		evidence = append(evidence, "No JFIF APP0 — non-Adobe encoder likely")
	}

	// Quantization table analysis
	if len(quantTables) > 0 {
		qHash := hashQuantTables(quantTables)
		if encoder, known := knownQuantTableHashes[qHash]; known {
			fp.Encoder = encoder
			fp.Confidence = 0.85
			evidence = append(evidence, "Quantization table signature matches known encoder")
		}
	}

	fp.Evidence = evidence
	return fp
}

// fingerprintPNG identifies PNG encoders by chunk ordering patterns.
func fingerprintPNG(data []byte) *EncoderFingerprint {
	if len(data) < 8 || string(data[0:8]) != "\x89PNG\r\n\x1a\n" {
		return nil
	}

	fp := &EncoderFingerprint{Encoder: "Unknown PNG encoder", Confidence: 0.3}
	var evidence []string

	// Walk chunks and record ordering
	pos := 8
	var chunkOrder []string
	hasTextBeforeIDAT := false
	hasTextAfterIDAT := false
	idatSeen := false

	for pos+8 <= len(data) {
		length := int(uint32(data[pos])<<24 | uint32(data[pos+1])<<16 | uint32(data[pos+2])<<8 | uint32(data[pos+3]))
		typ := string(data[pos+4 : pos+8])
		dataStart := pos + 8
		if length < 0 || dataStart+length+4 > len(data) {
			break
		}

		chunkOrder = append(chunkOrder, typ)

		if typ == "IDAT" {
			idatSeen = true
		} else if !idatSeen && (typ == "tEXt" || typ == "zTXt" || typ == "iTXt") {
			hasTextBeforeIDAT = true
		} else if idatSeen && (typ == "tEXt" || typ == "zTXt" || typ == "iTXt") {
			hasTextAfterIDAT = true
		}

		pos = dataStart + length + 4
	}

	// GIMP: typically places tEXt/iTXt after IDAT
	// Photoshop: typically places tEXt before IDAT
	// libpng: places iTXt with pHYs before IDAT
	if hasTextAfterIDAT && !hasTextBeforeIDAT {
		fp.Encoder = "GIMP"
		fp.Confidence = 0.5
		evidence = append(evidence, "Text chunks after IDAT (GIMP pattern)")
	} else if hasTextBeforeIDAT && !hasTextAfterIDAT {
		fp.Encoder = "Adobe Photoshop"
		fp.Confidence = 0.4
		evidence = append(evidence, "Text chunks before IDAT (Photoshop pattern)")
	}

	// Check for specific GIMP markers
	for _, c := range chunkOrder {
		if c == "gAMA" {
			evidence = append(evidence, "gAMA chunk present")
		}
	}

	fp.Evidence = evidence
	return fp
}

// hashQuantTables produces a stable identifier for a set of JPEG quantization
// tables using CRC-32 (IEEE). This replaces the previous ad-hoc sum, which
// collided trivially (any permutation of byte values produced the same value).
func hashQuantTables(tables [][]byte) string {
	h := crc32.NewIEEE()
	for _, table := range tables {
		n := len(table)
		if n > 64 {
			n = 64
		}
		h.Write(table[:n])
	}
	return fmt.Sprintf("crc32:%08x", h.Sum32())
}

// hashQuantTablesLegacy is retained only for reference; unused.
func hashQuantTablesLegacy(tables [][]byte) string {
	var hash byte
	for _, t := range tables {
		for i, b := range t {
			if i < 64 { // first 64 bytes = one table
				hash ^= b
				hash = (hash << 1) | (hash >> 7) // rotate
			}
		}
	}
	return string([]byte{hash})
}

// knownQuantTableHashes maps quantization table hashes to known encoders.
var knownQuantTableHashes = map[string]string{}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
