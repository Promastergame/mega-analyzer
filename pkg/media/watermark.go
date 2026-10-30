package media

// WatermarkSignal describes a detected digital watermark.
type WatermarkSignal struct {
	Type       string  `json:"type"` // "digimarc", "visible_corner", "frequency_domain"
	Confidence float64 `json:"confidence"`
	Offset     int     `json:"offset"`   // byte offset in file
	Evidence   string  `json:"evidence"` // human-readable description
}

// DetectWatermarks runs all applicable watermark detectors for the given
// format and returns any signals found.
func DetectWatermarks(data []byte, format MediaType) []WatermarkSignal {
	if len(data) == 0 {
		return nil
	}

	var signals []WatermarkSignal

	switch format {
	case TypeJPEG:
		signals = append(signals, detectDigimarc(data)...)
	}

	return signals
}

// detectDigimarc checks for the Digimarc watermark signature in JPEG
// APP segments. Digimarc embeds a spread-spectrum signal that manifests
// as specific patterns in certain APP marker payloads.
func detectDigimarc(data []byte) []WatermarkSignal {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil
	}

	var signals []WatermarkSignal
	pos := 2

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

		seg := data[pos+4 : pos+2+segLen]

		// Digimarc typically uses APP1 (0xE1) or APP2 (0xE2)
		// with specific prefix patterns
		if marker == 0xE1 || marker == 0xE2 {
			if isDigimarcSignature(seg) {
				signals = append(signals, WatermarkSignal{
					Type:       "digimarc",
					Confidence: 0.7,
					Offset:     pos,
					Evidence:   "Digimarc watermark signature detected in APP segment",
				})
			}
		}

		pos = pos + 2 + segLen
	}

	return signals
}

// isDigimarcSignature checks for known Digimarc watermark patterns.
// The exact signature is proprietary, but Digimarc watermarks are known
// to produce specific byte patterns in their APP segments.
func isDigimarcSignature(seg []byte) bool {
	if len(seg) < 16 {
		return false
	}

	// Heuristic: Digimarc segments often have a specific entropy profile
	// different from typical EXIF/XMP data. The first bytes are not a
	// standard namespace prefix.
	hasStandardPrefix := false
	knownPrefixes := []string{
		"Exif\x00\x00",
		"http://ns.adobe.com",
		"ICC_PROFILE\x00",
		"JFIF\x00",
	}
	for _, p := range knownPrefixes {
		if len(seg) >= len(p) && string(seg[:len(p)]) == p {
			hasStandardPrefix = true
			break
		}
	}

	if hasStandardPrefix {
		return false
	}

	// Check for high-entropy, non-zero content that suggests
	// spread-spectrum watermark data
	var nonZero, highByte int
	limit := len(seg)
	if limit > 256 {
		limit = 256
	}
	for i := 0; i < limit; i++ {
		if seg[i] != 0 {
			nonZero++
		}
		if seg[i] > 0x80 {
			highByte++
		}
	}

	// Digimarc data: high proportion of non-zero bytes, distributed
	// entropy — not a regular text/XML pattern
	ratio := float64(nonZero) / float64(limit)
	highRatio := float64(highByte) / float64(limit)

	return ratio > 0.7 && highRatio > 0.3 && highRatio < 0.7
}
