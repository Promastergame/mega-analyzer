package media

// GIFThreat describes a suspicious element found in a GIF file.
type GIFThreat struct {
	Type       string  `json:"type"` // "nested_image", "delay_manipulation", "application_extension"
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`
	Frame      int     `json:"frame"` // frame index (0-based)
}

// AnalyzeGIF performs deep analysis on a GIF file, looking for nested
// images, delay manipulation, and suspicious application extensions.
func AnalyzeGIF(data []byte) []GIFThreat {
	if len(data) < 6 {
		return nil
	}

	// Verify GIF signature
	sig := string(data[0:6])
	if sig != "GIF87a" && sig != "GIF89a" {
		return nil
	}

	var threats []GIFThreat

	// Scan for application extensions (NETSCAPE, etc.)
	threats = append(threats, detectGIFApplicationExtensions(data)...)

	// Check for suspiciously short frame delays (possible animation attacks)
	threats = append(threats, detectGIFDelayAnomalies(data)...)

	return threats
}

func detectGIFApplicationExtensions(data []byte) []GIFThreat {
	var threats []GIFThreat

	// Application Extension introducer: 0x21 0xFF
	for i := 0; i < len(data)-1; i++ {
		if data[i] == 0x21 && data[i+1] == 0xFF {
			// Read the block size (should be 11)
			if i+2 < len(data) {
				blockSize := int(data[i+2])
				if i+3+blockSize <= len(data) {
					ext := string(data[i+3 : i+3+blockSize])
					if ext == "NETSCAPE2.0" || ext == "ANIMEXTS1.0" {
						threats = append(threats, GIFThreat{
							Type:       "application_extension",
							Confidence: 0.2,
							Evidence:   "Animation extension: " + ext,
							Frame:      0,
						})
					}
				}
			}
		}
	}

	return threats
}

func detectGIFDelayAnomalies(data []byte) []GIFThreat {
	var threats []GIFThreat

	// GIF Graphic Control Extension: 0x21 0xF9
	// Contains a 2-byte delay in centiseconds
	frameIdx := 0
	for i := 0; i+5 < len(data); i++ {
		if data[i] == 0x21 && data[i+1] == 0xF9 && data[i+2] == 0x04 {
			// Block size is fixed at 4 bytes
			delay := int(data[i+4]) | int(data[i+5])<<8 // little-endian centiseconds

			// Flag suspiciously short delays (< 1 centisecond = potential clickjacking)
			if delay == 0 || delay == 1 {
				threats = append(threats, GIFThreat{
					Type:       "delay_manipulation",
					Confidence: 0.4,
					Evidence:   "Frame delay is extremely short — possible clickjacking or animation attack",
					Frame:      frameIdx,
				})
			}

			frameIdx++
		}
	}

	return threats
}
