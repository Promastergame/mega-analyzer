package imageforensics

import "bytes"

// ═══════════════════════════════════════════════════════════════════════════════
// JPEG PARSER
//
// Walks JPEG segments looking for the EOI marker (FF D9). Reports any data
// that follows EOI as TrailingData. Captures sizes of COM / APPn segments
// for later flagging.
// ═══════════════════════════════════════════════════════════════════════════════

// JPEGInfo is the parsed JPEG structure.
type JPEGInfo struct {
	Valid           bool
	Width, Height   int
	EOIOffset       int
	TrailingData    []byte
	APPSegmentSizes map[byte]int // marker (E0..EF / FE) → bytes
	HasEXIF         bool
}

// ParseJPEG scans data for SOI ... EOI. Panic-safe.
func ParseJPEG(data []byte) (info JPEGInfo) {
	defer func() { notePanic("imageforensics.jpeg", recover()) }()

	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return JPEGInfo{}
	}
	info.Valid = true
	info.APPSegmentSizes = make(map[byte]int)

	pos := 2
	for pos+1 < len(data) {
		if data[pos] != 0xFF {
			return info
		}
		// skip fill bytes
		marker := data[pos+1]
		for marker == 0xFF && pos+2 < len(data) {
			pos++
			marker = data[pos+1]
		}

		// Standalone markers (no length): SOI, EOI, RSTn, TEM
		switch marker {
		case 0xD8: // SOI
			pos += 2
			continue
		case 0xD9: // EOI
			info.EOIOffset = pos + 2
			if info.EOIOffset < len(data) {
				info.TrailingData = data[info.EOIOffset:]
			}
			return info
		}
		if marker >= 0xD0 && marker <= 0xD7 { // RSTn
			pos += 2
			continue
		}

		if pos+4 > len(data) {
			return info
		}
		length := int(data[pos+2])<<8 | int(data[pos+3])
		if length < 2 {
			return info
		}
		// payloadStart points at the first byte after the 2-byte length field;
		// payloadEnd is exclusive end of segment payload. segEnd is the byte
		// position immediately after the entire segment (including length).
		payloadStart := pos + 4
		payloadEnd := pos + 2 + length
		segEnd := payloadEnd
		if segEnd > len(data) {
			return info
		}

		switch {
		case marker == 0xC0 || marker == 0xC2: // SOF0/2 — baseline / progressive
			if length >= 7 && pos+9 < len(data) {
				info.Height = int(data[pos+5])<<8 | int(data[pos+6])
				info.Width = int(data[pos+7])<<8 | int(data[pos+8])
			}
		case marker == 0xFE || (marker >= 0xE0 && marker <= 0xEF): // COM / APPn
			info.APPSegmentSizes[marker] = length
			if marker == 0xE1 && payloadEnd-payloadStart >= 6 {
				if bytes.Equal(data[payloadStart:payloadStart+6], []byte("Exif\x00\x00")) {
					info.HasEXIF = true
				}
			}
		case marker == 0xDA: // SOS — start of scan, raw entropy data follows
			pos = segEnd
			// Scan for FF D9 directly.
			for pos+1 < len(data) {
				if data[pos] == 0xFF && data[pos+1] != 0x00 && data[pos+1] != 0xFF {
					if data[pos+1] == 0xD9 {
						info.EOIOffset = pos + 2
						if info.EOIOffset < len(data) {
							info.TrailingData = data[info.EOIOffset:]
						}
						return info
					}
					if data[pos+1] >= 0xD0 && data[pos+1] <= 0xD7 {
						pos += 2
						continue
					}
					// unexpected marker inside scan — stop scanning
					return info
				}
				pos++
			}
			return info
		}

		pos = segEnd
	}
	return info
}
