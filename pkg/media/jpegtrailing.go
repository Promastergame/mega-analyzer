package media

// ─── JPEG EOI + trailing data ────────────────────────────────────────────────
//
// JPEG's logical end is the EOI marker (0xFF 0xD9). Anything after it is
// trailing/overlay data - a classic polyglot/steganography vector. Finding
// EOI requires scanning the entropy-coded scan data byte-by-byte rather than
// treating it as another marker segment, and correctly skipping two things
// that look like they could be EOI but aren't: 0xFF 0x00 (byte-stuffing, the
// JPEG spec's escape for a literal 0xFF byte inside entropy data) and
// 0xFF 0xD0-0xD7 (restart markers, which are valid inside the scan).

// findJPEGEOITrailing walks JPEG markers up through SOS, then scans the
// entropy-coded data for the real EOI marker. Returns ok=false if EOI is
// never found (truncated/non-standard JPEG - don't guess at trailing data).
func findJPEGEOITrailing(data []byte) (eoiOffset int, trailing []byte, ok bool) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return 0, nil, false
	}
	pos := 2
	sosFound := false
	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			return 0, nil, false
		}
		marker := data[pos+1]
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD9) {
			pos += 2
			continue
		}
		segLen := int(data[pos+2])<<8 | int(data[pos+3])
		if segLen < 2 || pos+2+segLen > len(data) {
			return 0, nil, false
		}
		if marker == 0xDA {
			// SOS segment header itself is length-prefixed like any other
			// marker segment; entropy-coded scan data starts right after it.
			pos += 2 + segLen
			sosFound = true
			break
		}
		pos += 2 + segLen
	}
	if !sosFound {
		return 0, nil, false
	}

	for i := pos; i+1 < len(data); i++ {
		if data[i] != 0xFF {
			continue
		}
		next := data[i+1]
		if next == 0x00 {
			i++ // byte-stuffed literal 0xFF - not a marker, skip the stuffing byte
			continue
		}
		if next >= 0xD0 && next <= 0xD7 {
			i++ // restart marker - valid inside scan data, keep scanning
			continue
		}
		if next == 0xD9 {
			eoiOffset = i
			if i+2 < len(data) {
				trailing = data[i+2:]
			}
			return eoiOffset, trailing, true
		}
		// Any other 0xFFxx here (another marker appearing mid-scan, e.g. a
		// second SOS for progressive JPEG, or garbage) - keep scanning
		// rather than giving up; EOI may still follow later in the file.
	}

	return 0, nil, false
}
