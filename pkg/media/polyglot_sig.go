package media

import "bytes"

// ─── Overlay/trailing-data signature identification ─────────────────────────
//
// Distinct from the whole-file PrecompiledMagic scan in signals.go/detector.go
// (which looks for a *second* format's magic bytes anywhere in the file to
// flag polyglots): this specifically identifies what a chunk of *trailing*
// data (bytes after PNG IEND or JPEG EOI) actually is, so a report can say
// "512 bytes of trailing data - looks like a ZIP" instead of just "unknown
// trailing bytes".

type trailingSignature struct {
	Name  string
	Magic []byte
}

var trailingSignatures = []trailingSignature{
	{"ZIP", []byte("PK\x03\x04")},
	{"ZIP (empty archive)", []byte("PK\x05\x06")},
	{"RAR", []byte("Rar!\x1a\x07")},
	{"7-Zip", []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}},
	{"PE/EXE", []byte("MZ")},
	{"ELF", []byte("\x7fELF")},
	{"PDF", []byte("%PDF-")},
	{"DEX", []byte("dex\n")},
	{"GZIP", []byte{0x1F, 0x8B}},
}

// maxTrailingScanBytes bounds how far into a trailing-data blob we look for
// a signature - overlay data is typically small; this also guards against
// scanning multi-MB appended payloads on every file.
const maxTrailingScanBytes = 4096

// identifyTrailingFormat inspects a block of trailing/overlay data for a
// recognizable file signature, skipping a small amount of leading padding
// (NUL bytes are common between a logical EOF and an appended payload).
// Returns "" if nothing recognizable is found.
func identifyTrailingFormat(trailing []byte) string {
	if len(trailing) == 0 {
		return ""
	}

	start := 0
	for start < len(trailing) && start < 64 && trailing[start] == 0x00 {
		start++
	}

	window := trailing[start:]
	if len(window) > maxTrailingScanBytes {
		window = window[:maxTrailingScanBytes]
	}

	for _, sig := range trailingSignatures {
		if bytes.HasPrefix(window, sig.Magic) {
			return sig.Name
		}
	}
	// Fall back to a bounded scan (not just prefix) in case there's a small
	// amount of non-zero junk before the real payload starts.
	for _, sig := range trailingSignatures {
		if idx := bytes.Index(window, sig.Magic); idx != -1 && idx < 256 {
			return sig.Name
		}
	}
	return ""
}
