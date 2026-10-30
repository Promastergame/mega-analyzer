package imageforensics

import "bytes"

// PolyglotSignal describes a hidden archive / executable header found inside
// the trailing bytes of an image.
type PolyglotSignal struct {
	Format string // "ZIP", "RAR", "7z", "PE", "ELF", "DEX"
	Offset int    // offset within the trailing region (NOT global file offset)
}

var polyglotSigs = []struct {
	prefix []byte
	format string
}{
	{[]byte("PK\x03\x04"), "ZIP"},
	{[]byte("PK\x05\x06"), "ZIP"}, // empty archive marker
	{[]byte("Rar!\x1A\x07"), "RAR"},
	{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7z"},
	{[]byte{0x4D, 0x5A}, "PE"}, // MZ
	{[]byte{0x7F, 'E', 'L', 'F'}, "ELF"},
	{[]byte("dex\n"), "DEX"},
}

// FindPolyglot scans data for any known archive / executable header.
// Returns ALL matches — callers may deduplicate.
func FindPolyglot(data []byte) []PolyglotSignal {
	if len(data) == 0 {
		return nil
	}
	var out []PolyglotSignal
	for _, sig := range polyglotSigs {
		offset := 0
		for {
			idx := bytes.Index(data[offset:], sig.prefix)
			if idx < 0 {
				break
			}
			out = append(out, PolyglotSignal{Format: sig.format, Offset: offset + idx})
			offset = offset + idx + len(sig.prefix)
			if offset >= len(data) {
				break
			}
		}
	}
	return out
}
