package imageforensics

import (
	"bytes"
	"net/http"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// MAGIC / MIME SNIFFING
//
// Wraps net/http.DetectContentType plus a few extra signatures that Go's
// stdlib doesn't recognise (WEBP, modern AVIF/HEIF, ELF, DEX).
// ═══════════════════════════════════════════════════════════════════════════════

// SniffMime returns the canonical MIME type for the given byte slice.
// Falls back to net/http detection when no custom rule matches.
func SniffMime(data []byte) string {
	if len(data) == 0 {
		return "application/octet-stream"
	}

	// SVG — detect before stdlib (which returns text/xml or text/html).
	if looksLikeSVG(data) {
		return "image/svg+xml"
	}

	// ICO — 00 00 01 00 (icon) or 00 00 02 00 (cursor).
	if len(data) >= 4 && data[0] == 0x00 && data[1] == 0x00 &&
		(data[2] == 0x01 || data[2] == 0x02) && data[3] == 0x00 {
		return "image/x-icon"
	}

	// WEBP — RIFF + WEBP form-type marker.
	if len(data) >= 12 && bytes.Equal(data[:4], []byte("RIFF")) && bytes.Equal(data[8:12], []byte("WEBP")) {
		return "image/webp"
	}

	// ISO BMFF — bytes 4..8 are "ftyp", bytes 8..12 are the major brand.
	if len(data) >= 12 && bytes.Equal(data[4:8], []byte("ftyp")) {
		brand := string(data[8:12])
		switch brand {
		case "heic", "heix", "hevc", "hevx", "mif1", "msf1":
			return "image/heic"
		case "avif", "avis":
			return "image/avif"
		}
	}

	// BMP — "BM" header.
	if len(data) >= 2 && data[0] == 'B' && data[1] == 'M' {
		return "image/bmp"
	}

	// TIFF — "II" (little-endian) or "MM" (big-endian) + magic 42.
	if len(data) >= 4 {
		if (data[0] == 'I' && data[1] == 'I' && data[2] == 0x2A && data[3] == 0x00) ||
			(data[0] == 'M' && data[1] == 'M' && data[2] == 0x00 && data[3] == 0x2A) {
			return "image/tiff"
		}
	}

	// Native magic bytes.
	switch {
	case len(data) >= 4 && bytes.Equal(data[:4], []byte{0x7F, 'E', 'L', 'F'}):
		return "application/x-elf"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte("dex\n")):
		return "application/x-dex"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte("PK\x03\x04")):
		return "application/zip"
	case len(data) >= 4 && bytes.Equal(data[:4], []byte("Rar!")):
		return "application/x-rar"
	case len(data) >= 6 && bytes.Equal(data[:6], []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}):
		return "application/x-7z-compressed"
	case len(data) >= 2 && data[0] == 'M' && data[1] == 'Z':
		return "application/x-msdownload"
	}

	// Font magic bytes.
	if len(data) >= 4 {
		// TrueType / OpenType.
		if bytes.Equal(data[:4], []byte{0x00, 0x01, 0x00, 0x00}) ||
			bytes.Equal(data[:4], []byte("OTTO")) {
			return "font/otf"
		}
		// WOFF.
		if bytes.Equal(data[:4], []byte("wOFF")) {
			return "font/woff"
		}
		// WOFF2.
		if bytes.Equal(data[:4], []byte("wOF2")) {
			return "font/woff2"
		}
	}

	// stdlib fallback
	mime := http.DetectContentType(data)
	// Drop charset suffix for cleaner comparison.
	if i := strings.IndexByte(mime, ';'); i > 0 {
		mime = strings.TrimSpace(mime[:i])
	}
	return mime
}

// looksLikeSVG checks if data starts with an SVG tag (possibly after
// an XML declaration or whitespace/BOM).
func looksLikeSVG(data []byte) bool {
	// Check first 1KB for <svg to avoid scanning huge files.
	limit := 1024
	if len(data) < limit {
		limit = len(data)
	}
	s := strings.ToLower(string(data[:limit]))
	return strings.Contains(s, "<svg")
}

// MimeFromExt returns the expected MIME type for a file extension.
// Used to detect MIME-vs-extension mismatch.
func MimeFromExt(ext string) string {
	ext = strings.ToLower(strings.TrimPrefix(ext, "."))
	switch ext {
	case "png":
		return "image/png"
	case "jpg", "jpeg", "jpe", "jfif":
		return "image/jpeg"
	case "gif":
		return "image/gif"
	case "webp":
		return "image/webp"
	case "bmp":
		return "image/bmp"
	case "tiff", "tif":
		return "image/tiff"
	case "ico":
		return "image/x-icon"
	case "heic", "heif":
		return "image/heic"
	case "avif":
		return "image/avif"
	case "svg":
		return "image/svg+xml"
	}
	return ""
}

// MimesCompatible returns true if got is a reasonable detection for want.
func MimesCompatible(got, want string) bool {
	if got == want {
		return true
	}
	// http.DetectContentType returns "image/x-icon" or "image/vnd.microsoft.icon" for ICO.
	if (got == "image/x-icon" || got == "image/vnd.microsoft.icon") &&
		(want == "image/x-icon" || want == "image/vnd.microsoft.icon") {
		return true
	}
	return false
}
