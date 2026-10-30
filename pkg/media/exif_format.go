package media

import (
	"bytes"
)

// container sniffing (extended for TIFF/RAW/BMP/GIF/HEIC/AVIF).
//
// Split from exif.go: exact code move, no logic changes.

// --- Format sniffing --------------------------------------------------------

// sniffFormat identifies the container from its magic bytes. The declared
// format is usually derived from the filename extension, and a mismatch
// between the extension and the content is both a common upload attack and a
// forensic signal in its own right. Trusting the caller's format meant a JPEG
// named .png returned zero metadata with no explanation.
//
// Coverage: JPEG, PNG, GIF (87a/89a), BMP, TIFF (refined to DNG/RAW via
// identifyTIFFVariant), WEBP (RIFF), HEIC/AVIF/CR3/JXL/MP4 (ftyp brand
// dispatch — the old detector called every ftyp "mp4"), PSD, JXL codestream,
// Fuji RAF, ICO, SVG. Order matters: distinctive offset-0 magics first,
// BMFF brand before the generic MP4 assumption, text SVG last.
func sniffFormat(data []byte) (MediaType, bool) {
	switch {
	case len(data) >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF:
		return TypeJPEG, true
	case len(data) >= 8 && bytes.Equal(data[0:8], pngSignature):
		return TypePNG, true
	case len(data) >= 6 && (string(data[0:6]) == "GIF87a" || string(data[0:6]) == "GIF89a"):
		return TypeGIF, true
	case len(data) >= 2 && data[0] == 'B' && data[1] == 'M':
		return TypeBMP, true
	case isTIFFHeader(data):
		// Extension-agnostic here (filename unknown at some call sites):
		// TIFF vs DNG vs RAW refinement happens in the extract branch,
		// where identifyTIFFVariant sees the filename.
		return TypeTIFF, true
	case len(data) >= 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return TypeWEBP, true
	case len(data) >= 12 && string(data[4:8]) == "ftyp":
		return dispatchBMFFBrand(string(data[8:12])), true
	case len(data) >= 4 && string(data[0:4]) == "8BPS":
		return TypePSD, true
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0x0A:
		return TypeJXL, true // raw JXL codestream
	case len(data) >= 16 && string(data[0:16]) == "FUJIFILMCCD-RAW ":
		return TypeRAW, true
	case len(data) >= 4 && data[0] == 0x00 && data[1] == 0x00 && data[2] == 0x01 && data[3] == 0x00:
		return TypeICO, true
	case len(data) >= 5 && (bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("<svg")) ||
		bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("<?xml"))):
		return TypeSVG, true
	}
	return TypeUnknown, false
}

// sniffFormatWithName is sniffFormat plus the TIFF -> DNG/RAW refinement,
// which needs the filename extension (a .cr2 holding a TIFF header is a
// Canon RAW, not a generic TIFF).
func sniffFormatWithName(data []byte, filename string) (MediaType, bool) {
	t, ok := sniffFormat(data)
	if !ok {
		return TypeUnknown, false
	}
	if t == TypeTIFF {
		variant, _ := identifyTIFFVariant(data, filename)
		return variant, true
	}
	return t, true
}
