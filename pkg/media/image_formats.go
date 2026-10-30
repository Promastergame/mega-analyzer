package media

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"strings"
)

// image_formats.go — still-image formats missing from the original pipeline.
//
// Before this file the analyzer knew 5 raster containers in sniffFormat
// (JPEG/PNG/WEBP/ICO/SVG) while MediaType/detector half-knew GIF and nothing
// else. That meant TIFF, DNG, vendor RAW (CR2/CR3/NEF/ARW/RW2/ORF/RAF/PEF/..),
// BMP, HEIC/HEIF, AVIF, PSD and JXL fell through to "unknown/unsupported"
// with no dimensions, no EXIF and no mismatch signal.
//
// Layout:
//   - extension sets for DNG vs generic RAW (content alone cannot tell most
//     TIFF-based RAWs apart — they share the TIFF header by design);
//   - TIFF-header test + identifyTIFFVariant (TIFF vs DNG vs RAW + note);
//   - ISO-BMFF brand dispatch (HEIC/AVIF/CR3/JXL/MP4 share the ftyp box;
//     the old detector called every ftyp "mp4");
//   - tiny dims parsers for GIF/BMP/PSD/TIFF (no new deps, bounded reads);
//   - bounded BMFF walk for HEIC/AVIF/CR3 stills (ispe dims + Exif box).
//
// Everything here is best-effort and defensive: suspect values yield ok=false,
// never a panic, never a guess presented as a dimension.

// --- Extensions -------------------------------------------------------------

// dngExtensions are files that are TIFF-based DNG by construction.
var dngExtensions = map[string]bool{".dng": true}

// rawExtensions are vendor RAW stills. Most are TIFF containers
// (CR2/NEF/ARW/RW2/ORF/PEF/SRW/RWL/IIQ/3FR/...); CR3 is ISO-BMFF ("crx ").
var rawExtensions = map[string]bool{
	".cr2": true, ".cr3": true, ".nef": true, ".nrw": true,
	".arw": true, ".srf": true, ".sr2": true, ".raf": true,
	".orf": true, ".rw2": true, ".pef": true, ".srw": true,
	".rwl": true, ".iiq": true, ".3fr": true, ".dcr": true,
	".kdc": true, ".erf": true, ".mef": true, ".mos": true,
	".x3f": true,
}

func isDNGFilename(name string) bool {
	return dngExtensions[strings.ToLower(filepath.Ext(name))]
}

func isRAWFilename(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return rawExtensions[ext] || dngExtensions[ext]
}

// --- TIFF header ------------------------------------------------------------

func isTIFFHeader(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	le := data[0] == 'I' && data[1] == 'I' && data[2] == 0x2A && data[3] == 0x00
	be := data[0] == 'M' && data[1] == 'M' && data[2] == 0x00 && data[3] == 0x2A
	return le || be
}

// identifyTIFFVariant refines a TIFF header into TIFF vs DNG vs RAW.
//
// Rationale: DNG/CR2/NEF/ARW/... are all TIFF/EP by design, so magic bytes
// alone cannot separate them. The DNGVersion tag (0xC612) marks real DNG;
// otherwise the filename extension is the signal (a .cr2 holding a TIFF
// header is a Canon RAW, not a generic TIFF). Returns a short note for the
// Format_Note field.
func identifyTIFFVariant(data []byte, filename string) (MediaType, string) {
	if isDNGFilename(filename) {
		return TypeDNG, "Adobe DNG (TIFF-based RAW)"
	}
	if doc, ok := parseTIFFDoc(data, nil); ok {
		if _, present := doc.IFD0[0xC612]; present {
			return TypeDNG, "Adobe DNG (TIFF-based RAW, DNGVersion tag present)"
		}
		if _, present := doc.Exif[0xC612]; present {
			return TypeDNG, "Adobe DNG (TIFF-based RAW, DNGVersion tag present)"
		}
	}
	ext := strings.ToLower(filepath.Ext(filename))
	if rawExtensions[ext] {
		if ext == ".raf" {
			return TypeRAW, "Fujifilm RAF (TIFF-based RAW)"
		}
		return TypeRAW, "vendor RAW (TIFF-based, " + ext + ")"
	}
	return TypeTIFF, ""
}

// --- ISO-BMFF brand dispatch ------------------------------------------------

// bmffBrand returns the major brand of an ISO-BMFF file (ftyp at offset 4).
// ok=false when the data is not BMFF.
func bmffBrand(data []byte) (brand string, ok bool) {
	if len(data) < 12 || string(data[4:8]) != "ftyp" {
		return "", false
	}
	return string(data[8:12]), true
}

// dispatchBMFFBrand maps an ftyp major brand to the still/video type.
// The old detector reported every ftyp as MP4, misclassifying HEIC/AVIF/JXL
// stills and Canon CR3 RAWs as video.
func dispatchBMFFBrand(brand string) MediaType {
	switch brand {
	case "heic", "heix", "hevc", "hevx", "heim", "heis", "hevm", "hevs",
		"mif1", "msf1":
		return TypeHEIC
	case "avif", "avis":
		return TypeAVIF
	case "crx ":
		return TypeRAW // Canon CR3
	case "jxl ":
		return TypeJXL
	}
	return TypeMP4
}

// --- Tiny dims parsers ------------------------------------------------------

// parseGIFDims reads the logical screen descriptor. GIF87a and GIF89a share
// the same 6-byte header + LE width/height.
func parseGIFDims(data []byte) (w, h int, ok bool) {
	if len(data) < 10 {
		return 0, 0, false
	}
	if string(data[0:6]) != "GIF87a" && string(data[0:6]) != "GIF89a" {
		return 0, 0, false
	}
	w = int(binary.LittleEndian.Uint16(data[6:8]))
	h = int(binary.LittleEndian.Uint16(data[8:10]))
	if w <= 0 || h <= 0 || w > 100000 || h > 100000 {
		return 0, 0, false
	}
	return w, h, true
}

// parseBMPDims reads BITMAPCOREHEADER/BITMAPINFOHEADER. Height may be
// negative (top-down); the absolute value is the frame height.
func parseBMPDims(data []byte) (w, h int, bpp int, ok bool) {
	if len(data) < 26 || data[0] != 'B' || data[1] != 'M' {
		return 0, 0, 0, false
	}
	headerSize := int(binary.LittleEndian.Uint32(data[14:18]))
	switch headerSize {
	case 12: // BITMAPCOREHEADER: u16 w/h
		w = int(binary.LittleEndian.Uint16(data[18:20]))
		h = int(binary.LittleEndian.Uint16(data[20:22]))
	case 40, 52, 56, 108, 124: // INFOHEADER variants: i32 w/h
		w32 := int32(binary.LittleEndian.Uint32(data[18:22]))
		h32 := int32(binary.LittleEndian.Uint32(data[22:26]))
		if w32 < 0 {
			w32 = -w32
		}
		if h32 < 0 {
			h32 = -h32
		}
		w, h = int(w32), int(h32)
		if len(data) >= 28 {
			bpp = int(binary.LittleEndian.Uint16(data[28:30]))
		}
	default:
		return 0, 0, 0, false
	}
	if w <= 0 || h <= 0 || w > 100000 || h > 100000 {
		return 0, 0, 0, false
	}
	return w, h, bpp, true
}

// parsePSDDims reads the PSD/PSB header: 26-byte fixed part, BE width/height.
func parsePSDDims(data []byte) (w, h int, ok bool) {
	if len(data) < 26 || string(data[0:4]) != "8BPS" {
		return 0, 0, false
	}
	h = int(binary.BigEndian.Uint32(data[14:18]))
	w = int(binary.BigEndian.Uint32(data[18:22]))
	if w <= 0 || h <= 0 || w > 100000 || h > 100000 {
		return 0, 0, false
	}
	return w, h, true
}

// parseTIFFDims reads ImageWidth/ImageLength from the already-walked IFD0.
// TIFF-based RAWs carry real frame size here, which is what makes
// resize/crop detection work for them too.
func parseTIFFDims(data []byte) (w, h int, ok bool) {
	doc, valid := parseTIFFDoc(data, nil)
	if !valid || doc.File == nil {
		return 0, 0, false
	}
	t := doc.File
	we, wok := doc.IFD0[tagImageWidth0]
	he, hok := doc.IFD0[tagImageHeight0]
	if !wok || !hok {
		return 0, 0, false
	}
	wv, ok1 := t.uint(we)
	hv, ok2 := t.uint(he)
	if !ok1 || !ok2 || wv == 0 || hv == 0 || wv > 100000 || hv > 100000 {
		return 0, 0, false
	}
	return int(wv), int(hv), true
}

// --- BMFF stills (HEIC/AVIF/CR3) --------------------------------------------

// bmffLimits bounds the box walk against hostile size fields.
const (
	maxBMFFBoxes = 512
	maxBMFFDepth = 6
)

// bmffStillInfo is what a HEIC/AVIF/CR3 still yields: dims from ispe,
// raw TIFF from an Exif box, XMP when present.
type bmffStillInfo struct {
	Width, Height int
	HasDims       bool
	Brand         string
	EXIF          []byte
	XMP           []byte
}

// parseBMFFStill walks ISO-BMFF boxes (bounded) collecting ispe dims and an
// Exif-box TIFF payload. Container boxes (meta/moof/trak/...) are recursed;
// "meta" skips its 4-byte version/flags prefix. An Exif item payload starts
// with a 4-byte TIFF-header offset that is stripped before TIFF parsing.
func parseBMFFStill(data []byte) (bmffStillInfo, bool) {
	var info bmffStillInfo
	brand, ok := bmffBrand(data)
	if !ok {
		return info, false
	}
	info.Brand = brand
	boxes := 0
	var walk func(buf []byte, depth int) bool
	walk = func(buf []byte, depth int) bool {
		if depth > maxBMFFDepth {
			return true
		}
		pos := 0
		// "meta" boxes carry 4 version/flags bytes before their children.
		if len(buf) >= 4 && depth > 0 {
			_ = pos
		}
		for pos+8 <= len(buf) {
			if boxes >= maxBMFFBoxes {
				return false
			}
			boxes++
			size := int(binary.BigEndian.Uint32(buf[pos : pos+4]))
			typ := string(buf[pos+4 : pos+8])
			head := 8
			payloadEnd := pos + size
			if size == 1 { // largesize
				if pos+16 > len(buf) {
					return true
				}
				large := binary.BigEndian.Uint64(buf[pos+8 : pos+16])
				head = 16
				if large > uint64(len(buf)-pos) || large < 16 {
					return true
				}
				payloadEnd = pos + int(large)
			} else if size == 0 {
				payloadEnd = len(buf)
			} else if size < 8 || payloadEnd > len(buf) {
				return true
			}
			payload := buf[pos+head : payloadEnd]
			switch typ {
			case "ispe":
				// version/flags(4) + width(4BE) + height(4BE)
				if len(payload) >= 12 {
					w := binary.BigEndian.Uint32(payload[4:8])
					h := binary.BigEndian.Uint32(payload[8:12])
					if w > 0 && h > 0 && w <= 100000 && h <= 100000 && !info.HasDims {
						info.Width, info.Height, info.HasDims = int(w), int(h), true
					}
				}
			case "Exif":
				if len(payload) > 4 && info.EXIF == nil {
					body := payload
					// First 4 bytes are the TIFF-header offset per spec.
					if off := binary.BigEndian.Uint32(payload[0:4]); int(off) < len(payload) {
						if isTIFFHeader(payload[off:]) {
							body = payload[off:]
						} else if isTIFFHeader(payload) {
							body = payload
						} else {
							body = payload[4:]
						}
					} else if isTIFFHeader(payload[4:]) {
						body = payload[4:]
					}
					info.EXIF = bytes.Clone(body)
				}
			case "mime", "data":
				// XMP riding as mime/data with xmp payload marker nearby.
				if bytes.Contains(payload, []byte("http://ns.adobe.com/xap/1.0/")) && info.XMP == nil {
					if idx := bytes.Index(payload, []byte("<x:")); idx != -1 {
						info.XMP = bytes.Clone(payload[idx:])
					}
				}
			case "meta", "iprp", "ipco", "moov", "trak", "mdia", "minf", "stbl", "dinf", "edts", "uuid":
				child := payload
				if typ == "meta" && len(child) >= 4 {
					child = child[4:]
				}
				if typ == "uuid" && len(child) >= 16 {
					child = child[16:]
				}
				if !walk(child, depth+1) {
					return false
				}
			}
			if payloadEnd <= pos {
				break
			}
			pos = payloadEnd
		}
		return true
	}
	// Top-level boxes start at 0; ftyp itself is skipped by the walker naturally.
	walk(data, 0)
	if !info.HasDims && info.EXIF == nil && info.XMP == nil {
		return info, false
	}
	return info, true
}

// --- GIF/BMP trailing data --------------------------------------------------

// gifTrailing returns bytes after the GIF trailer (0x3B). GIF has no
// declared-length EOF, so the first top-level 0x3B terminates the stream;
// anything after it is overlay (some encoders emit a second trailer for
// the last frame — a single trailing 0x3B byte is tolerated as clean).
func gifTrailing(data []byte) []byte {
	if len(data) < 7 {
		return nil
	}
	// Skip header + LSD; then walk blocks to the trailer without decoding
	// the whole stream: scan for 0x3B preceded by a plausible terminator.
	// Conservative version: last occurrence semantics are wrong for appended
	// payloads, so use the FIRST 0x3B at/after the pixel data start.
	for i := 13; i < len(data); i++ {
		if data[i] == 0x3B {
			rest := data[i+1:]
			if len(rest) == 0 || (len(rest) == 1 && rest[0] == 0x3B) {
				return nil
			}
			return rest
		}
	}
	return nil
}

// bmpDeclaredSize returns the bfSize file-size field for overlay comparison.
func bmpDeclaredSize(data []byte) (int, bool) {
	if len(data) < 6 || data[0] != 'B' || data[1] != 'M' {
		return 0, false
	}
	size := int(binary.LittleEndian.Uint32(data[2:6]))
	if size < 26 || size > 1<<31-1 {
		return 0, false
	}
	return size, true
}
