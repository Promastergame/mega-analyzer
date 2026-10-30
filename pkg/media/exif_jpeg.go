package media

import (
	"bytes"
	"fmt"
)

// JPEG marker walker, APP1 EXIF, SOF frame, EOI.
//
// Split from exif.go: exact code move, no logic changes.

// --- JPEG marker walker -----------------------------------------------------

// jpegSeg is one JPEG marker segment. Payload is nil for standalone markers.
type jpegSeg struct {
	Marker  byte
	Offset  int    // offset of the marker's 0xFF byte
	Payload []byte // segment body, length field excluded
}

// walkJPEG is the single JPEG traversal for this file.
//
// The old code had two near-identical walkers that disagreed with each other:
// one treated 0xD9 as "skip and continue", the other as "stop"; one validated
// segLen, the SOF branch did not. On a damaged file they produced
// "dimensions found, EXIF missing" for no discoverable reason.
//
// Handled here and not before:
//   - fill bytes: any number of 0xFF may precede a marker. The old code read
//     data[pos+1] directly, so a padded marker became a garbage length.
//   - standalone markers (TEM, RST0-7, SOI, EOI) carry no length field. The
//     naive fill-skip fix that a review usually suggests reads a length for
//     them anyway.
//   - 0x00 after 0xFF is a stuffed byte, not a marker.
//   - entropy-coded scan data is walked with stuffing and RST awareness, so
//     DNL and the TOP-LEVEL EOI are reachable. A plain bytes.Index for FF D9
//     finds the EOI of the embedded thumbnail inside APP1 and reports the rest
//     of the file as "trailing data".
//
// Returns the offset of the top-level EOI, or -1.
func walkJPEG(data []byte, w *warnBag, fn func(jpegSeg) bool) int {
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xD8 {
		w.add("jpeg.walk", "missing_soi", 0, "")
		return -1
	}
	pos := 2
	for pos < len(data) {
		if data[pos] != 0xFF {
			w.add("jpeg.walk", "marker_desync", int64(pos), "expected 0xFF")
			return -1
		}
		for pos < len(data) && data[pos] == 0xFF {
			pos++ // fill bytes
		}
		if pos >= len(data) {
			w.add("jpeg.walk", "truncated_marker", int64(pos), "")
			return -1
		}
		marker := data[pos]
		markerOff := pos - 1
		pos++

		switch {
		case marker == 0x00:
			w.add("jpeg.walk", "stuffed_byte_outside_scan", int64(markerOff), "")
			return -1
		case marker == 0xD9: // EOI at top level
			fn(jpegSeg{Marker: marker, Offset: markerOff})
			return markerOff
		case marker == 0xD8: // a second SOI is a polyglot / embedded image
			w.add("jpeg.walk", "extra_soi", int64(markerOff), "")
			if !fn(jpegSeg{Marker: marker, Offset: markerOff}) {
				return -1
			}
			continue
		case marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7):
			if !fn(jpegSeg{Marker: marker, Offset: markerOff}) {
				return -1
			}
			continue
		}

		lenBytes, ok := sliceOf(data, pos, 2)
		if !ok {
			w.add("jpeg.walk", "truncated_length", int64(pos), "")
			return -1
		}
		segLen := int(lenBytes[0])<<8 | int(lenBytes[1])
		if segLen < 2 {
			w.add("jpeg.walk", "malformed_segment", int64(markerOff),
				fmt.Sprintf("marker 0x%02X length %d", marker, segLen))
			return -1
		}
		body, ok := sliceOf(data, pos+2, segLen-2)
		if !ok {
			w.add("jpeg.walk", "segment_past_eof", int64(markerOff),
				fmt.Sprintf("marker 0x%02X length %d", marker, segLen))
			return -1
		}
		if !fn(jpegSeg{Marker: marker, Offset: markerOff, Payload: body}) {
			return -1
		}
		pos += segLen

		if marker == 0xDA { // Start of Scan: skip entropy-coded data
			p := pos
			for p+1 < len(data) {
				if data[p] != 0xFF {
					p++
					continue
				}
				next := data[p+1]
				if next == 0x00 || next == 0xFF || (next >= 0xD0 && next <= 0xD7) {
					p += 2 // byte stuffing, fill, or restart marker
					continue
				}
				break
			}
			if p+1 >= len(data) {
				w.add("jpeg.walk", "truncated_before_eoi", int64(p), "")
				return -1
			}
			pos = p
		}
	}
	w.add("jpeg.walk", "no_eoi", int64(len(data)), "")
	return -1
}

// sliceOf is the overflow-safe window helper for plain byte slices.
func sliceOf(b []byte, off, n int) ([]byte, bool) {
	if off < 0 || n < 0 || n > len(b) || off > len(b)-n {
		return nil, false
	}
	return b[off : off+n], true
}

// findJPEGExifTIFF returns the raw TIFF payload of the APP1 "Exif\0\0" segment.
// The result is cloned: returning a subslice of the input keeps the whole file
// (possibly tens of megabytes) alive for as long as the metadata is cached.
func findJPEGExifTIFF(data []byte) []byte {
	return findJPEGExifTIFFWarn(data, nil)
}

func findJPEGExifTIFFWarn(data []byte, w *warnBag) []byte {
	var out []byte
	walkJPEG(data, w, func(s jpegSeg) bool {
		if s.Marker != 0xE1 || len(s.Payload) < 6 || string(s.Payload[0:6]) != "Exif\x00\x00" {
			return true
		}
		tiff := s.Payload[6:]
		// Require a real TIFF header, so an XMP-extended APP1 that reuses the
		// Exif prefix is not fed to the TIFF parser.
		if len(tiff) >= 4 && (tiff[0] == 'I' || tiff[0] == 'M') && tiff[0] == tiff[1] &&
			((tiff[0] == 'I' && tiff[2] == 0x00 && tiff[3] == 0x2A) ||
				(tiff[0] == 'M' && tiff[2] == 0x00 && tiff[3] == 0x2A)) {
			out = bytes.Clone(tiff)
			return false
		}
		w.add("jpeg.app1", "exif_prefix_without_tiff_header", int64(s.Offset), "")
		return true
	})
	return out
}

// jpegFrame is what a SOF marker plus an optional DNL tells us about the frame.
type jpegFrame struct {
	Width, Height int
	Progressive   bool
	Arithmetic    bool
	Components    int
	// Subsampling is "4:2:0" / "4:2:2" / "4:4:4" / "" when not derivable.
	// 4:4:4 on a photo-sized image is a graphics/screenshot signal; cameras
	// almost always write 4:2:0 or 4:2:2.
	Subsampling string
	HasDims     bool
}

func parseJPEGFrame(data []byte, w *warnBag) jpegFrame {
	var f jpegFrame
	found := false
	walkJPEG(data, w, func(s jpegSeg) bool {
		m := s.Marker
		if m == 0xDC && found && f.Height == 0 { // DNL carries the real height
			if len(s.Payload) >= 2 {
				f.Height = int(s.Payload[0])<<8 | int(s.Payload[1])
				f.HasDims = f.Width > 0 && f.Height > 0
			}
			return false
		}
		isSOF := m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC
		if !isSOF || found {
			return true
		}
		if len(s.Payload) < 6 {
			w.add("jpeg.sof", "truncated_sof", int64(s.Offset), "")
			return true
		}
		found = true
		f.Height = int(s.Payload[1])<<8 | int(s.Payload[2])
		f.Width = int(s.Payload[3])<<8 | int(s.Payload[4])
		f.Components = int(s.Payload[5])
		f.Progressive = m == 0xC2 || m == 0xC6 || m == 0xCA || m == 0xCE
		// Arithmetic coding is legal and essentially absent from real files;
		// its presence is worth flagging on its own.
		f.Arithmetic = m >= 0xC9 && m <= 0xCF
		if f.Components >= 1 && len(s.Payload) >= 6+f.Components*3 {
			h := int(s.Payload[7] >> 4)
			v := int(s.Payload[7] & 0x0F)
			switch {
			case f.Components == 1:
				f.Subsampling = "grayscale"
			case h == 2 && v == 2:
				f.Subsampling = "4:2:0"
			case h == 2 && v == 1:
				f.Subsampling = "4:2:2"
			case h == 1 && v == 1:
				f.Subsampling = "4:4:4"
			}
		}
		// height == 0 means "see DNL"; keep walking instead of reporting 0.
		if f.Height == 0 {
			w.add("jpeg.sof", "height_deferred_to_dnl", int64(s.Offset), "")
			return true
		}
		f.HasDims = f.Width > 0 && f.Height > 0
		return false
	})
	return f
}

// findJPEGDimensions keeps the old signature. Unlike before it does not report
// success for a SOF that defers its height to DNL (which produced 1920x0 with
// ok == true).
func findJPEGDimensions(data []byte) (width, height int, ok bool) {
	f := parseJPEGFrame(data, nil)
	return f.Width, f.Height, f.HasDims
}

// jpegTopLevelEOI finds the EOI that terminates the outermost image and the
// bytes that follow it.
func jpegTopLevelEOI(data []byte, w *warnBag) (eoi int, trailing []byte, ok bool) {
	eoi = walkJPEG(data, w, func(jpegSeg) bool { return true })
	if eoi < 0 {
		return 0, nil, false
	}
	end := eoi + 2
	if end > len(data) {
		return eoi, nil, true
	}
	return eoi, data[end:], true
}
