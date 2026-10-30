package media

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
)

// TIFF/EXIF primitives, IFD walker, parseTIFFDoc.
//
// Split from exif.go: exact code move, no logic changes.

// --- Tag numbers ------------------------------------------------------------

const (
	// IFD0
	tagImageWidth0    = 0x0100
	tagImageHeight0   = 0x0101
	tagMake           = 0x010F
	tagModel          = 0x0110
	tagOrientation    = 0x0112
	tagArtist         = 0x013B
	tagHostComputer   = 0x013C
	tagSoftware       = 0x0131
	tagDateTime       = 0x0132
	tagCopyright      = 0x8298
	tagExifIFDPointer = 0x8769
	tagGPSIFDPointer  = 0x8825
	tagXPComment      = 0x9C9C

	// Exif SubIFD
	tagExposureTime    = 0x829A
	tagFNumber         = 0x829D
	tagISOSpeedRatings = 0x8827
	tagRecommendedEI   = 0x8832
	tagISOSpeed        = 0x8833
	tagDateTimeOrig    = 0x9003
	tagDateTimeDigit   = 0x9004
	tagOffsetTimeOrig  = 0x9011
	tagShutterSpeedVal = 0x9201
	tagApertureValue   = 0x9202
	tagExposureBias    = 0x9204
	tagFlash           = 0x9209
	tagFocalLength     = 0x920A
	tagSubSecTimeOrig  = 0x9291
	tagUserComment     = 0x9286
	tagPixelXDimension = 0xA002
	tagPixelYDimension = 0xA003
	tagInteropPointer  = 0xA005
	tagFocalLength35   = 0xA405
	tagImageUniqueID   = 0xA420
	tagCameraOwner     = 0xA430
	tagBodySerial      = 0xA431
	tagLensMake        = 0xA433
	tagLensModel       = 0xA434
	tagLensSerial      = 0xA435

	// GPS IFD
	tagGPSLatRef     = 0x0001
	tagGPSLat        = 0x0002
	tagGPSLonRef     = 0x0003
	tagGPSLon        = 0x0004
	tagGPSAltRef     = 0x0005
	tagGPSAlt        = 0x0006
	tagGPSTimeStamp  = 0x0007
	tagGPSImgDirRef  = 0x0010
	tagGPSImgDir     = 0x0011
	tagGPSProcMethod = 0x001B
	tagGPSDateStamp  = 0x001D
	tagGPSHPosError  = 0x001F

	// IFD1 (thumbnail IFD)
	tagThumbOffset = 0x0201 // JPEGInterchangeFormat
	tagThumbLength = 0x0202 // JPEGInterchangeFormatLength
)

const (
	// maxThumbnailBytes bounds thumbnail extraction against a hostile length.
	maxThumbnailBytes = 512 * 1024
	// maxIFDEntries was 512, which is below what real DNG/CR2 files carry;
	// the old code returned an EMPTY map for anything larger, so a legitimate
	// RAW lost its entire IFD *and* the IFD0 -> IFD1 chain with it.
	maxIFDEntries = 4096
	// maxIFDChain bounds the IFD0 -> IFD1 -> ... walk in addition to the
	// visited-offset check, against a self-referential chain.
	maxIFDChain = 16
	// maxCuratedTextBytes caps any single curated string. Without it a 64 KB
	// Camera_Model lands in your JSON and your database.
	maxCuratedTextBytes = 512
	tiffEntrySize       = 12
)

// --- TIFF reader ------------------------------------------------------------

type tiffEntry struct {
	typ       uint16
	count     uint32
	valOffset int
}

type tiffFile struct {
	buf   []byte
	order binary.ByteOrder
	warn  *warnBag
}

func (t *tiffFile) u16(off int) (uint16, bool) {
	b, ok := t.sliceAt(off, 2)
	if !ok {
		return 0, false
	}
	return t.byteOrder().Uint16(b), true
}

func (t *tiffFile) u32(off int) (uint32, bool) {
	b, ok := t.sliceAt(off, 4)
	if !ok {
		return 0, false
	}
	return t.byteOrder().Uint32(b), true
}

// byteOrder never returns nil, so a zero-value tiffFile used in a test cannot
// nil-panic deep inside a formatter.
func (t *tiffFile) byteOrder() binary.ByteOrder {
	if t.order == nil {
		return binary.LittleEndian
	}
	return t.order
}

// slice is the single bounds-checked window helper. Written with subtraction
// rather than `off+n > len(buf)` precisely because the latter can overflow to
// a negative int on a 32-bit build and pass a check it should fail.
func (t *tiffFile) slice(off, n uint64) ([]byte, bool) {
	size := uint64(len(t.buf))
	if n > size || off > size-n {
		return nil, false
	}
	return t.buf[off : off+n], true
}

func (t *tiffFile) sliceAt(off int, n int) ([]byte, bool) {
	if off < 0 || n < 0 {
		return nil, false
	}
	return t.slice(uint64(off), uint64(n))
}

// parseIFD reads one IFD and returns its tag->entry map plus the offset of the
// next IFD in the chain (0 if none).
//
// Unlike the previous version this KEEPS entries whose value offset or length
// is out of range. Validation is payloadOf's job, and it reports an anomaly
// instead of silence; dropping the entry here made AnomalyOffsetOutOfRange and
// "<truncated: N of M>" permanently unreachable.
func (t *tiffFile) parseIFD(stage string, offset int) (map[uint16]tiffEntry, int) {
	count16, ok := t.u16(offset)
	if !ok {
		t.warn.add(stage, "ifd_header_out_of_bounds", int64(offset), "")
		return map[uint16]tiffEntry{}, 0
	}
	declared := int(count16)
	n := declared
	if n > maxIFDEntries {
		t.warn.add(stage, "ifd_entry_count_capped", int64(offset),
			fmt.Sprintf("%d entries declared", declared))
		n = maxIFDEntries
	}

	entries := make(map[uint16]tiffEntry, n)
	for i := 0; i < n; i++ {
		base := offset + 2 + i*tiffEntrySize
		tag, ok1 := t.u16(base)
		typ, ok2 := t.u16(base + 2)
		cnt, ok3 := t.u32(base + 4)
		if !ok1 || !ok2 || !ok3 {
			t.warn.add(stage, "ifd_truncated", int64(base),
				fmt.Sprintf("stopped at entry %d of %d", i, declared))
			break
		}

		// TiffType knows about type 13 (IFD). The old tiffTypeSize map did not,
		// so libtiff/Adobe files that write ExifIFDPointer as IFD rather than
		// LONG lost their entire Exif SubIFD and GPS IFD.
		size := TiffType(typ).Size()
		if size == 0 {
			t.warn.add(stage, "unrecognized_field_type", int64(base),
				fmt.Sprintf("tag 0x%04X type %d", tag, typ))
		}
		total := uint64(cnt) * uint64(size)

		valOff := base + 8
		if size == 0 || total > tiffInlineValueLen {
			ptr, ok := t.u32(base + 8)
			if !ok {
				t.warn.add(stage, "ifd_truncated", int64(base), "value pointer")
				break
			}
			valOff = int(ptr)
		}
		if total > uint64(len(t.buf)) {
			t.warn.add(stage, "value_larger_than_buffer", int64(base),
				fmt.Sprintf("tag 0x%04X claims %d bytes of %d", tag, total, len(t.buf)))
		}

		// First occurrence wins, matching exiftool. "Last wins" made golden
		// diffs against a reference implementation inexplicable.
		if _, dup := entries[tag]; dup {
			// Two Software or two DateTime tags in one IFD is a splice signal,
			// so the duplicate is reported even though its value is discarded.
			t.warn.add(stage, "duplicate_tag", int64(base), fmt.Sprintf("0x%04X", tag))
			continue
		}
		entries[tag] = tiffEntry{typ: typ, count: cnt, valOffset: valOff}
	}

	// The next-IFD pointer sits after the DECLARED entry array. Using the
	// capped count here would read from the middle of the entries and corrupt
	// the IFD0 -> IFD1 chain.
	next := 0
	if v, ok := t.u32(offset + 2 + declared*tiffEntrySize); ok {
		next = int(v)
	} else {
		t.warn.add(stage, "next_ifd_pointer_out_of_bounds", int64(offset), "")
	}
	return entries, next
}

// ascii reads a NUL-terminated string, bounded and sanitized.
//
// The old version returned raw attacker bytes: no length cap (a 64 KB
// Camera_Model), no UTF-8 validation, no control-character stripping (ANSI
// escapes and CRLF in your logs is log injection), and no bidi handling
// (U+202E in Artist makes the UI display something other than the bytes).
func (t *tiffFile) ascii(e tiffEntry) string {
	s, _ := t.asciiWarn(e)
	return s
}

func (t *tiffFile) asciiWarn(e tiffEntry) (string, TagAnomaly) {
	typ := TiffType(e.typ)
	if typ != TypeASCII && typ != TypeUndefined && typ != TypeByte {
		return "", 0
	}
	p, an := t.payloadOf(e)
	trimmed := bytes.TrimRight(p.data, "\x00")
	if len(trimmed) > maxCuratedTextBytes {
		trimmed = truncateRunes(trimmed, maxCuratedTextBytes)
		an |= AnomalyOversizedValue
	}
	s, tan := sanitizeText(trimmed)
	return s, an | tan
}

// uint reads a single integer field. Handles SSHORT/SLONG/IFD in addition to
// the three types the old version knew, and refuses to silently return the
// first byte of a multi-byte UNDEFINED blob as if it were the value.
func (t *tiffFile) uint(e tiffEntry) (uint64, bool) {
	switch TiffType(e.typ) {
	case TypeByte, TypeUndefined, TypeSByte:
		b, ok := t.sliceAt(e.valOffset, 1)
		if !ok {
			return 0, false
		}
		if TiffType(e.typ) == TypeUndefined && e.count > 1 {
			// One byte out of a blob is not a number.
			return 0, false
		}
		return uint64(b[0]), true
	case TypeShort, TypeSShort:
		v, ok := t.u16(e.valOffset)
		return uint64(v), ok
	case TypeLong, TypeSLong, TypeIFD:
		v, ok := t.u32(e.valOffset)
		return uint64(v), ok
	}
	return 0, false
}

// exifRational keeps the numerator and denominator. Reconstructing "1/250"
// from a float is what produced "1/2s" for a 0.6 second exposure, and turned
// f/1.75 into f/1.8.
type exifRational struct {
	Num int64
	Den int64
}

func (r exifRational) float() (float64, bool) {
	if r.Den == 0 {
		return 0, false
	}
	v := float64(r.Num) / float64(r.Den)
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return v, true
}

func (t *tiffFile) rationalAtRaw(off int, signed bool) (exifRational, bool) {
	b, ok := t.sliceAt(off, 8)
	if !ok {
		return exifRational{}, false
	}
	bo := t.byteOrder()
	if signed {
		return exifRational{
			Num: int64(int32(bo.Uint32(b))),
			Den: int64(int32(bo.Uint32(b[4:]))),
		}, true
	}
	return exifRational{
		Num: int64(bo.Uint32(b)),
		Den: int64(bo.Uint32(b[4:])),
	}, true
}

// rationalAt keeps the old float-returning shape for existing callers.
func (t *tiffFile) rationalAt(off int) (float64, bool) {
	r, ok := t.rationalAtRaw(off, false)
	if !ok {
		return 0, false
	}
	return r.float()
}

func (t *tiffFile) rationalRaw(e tiffEntry) (exifRational, bool) {
	switch TiffType(e.typ) {
	case TypeRational:
		if e.count == 0 {
			return exifRational{}, false
		}
		return t.rationalAtRaw(e.valOffset, false)
	case TypeSRational:
		if e.count == 0 {
			return exifRational{}, false
		}
		return t.rationalAtRaw(e.valOffset, true)
	}
	return exifRational{}, false
}

func (t *tiffFile) rational(e tiffEntry) (float64, bool) {
	r, ok := t.rationalRaw(e)
	if !ok {
		return 0, false
	}
	return r.float()
}

func (t *tiffFile) srationalAt(off int) (float64, bool) {
	r, ok := t.rationalAtRaw(off, true)
	if !ok {
		return 0, false
	}
	return r.float()
}

// srational is no longer dead code: the APEX fallbacks below use it.
func (t *tiffFile) srational(e tiffEntry) (float64, bool) {
	if TiffType(e.typ) != TypeSRational || e.count == 0 {
		return 0, false
	}
	return t.srationalAt(e.valOffset)
}

// gpsDMS reads the degrees/minutes/seconds triplet.
//
// Critical difference from rationalTriplet: a great many firmwares write the
// seconds (and sometimes the minutes) component as 0/0 meaning "not used",
// because they store degrees plus decimal minutes. The old code treated any
// zero denominator as failure and threw away the ENTIRE coordinate, so GPS
// silently vanished from a large class of real files. 0/0 is "unknown" and
// legitimately zero; n/0 is corruption and still rejected.
func (t *tiffFile) gpsDMS(e tiffEntry) ([3]float64, bool) {
	var out [3]float64
	if TiffType(e.typ) != TypeRational || e.count < 3 {
		return out, false
	}
	for i := 0; i < 3; i++ {
		r, ok := t.rationalAtRaw(e.valOffset+i*8, false)
		switch {
		case !ok:
			return out, false
		case r.Den == 0 && r.Num == 0:
			out[i] = 0
		case r.Den == 0:
			return out, false
		default:
			v, ok := r.float()
			if !ok {
				return out, false
			}
			out[i] = v
		}
	}
	// Degrees must be real; minutes/seconds >= 60 means the writer used some
	// other layout and interpreting it as DMS would invent a location.
	if out[0] < 0 || out[0] > 180 || out[1] >= 60 || out[2] >= 60 {
		return out, false
	}
	return out, true
}

// rationalTriplet is kept for compatibility with any other caller.
//
// Deprecated: use gpsDMS, which tolerates the 0/0 "unused" component.
func (t *tiffFile) rationalTriplet(e tiffEntry) ([3]float64, bool) {
	return t.gpsDMS(e)
}

// --- TIFF document ----------------------------------------------------------

// tiffDoc replaces parseTIFF's six return values and adds the Interop IFD,
// which was parsed by nobody, and IFD1, which was parsed but never dumped.
type tiffDoc struct {
	File    *tiffFile
	IFD0    map[uint16]tiffEntry
	Exif    map[uint16]tiffEntry
	GPS     map[uint16]tiffEntry
	Interop map[uint16]tiffEntry
	IFD1    map[uint16]tiffEntry
}

func emptyIFD() map[uint16]tiffEntry { return map[uint16]tiffEntry{} }

// parseTIFFDoc parses a raw TIFF/EXIF buffer.
func parseTIFFDoc(buf []byte, w *warnBag) (tiffDoc, bool) {
	doc := tiffDoc{IFD0: emptyIFD(), Exif: emptyIFD(), GPS: emptyIFD(), Interop: emptyIFD(), IFD1: emptyIFD()}
	if len(buf) < 8 {
		w.add("tiff.header", "too_short", 0, fmt.Sprintf("%d bytes", len(buf)))
		return doc, false
	}

	var order binary.ByteOrder
	switch string(buf[0:2]) {
	case "II":
		order = binary.LittleEndian
	case "MM":
		order = binary.BigEndian
	default:
		w.add("tiff.header", "bad_byte_order_mark", 0, fmt.Sprintf("%q", buf[0:2]))
		return doc, false
	}

	t := &tiffFile{buf: buf, order: order, warn: w}
	doc.File = t

	magic, mok := t.u16(2)
	if !mok || (magic != 42 && magic != 43) {
		w.add("tiff.header", "bad_magic", 2, fmt.Sprintf("%d", magic))
		return doc, false
	}
	if magic == 43 {
		// BigTIFF has a different header and 8-byte offsets throughout.
		// Refuse it explicitly rather than misparsing it as classic TIFF.
		w.add("tiff.header", "bigtiff_unsupported", 2, "")
		return doc, false
	}
	ifd0Off, ook := t.u32(4)
	if !ook {
		w.add("tiff.header", "ifd0_pointer_out_of_bounds", 4, "")
		return doc, false
	}

	// Walk the IFD chain with a visited set. Without it a crafted file where
	// the next-IFD pointer equals the current offset makes IFD1 a copy of
	// IFD0, and extractThumbnail then hands out an arbitrary slice of the
	// EXIF buffer as if it were the embedded preview.
	visited := make(map[int]bool, maxIFDChain)
	chain := make([]map[uint16]tiffEntry, 0, maxIFDChain)
	for off, i := int(ifd0Off), 0; off > 0 && i < maxIFDChain; i++ {
		if visited[off] {
			w.add("tiff.chain", "ifd_cycle", int64(off), "")
			break
		}
		visited[off] = true
		ifd, next := t.parseIFD(fmt.Sprintf("tiff.ifd%d", i), off)
		chain = append(chain, ifd)
		off = next
	}
	if len(chain) > 0 {
		doc.IFD0 = chain[0]
	}
	if len(chain) > 1 {
		doc.IFD1 = chain[1]
	}
	if len(chain) > 2 {
		w.add("tiff.chain", "extra_ifds", -1, fmt.Sprintf("%d in chain", len(chain)))
	}

	sub := func(stage string, parent map[uint16]tiffEntry, tag uint16) map[uint16]tiffEntry {
		e, present := parent[tag]
		if !present {
			return emptyIFD()
		}
		off, ok := t.uint(e)
		if !ok {
			w.add(stage, "pointer_unreadable", int64(e.valOffset), "")
			return emptyIFD()
		}
		if off == 0 || off > uint64(len(t.buf)) {
			w.add(stage, "pointer_out_of_bounds", int64(off), "")
			return emptyIFD()
		}
		if visited[int(off)] {
			w.add(stage, "ifd_cycle", int64(off), "")
			return emptyIFD()
		}
		visited[int(off)] = true
		ifd, _ := t.parseIFD(stage, int(off))
		return ifd
	}

	doc.Exif = sub("tiff.exif", doc.IFD0, tagExifIFDPointer)
	doc.GPS = sub("tiff.gps", doc.IFD0, tagGPSIFDPointer)
	doc.Interop = sub("tiff.interop", doc.Exif, tagInteropPointer)

	return doc, true
}

// parseTIFF keeps the original six-value signature for existing callers.
func parseTIFF(buf []byte) (t *tiffFile, ifd0, exifIFD, gpsIFD, ifd1 map[uint16]tiffEntry, ok bool) {
	doc, ok := parseTIFFDoc(buf, nil)
	if !ok {
		return nil, nil, nil, nil, nil, false
	}
	return doc.File, doc.IFD0, doc.Exif, doc.GPS, doc.IFD1, true
}

