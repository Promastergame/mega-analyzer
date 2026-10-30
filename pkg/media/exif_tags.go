package media

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Generic EXIF tag dump.
//
// The curated fields in exif.go (Camera_Make, GPS_Coordinates, ...) cover a
// dozen well-known tags. Forensic review cares about *everything* a file
// carries - MakerNote blobs, vendor-private tags, pointers into the file -
// even when this tool doesn't know what a tag means.
//
// Guarantees of this file, in order of importance:
//
//  1. No panic and no unbounded allocation for any (type, count, offset)
//     triple, including count=0xFFFFFFFF and negative/overflowed offsets.
//     Every byte-count computation happens in uint64; nothing is multiplied
//     in int, where it would wrap on a 32-bit build.
//  2. Every rendered value is bounded: len(Value) <= maxDumpValueChars plus a
//     short fixed-size suffix, regardless of what the file claims. This holds
//     on *every* return path, including ASCII and UNDEFINED text.
//  3. Anomalies are machine-readable (TagAnomaly bitmask), not prose buried in
//     the display string. Callers filter on flags; humans read Value.
//  4. Names are resolved per numbering space. GPS 0x0001 and Interop 0x0001
//     are different tags; a single flat table silently mislabels them.
//  5. A mismatch between what an entry claims and what the file holds is
//     reported as data ("<truncated: 4 of 8 bytes readable>"), never silently
//     dropped - the mismatch itself is the forensic signal.
//
// COMPATIBILITY: TiffTagView is NOT wire-compatible with the previous
// flat-string version. Tag/Type/IFD are now named types (they still marshal
// to the same text - "0x927C", "RATIONAL", "IFD0" - but they are no longer
// plain strings in Go), and several fields were added. Old golden files must
// be regenerated once. From this revision on, the JSON shape is stable and
// round-trippable: every named type implements both MarshalText and
// UnmarshalText.
//
// Dependencies on exif.go: type tiffFile{buf []byte; order binary.ByteOrder},
// type tiffEntry{typ uint16; count uint32; valOffset int}, methods u16/u32.
// No struct field is added or renamed. Builds on Go 1.19+.

// --- IFD identity -----------------------------------------------------------

// IFDKind identifies which numbering space a tag lives in. A tag id is only
// meaningful together with its IFD. Exported (unlike the type it replaces) so
// callers outside this package can switch on it and construct a TiffTagView.
type IFDKind uint8

const (
	IFDUnknown IFDKind = iota
	IFD0
	IFD1
	IFDExif
	IFDGPS
	IFDInterop
	IFDSub
	IFDMakerNote
)

// String values are the on-the-wire labels. They intentionally match the
// strings the previous implementation emitted ("IFD0", "ExifSubIFD", "GPS")
// so a diff between an old and a new report shows only real changes.
var ifdKindNames = [...]string{
	IFDUnknown:   "Unknown",
	IFD0:         "IFD0",
	IFD1:         "IFD1",
	IFDExif:      "ExifSubIFD",
	IFDGPS:       "GPS",
	IFDInterop:   "Interop",
	IFDSub:       "SubIFD",
	IFDMakerNote: "MakerNote",
}

const ifdKindUnnamedPrefix = "IFD_"

func (k IFDKind) String() string {
	if int(k) < len(ifdKindNames) {
		return ifdKindNames[k]
	}
	return ifdKindUnnamedPrefix + strconv.Itoa(int(k))
}

// MarshalText keeps JSON stable: without it encoding/json would emit the raw
// iota ordinal, and inserting a new kind would silently change the meaning of
// every previously stored report.
func (k IFDKind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText accepts everything String can produce, including the
// "IFD_9" form for kinds this build does not know.
func (k *IFDKind) UnmarshalText(b []byte) error {
	s := string(b) // converted once, not per loop iteration
	for i := range ifdKindNames {
		if ifdKindNames[i] == s {
			*k = IFDKind(i)
			return nil
		}
	}
	if n, err := strconv.ParseUint(strings.TrimPrefix(s, ifdKindUnnamedPrefix), 10, 8); err == nil &&
		strings.HasPrefix(s, ifdKindUnnamedPrefix) {
		*k = IFDKind(n)
		return nil
	}
	return fmt.Errorf("media: unknown IFD kind %q", s)
}

// namespace collapses kinds that share a tag numbering space. IFD0, IFD1 and
// SubIFDs are all the TIFF baseline space; Exif/GPS/Interop are disjoint.
func (k IFDKind) namespace() IFDKind {
	switch k {
	case IFD0, IFD1, IFDSub:
		return IFD0
	case IFDExif, IFDGPS, IFDInterop:
		return k
	}
	return IFDUnknown
}

// --- Tag ids ----------------------------------------------------------------

// TagID is a TIFF tag number. It exists as a named type purely so that it
// marshals as "0x927C" instead of 37500: a decimal tag number in a report is
// unreadable, and it silently breaks every stored report and grep pattern
// written against the old string-valued field.
type TagID uint16

func (t TagID) String() string { return fmt.Sprintf("0x%04X", uint16(t)) }

func (t TagID) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// UnmarshalText accepts "0x927C", "927C" and plain decimal, so reports written
// by other tools can be read back.
func (t *TagID) UnmarshalText(b []byte) error {
	s := strings.TrimSpace(string(b))
	base := 16
	switch {
	case strings.HasPrefix(s, "0x"), strings.HasPrefix(s, "0X"):
		s = s[2:]
	case strings.HasPrefix(s, "#"):
		s = s[1:]
	default:
		// Bare digits are ambiguous. Treat them as hex only when they cannot
		// be decimal, so "0110" (Model) does not silently become 110.
		if strings.IndexFunc(s, func(r rune) bool {
			return (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		}) < 0 {
			base = 10
		}
	}
	n, err := strconv.ParseUint(s, base, 16)
	if err != nil {
		return fmt.Errorf("media: invalid tag id %q: %w", b, err)
	}
	*t = TagID(n)
	return nil
}

// --- TIFF field types -------------------------------------------------------

// TiffType is a TIFF 6.0 / Exif 3.0 field type code.
type TiffType uint16

const (
	TypeByte      TiffType = 1
	TypeASCII     TiffType = 2
	TypeShort     TiffType = 3
	TypeLong      TiffType = 4
	TypeRational  TiffType = 5
	TypeSByte     TiffType = 6
	TypeUndefined TiffType = 7
	TypeSShort    TiffType = 8
	TypeSLong     TiffType = 9
	TypeSRational TiffType = 10
	TypeFloat     TiffType = 11
	TypeDouble    TiffType = 12
	// TypeIFD (13) is emitted by real writers for ExifIFDPointer,
	// GPSIFDPointer and SubIFDs. Treating it as unknown makes Size() return 0
	// and drops the entire Exif SubIFD - the single most damaging omission a
	// TIFF type table can have.
	TypeIFD TiffType = 13
	// BigTIFF types. Not legal in Exif, but they occur in DNG/OME-TIFF and in
	// deliberately malformed files; naming them beats "TYPE_16".
	TypeLong8  TiffType = 16
	TypeSLong8 TiffType = 17
	TypeIFD8   TiffType = 18
)

var tiffTypeInfo = [...]struct {
	name string
	size int
}{
	TypeByte:      {"BYTE", 1},
	TypeASCII:     {"ASCII", 1},
	TypeShort:     {"SHORT", 2},
	TypeLong:      {"LONG", 4},
	TypeRational:  {"RATIONAL", 8},
	TypeSByte:     {"SBYTE", 1},
	TypeUndefined: {"UNDEFINED", 1},
	TypeSShort:    {"SSHORT", 2},
	TypeSLong:     {"SLONG", 4},
	TypeSRational: {"SRATIONAL", 8},
	TypeFloat:     {"FLOAT", 4},
	TypeDouble:    {"DOUBLE", 8},
	TypeIFD:       {"IFD", 4},
	TypeLong8:     {"LONG8", 8},
	TypeSLong8:    {"SLONG8", 8},
	TypeIFD8:      {"IFD8", 8},
}

const tiffTypeUnnamedPrefix = "TYPE_"

func (t TiffType) valid() bool {
	return int(t) < len(tiffTypeInfo) && tiffTypeInfo[t].size != 0
}

// Size returns the byte width of one element, or 0 for unrecognized types.
func (t TiffType) Size() int {
	if !t.valid() {
		return 0
	}
	return tiffTypeInfo[t].size
}

func (t TiffType) String() string {
	if !t.valid() {
		return tiffTypeUnnamedPrefix + strconv.Itoa(int(t))
	}
	return tiffTypeInfo[t].name
}

func (t TiffType) MarshalText() ([]byte, error) { return []byte(t.String()), nil }

// UnmarshalText accepts every form String can produce, so a stored report
// round-trips through json.Unmarshal.
func (t *TiffType) UnmarshalText(b []byte) error {
	s := string(b)
	for i := range tiffTypeInfo {
		if tiffTypeInfo[i].size != 0 && tiffTypeInfo[i].name == s {
			*t = TiffType(i)
			return nil
		}
	}
	if strings.HasPrefix(s, tiffTypeUnnamedPrefix) {
		if n, err := strconv.ParseUint(s[len(tiffTypeUnnamedPrefix):], 10, 16); err == nil {
			*t = TiffType(n)
			return nil
		}
	}
	return fmt.Errorf("media: unknown TIFF type %q", s)
}

// --- Anomalies --------------------------------------------------------------

// TagAnomaly is a bitmask of everything structurally wrong with one entry.
// Keeping this separate from Value is the whole point: a caller can ask "show
// me every tag whose declared length exceeds the file" without running a
// regex over display text.
type TagAnomaly uint32

const (
	AnomalyUnrecognizedType TagAnomaly = 1 << iota
	AnomalyZeroCount
	AnomalyOffsetOutOfRange
	AnomalyValueTruncated
	AnomalyOversizedValue
	AnomalyDisplayCapped
	AnomalyNoNULTerminator
	AnomalyEmbeddedNUL
	AnomalyNonPrintable
	AnomalyInvalidUTF8
	AnomalyBidiControl
	AnomalyNoByteOrder
)

var anomalyNames = []struct {
	flag TagAnomaly
	name string
}{
	{AnomalyUnrecognizedType, "unrecognized_type"},
	{AnomalyZeroCount, "zero_count"},
	{AnomalyOffsetOutOfRange, "offset_out_of_range"},
	{AnomalyValueTruncated, "value_truncated"},
	{AnomalyOversizedValue, "oversized_value"},
	{AnomalyDisplayCapped, "display_capped"},
	{AnomalyNoNULTerminator, "no_nul_terminator"},
	{AnomalyEmbeddedNUL, "embedded_nul"},
	{AnomalyNonPrintable, "non_printable"},
	{AnomalyInvalidUTF8, "invalid_utf8"},
	{AnomalyBidiControl, "bidi_control"},
	{AnomalyNoByteOrder, "no_byte_order"},
}

const anomalyNone = "none"

func (a TagAnomaly) Has(f TagAnomaly) bool { return a&f != 0 }

func (a TagAnomaly) Names() []string {
	if a == 0 {
		return nil
	}
	out := make([]string, 0, len(anomalyNames))
	for _, n := range anomalyNames {
		if a&n.flag != 0 {
			out = append(out, n.name)
		}
	}
	return out
}

func (a TagAnomaly) String() string {
	if a == 0 {
		return anomalyNone
	}
	return strings.Join(a.Names(), "|")
}

func (a TagAnomaly) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText parses "none" or a "|"-joined flag list. Unknown flag names
// are an error rather than a silent drop: quietly losing an anomaly is the
// exact failure mode this type exists to prevent.
func (a *TagAnomaly) UnmarshalText(b []byte) error {
	s := string(b)
	if s == "" || s == anomalyNone {
		*a = 0
		return nil
	}
	var out TagAnomaly
fields:
	for _, field := range strings.Split(s, "|") {
		for _, n := range anomalyNames {
			if n.name == field {
				out |= n.flag
				continue fields
			}
		}
		return fmt.Errorf("media: unknown tag anomaly %q", field)
	}
	*a = out
	return nil
}

// --- Public view ------------------------------------------------------------

// TiffTagView is one row of the generic tag dump. It keeps identifiers as
// typed values (not pre-formatted display strings) so callers can filter and
// sort without parsing text back, while still marshalling to readable text.
// Count/Offset/Declared/Available are deliberately exposed: anomalous values
// there are exactly what a suspicious-file review looks for.
type TiffTagView struct {
	IFD       IFDKind
	Tag       TagID    // marshals as "0x927C"
	Name      string   // "" if unknown to this tool
	Type      TiffType // marshals as "RATIONAL"
	Count     uint32   // element count as claimed by the entry
	Offset    int      // absolute offset of the value bytes within the blob
	Inline    bool     // value fits the 4-byte entry slot (no pointer chase)
	Declared  uint64   // bytes the entry claims (count * element size)
	Available uint64   // bytes actually readable; < Declared means short file
	Anomalies TagAnomaly
	Value     string // human-readable rendering, always non-empty
}

// TagHex renders the tag id as "0x927C".
func (v TiffTagView) TagHex() string { return v.Tag.String() }

// DisplayName is Name when known, otherwise "Unknown_0x1234".
func (v TiffTagView) DisplayName() string {
	if v.Name != "" {
		return v.Name
	}
	return "Unknown_" + v.TagHex()
}

// TypeName is a convenience for templates that cannot call methods on fields.
func (v TiffTagView) TypeName() string { return v.Type.String() }

// String renders one report line.
func (v TiffTagView) String() string {
	s := fmt.Sprintf("%v %v %-28s %-9v [%d] = %s",
		v.IFD, v.Tag, v.DisplayName(), v.Type, v.Count, v.Value)
	if v.Anomalies != 0 {
		s += "  !" + v.Anomalies.String()
	}
	return s
}

// Display budget: bounds output size per tag regardless of what the file
// claims. maxDumpValueChars is enforced on every return path.
const (
	maxDumpValueChars  = 512
	maxDumpArrayValues = 16
	maxDumpHexBytes    = 24
	maxTextProbeBytes  = 4096 // never copy more than this to probe for text
	tiffInlineValueLen = 4    // value slot size in a 12-byte IFD entry
)

// DumpAllTags turns a parsed IFD into a stable-ordered, fully generic table.
// The map key is the authoritative tag id, so tiffEntry needs no tag field.
//
// The result is non-nil even for an empty IFD: it marshals to [] rather than
// null, matching the previous implementation.
func DumpAllTags(t *tiffFile, kind IFDKind, ifd map[uint16]tiffEntry) []TiffTagView {
	views := make([]TiffTagView, 0, len(ifd))
	if t == nil || len(ifd) == 0 {
		return views
	}
	tags := make([]uint16, 0, len(ifd))
	for tag := range ifd {
		tags = append(tags, tag)
	}
	sort.Slice(tags, func(i, j int) bool { return tags[i] < tags[j] })

	for _, tag := range tags {
		views = append(views, describeTag(t, kind, TagID(tag), ifd[tag]))
	}
	return views
}

// dumpAllTags is the internal spelling used by exif.go.
func dumpAllTags(t *tiffFile, kind IFDKind, ifd map[uint16]tiffEntry) []TiffTagView {
	return DumpAllTags(t, kind, ifd)
}

// SortTagViews orders a merged multi-IFD dump: by IFD, then by tag.
func SortTagViews(views []TiffTagView) {
	sort.SliceStable(views, func(i, j int) bool {
		if views[i].IFD != views[j].IFD {
			return views[i].IFD < views[j].IFD
		}
		return views[i].Tag < views[j].Tag
	})
}

// describeTag builds one row, resolving the payload exactly once.
func describeTag(t *tiffFile, kind IFDKind, tag TagID, e tiffEntry) TiffTagView {
	typ := TiffType(e.typ)
	v := TiffTagView{
		IFD:    kind,
		Tag:    tag,
		Name:   tagName(kind, tag),
		Type:   typ,
		Count:  e.count,
		Offset: e.valOffset,
	}
	if size := typ.Size(); size > 0 {
		v.Declared = uint64(e.count) * uint64(size)
		v.Inline = e.count > 0 && v.Declared <= tiffInlineValueLen
	}
	p, an := t.payloadOf(e)
	v.Available = p.available
	v.Value, v.Anomalies = renderValue(t, kind, tag, e, p, an)
	return v
}

// --- Bounded payload access -------------------------------------------------

// payload is the readable window of an entry's value. All sizes are byte
// counts in uint64; element counts are derived, never stored pre-multiplied.
type payload struct {
	data      []byte // bytes present in the buffer, whole elements only
	elemSize  int    // 0 only for unrecognized types
	declared  uint64 // bytes the entry claims
	available uint64 // bytes actually readable
}

func (p payload) truncated() bool { return p.available < p.declared }

func (p payload) availableElems() uint64 {
	if p.elemSize == 0 {
		return 0
	}
	return p.available / uint64(p.elemSize)
}

// payloadOf resolves e's value window. It never panics and never allocates
// based on e.count. The declared size is kept verbatim - clamping it to
// MaxInt32 would make the report lie about the very number that is suspicious.
//
// The offset is validated BEFORE the element size, because an entry's offset
// is out of range independently of whether this build recognizes its type:
// checking size first would drop AnomalyOffsetOutOfRange for TYPE_14 pointing
// past the end of the file, which is precisely the interesting case.
func (t *tiffFile) payloadOf(e tiffEntry) (payload, TagAnomaly) {
	var an TagAnomaly
	if e.count == 0 {
		an |= AnomalyZeroCount
	}
	offsetBad := e.valOffset < 0 || uint64(e.valOffset) > uint64(len(t.buf))
	if offsetBad {
		an |= AnomalyOffsetOutOfRange
	}

	size := TiffType(e.typ).Size()
	if size == 0 {
		return payload{}, an | AnomalyUnrecognizedType
	}
	// uint64: the maximum here is 0xFFFFFFFF * 8, nowhere near overflow, and
	// correct on 32-bit where int(e.count) alone would wrap negative.
	declared := uint64(e.count) * uint64(size)
	if offsetBad {
		return payload{elemSize: size, declared: declared}, an
	}

	room := uint64(len(t.buf)) - uint64(e.valOffset)
	avail := declared
	if avail > room {
		avail = room - room%uint64(size) // whole elements only
		an |= AnomalyValueTruncated
	}
	// avail <= room <= len(t.buf), so both bounds fit int on every platform.
	return payload{
		data:      t.buf[e.valOffset : e.valOffset+int(avail)],
		elemSize:  size,
		declared:  declared,
		available: avail,
	}, an
}

// --- Output budget ----------------------------------------------------------

// truncateRunes cuts b to at most limit bytes without splitting a UTF-8 rune.
// Splitting one would make utf8.Valid report invalid input and raise a flag
// that is not in the file - and a false forensic flag is worse than a missed
// one.
func truncateRunes(b []byte, limit int) []byte {
	if len(b) <= limit {
		return b
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return b[:cut]
}

// truncateRunesStr is truncateRunes for strings.
func truncateRunesStr(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// capValue truncates s on a rune boundary and records that it did. Called on
// every return path, so "bounded output" is structural rather than a property
// of whichever branch happened to run.
func capValue(s string, an TagAnomaly) (string, TagAnomaly) {
	if len(s) <= maxDumpValueChars {
		return s, an
	}
	return truncateRunesStr(s, maxDumpValueChars) + "\u2026", an | AnomalyDisplayCapped
}

// --- Text sanitation --------------------------------------------------------

// sanitizeText makes an arbitrary byte blob safe to embed in a report:
// bounded length, valid UTF-8, no control characters, no bidi overrides. Each
// class of damage sets a flag, so nothing is hidden by being cleaned up.
func sanitizeText(raw []byte) (string, TagAnomaly) {
	var an TagAnomaly
	if len(raw) > maxTextProbeBytes {
		raw = truncateRunes(raw, maxTextProbeBytes)
		an |= AnomalyOversizedValue
	}
	s := string(raw)
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
		an |= AnomalyInvalidUTF8
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == 0:
			an |= AnomalyEmbeddedNUL
		case r == '\n' || r == '\r' || r == '\t':
			an |= AnomalyNonPrintable
			b.WriteByte(' ')
		case r < 0x20 || (r >= 0x7F && r <= 0x9F):
			an |= AnomalyNonPrintable
		case isBidiControl(r):
			// A right-to-left override inside Software or ImageDescription is a
			// display-spoofing attempt, not a formatting choice.
			an |= AnomalyBidiControl
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String()), an
}

// isBidiControl covers the runes used to make displayed text disagree with
// stored bytes: explicit bidi embedding/override, isolates, marks, and the
// separator/BOM characters that break line rendering in report viewers.
func isBidiControl(r rune) bool {
	switch r {
	case 0x200E, 0x200F, // LRM, RLM
		0x061C,         // ARABIC LETTER MARK
		0x2028, 0x2029, // LINE / PARAGRAPH SEPARATOR
		0xFEFF: // ZERO WIDTH NO-BREAK SPACE (BOM used mid-string)
		return true
	}
	return (r >= 0x202A && r <= 0x202E) || // LRE RLE PDF LRO RLO
		(r >= 0x2066 && r <= 0x2069) // LRI RLI FSI PDI
}

func isPrintableASCII(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// --- Value rendering --------------------------------------------------------

// formatTiffValue renders any entry's value as a non-empty display string
// plus its anomaly set. Kept as a standalone entry point for tests.
func formatTiffValue(t *tiffFile, kind IFDKind, tag TagID, e tiffEntry) (string, TagAnomaly) {
	p, an := t.payloadOf(e)
	return renderValue(t, kind, tag, e, p, an)
}

func renderValue(t *tiffFile, kind IFDKind, tag TagID, e tiffEntry, p payload, an TagAnomaly) (string, TagAnomaly) {
	typ := TiffType(e.typ)
	if !typ.valid() {
		// The offset flag from payloadOf is preserved here; the type is what
		// stops us rendering a value, not what stops us judging the offset.
		msg := fmt.Sprintf("<unrecognized type %d, count %d>", e.typ, e.count)
		if an.Has(AnomalyOffsetOutOfRange) {
			msg = fmt.Sprintf("<unrecognized type %d, count %d, offset %d outside %d-byte TIFF blob>",
				e.typ, e.count, e.valOffset, len(t.buf))
		}
		return capValue(msg, an|AnomalyUnrecognizedType)
	}
	if an.Has(AnomalyOffsetOutOfRange) {
		return capValue(fmt.Sprintf("<value offset %d outside %d-byte TIFF blob, count %d>",
			e.valOffset, len(t.buf), e.count), an)
	}
	// A nil byte order is a caller bug, not a TIFF default. Render anyway, but
	// flag it: plausible-looking wrong numbers are worse than a visible error.
	order := t.order
	if order == nil {
		order = binary.LittleEndian
		an |= AnomalyNoByteOrder
	}
	if e.count == 0 {
		return capValue("<empty>", an)
	}

	var (
		s   string
		ran TagAnomaly
	)
	switch {
	// XP* tags are BYTE arrays holding UTF-16LE regardless of the TIFF byte
	// order. Rendered as a numeric array they read "77, 0, 105, 0, ...".
	case isXPTag(tag) && kind.namespace() == IFD0 && (typ == TypeByte || typ == TypeUndefined):
		s, ran = decodeUTF16(p.data, binary.LittleEndian)
		if s == "" {
			s = hexPreview(p.data, p.declared)
		}
	case typ == TypeASCII:
		s, ran = renderASCII(p)
	case typ == TypeUndefined:
		s, ran = renderUndefined(kind, tag, p, order)
	default:
		s, ran = renderArray(p, elemFormatter(typ, p.data, order))
	}

	s, an = capValue(s, an|ran)
	if p.truncated() {
		// Short fixed-size suffix, appended after capping so the report of the
		// mismatch can never itself be truncated away.
		s += fmt.Sprintf(" <truncated: %d of %d bytes readable>", p.available, p.declared)
	}
	return s, an
}

func isXPTag(tag TagID) bool { return tag >= 0x9C9B && tag <= 0x9C9F }

// renderASCII renders a NUL-terminated string. A missing terminator, embedded
// NULs and non-printable bytes are reported as flags, not smuggled into text.
func renderASCII(p payload) (string, TagAnomaly) {
	var an TagAnomaly
	// bytes.TrimRight on the slice: no whole-blob string copy, so a 2 MB
	// bogus-count ASCII field costs nothing.
	trimmed := bytes.TrimRight(p.data, "\x00")
	if len(trimmed) == len(p.data) && !p.truncated() {
		// When the value is truncated, truncation already explains the missing
		// terminator; flagging both would double-count one defect.
		an |= AnomalyNoNULTerminator
	}
	s, tan := sanitizeText(trimmed)
	if s == "" {
		s = "<empty>"
	}
	return s, an | tan
}

// renderUndefined shows UNDEFINED fields as text when they decode to printable
// ASCII (ExifVersion is literally "0232"), decodes the charset-prefixed
// comment tags, identifies MakerNote vendors, and otherwise emits capped hex.
func renderUndefined(kind IFDKind, tag TagID, p payload, order binary.ByteOrder) (string, TagAnomaly) {
	raw := p.data

	switch kind.namespace() {
	case IFDExif:
		switch tag {
		case exifTagUserComment:
			if s, an, ok := renderCharsetPrefixed(raw, order); ok {
				return s, an
			}
		case exifTagMakerNote:
			return renderMakerNote(raw, p.declared)
		}
	case IFDGPS:
		// GPSProcessingMethod / GPSAreaInformation use the same 8-byte
		// character-code prefix as UserComment. "GPS" vs "CELLID" vs "WLAN"
		// here tells you whether the coordinates came from a real fix.
		if tag == gpsTagProcessingMethod || tag == gpsTagAreaInformation {
			if s, an, ok := renderCharsetPrefixed(raw, order); ok {
				return s, an
			}
		}
	}

	var an TagAnomaly
	probe := raw
	if len(probe) > maxTextProbeBytes {
		probe = probe[:maxTextProbeBytes]
		an |= AnomalyOversizedValue
	}
	if body := bytes.TrimRight(probe, "\x00"); isPrintableASCII(body) {
		if s, tan := sanitizeText(body); s != "" {
			return s, an | tan
		}
	}
	return hexPreview(raw, p.declared), an
}

const (
	exifTagUserComment     TagID = 0x9286
	exifTagMakerNote       TagID = 0x927C
	gpsTagProcessingMethod TagID = 0x001B
	gpsTagAreaInformation  TagID = 0x001C
)

// renderCharsetPrefixed decodes the 8-byte character-code prefix used by
// UserComment and the GPS text tags. UNICODE is actually decoded, not
// hex-dumped: on iOS and macOS a screenshot writes the literal word
// "Screenshot" here in UTF-16, which is the single strongest screenshot
// signal a file carries. Hex-dumping it throws that away.
func renderCharsetPrefixed(raw []byte, order binary.ByteOrder) (string, TagAnomaly, bool) {
	if len(raw) < 8 {
		return "", 0, false
	}
	prefix, body := raw[:8], raw[8:]
	switch string(prefix) {
	case "ASCII\x00\x00\x00":
		s, an := sanitizeText(bytes.Trim(body, "\x00 "))
		if s == "" {
			return "[ASCII] <empty>", an, true
		}
		return "[ASCII] " + s, an, true

	case "UNICODE\x00":
		if s, an := decodeUTF16(body, order); s != "" {
			return "[UNICODE] " + s, an, true
		}
		return "[UNICODE] " + hexPreview(body, uint64(len(body))), 0, true

	case "JIS\x00\x00\x00\x00\x00":
		// Shift-JIS transcoding needs x/text. If the payload happens to be
		// plain ASCII (common for lazy writers) show it; otherwise report
		// honestly instead of pretending the bytes are text.
		if isPrintableASCII(body) {
			if s, an := sanitizeText(bytes.Trim(body, "\x00 ")); s != "" {
				return "[JIS] " + s, an, true
			}
		}
		return "[JIS, not transcoded] " + hexPreview(body, uint64(len(body))), 0, true

	case "\x00\x00\x00\x00\x00\x00\x00\x00":
		trimmed := bytes.Trim(body, "\x00 ")
		if len(trimmed) == 0 {
			return "[undefined charset] <empty>", 0, true
		}
		if looksUTF16(body, order) {
			if s, an := decodeUTF16(body, order); s != "" {
				return "[undefined charset, UTF-16 guess] " + s, an, true
			}
		}
		s, an := sanitizeText(trimmed)
		if s == "" {
			return "[undefined charset] " + hexPreview(body, uint64(len(body))), an, true
		}
		return "[undefined charset] " + s, an, true
	}
	return "", 0, false
}

// decodeUTF16 decodes NUL-terminated UTF-16 in the given order.
func decodeUTF16(b []byte, order binary.ByteOrder) (string, TagAnomaly) {
	var an TagAnomaly
	if order == nil {
		order = binary.LittleEndian
		an |= AnomalyNoByteOrder
	}
	if len(b) > maxTextProbeBytes {
		b = b[:maxTextProbeBytes&^1] // even cut: never split a code unit
		an |= AnomalyOversizedValue
	}
	n := len(b) / 2
	units := make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		u := order.Uint16(b[i*2:])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	if len(units) == 0 {
		return "", an
	}
	s, tan := sanitizeText([]byte(string(utf16.Decode(units))))
	return s, an | tan
}

// looksUTF16 heuristically detects UTF-16 text stored without a charset tag:
// most code units are ASCII, i.e. every other byte is zero.
func looksUTF16(b []byte, order binary.ByteOrder) bool {
	if len(b) < 4 || len(b)%2 != 0 {
		return false
	}
	if order == nil {
		order = binary.LittleEndian
	}
	bigEndian := order == binary.BigEndian
	n := len(b)
	if n > 64 {
		n = 64
	}
	pairs, hits := 0, 0
	for i := 0; i+1 < n; i += 2 {
		lo, hi := b[i], b[i+1]
		if bigEndian {
			lo, hi = hi, lo
		}
		pairs++
		if hi == 0 && lo >= 0x20 && lo < 0x7F {
			hits++
		}
	}
	return pairs > 0 && hits*4 >= pairs*3
}

// --- MakerNote --------------------------------------------------------------

// makerNoteSignatures maps the leading bytes of a MakerNote to its vendor.
// Knowing the vendor is worth more than 24 hex bytes: a MakerNote signature
// that disagrees with the Make tag is a strong splice indicator, and a note
// present with no recognizable signature is itself suspicious.
var makerNoteSignatures = []struct {
	prefix string
	vendor string
}{
	{"Apple iOS\x00", "Apple"},
	{"Nikon\x00", "Nikon"},
	{"NIKON", "Nikon"},
	{"OLYMP", "Olympus"},
	{"OM SYSTEM", "OM Digital"},
	{"FUJIFILM", "Fujifilm"},
	{"SONY DSC ", "Sony"},
	{"SONY CAM ", "Sony"},
	{"SONY MOBILE", "Sony"},
	{"Panasonic\x00", "Panasonic"},
	{"LEICA", "Leica"},
	{"PENTAX \x00", "Pentax"},
	{"AOC\x00", "Pentax/Casio"},
	{"QVC\x00", "Casio"},
	{"SIGMA\x00", "Sigma"},
	{"FOVEON\x00", "Sigma"},
	{"RICOH", "Ricoh"},
	{"SAMSUNG", "Samsung"},
	{"CANON", "Canon"},
	{"KDK", "Kodak"},
	{"Eastman Kodak", "Kodak"},
	{"MOT", "Motorola"},
	{"DJI", "DJI"},
	{"GoPro", "GoPro"},
	{"HUAWEI", "Huawei"},
	{"XIAOMI", "Xiaomi"},
	{"Google", "Google"},
	{"Reconyx", "Reconyx"},
}

func renderMakerNote(raw []byte, declared uint64) (string, TagAnomaly) {
	for _, sig := range makerNoteSignatures {
		if bytes.HasPrefix(raw, []byte(sig.prefix)) {
			return "[" + sig.vendor + "] " + hexPreview(raw, declared), 0
		}
	}
	return "[unrecognized vendor] " + hexPreview(raw, declared), 0
}

// --- Array and hex rendering ------------------------------------------------

// renderArray renders up to maxDumpArrayValues elements. Display truncation
// ("+N more") is distinct from data truncation, which renderValue appends.
func renderArray(p payload, elem func(i uint64) string) (string, TagAnomaly) {
	var an TagAnomaly
	n := p.availableElems()
	shown := n
	if shown > maxDumpArrayValues {
		shown = maxDumpArrayValues
	}
	var sb strings.Builder
	for i := uint64(0); i < shown; i++ {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(elem(i))
	}
	if shown < n {
		fmt.Fprintf(&sb, " \u2026 (+%d more)", n-shown)
		an |= AnomalyDisplayCapped
	}
	if sb.Len() == 0 {
		return "<empty>", an
	}
	return sb.String(), an
}

// elemFormatter returns a closure rendering element i of data for typ. data is
// guaranteed by payloadOf to hold whole elements only, and i is bounded by
// availableElems, so no bounds check is needed inside the hot loop.
func elemFormatter(typ TiffType, data []byte, order binary.ByteOrder) func(i uint64) string {
	at := func(i uint64, n int) []byte {
		off := i * uint64(n)
		return data[off : off+uint64(n)]
	}
	switch typ {
	case TypeByte, TypeUndefined:
		return func(i uint64) string { return strconv.FormatUint(uint64(data[i]), 10) }
	case TypeSByte:
		return func(i uint64) string { return strconv.FormatInt(int64(int8(data[i])), 10) }
	case TypeShort:
		return func(i uint64) string { return strconv.FormatUint(uint64(order.Uint16(at(i, 2))), 10) }
	case TypeSShort:
		return func(i uint64) string { return strconv.FormatInt(int64(int16(order.Uint16(at(i, 2)))), 10) }
	case TypeLong:
		return func(i uint64) string { return strconv.FormatUint(uint64(order.Uint32(at(i, 4))), 10) }
	case TypeSLong:
		return func(i uint64) string { return strconv.FormatInt(int64(int32(order.Uint32(at(i, 4)))), 10) }
	case TypeIFD:
		// A nested-IFD pointer is an offset, not a quantity. Rendering it as a
		// decimal hides that it should be cross-checked against the file size.
		return func(i uint64) string { return fmt.Sprintf("->0x%08X", order.Uint32(at(i, 4))) }
	case TypeRational:
		return func(i uint64) string {
			b := at(i, 8)
			return formatRational(int64(order.Uint32(b)), int64(order.Uint32(b[4:])))
		}
	case TypeSRational:
		return func(i uint64) string {
			b := at(i, 8)
			return formatRational(int64(int32(order.Uint32(b))), int64(int32(order.Uint32(b[4:]))))
		}
	case TypeFloat:
		return func(i uint64) string {
			return strconv.FormatFloat(float64(math.Float32frombits(order.Uint32(at(i, 4)))), 'g', -1, 32)
		}
	case TypeDouble:
		return func(i uint64) string {
			return strconv.FormatFloat(math.Float64frombits(order.Uint64(at(i, 8))), 'g', -1, 64)
		}
	case TypeLong8:
		return func(i uint64) string { return strconv.FormatUint(order.Uint64(at(i, 8)), 10) }
	case TypeSLong8:
		return func(i uint64) string { return strconv.FormatInt(int64(order.Uint64(at(i, 8))), 10) }
	case TypeIFD8:
		return func(i uint64) string { return fmt.Sprintf("->0x%016X", order.Uint64(at(i, 8))) }
	}
	return func(uint64) string { return "?" } // unreachable: typ validated by caller
}

// formatRational keeps the exact numerator/denominator (1/250, not 0.0040) and
// appends a decimal hint only when it adds information. 0/0 and n/0 are
// different defects: the first is an unwritten field, the second is corruption.
func formatRational(num, den int64) string {
	switch {
	case den == 0 && num == 0:
		return "0/0 (unset)"
	case den == 0:
		return strconv.FormatInt(num, 10) + "/0 (undefined)"
	case den == 1:
		return strconv.FormatInt(num, 10)
	case num%den == 0:
		return fmt.Sprintf("%d/%d (%d)", num, den, num/den)
	default:
		return fmt.Sprintf("%d/%d (%s)", num, den,
			strconv.FormatFloat(float64(num)/float64(den), 'g', 6, 64))
	}
}

// hexPreview renders "N bytes: XX XX ..." capped at maxDumpHexBytes. declared
// is the entry's claimed length, so a 2 MB MakerNote reports its real size
// even though only the first bytes are shown.
func hexPreview(raw []byte, declared uint64) string {
	if declared == 0 && len(raw) == 0 {
		return "0 bytes"
	}
	shown := raw
	if len(shown) > maxDumpHexBytes {
		shown = shown[:maxDumpHexBytes]
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d bytes: % X", declared, shown)
	if uint64(len(shown)) < declared {
		fmt.Fprintf(&sb, " \u2026 (+%d more)", declared-uint64(len(shown)))
	}
	return sb.String()
}

// --- Tag name tables (per numbering space) ----------------------------------
//
// Sources: TIFF 6.0, TIFF/EP, Exif 2.32 / 3.0, DNG 1.6, and the de-facto
// Adobe/Microsoft extensions. Names match exiftool where exiftool has one, so
// output can be diffed against a reference implementation.
//
// Deliberate omissions: the TIFF/EP aliases at 0x920B-0x9210, 0x9215 and
// 0x9217 duplicate the Exif tags at 0xA20B-0xA217 under the same names. They
// are left out so that no name appears twice inside one table.

func tagName(kind IFDKind, tag TagID) string {
	switch kind.namespace() {
	case IFD0:
		return ifd0TagNames[uint16(tag)]
	case IFDExif:
		return exifTagNames[uint16(tag)]
	case IFDGPS:
		return gpsTagNames[uint16(tag)]
	case IFDInterop:
		return interopTagNames[uint16(tag)]
	}
	return ""
}

var ifd0TagNames = map[uint16]string{
	0x00FE: "NewSubfileType",
	0x00FF: "SubfileType",
	0x0100: "ImageWidth",
	0x0101: "ImageLength",
	0x0102: "BitsPerSample",
	0x0103: "Compression",
	0x0106: "PhotometricInterpretation",
	0x0107: "Thresholding",
	0x0108: "CellWidth",
	0x0109: "CellLength",
	0x010A: "FillOrder",
	0x010D: "DocumentName",
	0x010E: "ImageDescription",
	0x010F: "Make",
	0x0110: "Model",
	0x0111: "StripOffsets",
	0x0112: "Orientation",
	0x0115: "SamplesPerPixel",
	0x0116: "RowsPerStrip",
	0x0117: "StripByteCounts",
	0x0118: "MinSampleValue",
	0x0119: "MaxSampleValue",
	0x011A: "XResolution",
	0x011B: "YResolution",
	0x011C: "PlanarConfiguration",
	0x011D: "PageName",
	0x0120: "FreeOffsets",
	0x0121: "FreeByteCounts",
	0x0128: "ResolutionUnit",
	0x0129: "PageNumber",
	0x012D: "TransferFunction",
	0x0131: "Software",
	0x0132: "DateTime",
	0x013B: "Artist",
	0x013C: "HostComputer",
	0x013D: "Predictor",
	0x013E: "WhitePoint",
	0x013F: "PrimaryChromaticities",
	0x0140: "ColorMap",
	0x0141: "HalftoneHints",
	0x0142: "TileWidth",
	0x0143: "TileLength",
	0x0144: "TileOffsets",
	0x0145: "TileByteCounts",
	0x014A: "SubIFDs",
	0x014C: "InkSet",
	0x0151: "TargetPrinter",
	0x0152: "ExtraSamples",
	0x0153: "SampleFormat",
	0x0154: "SMinSampleValue",
	0x0155: "SMaxSampleValue",
	0x0156: "TransferRange",
	0x0201: "JPEGInterchangeFormat",
	0x0202: "JPEGInterchangeFormatLength",
	0x0211: "YCbCrCoefficients",
	0x0212: "YCbCrSubSampling",
	0x0213: "YCbCrPositioning",
	0x0214: "ReferenceBlackWhite",
	0x02BC: "XMP",
	0x4746: "Rating",
	0x4749: "RatingPercent",
	0x828D: "CFARepeatPatternDim",
	0x828E: "CFAPattern",
	0x828F: "BatteryLevel",
	0x8298: "Copyright",
	0x83BB: "IPTC-NAA",
	0x8649: "PhotoshopImageResources",
	0x8769: "ExifIFDPointer",
	0x8773: "ICCProfile",
	0x8825: "GPSIFDPointer",
	0x9C9B: "XPTitle",
	0x9C9C: "XPComment",
	0x9C9D: "XPAuthor",
	0x9C9E: "XPKeywords",
	0x9C9F: "XPSubject",
	0xC4A5: "PrintIM",
	0xC612: "DNGVersion",
	0xC613: "DNGBackwardVersion",
	0xC614: "UniqueCameraModel",
	0xC615: "LocalizedCameraModel",
	0xC61A: "BlackLevel",
	0xC61D: "WhiteLevel",
	0xC621: "ColorMatrix1",
	0xC622: "ColorMatrix2",
	0xC62F: "CameraSerialNumber",
	0xC630: "LensInfo",
	0xC634: "DNGPrivateData",
	0xC635: "MakerNoteSafety",
	0xC65D: "RawDataUniqueID",
	0xC68B: "OriginalRawFileName",
	0xC68D: "ActiveArea",
	0xC71A: "PreviewApplicationName",
	0xC71B: "PreviewApplicationVersion",
	0xEA1C: "Padding",
	0xEA1D: "OffsetSchema",
}

var exifTagNames = map[uint16]string{
	0x829A: "ExposureTime",
	0x829D: "FNumber",
	0x8822: "ExposureProgram",
	0x8824: "SpectralSensitivity",
	0x8827: "ISOSpeedRatings",
	0x8828: "OECF",
	0x8829: "Interlace",
	0x882A: "TimeZoneOffset",
	0x882B: "SelfTimerMode",
	0x8830: "SensitivityType",
	0x8831: "StandardOutputSensitivity",
	0x8832: "RecommendedExposureIndex",
	0x8833: "ISOSpeed",
	0x8834: "ISOSpeedLatitudeyyy",
	0x8835: "ISOSpeedLatitudezzz",
	0x9000: "ExifVersion",
	0x9003: "DateTimeOriginal",
	0x9004: "DateTimeDigitized",
	0x9010: "OffsetTime",
	0x9011: "OffsetTimeOriginal",
	0x9012: "OffsetTimeDigitized",
	0x9101: "ComponentsConfiguration",
	0x9102: "CompressedBitsPerPixel",
	0x9201: "ShutterSpeedValue",
	0x9202: "ApertureValue",
	0x9203: "BrightnessValue",
	0x9204: "ExposureBiasValue",
	0x9205: "MaxApertureValue",
	0x9206: "SubjectDistance",
	0x9207: "MeteringMode",
	0x9208: "LightSource",
	0x9209: "Flash",
	0x920A: "FocalLength",
	0x9211: "ImageNumber",
	0x9212: "SecurityClassification",
	0x9213: "ImageHistory",
	0x9214: "SubjectArea",
	0x9216: "TIFFEPStandardID",
	0x927C: "MakerNote",
	0x9286: "UserComment",
	0x9290: "SubSecTime",
	0x9291: "SubSecTimeOriginal",
	0x9292: "SubSecTimeDigitized",
	0x9400: "Temperature",
	0x9401: "Humidity",
	0x9402: "Pressure",
	0x9403: "WaterDepth",
	0x9404: "Acceleration",
	0x9405: "CameraElevationAngle",
	0xA000: "FlashpixVersion",
	0xA001: "ColorSpace",
	0xA002: "PixelXDimension",
	0xA003: "PixelYDimension",
	0xA004: "RelatedSoundFile",
	0xA005: "InteropIFDPointer",
	0xA20B: "FlashEnergy",
	0xA20C: "SpatialFrequencyResponse",
	0xA20E: "FocalPlaneXResolution",
	0xA20F: "FocalPlaneYResolution",
	0xA210: "FocalPlaneResolutionUnit",
	0xA214: "SubjectLocation",
	0xA215: "ExposureIndex",
	0xA217: "SensingMethod",
	0xA300: "FileSource",
	0xA301: "SceneType",
	0xA302: "CFAPattern",
	0xA401: "CustomRendered",
	0xA402: "ExposureMode",
	0xA403: "WhiteBalance",
	0xA404: "DigitalZoomRatio",
	0xA405: "FocalLengthIn35mmFilm",
	0xA406: "SceneCaptureType",
	0xA407: "GainControl",
	0xA408: "Contrast",
	0xA409: "Saturation",
	0xA40A: "Sharpness",
	0xA40B: "DeviceSettingDescription",
	0xA40C: "SubjectDistanceRange",
	0xA420: "ImageUniqueID",
	0xA430: "CameraOwnerName",
	0xA431: "BodySerialNumber",
	0xA432: "LensSpecification",
	0xA433: "LensMake",
	0xA434: "LensModel",
	0xA435: "LensSerialNumber",
	0xA436: "ImageTitle",
	0xA437: "Photographer",
	0xA438: "ImageEditor",
	0xA439: "CameraFirmware",
	0xA43A: "RAWDevelopingSoftware",
	0xA43B: "ImageEditingSoftware",
	0xA43C: "MetadataEditingSoftware",
	0xA460: "CompositeImage",
	0xA461: "SourceImageNumberOfCompositeImage",
	0xA462: "SourceExposureTimesOfCompositeImage",
	0xA500: "Gamma",
	0xEA1C: "Padding",
	0xEA1D: "OffsetSchema",
}

var gpsTagNames = map[uint16]string{
	0x0000: "GPSVersionID",
	0x0001: "GPSLatitudeRef",
	0x0002: "GPSLatitude",
	0x0003: "GPSLongitudeRef",
	0x0004: "GPSLongitude",
	0x0005: "GPSAltitudeRef",
	0x0006: "GPSAltitude",
	0x0007: "GPSTimeStamp",
	0x0008: "GPSSatellites",
	0x0009: "GPSStatus",
	0x000A: "GPSMeasureMode",
	0x000B: "GPSDOP",
	0x000C: "GPSSpeedRef",
	0x000D: "GPSSpeed",
	0x000E: "GPSTrackRef",
	0x000F: "GPSTrack",
	0x0010: "GPSImgDirectionRef",
	0x0011: "GPSImgDirection",
	0x0012: "GPSMapDatum",
	0x0013: "GPSDestLatitudeRef",
	0x0014: "GPSDestLatitude",
	0x0015: "GPSDestLongitudeRef",
	0x0016: "GPSDestLongitude",
	0x0017: "GPSDestBearingRef",
	0x0018: "GPSDestBearing",
	0x0019: "GPSDestDistanceRef",
	0x001A: "GPSDestDistance",
	0x001B: "GPSProcessingMethod",
	0x001C: "GPSAreaInformation",
	0x001D: "GPSDateStamp",
	0x001E: "GPSDifferential",
	0x001F: "GPSHPositioningError",
}

var interopTagNames = map[uint16]string{
	0x0001: "InteroperabilityIndex",
	0x0002: "InteroperabilityVersion",
	0x1000: "RelatedImageFileFormat",
	0x1001: "RelatedImageWidth",
	0x1002: "RelatedImageLength",
}
