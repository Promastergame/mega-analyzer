package media

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// --- helpers ----------------------------------------------------------------

// Named tfLE/tfBE/tagEntry rather than le/entry to avoid colliding with any
// helper already present in exif_test.go.

func tfLE(buf []byte) *tiffFile { return &tiffFile{buf: buf, order: binary.LittleEndian} }
func tfBE(buf []byte) *tiffFile { return &tiffFile{buf: buf, order: binary.BigEndian} }

func tagEntry(typ TiffType, count uint32, off int) tiffEntry {
	return tiffEntry{typ: uint16(typ), count: count, valOffset: off}
}

// --- value formatting -------------------------------------------------------

func TestFormatTiffValue(t *testing.T) {
	tests := []struct {
		name  string
		buf   []byte
		kind  IFDKind
		tag   TagID
		e     tiffEntry
		want  string
		flags TagAnomaly
	}{
		{
			name: "short",
			buf:  []byte{42, 0},
			e:    tagEntry(TypeShort, 1, 0),
			want: "42",
		},
		{
			name: "sshort negative",
			buf:  []byte{0xFF, 0xFF},
			e:    tagEntry(TypeSShort, 1, 0),
			want: "-1",
		},
		{
			name: "rational keeps fraction",
			buf:  []byte{1, 0, 0, 0, 0xFA, 0, 0, 0},
			e:    tagEntry(TypeRational, 1, 0),
			want: "1/250 (0.004)",
		},
		{
			name: "rational n over zero",
			buf:  []byte{7, 0, 0, 0, 0, 0, 0, 0},
			e:    tagEntry(TypeRational, 1, 0),
			want: "7/0 (undefined)",
		},
		{
			name: "rational zero over zero is unset not corrupt",
			buf:  make([]byte, 8),
			e:    tagEntry(TypeRational, 1, 0),
			want: "0/0 (unset)",
		},
		{
			name: "srational exact division",
			buf:  []byte{0xFE, 0xFF, 0xFF, 0xFF, 2, 0, 0, 0},
			e:    tagEntry(TypeSRational, 1, 0),
			want: "-2/2 (-1)",
		},
		{
			name: "float",
			buf:  []byte{0x00, 0x00, 0x80, 0x3F},
			e:    tagEntry(TypeFloat, 1, 0),
			want: "1",
		},
		{
			name: "ascii terminated",
			buf:  []byte("Canon\x00"),
			e:    tagEntry(TypeASCII, 6, 0),
			want: "Canon",
		},
		{
			name:  "ascii without terminator is flagged",
			buf:   []byte("ABC"),
			e:     tagEntry(TypeASCII, 3, 0),
			want:  "ABC",
			flags: AnomalyNoNULTerminator,
		},
		{
			name:  "ascii with embedded nul is flagged",
			buf:   []byte("AB\x00CD\x00"),
			e:     tagEntry(TypeASCII, 6, 0),
			want:  "ABCD",
			flags: AnomalyEmbeddedNUL,
		},
		{
			name: "undefined printable is text",
			buf:  []byte("0232"),
			e:    tagEntry(TypeUndefined, 4, 0),
			want: "0232",
		},
		{
			name: "undefined binary is hex",
			buf:  []byte{0x00, 0x01, 0x02, 0x03},
			e:    tagEntry(TypeUndefined, 4, 0),
			want: "4 bytes: 00 01 02 03",
		},
		{
			name: "user comment ascii prefix",
			buf:  []byte("ASCII\x00\x00\x00hello"),
			kind: IFDExif,
			tag:  exifTagUserComment,
			e:    tagEntry(TypeUndefined, 13, 0),
			want: "[ASCII] hello",
		},
		{
			name:  "zero count",
			buf:   []byte{1, 2, 3, 4},
			e:     tagEntry(TypeShort, 0, 0),
			want:  "<empty>",
			flags: AnomalyZeroCount,
		},
		{
			name:  "unrecognized type",
			buf:   []byte{1, 2},
			e:     tagEntry(99, 1, 0),
			want:  "<unrecognized type 99, count 1>",
			flags: AnomalyUnrecognizedType,
		},
		{
			name:  "offset out of range",
			buf:   []byte{1, 2},
			e:     tagEntry(TypeShort, 1, 10),
			want:  "<value offset 10 outside 2-byte TIFF blob, count 1>",
			flags: AnomalyOffsetOutOfRange,
		},
		{
			// Regression: the old parseIFD dropped this entry entirely, so the
			// claim/reality mismatch never reached the report.
			name:  "short read is reported not dropped",
			buf:   []byte{1, 0, 2, 0, 3},
			e:     tagEntry(TypeShort, 4, 0),
			want:  "1, 2 <truncated: 4 of 8 bytes readable>",
			flags: AnomalyValueTruncated,
		},
		{
			name:  "long array is display capped",
			buf:   make([]byte, 40),
			e:     tagEntry(TypeByte, 40, 0),
			want:  "\u2026 (+24 more)",
			flags: AnomalyDisplayCapped,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, an := formatTiffValue(tfLE(tc.buf), tc.kind, tc.tag, tc.e)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("value = %q, want it to contain %q", got, tc.want)
			}
			if tc.flags != 0 && !an.Has(tc.flags) {
				t.Fatalf("anomalies = %v, want %v set", an, tc.flags)
			}
		})
	}
}

func TestFormatTiffValue_BigEndian(t *testing.T) {
	got, _ := formatTiffValue(tfBE([]byte{0x01, 0x00}), IFD0, 0, tagEntry(TypeShort, 1, 0))
	if got != "256" {
		t.Fatalf("big-endian SHORT = %q, want 256", got)
	}
}

// TYPE_14 with a bogus offset must still report the offset anomaly: the offset
// is wrong independently of whether this build knows the type.
func TestUnknownType_StillReportsOffset(t *testing.T) {
	_, an := formatTiffValue(tfLE([]byte{1, 2}), IFD0, 0, tagEntry(14, 1, 999))
	if !an.Has(AnomalyOffsetOutOfRange) || !an.Has(AnomalyUnrecognizedType) {
		t.Fatalf("anomalies = %v, want both unrecognized_type and offset_out_of_range", an)
	}
}

// The iOS/macOS screenshot marker lives in a UTF-16 UserComment. Hex-dumping
// it, as the previous implementation did, discarded the strongest screenshot
// signal a file carries.
func TestUserComment_UTF16IsDecoded(t *testing.T) {
	buf := append([]byte("UNICODE\x00"), utf16LE("Screenshot")...)
	got, _ := formatTiffValue(tfLE(buf), IFDExif, exifTagUserComment,
		tagEntry(TypeUndefined, uint32(len(buf)), 0))
	if got != "[UNICODE] Screenshot" {
		t.Fatalf("UserComment = %q, want \"[UNICODE] Screenshot\"", got)
	}
}

// XP* tags are UTF-16LE BYTE arrays regardless of the TIFF byte order.
func TestXPTag_DecodedInBothByteOrders(t *testing.T) {
	buf := utf16LE("hi")
	for _, tf := range []*tiffFile{tfLE(buf), tfBE(buf)} {
		got, _ := formatTiffValue(tf, IFD0, 0x9C9C, tagEntry(TypeByte, uint32(len(buf)), 0))
		if got != "hi" {
			t.Fatalf("XPComment = %q, want \"hi\"", got)
		}
	}
}

func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2+2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return append(out, 0, 0)
}

func TestMakerNote_VendorSignature(t *testing.T) {
	buf := append([]byte("Apple iOS\x00"), 1, 2, 3)
	got, _ := formatTiffValue(tfLE(buf), IFDExif, exifTagMakerNote,
		tagEntry(TypeUndefined, uint32(len(buf)), 0))
	if !strings.HasPrefix(got, "[Apple] ") {
		t.Fatalf("MakerNote = %q, want an [Apple] prefix", got)
	}
}

func TestSanitizeText_NoFalseInvalidUTF8(t *testing.T) {
	// A multi-byte rune straddling the probe boundary must be dropped whole,
	// not sliced - a false forensic flag is worse than a missed one.
	raw := append([]byte(strings.Repeat("a", maxTextProbeBytes-1)), []byte("\u00E9")...)
	_, an := sanitizeText(raw)
	if an.Has(AnomalyInvalidUTF8) {
		t.Fatal("probe truncation raised a bogus invalid_utf8 flag")
	}
	if !an.Has(AnomalyOversizedValue) {
		t.Fatal("probe truncation should be reported as oversized_value")
	}
}

func TestSanitizeText_BidiSpoofing(t *testing.T) {
	for _, r := range []string{"\u202E", "\u200F", "\u2028", "\uFEFF", "\u2066"} {
		if _, an := sanitizeText([]byte("a" + r + "b")); !an.Has(AnomalyBidiControl) {
			t.Fatalf("rune %q not flagged as a bidi/display control", r)
		}
	}
}

// --- naming -----------------------------------------------------------------

// GPS 0x0001 and Interop 0x0001 are different tags. A single flat table, as in
// the previous implementation, mislabels one of them.
func TestTagName_PerNamespace(t *testing.T) {
	if got := tagName(IFDGPS, 0x0001); got != "GPSLatitudeRef" {
		t.Fatalf("GPS 0x0001 = %q", got)
	}
	if got := tagName(IFDInterop, 0x0001); got != "InteroperabilityIndex" {
		t.Fatalf("Interop 0x0001 = %q", got)
	}
	if got := tagName(IFD0, 0x0001); got != "" {
		t.Fatalf("IFD0 0x0001 = %q, want \"\" (unknown, do not guess)", got)
	}
	if got := tagName(IFD1, 0x0110); got != "Model" {
		t.Fatalf("IFD1 shares the baseline space; 0x0110 = %q", got)
	}
}

func TestNameTables_WellFormed(t *testing.T) {
	tables := map[string]map[uint16]string{
		"ifd0": ifd0TagNames, "exif": exifTagNames,
		"gps": gpsTagNames, "interop": interopTagNames,
	}
	for tableName, table := range tables {
		seen := make(map[string]uint16, len(table))
		for tag, name := range table {
			if name == "" {
				t.Errorf("%s: 0x%04X has an empty name", tableName, tag)
			}
			if prev, dup := seen[name]; dup {
				t.Errorf("%s: %q used for both 0x%04X and 0x%04X", tableName, name, prev, tag)
			}
			seen[name] = tag
			for _, r := range name {
				ok := r == '_' || r == '-' ||
					(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
				if !ok {
					t.Errorf("%s: %q contains %q", tableName, name, r)
				}
			}
		}
	}
}

func TestTiffTypeTable(t *testing.T) {
	// Type 13 (IFD) must be recognized: treating it as unknown makes Size()
	// return 0 and silently drops the whole Exif SubIFD.
	if TypeIFD.Size() != 4 || TypeIFD.String() != "IFD" {
		t.Fatalf("type 13 = %v/%d, want IFD/4", TypeIFD, TypeIFD.Size())
	}
	if TiffType(0).valid() || TiffType(14).valid() || TiffType(999).valid() {
		t.Fatal("types 0, 14 and 999 must not be considered valid")
	}
	if got := TiffType(14).String(); got != "TYPE_14" {
		t.Fatalf("TiffType(14) = %q", got)
	}
}

// --- serialization ----------------------------------------------------------

// Every named type must round-trip, or a stored report cannot be read back.
func TestTiffTagView_JSONRoundTrip(t *testing.T) {
	in := TiffTagView{
		IFD: IFDExif, Tag: 0x927C, Name: "MakerNote", Type: TypeUndefined,
		Count: 3, Offset: 8, Declared: 3, Available: 3,
		Anomalies: AnomalyValueTruncated | AnomalyDisplayCapped,
		Value:     "3 bytes: 01 02 03",
	}
	blob, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	// Tag must be readable text, not the decimal 37500.
	if !strings.Contains(string(blob), `"Tag":"0x927C"`) {
		t.Fatalf("Tag not marshalled as hex text: %s", blob)
	}
	var out TiffTagView
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	if out != in {
		t.Fatalf("round trip changed the value:\n got %+v\nwant %+v", out, in)
	}
}

func TestNamedTypes_TextRoundTrip(t *testing.T) {
	for _, k := range []IFDKind{IFDUnknown, IFD0, IFD1, IFDExif, IFDGPS, IFDInterop, IFDSub, IFDMakerNote, IFDKind(9)} {
		var got IFDKind
		if err := got.UnmarshalText([]byte(k.String())); err != nil || got != k {
			t.Fatalf("IFDKind(%d) round trip: got %d, err %v", k, got, err)
		}
	}
	for _, ty := range []TiffType{TypeByte, TypeRational, TypeIFD, TypeIFD8, TiffType(14)} {
		var got TiffType
		if err := got.UnmarshalText([]byte(ty.String())); err != nil || got != ty {
			t.Fatalf("TiffType(%d) round trip: got %d, err %v", ty, got, err)
		}
	}
	for _, a := range []TagAnomaly{0, AnomalyZeroCount, AnomalyBidiControl | AnomalyInvalidUTF8} {
		var got TagAnomaly
		if err := got.UnmarshalText([]byte(a.String())); err != nil || got != a {
			t.Fatalf("TagAnomaly(%d) round trip: got %d, err %v", a, got, err)
		}
	}
	var bad TagAnomaly
	if err := bad.UnmarshalText([]byte("not_a_flag")); err == nil {
		t.Fatal("an unknown anomaly name must be an error, not a silent drop")
	}
}

// An empty IFD must marshal to [] rather than null, as it did before.
func TestDumpAllTags_EmptyIsNotNull(t *testing.T) {
	views := DumpAllTags(tfLE(nil), IFD0, nil)
	if views == nil {
		t.Fatal("DumpAllTags returned nil for an empty IFD")
	}
	if blob, _ := json.Marshal(views); string(blob) != "[]" {
		t.Fatalf("empty dump marshalled to %s, want []", blob)
	}
}

func TestDumpAllTags_OrderAndInline(t *testing.T) {
	buf := []byte("Canon\x00\x00\x00")
	ifd := map[uint16]tiffEntry{
		0x0110: tagEntry(TypeASCII, 6, 0),
		0x0112: tagEntry(TypeShort, 1, 0),
		0x010F: tagEntry(TypeASCII, 6, 0),
	}
	views := DumpAllTags(tfLE(buf), IFD0, ifd)
	if len(views) != 3 {
		t.Fatalf("got %d rows, want 3", len(views))
	}
	if views[0].Tag != 0x010F || views[1].Tag != 0x0110 || views[2].Tag != 0x0112 {
		t.Fatalf("rows are not tag-ordered: %v", views)
	}
	if views[0].Name != "Make" || views[2].Name != "Orientation" {
		t.Fatalf("names not resolved: %+v", views)
	}
	if views[0].Inline {
		t.Error("a 6-byte ASCII value does not fit the 4-byte slot")
	}
	if !views[2].Inline {
		t.Error("a 1-element SHORT does fit the 4-byte slot")
	}
}

// --- hostile input ----------------------------------------------------------

func TestFormatTiffValue_Hostile(t *testing.T) {
	buf := make([]byte, 64)
	for _, tf := range []*tiffFile{tfLE(buf), tfBE(buf), {buf: buf}} {
		for typ := uint16(0); typ <= 18; typ++ {
			for _, count := range []uint32{0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF} {
				for _, off := range []int{-1, 0, 63, 64, 65, 1 << 30} {
					e := tiffEntry{typ: typ, count: count, valOffset: off}
					for _, kind := range []IFDKind{IFD0, IFDExif, IFDGPS} {
						v, _ := formatTiffValue(tf, kind, 0x9286, e)
						if v == "" {
							t.Fatalf("empty value for typ=%d count=%d off=%d", typ, count, off)
						}
						if len(v) > maxDumpValueChars+128 {
							t.Fatalf("unbounded output (%d bytes) for typ=%d count=%d", len(v), typ, count)
						}
					}
				}
			}
		}
	}
}

// FuzzFormatTiffValue checks real invariants, not merely "did not panic".
// Run a 32-bit job too: on amd64 an int(uint32) count cannot wrap, so the
// overflow class this file guards against is unreachable there.
//
//	GOARCH=386 go test ./media/
func FuzzFormatTiffValue(f *testing.F) {
	f.Add([]byte("Canon\x00"), uint16(2), uint32(6), int64(0))
	f.Add([]byte("ASCII\x00\x00\x00hi"), uint16(7), uint32(10), int64(0))
	f.Add([]byte{0, 0, 0, 0}, uint16(13), uint32(1), int64(0))

	f.Fuzz(func(t *testing.T, buf []byte, typ uint16, count uint32, off int64) {
		if off > 1<<40 || off < -(1<<40) {
			t.Skip()
		}
		e := tiffEntry{typ: typ, count: count, valOffset: int(off)}
		for _, tf := range []*tiffFile{tfLE(buf), tfBE(buf), {buf: buf}} {
			for _, kind := range []IFDKind{IFD0, IFDExif, IFDGPS, IFDInterop} {
				v, an := formatTiffValue(tf, kind, 0x9286, e)
				if v == "" {
					t.Fatal("empty display value")
				}
				if !utf8.ValidString(v) {
					t.Fatalf("invalid UTF-8 in report output: %q", v)
				}
				for _, r := range v {
					if r < 0x20 && r != ' ' {
						t.Fatalf("control rune %q leaked into output %q", r, v)
					}
					if isBidiControl(r) {
						t.Fatalf("bidi control leaked into output %q", v)
					}
				}
				if len(v) > maxDumpValueChars+128 {
					t.Fatalf("output not bounded: %d bytes", len(v))
				}
				// Determinism: a forensic report must be reproducible.
				if v2, an2 := formatTiffValue(tf, kind, 0x9286, e); v2 != v || an2 != an {
					t.Fatal("formatTiffValue is not deterministic")
				}
				p, _ := tf.payloadOf(e)
				if p.available > p.declared {
					t.Fatalf("available %d exceeds declared %d", p.available, p.declared)
				}
				if p.elemSize > 0 && p.available%uint64(p.elemSize) != 0 {
					t.Fatal("payload holds a partial element")
				}
			}
		}
	})
}
