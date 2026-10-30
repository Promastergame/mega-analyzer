package imageforensics

import (
	"encoding/binary"
	"testing"
)

// buildEXIF constructs a tiny TIFF block with one ASCII entry.
//
// Layout: II marker, magic 0x002A, IFD offset 8, then 1 IFD entry with
// tag=Make, type=2 (ASCII), count=N, value-or-offset.
func buildEXIF(t *testing.T, withPrefix bool) []byte {
	t.Helper()
	value := "TestCam\x00" // null-terminated ASCII (8 bytes → must use offset)
	header := make([]byte, 0, 16)
	header = append(header, 'I', 'I')
	header = binary.LittleEndian.AppendUint16(header, 0x002A)
	header = binary.LittleEndian.AppendUint32(header, 8) // first IFD at offset 8

	ifd := make([]byte, 0, 32)
	ifd = binary.LittleEndian.AppendUint16(ifd, 1) // 1 entry

	// Pre-compute where the value will live: header(8) + ifd-count(2) + entry(12)
	// + next-ifd(4) = 26.
	const valueOffset = 26
	ifd = binary.LittleEndian.AppendUint16(ifd, tagMake)
	ifd = binary.LittleEndian.AppendUint16(ifd, 2) // ASCII
	ifd = binary.LittleEndian.AppendUint32(ifd, uint32(len(value)))
	ifd = binary.LittleEndian.AppendUint32(ifd, valueOffset)
	ifd = binary.LittleEndian.AppendUint32(ifd, 0) // next IFD = 0

	body := append(header, ifd...)
	body = append(body, []byte(value)...)

	if withPrefix {
		return append([]byte("Exif\x00\x00"), body...)
	}
	return body
}

func TestParseEXIFLittleEndianWithPrefix(t *testing.T) {
	got := ParseEXIF(buildEXIF(t, true))
	if got["Make"] != "TestCam" {
		t.Errorf("Make = %q, want %q", got["Make"], "TestCam")
	}
}

func TestParseEXIFLittleEndianNoPrefix(t *testing.T) {
	got := ParseEXIF(buildEXIF(t, false))
	if got["Make"] != "TestCam" {
		t.Errorf("Make = %q, want %q", got["Make"], "TestCam")
	}
}

func TestParseEXIFShortInputReturnsEmpty(t *testing.T) {
	if got := ParseEXIF([]byte{}); len(got) != 0 {
		t.Errorf("empty input should yield empty map, got %v", got)
	}
	if got := ParseEXIF([]byte{0x01, 0x02, 0x03}); len(got) != 0 {
		t.Errorf("tiny input should yield empty map, got %v", got)
	}
}

func TestParseEXIFInvalidByteOrderReturnsEmpty(t *testing.T) {
	bad := []byte{'X', 'X', 0, 0, 0, 0, 0, 0}
	if got := ParseEXIF(bad); len(got) != 0 {
		t.Errorf("invalid byte order should yield empty map, got %v", got)
	}
}

func TestParseEXIFWrongMagicReturnsEmpty(t *testing.T) {
	body := []byte{'I', 'I', 0xFF, 0xFF, 0, 0, 0, 0}
	if got := ParseEXIF(body); len(got) != 0 {
		t.Errorf("wrong magic should yield empty map, got %v", got)
	}
}

func TestParseEXIFGPSIFDPresent(t *testing.T) {
	body := make([]byte, 0, 64)
	body = append(body, 'I', 'I')
	body = binary.LittleEndian.AppendUint16(body, 0x002A)
	body = binary.LittleEndian.AppendUint32(body, 8)
	body = binary.LittleEndian.AppendUint16(body, 1) // 1 entry
	body = binary.LittleEndian.AppendUint16(body, tagGPSIFD)
	body = binary.LittleEndian.AppendUint16(body, 4) // arbitrary type
	body = binary.LittleEndian.AppendUint32(body, 1)
	body = binary.LittleEndian.AppendUint32(body, 0)
	body = binary.LittleEndian.AppendUint32(body, 0)

	got := ParseEXIF(body)
	if got["GPSIFD"] != "present" {
		t.Errorf("GPSIFD presence not detected: %v", got)
	}
}

func TestTagNameKnownAndUnknown(t *testing.T) {
	if tagName(tagMake) != "Make" {
		t.Error("tagName(Make) must yield Make")
	}
	if tagName(0xFFFF) != "" {
		t.Errorf("unknown tag should yield empty, got %q", tagName(0xFFFF))
	}
}

func TestReadEXIFStringInlineAndOffset(t *testing.T) {
	// Inline (≤4 bytes)
	if got := readEXIFString(nil, []byte{'a', 'b', 0, 0}, 0, 2); got != "ab" {
		t.Errorf("inline read = %q, want ab", got)
	}
	// Trim trailing NULs.
	if got := readEXIFString(nil, []byte{'A', 0, 0, 0}, 0, 4); got != "A" {
		t.Errorf("inline NUL-trim failed, got %q", got)
	}
	// Length <= 0 → empty
	if got := readEXIFString(nil, nil, 0, 0); got != "" {
		t.Error("zero length should be empty")
	}
	// Length larger than valueField
	if got := readEXIFString(nil, []byte{'a'}, 0, 5); got != "" {
		t.Error("over-long inline read should be empty")
	}
	// Offset out of range
	if got := readEXIFString([]byte{'x'}, []byte{0, 0, 0, 0}, 100, 5); got != "" {
		t.Error("bad offset should be empty")
	}
	// Non-UTF8 must be rejected
	if got := readEXIFString([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb}, []byte{0, 0, 0, 0}, 0, 5); got != "" {
		t.Error("invalid UTF-8 should be empty")
	}
	// Pure NULs become empty.
	if got := readEXIFString(nil, []byte{0, 0, 0, 0}, 0, 4); got != "" {
		t.Error("all-NUL must be empty")
	}
}
