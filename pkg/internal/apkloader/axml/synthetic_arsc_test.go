package axml

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatSimpleValue(t *testing.T) {
	cases := []struct {
		typ  uint8
		data uint32
		want string
	}{
		{typeNull, 0, "@null"},
		{typeReference, 0x7f010002, "@0x7f010002"},
		{typeDynamicRef, 0x7f010002, "@0x7f010002"},
		{typeAttribute, 0x01010003, "?0x01010003"},
		{typeDynamicAttr, 0x01010003, "?0x01010003"},
		{typeString, 42, "strpool:42"},
		{typeIntDec, 12345, "12345"},
		{typeIntDec, 0xfffffff6, "-10"},
		{typeIntHex, 0xabcdef, "0x00abcdef"},
		{typeIntBoolean, 0, "false"},
		{typeIntBoolean, 1, "true"},
		{typeIntBoolean, 99, "true"},
		{typeIntColorARGB8, 0xff00ff00, "#ff00ff00"},
		{typeIntColorRGB8, 0x00ff00ff, "#00ff00ff"},
		{typeIntColorARGB4, 0xf0f0, "#0000f0f0"},
		{typeIntColorRGB4, 0x0f0f, "#00000f0f"},
		{typeFloat, 0x3f800000, "1"}, // 1.0 represented as float bits
		{typeDimension, 0x1234, "dim:0x00001234"},
		{typeFraction, 0x5678, "frac:0x00005678"},
		{99, 100, "0x64"}, // default
	}

	for _, tc := range cases {
		got := formatSimpleValue(tc.typ, tc.data, nil)
		if got.String != tc.want {
			t.Errorf("formatSimpleValue(%d, 0x%x) = %q, want %q", tc.typ, tc.data, got.String, tc.want)
		}
	}
}

func TestParseResConfigBoundaries(t *testing.T) {
	// 1. Buffer too small (< 4 bytes)
	_, _, err := parseResConfig([]byte{1, 2, 3})
	if err == nil || !strings.Contains(err.Error(), "too small") {
		t.Errorf("Expected 'too small' error, got %v", err)
	}

	// 2. Bad size (< 8)
	_, _, err = parseResConfig([]byte{4, 0, 0, 0})
	if err == nil || !strings.Contains(err.Error(), "bad size") {
		t.Errorf("Expected 'bad size' error, got %v", err)
	}

	// 3. Size > len(buf)
	_, _, err = parseResConfig([]byte{16, 0, 0, 0, 0, 0, 0, 0})
	if err == nil || !strings.Contains(err.Error(), "bad size") {
		t.Errorf("Expected 'bad size' error, got %v", err)
	}
}

func TestResConfigStringRepresentation(t *testing.T) {
	buildConfigBuf := func(size uint32, modifiers func(buf []byte)) []byte {
		buf := make([]byte, size)
		binary.LittleEndian.PutUint32(buf[0:4], size)
		if modifiers != nil {
			modifiers(buf)
		}
		return buf
	}

	// 1. Default config
	cfg, _, err := parseResConfig(buildConfigBuf(32, nil))
	if err != nil {
		t.Fatalf("parseResConfig failed: %v", err)
	}
	if cfg.String() != "default" {
		t.Errorf("Expected 'default', got %q", cfg.String())
	}

	// 2. MCC / MNC
	cfgMCC, _, err := parseResConfig(buildConfigBuf(12, func(b []byte) {
		binary.LittleEndian.PutUint16(b[4:6], 250) // mcc
		binary.LittleEndian.PutUint16(b[6:8], 99)  // mnc
	}))
	if err != nil {
		t.Fatalf("parseResConfig failed: %v", err)
	}
	if cfgMCC.String() != "mcc250-mnc99" {
		t.Errorf("Expected 'mcc250-mnc99', got %q", cfgMCC.String())
	}

	// 3. Locale: 2-letter codes (en-rUS)
	cfgLocale2, _, err := parseResConfig(buildConfigBuf(12, func(b []byte) {
		b[8] = 'e'
		b[9] = 'n'
		b[10] = 'u'
		b[11] = 's'
	}))
	if err != nil {
		t.Fatalf("parseResConfig failed: %v", err)
	}
	if cfgLocale2.String() != "en-rUS" {
		t.Errorf("Expected 'en-rUS', got %q", cfgLocale2.String())
	}

	// 4. Locale: 3-letter language code using high-bit trick (e.g. "eng")
	// The high-bit trick packs 3 characters into 15 bits:
	//   Language base: 'a'
	//   Bit 15 is set: 0x80
	//   For eng: e - a = 4, n - a = 13, g - a = 6
	//   Packed value: 0x8000 | (6 << 10) | (13 << 5) | 4
	//   Let's write it down:
	//   in[0] = 0x80 | (6 >> 3) = 0x80
	//   in[1] = ((6 & 7) << 5) | 13
	//   Wait, let's just make it simple: let's pack it correctly.
	//   Let's check unpackLocaleField logic:
	//     out[0] = base + (in[1] & 0x1F)
	//     out[1] = base + ((in[1] & 0xE0) >> 5) | ((in[0] & 0x03) << 3)
	//     out[2] = base + ((in[0] & 0x7C) >> 2)
	//   If we want "eng" (offsets e-a=4, n-a=13, g-a=6):
	//     in[1] & 0x1F = 4 => in[1] lower 5 bits = 4
	//     ((in[1] & 0xE0) >> 5) | ((in[0] & 0x03) << 3) = 13
	//       Let's choose: (in[1] & 0xE0) >> 5 = 5 (so in[1] upper 3 bits = 5)
	//                     (in[0] & 0x03) << 3 = 8 (so in[0] lower 2 bits = 1)
	//       Then 5 | 8 = 13.
	//     (in[0] & 0x7C) >> 2 = 6 => (in[0] & 0x7C) = 24 => in[0] bits 2..6 = 6
	//     And in[0] must have high bit 0x80 set.
	//     So:
	//       in[0] = 0x80 | (6 << 2) | 1 = 0x80 | 24 | 1 = 0x99
	//       in[1] = (5 << 5) | 4 = 160 | 4 = 164 (0xA4)
	cfgLocale3, _, err := parseResConfig(buildConfigBuf(12, func(b []byte) {
		b[8] = 0x99
		b[9] = 0xA4
	}))
	if err != nil {
		t.Fatalf("parseResConfig failed: %v", err)
	}
	if !strings.HasPrefix(cfgLocale3.String(), "eng") {
		t.Errorf("Expected locale string starting with 'eng', got %q", cfgLocale3.String())
	}

	// 5. Orientations
	orientations := map[uint8]string{
		1: "port",
		2: "land",
		3: "square",
	}
	for o, expected := range orientations {
		cfgO, _, err := parseResConfig(buildConfigBuf(14, func(b []byte) {
			b[12] = o
		}))
		if err != nil {
			t.Fatalf("parseResConfig failed: %v", err)
		}
		if cfgO.String() != expected {
			t.Errorf("Expected orientation %q, got %q", expected, cfgO.String())
		}
	}

	// 6. Densities
	densities := map[uint16]string{
		0xffff: "anydpi",
		120:    "ldpi",
		160:    "mdpi",
		213:    "tvdpi",
		240:    "hdpi",
		320:    "xhdpi",
		480:    "xxhdpi",
		640:    "xxxhdpi",
		500:    "500dpi",
	}
	for d, expected := range densities {
		cfgD, _, err := parseResConfig(buildConfigBuf(16, func(b []byte) {
			binary.LittleEndian.PutUint16(b[14:16], d)
		}))
		if err != nil {
			t.Fatalf("parseResConfig failed: %v", err)
		}
		if cfgD.String() != expected {
			t.Errorf("Expected density %q, got %q", expected, cfgD.String())
		}
	}

	// 7. SDK Version
	cfgSDK, _, err := parseResConfig(buildConfigBuf(28, func(b []byte) {
		binary.LittleEndian.PutUint16(b[24:26], 26) // sdkVersion
	}))
	if err != nil {
		t.Fatalf("parseResConfig failed: %v", err)
	}
	if cfgSDK.String() != "v26" {
		t.Errorf("Expected 'v26', got %q", cfgSDK.String())
	}
}

func TestARSCFileLoading(t *testing.T) {
	// Test ParseARSCFile with nonexistent file
	_, err := ParseARSCFile("nonexistent_arsc_file_12345.arsc")
	if err == nil {
		t.Error("Expected error loading nonexistent file")
	}

	// Test ParseARSCFile with invalid content
	tmpDir, err := os.MkdirTemp("", "arsc-test")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	invalidPath := filepath.Join(tmpDir, "invalid.arsc")
	if err := os.WriteFile(invalidPath, []byte("invalid-content"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err = ParseARSCFile(invalidPath)
	if err == nil {
		t.Error("Expected error parsing invalid ARSC file")
	}
}

func TestUTF16DecodingEdgeCases(t *testing.T) {
	// 1. decodeFixedUTF16 empty
	if decodeFixedUTF16([]byte{}) != "" {
		t.Error("Expected empty string for empty UTF-16 buffer")
	}

	// 2. decodeFixedUTF16 with only NULs
	if decodeFixedUTF16([]byte{0, 0, 0, 0}) != "" {
		t.Error("Expected empty string for NUL-only buffer")
	}

	// 3. decodeUTF16 with invalid surrogate pair (missing low surrogate)
	badSurrogates := []uint16{0xD800, 0x0041} // High surrogate followed by 'A'
	got := decodeUTF16(badSurrogates)
	if len(got) != 2 || got[0] != '\uFFFD' || got[1] != 'A' {
		t.Errorf("Unexpected decodeUTF16 output for bad surrogates: %q", string(got))
	}

	// 4. decodeUTF16 with stray low surrogate
	strayLow := []uint16{0xDC00}
	gotLow := decodeUTF16(strayLow)
	if len(gotLow) != 1 || gotLow[0] != '\uFFFD' {
		t.Errorf("Unexpected decodeUTF16 output for stray low surrogate: %q", string(gotLow))
	}
}

func TestParseStrpoolIdx(t *testing.T) {
	// 1. Correct format
	idx, ok := parseStrpoolIdx("strpool:12345")
	if !ok || idx != 12345 {
		t.Errorf("parseStrpoolIdx failed for valid input: got %d, %v", idx, ok)
	}

	// 2. Missing prefix
	_, ok = parseStrpoolIdx("12345")
	if ok {
		t.Error("Expected parseStrpoolIdx to fail without prefix")
	}

	// 3. Non-digit character
	_, ok = parseStrpoolIdx("strpool:12a45")
	if ok {
		t.Error("Expected parseStrpoolIdx to fail with non-digit character")
	}
}
