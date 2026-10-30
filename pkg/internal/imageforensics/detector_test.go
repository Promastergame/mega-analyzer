package imageforensics

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

// buildPNG returns a minimal valid PNG with optional trailing bytes.
// CRCs are computed correctly so the parser does not flag BadCRC.
func buildPNG(trailing []byte) []byte {
	var b bytes.Buffer
	b.Write(pngMagic)

	writeChunk := func(ctype string, payload []byte) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
		b.Write(lenBuf[:])
		b.WriteString(ctype)
		b.Write(payload)
		// Real CRC: covers chunk type + chunk data.
		crcInput := make([]byte, 0, 4+len(payload))
		crcInput = append(crcInput, ctype...)
		crcInput = append(crcInput, payload...)
		var crcBuf [4]byte
		binary.BigEndian.PutUint32(crcBuf[:], crc32.ChecksumIEEE(crcInput))
		b.Write(crcBuf[:])
	}

	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], 8) // width
	binary.BigEndian.PutUint32(ihdr[4:8], 8) // height
	ihdr[8] = 8                              // bit depth
	ihdr[9] = 2                              // color type: RGB
	writeChunk("IHDR", ihdr)
	writeChunk("IEND", nil)
	if len(trailing) > 0 {
		b.Write(trailing)
	}
	return b.Bytes()
}

// buildPNGBadCRC builds a PNG whose IHDR CRC is intentionally wrong.
func buildPNGBadCRC() []byte {
	var b bytes.Buffer
	b.Write(pngMagic)

	writeChunkWithCRC := func(ctype string, payload []byte, crcVal uint32) {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
		b.Write(lenBuf[:])
		b.WriteString(ctype)
		b.Write(payload)
		var crcBuf [4]byte
		binary.BigEndian.PutUint32(crcBuf[:], crcVal)
		b.Write(crcBuf[:])
	}

	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], 8)
	binary.BigEndian.PutUint32(ihdr[4:8], 8)
	ihdr[8] = 8
	ihdr[9] = 2
	writeChunkWithCRC("IHDR", ihdr, 0xDEADBEEF)

	// IEND with correct CRC so the parser still terminates normally.
	correctIEND := crc32.ChecksumIEEE([]byte("IEND"))
	writeChunkWithCRC("IEND", nil, correctIEND)
	return b.Bytes()
}

// buildJPEG returns a minimal JPEG with optional trailing bytes.
func buildJPEG(trailing []byte) []byte {
	// SOI(FFD8) + JFIF APP0 + EOI(FFD9).
	jfif := []byte{
		0xFF, 0xD8,
		0xFF, 0xE0, 0x00, 0x10,
		'J', 'F', 'I', 'F', 0x00,
		0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
		0xFF, 0xD9,
	}
	if len(trailing) > 0 {
		jfif = append(jfif, trailing...)
	}
	return jfif
}

// buildWEBP returns a minimal RIFF/WEBP container.
func buildWEBP() []byte {
	body := []byte("WEBPVP8 \x10\x00\x00\x00")
	body = append(body, make([]byte, 16)...)
	hdr := make([]byte, 8)
	copy(hdr[:4], "RIFF")
	binary.LittleEndian.PutUint32(hdr[4:], uint32(len(body)))
	return append(hdr, body...)
}

func TestAnalyzeOK(t *testing.T) {
	rep := Analyze(buildPNG(nil), ".png")
	if rep.Verdict != VerdictOK {
		t.Fatalf("expected ok, got %q (reasons=%v)", rep.Verdict, rep.Reasons)
	}
	if rep.TrailingData != 0 {
		t.Fatalf("expected no trailing data, got %d", rep.TrailingData)
	}
	if rep.Width != 8 || rep.Height != 8 {
		t.Fatalf("expected 8x8, got %dx%d", rep.Width, rep.Height)
	}
	if len(rep.BadCRC) != 0 {
		t.Fatalf("expected no bad CRC, got %v", rep.BadCRC)
	}
}

func TestAnalyzeTrailingZip(t *testing.T) {
	rep := Analyze(buildPNG([]byte("PK\x03\x04...zip-payload...")), ".png")
	if rep.Verdict != VerdictPossibleEmbedded {
		t.Fatalf("expected possible embedded payload, got %q", rep.Verdict)
	}
	if len(rep.PolyglotSignals) == 0 || rep.PolyglotSignals[0] != "ZIP" {
		t.Fatalf("expected ZIP polyglot, got %v", rep.PolyglotSignals)
	}
	if len(rep.Reasons) == 0 {
		t.Fatal("expected non-empty reasons")
	}
}

func TestAnalyzeMimeMismatch(t *testing.T) {
	rep := Analyze([]byte("hello world"), ".png")
	if !IsAllowedVerdict(rep.Verdict) {
		t.Fatalf("verdict not allowed: %q", rep.Verdict)
	}
	if !rep.MimeMismatch {
		t.Fatal("expected MimeMismatch flag")
	}
}

func TestAnalyzePanicSafe(t *testing.T) {
	// Truncated PNG header + garbage — must not panic.
	data := append([]byte(nil), pngMagic...)
	data = append(data, 0xFF, 0xFF, 0xFF, 0xFF, 'I', 'H', 'D', 'R')
	rep := Analyze(data, ".png")
	if !IsAllowedVerdict(rep.Verdict) {
		t.Fatalf("verdict not in whitelist: %q", rep.Verdict)
	}
}

func TestAnalyzeJPEGTrailingZip(t *testing.T) {
	rep := Analyze(buildJPEG([]byte("PK\x03\x04hello")), ".jpg")
	if rep.Verdict != VerdictPossibleEmbedded {
		t.Fatalf("expected possible embedded payload, got %q", rep.Verdict)
	}
	if len(rep.PolyglotSignals) == 0 {
		t.Fatal("expected polyglot signal")
	}
}

func TestAnalyzePotentiallyUnsafeWhenExtensionLies(t *testing.T) {
	// .png extension but raw ZIP bytes -> mime mismatch + application/* -> potentially unsafe.
	rep := Analyze([]byte("PK\x03\x04hello-world-archive-payload"), ".png")
	if rep.Verdict != VerdictPotentiallyUnsafe {
		t.Fatalf("expected potentially unsafe, got %q (reasons=%v)", rep.Verdict, rep.Reasons)
	}
}

func TestAnalyzePNGBadCRC(t *testing.T) {
	rep := Analyze(buildPNGBadCRC(), ".png")
	if len(rep.BadCRC) == 0 {
		t.Fatal("expected BadCRC entry for IHDR")
	}
	if rep.Verdict != VerdictSuspicious {
		t.Fatalf("expected suspicious for bad CRC, got %q", rep.Verdict)
	}
}

func TestVerdictWhitelistEnforced(t *testing.T) {
	// Property test: every Analyze invocation produces a whitelist verdict.
	cases := [][]byte{
		nil,
		{},
		[]byte("not-an-image"),
		buildPNG(nil),
		buildPNG([]byte("MZ trailing pe")),
		buildPNG([]byte{0x7F, 'E', 'L', 'F'}),
		buildJPEG(nil),
		buildJPEG([]byte("PK\x03\x04")),
		buildWEBP(),
		{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0xFF, 0xD9},
	}
	for i, c := range cases {
		rep := Analyze(c, ".png")
		if !IsAllowedVerdict(rep.Verdict) {
			t.Fatalf("case %d: verdict not allowed: %q", i, rep.Verdict)
		}
	}
}

func TestSanitizeVerdictForbidsVirus(t *testing.T) {
	if got := SanitizeVerdict("virus"); got == "virus" {
		t.Fatal("SanitizeVerdict allowed 'virus'")
	}
	if got := SanitizeVerdict(""); got == "virus" {
		t.Fatal("SanitizeVerdict allowed 'virus' for empty")
	}
}

func TestShannonEmpty(t *testing.T) {
	if got := Shannon(nil); got != 0 {
		t.Fatalf("expected 0 for nil, got %v", got)
	}
	if got := Shannon([]byte{}); got != 0 {
		t.Fatalf("expected 0 for empty, got %v", got)
	}
}

func TestShannonRange(t *testing.T) {
	// Uniform distribution -> entropy near 8.
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	h := Shannon(data)
	if h < 7.0 || h > 8.0 {
		t.Fatalf("expected entropy ~8, got %v", h)
	}
	// Constant byte -> entropy 0.
	data = bytes.Repeat([]byte{0x42}, 128)
	if h := Shannon(data); h != 0 {
		t.Fatalf("expected 0 for constant, got %v", h)
	}
}

func TestSniffWebP(t *testing.T) {
	if got := SniffMime(buildWEBP()); got != "image/webp" {
		t.Fatalf("expected image/webp, got %q", got)
	}
}

func TestSniffHEICBrands(t *testing.T) {
	mk := func(brand string) []byte {
		// 4 bytes size (unused) + "ftyp" + brand + padding.
		out := []byte{0, 0, 0, 0x20}
		out = append(out, "ftyp"...)
		out = append(out, brand...)
		out = append(out, make([]byte, 16)...)
		return out
	}
	for _, brand := range []string{"heic", "heix", "hevc", "hevx", "mif1", "msf1"} {
		if got := SniffMime(mk(brand)); got != "image/heic" {
			t.Fatalf("brand %q: expected image/heic, got %q", brand, got)
		}
	}
	for _, brand := range []string{"avif", "avis"} {
		if got := SniffMime(mk(brand)); got != "image/avif" {
			t.Fatalf("brand %q: expected image/avif, got %q", brand, got)
		}
	}
}

func TestPNGTrailingData(t *testing.T) {
	rep := Analyze(buildPNG([]byte("plain trailing bytes")), ".png")
	if rep.TrailingData == 0 {
		t.Fatal("expected trailing data")
	}
	if rep.Verdict != VerdictPossibleEmbedded {
		t.Fatalf("expected possible embedded, got %q", rep.Verdict)
	}
}

func TestWEBPTruncated(t *testing.T) {
	// Build a header that lies about the payload length.
	hdr := []byte("RIFF")
	sz := make([]byte, 4)
	binary.LittleEndian.PutUint32(sz, 0x100000) // claim 1 MB
	hdr = append(hdr, sz...)
	hdr = append(hdr, "WEBPVP8 "...)
	hdr = append(hdr, make([]byte, 8)...)
	rep := Analyze(hdr, ".webp")
	if !rep.Truncated {
		t.Fatal("expected Truncated flag")
	}
	if !IsAllowedVerdict(rep.Verdict) {
		t.Fatalf("verdict not allowed: %q", rep.Verdict)
	}
}

func TestAnalyzeNeverPanics(t *testing.T) {
	bad := [][]byte{
		nil,
		{},
		{0x89},
		append([]byte(nil), pngMagic...),
		append(append([]byte(nil), pngMagic...), 0xFF, 0xFF, 0xFF, 0xFF),
		{0xFF, 0xD8},
		[]byte("RIFF\xff\xff\xff\xffWEBP"),
	}
	for i, b := range bad {
		rep := Analyze(b, ".png")
		if !IsAllowedVerdict(rep.Verdict) {
			t.Fatalf("case %d: verdict not allowed: %q", i, rep.Verdict)
		}
	}
}

func FuzzAnalyze(f *testing.F) {
	f.Add(buildPNG(nil))
	f.Add(buildPNG([]byte("PK\x03\x04")))
	f.Add(buildJPEG(nil))
	f.Add(buildJPEG([]byte("trailing")))
	f.Add(buildWEBP())
	f.Add([]byte("\x89PNG\r\n\x1a\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rep := Analyze(data, ".png")
		if !IsAllowedVerdict(rep.Verdict) {
			t.Fatalf("verdict not in whitelist: %q", rep.Verdict)
		}
	})
}
