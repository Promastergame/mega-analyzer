package media

import (
	"encoding/binary"
	"hash/crc32"
	"testing"
)

// ─── extractMediaMetadata / extractMediaMetadataFull ─────────────────────

func TestExtractMediaMetadata_NoExif(t *testing.T) {
	data := []byte("just some regular image data, no exif here")
	result := extractMediaMetadata(data, TypeJPEG, "file.jpg")
	// Garbage input yields parse warnings, never curated metadata: defects
	// are reported, not dropped silently.
	if result["Parse_Warnings"] == "" {
		t.Errorf("expected parse warnings for non-JPEG bytes, got %v", result)
	}
	for k := range result {
		if k != "Parse_Warnings" && k != "Parse_Warning_Count" {
			t.Errorf("expected no curated metadata for garbage input, got key %q (%v)", k, result)
		}
	}
}

func TestExtractMediaMetadata_PNGWithEXIFChunk(t *testing.T) {
	// Build a minimal PNG with a synthetic eXIf chunk carrying a TIFF buffer
	// with Make="TestCam" in IFD0, and a correct CRC32 over type+data.
	tiff := buildMinimalTIFFWithMake("TestCam")

	var buf []byte
	buf = append(buf, pngSignature...)
	buf = append(buf, buildPNGChunk("eXIf", tiff)...)
	buf = append(buf, buildPNGChunk("IEND", nil)...)

	full := extractMediaMetadataFull(buf, TypePNG, "photo.png")
	if full.Fields["Camera_Make"] != "TestCam" {
		t.Errorf("expected Camera_Make=TestCam, got Fields=%v", full.Fields)
	}
	if len(full.PNGChunks) == 0 {
		t.Error("expected PNGChunks to be populated")
	}
}

func TestExtractMediaMetadata_EmptyData(t *testing.T) {
	result := extractMediaMetadata([]byte{}, TypePNG, "file.png")
	// Empty input is itself a finding: a bad-signature warning, and nothing else.
	if result["Parse_Warnings"] == "" {
		t.Errorf("expected parse warnings for empty input, got %v", result)
	}
	for k := range result {
		if k != "Parse_Warnings" && k != "Parse_Warning_Count" {
			t.Errorf("expected no curated metadata for empty input, got key %q (%v)", k, result)
		}
	}
}

// ─── Detector.Detect method ───────────────────────────────────────────────

func TestDetector_Detect_EmptyData(t *testing.T) {
	d := NewDetector()
	signals, stats := d.Detect([]byte{})
	if len(signals) > 0 {
		t.Errorf("expected no signals in empty data, got %d", len(signals))
	}
	_ = stats
}

func TestDetector_Detect_PNG(t *testing.T) {
	d := NewDetector()
	// Minimal PNG header
	pngMagic := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	signals, stats := d.Detect(pngMagic)
	_ = signals
	if stats.MeanEntropy < 0 {
		t.Error("expected non-negative mean entropy")
	}
}

func TestDetector_Detect_JPEG(t *testing.T) {
	d := NewDetector()
	jpegMagic := []byte{0xFF, 0xD8, 0xFF, 0xE0}
	signals, stats := d.Detect(jpegMagic)
	_ = signals
	if stats.MaxEntropy < 0 {
		t.Error("expected non-negative max entropy")
	}
}

func TestDetector_Detect_Entropy_Uniform(t *testing.T) {
	d := NewDetector()
	// Low entropy data (uniform)
	data := []byte("aaaaaaaaaa")
	_, stats := d.Detect(data)
	if stats.MeanEntropy < 0 {
		t.Error("expected non-negative entropy")
	}
}

func TestDetector_Detect_Entropy_Random(t *testing.T) {
	d := NewDetector()
	// Higher entropy data
	data := []byte{0xFF, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE}
	_, stats := d.Detect(data)
	if stats.MaxEntropy < 0 {
		t.Error("expected non-negative max entropy")
	}
}

// ─── NewForensicEngine tests ──────────────────────────────────────────────

func TestNewForensicEngine_NotNil(t *testing.T) {
	engine := NewForensicEngine()
	if engine == nil {
		t.Fatal("expected non-nil engine")
	}
}

// ─── Analyze method ───────────────────────────────────────────────────────

func TestForensicEngine_Analyze_EmptyData(t *testing.T) {
	engine := NewForensicEngine()
	report := engine.Analyze([]byte{}, "path/to", "file.dat")
	_ = report
}

func TestForensicEngine_Analyze_PNGData(t *testing.T) {
	engine := NewForensicEngine()
	// Minimal PNG
	pngData := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0x00, 0x00, 0x00, 0x0D}
	report := engine.Analyze(pngData, "/images", "test.png")
	if report.Format == "" {
		t.Error("expected Format to be identified")
	}
}

func TestForensicEngine_Analyze_JPEGData(t *testing.T) {
	engine := NewForensicEngine()
	// Minimal JPEG
	jpegData := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00}
	report := engine.Analyze(jpegData, "/photos", "image.jpg")
	if report.Format == "" {
		t.Error("expected Format to be identified")
	}
}

func TestForensicEngine_Analyze_LargeData(t *testing.T) {
	engine := NewForensicEngine()
	// Large random data
	data := make([]byte, 10000)
	for i := range data {
		data[i] = byte(i % 256)
	}
	report := engine.Analyze(data, "/tmp", "large.bin")
	_ = report
}

// ─── AnalysisResult fields ────────────────────────────────────────────────

func TestAnalysisResult_RiskScore(t *testing.T) {
	engine := NewForensicEngine()
	report := engine.Analyze([]byte{0x89, 'P', 'N', 'G'}, "path", "file.png")
	if report.RiskScore < 0 {
		t.Errorf("expected non-negative risk score, got %f", report.RiskScore)
	}
}

func TestAnalysisResult_HasFilePath(t *testing.T) {
	engine := NewForensicEngine()
	report := engine.Analyze([]byte{0xFF, 0xD8, 0xFF}, "path", "file.jpg")
	if len(report.FilePath) == 0 {
		t.Error("expected FilePath to be set")
	}
}

func TestAnalysisResult_GlobalStats(t *testing.T) {
	engine := NewForensicEngine()
	report := engine.Analyze([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}, "path", "file.png")
	if report.GlobalStats.MeanEntropy < 0 {
		t.Errorf("expected non-negative mean entropy, got %f", report.GlobalStats.MeanEntropy)
	}
}

func TestAnalysisResult_Regions(t *testing.T) {
	engine := NewForensicEngine()
	report := engine.Analyze([]byte{0xFF, 0xD8, 0xFF, 0xE0}, "path", "file.jpg")
	if report.Regions == nil {
		t.Error("expected Regions to be a slice, not nil")
	}
}

// ─── Shared test fixture builders ─────────────────────────────────────────
// NOTE: pngSignature lives in exif.go (package level); do not redeclare it
// here — same-package redeclaration breaks the test build.

// buildPNGChunk assembles one length-prefixed, CRC-terminated PNG chunk.
func buildPNGChunk(typ string, data []byte) []byte {
	var buf []byte
	lenField := make([]byte, 4)
	binary.BigEndian.PutUint32(lenField, uint32(len(data)))
	buf = append(buf, lenField...)
	buf = append(buf, []byte(typ)...)
	buf = append(buf, data...)
	crc := crc32.ChecksumIEEE(append([]byte(typ), data...))
	crcField := make([]byte, 4)
	binary.BigEndian.PutUint32(crcField, crc)
	buf = append(buf, crcField...)
	return buf
}

// buildMinimalTIFFWithMake builds a little-endian TIFF/EXIF buffer with a
// single IFD0 entry: tag 0x010F (Make), type ASCII, holding the given value.
func buildMinimalTIFFWithMake(makeName string) []byte {
	val := makeName + "\x00" // NUL-terminated per TIFF ASCII convention
	valLen := len(val)

	var buf []byte
	buf = append(buf, 'I', 'I')   // little-endian byte order
	buf = append(buf, 42, 0)      // TIFF magic
	buf = append(buf, 8, 0, 0, 0) // offset to IFD0 = 8
	// IFD0: entry count = 1
	buf = append(buf, 1, 0)
	// entry: tag=0x010F, type=ASCII(2), count=valLen
	entry := make2Bytes(0x010F)
	entry = append(entry, make2Bytes(uint16(TypeASCII))...)
	entry = append(entry, make4Bytes(uint32(valLen))...)

	// Value offset: inline if <=4 bytes, else points past IFD (here: past
	// IFD0 count(2)+entry(12)+nextIFDOffset(4) = right after this header).
	valueOffset := uint32(8 + 2 + 12 + 4)
	if valLen <= 4 {
		var inline [4]byte
		copy(inline[:], val)
		entry = append(entry, inline[:]...)
	} else {
		entry = append(entry, make4Bytes(valueOffset)...)
	}
	buf = append(buf, entry...)
	buf = append(buf, 0, 0, 0, 0) // next IFD offset = 0 (none)

	if valLen > 4 {
		buf = append(buf, []byte(val)...)
	}
	return buf
}

func make2Bytes(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func make4Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}
