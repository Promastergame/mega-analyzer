package media

// Regression tests covering the P1/P2 fixes from the code review.

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// ─── P1: AnalyzeDeep must not panic on non-JPEG/PNG formats ─────────────────
// FingerprintFile returns nil for anything other than JPEG/PNG. The old code
// dereferenced that nil (deep.Fingerprint.Encoder) and panicked.
func TestAnalyzeDeep_NonJpegPngFormats(t *testing.T) {
	engine := NewForensicEngine()

	gif := append([]byte("GIF89a"), make([]byte, 512)...)

	pdf := append([]byte("%PDF-1.4\n"), make([]byte, 512)...)

	webp := make([]byte, 512)
	copy(webp[0:], "RIFF")
	binary.LittleEndian.PutUint32(webp[4:], uint32(len(webp)-8))
	copy(webp[8:], "WEBP")
	copy(webp[12:], "VP8 ")

	mp4 := make([]byte, 512)
	binary.BigEndian.PutUint32(mp4[0:], 16)
	copy(mp4[4:], "ftyp")
	copy(mp4[8:], "isom")

	unknown := bytes.Repeat([]byte{0xAB, 0xCD, 0x01, 0x02}, 128)

	cases := []struct {
		name string
		data []byte
	}{
		{"gif", gif},
		{"pdf", pdf},
		{"webp", webp},
		{"mp4", mp4},
		{"unknown", unknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A panic in AnalyzeDeep fails the test automatically.
			_, deep := engine.AnalyzeDeep(tc.data, tc.name, tc.name)
			if deep == nil {
				t.Fatalf("%s: deep analysis should not be nil for non-empty input", tc.name)
			}
			// Non-JPEG/PNG inputs have no encoder fingerprint; the key point is
			// that a nil fingerprint is handled safely rather than panicking.
			if deep.Fingerprint != nil {
				t.Logf("%s: unexpected non-nil fingerprint (acceptable): %+v", tc.name, deep.Fingerprint)
			}
		})
	}
}

// ─── P1: AnalyzePaths must actually read files from disk ────────────────────
func TestAnalyzePaths_ReadsRealFiles(t *testing.T) {
	dir := t.TempDir()

	// Real PNG on disk
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	png := append([]byte{}, pngSig...)
	png = append(png, buildPNGChunk("IHDR", make([]byte, 13))...)
	png = append(png, buildPNGChunk("IEND", nil)...)
	pngPath := filepath.Join(dir, "real.png")
	if err := os.WriteFile(pngPath, png, 0o644); err != nil {
		t.Fatalf("write png: %v", err)
	}

	// Real JPEG on disk
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01}
	jpeg = append(jpeg, make([]byte, 256)...)
	jpeg = append(jpeg, 0xFF, 0xD9)
	jpegPath := filepath.Join(dir, "real.jpg")
	if err := os.WriteFile(jpegPath, jpeg, 0o644); err != nil {
		t.Fatalf("write jpeg: %v", err)
	}

	missingPath := filepath.Join(dir, "does_not_exist.bin")

	ba := NewBatchAnalyzer(2, nil)
	results := ba.AnalyzePaths([]string{pngPath, jpegPath, missingPath})

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// PNG and JPEG must be read from disk and classified — NOT reported empty.
	if results[0].Error != "" {
		t.Errorf("png: unexpected error: %s", results[0].Error)
	}
	if results[0].Format != TypePNG {
		t.Errorf("png: expected format png, got %q", results[0].Format)
	}
	if results[1].Error != "" {
		t.Errorf("jpeg: unexpected error: %s", results[1].Error)
	}
	if results[1].Format != TypeJPEG {
		t.Errorf("jpeg: expected format jpeg, got %q", results[1].Format)
	}

	// A file that cannot be read MUST be flagged with an error and must NOT be
	// silently reported as a clean/safe (empty) result.
	if results[2].Error == "" {
		t.Error("missing file: expected an error, got none (silent false-negative)")
	}
	if results[2].Format != "" {
		t.Errorf("missing file: expected empty format, got %q", results[2].Format)
	}
}

// ─── P2: DepthQuick offsets on large files map to real positions ───────────
func TestDepthQuick_LargeFileOffsets(t *testing.T) {
	engine := NewForensicEngine()

	const size = smallFileThreshold + 1*1024*1024 // > 10 MB triggers chunked path
	buf := make([]byte, size)

	// JPEG header so the file classifies as JPEG.
	copy(buf[0:], []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00})

	// Embed a detectable payload near the very END of the file, isolated by
	// zero bytes so it is extracted as a single string.
	payload := []byte("<script>alert('xss-near-eof')</script>")
	payloadOffset := size - 1000
	copy(buf[payloadOffset:], payload)

	ctx := DefaultContext()
	ctx.Depth = DepthQuick
	sa := NewStreamingAnalyzer(engine, ctx)

	result := sa.AnalyzeReader(bytes.NewReader(buf), "large.jpg", "large.jpg")

	// With correct offset handling the tail-detected region must map to its
	// real position (~size-1000), not to a small offset inside the scratch
	// header/tail buffer.
	found := false
	var offsets []int
	for _, r := range result.Regions {
		offsets = append(offsets, r.StartOffset)
		if r.StartOffset >= smallFileThreshold {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a detected region at a real large offset (>= %d); got region offsets %v",
			smallFileThreshold, offsets)
	}
}

// ─── P2: RiskScore and RiskBreakdown must be consistent ────────────────────
func TestRiskBreakdownConsistency(t *testing.T) {
	s := NewScorer()
	class := Classification{
		PrimaryFormat: TypeJPEG,
		IsPolyglot:    true,
		HiddenFormats: []MediaType{TypeZIP},
		RecoveredData: map[string]string{},
	}
	regions := []Region{
		{StartOffset: 200000, EndOffset: 200100, FusedSeverity: 0.8, FusedConfidence: 0.9},
	}
	globalStats := GlobalStats{}

	score, rb := s.ScoreWithBreakdown(class, regions, globalStats)
	if score <= 0 {
		t.Fatalf("expected a positive risk score for a polyglot with a severe region, got %f", score)
	}
	if rb.TotalScore != score {
		t.Errorf("breakdown TotalScore (%f) should equal score (%f)", rb.TotalScore, score)
	}

	result := AnalysisResult{
		FilePath:       "poly.jpg",
		Format:         TypeJPEG,
		Classification: class,
		Regions:        regions,
		GlobalStats:    globalStats,
		RiskScore:      score,
	}

	report := GenerateReport(result, nil)
	if report.RiskBreakdown.TotalScore != result.RiskScore {
		t.Errorf("report TotalScore (%f) must match RiskScore (%f)",
			report.RiskBreakdown.TotalScore, result.RiskScore)
	}
	if report.RiskBreakdown.PolyglotRisk != rb.PolyglotRisk {
		t.Errorf("report PolyglotRisk (%f) should match scorer PolyglotRisk (%f)",
			report.RiskBreakdown.PolyglotRisk, rb.PolyglotRisk)
	}
}

// ─── P2: MP4 parsing with 64-bit largesize and size==0 atoms ───────────────
func TestAnalyzeMP4_64BitAndSizeZeroAtoms(t *testing.T) {
	buf := make([]byte, 64)

	// ftyp (normal 32-bit size == 16)
	binary.BigEndian.PutUint32(buf[0:], 16)
	copy(buf[4:], "ftyp")
	copy(buf[8:], "isom")

	// mdat using a 64-bit largesize (32-bit size field == 1)
	binary.BigEndian.PutUint32(buf[16:], 1)
	copy(buf[20:], "mdat")
	binary.BigEndian.PutUint64(buf[24:], 32) // real size = 32 bytes

	// free using size == 0 (extends to EOF)
	binary.BigEndian.PutUint32(buf[48:], 0)
	copy(buf[52:], "free")

	atoms, _ := AnalyzeMP4(buf)

	byType := map[string]MP4Atom{}
	for _, a := range atoms {
		byType[a.Type] = a
	}

	mdat, ok := byType["mdat"]
	if !ok {
		t.Fatal("mdat atom (64-bit largesize) should be parsed")
	}
	if mdat.Size != 32 {
		t.Errorf("mdat size should be 32 (from 64-bit largesize), got %d", mdat.Size)
	}
	if mdat.Offset != 16 {
		t.Errorf("mdat offset should be 16, got %d", mdat.Offset)
	}

	free, ok := byType["free"]
	if !ok {
		t.Fatal("free atom (size==0, extends to EOF) should be parsed")
	}
	if free.Size != len(buf)-48 {
		t.Errorf("free size should extend to EOF (%d), got %d", len(buf)-48, free.Size)
	}
}
