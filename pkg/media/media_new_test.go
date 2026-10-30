package media

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// ─── Bug fix regression tests ─────────────────────────────────────────────

func TestBugFix_MP4FtypAtOffset4(t *testing.T) {
	d := NewDetector()

	// ftyp at offset 4 — should detect as MP4
	mp4 := make([]byte, 1024)
	copy(mp4[4:], "ftypisom")
	sigs, _ := d.Detect(mp4)
	found := false
	for _, s := range sigs {
		if s.Type == SignalMagic && s.Value == string(TypeMP4) && s.Offset == 4 {
			found = true
			break
		}
	}
	if !found {
		t.Error("MP4 ftyp at offset 4 should be detected")
	}

	// ftyp at offset 100 — should NOT detect as MP4
	bad := make([]byte, 1024)
	copy(bad[100:], "ftypisom")
	sigs2, _ := d.Detect(bad)
	for _, s := range sigs2 {
		if s.Type == SignalMagic && s.Value == string(TypeMP4) {
			t.Error("ftyp at offset 100 should NOT be detected as MP4")
		}
	}
}

func TestBugFix_SVGLength(t *testing.T) {
	d := NewDetector()

	// <?xml at start
	data := []byte("<?xml version=\"1.0\"?>\n<svg>")
	sigs, _ := d.Detect(data)
	for _, s := range sigs {
		if s.Type == SignalMagic && s.Value == string(TypeSVG) {
			if s.Length != 5 {
				t.Errorf("SVG <?xml should have length 5, got %d", s.Length)
			}
			if s.Offset != 0 {
				t.Errorf("SVG <?xml should be at offset 0, got %d", s.Offset)
			}
		}
	}

	// <svg at start
	data2 := []byte("<svg xmlns=\"http://www.w3.org/2000/svg\">")
	sigs2, _ := d.Detect(data2)
	for _, s := range sigs2 {
		if s.Type == SignalMagic && s.Value == string(TypeSVG) {
			if s.Length != 4 {
				t.Errorf("SVG <svg should have length 4, got %d", s.Length)
			}
		}
	}
}

func TestBugFix_FusionDeadCode(t *testing.T) {
	f := NewFusionLayer()

	// Two signals far apart — should create two regions
	sigs := []Signal{
		{Type: SignalMagic, Value: "jpeg", Offset: 0, Length: 3, Confidence: 1.0},
		{Type: SignalPayload, Value: "SQLi", Offset: 100000, Length: 10, Confidence: 0.9, Severity: 0.8},
	}
	regions := f.Fuse(sigs)
	if len(regions) != 2 {
		t.Errorf("Expected 2 regions for widely separated signals, got %d", len(regions))
	}
}

func TestBugFix_PNGScrubbing(t *testing.T) {
	// Build a PNG with tEXt chunk
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	textChunk := buildPNGChunk("tEXt", []byte("Comment\x00Hello World"))
	iendChunk := buildPNGChunk("IEND", nil)

	png := append(pngSig, textChunk...)
	png = append(png, iendChunk...)

	result := ScrubMetadata(png, TypePNG)
	if !result.Success {
		t.Errorf("Scrubbing should succeed: %s", result.Message)
	}
	if !strings.Contains(result.Message, "1") {
		t.Errorf("Should report 1 scrubbed chunk, got: %s", result.Message)
	}

	// Verify the tEXt chunk is completely removed
	if bytes.Contains(result.Data, []byte("tEXt")) {
		t.Error("tEXt chunk should be fully removed after scrubbing")
	}
	if bytes.Contains(result.Data, []byte("Hello World")) {
		t.Error("tEXt content should be removed after scrubbing")
	}

	// Verify IEND is still present
	if !bytes.Contains(result.Data, []byte("IEND")) {
		t.Error("IEND chunk should be preserved after scrubbing")
	}
}

func TestBugFix_PNGInjectPayload(t *testing.T) {
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	ihdr := buildPNGChunk("IHDR", make([]byte, 13))
	iend := buildPNGChunk("IEND", nil)

	png := append(pngSig, ihdr...)
	png = append(png, iend...)

	result := InjectPayload(png, TypePNG, "test_secret_data")
	if !result.Success {
		t.Errorf("PNG injection should succeed: %s", result.Message)
	}
	if !strings.Contains(result.Message, "tEXt") {
		t.Error("Should report injection into tEXt chunk")
	}
	if !bytes.Contains(result.Data, []byte("MEGA")) {
		t.Error("Injected tEXt chunk should contain MEGA keyword")
	}
	if !bytes.Contains(result.Data, []byte("test_secret_data")) {
		t.Error("Injected data should be present")
	}
}

func TestBugFix_JPEGScrubbing(t *testing.T) {
	// Build JPEG with SOI + APP1 (EXIF) + APP0 (JFIF) + SOS
	var jpeg []byte
	jpeg = append(jpeg, 0xFF, 0xD8) // SOI

	// APP1 (EXIF) — should be removed
	app1Len := 20
	jpeg = append(jpeg, 0xFF, 0xE1)
	jpeg = append(jpeg, byte(app1Len>>8), byte(app1Len&0xFF))
	jpeg = append(jpeg, make([]byte, app1Len-2)...)

	// APP0 (JFIF) — should be removed
	app0Len := 16
	jpeg = append(jpeg, 0xFF, 0xE0)
	jpeg = append(jpeg, byte(app0Len>>8), byte(app0Len&0xFF))
	jpeg = append(jpeg, make([]byte, app0Len-2)...)

	// DQT (structural) — should be preserved
	dqtLen := 35
	jpeg = append(jpeg, 0xFF, 0xDB)
	jpeg = append(jpeg, byte(dqtLen>>8), byte(dqtLen&0xFF))
	dqtData := make([]byte, dqtLen-2)
	dqtData[0] = 0x00 // table 0
	jpeg = append(jpeg, dqtData...)

	// SOS
	jpeg = append(jpeg, 0xFF, 0xDA, 0x00, 0x08)
	jpeg = append(jpeg, make([]byte, 6)...)

	result := ScrubMetadata(jpeg, TypeJPEG)
	if !result.Success {
		t.Errorf("JPEG scrubbing should succeed: %s", result.Message)
	}
	if !strings.Contains(result.Message, "2") {
		t.Errorf("Should report 2 scrubbed segments (APP0+APP1), got: %s", result.Message)
	}
	// DQT should be preserved
	if !bytes.Contains(result.Data, []byte{0xFF, 0xDB}) {
		t.Error("DQT structural marker should be preserved")
	}
}

func TestBugFix_zTXtCompressionMethod(t *testing.T) {
	// Build a zTXt chunk with invalid compression method (0x01 instead of 0x00)
	chunkData := []byte("Comment\x01compressed_data_here")
	out := make(map[string]string)
	parsePNGzTXt(chunkData, out)
	if _, exists := out["Comment"]; exists {
		t.Error("zTXt with non-zero compression method should be rejected")
	}
}

// ─── New feature tests ────────────────────────────────────────────────────

func TestContext_AnalysisDepth(t *testing.T) {
	ctx := DefaultContext()
	if ctx.Depth != DepthStandard {
		t.Errorf("DefaultContext should be DepthStandard, got %d", ctx.Depth)
	}

	ctx2 := &AnalysisContext{Depth: DepthDeep}
	if ctx2.Depth != DepthDeep {
		t.Error("Should support DepthDeep")
	}
}

func TestContext_Cancelled(t *testing.T) {
	ctx := &AnalysisContext{}
	if ctx.cancelled() {
		t.Error("Nil context should not be cancelled")
	}
}

func TestEntropyHeatmap_Build(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	hm := BuildEntropyHeatmap(data, 256)
	if hm == nil {
		t.Fatal("Heatmap should not be nil")
	}
	if hm.CellSize != 256 {
		t.Errorf("CellSize should be 256, got %d", hm.CellSize)
	}
	if hm.Width != 4 {
		t.Errorf("Width should be 4 (1024/256), got %d", hm.Width)
	}
	if len(hm.Grid) != 1 || len(hm.Grid[0]) != 4 {
		t.Errorf("Grid should be 1x4, got %dx%d", len(hm.Grid), len(hm.Grid[0]))
	}
}

func TestEntropyHeatmap_EmptyData(t *testing.T) {
	hm := BuildEntropyHeatmap([]byte{}, 256)
	if hm == nil {
		t.Fatal("Should return non-nil heatmap for empty data")
	}
	if hm.Width != 0 {
		t.Error("Width should be 0 for empty data")
	}
}

func TestSteganography_LSB(t *testing.T) {
	// Create data with biased LSB (simulating stego)
	data := make([]byte, 4096)
	for i := range data {
		data[i] = 0xFE // LSB = 0 always — very biased
	}

	signals := detectLSBFrequency(data)
	if len(signals) == 0 {
		t.Error("Should detect LSB anomaly in biased data")
	}
	if signals[0].Method != "lsb_frequency" {
		t.Errorf("Method should be lsb_frequency, got %s", signals[0].Method)
	}
}

func TestSteganography_UniformLSB(t *testing.T) {
	// Create data with approximately uniform LSB
	data := make([]byte, 4096)
	for i := range data {
		if i%2 == 0 {
			data[i] = 0x00 // LSB = 0
		} else {
			data[i] = 0x01 // LSB = 1
		}
	}

	signals := detectLSBFrequency(data)
	if len(signals) != 0 {
		t.Error("Should NOT detect anomaly in uniformly distributed LSB data")
	}
}

func TestTimeline_Build(t *testing.T) {
	meta := &MediaMetadata{
		Fields: map[string]string{
			"Date_Taken": "2024:01:15 10:30:00",
		},
		XMP: map[string]string{
			"CreateDate": "2024:01:15 10:30:00",
			"ModifyDate": "2024:02:20 14:00:00",
		},
	}

	tl := BuildTimeline(meta)
	if len(tl.Entries) < 2 {
		t.Errorf("Expected at least 2 timeline entries, got %d", len(tl.Entries))
	}

	// Should be sorted by timestamp
	for i := 1; i < len(tl.Entries); i++ {
		if tl.Entries[i].Timestamp.Before(tl.Entries[i-1].Timestamp) {
			t.Error("Timeline entries should be sorted by timestamp")
		}
	}
}

func TestTimeline_AnomalyCreationAfterModification(t *testing.T) {
	meta := &MediaMetadata{
		XMP: map[string]string{
			"CreateDate": "2024:06:01 12:00:00",
			"ModifyDate": "2024:01:01 12:00:00", // modification before creation — anomaly
		},
	}

	tl := BuildTimeline(meta)
	if len(tl.Anomalies) == 0 {
		t.Error("Should detect creation-after-modification anomaly")
	}

	found := false
	for _, a := range tl.Anomalies {
		if a.Type == "creation_after_modification" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Should find creation_after_modification anomaly type")
	}
}

func TestFingerprint_JPEG(t *testing.T) {
	// Build minimal JPEG with Photoshop comment
	var jpeg []byte
	jpeg = append(jpeg, 0xFF, 0xD8) // SOI

	// COM marker with Adobe content
	comment := []byte("Adobe Photoshop")
	comLen := len(comment) + 2
	jpeg = append(jpeg, 0xFF, 0xFE)
	jpeg = append(jpeg, byte(comLen>>8), byte(comLen&0xFF))
	jpeg = append(jpeg, comment...)

	// SOS
	jpeg = append(jpeg, 0xFF, 0xDA, 0x00, 0x02)

	fp := FingerprintFile(jpeg, TypeJPEG)
	if fp == nil {
		t.Fatal("Should return fingerprint for JPEG")
	}
	if !strings.Contains(fp.Encoder, "Photoshop") {
		t.Errorf("Should identify as Photoshop, got: %s", fp.Encoder)
	}
}

func TestSimilarity_ByteCompare(t *testing.T) {
	a := []byte("hello world")
	b := []byte("hello world")
	sim := CompareBytes(a, b)
	if sim.Similarity != 1.0 {
		t.Errorf("Identical bytes should have similarity 1.0, got %f", sim.Similarity)
	}

	c := []byte("goodbye world")
	sim2 := CompareBytes(a, c)
	if sim2.Similarity > 0.8 {
		t.Errorf("Different bytes should have low similarity, got %f", sim2.Similarity)
	}
}

func TestSimilarity_EmptyFiles(t *testing.T) {
	sim := CompareBytes([]byte{}, []byte{})
	if sim.Similarity != 1.0 {
		t.Error("Two empty files should be identical")
	}
	sim2 := CompareBytes([]byte("data"), []byte{})
	if sim2.Similarity != 0.0 {
		t.Error("Empty vs non-empty should have 0 similarity")
	}
}

func TestCrossAnalysis_Basic(t *testing.T) {
	results := []AnalysisResult{
		{
			Format:         TypePNG,
			Classification: Classification{PrimaryFormat: TypePNG, RecoveredData: map[string]string{"Camera_Make": "Canon"}},
			RiskScore:      10.0,
		},
		{
			Format:         TypeJPEG,
			Classification: Classification{PrimaryFormat: TypeJPEG, RecoveredData: map[string]string{"Camera_Make": "Nikon"}},
			RiskScore:      30.0,
		},
	}

	report := CrossAnalyze(results)
	if report.TotalFiles != 2 {
		t.Errorf("Should report 2 files, got %d", report.TotalFiles)
	}
	if report.FormatCounts[TypePNG] != 1 {
		t.Error("Should count 1 PNG")
	}
	if report.FormatCounts[TypeJPEG] != 1 {
		t.Error("Should count 1 JPEG")
	}
	if report.MaxRiskScore != 30.0 {
		t.Errorf("Max risk should be 30, got %f", report.MaxRiskScore)
	}
}

func TestReport_GenerateJSON(t *testing.T) {
	result := AnalysisResult{
		FilePath:       "test.jpg",
		Format:         TypeJPEG,
		Classification: Classification{PrimaryFormat: TypeJPEG, Confidence: 0.9},
		RiskScore:      25.0,
	}

	data := GenerateJSONReport(result, nil)
	if len(data) == 0 {
		t.Error("JSON report should not be empty")
	}
	if !bytes.Contains(data, []byte("test.jpg")) {
		t.Error("JSON should contain filename")
	}
}

func TestReport_GenerateText(t *testing.T) {
	result := AnalysisResult{
		FilePath:       "test.png",
		Format:         TypePNG,
		Classification: Classification{PrimaryFormat: TypePNG, Confidence: 0.95},
		RiskScore:      15.0,
	}

	text := GenerateTextReport(result, nil)
	if !strings.Contains(text, "MEGA-ANALYZER") {
		t.Error("Text report should contain header")
	}
	if !strings.Contains(text, "test.png") {
		t.Error("Text report should contain filename")
	}
}

func TestDeepPDF_DetectJavaScript(t *testing.T) {
	pdf := []byte("%PDF-1.4\n/JavaScript /JS (alert('xss')); ")
	threats := AnalyzePDF(pdf)
	found := false
	for _, th := range threats {
		if th.Type == "javascript" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Should detect JavaScript in PDF")
	}
}

func TestDeepMP4_ParseAtoms(t *testing.T) {
	// Build minimal MP4 with ftyp + moov atoms
	data := make([]byte, 256)
	// ftyp at offset 0
	binary.BigEndian.PutUint32(data[0:], 20) // size
	copy(data[4:], "ftyp")
	copy(data[8:], "isom")

	// moov at offset 20
	binary.BigEndian.PutUint32(data[20:], 100) // size
	copy(data[24:], "moov")

	atoms, _ := AnalyzeMP4(data)
	if len(atoms) < 2 {
		t.Errorf("Expected at least 2 atoms, got %d", len(atoms))
	}
	if atoms[0].Type != "ftyp" {
		t.Errorf("First atom should be ftyp, got %s", atoms[0].Type)
	}
}

func TestDeepGIF_DetectDelayAnomaly(t *testing.T) {
	// Build GIF with suspiciously short delay
	var gif []byte
	gif = append(gif, []byte("GIF89a")...)
	// Logical Screen Descriptor: width(2) + height(2) + packed(1) + bgColor(1) + aspect(1) = 7 bytes
	gif = append(gif, 0x01, 0x00) // width = 1
	gif = append(gif, 0x01, 0x00) // height = 1
	gif = append(gif, 0x00)       // packed byte (no GCT)
	gif = append(gif, 0x00)       // background color index
	gif = append(gif, 0x00)       // pixel aspect ratio

	// Graphic Control Extension: 0x21 0xF9 0x04 [data] 0x00
	gif = append(gif, 0x21, 0xF9, 0x04) // introducer + block size
	gif = append(gif, 0x00)             // packed byte
	gif = append(gif, 0x00, 0x00)       // delay = 0 centiseconds
	gif = append(gif, 0x00)             // transparent color index
	gif = append(gif, 0x00)             // block terminator

	threats := AnalyzeGIF(gif)
	found := false
	for _, th := range threats {
		if th.Type == "delay_manipulation" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Should detect delay manipulation in GIF with delay=0")
	}
}

func TestScorer_FormatAware(t *testing.T) {
	s := NewScorer()

	// PDF with hidden APK — should be high risk
	class := Classification{
		PrimaryFormat: TypePDF,
		IsPolyglot:    true,
		HiddenFormats: []MediaType{TypeAPK},
	}
	score := s.Score(class, nil, GlobalStats{})
	if score < 50 {
		t.Errorf("PDF+APK polyglot should have high risk, got %f", score)
	}

	// Clean image — should be low risk
	class2 := Classification{
		PrimaryFormat: TypePNG,
		IsPolyglot:    false,
	}
	score2 := s.Score(class2, nil, GlobalStats{})
	if score2 > 10 {
		t.Errorf("Clean PNG should have low risk, got %f", score2)
	}
}

func TestAnalyzeDeep_Basic(t *testing.T) {
	engine := NewForensicEngine()

	// Minimal JPEG
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00}
	result, deep := engine.AnalyzeDeep(data, "test.jpg", "test.jpg")

	if result.Format == "" {
		t.Error("Should identify format")
	}
	if deep == nil {
		t.Error("Deep analysis should not be nil")
	}
	if deep.Heatmap == nil {
		t.Error("Heatmap should be populated")
	}
}

func TestBatchAnalyzer_NotNil(t *testing.T) {
	ba := NewBatchAnalyzer(4, nil)
	if ba == nil {
		t.Fatal("BatchAnalyzer should not be nil")
	}
	if ba.workers != 4 {
		t.Errorf("Workers should be 4, got %d", ba.workers)
	}
}

func TestStreamingAnalyzer_Fallback(t *testing.T) {
	engine := NewForensicEngine()
	sa := NewStreamingAnalyzer(engine, nil)

	// Test with a simple reader (falls back to full read)
	data := bytes.NewReader([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	result := sa.AnalyzeReader(data, "test.png", "test.png")
	if result.Format == "" {
		t.Error("Should identify PNG format")
	}
}

// ─── Test helpers ─────────────────────────────────────────────────────────

func buildPNGChunkForTest(typ string, data []byte) []byte {
	return buildPNGChunk(typ, data)
}

// Verify all new types are properly exported
func TestExportedTypes(t *testing.T) {
	// Context
	_ = DefaultContext()
	_ = &AnalysisContext{Depth: DepthDeep}

	// Heatmap
	_ = &EntropyHeatmap{}
	_ = &HeatmapRegion{}

	// Stego
	_ = &StegoSignal{}

	// Timeline
	_ = &TimelineEntry{}
	_ = &Timeline{}
	_ = &TimelineAnomaly{}

	// Fingerprint
	_ = &EncoderFingerprint{}

	// Watermark
	_ = &WatermarkSignal{}

	// Report
	_ = &ForensicReport{}
	_ = &RiskBreakdown{}

	// Deep analysis
	_ = &DeepAnalysis{}
	_ = &PDFThreat{}
	_ = &MP4Atom{}
	_ = &MP4Threat{}
	_ = &GIFThreat{}

	// Similarity
	_ = &SimilarityResult{}

	// Batch
	_ = &BatchAnalyzer{}
	_ = &NamedReader{}

	// Streaming
	_ = &StreamingAnalyzer{}
}
