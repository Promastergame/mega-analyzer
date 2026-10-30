package media

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// ─── SVG TESTS ──────────────────────────────────────────────────────────────

func TestParseSVGInfo_Base(t *testing.T) {
	// Simple valid SVG
	svgData := []byte(`<svg width="100" height="200" viewBox="0 0 100 200"></svg>`)
	res := parseSVGInfo(svgData)
	if res["SVG_Width"] != "100" || res["SVG_Height"] != "200" || res["SVG_ViewBox"] != "0 0 100 200" {
		t.Errorf("parseSVGInfo failed on basic SVG, got: %v", res)
	}

	// SVG with script and event handlers
	svgXSS := []byte(`<svg width="50" height="50"><script>alert(1)</script><rect onload="javascript:alert(2)" /></svg>`)
	resXSS := parseSVGInfo(svgXSS)
	if _, ok := resXSS["SVG_Has_Script"]; !ok {
		t.Errorf("parseSVGInfo failed to detect scripts/event handlers")
	}

	// Malformed XML recovery
	resMalformed := parseSVGInfo([]byte(`<svg width="100"><invalid`))
	if len(resMalformed) != 1 || resMalformed["SVG_Width"] != "100" {
		t.Errorf("parseSVGInfo failed to recover/decode malformed XML: %v", resMalformed)
	}

	// Truncation limit check
	hugeSVG := make([]byte, maxSVGScanBytes+100)
	copy(hugeSVG, []byte(`<svg width="999"></svg>`))
	resHuge := parseSVGInfo(hugeSVG)
	if resHuge["SVG_Width"] != "999" {
		t.Errorf("parseSVGInfo failed with large input: %v", resHuge)
	}
}

// ─── ICO TESTS ──────────────────────────────────────────────────────────────

func TestParseICOInfo_InvalidHeaders(t *testing.T) {
	// Truncated data
	if _, ok := parseICOInfo(nil); ok {
		t.Error("expected failure on nil data")
	}
	if _, ok := parseICOInfo(make([]byte, 5)); ok {
		t.Error("expected failure on less than 6 bytes")
	}

	// Non-zero reserved bytes
	badReserved := []byte{0x01, 0x00, 0x01, 0x00, 0x01, 0x00}
	if _, ok := parseICOInfo(badReserved); ok {
		t.Error("expected failure on non-zero reserved field")
	}

	// Invalid type
	badType := []byte{0x00, 0x00, 0x03, 0x00, 0x01, 0x00}
	if _, ok := parseICOInfo(badType); ok {
		t.Error("expected failure on type != 1 && type != 2")
	}

	// Zero count
	zeroCount := []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	if _, ok := parseICOInfo(zeroCount); ok {
		t.Error("expected failure on zero count")
	}

	// Too large count
	hugeCount := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x01} // count = 257
	if _, ok := parseICOInfo(hugeCount); ok {
		t.Error("expected failure on count > 256")
	}

	// Truncated entries
	truncEntries := []byte{0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x10, 0x10, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00}
	if _, ok := parseICOInfo(truncEntries); ok {
		t.Error("expected failure on truncated entry list")
	}
}

func TestParseICOInfo_Valid(t *testing.T) {
	// 1 icon entry: 16x16, bitCount=32, bytes=1000
	icoData := make([]byte, 6+16)
	binary.LittleEndian.PutUint16(icoData[0:2], 0)
	binary.LittleEndian.PutUint16(icoData[2:4], 1)
	binary.LittleEndian.PutUint16(icoData[4:6], 1)

	entryOff := 6
	icoData[entryOff] = 16                                               // width
	icoData[entryOff+1] = 16                                             // height
	binary.LittleEndian.PutUint16(icoData[entryOff+6:entryOff+8], 32)    // bitCount
	binary.LittleEndian.PutUint32(icoData[entryOff+8:entryOff+12], 1000) // bytesInRes

	entries, ok := parseICOInfo(icoData)
	if !ok || len(entries) != 1 {
		t.Fatalf("parseICOInfo failed to parse valid ICO: %v", entries)
	}
	if entries[0].Width != 16 || entries[0].Height != 16 || entries[0].BitDepth != 32 || entries[0].SizeBytes != 1000 {
		t.Errorf("ICO entry fields mismatched: %v", entries[0])
	}

	summary := summarizeICOEntries(entries)
	if !strings.Contains(summary, "16x16@32bit") {
		t.Errorf("summarizeICOEntries failed: %q", summary)
	}

	// Test zero height/width mapping to 256
	icoData2 := make([]byte, 6+16)
	binary.LittleEndian.PutUint16(icoData2[0:2], 0)
	binary.LittleEndian.PutUint16(icoData2[2:4], 2) // cursor type
	binary.LittleEndian.PutUint16(icoData2[4:6], 1)
	icoData2[6] = 0 // 256 width
	icoData2[7] = 0 // 256 height
	entries2, _ := parseICOInfo(icoData2)
	if entries2[0].Width != 256 || entries2[0].Height != 256 {
		t.Errorf("expected 0 value to map to 256, got w=%d, h=%d", entries2[0].Width, entries2[0].Height)
	}
}

// ─── WEBP TESTS ─────────────────────────────────────────────────────────────

func TestParseWEBPInfo(t *testing.T) {
	// Truncated header
	if _, ok := parseWEBPInfo(nil); ok {
		t.Error("expected parseWEBPInfo on nil data to fail")
	}

	// Basic invalid header
	if _, ok := parseWEBPInfo([]byte("RIFF1234WEBA")); ok {
		t.Error("expected failure on non-WEBP RIFF")
	}

	// Build a valid mock WEBP structure with VP8, EXIF, and XMP chunks
	var buf bytes.Buffer
	buf.WriteString("RIFF")
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // dummy total size
	buf.WriteString("WEBP")

	// VP8 chunk
	buf.WriteString("VP8 ")
	// Payload: 10 bytes: 3 frame tag, 3 start code, 4 width/height
	vp8Payload := []byte{0x00, 0x00, 0x00, 0x9d, 0x01, 0x2a, 0x64, 0x00, 0xc8, 0x00} // 100x200
	binary.Write(&buf, binary.LittleEndian, uint32(len(vp8Payload)))
	buf.Write(vp8Payload)

	// EXIF chunk
	exifPayload := []byte("fake exif data")
	buf.WriteString("EXIF")
	binary.Write(&buf, binary.LittleEndian, uint32(len(exifPayload)))
	buf.Write(exifPayload)

	// XMP chunk (odd size payload to test padding check)
	xmpPayload := []byte("<xmp/>") // 6 bytes
	buf.WriteString("XMP ")
	binary.Write(&buf, binary.LittleEndian, uint32(len(xmpPayload)))
	buf.Write(xmpPayload)

	info, ok := parseWEBPInfo(buf.Bytes())
	if !ok {
		t.Fatalf("parseWEBPInfo failed to parse mock WEBP")
	}
	if info.Width != 100 || info.Height != 200 || info.Format != "VP8" {
		t.Errorf("mismatched VP8 dimensions: w=%d, h=%d, fmt=%s", info.Width, info.Height, info.Format)
	}
	if string(info.EXIFChunk) != "fake exif data" {
		t.Errorf("EXIF chunk mismatch: %q", info.EXIFChunk)
	}
	if string(info.XMPChunk) != "<xmp/>" {
		t.Errorf("XMP chunk mismatch: %q", info.XMPChunk)
	}

	// Test VP8L (lossless WebP) chunk
	var bufL bytes.Buffer
	bufL.WriteString("RIFF")
	binary.Write(&bufL, binary.LittleEndian, uint32(0))
	bufL.WriteString("WEBP")
	bufL.WriteString("VP8L")
	// VP8L Payload: 0x2F signature, 4 bytes width-1/height-1
	// Width = 50 (49 = 0x31), Height = 60 (59 = 0x3B)
	// Bits: Width-1 (14 bits) | (Height-1) (14 bits) << 14
	// 49 | 59 << 14 = 49 | 966656 = 966705 (0xEC031)
	vp8lPayload := []byte{0x2F, 0x31, 0xC0, 0x0E, 0x00}
	binary.Write(&bufL, binary.LittleEndian, uint32(len(vp8lPayload)))
	bufL.Write(vp8lPayload)

	infoL, okL := parseWEBPInfo(bufL.Bytes())
	if !okL || infoL.Width != 50 || infoL.Height != 60 || infoL.Format != "VP8L" {
		t.Errorf("VP8L parsing failed: w=%d, h=%d, format=%s", infoL.Width, infoL.Height, infoL.Format)
	}

	// Test VP8X (extended WebP) chunk
	var bufX bytes.Buffer
	bufX.WriteString("RIFF")
	binary.Write(&bufX, binary.LittleEndian, uint32(0))
	bufX.WriteString("WEBP")
	bufX.WriteString("VP8X")
	// VP8X Payload: 10 bytes. 1 flag, 3 reserved, 3 width-1, 3 height-1
	// Width = 400 (399 = 0x00018F), Height = 300 (299 = 0x00012B)
	vp8xPayload := []byte{0x00, 0x00, 0x00, 0x00, 0x8F, 0x01, 0x00, 0x2B, 0x01, 0x00}
	binary.Write(&bufX, binary.LittleEndian, uint32(len(vp8xPayload)))
	bufX.Write(vp8xPayload)

	infoX, okX := parseWEBPInfo(bufX.Bytes())
	if !okX || infoX.Width != 400 || infoX.Height != 300 || infoX.Format != "VP8X" {
		t.Errorf("VP8X parsing failed: w=%d, h=%d, format=%s", infoX.Width, infoX.Height, infoX.Format)
	}
}

func TestWebPDecoder_BadChunks(t *testing.T) {
	// VP8 chunk too small
	if _, _, ok := decodeVP8Dims(make([]byte, 5)); ok {
		t.Error("expected VP8 decode failure on short payload")
	}
	// VP8 invalid signature code
	if _, _, ok := decodeVP8Dims([]byte{0, 0, 0, 0x00, 0x00, 0x00, 0, 0, 0, 0}); ok {
		t.Error("expected VP8 decode failure on bad signature")
	}
	// VP8 zero dimensions
	if _, _, ok := decodeVP8Dims([]byte{0, 0, 0, 0x9d, 0x01, 0x2a, 0, 0, 0, 0}); ok {
		t.Error("expected VP8 decode failure on zero dimensions")
	}

	// VP8L chunk too small
	if _, _, ok := decodeVP8LDims(make([]byte, 4)); ok {
		t.Error("expected VP8L decode failure on short payload")
	}
	// VP8L invalid signature code
	if _, _, ok := decodeVP8LDims([]byte{0x00, 0, 0, 0, 0}); ok {
		t.Error("expected VP8L decode failure on bad signature")
	}

	// VP8X chunk too small
	if _, _, ok := decodeVP8XDims(make([]byte, 9)); ok {
		t.Error("expected VP8X decode failure on short payload")
	}
}

// ─── XMP TESTS ──────────────────────────────────────────────────────────────

func TestFindJPEGXMP(t *testing.T) {
	// Nil / short data
	if findJPEGXMP(nil) != nil {
		t.Error("expected nil on nil input")
	}
	if findJPEGXMP([]byte{0xFF}) != nil {
		t.Error("expected nil on short input")
	}

	// Valid JPEG structure with APP1 XMP segment
	var data bytes.Buffer
	data.Write([]byte{0xFF, 0xD8}) // SOI
	data.Write([]byte{0xFF, 0xE1}) // APP1
	prefix := xmpAPP1Prefix
	payload := []byte("<xmpmeta>hello</xmpmeta>")
	segLen := len(prefix) + len(payload) + 2
	data.Write([]byte{byte(segLen >> 8), byte(segLen)})
	data.WriteString(prefix)
	data.Write(payload)
	data.Write([]byte{0xFF, 0xD9}) // EOI

	res := findJPEGXMP(data.Bytes())
	if string(res) != string(payload) {
		t.Errorf("findJPEGXMP failed, got: %q", res)
	}

	// Non-JPEG E1 segment (fails because no SOI)
	if findJPEGXMP(data.Bytes()[2:]) != nil {
		t.Error("expected nil when missing SOI")
	}
}

func TestParseXMP_Base(t *testing.T) {
	// Empty input
	if _, ok := parseXMP(nil); ok {
		t.Error("expected parseXMP on nil to fail")
	}

	// Valid XMP metadata XML string
	xmlData := []byte(`
		<x:xmpmeta xmlns:x="adobe:ns:meta/">
			<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
				<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
					<dc:title>Test Image</dc:title>
					<dc:creator>Test Creator</dc:creator>
					<dc:subject>nature</dc:subject>
					<dc:subject>landscape</dc:subject>
				</rdf:Description>
			</rdf:RDF>
		</x:xmpmeta>
	`)
	fields, ok := parseXMP(xmlData)
	if !ok {
		t.Fatal("parseXMP failed to parse valid XML")
	}
	if fields["Title"] != "Test Image" {
		t.Errorf("expected Title 'Test Image', got %q", fields["Title"])
	}
	if fields["Creator"] != "Test Creator" {
		t.Errorf("expected Creator 'Test Creator', got %q", fields["Creator"])
	}
	// Sequence tags should be flattened with comma-joins
	if fields["Subject"] != "nature, landscape" {
		t.Errorf("expected Subject 'nature, landscape', got %q", fields["Subject"])
	}

	// Truncation check
	truncated := capXMPRaw([]byte("abc"))
	if truncated != "abc" {
		t.Errorf("capXMPRaw should not truncate small strings, got %q", truncated)
	}
	largeRaw := make([]byte, xmpRawCap+10)
	for i := range largeRaw {
		largeRaw[i] = 'A'
	}
	truncatedLarge := capXMPRaw(largeRaw)
	if !strings.HasSuffix(truncatedLarge, "... (truncated)") || len(truncatedLarge) != xmpRawCap+15 {
		t.Errorf("capXMPRaw failed to truncate correctly, len: %d", len(truncatedLarge))
	}
}

// ─── PNG CHUNKS TESTS ───────────────────────────────────────────────────────

func TestPNGChunks_Invalid(t *testing.T) {
	// Invalid PNG header
	res := walkPNGChunks([]byte("not a png file"))
	if len(res.Chunks) != 0 {
		t.Error("expected walkPNGChunks to return empty results with invalid header")
	}
}

func TestPNGChunks_TextAndICCP(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("\x89PNG\r\n\x1a\n") // Header

	// 1. Write a tEXt chunk: keyword "Title", value "Hello PNG"
	kwValue := []byte("Title\x00Hello PNG")
	binary.Write(&buf, binary.BigEndian, uint32(len(kwValue)))
	buf.WriteString("tEXt")
	buf.Write(kwValue)
	binary.Write(&buf, binary.BigEndian, uint32(0)) // CRC placeholder

	// 2. Write a zTXt chunk: keyword "Desc", compression 0, compressed data
	var ztxtBuf bytes.Buffer
	zw := zlib.NewWriter(&ztxtBuf)
	zw.Write([]byte("hello world"))
	zw.Close()
	zlibData := ztxtBuf.Bytes()

	ztxtPayload := append([]byte("Desc\x00\x00"), zlibData...)
	binary.Write(&buf, binary.BigEndian, uint32(len(ztxtPayload)))
	buf.WriteString("zTXt")
	buf.Write(ztxtPayload)
	binary.Write(&buf, binary.BigEndian, uint32(0)) // CRC placeholder

	// 3. Write a malformed zTXt (unsupported compression method)
	ztxtBadCompPayload := []byte("BadComp\x00\x01data")
	binary.Write(&buf, binary.BigEndian, uint32(len(ztxtBadCompPayload)))
	buf.WriteString("zTXt")
	buf.Write(ztxtBadCompPayload)
	binary.Write(&buf, binary.BigEndian, uint32(0)) // CRC placeholder

	// 4. Write an iCCP chunk: name "profile", compression 0, profile data (128 bytes header)
	// Compress a 128-byte array dynamically using zlib
	var zlibBuf bytes.Buffer
	zwICC := zlib.NewWriter(&zlibBuf)
	iccDecoded := make([]byte, 128)
	binary.BigEndian.PutUint32(iccDecoded[0:4], 128) // size
	copy(iccDecoded[12:16], "mntr")                  // device class
	copy(iccDecoded[16:20], "RGB ")                  // color space
	copy(iccDecoded[20:24], "XYZ ")                  // PCS
	zwICC.Write(iccDecoded)
	zwICC.Close()
	zlibICC := zlibBuf.Bytes()

	iccpPayload := append([]byte("profile\x00\x00"), zlibICC...)
	binary.Write(&buf, binary.BigEndian, uint32(len(iccpPayload)))
	buf.WriteString("iCCP")
	buf.Write(iccpPayload)
	binary.Write(&buf, binary.BigEndian, uint32(0)) // CRC placeholder

	// 5. Write an IEND chunk to finish properly
	binary.Write(&buf, binary.BigEndian, uint32(0))
	buf.WriteString("IEND")
	binary.Write(&buf, binary.BigEndian, uint32(0))

	// Now run the metadata extraction logic!
	meta := extractMediaMetadataFull(buf.Bytes(), TypePNG, "test.png")
	if meta.PNGTextChunks["Title"] != "Hello PNG" {
		t.Errorf("tEXt parsing failed, got %q", meta.PNGTextChunks["Title"])
	}
	if meta.PNGTextChunks["Desc"] != "hello world" {
		t.Errorf("zTXt parsing failed, got %q", meta.PNGTextChunks["Desc"])
	}
	if meta.ICCProfile == nil {
		t.Errorf("iCCP parsing failed entirely, ICCProfile is nil")
	} else {
		if meta.ICCProfile.ColorSpace != "RGB" || meta.ICCProfile.PCS != "XYZ" || meta.ICCProfile.DeviceClass != "mntr" {
			t.Errorf("ICC profile field mismatch: %+v", meta.ICCProfile)
		}
	}
}

// ─── STEGANOGRAPHY & WATERMARKS TESTS ───────────────────────────────────────

func TestDigimarcWatermark(t *testing.T) {
	// Construct JPEG containing an APP1 (0xE1) segment with high-entropy Digimarc-like data
	// ratios: nonZero > 0.7, highByte > 0.3 && < 0.7
	segPayload := []byte{
		0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x01,
	}

	var data bytes.Buffer
	data.Write([]byte{0xFF, 0xD8}) // SOI
	data.Write([]byte{0xFF, 0xE1}) // APP1
	segLen := len(segPayload) + 2
	data.Write([]byte{byte(segLen >> 8), byte(segLen)})
	data.Write(segPayload)
	data.Write([]byte{0xFF, 0xD9}) // EOI

	sigs := DetectWatermarks(data.Bytes(), TypeJPEG)
	if len(sigs) != 1 || sigs[0].Type != "digimarc" {
		t.Errorf("expected 1 digimarc watermark signal, got: %v", sigs)
	}

	// Test detectDCTChiSquared dummy call trigger
	chiRes := detectDCTChiSquared(nil)
	if chiRes != nil {
		t.Errorf("expected nil from empty DCT check, got %v", chiRes)
	}
}

// ─── ENCODER FINGERPRINT TESTS ──────────────────────────────────────────────

func TestEncoderFingerprint(t *testing.T) {
	// Empty input
	if FingerprintFile(nil, TypeJPEG) != nil {
		t.Error("expected nil fingerprint on nil input")
	}

	// Unknown PNG
	pngFP := FingerprintFile([]byte("\x89PNG\r\n\x1a\n"), TypePNG)
	if pngFP == nil || pngFP.Encoder != "Unknown PNG encoder" {
		t.Errorf("expected unknown PNG encoder, got %+v", pngFP)
	}

	// Legacy quantization tables hash
	tables := [][]byte{{0x01, 0x02, 0x03}}
	legacyHash := hashQuantTablesLegacy(tables)
	if len(legacyHash) != 1 {
		t.Errorf("unexpected legacy hash length: %d", len(legacyHash))
	}
}

func TestEncoderFingerprintDetailed(t *testing.T) {
	// 1. GIMP Comment Test
	var gimpCom bytes.Buffer
	gimpCom.Write([]byte{0xFF, 0xD8}) // SOI
	gimpCom.Write([]byte{0xFF, 0xFE}) // COM
	gimpCom.Write([]byte{0x00, 0x08}) // length (8)
	gimpCom.Write([]byte("GIMP\x00\x00"))
	gimpCom.Write([]byte{0xFF, 0xD9}) // EOI

	fpGimp := FingerprintFile(gimpCom.Bytes(), TypeJPEG)
	if fpGimp == nil || fpGimp.Encoder != "GIMP" {
		t.Errorf("failed to detect GIMP comment, got: %+v", fpGimp)
	}

	// 2. Adobe Photoshop Comment Test
	var psCom bytes.Buffer
	psCom.Write([]byte{0xFF, 0xD8}) // SOI
	psCom.Write([]byte{0xFF, 0xFE}) // COM
	psCom.Write([]byte{0x00, 0x08}) // length (8)
	psCom.Write([]byte("Adobe\x00"))
	psCom.Write([]byte{0xFF, 0xD9}) // EOI

	fpPs := FingerprintFile(psCom.Bytes(), TypeJPEG)
	if fpPs == nil || fpPs.Encoder != "Adobe Photoshop" {
		t.Errorf("failed to detect Adobe comment, got: %+v", fpPs)
	}

	// 3. Photoshop ordering APP0 + APP1
	var ordCom bytes.Buffer
	ordCom.Write([]byte{0xFF, 0xD8}) // SOI
	ordCom.Write([]byte{0xFF, 0xE0}) // APP0
	ordCom.Write([]byte{0x00, 0x07}) // length (7)
	ordCom.Write([]byte("JFIF\x00"))
	ordCom.Write([]byte{0xFF, 0xE1}) // APP1
	ordCom.Write([]byte{0x00, 0x22}) // length (34)
	ordCom.Write([]byte("http://ns.adobe.com/xmp/1.0/\x00\x00\x00\x00"))
	ordCom.Write([]byte{0xFF, 0xD9}) // EOI

	fpOrd := FingerprintFile(ordCom.Bytes(), TypeJPEG)
	if fpOrd == nil || fpOrd.Encoder != "Adobe Photoshop" {
		t.Errorf("failed to detect Adobe Photoshop via ordering/XMP, got: %+v", fpOrd)
	}

	// 4. Known Quantization Table Hash Test
	var qCom bytes.Buffer
	qCom.Write([]byte{0xFF, 0xD8}) // SOI
	qCom.Write([]byte{0xFF, 0xDB}) // DQT
	qCom.Write([]byte{0x00, 0x06}) // length (6)
	qCom.Write([]byte{0x00, 0x01, 0x02, 0x03})
	qCom.Write([]byte{0xFF, 0xD9}) // EOI

	hVal := hashQuantTables([][]byte{{0x00, 0x01, 0x02, 0x03}})
	knownQuantTableHashes[hVal] = "Test Custom Encoder"

	fpQ := FingerprintFile(qCom.Bytes(), TypeJPEG)
	if fpQ == nil || fpQ.Encoder != "Test Custom Encoder" {
		t.Errorf("failed to match known quant table hash, got: %+v", fpQ)
	}

	// 5. PNG GIMP Pattern Chunk Ordering
	var pngGimp bytes.Buffer
	pngGimp.WriteString("\x89PNG\r\n\x1a\n")
	// IDAT chunk
	binary.Write(&pngGimp, binary.BigEndian, uint32(0))
	pngGimp.WriteString("IDAT")
	binary.Write(&pngGimp, binary.BigEndian, uint32(0))
	// tEXt chunk
	binary.Write(&pngGimp, binary.BigEndian, uint32(0))
	pngGimp.WriteString("tEXt")
	binary.Write(&pngGimp, binary.BigEndian, uint32(0))
	// gAMA chunk
	binary.Write(&pngGimp, binary.BigEndian, uint32(0))
	pngGimp.WriteString("gAMA")
	binary.Write(&pngGimp, binary.BigEndian, uint32(0))

	fpPngGimp := FingerprintFile(pngGimp.Bytes(), TypePNG)
	if fpPngGimp == nil || fpPngGimp.Encoder != "GIMP" {
		t.Errorf("failed to detect GIMP PNG chunk pattern, got: %+v", fpPngGimp)
	}

	// 6. PNG Adobe Photoshop Pattern Chunk Ordering
	var pngPs bytes.Buffer
	pngPs.WriteString("\x89PNG\r\n\x1a\n")
	// tEXt chunk
	binary.Write(&pngPs, binary.BigEndian, uint32(0))
	pngPs.WriteString("tEXt")
	binary.Write(&pngPs, binary.BigEndian, uint32(0))
	// IDAT chunk
	binary.Write(&pngPs, binary.BigEndian, uint32(0))
	pngPs.WriteString("IDAT")
	binary.Write(&pngPs, binary.BigEndian, uint32(0))

	fpPngPs := FingerprintFile(pngPs.Bytes(), TypePNG)
	if fpPngPs == nil || fpPngPs.Encoder != "Adobe Photoshop" {
		t.Errorf("failed to detect Photoshop PNG chunk pattern, got: %+v", fpPngPs)
	}
}

// ─── EXIF TAG FORMATS TESTS ─────────────────────────────────────────────────

func TestExifTagFormats(t *testing.T) {
	tf := &tiffFile{
		buf:   make([]byte, 100),
		order: binary.LittleEndian,
	}

	// Rational array format (exact fraction plus decimal hint).
	eRational := tiffEntry{
		typ:       uint16(TypeRational),
		count:     2,
		valOffset: 10,
	}
	// Put 2 rational values: 5/2, 10/4.
	binary.LittleEndian.PutUint32(tf.buf[10:14], 5)
	binary.LittleEndian.PutUint32(tf.buf[14:18], 2)
	binary.LittleEndian.PutUint32(tf.buf[18:22], 10)
	binary.LittleEndian.PutUint32(tf.buf[22:26], 4)

	resRat, _ := formatTiffValue(tf, IFD0, 0x0100, eRational)
	if resRat != "5/2 (2.5), 10/4 (2.5)" {
		t.Errorf("formatTiffValue rational failed: %q", resRat)
	}

	// SRational array format
	eSRational := tiffEntry{
		typ:       uint16(TypeSRational),
		count:     1,
		valOffset: 30,
	}
	// Put 1 srational: -7/2.
	val := int32(-7)
	binary.LittleEndian.PutUint32(tf.buf[30:34], uint32(val))
	binary.LittleEndian.PutUint32(tf.buf[34:38], 2)

	resSRat, _ := formatTiffValue(tf, IFD0, 0x0100, eSRational)
	if resSRat != "-7/2 (-3.5)" {
		t.Errorf("formatTiffValue srational failed: %q", resSRat)
	}

	// Undefined tag output
	eUndefined := tiffEntry{
		typ:       uint16(TypeUndefined),
		count:     4,
		valOffset: 50,
	}
	copy(tf.buf[50:54], "TEST")
	resUndef, _ := formatTiffValue(tf, IFD0, 0x0100, eUndefined)
	if resUndef != "TEST" {
		t.Errorf("formatTiffValue undefined failed: %q", resUndef)
	}

	// Non-printable Undefined tag output
	tf.buf[50] = 0xFF
	resUndefHex, _ := formatTiffValue(tf, IFD0, 0x0100, eUndefined)
	if !strings.Contains(resUndefHex, "bytes:") {
		t.Errorf("formatTiffValue failed for non-printable undefined: %q", resUndefHex)
	}

	// Fully out-of-range Undefined tag (offset past the end of the blob).
	eOutOfRange := tiffEntry{
		typ:       uint16(TypeUndefined),
		count:     10,
		valOffset: 150,
	}
	resOOR, _ := formatTiffValue(tf, IFD0, 0x0100, eOutOfRange)
	if !strings.Contains(resOOR, "outside") {
		t.Errorf("formatTiffValue failed on out of range: %q", resOOR)
	}

	// DumpAllTags ordered output
	ifd := map[uint16]tiffEntry{
		0x0110: {typ: uint16(TypeASCII), count: 5, valOffset: 60},
	}
	copy(tf.buf[60:65], "SONY\x00")
	views := DumpAllTags(tf, IFD0, ifd)
	if len(views) != 1 || views[0].Name != "Model" || views[0].Value != "SONY" {
		t.Errorf("DumpAllTags failed: %+v", views)
	}

	// Uint array format & out of range checks
	eUint := tiffEntry{
		typ:       uint16(TypeLong),
		count:     2,
		valOffset: 70,
	}
	binary.LittleEndian.PutUint32(tf.buf[70:74], 42)
	binary.LittleEndian.PutUint32(tf.buf[74:78], 43)
	resUint, _ := formatTiffValue(tf, IFD0, 0x0100, eUint)
	if resUint != "42, 43" {
		t.Errorf("formatTiffValue uint failed: %q", resUint)
	}

	// Display truncation for Rational arrays (available elems > maxDumpArrayValues).
	// 176-byte blob, 20 rationals at offset 10: all 20 fit, 16 shown, 4 capped.
	big := &tiffFile{buf: make([]byte, 176), order: binary.LittleEndian}
	eTruncRat := tiffEntry{
		typ:       uint16(TypeRational),
		count:     20,
		valOffset: 10,
	}
	resTruncRat, _ := formatTiffValue(big, IFD0, 0x0100, eTruncRat)
	if !strings.Contains(resTruncRat, "(+4 more)") {
		t.Errorf("formatTiffValue expected display truncation, got: %q", resTruncRat)
	}
}

// ─── FORENSIC LOGGER TESTS ──────────────────────────────────────────────────

func TestForensicLogger(t *testing.T) {
	// Test Logger initialization & standard methods
	var buf bytes.Buffer
	logger := NewTextForensicLogger(&buf, LogTrace)
	logger.SetLevel(LogDebug)

	// Logging methods
	logger.Trace("detect", "trace message") // will be ignored as level is LogDebug
	logger.Debug("detect", "debug message")
	logger.Info("detect", "info message")
	logger.Warn("detect", "warn message")

	logOutput := buf.String()
	if strings.Contains(logOutput, "trace message") {
		t.Error("Trace log should have been ignored")
	}
	if !strings.Contains(logOutput, "debug message") || !strings.Contains(logOutput, "info message") {
		t.Errorf("missing expected log messages: %q", logOutput)
	}

	// Test callback logger
	called := false
	cbLogger := NewCallbackForensicLogger(func(e ForensicEvent) {
		called = true
		if e.Message != "test callback" {
			t.Errorf("mismatched callback message: %q", e.Message)
		}
	}, LogInfo)
	cbLogger.Info("detect", "test callback")
	if !called {
		t.Error("Callback was not invoked")
	}

	// Test specific event formatting logs
	var bufJSON bytes.Buffer
	jsonLogger := NewForensicLogger(&bufJSON, LogDebug)
	jsonLogger.LogAnalysisStart("sample.jpg", DepthQuick, 1000)
	jsonLogger.LogMagicDetection("jpeg", 0, 1.0)
	jsonLogger.LogPolyglot(TypeJPEG, []MediaType{TypeZIP}, false)
	jsonLogger.LogEntropyAnomaly(100, 200, 7.8, 2.1)
	jsonLogger.LogRiskScore(0.85, 0.2, 0.3, 0.4)
	jsonLogger.LogAnalysisComplete("sample.jpg", TypeJPEG, 0.85, time.Millisecond*10)

	jsonStr := bufJSON.String()
	if !strings.Contains(jsonStr, "Analysis started") || !strings.Contains(jsonStr, "High-entropy region detected") {
		t.Errorf("JSON logger missed output fields: %q", jsonStr)
	}

	// Test events JSON escaping & formatting
	jsonLogger.Info("detect", "hello \"world\" \n \t \\")
	eventsJSON := jsonLogger.LogEventsJSON()
	if !strings.Contains(string(eventsJSON), `\\`) || !strings.Contains(string(eventsJSON), `\"`) {
		t.Errorf("LogEventsJSON failed to escape correctly: %s", eventsJSON)
	}

	// Test silent logger
	silent := SilentLogger()
	silent.Info("detect", "silent log") // should discard silently
}

func TestForensicLogger_Events(t *testing.T) {
	cbLogger := NewCallbackForensicLogger(nil, LogTrace)
	cbLogger.LogAnalysisStart("sample.jpg", DepthQuick, 1000)

	evs := cbLogger.Events()
	if len(evs) != 1 {
		t.Fatalf("expected 1 recorded event, got %d", len(evs))
	}

	cbLogger.ClearEvents()
	if len(cbLogger.Events()) != 0 {
		t.Errorf("expected 0 events after clearing, got %d", len(cbLogger.Events()))
	}
}

// ─── INTEGRATION AND CORNER-CASE TESTS ──────────────────────────────────────

func TestMediaMetaHeuristics_ContextAndPipeline(t *testing.T) {
	// Test depth quick check & timeout cancel
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // instantly cancel context

	engine := NewForensicEngine()
	actx := NewAnalysisContext(ctx, DepthQuick, SilentLogger())
	res := engine.AnalyzeWithCtx([]byte("fake content"), "test.jpg", "test.jpg", actx)
	if res.FilePath != "test.jpg" {
		t.Errorf("expected FilePath 'test.jpg', got: %s", res.FilePath)
	}
}

func TestEXIFTIFF_MockParsers(t *testing.T) {
	// 1. Build a valid mock TIFF buffer
	var tfBuf bytes.Buffer
	tfBuf.WriteString("II")
	binary.Write(&tfBuf, binary.LittleEndian, uint16(42))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(8)) // IFD0 at offset 8

	// IFD0:
	binary.Write(&tfBuf, binary.LittleEndian, uint16(5)) // 5 entries (Make, Software, Orientation, ExifPointer, GPSPointer)

	// Entry 1: Make (0x010F), type = ASCII (2), count = 5, offset = 74
	binary.Write(&tfBuf, binary.LittleEndian, uint16(0x010F))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(2))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(5))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(74))

	// Entry 2: Software (0x0131), type = ASCII (2), count = 10, offset = 80
	binary.Write(&tfBuf, binary.LittleEndian, uint16(0x0131))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(2))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(10))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(80))

	// Entry 3: Orientation (0x0112), type = Short (3), count = 1, value = 1
	binary.Write(&tfBuf, binary.LittleEndian, uint16(0x0112))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(3))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(1)) // value
	binary.Write(&tfBuf, binary.LittleEndian, uint16(0)) // padding

	// Entry 4: ExifIFDPointer (0x8769), type = Long (4), count = 1, value = 100
	binary.Write(&tfBuf, binary.LittleEndian, uint16(0x8769))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(4))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(100)) // offset of ExifSubIFD

	// Entry 5: GPSIFDPointer (0x8825), type = Long (4), count = 1, value = 180
	binary.Write(&tfBuf, binary.LittleEndian, uint16(0x8825))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(4))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(180)) // offset of GPS IFD

	// Next IFD offset = 330 (IFD1 / Thumbnail)
	binary.Write(&tfBuf, binary.LittleEndian, uint32(330))

	// Padding to offset 74
	for tfBuf.Len() < 74 {
		tfBuf.WriteByte(0)
	}
	tfBuf.Write([]byte("SONY\x00"))

	// Padding to offset 80
	for tfBuf.Len() < 80 {
		tfBuf.WriteByte(0)
	}
	tfBuf.Write([]byte("Paint.NET\x00"))

	// Padding to offset 100
	for tfBuf.Len() < 100 {
		tfBuf.WriteByte(0)
	}

	// ExifSubIFD:
	binary.Write(&tfBuf, binary.LittleEndian, uint16(2))

	// Entry 1: DateTimeOriginal (0x9003), ASCII (2), count = 20, offset = 130
	binary.Write(&tfBuf, binary.LittleEndian, uint16(0x9003))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(2))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(20))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(130))

	// Entry 2: FNumber (0x829D), Rational (5), count = 1, offset = 150
	binary.Write(&tfBuf, binary.LittleEndian, uint16(0x829D))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(5))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(150))

	// Next IFD offset (0)
	binary.Write(&tfBuf, binary.LittleEndian, uint32(0))

	// Padding to 130
	for tfBuf.Len() < 130 {
		tfBuf.WriteByte(0)
	}
	tfBuf.Write([]byte("2026:07:19 13:00:00\x00"))

	// Padding to 150
	for tfBuf.Len() < 150 {
		tfBuf.WriteByte(0)
	}
	// FNumber at 150: 8/2 = 4.0
	binary.Write(&tfBuf, binary.LittleEndian, uint32(8))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(2))

	// Padding to 180 (GPS IFD)
	for tfBuf.Len() < 180 {
		tfBuf.WriteByte(0)
	}
	binary.Write(&tfBuf, binary.LittleEndian, uint16(6)) // 6 entries

	// GPS Entry 1: GPSLatRef (1), ASCII (2), count = 2, value = "S\x00" stored in offset field
	binary.Write(&tfBuf, binary.LittleEndian, uint16(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(2))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(2))
	binary.Write(&tfBuf, binary.LittleEndian, []byte("S\x00\x00\x00"))

	// GPS Entry 2: GPSLat (2), Rational (5), count = 3, offset = 260
	binary.Write(&tfBuf, binary.LittleEndian, uint16(2))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(5))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(3))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(260))

	// GPS Entry 3: GPSLonRef (3), ASCII (2), count = 2, value = "W\x00" stored in offset field
	binary.Write(&tfBuf, binary.LittleEndian, uint16(3))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(2))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(2))
	binary.Write(&tfBuf, binary.LittleEndian, []byte("W\x00\x00\x00"))

	// GPS Entry 4: GPSLon (4), Rational (5), count = 3, offset = 284
	binary.Write(&tfBuf, binary.LittleEndian, uint16(4))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(5))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(3))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(284))

	// GPS Entry 5: GPSAltRef (5), Byte (1), count = 1, value = 1 (negative altitude) stored in offset field
	binary.Write(&tfBuf, binary.LittleEndian, uint16(5))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, []byte{1, 0, 0, 0})

	// GPS Entry 6: GPSAlt (6), Rational (5), count = 1, offset = 308
	binary.Write(&tfBuf, binary.LittleEndian, uint16(6))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(5))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(308))

	// Next IFD (0)
	binary.Write(&tfBuf, binary.LittleEndian, uint32(0))

	// GPS data values
	// Padding to 260
	for tfBuf.Len() < 260 {
		tfBuf.WriteByte(0)
	}
	// Lat at 260 (12/1, 30/1, 0/1)
	binary.Write(&tfBuf, binary.LittleEndian, uint32(12))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(30))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(0))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))

	// Padding to 284
	for tfBuf.Len() < 284 {
		tfBuf.WriteByte(0)
	}
	// Lon at 284 (45/1, 15/1, 0/1)
	binary.Write(&tfBuf, binary.LittleEndian, uint32(45))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(15))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(0))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))

	// Padding to 308
	for tfBuf.Len() < 308 {
		tfBuf.WriteByte(0)
	}
	// Alt at 308 (100/2 = 50.0m)
	binary.Write(&tfBuf, binary.LittleEndian, uint32(100))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(2))

	// Padding to 330 (IFD1)
	for tfBuf.Len() < 330 {
		tfBuf.WriteByte(0)
	}

	// IFD1 entries
	binary.Write(&tfBuf, binary.LittleEndian, uint16(2)) // 2 entries

	// Entry 1: tagThumbOffset (0x0201), Long (4), count 1, value 360
	binary.Write(&tfBuf, binary.LittleEndian, uint16(0x0201))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(4))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(360))

	// Entry 2: tagThumbLength (0x0202), Long (4), count 1, value 10
	binary.Write(&tfBuf, binary.LittleEndian, uint16(0x0202))
	binary.Write(&tfBuf, binary.LittleEndian, uint16(4))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(1))
	binary.Write(&tfBuf, binary.LittleEndian, uint32(10))

	// Next IFD (0)
	binary.Write(&tfBuf, binary.LittleEndian, uint32(0))

	// Padding to 360 (Thumbnail)
	for tfBuf.Len() < 360 {
		tfBuf.WriteByte(0)
	}
	// JPEG SOI to EOI
	tfBuf.Write([]byte{0xFF, 0xD8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD9})

	outcome := extractCuratedEXIF(tfBuf.Bytes())
	if outcome.Fields["Camera_Make"] != "SONY" || outcome.Fields["Software"] != "Paint.NET" || outcome.Fields["Date_Taken"] != "2026:07:19 13:00:00" {
		t.Errorf("extractCuratedEXIF failed to extract mock fields: %+v", outcome.Fields)
	}

	// Verify GPS
	if outcome.Fields["GPS_Coordinates"] != "-12.500000, -45.250000" {
		t.Errorf("GPSCoordinates mismatch, got: %q", outcome.Fields["GPS_Coordinates"])
	}
	if outcome.Fields["GPS_Altitude"] != "-50.0 m" {
		t.Errorf("GPSAltitude mismatch, got: %q", outcome.Fields["GPS_Altitude"])
	}

	// Verify Thumbnail
	if len(outcome.Thumbnail) != 10 || outcome.Thumbnail[0] != 0xFF || outcome.Thumbnail[9] != 0xD9 {
		t.Errorf("Thumbnail extraction failed, len=%d", len(outcome.Thumbnail))
	}

	// 2. Test findJPEGDimensions with a mock JPEG Start-Of-Frame (SOF0) marker
	var jpegBuf bytes.Buffer
	jpegBuf.Write([]byte{0xFF, 0xD8})                               // SOI
	jpegBuf.Write([]byte{0xFF, 0xC0})                               // SOF0
	jpegBuf.Write([]byte{0x00, 0x0B})                               // segment length (11)
	jpegBuf.Write([]byte{0x08, 0x00, 0xC8, 0x00, 0x64})             // precision, height (200), width (100)
	jpegBuf.Write([]byte{0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x01}) // rest of SOF0 data

	w, h, ok := findJPEGDimensions(jpegBuf.Bytes())
	if !ok || w != 100 || h != 200 {
		t.Errorf("findJPEGDimensions failed: w=%d, h=%d, ok=%t", w, h, ok)
	}
}

func TestJPEGTrailingDetailed(t *testing.T) {
	// 1. Invalid SOI
	if _, _, ok := findJPEGEOITrailing([]byte{0x00, 0x00, 0x00, 0x00}); ok {
		t.Error("expected false on invalid SOI")
	}

	// 2. Non-marker at position
	badMarker := []byte{0xFF, 0xD8, 0x00, 0x00, 0x00, 0x00}
	if _, _, ok := findJPEGEOITrailing(badMarker); ok {
		t.Error("expected false on bad marker byte")
	}

	// 3. SOS not found
	noSOS := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x03, 0x00}
	if _, _, ok := findJPEGEOITrailing(noSOS); ok {
		t.Error("expected false when SOS not found")
	}

	// 4. Valid JPEG with SOS and EOI, restart markers and byte-stuffed FF
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI
	buf.Write([]byte{0xFF, 0xDA}) // SOS
	buf.Write([]byte{0x00, 0x03}) // segLen = 3
	buf.Write([]byte{0x00})       // SOS payload (1 byte)
	// Entropy coded data:
	buf.Write([]byte{0x01, 0x02})
	buf.Write([]byte{0xFF, 0x00}) // byte-stuffed 0xFF
	buf.Write([]byte{0x03, 0x04})
	buf.Write([]byte{0xFF, 0xD0}) // restart marker
	buf.Write([]byte{0x05, 0x06})
	buf.Write([]byte{0xFF, 0xD9}) // EOI
	buf.Write([]byte("trailing data here"))

	eoi, trailing, ok := findJPEGEOITrailing(buf.Bytes())
	if !ok {
		t.Fatalf("expected true, EOI not found")
	}
	if string(trailing) != "trailing data here" {
		t.Errorf("mismatched trailing data: %q", trailing)
	}
	if eoi != len(buf.Bytes())-len("trailing data here")-2 {
		t.Errorf("mismatched EOI offset: %d", eoi)
	}
}

func TestIdentifyTrailingFormat(t *testing.T) {
	// 1. Empty input
	if identifyTrailingFormat(nil) != "" {
		t.Error("expected empty string on nil input")
	}

	// 2. Padding skip
	paddingData := append(make([]byte, 10), []byte("PK\x03\x04")...)
	if identifyTrailingFormat(paddingData) != "ZIP" {
		t.Errorf("failed to identify ZIP trailing signature with padding: %q", identifyTrailingFormat(paddingData))
	}

	// 3. Bounded scan matches
	junkData := append([]byte("12345"), []byte("MZ")...)
	if identifyTrailingFormat(junkData) != "PE/EXE" {
		t.Errorf("failed to identify PE/EXE with leading junk: %q", identifyTrailingFormat(junkData))
	}

	// 4. Exceeding bounded scan threshold (256 bytes relative to window after first 64 skip)
	farJunkData := append(make([]byte, 350), []byte("MZ")...)
	if identifyTrailingFormat(farJunkData) != "" {
		t.Errorf("expected empty string when signature is too far, got: %q", identifyTrailingFormat(farJunkData))
	}

	// 5. Exceeding maxTrailingScanBytes truncation
	hugeTrailing := make([]byte, 5000)
	copy(hugeTrailing, []byte("PK\x03\x04"))
	if identifyTrailingFormat(hugeTrailing) != "ZIP" {
		t.Errorf("failed to identify ZIP with huge trailing data: %q", identifyTrailingFormat(hugeTrailing))
	}
}

func TestAnalysisContextDetailed(t *testing.T) {
	// 1. DefaultContext
	defCtx := DefaultContext()
	if defCtx.Depth != DepthStandard {
		t.Errorf("expected DepthStandard, got %v", defCtx.Depth)
	}

	// 2. WithForensicLog on nil context
	var nilCtx *AnalysisContext
	customLogger := SilentLogger()
	withLog := nilCtx.WithForensicLog(customLogger)
	if withLog.ForensicLog != customLogger {
		t.Error("failed to attach forensic log to nil context fallback")
	}

	// 3. log() helper on nil context
	l := nilCtx.log()
	if l == nil {
		t.Error("expected non-nil silent logger fallback")
	}

	// 4. reportProgress nil/not nil branches
	var progressCalled bool
	progCtx := &AnalysisContext{
		Ctx: context.Background(),
		Progress: func(phase string, pct float64) {
			progressCalled = true
		},
	}
	progCtx.reportProgress("test", 0.5)
	if !progressCalled {
		t.Error("Progress callback was not invoked")
	}

	// progress with cancelled context
	ctxCancel, cancel := context.WithCancel(context.Background())
	cancel()
	progCtxCancel := &AnalysisContext{
		Ctx: ctxCancel,
		Progress: func(phase string, pct float64) {
			t.Error("Progress should not be called on cancelled context")
		},
	}
	progCtxCancel.reportProgress("test", 0.5)

	// nil reportProgress
	var nilProgCtx *AnalysisContext
	nilProgCtx.reportProgress("test", 0.5) // should not panic

	// 5. cancelled() helper nil/not nil
	if nilProgCtx.cancelled() {
		t.Error("nil context should not be cancelled")
	}
	noCtx := &AnalysisContext{Ctx: nil}
	if noCtx.cancelled() {
		t.Error("nil underlying context should not be cancelled")
	}

	activeCtx := &AnalysisContext{Ctx: context.Background()}
	if activeCtx.cancelled() {
		t.Error("active context should not be cancelled")
	}
}

func TestDeepGIFDetailed(t *testing.T) {
	// 1. Data too short
	if AnalyzeGIF(make([]byte, 5)) != nil {
		t.Error("expected nil on short data")
	}

	// 2. Bad signature
	if AnalyzeGIF([]byte("GIF88a")) != nil {
		t.Error("expected nil on bad signature")
	}

	// 3. Application Extension out of bounds or bad block size
	badAppExt := []byte("GIF89a\x21\xFF\x0B\x00\x00")
	if len(AnalyzeGIF(badAppExt)) != 0 {
		t.Error("expected no threats on truncated application extension")
	}

	// 4. Animexts application extension
	var buf bytes.Buffer
	buf.WriteString("GIF89a")
	// Application Extension: 0x21, 0xFF, size = 11, data = "ANIMEXTS1.0"
	buf.Write([]byte{0x21, 0xFF, 11})
	buf.WriteString("ANIMEXTS1.0")

	threats := AnalyzeGIF(buf.Bytes())
	if len(threats) != 1 || threats[0].Type != "application_extension" {
		t.Errorf("expected 1 application extension threat, got: %v", threats)
	}
}

func TestWatermarksDetailed(t *testing.T) {
	// 1. len(data) == 0 in DetectWatermarks
	if DetectWatermarks(nil, TypeJPEG) != nil {
		t.Error("expected nil on nil data")
	}

	// 2. Non-JPEG format
	if DetectWatermarks([]byte("fake data"), TypePNG) != nil {
		t.Error("expected nil on non-JPEG format")
	}

	// 3. detectDigimarc bad SOI
	badSOI := []byte{0x00, 0x00, 0x00, 0x00}
	if len(DetectWatermarks(badSOI, TypeJPEG)) != 0 {
		t.Error("expected no watermarks on bad SOI")
	}

	// 4. isDigimarcSignature size < 16
	shortSeg := []byte{0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x0A, 0x01, 0x02, 0x03, 0x04}
	if len(DetectWatermarks(shortSeg, TypeJPEG)) != 0 {
		t.Error("expected no watermarks on short APP segment")
	}

	// 5. isDigimarcSignature standard prefix (Exif)
	exifSeg := []byte{0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x14, 'E', 'x', 'i', 'f', 0x00, 0x00, 7, 8, 9, 10, 11, 12, 13, 14}
	if len(DetectWatermarks(exifSeg, TypeJPEG)) != 0 {
		t.Error("expected no watermarks on standard Exif prefix segment")
	}

	// 6. Segment length > 256 limit clamping test
	// Prepare a huge segment (say 300 bytes) with high-entropy profile
	segPayload := make([]byte, 300)
	for i := range segPayload {
		if i%2 == 0 {
			segPayload[i] = 0x90
		} else {
			segPayload[i] = 0x01
		}
	}
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xD8}) // SOI
	buf.Write([]byte{0xFF, 0xE2}) // APP2
	segLen := len(segPayload) + 2
	buf.Write([]byte{byte(segLen >> 8), byte(segLen)})
	buf.Write(segPayload)
	buf.Write([]byte{0xFF, 0xD9}) // EOI

	sigs := DetectWatermarks(buf.Bytes(), TypeJPEG)
	if len(sigs) != 1 || sigs[0].Type != "digimarc" {
		t.Errorf("expected 1 digimarc watermark on huge segment, got: %v", sigs)
	}
}

func TestSteganographyDetailed(t *testing.T) {
	// 1. len(data) == 0 in DetectSteganography
	if DetectSteganography(nil, TypePNG) != nil {
		t.Error("expected nil on nil data")
	}

	// 2. Unknown format
	if DetectSteganography([]byte("fake data"), "unknown") != nil {
		t.Error("expected nil on unknown format")
	}

	// 3. detectLSBFrequency short data (< 1024)
	if len(DetectSteganography(make([]byte, 100), TypePNG)) != 0 {
		t.Error("expected no stego signals on short PNG")
	}

	// 4. detectDCTChiSquared short data (< 1024)
	if len(DetectSteganography(make([]byte, 100), TypeJPEG)) != 0 {
		t.Error("expected no stego signals on short JPEG")
	}

	// 5. detectPaletteLSB short data (< 512)
	if len(DetectSteganography(make([]byte, 100), TypeGIF)) != 0 {
		t.Error("expected no stego signals on short GIF")
	}

	// 6. detectPaletteLSB where end > len(data)
	// We need data size between 512 and 4096 (e.g. 1000 bytes)
	// with high-entropy/deviating LSB to trigger palette stego signal
	stegoGIF := make([]byte, 1000)
	for i := range stegoGIF {
		stegoGIF[i] = 0xFF // all LSB = 1, deviation = 0.5 > 0.08
	}
	sigs := DetectSteganography(stegoGIF, TypeGIF)
	if len(sigs) != 1 || sigs[0].Method != "palette_lsb" {
		t.Errorf("expected palette_lsb stego signal, got: %v", sigs)
	}
}

func TestDeepPDFDetailed(t *testing.T) {
	// 1. Too short PDF / bad magic
	if AnalyzePDF([]byte("%PD")) != nil {
		t.Error("expected nil on bad PDF magic")
	}

	// 2. JavaScript limit check (> 20 javascript occurrences)
	// We'll write 25 instances of "/JS "
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")
	for i := 0; i < 25; i++ {
		buf.WriteString("/JS ")
	}
	threats := AnalyzePDF(buf.Bytes())
	// It should limit the threats count to 21 (since idx is advanced, 0-indexed, up to 21 javascript threats)
	jsCount := 0
	for _, th := range threats {
		if th.Type == "javascript" {
			jsCount++
		}
	}
	if jsCount != 21 {
		t.Errorf("expected 21 javascript threats (limited), got %d", jsCount)
	}

	// 3. Embedded files and launch actions detection
	embeddedPDF := []byte("%PDF-1.4\n/EmbeddedFile /Launch /SubmitForm /ImportData")
	threatsEmbedded := AnalyzePDF(embeddedPDF)
	if len(threatsEmbedded) < 4 {
		t.Errorf("expected at least 4 action threats, got %d", len(threatsEmbedded))
	}

	// 4. AcroForm detection
	acroPDF := []byte("%PDF-1.4\n/AcroForm")
	threatsAcro := AnalyzePDF(acroPDF)
	if len(threatsAcro) != 1 || threatsAcro[0].Type != "acroform" {
		t.Errorf("expected acroform threat, got: %v", threatsAcro)
	}
}
