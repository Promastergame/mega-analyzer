package imagedec

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ── helpers ──────────────────────────────────────────────────────────────

// validPNG builds a header a real decoder would accept: the 8-byte signature
// followed by a 13-byte IHDR declaring 256x128.
func validPNG() []byte {
	out := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	ihdr := make([]byte, 16)
	binary.BigEndian.PutUint32(ihdr[0:4], 13)
	copy(ihdr[4:8], "IHDR")
	binary.BigEndian.PutUint32(ihdr[8:12], 256)
	binary.BigEndian.PutUint32(ihdr[12:16], 128)
	out = append(out, ihdr...)
	return append(out, make([]byte, 96)...)
}

// validKTX2 is the container KHR_texture_basisu points at, and the shape a
// mobile game actually ships instead of PNG.
func validKTX2() []byte {
	out := []byte{0xAB, 'K', 'T', 'X', ' ', '2', '0', 0xBB, 0x0D, 0x0A, 0x1A, 0x0A}
	rest := make([]byte, 52)
	binary.LittleEndian.PutUint32(rest[0:4], 43)  // vkFormat   -> offset 12
	binary.LittleEndian.PutUint32(rest[4:8], 1)   // typeSize   -> offset 16
	binary.LittleEndian.PutUint32(rest[8:12], 512) // pixelWidth -> offset 20
	binary.LittleEndian.PutUint32(rest[12:16], 512)
	return append(out, rest...)
}

func xorWith(src []byte, key ...byte) []byte {
	out := make([]byte, len(src))
	for i := range src {
		out[i] = src[i] ^ key[i%len(key)]
	}
	return out
}

// subWith produces the ciphertext for a KindAdd recovery of n.
func subWith(src []byte, n byte) []byte {
	out := make([]byte, len(src))
	for i := range src {
		out[i] = src[i] - n
	}
	return out
}

// rotrWith produces the ciphertext for a KindRotate recovery of n.
func rotrWith(src []byte, n uint8) []byte {
	out := make([]byte, len(src))
	for i, b := range src {
		out[i] = b>>n | b<<(8-n)
	}
	return out
}

func notAll(src []byte) []byte {
	out := make([]byte, len(src))
	for i, b := range src {
		out[i] = ^b
	}
	return out
}

func nibbleAll(src []byte) []byte {
	out := make([]byte, len(src))
	for i, b := range src {
		out[i] = b<<4 | b>>4
	}
	return out
}

// ── table ────────────────────────────────────────────────────────────────

func TestSignatureTableIsPopulated(t *testing.T) {
	if n := SignatureCount(); n < 25 {
		t.Fatalf("signature table holds %d entries, expected the full set", n)
	}
	for _, s := range Signatures() {
		if s.Name == "" || len(s.Magic) == 0 {
			t.Errorf("signature %+v is incomplete", s)
		}
		if s.Span() <= 0 {
			t.Errorf("signature %s has a non-positive span", s.Name)
		}
		if len(s.Anchors()) != len(s.Magic)+len(s.Magic2) {
			t.Errorf("signature %s: anchor count disagrees with its magic runs", s.Name)
		}
	}
}

func TestWebpRequiresBothTagRuns(t *testing.T) {
	good := append([]byte("RIFF\x10\x00\x00\x00WEBP"), make([]byte, 32)...)
	if sig, ok := Identify(good, 0); !ok || sig.Name != "webp" {
		t.Errorf("Identify = %q/%v, want webp/true", sig.Name, ok)
	}
	// A RIFF wrapper that is not WebP must not be claimed.
	bad := append([]byte("RIFF\x10\x00\x00\x00AVI "), make([]byte, 32)...)
	if sig, ok := Identify(bad, 0); ok {
		t.Errorf("a RIFF/AVI file was identified as %q", sig.Name)
	}
}

// ── direct ──────────────────────────────────────────────────────────────

func TestDirectPNGNeedsNoTransform(t *testing.T) {
	res := Analyze(validPNG(), Options{})
	if !res.Direct {
		t.Fatal("a plain PNG should be recognised directly")
	}
	best, ok := res.Best()
	if !ok {
		t.Fatal("no candidate")
	}
	if best.Signature != "png" {
		t.Errorf("Signature = %q, want png", best.Signature)
	}
	if !best.Transform.IsIdentity() {
		t.Errorf("Transform = %s, want identity", best.Transform)
	}
	if best.Score < 80 {
		t.Errorf("Score = %d; a clean PNG with a valid IHDR should score high", best.Score)
	}
	if best.Family != FamilyRaster {
		t.Errorf("Family = %v, want raster", best.Family)
	}
}

// ── recovery: the point of the package ──────────────────────────────────────

func TestSingleByteXORIsRecovered(t *testing.T) {
	res := Analyze(xorWith(validPNG(), 0x5A), Options{})
	if res.Direct {
		t.Fatal("the obfuscated buffer is not a direct match")
	}
	best, ok := res.Best()
	if !ok {
		t.Fatal("no candidate recovered")
	}
	if best.Signature != "png" {
		t.Fatalf("Signature = %q, want png", best.Signature)
	}
	if best.Transform.Kind != KindXOR {
		t.Fatalf("Kind = %s, want an xor", best.Transform)
	}
	// The shortest key that explains the header is the right answer; a longer
	// key fits by having more freedom, not by being more correct.
	if len(best.Transform.Key) != 1 || best.Transform.Key[0] != 0x5A {
		t.Errorf("Key = %x, want [5a]", best.Transform.Key)
	}
	plain := best.Transform.Apply(xorWith(validPNG(), 0x5A))
	if !bytes.Equal(plain, validPNG()) {
		t.Error("applying the recovered transform did not reproduce the PNG")
	}
}

func TestRepeatingXORKeyIsRecovered(t *testing.T) {
	key := []byte{0xDE, 0xAD, 0xBE}
	res := Analyze(xorWith(validPNG(), key...), Options{})
	best, ok := res.Best()
	if !ok {
		t.Fatal("no candidate recovered")
	}
	if best.Transform.Kind != KindXOR || !bytes.Equal(best.Transform.Key, key) {
		t.Fatalf("Transform = %s, want xor[3]=de ad be", best.Transform)
	}
}

// The real target. A GPU texture behind a rolling key is exactly the shape
// that used to need a bespoke per-game reader.
func TestKTX2UnderARollingKeyIsRecovered(t *testing.T) {
	key := []byte{0xC3, 0x1F, 0xA7, 0x55}
	ct := xorWith(validKTX2(), key...)

	res := Analyze(ct, Options{})
	best, ok := res.Best()
	if !ok {
		t.Fatal("no candidate recovered")
	}
	if best.Signature != "ktx2" {
		t.Fatalf("Signature = %q, want ktx2", best.Signature)
	}
	if best.Family != FamilyGPUTexture {
		t.Errorf("Family = %v, want gpu-texture", best.Family)
	}
	if !bytes.Equal(best.Transform.Key, key) {
		t.Errorf("Key = %x, want %x", best.Transform.Key, key)
	}
	if !bytes.Equal(best.Transform.Apply(ct), validKTX2()) {
		t.Error("the recovered transform did not reproduce the texture")
	}
}

func TestAddTransformIsRecovered(t *testing.T) {
	res := Analyze(subWith(validPNG(), 7), Options{})
	best, ok := res.Best()
	if !ok {
		t.Fatal("no candidate recovered")
	}
	if best.Transform.Kind != KindAdd || best.Transform.N != 7 {
		t.Errorf("Transform = %s, want add+7", best.Transform)
	}
}

func TestRotateTransformIsRecovered(t *testing.T) {
	res := Analyze(rotrWith(validPNG(), 3), Options{})
	best, ok := res.Best()
	if !ok {
		t.Fatal("no candidate recovered")
	}
	if best.Transform.Kind != KindRotate || best.Transform.N != 3 {
		t.Errorf("Transform = %s, want rotl3", best.Transform)
	}
}

func TestComplementAndNibbleSwapAreRecovered(t *testing.T) {
	if best, ok := Analyze(notAll(validPNG()), Options{}).Best(); !ok || best.Transform.Kind != KindNot {
		t.Errorf("complement not recovered: %+v", best)
	}
	if best, ok := Analyze(nibbleAll(validPNG()), Options{}).Best(); !ok || best.Transform.Kind != KindNibble {
		t.Errorf("nibble swap not recovered: %+v", best)
	}
}

// ── false positives ────────────────────────────────────────────────────

// A two-byte magic can always be "solved": one byte derives the key and the
// other is consumed deriving it, leaving nothing to verify against. Reporting
// that as a recovery would make the whole module noise.
func TestShortMagicsNeverYieldASolvedKey(t *testing.T) {
	bmp := append([]byte{'B', 'M'}, make([]byte, 62)...)
	res := Analyze(xorWith(bmp, 0x77), Options{SkipScan: true})

	for _, c := range res.Candidates {
		switch c.Signature {
		case "bmp", "gzip", "zlib-default", "zlib-best", "zlib-none":
			t.Errorf("signature %s has only two fixed bytes and must never be solved for; got %s",
				c.Signature, c.Transform)
		}
	}
}

// Structured, non-random input is the hard case for a solver: an arithmetic
// progression looks orderly enough to tempt a bad scorer.
func TestStructuredNoiseProducesNoConfidentCandidate(t *testing.T) {
	noise := make([]byte, 512)
	for i := range noise {
		noise[i] = byte(i*37 + 11)
	}
	res := Analyze(noise, Options{SkipScan: true})
	for _, c := range res.Candidates {
		if c.Score >= 50 {
			t.Errorf("noise yielded a confident candidate: %s via %s, score %d",
				c.Signature, c.Transform, c.Score)
		}
	}
}

func TestTinyBufferIsHandled(t *testing.T) {
	for _, in := range [][]byte{nil, {}, {0x89}, {0x89, 'P', 'N'}} {
		res := Analyze(in, Options{})
		if len(res.Candidates) != 0 {
			t.Errorf("Analyze(%x) produced %d candidates", in, len(res.Candidates))
		}
	}
}

// ── embedded streams: the generic replacement for a per-format reader ───────

// This is the .sctx shape: a short proprietary head, then one zstd frame. The
// scan finds it without knowing anything about the wrapper.
func TestEmbeddedZstdFrameIsFoundBehindAProprietaryHead(t *testing.T) {
	head := make([]byte, 12)
	binary.LittleEndian.PutUint32(head[0:4], 0x34)
	binary.LittleEndian.PutUint32(head[4:8], 0x1C)
	copy(head[8:12], "SCTX")

	// descriptor 0x60: content-size field is 2 bytes, single segment, no
	// dictionary. The stored value is biased by 256.
	frame := []byte{0x28, 0xB5, 0x2F, 0xFD, 0x60, 0x00, 0x04}

	blob := append(append([]byte{}, head...), frame...)
	blob = append(blob, make([]byte, 64)...)

	res := Analyze(blob, Options{})
	if len(res.Frames) == 0 {
		t.Fatal("the embedded zstd frame was not found")
	}
	f := res.Frames[0]
	if f.Format != "zstd" {
		t.Errorf("Format = %q, want zstd", f.Format)
	}
	if f.Offset != 12 {
		t.Errorf("Offset = %d, want 12", f.Offset)
	}
	if f.DeclaredSize != 1280 {
		t.Errorf("DeclaredSize = %d, want 1280 (1024 stored, biased by 256)", f.DeclaredSize)
	}
	if !f.Decodable {
		t.Error("zstd should be decodable via pkg/ml/zstd")
	}
	if best, ok := res.Best(); !ok || best.Base != 12 {
		t.Errorf("best candidate base = %d, want the payload offset 12", best.Base)
	}
}

func TestZstdFrameHeaderVariants(t *testing.T) {
	// No content size: descriptor 0x00 means a window descriptor follows and
	// no size is recorded.
	f, ok := parseZstdFrame([]byte{0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x40, 0x00}, 0)
	if !ok {
		t.Fatal("a sizeless frame header is still valid")
	}
	if f.DeclaredSize != SizeUnknown {
		t.Errorf("DeclaredSize = %d, want SizeUnknown", f.DeclaredSize)
	}

	// Reserved bit 3 set: not a zstd frame, whatever the magic says.
	if _, ok := parseZstdFrame([]byte{0x28, 0xB5, 0x2F, 0xFD, 0x08, 0x40}, 0); ok {
		t.Error("a frame with the reserved bit set must be rejected")
	}

	// Truncated before the content-size field.
	if _, ok := parseZstdFrame([]byte{0x28, 0xB5, 0x2F, 0xFD, 0x60}, 0); ok {
		t.Error("a truncated frame header must be rejected")
	}
}

func TestZlibCheckValueRejectsCoincidence(t *testing.T) {
	if _, ok := parseZlibFrame([]byte{0x78, 0x9C, 0x00}, 0); !ok {
		t.Error("78 9c is the canonical zlib header")
	}
	if _, ok := parseZlibFrame([]byte{0x78, 0x9D, 0x00}, 0); ok {
		t.Error("78 9d fails the multiple-of-31 check and must be rejected")
	}
	if _, ok := parseZlibFrame([]byte{0x79, 0x9C, 0x00}, 0); ok {
		t.Error("compression method 9 is not deflate")
	}
}

func TestGzipFrameReportsISIZE(t *testing.T) {
	blob := []byte{0x1F, 0x8B, 0x08, 0, 0, 0, 0, 0, 0, 0x03}
	blob = append(blob, make([]byte, 8)...)
	binary.LittleEndian.PutUint32(blob[len(blob)-4:], 4096)

	f, ok := parseGzipFrame(blob, 0)
	if !ok {
		t.Fatal("a deflate gzip header should parse")
	}
	if f.DeclaredSize != 4096 {
		t.Errorf("DeclaredSize = %d, want 4096", f.DeclaredSize)
	}
	if !f.Decodable {
		t.Error("gzip IS decodable with the standard library")
	}
}

func TestEmbeddedGLBIsFoundInsideAWrapper(t *testing.T) {
	blob := append([]byte("PROPRIETARYHEAD!"), 'g', 'l', 'T', 'F')
	ver := make([]byte, 8)
	binary.LittleEndian.PutUint32(ver[0:4], 2)
	binary.LittleEndian.PutUint32(ver[4:8], 64)
	blob = append(blob, ver...)
	blob = append(blob, make([]byte, 32)...)

	res := Analyze(blob, Options{})
	found := false
	for _, c := range res.Candidates {
		if c.Signature == "glb" && c.Base == 16 {
			found = true
		}
	}
	if !found {
		t.Errorf("the embedded GLB at offset 16 was not reported; candidates = %+v", res.Candidates)
	}
}

// ── transforms ────────────────────────────────────────────────────────

func TestApplyDoesNotMutateItsInput(t *testing.T) {
	src := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	keep := append([]byte{}, src...)
	for _, tr := range []Transform{
		{Kind: KindXOR, Key: []byte{0xFF}},
		{Kind: KindAdd, N: 9},
		{Kind: KindRotate, N: 3},
		{Kind: KindNot},
		{Kind: KindReverse},
		{Kind: KindNibble},
		{Kind: KindSwap16},
		{Kind: KindSwap32},
	} {
		_ = tr.Apply(src)
		if !bytes.Equal(src, keep) {
			t.Fatalf("%s mutated its input", tr)
		}
	}
}

func TestInvolutiveTransformsRoundTrip(t *testing.T) {
	src := []byte{0x00, 0x11, 0x89, 0xFF, 0x5A, 0xA5, 0x0F, 0xF0}
	for _, tr := range []Transform{
		{Kind: KindXOR, Key: []byte{0x3C, 0x77}},
		{Kind: KindNot},
		{Kind: KindReverse},
		{Kind: KindNibble},
		{Kind: KindSwap16},
		{Kind: KindSwap32},
	} {
		if got := tr.Apply(tr.Apply(src)); !bytes.Equal(got, src) {
			t.Errorf("%s is not involutive: %x -> %x", tr, src, got)
		}
	}
}

func TestAddAndRotateInvertWithTheirComplement(t *testing.T) {
	src := []byte{0x00, 0x11, 0x89, 0xFF, 0x5A, 0xA5, 0x0F, 0xF0}

	add := Transform{Kind: KindAdd, N: 7}
	back := Transform{Kind: KindAdd, N: 249} // -7 modulo 256
	if got := back.Apply(add.Apply(src)); !bytes.Equal(got, src) {
		t.Errorf("add+7 then add+249 gave %x, want %x", got, src)
	}

	rot := Transform{Kind: KindRotate, N: 3}
	rback := Transform{Kind: KindRotate, N: 5}
	if got := rback.Apply(rot.Apply(src)); !bytes.Equal(got, src) {
		t.Errorf("rotl3 then rotl5 gave %x, want %x", got, src)
	}
}

func TestIdentityIsRecognisedThroughEveryDisguise(t *testing.T) {
	for _, tr := range []Transform{
		{Kind: KindIdentity},
		{Kind: KindXOR, Key: []byte{0x00, 0x00}},
		{Kind: KindAdd, N: 0},
		{Kind: KindRotate, N: 0},
		{Kind: KindRotate, N: 8},
	} {
		if !tr.IsIdentity() {
			t.Errorf("%s should be recognised as identity", tr)
		}
	}
	for _, tr := range []Transform{
		{Kind: KindXOR, Key: []byte{0x00, 0x01}},
		{Kind: KindAdd, N: 1},
		{Kind: KindRotate, N: 4},
		{Kind: KindNot},
	} {
		if tr.IsIdentity() {
			t.Errorf("%s is not identity", tr)
		}
	}
}

func TestOptionsNormalizeFillsDefaults(t *testing.T) {
	o := Options{}.Normalize()
	if o.MaxKeyLen <= 0 || o.MaxCandidates <= 0 || o.ScanWindow <= 0 {
		t.Errorf("Normalize left a zero field: %+v", o)
	}
	keep := Options{MaxKeyLen: 3, MaxCandidates: 1, ScanWindow: 8}.Normalize()
	if keep.MaxKeyLen != 3 || keep.MaxCandidates != 1 || keep.ScanWindow != 8 {
		t.Errorf("Normalize overwrote explicit values: %+v", keep)
	}
}
