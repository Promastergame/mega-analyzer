package assetscan

import (
	"strings"
	"testing"
)

// astcTestBlock is one legal ASTC block: a 4x4 weight grid at range 0..3 with
// luminance endpoints. The bits above the block mode are arbitrary, because
// any pattern there is a valid texture, which is all these tests need.
func astcTestBlock(seed byte) []byte {
	blk := make([]byte, 16)
	blk[0] = 0x42
	blk[1] = 0x00
	for i := 2; i < 16; i++ {
		blk[i] = seed + byte(i)*7
	}
	return blk
}

func astcTestPayload(n int) []byte {
	out := make([]byte, 0, n*16)
	for i := 0; i < n; i++ {
		out = append(out, astcTestBlock(byte(i))...)
	}
	return out
}

func astcTestFile(bw, bh, w, h int, blocks []byte) []byte {
	hdr := make([]byte, 16)
	hdr[0], hdr[1], hdr[2], hdr[3] = 0x13, 0xAB, 0xA1, 0x5C
	hdr[4] = byte(bw)
	hdr[5] = byte(bh)
	hdr[6] = 1
	put24 := func(at, v int) {
		hdr[at] = byte(v)
		hdr[at+1] = byte(v >> 8)
		hdr[at+2] = byte(v >> 16)
	}
	put24(7, w)
	put24(10, h)
	put24(13, 1)
	return append(hdr, blocks...)
}

// This is the payload shape that used to become a byte map with a note saying
// a block decoder was missing: no container, no signature, nothing but blocks.
func TestTryASTCIdentifiesAHeaderlessPayload(t *testing.T) {
	s := &scanner{opts: Options{}.Normalize()}
	it := &Item{Path: "atlas.bin"}

	if !s.tryASTC(it, astcTestPayload(16), "file") {
		t.Fatal("a bare block payload was not identified")
	}
	if it.Class != ClassTexture {
		t.Errorf("class %q, want %q", it.Class, ClassTexture)
	}
	if it.Format != "astc" {
		t.Errorf("format %q, want astc", it.Format)
	}
	if it.ASTC == nil {
		t.Fatal("no ASTC block was reported")
	}
	if it.ASTC.Footprint != "4x4" {
		t.Errorf("footprint %q, want 4x4", it.ASTC.Footprint)
	}
	if it.ASTC.Blocks != 16 {
		t.Errorf("%d blocks, want 16", it.ASTC.Blocks)
	}
	if it.ASTC.Width != 16 || it.ASTC.Height != 16 {
		t.Errorf("%dx%d assumed, want 16x16", it.ASTC.Width, it.ASTC.Height)
	}
	// The block count cannot pin the aspect ratio, and the report has to say
	// so rather than presenting a guess as a measurement.
	if it.ASTC.Certain {
		t.Error("a single level does not pin the dimensions")
	}
	if !strings.Contains(strings.Join(it.Notes, " "), "legal") {
		t.Errorf("notes %v should carry the block-mode summary", it.Notes)
	}
}

func TestTryASTCRecognisesAMipPyramid(t *testing.T) {
	s := &scanner{opts: Options{}.Normalize()}
	it := &Item{Path: "tex.sctx"}

	// 64x64 in 4x4 blocks is 256 + 64 + 16 + 4 + 1 + 1 + 1 = 343 blocks.
	if !s.tryASTC(it, astcTestPayload(343), "recovered") {
		t.Fatal("a pyramid payload was not identified")
	}
	if it.ASTC == nil {
		t.Fatal("no ASTC block was reported")
	}
	if it.ASTC.MipLevels != 7 {
		t.Errorf("%d mip levels, want 7", it.ASTC.MipLevels)
	}
	if !it.ASTC.Certain {
		t.Error("a full chain pins the dimensions exactly")
	}
	if it.ASTC.Width != 64 || it.ASTC.Height != 64 {
		t.Errorf("base level %dx%d, want 64x64", it.ASTC.Width, it.ASTC.Height)
	}
	if !strings.Contains(it.Verdict, "mip pyramid") {
		t.Errorf("verdict %q should mention the pyramid", it.Verdict)
	}
}

func TestTryASTCDeclinesWhatIsNotATexture(t *testing.T) {
	s := &scanner{opts: Options{}.Normalize()}

	random := make([]byte, 64*16)
	state := uint32(9876)
	for i := range random {
		state = state*1664525 + 1013904223
		random[i] = byte(state >> 24)
	}
	for name, data := range map[string][]byte{
		"random bytes":      random,
		"all zeroes":        make([]byte, 64*16),
		"a misaligned size": astcTestPayload(4)[:60],
		"nothing at all":    nil,
		"a text file":       []byte(strings.Repeat("hello world, ", 64)),
	} {
		it := &Item{Path: "x"}
		if s.tryASTC(it, data, "file") {
			t.Errorf("%s was claimed as ASTC", name)
		}
		if it.Class != "" || it.ASTC != nil {
			t.Errorf("%s left the item modified", name)
		}
	}
}

func TestNoASTCTurnsTheDecoderOff(t *testing.T) {
	s := &scanner{opts: Options{NoASTC: true}.Normalize()}
	it := &Item{Path: "atlas.bin"}
	if s.tryASTC(it, astcTestPayload(16), "file") {
		t.Error("-assets-no-astc should stop the decoder")
	}
	if it.ASTC != nil {
		t.Error("nothing should have been reported")
	}

	s.describeASTC(it, astcTestFile(4, 4, 16, 16, astcTestPayload(16)))
	if it.ASTC != nil {
		t.Error("-assets-no-astc should also silence the container description")
	}
	// Normalize must not quietly clear the switch.
	normalized := Options{NoASTC: true}.Normalize()
	if !normalized.NoASTC {
		t.Error("Normalize dropped NoASTC")
	}
}

func TestDescribeASTCReadsAContainerHeader(t *testing.T) {
	s := &scanner{opts: Options{}.Normalize()}
	it := &Item{Path: "tex.astc"}

	s.describeASTC(it, astcTestFile(6, 5, 12, 10, astcTestPayload(4)))
	if it.ASTC == nil {
		t.Fatal("a .astc container was not described")
	}
	if it.ASTC.Footprint != "6x5" {
		t.Errorf("footprint %q, want 6x5", it.ASTC.Footprint)
	}
	if it.ASTC.Width != 12 || it.ASTC.Height != 10 {
		t.Errorf("%dx%d, want 12x10", it.ASTC.Width, it.ASTC.Height)
	}
	// A container states its dimensions, so nothing was assumed.
	if !it.ASTC.Certain {
		t.Error("a container gives exact dimensions")
	}
	if it.ASTC.Blocks != 4 {
		t.Errorf("%d blocks, want 4", it.ASTC.Blocks)
	}

	// Safe to call on anything: a PNG or a zip must simply be left alone.
	plain := &Item{Path: "a.png"}
	s.describeASTC(plain, []byte("\x89PNG\r\n\x1a\n and then some"))
	if plain.ASTC != nil {
		t.Error("a PNG should not be described as ASTC")
	}
}
