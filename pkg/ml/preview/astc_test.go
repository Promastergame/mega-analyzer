package preview

import (
	"errors"
	"strings"
	"testing"
)

// astcVoidBlock builds a void-extent block: the ASTC encoding of "this whole
// block is one colour". Handy for tests because the expected pixels are known
// exactly without decoding anything.
//
// Bits 0..8 are the void-extent pattern 111111100, bit 9 stays clear to mean
// LDR, bits 10 and 11 are reserved and must both be set, and the four extent
// coordinates are all ones, which is the encoding for "ignore the extent".
func astcVoidBlock(r, g, b, a uint8) []byte {
	blk := make([]byte, 16)
	blk[0] = 0xFC
	blk[1] = 0xFD
	for i := 2; i < 8; i++ {
		blk[i] = 0xFF
	}
	// The colours are UNORM16, so an eight-bit value is multiplied by 257.
	put := func(at int, c uint8) {
		v := uint16(c) * 257
		blk[at] = byte(v)
		blk[at+1] = byte(v >> 8)
	}
	put(8, r)
	put(10, g)
	put(12, b)
	put(14, a)
	return blk
}

// astcSolidBlock builds an ordinary weighted block: a 4x4 weight grid at range
// 0..3, single plane, luminance endpoints. The endpoint and weight bits are
// arbitrary - any pattern there is a legal texture - which is exactly what a
// layout-inference test needs.
func astcSolidBlock(seed byte) []byte {
	blk := make([]byte, 16)
	blk[0] = 0x42
	blk[1] = 0x00
	for i := 2; i < 16; i++ {
		blk[i] = seed + byte(i)*7
	}
	return blk
}

func astcBlocks(n int) []byte {
	out := make([]byte, 0, n*16)
	for i := 0; i < n; i++ {
		out = append(out, astcSolidBlock(byte(i))...)
	}
	return out
}

// astcFile wraps blocks in the reference encoder's container.
func astcFile(bw, bh, w, h int, blocks []byte) []byte {
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

func TestCanDecodeASTCOnlyClaimsContainers(t *testing.T) {
	file := astcFile(4, 4, 4, 4, astcVoidBlock(1, 2, 3, 4))
	if !CanDecodeASTC(file) {
		t.Error("a .astc file should be recognised")
	}
	if !CanDecode(file) {
		t.Error("the general check should recognise it too")
	}
	// A bare payload has no header, so a cheap signature test must not claim
	// it; identifying those takes a pass over the block modes.
	if CanDecodeASTC(astcBlocks(4)) {
		t.Error("headerless blocks should not pass a signature test")
	}
	if CanDecodeASTC(astcFile(4, 4, 4, 4, nil)) {
		t.Error("a header with no blocks behind it is not decodable")
	}
	for _, junk := range [][]byte{nil, {0x13}, {0x13, 0xAB, 0xA1, 0x5C}} {
		if CanDecodeASTC(junk) {
			t.Errorf("%v should not be decodable", junk)
		}
	}
}

// The point of joining the ordinary chain: Render needs no special casing for
// a .astc file, because the container carries its own dimensions.
func TestRenderDecodesAnASTCFileThroughTheNormalChain(t *testing.T) {
	file := astcFile(4, 4, 7, 5, astcVoidBlock(12, 34, 56, 200))
	res, err := Render(file, Options{MaxDim: 256, NoFallback: true})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if res.Decoder != "astc" {
		t.Errorf("decoder %q, want astc", res.Decoder)
	}
	if res.Lossy {
		t.Error("a real block decode is not lossy")
	}
	if res.SrcWidth != 7 || res.SrcHeight != 5 {
		t.Errorf("source %dx%d, want 7x5", res.SrcWidth, res.SrcHeight)
	}
	if len(res.PNG) == 0 {
		t.Error("no PNG came out")
	}
	img, format, err := decode(file)
	if err != nil || format != "astc" {
		t.Fatalf("decode gave (%q, %v)", format, err)
	}
	if got := img.Bounds().Dx(); got != 7 {
		t.Errorf("decoded width %d, want 7", got)
	}
}

func TestRenderASTCWithAKnownSpec(t *testing.T) {
	spec := ASTCSpec{Width: 16, Height: 16, BlockWidth: 4, BlockHeight: 4}
	if !spec.Complete() {
		t.Fatal("the spec should be complete")
	}
	res, err := RenderASTC(astcBlocks(16), spec, Options{MaxDim: 256})
	if err != nil {
		t.Fatalf("RenderASTC: %v", err)
	}
	if res.Decoder != "astc" || res.SrcWidth != 16 || res.SrcHeight != 16 {
		t.Errorf("got %q at %dx%d", res.Decoder, res.SrcWidth, res.SrcHeight)
	}
	if !strings.Contains(res.Note, "4x4 blocks") {
		t.Errorf("note %q should describe the spec", res.Note)
	}
	if !strings.Contains(res.Note, "linear") {
		t.Errorf("note %q should state the colour space", res.Note)
	}

	srgb := spec
	srgb.SRGB = true
	if !strings.Contains(srgb.String(), "sRGB") {
		t.Errorf("an sRGB spec describes itself as %q", srgb.String())
	}
}

func TestRenderASTCRejectsAnIncompleteSpec(t *testing.T) {
	data := astcBlocks(16)
	for _, spec := range []ASTCSpec{
		{Width: 16, Height: 16},
		{Width: 0, Height: 16, BlockWidth: 4, BlockHeight: 4},
		{Width: 16, Height: 16, BlockWidth: 7, BlockHeight: 7},
	} {
		if spec.Complete() {
			t.Errorf("%v should be incomplete", spec)
		}
		if _, err := RenderASTC(data, spec, Options{}); !errors.Is(err, ErrBadHeader) {
			t.Errorf("%v should be ErrBadHeader, got %v", spec, err)
		}
	}
}

// Inference is deliberately kept out of the automatic chain, so this is the
// explicit entry point, and it has to say what it assumed.
func TestRenderASTCInferredReportsWhatItAssumed(t *testing.T) {
	res, layout, st, err := RenderASTCInferred(astcBlocks(16), false, Options{MaxDim: 256})
	if err != nil {
		t.Fatalf("RenderASTCInferred: %v", err)
	}
	if res.Decoder != "astc" {
		t.Errorf("decoder %q, want astc", res.Decoder)
	}
	if layout.Footprint.Width != 4 || layout.Footprint.Height != 4 {
		t.Errorf("inferred footprint %s, want 4x4", layout.Footprint)
	}
	if layout.Blocks != 16 {
		t.Errorf("counted %d blocks, want 16", layout.Blocks)
	}
	if st.Blocks == 0 {
		t.Error("the stats should describe the decode")
	}
	if !strings.Contains(res.Note, "aspect") {
		t.Errorf("note %q must admit the aspect ratio was assumed", res.Note)
	}

	if _, _, _, err := RenderASTCInferred([]byte{1, 2, 3}, false, Options{}); err == nil {
		t.Error("a payload that is not blocks should fail")
	}

	img, spec, note, err := DecodeASTCInferred(astcBlocks(16), true)
	if err != nil {
		t.Fatalf("DecodeASTCInferred: %v", err)
	}
	if !spec.SRGB || !spec.Complete() {
		t.Errorf("spec %v should be complete and sRGB", spec)
	}
	if img.Bounds().Dx() != spec.Width {
		t.Errorf("image is %d wide, spec says %d", img.Bounds().Dx(), spec.Width)
	}
	if note == "" {
		t.Error("the note should not be empty")
	}
}

func TestDecodeASTCContainerRejectsNonASTC(t *testing.T) {
	if _, _, err := DecodeASTCContainer([]byte("not a texture")); !errors.Is(err, ErrWrongFormat) {
		t.Errorf("junk should be ErrWrongFormat, got %v", err)
	}
	truncated := astcFile(4, 4, 64, 64, astcVoidBlock(1, 1, 1, 1))
	if _, _, err := DecodeASTCContainer(truncated); err == nil {
		t.Error("a header promising 64x64 with one block should fail")
	}
}
