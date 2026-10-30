package astc

import (
	"encoding/binary"
	"errors"
	"testing"
)

func astcFileHeader(bw, bh, w, h int) []byte {
	b := make([]byte, FileHeaderSize)
	copy(b, FileMagic[:])
	b[4] = byte(bw)
	b[5] = byte(bh)
	b[6] = 1
	put24 := func(at, v int) {
		b[at] = byte(v)
		b[at+1] = byte(v >> 8)
		b[at+2] = byte(v >> 16)
	}
	put24(7, w)
	put24(10, h)
	put24(13, 1)
	return b
}

func TestParseFileHeaderReadsTheReferenceEncoderLayout(t *testing.T) {
	h, err := ParseFileHeader(astcFileHeader(6, 5, 300, 70000))
	if err != nil {
		t.Fatalf("ParseFileHeader: %v", err)
	}
	if h.Footprint != (Footprint{Width: 6, Height: 5}) {
		t.Errorf("footprint %s, want 6x5", h.Footprint)
	}
	// The dimensions are three-byte little-endian values, so a height above
	// 65535 is the case that catches a two-byte misreading.
	if h.Width != 300 || h.Height != 70000 {
		t.Errorf("dimensions %dx%d, want 300x70000", h.Width, h.Height)
	}
	if h.DataOffset != 16 {
		t.Errorf("data starts at %d, want 16", h.DataOffset)
	}
	if h.BlockDepth != 1 {
		t.Errorf("block depth %d, want 1", h.BlockDepth)
	}
}

func TestParseFileHeaderRejections(t *testing.T) {
	if _, err := ParseFileHeader([]byte{1, 2, 3, 4}); !errors.Is(err, ErrHeader) {
		t.Errorf("a stub should be ErrHeader, got %v", err)
	}
	junk := astcFileHeader(4, 4, 16, 16)
	junk[0] = 0
	if _, err := ParseFileHeader(junk); !errors.Is(err, ErrMagic) {
		t.Errorf("a wrong magic should be ErrMagic, got %v", err)
	}
	threeD := astcFileHeader(4, 4, 16, 16)
	threeD[6] = 4
	if _, err := ParseFileHeader(threeD); !errors.Is(err, ErrFootprint) {
		t.Errorf("a 3D footprint should be ErrFootprint, got %v", err)
	}
	if _, err := ParseFileHeader(astcFileHeader(7, 7, 16, 16)); !errors.Is(err, ErrFootprint) {
		t.Errorf("7x7 should be ErrFootprint, got %v", err)
	}
	if _, err := ParseFileHeader(astcFileHeader(4, 4, 0, 16)); !errors.Is(err, ErrDims) {
		t.Errorf("a zero width should be ErrDims, got %v", err)
	}
	if !IsFile(astcFileHeader(4, 4, 16, 16)) {
		t.Error("IsFile should recognise its own header")
	}
	if IsFile([]byte{0x13, 0xAB}) {
		t.Error("IsFile should not match a two-byte prefix")
	}
}

func TestDecodeFileEndToEnd(t *testing.T) {
	data := append(astcFileHeader(4, 4, 7, 5), tealBlocks(t, 4)...)
	im, st, err := DecodeFile(data, false)
	if err != nil {
		t.Fatalf("DecodeFile: %v", err)
	}
	if im.Width != 7 || im.Height != 5 {
		t.Fatalf("image is %dx%d, want 7x5", im.Width, im.Height)
	}
	if st.Blocks != 4 || st.VoidExtent != 4 {
		t.Errorf("stats say %d blocks and %d void extents, want 4 and 4",
			st.Blocks, st.VoidExtent)
	}
	if got := im.At(6, 4); got != [4]uint8{12, 34, 56, 200} {
		t.Errorf("the far corner is %v", got)
	}
}

// ---- format enums

func TestVkFormatCoversEveryASTCFormat(t *testing.T) {
	if _, _, ok := FootprintForVkFormat(156); ok {
		t.Error("156 is below the ASTC range")
	}
	if _, _, ok := FootprintForVkFormat(185); ok {
		t.Error("185 is above the ASTC LDR range")
	}
	seen := map[string]int{}
	for vk := uint32(157); vk <= 184; vk++ {
		fp, srgb, ok := FootprintForVkFormat(vk)
		if !ok {
			t.Fatalf("vkFormat %d should be ASTC", vk)
		}
		if !ValidFootprint(fp.Width, fp.Height) {
			t.Fatalf("vkFormat %d gave the illegal footprint %s", vk, fp)
		}
		if srgb != (vk%2 == 0) {
			t.Errorf("vkFormat %d sRGB = %v", vk, srgb)
		}
		seen[fp.String()]++
	}
	if len(seen) != 14 {
		t.Errorf("the 28 formats cover %d footprints, want 14", len(seen))
	}
	for fp, n := range seen {
		if n != 2 {
			t.Errorf("%s appears %d times, want a linear and an sRGB form", fp, n)
		}
	}
	// Both ends of the table, since an off-by-one here silently swaps every
	// footprint in between.
	if fp, srgb, _ := FootprintForVkFormat(157); fp != (Footprint{Width: 4, Height: 4}) || srgb {
		t.Errorf("157 is %s srgb=%v, want 4x4 linear", fp, srgb)
	}
	if fp, srgb, _ := FootprintForVkFormat(158); fp != (Footprint{Width: 4, Height: 4}) || !srgb {
		t.Errorf("158 is %s srgb=%v, want 4x4 sRGB", fp, srgb)
	}
	if fp, _, _ := FootprintForVkFormat(171); fp != (Footprint{Width: 8, Height: 8}) {
		t.Errorf("171 is %s, want 8x8", fp)
	}
	if fp, srgb, _ := FootprintForVkFormat(184); fp != (Footprint{Width: 12, Height: 12}) || !srgb {
		t.Errorf("184 is %s srgb=%v, want 12x12 sRGB", fp, srgb)
	}
}

func TestGLFormatMapping(t *testing.T) {
	if fp, srgb, ok := FootprintForGLFormat(0x93B0); !ok ||
		fp != (Footprint{Width: 4, Height: 4}) || srgb {
		t.Errorf("0x93B0 is %s srgb=%v ok=%v, want 4x4 linear", fp, srgb, ok)
	}
	if fp, _, ok := FootprintForGLFormat(0x93BD); !ok ||
		fp != (Footprint{Width: 12, Height: 12}) {
		t.Errorf("0x93BD is %s ok=%v, want 12x12", fp, ok)
	}
	if fp, srgb, ok := FootprintForGLFormat(0x93D0); !ok ||
		fp != (Footprint{Width: 4, Height: 4}) || !srgb {
		t.Errorf("0x93D0 is %s srgb=%v ok=%v, want 4x4 sRGB", fp, srgb, ok)
	}
	if fp, srgb, ok := FootprintForGLFormat(0x93DD); !ok ||
		fp != (Footprint{Width: 12, Height: 12}) || !srgb {
		t.Errorf("0x93DD is %s srgb=%v ok=%v, want 12x12 sRGB", fp, srgb, ok)
	}
	for _, gl := range []uint32{0x93AF, 0x93BE, 0x93CF, 0x93DE, 0} {
		if _, _, ok := FootprintForGLFormat(gl); ok {
			t.Errorf("%#x is not an ASTC internal format", gl)
		}
	}
}

// ---- KTX2

func buildKTX2(vk uint32, w, h, levels int, scheme uint32, payload []byte) []byte {
	head := ktx2FixedHeader + levels*24
	b := make([]byte, head)
	copy(b, KTX2Magic[:])
	binary.LittleEndian.PutUint32(b[12:], vk)
	binary.LittleEndian.PutUint32(b[16:], 1)
	binary.LittleEndian.PutUint32(b[20:], uint32(w))
	binary.LittleEndian.PutUint32(b[24:], uint32(h))
	binary.LittleEndian.PutUint32(b[40:], uint32(levels))
	binary.LittleEndian.PutUint32(b[44:], scheme)
	for i := 0; i < levels; i++ {
		at := ktx2FixedHeader + i*24
		binary.LittleEndian.PutUint64(b[at:], uint64(head))
		binary.LittleEndian.PutUint64(b[at+8:], uint64(len(payload)))
		binary.LittleEndian.PutUint64(b[at+16:], uint64(len(payload)))
	}
	return append(b, payload...)
}

func TestParseKTX2ReadsAnASTCTexture(t *testing.T) {
	payload := tealBlocks(t, 4)
	data := buildKTX2(157, 8, 8, 1, SupercompressionZstd, payload)
	if !IsKTX2(data) {
		t.Fatal("IsKTX2 should recognise the identifier")
	}
	k, err := ParseKTX2(data)
	if err != nil {
		t.Fatalf("ParseKTX2: %v", err)
	}
	if !k.IsASTC {
		t.Fatal("vkFormat 157 is ASTC")
	}
	if k.Footprint != (Footprint{Width: 4, Height: 4}) || k.SRGB {
		t.Errorf("footprint %s srgb=%v, want 4x4 linear", k.Footprint, k.SRGB)
	}
	if k.Width != 8 || k.Height != 8 {
		t.Errorf("dimensions %dx%d, want 8x8", k.Width, k.Height)
	}
	if len(k.Levels) != 1 {
		t.Fatalf("%d levels, want 1", len(k.Levels))
	}
	if k.Levels[0].Length != len(payload) {
		t.Errorf("level length %d, want %d", k.Levels[0].Length, len(payload))
	}
	if k.SupercompressionName() != "zstd" {
		t.Errorf("scheme name %q, want zstd", k.SupercompressionName())
	}

	im, st, err := DecodeKTX2Level(k, 0, payload)
	if err != nil {
		t.Fatalf("DecodeKTX2Level: %v", err)
	}
	if im.Width != 8 || im.Height != 8 || st.Blocks != 4 {
		t.Errorf("decoded %dx%d from %d blocks, want 8x8 from 4",
			im.Width, im.Height, st.Blocks)
	}
	if _, _, err := DecodeKTX2Level(k, 3, payload); err == nil {
		t.Error("a missing level should be an error")
	}
}

func TestParseKTX2LevelDimensionsHalve(t *testing.T) {
	k, err := ParseKTX2(buildKTX2(157, 16, 9, 4, SupercompressionNone, make([]byte, 16)))
	if err != nil {
		t.Fatalf("ParseKTX2: %v", err)
	}
	want := [][2]int{{16, 9}, {8, 4}, {4, 2}, {2, 1}}
	for i, w := range want {
		if k.Levels[i].Width != w[0] || k.Levels[i].Height != w[1] {
			t.Errorf("level %d is %dx%d, want %dx%d", i,
				k.Levels[i].Width, k.Levels[i].Height, w[0], w[1])
		}
	}
}

func TestParseKTX2Rejections(t *testing.T) {
	if _, err := ParseKTX2([]byte{1, 2, 3}); !errors.Is(err, ErrMagic) {
		t.Errorf("junk should be ErrMagic, got %v", err)
	}
	short := buildKTX2(157, 8, 8, 1, 0, make([]byte, 16))
	if _, err := ParseKTX2(short[:60]); !errors.Is(err, ErrHeader) {
		t.Errorf("a truncated header should be ErrHeader, got %v", err)
	}
	// A forged level index that points past the end of the file must not be
	// trusted into a slice bound.
	bad := buildKTX2(157, 8, 8, 1, 0, make([]byte, 16))
	binary.LittleEndian.PutUint64(bad[ktx2FixedHeader+8:], 1<<40)
	if _, err := ParseKTX2(bad); err == nil {
		t.Error("an overrunning level should be rejected")
	}
	absurd := buildKTX2(157, 8, 8, 1, 0, make([]byte, 16))
	binary.LittleEndian.PutUint32(absurd[40:], 9999)
	if _, err := ParseKTX2(absurd); !errors.Is(err, ErrHeader) {
		t.Errorf("an absurd level count should be ErrHeader, got %v", err)
	}
	wide := buildKTX2(157, maxSide+1, 8, 1, 0, make([]byte, 16))
	if _, err := ParseKTX2(wide); !errors.Is(err, ErrDims) {
		t.Errorf("an absurd width should be ErrDims, got %v", err)
	}
	// A valid KTX2 holding some other format is not an error, just not ours.
	other, err := ParseKTX2(buildKTX2(37, 8, 8, 1, 0, make([]byte, 16)))
	if err != nil {
		t.Fatalf("a non-ASTC KTX2 should parse: %v", err)
	}
	if other.IsASTC {
		t.Error("vkFormat 37 is not ASTC")
	}
	if _, _, err := DecodeKTX2Level(other, 0, make([]byte, 16)); !errors.Is(err, ErrFootprint) {
		t.Errorf("decoding a non-ASTC level should be ErrFootprint, got %v", err)
	}
}

func TestSupercompressionNames(t *testing.T) {
	for scheme, want := range map[uint32]string{
		SupercompressionNone:    "none",
		SupercompressionBasisLZ: "BasisLZ",
		SupercompressionZstd:    "zstd",
		SupercompressionZlib:    "zlib",
	} {
		if got := (KTX2Info{SupercompressionScheme: scheme}).SupercompressionName(); got != want {
			t.Errorf("scheme %d is %q, want %q", scheme, got, want)
		}
	}
	if got := (KTX2Info{SupercompressionScheme: 77}).SupercompressionName(); got == "" {
		t.Error("an unknown scheme should still be described")
	}
}

// ---- footprint inference

// Raw payloads from .sctx and similar wrappers carry dimensions but not a
// footprint. Often exactly one legal footprint explains the byte count; when
// several do, saying so is the only honest answer.
func TestGuessFootprintIsUnambiguousOrSaysSo(t *testing.T) {
	if fp, ok := GuessFootprint(16, 12, 12); !ok ||
		fp != (Footprint{Width: 12, Height: 12}) {
		t.Errorf("one block for a 12x12 image is %s ok=%v, want 12x12", fp, ok)
	}
	if _, ok := GuessFootprint(64, 8, 8); ok {
		t.Error("four blocks for an 8x8 image fits several footprints; " +
			"guessing one would be wrong")
	}
	if _, ok := GuessFootprint(999, 8, 8); ok {
		t.Error("a size no footprint explains should fail")
	}
	for _, bad := range [][3]int{{0, 8, 8}, {16, 0, 8}, {16, 8, 0}, {-1, 8, 8}} {
		if _, ok := GuessFootprint(bad[0], bad[1], bad[2]); ok {
			t.Errorf("GuessFootprint%v should fail", bad)
		}
	}
	// Whatever it returns must at least be self-consistent.
	for _, f := range Footprints() {
		w, h := 37, 23
		xb := (w + f.Width - 1) / f.Width
		yb := (h + f.Height - 1) / f.Height
		if fp, ok := GuessFootprint(xb*yb*blockSize, w, h); ok {
			xb2 := (w + fp.Width - 1) / fp.Width
			yb2 := (h + fp.Height - 1) / fp.Height
			if xb2*yb2 != xb*yb {
				t.Errorf("guessed %s for %d blocks of %s", fp, xb*yb, f)
			}
		}
	}
}
