package astc

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func fixtureByName(t *testing.T, name string) goldenFixture {
	t.Helper()
	for _, f := range goldenFixtures {
		if f.name == name {
			return f
		}
	}
	t.Fatalf("fixture %q is missing", name)
	return goldenFixture{}
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in fixture: %v", err)
	}
	return b
}

// This is the test that matters. Every fixture was assembled bit by bit and
// decoded by a separate reference implementation, so agreement here means the
// two independent readings of the specification produce identical pixels.
func TestGoldenFixturesDecodeExactly(t *testing.T) {
	if len(goldenFixtures) < 40 {
		t.Fatalf("only %d fixtures; regenerate them", len(goldenFixtures))
	}
	for _, f := range goldenFixtures {
		raw := mustHexBytes(t, f.block)
		if len(raw) != blockSize {
			t.Fatalf("%s: block is %d bytes, want %d", f.name, len(raw), blockSize)
		}
		want := mustHexBytes(t, f.pixels)
		fp := Footprint{Width: f.fpW, Height: f.fpH}
		if len(want) != fp.Texels()*4 {
			t.Fatalf("%s: %d expected bytes for a %s footprint",
				f.name, len(want), fp)
		}

		out := make([]uint8, fp.Texels()*4)
		info := DecodeBlock(raw, fp, f.srgb, out)

		if (info.Err != "") != f.bad {
			t.Errorf("%s: Err = %q, expected illegal = %v",
				f.name, info.Err, f.bad)
		}
		if !bytes.Equal(out, want) {
			for i := 0; i+3 < len(want); i += 4 {
				if !bytes.Equal(out[i:i+4], want[i:i+4]) {
					tx := (i / 4) % fp.Width
					ty := (i / 4) / fp.Width
					t.Errorf("%s: texel (%d,%d) is %v, want %v (%s)",
						f.name, tx, ty, out[i:i+4], want[i:i+4], info)
					break
				}
			}
			continue
		}
		if info.VoidExtent != f.void {
			t.Errorf("%s: VoidExtent = %v, want %v", f.name, info.VoidExtent, f.void)
		}
		if f.bad || f.void {
			continue
		}
		if info.GridWidth != f.gw || info.GridHeight != f.gh {
			t.Errorf("%s: grid %dx%d, want %dx%d",
				f.name, info.GridWidth, info.GridHeight, f.gw, f.gh)
		}
		if info.WeightRange != f.wrange {
			t.Errorf("%s: weight range 0..%d, want 0..%d",
				f.name, info.WeightRange, f.wrange)
		}
		if info.ColorRange != f.crange {
			t.Errorf("%s: colour range 0..%d, want 0..%d",
				f.name, info.ColorRange, f.crange)
		}
		if info.DualPlane != f.dual {
			t.Errorf("%s: dual plane %v, want %v", f.name, info.DualPlane, f.dual)
		}
		if info.DualPlane && info.CCS != f.ccs {
			t.Errorf("%s: component selector %d, want %d", f.name, info.CCS, f.ccs)
		}
		if info.WeightBits != f.wbits {
			t.Errorf("%s: %d weight bits, want %d", f.name, info.WeightBits, f.wbits)
		}
		if info.Partitions != f.parts {
			t.Errorf("%s: %d partitions, want %d", f.name, info.Partitions, f.parts)
		}
	}
}

// A fixture set that happened to miss dual-plane blocks or partitions would
// pass the test above while proving very little, so the coverage itself is
// asserted.
func TestGoldenFixturesCoverTheFormat(t *testing.T) {
	var dual, voids, bad, parts4, infill, srgb int
	wranges := map[int]bool{}
	cranges := map[int]bool{}
	partCounts := map[int]bool{}
	for _, f := range goldenFixtures {
		if f.dual {
			dual++
		}
		if f.void {
			voids++
		}
		if f.bad {
			bad++
		}
		if f.srgb {
			srgb++
		}
		if f.parts == 4 {
			parts4++
		}
		if !f.void && !f.bad && (f.gw < f.fpW || f.gh < f.fpH) {
			infill++
		}
		if !f.void && !f.bad {
			wranges[f.wrange] = true
			cranges[f.crange] = true
			partCounts[f.parts] = true
		}
	}
	check := func(name string, got, min int) {
		if got < min {
			t.Errorf("fixtures cover %s only %d times, want at least %d",
				name, got, min)
		}
	}
	check("dual plane", dual, 4)
	check("void extent", voids, 2)
	check("illegal blocks", bad, 3)
	check("four partitions", parts4, 1)
	check("grid smaller than footprint", infill, 5)
	check("sRGB", srgb, 1)
	check("distinct weight ranges", len(wranges), 10)
	check("distinct colour ranges", len(cranges), 5)
	check("distinct partition counts", len(partCounts), 4)
}

func TestIllegalBlocksAreEntirelyMagenta(t *testing.T) {
	seen := 0
	for _, f := range goldenFixtures {
		if !f.bad {
			continue
		}
		seen++
		px := mustHexBytes(t, f.pixels)
		for i := 0; i+3 < len(px); i += 4 {
			if px[i] != ErrorColor[0] || px[i+1] != ErrorColor[1] ||
				px[i+2] != ErrorColor[2] || px[i+3] != ErrorColor[3] {
				t.Fatalf("%s: texel %d is %v, want the error colour %v",
					f.name, i/4, px[i:i+4], ErrorColor)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no illegal fixtures to check")
	}
}

// An LDR decoder is required to return the error colour for HDR endpoint
// modes rather than approximating them. This pins that behaviour so nobody
// "improves" it into a silent wrong answer later.
func TestHDREndpointModesReturnTheErrorColour(t *testing.T) {
	f := fixtureByName(t, "hdr_cem2")
	fp := Footprint{Width: f.fpW, Height: f.fpH}
	out := make([]uint8, fp.Texels()*4)
	info := DecodeBlock(mustHexBytes(t, f.block), fp, false, out)
	if !info.HDR {
		t.Error("the HDR flag should be set")
	}
	for i := 0; i+3 < len(out); i += 4 {
		if out[i] != 255 || out[i+1] != 0 || out[i+2] != 255 {
			t.Fatalf("texel %d is %v, want magenta", i/4, out[i:i+4])
		}
	}
	if info.Err != "" {
		t.Errorf("an HDR block is not malformed, but Err = %q", info.Err)
	}
}

func TestErrorColourIsOpaqueMagenta(t *testing.T) {
	if ErrorColor != [4]uint8{255, 0, 255, 255} {
		t.Errorf("error colour is %v, want opaque magenta", ErrorColor)
	}
}

func TestBlockInfoDescribesItself(t *testing.T) {
	f := fixtureByName(t, "dual_ccs2")
	fp := Footprint{Width: f.fpW, Height: f.fpH}
	out := make([]uint8, fp.Texels()*4)
	info := DecodeBlock(mustHexBytes(t, f.block), fp, false, out)
	s := info.String()
	for _, want := range []string{"2x2", "dual plane", "channel 2"} {
		if !strings.Contains(s, want) {
			t.Errorf("description %q does not mention %q", s, want)
		}
	}
	void := fixtureByName(t, "void_teal")
	info = DecodeBlock(mustHexBytes(t, void.block), fp, false, out)
	if !strings.Contains(info.String(), "void extent") {
		t.Errorf("void extent description is %q", info.String())
	}
	bad := fixtureByName(t, "err_reserved_mode")
	info = DecodeBlock(mustHexBytes(t, bad.block), fp, false, out)
	if !strings.Contains(info.String(), "illegal") {
		t.Errorf("illegal block description is %q", info.String())
	}
}

// ---- whole-image assembly

func tealBlocks(t *testing.T, n int) []byte {
	t.Helper()
	one := mustHexBytes(t, fixtureByName(t, "void_teal").block)
	out := make([]byte, 0, n*blockSize)
	for i := 0; i < n; i++ {
		out = append(out, one...)
	}
	return out
}

// A 7x5 image needs 2x2 blocks of 4x4, and the blocks overhang the image on
// two sides. Getting the clipping wrong is the classic block-decoder bug.
func TestDecodeClipsPartialEdgeBlocks(t *testing.T) {
	fp := Footprint{Width: 4, Height: 4}
	im, err := Decode(tealBlocks(t, 4), 7, 5, fp, false)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if im.Width != 7 || im.Height != 5 {
		t.Fatalf("image is %dx%d, want 7x5", im.Width, im.Height)
	}
	if len(im.Pix) != 7*5*4 {
		t.Fatalf("pixel buffer is %d bytes, want %d", len(im.Pix), 7*5*4)
	}
	want := [4]uint8{12, 34, 56, 200}
	for y := 0; y < im.Height; y++ {
		for x := 0; x < im.Width; x++ {
			if got := im.At(x, y); got != want {
				t.Fatalf("pixel (%d,%d) is %v, want %v", x, y, got, want)
			}
		}
	}
	if got := im.At(-1, 0); got != [4]uint8{} {
		t.Errorf("out-of-bounds At returned %v, want the zero value", got)
	}
	if got := im.At(7, 0); got != [4]uint8{} {
		t.Errorf("out-of-bounds At returned %v, want the zero value", got)
	}
}

func TestDecodeRejectsBadArguments(t *testing.T) {
	fp := Footprint{Width: 4, Height: 4}
	data := tealBlocks(t, 4)

	if _, err := Decode(data, 7, 5, Footprint{Width: 7, Height: 7}, false); !errors.Is(err, ErrFootprint) {
		t.Errorf("a 7x7 footprint should be rejected, got %v", err)
	}
	if _, err := Decode(data, 0, 5, fp, false); !errors.Is(err, ErrDims) {
		t.Errorf("zero width should be rejected, got %v", err)
	}
	if _, err := Decode(data, -3, 5, fp, false); !errors.Is(err, ErrDims) {
		t.Errorf("negative width should be rejected, got %v", err)
	}
	if _, err := Decode(data[:len(data)-1], 7, 5, fp, false); !errors.Is(err, ErrShort) {
		t.Errorf("a truncated payload should be rejected, got %v", err)
	}
	if _, err := Decode(data, maxSide+1, 5, fp, false); !errors.Is(err, ErrDims) {
		t.Errorf("an absurd width should be rejected, got %v", err)
	}
	// Extra trailing bytes are common in real files and must not be an error.
	if _, err := Decode(append(data, 0, 0, 0), 7, 5, fp, false); err != nil {
		t.Errorf("trailing bytes should be ignored, got %v", err)
	}
}

func TestDecodeWithStatsCountsWhatItSaw(t *testing.T) {
	fp := Footprint{Width: 4, Height: 4}
	void := mustHexBytes(t, fixtureByName(t, "void_teal").block)
	dual := mustHexBytes(t, fixtureByName(t, "dual_ccs1").block)
	bad := mustHexBytes(t, fixtureByName(t, "err_reserved_mode").block)

	data := make([]byte, 0, 4*blockSize)
	data = append(data, void...)
	data = append(data, dual...)
	data = append(data, bad...)
	data = append(data, void...)

	_, st, err := DecodeWithStats(data, 8, 8, fp, false)
	if err != nil {
		t.Fatalf("DecodeWithStats: %v", err)
	}
	if st.Blocks != 4 {
		t.Errorf("counted %d blocks, want 4", st.Blocks)
	}
	if st.VoidExtent != 2 {
		t.Errorf("counted %d void extents, want 2", st.VoidExtent)
	}
	if st.DualPlane != 1 {
		t.Errorf("counted %d dual-plane blocks, want 1", st.DualPlane)
	}
	if st.Errors != 1 {
		t.Errorf("counted %d illegal blocks, want 1", st.Errors)
	}
	summary := st.Summary()
	if !strings.Contains(summary, "4 blocks") {
		t.Errorf("summary %q should state the block count", summary)
	}
	for _, want := range []string{"2 flat", "1 dual-plane", "1 illegal", "grids"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q should mention %q", summary, want)
		}
	}
}

func TestStatsSummaryOnAnEmptyRun(t *testing.T) {
	var st Stats
	if s := st.Summary(); s == "" {
		t.Error("an empty summary should still say something")
	}
}

// ---- footprints

func TestFootprintTableIsTheFourteenLDRShapes(t *testing.T) {
	fps := Footprints()
	if len(fps) != 14 {
		t.Fatalf("%d footprints, want 14", len(fps))
	}
	seen := map[string]bool{}
	for _, f := range fps {
		if seen[f.String()] {
			t.Errorf("footprint %s appears twice", f)
		}
		seen[f.String()] = true
		if !ValidFootprint(f.Width, f.Height) {
			t.Errorf("%s is in the table but ValidFootprint rejects it", f)
		}
		if f.Texels() < 16 || f.Texels() > 144 {
			t.Errorf("%s has %d texels, outside 16..144", f, f.Texels())
		}
	}
	// Mutating the returned slice must not corrupt the package table.
	fps[0] = Footprint{Width: 99, Height: 99}
	if Footprints()[0].Width == 99 {
		t.Error("Footprints() hands out its backing array")
	}
	for _, bad := range [][2]int{{7, 7}, {4, 6}, {0, 0}, {12, 11}, {16, 16}} {
		if ValidFootprint(bad[0], bad[1]) {
			t.Errorf("%dx%d is not a legal ASTC footprint", bad[0], bad[1])
		}
	}
}

func TestBitsPerTexel(t *testing.T) {
	if got := (Footprint{Width: 4, Height: 4}).BitsPerTexel(); got != 8 {
		t.Errorf("4x4 is %v bits per texel, want 8", got)
	}
	small := (Footprint{Width: 12, Height: 12}).BitsPerTexel()
	if small > 1 || small < 0.85 {
		t.Errorf("12x12 is %v bits per texel, want about 0.89", small)
	}
}

func TestDecodeBlockRefusesAShortBuffer(t *testing.T) {
	fp := Footprint{Width: 4, Height: 4}
	out := make([]uint8, 4)
	info := DecodeBlock(tealBlocks(t, 1), fp, false, out)
	if info.Err == "" {
		t.Error("a too-small output buffer should be reported")
	}
	info = DecodeBlock([]byte{1, 2, 3}, fp, false, make([]uint8, 64))
	if info.Err == "" {
		t.Error("a truncated block should be reported")
	}
}
