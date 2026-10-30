package astc

import (
	"strings"
	"testing"
)

func repeatBlock(t *testing.T, name string, n int) []byte {
	t.Helper()
	one := mustHexBytes(t, fixtureByName(t, name).block)
	out := make([]byte, 0, n*blockSize)
	for i := 0; i < n; i++ {
		out = append(out, one...)
	}
	return out
}

func pseudoRandom(n int) []byte {
	out := make([]byte, n)
	s := uint32(12345)
	for i := range out {
		s = s*1664525 + 1013904223
		out[i] = byte(s >> 24)
	}
	return out
}

func TestProbeReadsBlockModesWithoutAnyContext(t *testing.T) {
	p := ProbeBlocks(repeatBlock(t, "wrange_3", 40))
	if p.Blocks != 40 {
		t.Errorf("sampled %d blocks, want 40", p.Blocks)
	}
	if p.Valid != 40 {
		t.Errorf("%d blocks legal, want 40", p.Valid)
	}
	if p.Reserved != 0 || p.Malformed != 0 {
		t.Errorf("a real texture should have no bad blocks, got %d and %d",
			p.Reserved, p.Malformed)
	}
	if p.GridMaxW != 4 || p.GridMaxH != 4 {
		t.Errorf("largest grid %dx%d, want 4x4", p.GridMaxW, p.GridMaxH)
	}
	if p.WeightBitsMin != 32 || p.WeightBitsMax != 32 {
		t.Errorf("weight bits %d..%d, want 32..32",
			p.WeightBitsMin, p.WeightBitsMax)
	}
	if p.ValidRate() != 1 {
		t.Errorf("valid rate %v, want 1", p.ValidRate())
	}
}

func TestProbeCountsTheInterestingKinds(t *testing.T) {
	data := make([]byte, 0)
	data = append(data, repeatBlock(t, "void_teal", 3)...)
	data = append(data, repeatBlock(t, "dual_ccs1", 2)...)
	data = append(data, repeatBlock(t, "parts2_cem8", 4)...)
	data = append(data, repeatBlock(t, "err_reserved_mode", 1)...)

	p := ProbeBlocks(data)
	if p.Void != 3 {
		t.Errorf("%d flat blocks, want 3", p.Void)
	}
	if p.DualPlane != 2 {
		t.Errorf("%d dual-plane blocks, want 2", p.DualPlane)
	}
	if p.MultiPart != 4 {
		t.Errorf("%d partitioned blocks, want 4", p.MultiPart)
	}
	if p.Reserved != 1 {
		t.Errorf("%d reserved blocks, want 1", p.Reserved)
	}
	summary := p.Summary()
	for _, want := range []string{"blocks sampled", "weight grid", "dual plane",
		"partitioned", "reserved"} {
		if !strings.Contains(summary, want) {
			t.Errorf("summary %q should mention %q", summary, want)
		}
	}
	if got := (Probe{}).Summary(); got != "no blocks" {
		t.Errorf("an empty probe says %q", got)
	}
}

// A sixteen-byte-aligned size proves nothing on its own, so the discriminator
// has to be the block modes. Random bytes hit reserved patterns and impossible
// weight configurations constantly; real textures never do.
func TestLooksLikeBlocksRejectsRandomBytes(t *testing.T) {
	if LooksLikeBlocks(pseudoRandom(64 * blockSize)) {
		t.Error("random bytes were accepted as ASTC")
	}
	if LooksLikeBlocks(make([]byte, 64*blockSize)) {
		t.Error("an all-zero buffer is all reserved block modes, not ASTC")
	}
	if LooksLikeBlocks(nil) {
		t.Error("nil is not ASTC")
	}
	if LooksLikeBlocks(repeatBlock(t, "wrange_3", 4)[:63]) {
		t.Error("a misaligned length cannot be whole blocks")
	}
}

func TestLooksLikeBlocksAcceptsRealTextures(t *testing.T) {
	for _, name := range []string{"wrange_3", "wrange_31", "parts4_cem0",
		"dual_ccs3", "infill_12x12_grid6x6"} {
		if !LooksLikeBlocks(repeatBlock(t, name, 32)) {
			t.Errorf("%s blocks were not recognised as ASTC", name)
		}
	}
}

// The footprint is deduced, not guessed: a weight grid may never exceed its
// footprint, so every smaller footprint is impossible and the smallest one
// left is the answer.
func TestInferFootprintTakesTheSmallestThatCanHoldTheGrid(t *testing.T) {
	cases := []struct {
		fixture string
		want    Footprint
	}{
		{"wrange_3", Footprint{Width: 4, Height: 4}},
		{"parts2_cem8", Footprint{Width: 6, Height: 6}},
		{"infill_8x6_grid6x5", Footprint{Width: 6, Height: 5}},
		{"infill_12x12_grid8x8", Footprint{Width: 8, Height: 8}},
	}
	for _, c := range cases {
		fp, _, ok := InferFootprint(repeatBlock(t, c.fixture, 16))
		if !ok {
			t.Errorf("%s: inference failed", c.fixture)
			continue
		}
		if fp != c.want {
			t.Errorf("%s: inferred %s, want %s", c.fixture, fp, c.want)
		}
	}
	if _, _, ok := InferFootprint(pseudoRandom(32 * blockSize)); ok {
		t.Error("random bytes should not yield a footprint")
	}
}

// This is the case the classifier used to give up on: a zstd payload that
// inflates to a whole mip chain with no header in front of it. The chain total
// is distinctive, so the dimensions come out exactly rather than assumed.
func TestInferLayoutRecognisesAMipPyramid(t *testing.T) {
	// 64x64 in 4x4 blocks: 256 + 64 + 16 + 4 + 1 + 1 + 1 = 343 blocks.
	l, ok := InferLayout(repeatBlock(t, "wrange_3", 343))
	if !ok {
		t.Fatal("inference failed")
	}
	if !l.Certain {
		t.Error("a pyramid pins the dimensions, so Certain should be true")
	}
	if l.Width != 64 || l.Height != 64 {
		t.Errorf("base level %dx%d, want 64x64", l.Width, l.Height)
	}
	if len(l.Mips) != 7 {
		t.Fatalf("%d mip levels, want 7", len(l.Mips))
	}
	if l.Mips[0].Blocks != 256 || l.Mips[0].Offset != 0 {
		t.Errorf("level 0 has %d blocks at +%d, want 256 at +0",
			l.Mips[0].Blocks, l.Mips[0].Offset)
	}
	if l.Mips[1].Offset != 256*blockSize {
		t.Errorf("level 1 starts at +%d, want +%d",
			l.Mips[1].Offset, 256*blockSize)
	}
	last := l.Mips[len(l.Mips)-1]
	if last.Width != 1 || last.Height != 1 {
		t.Errorf("the chain ends at %dx%d, want 1x1", last.Width, last.Height)
	}
	total := 0
	for _, m := range l.Mips {
		total += m.Blocks
	}
	if total != 343 {
		t.Errorf("the chain accounts for %d blocks, want 343", total)
	}
	if !strings.Contains(l.Note, "mip pyramid") {
		t.Errorf("note %q should say it found a pyramid", l.Note)
	}
}

func TestInferLayoutSingleLevelIsHonestAboutTheAspectRatio(t *testing.T) {
	l, ok := InferLayout(repeatBlock(t, "wrange_3", 16))
	if !ok {
		t.Fatal("inference failed")
	}
	if len(l.Mips) != 0 {
		t.Errorf("16 blocks is not a pyramid, got %d levels", len(l.Mips))
	}
	if l.Width != 16 || l.Height != 16 {
		t.Errorf("assumed %dx%d, want the square 16x16", l.Width, l.Height)
	}
	// The block count cannot pin the aspect ratio, and pretending otherwise
	// would be the wrong kind of confident.
	if l.Certain {
		t.Error("a single level does not pin the dimensions")
	}
	if !strings.Contains(l.Note, "aspect") {
		t.Errorf("note %q should admit the ratio is assumed", l.Note)
	}
	if l.Blocks != 16 {
		t.Errorf("counted %d blocks, want 16", l.Blocks)
	}
}

func TestInferLayoutRejectsWhatItCannotExplain(t *testing.T) {
	if _, ok := InferLayout(pseudoRandom(32 * blockSize)); ok {
		t.Error("random bytes should not produce a layout")
	}
	if _, ok := InferLayout(repeatBlock(t, "wrange_3", 4)[:60]); ok {
		t.Error("a misaligned payload should not produce a layout")
	}
	if _, ok := InferLayout(nil); ok {
		t.Error("nil should not produce a layout")
	}
}

func TestDecodeInferredDecodesTheTopLevel(t *testing.T) {
	im, l, st, err := DecodeInferred(repeatBlock(t, "wrange_3", 343), false)
	if err != nil {
		t.Fatalf("DecodeInferred: %v", err)
	}
	if len(l.Mips) != 7 {
		t.Fatalf("%d mip levels, want 7", len(l.Mips))
	}
	// Only level 0 is decoded, so the image is the base of the pyramid and
	// not the whole payload.
	if im.Width != l.Width || im.Height != l.Height {
		t.Errorf("decoded %dx%d but the layout says %dx%d",
			im.Width, im.Height, l.Width, l.Height)
	}
	if st.Blocks != l.Mips[0].Blocks {
		t.Errorf("decoded %d blocks, want just level 0's %d",
			st.Blocks, l.Mips[0].Blocks)
	}
	if st.Errors != 0 {
		t.Errorf("%d illegal blocks in a legal texture", st.Errors)
	}
	// A void-extent payload has no weight grid anywhere, so the footprint
	// cannot be deduced from it and inference has to decline rather than
	// pick a footprint at random.
	if _, _, _, err := DecodeInferred(repeatBlock(t, "void_teal", 343), false); err == nil {
		t.Error("flat blocks carry no grid, so the footprint is unknowable")
	}
	if _, _, _, err := DecodeInferred(pseudoRandom(32*blockSize), false); err == nil {
		t.Error("random bytes should not decode")
	}
}

func TestMipBlockArithmetic(t *testing.T) {
	fp := Footprint{Width: 4, Height: 4}
	if got := mipBlocks(64, 64, fp); got != 343 {
		t.Errorf("a 64x64 chain is %d blocks, want 343", got)
	}
	if got := mipBlocks(1, 1, fp); got != 1 {
		t.Errorf("a 1x1 chain is %d blocks, want 1", got)
	}
	// Non-square chains stop halving an axis once it reaches one.
	chain := mipChain(8, 2, fp)
	if len(chain) != 4 {
		t.Fatalf("an 8x2 chain has %d levels, want 4", len(chain))
	}
	want := [][2]int{{8, 2}, {4, 1}, {2, 1}, {1, 1}}
	for i, w := range want {
		if chain[i].Width != w[0] || chain[i].Height != w[1] {
			t.Errorf("level %d is %dx%d, want %dx%d", i,
				chain[i].Width, chain[i].Height, w[0], w[1])
		}
	}
	off := 0
	for _, m := range chain {
		if m.Offset != off {
			t.Errorf("level offsets are not contiguous at %d", m.Offset)
		}
		off += m.Length
	}
}

func TestPow2AndSquarishHelpers(t *testing.T) {
	for _, n := range []int{1, 2, 4, 256, 4096} {
		if !isPow2(n) {
			t.Errorf("%d is a power of two", n)
		}
	}
	for _, n := range []int{0, 3, 6, 100, -4} {
		if isPow2(n) {
			t.Errorf("%d is not a power of two", n)
		}
	}
	if squarish(4, 4) != 1 {
		t.Error("a square should score 1")
	}
	if squarish(16, 1) <= squarish(4, 4) {
		t.Error("a 16:1 strip should score worse than a square")
	}
}
