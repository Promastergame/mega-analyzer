package astc

import (
	"slices"
	"testing"
)

// The quantization tables are the part of ASTC that is easiest to get subtly
// wrong and hardest to notice: a single mistyped constant shifts colours by a
// few units everywhere, which looks like a plausible image. So the published
// sequences are pinned here literally. Three of them appear in independent
// public write-ups of the format, which is why these three were chosen.

func weightSeq(t *testing.T, max int) []uint32 {
	t.Helper()
	out := make([]uint32, 0, max+1)
	for v := 0; v <= max; v++ {
		out = append(out, unquantWeight(uint32(v), max))
	}
	return out
}

func colorSeq(t *testing.T, max int) []uint32 {
	t.Helper()
	out := make([]uint32, 0, max+1)
	for v := 0; v <= max; v++ {
		out = append(out, unquantColor(uint32(v), max))
	}
	return out
}

func equalSeq(a []uint32, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestWeightUnquantMatchesPublishedTables(t *testing.T) {
	cases := []struct {
		max  int
		want []uint32
	}{
		{1, []uint32{0, 64}},
		{2, []uint32{0, 32, 64}},
		{3, []uint32{0, 21, 43, 64}},
		{4, []uint32{0, 16, 32, 48, 64}},
		{5, []uint32{0, 64, 12, 52, 25, 39}},
		{7, []uint32{0, 9, 18, 27, 37, 46, 55, 64}},
		{9, []uint32{0, 64, 7, 57, 14, 50, 21, 43, 28, 36}},
		{11, []uint32{0, 64, 17, 47, 5, 59, 23, 41, 11, 53, 28, 36}},
		{15, []uint32{0, 4, 8, 12, 17, 21, 25, 29,
			35, 39, 43, 47, 52, 56, 60, 64}},
		{19, []uint32{0, 64, 16, 48, 3, 61, 19, 45, 6, 58,
			23, 41, 9, 55, 26, 38, 13, 51, 29, 35}},
		{23, []uint32{0, 64, 8, 56, 16, 48, 24, 40, 2, 62, 11, 53,
			19, 45, 27, 37, 5, 59, 13, 51, 22, 42, 30, 34}},
	}
	for _, c := range cases {
		got := weightSeq(t, c.max)
		if !equalSeq(got, c.want) {
			t.Errorf("weight range 0..%d:\n got %v\nwant %v", c.max, got, c.want)
		}
	}
}

// A weight range must cover 0..64 with max+1 distinct values. It must NOT be
// monotonic in the stored value: an earlier version of this test demanded that,
// which is only true of the bit-only ranges, and the sorted tables added to
// unquantWeight to satisfy it silently corrupted every trit and quint block.
// The invariant is about the set of values, so sort a copy before checking the
// spacing rather than assuming the sequence itself ascends.
func TestWeightUnquantSpansZeroToSixtyFour(t *testing.T) {
	for _, max := range weightRanges {
		seq := weightSeq(t, max)
		if len(seq) != max+1 {
			t.Fatalf("weight range 0..%d produced %d values", max, len(seq))
		}
		if seq[0] != 0 {
			t.Errorf("weight range 0..%d starts at %d, want 0", max, seq[0])
		}
		sorted := make([]uint32, len(seq))
		copy(sorted, seq)
		slices.Sort(sorted)
		if sorted[0] != 0 || sorted[len(sorted)-1] != 64 {
			t.Errorf("weight range 0..%d spans %d..%d, want 0..64",
				max, sorted[0], sorted[len(sorted)-1])
		}
		for i := 1; i < len(sorted); i++ {
			if sorted[i] == sorted[i-1] {
				t.Errorf("weight range 0..%d repeats %d: %v",
					max, sorted[i], seq)
				break
			}
		}
	}
}

// The mirror of TestColorUnquantIsDeliberatelyNotMonotonic. Every trit and
// quint weight range sends stored value 1 to 64, because the shared trit or
// quint reorders the decoded weights relative to the stored integers. This is
// the assertion that fails the moment somebody sorts the tables again.
func TestWeightUnquantIsDeliberatelyNotMonotonic(t *testing.T) {
	for _, max := range []int{5, 9, 11, 19, 23} {
		seq := weightSeq(t, max)
		if seq[1] != 64 {
			t.Errorf("weight range 0..%d: stored 1 gave %d, want 64 - the "+
				"trit/quint ranges must interleave, not ascend: %v",
				max, seq[1], seq)
		}
	}
}

// The gap straddling 32 is not a mistake in the table. Every unquantization
// procedure ends with "if the value exceeds 32, add one", which is what makes
// the endpoints reachable exactly; the cost is a one-unit hole in the middle.
func TestWeightUnquantHasTheGapAtThirtyTwo(t *testing.T) {
	if got := unquantWeight(15, 31); got != 30 {
		t.Errorf("unquantWeight(15, 31) = %d, want 30", got)
	}
	if got := unquantWeight(16, 31); got != 34 {
		t.Errorf("unquantWeight(16, 31) = %d, want 34", got)
	}
}

func TestColorUnquantMatchesPublishedTables(t *testing.T) {
	cases := []struct {
		max  int
		want []uint32
	}{
		{5, []uint32{0, 255, 51, 204, 102, 153}},
		{9, []uint32{0, 255, 28, 227, 56, 199, 84, 171, 113, 142}},
		{11, []uint32{0, 255, 69, 186, 23, 232, 92, 163, 46, 209, 116, 139}},
	}
	for _, c := range cases {
		got := colorSeq(t, c.max)
		if !equalSeq(got, c.want) {
			t.Errorf("colour range 0..%d:\n got %v\nwant %v", c.max, got, c.want)
		}
	}
}

// The published tables above look scrambled next to the sorted list of values
// they contain, and that is correct: the shared trit or quint reorders the
// decoded values relative to the encoded integers. Anyone "fixing" this into
// ascending order breaks every colour in every block.
func TestColorUnquantIsDeliberatelyNotMonotonic(t *testing.T) {
	seq := colorSeq(t, 5)
	if seq[1] <= seq[2] {
		t.Fatalf("colour range 0..5 came out ordered (%v); the trit-based "+
			"ranges must interleave", seq)
	}
}

func TestColorUnquantEdgeRanges(t *testing.T) {
	for v := 0; v <= 255; v++ {
		if got := unquantColor(uint32(v), 255); got != uint32(v) {
			t.Fatalf("colour range 0..255 must be the identity, %d gave %d", v, got)
		}
	}
	// A pure bit-count range replicates its top bits downward.
	if got := unquantColor(1, 127); got != 2 {
		t.Errorf("unquantColor(1, 127) = %d, want 2", got)
	}
	if got := unquantColor(64, 127); got != 129 {
		t.Errorf("unquantColor(64, 127) = %d, want 129", got)
	}
	for _, c := range []struct{ v, want uint32 }{
		{3, 24}, {6, 49}, {9, 74}, {15, 123}, {20, 165}, {25, 206},
	} {
		if got := unquantColor(c.v, 31); got != c.want {
			t.Errorf("unquantColor(%d, 31) = %d, want %d", c.v, got, c.want)
		}
	}
}

func TestColorUnquantSpansZeroToTwoFiveFive(t *testing.T) {
	for _, max := range colorRanges {
		seen := map[uint32]bool{}
		lo, hi := uint32(255), uint32(0)
		for v := 0; v <= max; v++ {
			u := unquantColor(uint32(v), max)
			if u > 255 {
				t.Fatalf("colour range 0..%d produced %d, above 255", max, u)
			}
			seen[u] = true
			if u < lo {
				lo = u
			}
			if u > hi {
				hi = u
			}
		}
		if lo != 0 || hi != 255 {
			t.Errorf("colour range 0..%d spans %d..%d, want 0..255", max, lo, hi)
		}
		if len(seen) != max+1 {
			t.Errorf("colour range 0..%d produced %d distinct values, want %d",
				max, len(seen), max+1)
		}
	}
}

func TestBuildBFollowsTheLayoutString(t *testing.T) {
	// Layout "b000b0bb0" with m = 2 sets bit b, which is bit 1 of m, so every
	// position holding a "b" becomes 1: 100010110 = 278.
	if got := buildB("b000b0bb0", 2); got != 278 {
		t.Errorf("buildB = %d, want 278", got)
	}
	if got := buildB("b000b0bb0", 0); got != 0 {
		t.Errorf("buildB with a zero source = %d, want 0", got)
	}
}

// The spec text says a three-bit weight replicates to five bits, but its own
// table lists weights up to 63, which needs six. Six is the width that
// reproduces the published sequences, so six is what the code does.
func TestRepBitsUsesSixBitsForWeights(t *testing.T) {
	if got := repBits(4, 3, 6); got != 36 {
		t.Errorf("repBits(4, 3, 6) = %d, want 36 (100100b)", got)
	}
	if got := repBits(1, 1, 8); got != 255 {
		t.Errorf("repBits(1, 1, 8) = %d, want 255", got)
	}
	if got := repBits(0, 4, 8); got != 0 {
		t.Errorf("repBits of zero = %d, want 0", got)
	}
}

func TestRangeSpecsAreConsistent(t *testing.T) {
	if len(allRanges) != 21 {
		t.Fatalf("expected 21 ranges, found %d", len(allRanges))
	}
	for _, s := range allRanges {
		switch {
		case s.trits == 1 && s.quints == 1:
			t.Errorf("range 0..%d claims both a trit and a quint", s.max)
		case s.trits == 1:
			if want := 3<<uint(s.bits) - 1; s.max != want {
				t.Errorf("trit range 0..%d should be 0..%d", s.max, want)
			}
		case s.quints == 1:
			if want := 5<<uint(s.bits) - 1; s.max != want {
				t.Errorf("quint range 0..%d should be 0..%d", s.max, want)
			}
		default:
			if want := 1<<uint(s.bits) - 1; s.max != want {
				t.Errorf("bit range 0..%d should be 0..%d", s.max, want)
			}
		}
		if _, ok := specFor(s.max); !ok {
			t.Errorf("specFor cannot find range 0..%d", s.max)
		}
	}
	if _, ok := specFor(6); ok {
		t.Error("0..6 is not an ASTC range but specFor accepted it")
	}
}

func TestISEBitsMatchesTheSpecFormula(t *testing.T) {
	for _, max := range colorRanges {
		s, ok := specFor(max)
		if !ok {
			t.Fatalf("missing spec for 0..%d", max)
		}
		for n := 1; n <= 18; n++ {
			want := n * s.bits
			if s.trits == 1 {
				want += (n*8 + 4) / 5
			}
			if s.quints == 1 {
				want += (n*7 + 2) / 3
			}
			if got := iseBits(n, s); got != want {
				t.Fatalf("iseBits(%d, 0..%d) = %d, want %d", n, max, got, want)
			}
		}
	}
	// A single trit alone occupies two bits, not one: eight bits carry five
	// trits, so one trit rounds up to ceil(8/5).
	s, _ := specFor(2)
	if got := iseBits(1, s); got != 2 {
		t.Errorf("one trit packs into %d bits, want 2", got)
	}
}

func TestTritDecodeCoversEveryCombination(t *testing.T) {
	seen := map[[5]uint8]bool{}
	for v := 0; v < 256; v++ {
		tr := decodeTrits(uint32(v))
		for _, x := range tr {
			if x > 2 {
				t.Fatalf("packed trit block %d decoded to %v, out of range", v, tr)
			}
		}
		seen[tr] = true
	}
	if len(seen) != 243 {
		t.Errorf("256 packed blocks produced %d of the 243 trit combinations",
			len(seen))
	}
}

func TestQuintDecodeCoversEveryCombination(t *testing.T) {
	seen := map[[3]uint8]bool{}
	for v := 0; v < 128; v++ {
		q := decodeQuints(uint32(v))
		for _, x := range q {
			if x > 4 {
				t.Fatalf("packed quint block %d decoded to %v, out of range", v, q)
			}
		}
		seen[q] = true
	}
	if len(seen) != 125 {
		t.Errorf("128 packed blocks produced %d of the 125 quint combinations",
			len(seen))
	}
}

func TestGroupBitLayouts(t *testing.T) {
	if tritGroupBits != [5]int{2, 2, 1, 2, 1} {
		t.Errorf("trit group bits are %v, want [2 2 1 2 1]", tritGroupBits)
	}
	if quintGroupBits != [3]int{3, 2, 2} {
		t.Errorf("quint group bits are %v, want [3 2 2]", quintGroupBits)
	}
	sum := 0
	for _, n := range tritGroupBits {
		sum += n
	}
	if sum != 8 {
		t.Errorf("a trit block must be 8 bits, got %d", sum)
	}
	sum = 0
	for _, n := range quintGroupBits {
		sum += n
	}
	if sum != 7 {
		t.Errorf("a quint block must be 7 bits, got %d", sum)
	}
}

func TestBlockModeKnownEncodings(t *testing.T) {
	cases := []struct {
		bm             uint32
		gw, gh, wrange int
		dual           bool
	}{
		{0x042, 4, 4, 3, false},
		{0x043, 4, 4, 5, false},
		{1311, 2, 2, 7, true},
		{260, 6, 6, 1, false},
	}
	for _, c := range cases {
		m := parseMode(c.bm)
		if m.voidExtent || m.reserved {
			t.Errorf("block mode %#x came out void/reserved", c.bm)
			continue
		}
		if m.gw != c.gw || m.gh != c.gh {
			t.Errorf("block mode %#x grid %dx%d, want %dx%d",
				c.bm, m.gw, m.gh, c.gw, c.gh)
		}
		if m.weightMax != c.wrange {
			t.Errorf("block mode %#x weight range 0..%d, want 0..%d",
				c.bm, m.weightMax, c.wrange)
		}
		if m.dualPlane != c.dual {
			t.Errorf("block mode %#x dual plane %v, want %v",
				c.bm, m.dualPlane, c.dual)
		}
	}
}

func TestBlockModeVoidAndReserved(t *testing.T) {
	if m := parseMode(0x1FC); !m.voidExtent {
		t.Error("0x1FC must be recognised as a void extent")
	}
	// The void extent pattern also matches a later row of the table, so the
	// order of the tests inside parseMode is part of the format.
	if m := parseMode(0x1FC); m.reserved {
		t.Error("the void extent must not also report reserved")
	}
	for _, bm := range []uint32{0, 0x1DC} {
		if m := parseMode(bm); !m.reserved {
			t.Errorf("block mode %#x must be reserved", bm)
		}
	}
}

func TestBlockModeReachableGrids(t *testing.T) {
	shapes := map[[2]int]bool{}
	for bm := uint32(0); bm < 2048; bm++ {
		m := parseMode(bm)
		if m.voidExtent || m.reserved {
			continue
		}
		if m.gw < 2 || m.gw > 12 || m.gh < 2 || m.gh > 12 {
			t.Fatalf("block mode %#x yields grid %dx%d, outside 2..12",
				bm, m.gw, m.gh)
		}
		found := false
		for _, r := range weightRanges {
			if r == m.weightMax {
				found = true
			}
		}
		if !found {
			t.Fatalf("block mode %#x yields weight range 0..%d, not a legal one",
				bm, m.weightMax)
		}
		shapes[[2]int{m.gw, m.gh}] = true
	}
	if len(shapes) != 90 {
		t.Errorf("the block mode field reaches %d grid shapes, want 90",
			len(shapes))
	}
}

// hash52 is built from shifts, xors and adds, every one of them invertible, so
// the whole mixer is a bijection. Checking that over a large window is the
// cheapest way to catch a mistyped shift count, and it is the reason a wrong
// constant here cannot slip through.
func TestHash52IsInjective(t *testing.T) {
	seen := make(map[uint32]uint32, 65536)
	for p := uint32(0); p < 65536; p++ {
		h := hash52(p)
		if prev, dup := seen[h]; dup {
			t.Fatalf("hash52 collides: %d and %d both hash to %#x", prev, p, h)
		}
		seen[h] = p
	}
	// No additive constant, so zero is a fixed point. Harmless: a partitioned
	// block always adds (partitions-1)*1024 before hashing.
	if hash52(0) != 0 {
		t.Errorf("hash52(0) = %#x, want 0", hash52(0))
	}
}

func TestPartitionSeedsSplitSixBySixBlocks(t *testing.T) {
	split, single := 0, 0
	for seed := 0; seed < 1024; seed++ {
		used := map[int]bool{}
		for y := 0; y < 6; y++ {
			for x := 0; x < 6; x++ {
				used[selectPartition(seed, x, y, 0, 2, false)] = true
			}
		}
		switch len(used) {
		case 2:
			split++
		case 1:
			single++
		default:
			t.Fatalf("seed %d produced %d regions for a 2-partition block",
				seed, len(used))
		}
	}
	// Some seeds legitimately degenerate to one region; an encoder simply
	// does not choose them. The exact split is a fingerprint of the hash.
	if split != 787 || single != 237 {
		t.Errorf("2-partition seeds: %d split, %d degenerate; want 787 and 237",
			split, single)
	}
}

func TestPartitionIndicesStayInRange(t *testing.T) {
	for _, count := range []int{2, 3, 4} {
		for seed := 0; seed < 64; seed++ {
			for y := 0; y < 12; y++ {
				for x := 0; x < 12; x++ {
					p := selectPartition(seed, x, y, 0, count, false)
					if p < 0 || p >= count {
						t.Fatalf("%d partitions gave index %d", count, p)
					}
				}
			}
		}
	}
	if got := selectPartition(123, 1, 1, 0, 1, false); got != 0 {
		t.Errorf("a single partition must always be 0, got %d", got)
	}
}

func TestSmallBlockFlagChangesThePattern(t *testing.T) {
	diff := false
	for seed := 0; seed < 64 && !diff; seed++ {
		for y := 0; y < 4 && !diff; y++ {
			for x := 0; x < 4; x++ {
				if selectPartition(seed, x, y, 0, 2, true) !=
					selectPartition(seed, x, y, 0, 2, false) {
					diff = true
					break
				}
			}
		}
	}
	if !diff {
		t.Error("the small-block coordinate doubling had no effect anywhere")
	}
}

func TestEndpointHelpers(t *testing.T) {
	// bit_transfer_signed moves the top bit of a into b and reads what is
	// left of a as a six-bit signed offset.
	a, b := bitTransferSigned(0x80, 0x00)
	if a != 0 || b != 0x80 {
		t.Errorf("bitTransferSigned(0x80, 0) = (%d, %d), want (0, 128)", a, b)
	}
	a, b = bitTransferSigned(0x40, 0x02)
	if a != -32 || b != 1 {
		t.Errorf("bitTransferSigned(0x40, 2) = (%d, %d), want (-32, 1)", a, b)
	}
	r, g, bl := blueContract(100, 200, 50)
	if r != 75 || g != 125 || bl != 50 {
		t.Errorf("blueContract = (%d, %d, %d), want (75, 125, 50)", r, g, bl)
	}
	if clampU8(-5) != 0 || clampU8(300) != 255 || clampU8(128) != 128 {
		t.Error("clampU8 does not clamp to 0..255")
	}
	for cem, want := range map[int]int{0: 2, 3: 2, 4: 4, 7: 4, 8: 6, 11: 6, 12: 8, 15: 8} {
		if got := cemValueCount(cem); got != want {
			t.Errorf("cemValueCount(%d) = %d, want %d", cem, got, want)
		}
	}
	for _, cem := range []int{2, 3, 7, 11, 14, 15} {
		if !isHDRMode(cem) {
			t.Errorf("mode %d is HDR", cem)
		}
	}
	for _, cem := range []int{0, 1, 4, 5, 6, 8, 9, 10, 12, 13} {
		if isHDRMode(cem) {
			t.Errorf("mode %d is LDR", cem)
		}
	}
}

// Dividing by 64 rather than 63 is what lets weight 0 and weight 64 land on
// the endpoints exactly instead of one unit short. Worth pinning.
func TestInterpolateHitsBothEndpointsExactly(t *testing.T) {
	for _, pair := range [][2]uint8{{0, 255}, {10, 200}, {77, 77}, {255, 0}} {
		if got := interpolate(pair[0], pair[1], 0, false); got != pair[0] {
			t.Errorf("weight 0 on (%d, %d) gave %d", pair[0], pair[1], got)
		}
		if got := interpolate(pair[0], pair[1], 64, false); got != pair[1] {
			t.Errorf("weight 64 on (%d, %d) gave %d", pair[0], pair[1], got)
		}
	}
	if got := interpolate(0, 255, 32, false); got != 127 && got != 128 {
		t.Errorf("midpoint of 0..255 is %d, want 127 or 128", got)
	}
	// sRGB widens differently, so the same weight gives a different result.
	if interpolate(0, 10, 16, true) == interpolate(0, 10, 16, false) {
		t.Error("the sRGB expansion should not match the linear one")
	}
}

func TestBitFieldsCrossTheWordBoundary(t *testing.T) {
	raw := make([]byte, 16)
	for i := range raw {
		raw[i] = byte(i * 17)
	}
	b := newBlock(raw)
	// Byte 8 is the first byte of the high word, so a field starting at bit
	// 60 and running twelve bits has to be stitched from both halves.
	want := ((uint32(raw[7]) >> 4) | (uint32(raw[8]) << 4)) & 0xFFF
	if got := b.field(60, 12); got != want {
		t.Errorf("field across the 64-bit boundary = %#x, want %#x", got, want)
	}
	if got := b.field(0, 8); got != uint32(raw[0]) {
		t.Errorf("field(0, 8) = %d, want %d", got, raw[0])
	}
	if got := b.field(120, 8); got != uint32(raw[15]) {
		t.Errorf("field(120, 8) = %d, want %d", got, raw[15])
	}
	if got := b.field(0, 0); got != 0 {
		t.Errorf("a zero-width field must be 0, got %d", got)
	}
}

// The weight stream is written downward from bit 127. Reversing the block once
// turns it into an ordinary forward stream, which is why there is no separate
// backward bit reader anywhere in this package.
func TestReversedBlockTurnsTheWeightStreamForward(t *testing.T) {
	raw := make([]byte, 16)
	raw[15] = 0x80 // the topmost bit of the block
	b := newBlock(raw)
	if got := b.field(127, 1); got != 1 {
		t.Fatalf("bit 127 reads %d, want 1", got)
	}
	if got := b.reversed().field(0, 1); got != 1 {
		t.Errorf("after reversing, bit 0 reads %d, want 1", got)
	}
	if got := b.reversed().reversed(); got != b {
		t.Error("reversing twice should return the original block")
	}
}

func TestReaderReadsZeroPastItsLimit(t *testing.T) {
	raw := make([]byte, 16)
	for i := range raw {
		raw[i] = 0xFF
	}
	r := reader{b: newBlock(raw), start: 0, limit: 4}
	if got := r.get(0, 4); got != 0xF {
		t.Errorf("inside the limit the reader returned %#x, want 0xF", got)
	}
	// A partial trailing trit or quint group reads its missing bits as zero
	// rather than borrowing whatever sits above it in the block.
	if got := r.get(4, 4); got != 0 {
		t.Errorf("past the limit the reader returned %#x, want 0", got)
	}
}
