package astc

// ── Quantization ranges and unquantization ─────────────────────────────────
//
// BISE stores a value in one of three forms, and the range decides which:
//
//   0 .. 2^n-1        n bits
//   0 .. (3*2^n)-1    one base-3 trit  plus n bits
//   0 .. (5*2^n)-1    one base-5 quint plus n bits
//
// Capped at 255 that yields exactly 21 ranges, listed here smallest first.
// The list is derived arithmetic, not a transcription, so it cannot contain a
// copying slip; the tests check the derivation against the three published
// dequantization tables anyway.

type rangeSpec struct {
	max    int
	trits  int
	quints int
	bits   int
}

var allRanges = [21]rangeSpec{
	{1, 0, 0, 1},
	{2, 1, 0, 0},
	{3, 0, 0, 2},
	{4, 0, 1, 0},
	{5, 1, 0, 1},
	{7, 0, 0, 3},
	{9, 0, 1, 1},
	{11, 1, 0, 2},
	{15, 0, 0, 4},
	{19, 0, 1, 2},
	{23, 1, 0, 3},
	{31, 0, 0, 5},
	{39, 0, 1, 3},
	{47, 1, 0, 4},
	{63, 0, 0, 6},
	{79, 0, 1, 4},
	{95, 1, 0, 5},
	{127, 0, 0, 7},
	{159, 0, 1, 5},
	{191, 1, 0, 6},
	{255, 0, 0, 8},
}

// weightRanges are the twelve ranges the block mode field can name. The other
// nine exist only for colour endpoints.
var weightRanges = [12]int{1, 2, 3, 4, 5, 7, 9, 11, 15, 19, 23, 31}

// colorRanges are the seventeen ranges colour endpoints can use, smallest
// first. Anything below 0..5 is ruled out by the spec's illegal-encoding list:
// "this would restrict color integers to a range smaller than 0..5, which is
// not supported".
var colorRanges = [17]int{5, 7, 9, 11, 15, 19, 23, 31, 39, 47, 63, 79, 95,
	127, 159, 191, 255}

func specFor(max int) (rangeSpec, bool) {
	for _, s := range allRanges {
		if s.max == max {
			return s, true
		}
	}
	return rangeSpec{}, false
}

// iseBits is the packed size of a sequence, straight from the spec's data-size
// determination pseudocode. The ceilings are what let a sequence stop part way
// through a trit or quint block instead of paying for the whole thing.
func iseBits(count int, s rangeSpec) int {
	n := count * s.bits
	if s.trits != 0 {
		n += (count*8 + 4) / 5
	}
	if s.quints != 0 {
		n += (count*7 + 2) / 3
	}
	return n
}

// repBits replicates the n-bit value v from its most significant bit until it
// fills width bits.
//
// The spec spells this out for colours: "the three-bit value C2 C1 C0 would
// become C2 C1 C0 C2 C1 C0 C2 C1". The weight section gives the same rule but
// its worked example says the result is 5 bits wide, which cannot be right -
// the table immediately below it lists unquantized weights up to 63, and the
// width that reproduces every published weight table is 6. The tests pin all
// five bit-only weight ranges against their known values so this cannot drift.
func repBits(v uint32, n, width int) uint32 {
	if n <= 0 {
		return 0
	}
	var out uint32
	for filled := 0; filled < width; {
		take := n
		if width-filled < take {
			take = width - filled
		}
		out = (out << uint(take)) | (v >> uint(n-take))
		filled += take
	}
	return out
}

// buildB evaluates one of the spec's bit-layout strings, such as "b000b0bb0".
// The string is most significant bit first; a letter selects that bit of the
// low-order value m, counting a as bit 0, and a zero contributes nothing.
//
// Keeping the layouts as the spec's own strings rather than pre-computed
// integers is deliberate: a wrong digit in a string is visible next to the
// specification, a wrong integer is not.
func buildB(layout string, m uint32) uint32 {
	var v uint32
	for i := 0; i < len(layout); i++ {
		v <<= 1
		if c := layout[i]; c != '0' {
			v |= (m >> uint(c-'a')) & 1
		}
	}
	return v
}

type unqParams struct {
	bits   int
	layout string
	c      uint32
}

// colorUnqFor is the spec table "ASTC color unquantization parameters".
func colorUnqFor(max int) (unqParams, bool) {
	switch max {
	case 5:
		return unqParams{1, "000000000", 204}, true
	case 9:
		return unqParams{1, "000000000", 113}, true
	case 11:
		return unqParams{2, "b000b0bb0", 93}, true
	case 19:
		return unqParams{2, "b0000bb00", 54}, true
	case 23:
		return unqParams{3, "cb000cbcb", 44}, true
	case 39:
		return unqParams{3, "cb0000cbc", 26}, true
	case 47:
		return unqParams{4, "dcb000dcb", 22}, true
	case 79:
		return unqParams{4, "dcb0000dc", 13}, true
	case 95:
		return unqParams{5, "edcb000ed", 11}, true
	case 159:
		return unqParams{5, "edcb0000e", 6}, true
	case 191:
		return unqParams{6, "fedcb000f", 5}, true
	}
	return unqParams{}, false
}

// weightUnqFor is the spec table "ASTC weight unquantization parameters".
func weightUnqFor(max int) (unqParams, bool) {
	switch max {
	case 5:
		return unqParams{1, "0000000", 50}, true
	case 9:
		return unqParams{1, "0000000", 28}, true
	case 11:
		return unqParams{2, "b000b0b", 23}, true
	case 19:
		return unqParams{2, "b0000b0", 13}, true
	case 23:
		return unqParams{3, "cb000cb", 11}, true
	}
	return unqParams{}, false
}

// unquantColor lifts a stored colour integer back to 0..255.
//
// The trit and quint path is the spec's three-line bit shuffle. It is cheap in
// hardware and it deliberately scrambles the ordering: stored value 1 in range
// 0..5 unquantizes to 255, not to 51. That is not a bug to be tidied up - an
// encoder is expected to compensate through a table - and the tests assert the
// scrambled order explicitly so nobody "fixes" it later.
func unquantColor(v uint32, max int) uint32 {
	s, ok := specFor(max)
	if !ok {
		return 0
	}
	if s.trits == 0 && s.quints == 0 {
		return repBits(v, s.bits, 8)
	}
	p, ok := colorUnqFor(max)
	if !ok {
		return 0
	}
	m := v & ((1 << uint(p.bits)) - 1)
	d := v >> uint(p.bits)
	var a uint32
	if m&1 != 0 {
		a = 0x1FF
	}
	unq := d*p.c + buildB(p.layout, m)
	unq ^= a
	return (a & 0x80) | (unq >> 2)
}

// unquantWeight lifts a stored weight back to 0..64.
//
// The last step, bumping anything above 32 by one, is what lets the
// interpolator divide by 64 instead of 63. It also puts a visible seam in the
// middle of every table: range 0..31 runs 0, 2, 4 ... 30 and then jumps to 34.
//
// The trit and quint ranges - 0..5, 0..9, 0..11, 0..19 and 0..23 - go through
// the same bit shuffle as unquantColor and come out scrambled for exactly the
// same reason: stored weight 1 unquantizes to 64, not to the second smallest
// value. Sorting those sequences into ascending order looks tidier and is
// wrong; it mismatches the weight the encoder chose for all but the two
// endpoints, which shows up as blotchy 4x4 patches scattered over the image
// wherever a block happens to pick a trit or quint weight range.
func unquantWeight(v uint32, max int) uint32 {
	s, ok := specFor(max)
	if !ok {
		return 0
	}
	var unq uint32
	switch {
	case max == 2:
		// Spec table "ASTC weight unquantization values", no extra bits.
		unq = [3]uint32{0, 32, 63}[v%3]
	case max == 4:
		unq = [5]uint32{0, 16, 32, 47, 63}[v%5]
	case s.trits == 0 && s.quints == 0:
		unq = repBits(v, s.bits, 6)
	default:
		p, pok := weightUnqFor(max)
		if !pok {
			return 0
		}
		m := v & ((1 << uint(p.bits)) - 1)
		d := v >> uint(p.bits)
		var a uint32
		if m&1 != 0 {
			a = 0x7F
		}
		unq = d*p.c + buildB(p.layout, m)
		unq ^= a
		unq = (a & 0x20) | (unq >> 2)
	}
	if unq > 32 {
		unq++
	}
	return unq
}
