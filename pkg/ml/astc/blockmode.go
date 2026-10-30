package astc

// ── The block mode field ───────────────────────────────────────────────────
//
// Eleven bits decide the weight grid, the weight precision and whether the
// block has two weight planes. It is the densest field in the format: the grid
// dimensions are spread across five discontiguous bit groups and the weight
// range is assembled from bits 0, 1 and 4 in one layout and bits 2, 3 and 4 in
// another. This is a lookup table in hardware; here it is the spec's decision
// tree, in the spec's order, because the order is load-bearing - the void
// extent pattern would otherwise be swallowed by a later row.
//
// Of the 2048 encodings, 90 distinct weight grid shapes are reachable and the
// rest are reserved. The tests check that every reachable shape lands inside
// 2..12 on both axes, which is the range the grid dimensions can express.

type mode struct {
	voidExtent bool
	reserved   bool
	gw         int
	gh         int
	dualPlane  bool
	weightMax  int
}

// parseMode decodes the low 11 bits of a block.
func parseMode(bm uint32) mode {
	var m mode

	// Row 1: the void extent pattern, which must be tested before anything
	// else because it also satisfies later rows.
	if field(bm, 0, 8) == 0x1FC {
		m.voidExtent = true
		return m
	}
	// Row 2 and row 3: the two reserved patterns.
	if field(bm, 0, 1) == 0 && field(bm, 6, 8) == 7 {
		m.reserved = true
		return m
	}
	if field(bm, 0, 3) == 0 {
		m.reserved = true
		return m
	}

	b4 := field(bm, 4, 4)
	b5 := field(bm, 5, 5)
	b6 := field(bm, 6, 6)
	b7 := field(bm, 7, 7)
	b8 := field(bm, 8, 8)
	low := field(bm, 5, 6)

	var rho, p uint32
	if field(bm, 0, 1) != 0 {
		rho = (field(bm, 1, 1) << 2) | (field(bm, 0, 0) << 1) | b4
		p = field(bm, 9, 9)
		m.dualPlane = field(bm, 10, 10) != 0
		high := field(bm, 7, 8)
		switch field(bm, 2, 3) {
		case 0:
			m.gw = int(high) + 4
			m.gh = int(low) + 2
		case 1:
			m.gw = int(high) + 8
			m.gh = int(low) + 2
		case 2:
			m.gw = int(low) + 2
			m.gh = int(high) + 8
		default:
			if b8 == 0 {
				m.gw = int(low) + 2
				m.gh = int(b7) + 6
			} else {
				m.gw = int(b7) + 2
				m.gh = int(low) + 2
			}
		}
	} else {
		rho = (field(bm, 3, 3) << 2) | (field(bm, 2, 2) << 1) | b4
		p = field(bm, 9, 9)
		m.dualPlane = field(bm, 10, 10) != 0
		switch {
		case b8 == 0 && b7 == 0:
			m.gw = 12
			m.gh = int(low) + 2
		case b8 == 0 && b7 == 1:
			m.gw = int(low) + 2
			m.gh = 12
		case b8 == 1 && b7 == 0:
			// This row carries the grid in bits 9 and 10, so it has no room
			// left for the dual-plane or high-precision flags and the spec
			// fixes both at zero.
			m.gw = int(low) + 6
			m.gh = int(field(bm, 9, 10)) + 6
			m.dualPlane = false
			p = 0
		case b6 == 0 && b5 == 0:
			m.gw = 6
			m.gh = 10
		case b6 == 0 && b5 == 1:
			m.gw = 10
			m.gh = 6
		default:
			m.reserved = true
			return m
		}
	}

	// R must be at least 2; the spec forbids the two low bits of R being
	// zero, and both assembly layouts above guarantee it, so a violation
	// here would mean a transcription error rather than bad input.
	if rho < 2 || rho > 7 {
		m.reserved = true
		return m
	}
	m.weightMax = weightRanges[int(rho-2)+6*int(p)]
	return m
}
