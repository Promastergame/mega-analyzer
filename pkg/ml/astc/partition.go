package astc

// ── Partition patterns ────────────────────────────────────────────────────
//
// A block can split its texels into up to four regions, each with its own
// colour endpoints. Storing the shape of that split would cost more bits than
// the endpoints save, so ASTC does not store it: a 10-bit seed is fed to a
// hash function and the pattern falls out of the arithmetic. 1024 seeds times
// four partition counts gives 4096 patterns for the price of 10 bits.
//
// That makes this function part of the bitstream. It is not a heuristic and it
// cannot be improved on, replaced with something prettier, or reordered - any
// change here silently decodes every partitioned block in the world wrongly.
// Transcribed from the spec's C listing, including the deliberately irregular
// bit positions of seeds 9 through 12.

// hash52 is the spec's mixer. Every step is invertible, so it is a bijection
// on uint32 - which the tests assert, because it is the cheapest possible
// check that no shift or constant got mistyped. It has no additive constant,
// so hash52(0) is 0; that is harmless because a partitioned block always adds
// (partitioncount-1)*1024 to the seed first.
func hash52(p uint32) uint32 {
	p ^= p >> 15
	p -= p << 17
	p += p << 7
	p += p << 4
	p ^= p >> 5
	p += p << 16
	p ^= p >> 7
	p ^= p >> 3
	p ^= p << 6
	p ^= p >> 17
	return p
}

// selectPartition returns which partition texel x, y, z belongs to.
//
// smallBlock doubles the coordinates for footprints with fewer than 31 texels,
// which spreads the same pattern family over a block too small to show it
// otherwise.
func selectPartition(seed, x, y, z, count int, smallBlock bool) int {
	if count <= 1 {
		return 0
	}
	if smallBlock {
		x <<= 1
		y <<= 1
		z <<= 1
	}

	seed += (count - 1) * 1024
	rnum := hash52(uint32(seed))

	s1 := rnum & 0xF
	s2 := (rnum >> 4) & 0xF
	s3 := (rnum >> 8) & 0xF
	s4 := (rnum >> 12) & 0xF
	s5 := (rnum >> 16) & 0xF
	s6 := (rnum >> 20) & 0xF
	s7 := (rnum >> 24) & 0xF
	s8 := (rnum >> 28) & 0xF
	// Seeds 9 to 12 overlap the earlier ones on purpose; seed 12 wraps around
	// the top of the word.
	s9 := (rnum >> 18) & 0xF
	s10 := (rnum >> 22) & 0xF
	s11 := (rnum >> 26) & 0xF
	s12 := ((rnum >> 30) | (rnum << 2)) & 0xF

	s1 *= s1
	s2 *= s2
	s3 *= s3
	s4 *= s4
	s5 *= s5
	s6 *= s6
	s7 *= s7
	s8 *= s8
	s9 *= s9
	s10 *= s10
	s11 *= s11
	s12 *= s12

	var sh1, sh2 uint
	if seed&1 != 0 {
		if seed&2 != 0 {
			sh1 = 4
		} else {
			sh1 = 5
		}
		if count == 3 {
			sh2 = 6
		} else {
			sh2 = 5
		}
	} else {
		if count == 3 {
			sh1 = 6
		} else {
			sh1 = 5
		}
		if seed&2 != 0 {
			sh2 = 4
		} else {
			sh2 = 5
		}
	}
	sh3 := sh2
	if seed&0x10 != 0 {
		sh3 = sh1
	}

	s1 >>= sh1
	s2 >>= sh2
	s3 >>= sh1
	s4 >>= sh2
	s5 >>= sh1
	s6 >>= sh2
	s7 >>= sh1
	s8 >>= sh2
	s9 >>= sh3
	s10 >>= sh3
	s11 >>= sh3
	s12 >>= sh3

	ux := uint32(x)
	uy := uint32(y)
	uz := uint32(z)

	a := (s1*ux + s2*uy + s11*uz + (rnum >> 14)) & 0x3F
	b := (s3*ux + s4*uy + s12*uz + (rnum >> 10)) & 0x3F
	c := (s5*ux + s6*uy + s9*uz + (rnum >> 6)) & 0x3F
	d := (s7*ux + s8*uy + s10*uz + (rnum >> 2)) & 0x3F

	if count < 4 {
		d = 0
	}
	if count < 3 {
		c = 0
	}

	switch {
	case a >= b && a >= c && a >= d:
		return 0
	case b >= c && b >= d:
		return 1
	case c >= d:
		return 2
	default:
		return 3
	}
}
