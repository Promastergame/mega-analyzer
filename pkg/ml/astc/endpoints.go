package astc

// ── Colour endpoint modes ────────────────────────────────────────────────
//
// Sixteen ways to spell two colours. The interesting ones are not the direct
// modes but the tricks:
//
//   base+offset  stores the second endpoint as a small signed delta, and steals
//                the top bit of the delta to extend the base - that is what
//                bitTransferSigned does.
//   base+scale   stores one colour and a scalar, so a gradient that runs to
//                black costs four values instead of six.
//   blue contract  is the odd one. When the encoder finds the endpoints in the
//                wrong order it swaps them, and the decoder reads that swap as
//                a signal to un-shift the red and green channels toward blue.
//                It buys roughly one extra bit of precision on the two
//                channels the eye cares about most, for free.
//
// Modes 2, 3, 7, 11, 14 and 15 are HDR. This decoder implements the LDR
// profile, and the spec's LDR Profile Support section is explicit that an
// LDR decoder returns the error colour for them rather than approximating.

// isHDRMode reports whether a colour endpoint mode needs HDR decoding.
func isHDRMode(cem int) bool {
	switch cem {
	case 2, 3, 7, 11, 14, 15:
		return true
	}
	return false
}

// cemValueCount is how many quantized integers a mode consumes. The mode
// number's top two bits are its class, and each class step adds two values.
func cemValueCount(cem int) int {
	return 2 * ((cem >> 2) + 1)
}

func clampU8(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}

// blueContract shifts red and green halfway toward blue.
func blueContract(r, g, b int) (int, int, int) {
	return (r + b) >> 1, (g + b) >> 1, b
}

// bitTransferSigned moves the top bit of a into b and reinterprets what is
// left of a as a six-bit signed offset. It returns the new a and b, in that
// order, matching the spec's argument order bit_transfer_signed(a, b).
func bitTransferSigned(a, b int) (int, int) {
	b >>= 1
	b |= a & 0x80
	a >>= 1
	a &= 0x3F
	if a&0x20 != 0 {
		a -= 0x40
	}
	return a, b
}

// decodeEndpoints turns unquantized colour integers into two RGBA endpoints.
// Callers must screen out HDR modes first; this returns black for them rather
// than guessing.
func decodeEndpoints(cem int, v []uint32) ([4]uint8, [4]uint8) {
	var e0, e1 [4]uint8
	need := cemValueCount(cem)
	if len(v) < need {
		return e0, e1
	}
	i := make([]int, need)
	for k := 0; k < need; k++ {
		i[k] = int(v[k])
	}

	switch cem {
	case 0: // LDR luminance, direct
		e0 = [4]uint8{uint8(i[0]), uint8(i[0]), uint8(i[0]), 0xFF}
		e1 = [4]uint8{uint8(i[1]), uint8(i[1]), uint8(i[1]), 0xFF}

	case 1: // LDR luminance, base plus offset
		l0 := (i[0] >> 2) | (i[1] & 0xC0)
		l1 := l0 + (i[1] & 0x3F)
		if l1 > 0xFF {
			l1 = 0xFF
		}
		e0 = [4]uint8{uint8(l0), uint8(l0), uint8(l0), 0xFF}
		e1 = [4]uint8{uint8(l1), uint8(l1), uint8(l1), 0xFF}

	case 4: // LDR luminance and alpha, direct
		e0 = [4]uint8{uint8(i[0]), uint8(i[0]), uint8(i[0]), uint8(i[2])}
		e1 = [4]uint8{uint8(i[1]), uint8(i[1]), uint8(i[1]), uint8(i[3])}

	case 5: // LDR luminance and alpha, base plus offset
		v1, v0 := bitTransferSigned(i[1], i[0])
		v3, v2 := bitTransferSigned(i[3], i[2])
		e0 = [4]uint8{clampU8(v0), clampU8(v0), clampU8(v0), clampU8(v2)}
		l1 := clampU8(v0 + v1)
		e1 = [4]uint8{l1, l1, l1, clampU8(v2 + v3)}

	case 6: // LDR RGB, base plus scale
		e0 = [4]uint8{
			uint8((i[0] * i[3]) >> 8),
			uint8((i[1] * i[3]) >> 8),
			uint8((i[2] * i[3]) >> 8),
			0xFF,
		}
		e1 = [4]uint8{uint8(i[0]), uint8(i[1]), uint8(i[2]), 0xFF}

	case 8: // LDR RGB, direct
		if i[1]+i[3]+i[5] >= i[0]+i[2]+i[4] {
			e0 = [4]uint8{uint8(i[0]), uint8(i[2]), uint8(i[4]), 0xFF}
			e1 = [4]uint8{uint8(i[1]), uint8(i[3]), uint8(i[5]), 0xFF}
		} else {
			r0, g0, b0 := blueContract(i[1], i[3], i[5])
			r1, g1, b1 := blueContract(i[0], i[2], i[4])
			e0 = [4]uint8{uint8(r0), uint8(g0), uint8(b0), 0xFF}
			e1 = [4]uint8{uint8(r1), uint8(g1), uint8(b1), 0xFF}
		}

	case 9: // LDR RGB, base plus offset
		v1, v0 := bitTransferSigned(i[1], i[0])
		v3, v2 := bitTransferSigned(i[3], i[2])
		v5, v4 := bitTransferSigned(i[5], i[4])
		if v1+v3+v5 >= 0 {
			e0 = [4]uint8{clampU8(v0), clampU8(v2), clampU8(v4), 0xFF}
			e1 = [4]uint8{clampU8(v0 + v1), clampU8(v2 + v3), clampU8(v4 + v5), 0xFF}
		} else {
			r0, g0, b0 := blueContract(v0+v1, v2+v3, v4+v5)
			r1, g1, b1 := blueContract(v0, v2, v4)
			e0 = [4]uint8{clampU8(r0), clampU8(g0), clampU8(b0), 0xFF}
			e1 = [4]uint8{clampU8(r1), clampU8(g1), clampU8(b1), 0xFF}
		}

	case 10: // LDR RGB, base plus scale, with two alphas
		e0 = [4]uint8{
			uint8((i[0] * i[3]) >> 8),
			uint8((i[1] * i[3]) >> 8),
			uint8((i[2] * i[3]) >> 8),
			uint8(i[4]),
		}
		e1 = [4]uint8{uint8(i[0]), uint8(i[1]), uint8(i[2]), uint8(i[5])}

	case 12: // LDR RGBA, direct
		if i[1]+i[3]+i[5] >= i[0]+i[2]+i[4] {
			e0 = [4]uint8{uint8(i[0]), uint8(i[2]), uint8(i[4]), uint8(i[6])}
			e1 = [4]uint8{uint8(i[1]), uint8(i[3]), uint8(i[5]), uint8(i[7])}
		} else {
			r0, g0, b0 := blueContract(i[1], i[3], i[5])
			r1, g1, b1 := blueContract(i[0], i[2], i[4])
			e0 = [4]uint8{uint8(r0), uint8(g0), uint8(b0), uint8(i[7])}
			e1 = [4]uint8{uint8(r1), uint8(g1), uint8(b1), uint8(i[6])}
		}

	case 13: // LDR RGBA, base plus offset
		v1, v0 := bitTransferSigned(i[1], i[0])
		v3, v2 := bitTransferSigned(i[3], i[2])
		v5, v4 := bitTransferSigned(i[5], i[4])
		v7, v6 := bitTransferSigned(i[7], i[6])
		if v1+v3+v5 >= 0 {
			e0 = [4]uint8{clampU8(v0), clampU8(v2), clampU8(v4), clampU8(v6)}
			e1 = [4]uint8{clampU8(v0 + v1), clampU8(v2 + v3),
				clampU8(v4 + v5), clampU8(v6 + v7)}
		} else {
			r0, g0, b0 := blueContract(v0+v1, v2+v3, v4+v5)
			r1, g1, b1 := blueContract(v0, v2, v4)
			e0 = [4]uint8{clampU8(r0), clampU8(g0), clampU8(b0), clampU8(v6 + v7)}
			e1 = [4]uint8{clampU8(r1), clampU8(g1), clampU8(b1), clampU8(v6)}
		}
	}
	return e0, e1
}

// interpolate blends two endpoint components with a 0..64 weight.
//
// The endpoints are widened to 16 bits first, and the divide is by 64 rather
// than 63 - that is the whole reason unquantWeight bumps values above 32, and
// it is what makes weight 0 and weight 64 land exactly on the endpoints
// instead of one least significant bit short.
func interpolate(c0, c1 uint8, w uint32, srgb bool) uint8 {
	var a, b uint32
	if srgb {
		a = (uint32(c0) << 8) | 0x80
		b = (uint32(c1) << 8) | 0x80
	} else {
		a = (uint32(c0) << 8) | uint32(c0)
		b = (uint32(c1) << 8) | uint32(c1)
	}
	if w > 64 {
		w = 64
	}
	return uint8(((a*(64-w) + b*w + 32) / 64) >> 8)
}
