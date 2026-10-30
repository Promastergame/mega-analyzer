package astc

// ── Bounded Integer Sequence Encoding ──────────────────────────────────────
//
// Five base-3 digits carry 7.92 bits of information, so they pack into 8 bits
// with 1% waste. Three base-5 digits carry 6.97 bits and pack into 7. That is
// the whole idea behind BISE, and it is why ASTC can offer twelve weight
// precisions instead of the three or four a power-of-two format manages.
//
// The packed digits are interleaved with the low-order bits of each value so
// that a sequence can stop at any length and a decoder can still address any
// single value directly. The group widths below come straight from the spec's
// packing diagrams; they also match kInterleavedTritBits and
// kInterleavedQuintBits in google/astc-codec, which is a useful independent
// confirmation of a diagram that is easy to misread.

var tritGroupBits = [5]int{2, 2, 1, 2, 1}
var quintGroupBits = [3]int{3, 2, 2}

// decodeTrits unpacks five trits from the 8 bits T[7:0].
//
// Transcribed from the spec verbatim. The C[2] & ~C[3] terms are written with
// a subtraction rather than a bitwise complement because Go's ^ on an untyped
// constant would sign-extend and the intent is a single bit.
func decodeTrits(t uint32) [5]uint8 {
	var out [5]uint8
	var c uint32
	if field(t, 2, 4) == 7 {
		c = (field(t, 5, 7) << 2) | field(t, 0, 1)
		out[4] = 2
		out[3] = 2
	} else {
		c = field(t, 0, 4)
		if field(t, 5, 6) == 3 {
			out[4] = 2
			out[3] = uint8(field(t, 7, 7))
		} else {
			out[4] = uint8(field(t, 7, 7))
			out[3] = uint8(field(t, 5, 6))
		}
	}
	switch {
	case field(c, 0, 1) == 3:
		out[2] = 2
		out[1] = uint8(field(c, 4, 4))
		c3 := field(c, 3, 3)
		out[0] = uint8((c3 << 1) | (field(c, 2, 2) * (1 - c3)))
	case field(c, 2, 3) == 3:
		out[2] = 2
		out[1] = 2
		out[0] = uint8(field(c, 0, 1))
	default:
		out[2] = uint8(field(c, 4, 4))
		out[1] = uint8(field(c, 2, 3))
		c1 := field(c, 1, 1)
		out[0] = uint8((c1 << 1) | (field(c, 0, 0) * (1 - c1)))
	}
	return out
}

// decodeQuints unpacks three quints from the 7 bits Q[6:0].
func decodeQuints(q uint32) [3]uint8 {
	var out [3]uint8
	if field(q, 1, 2) == 3 && field(q, 5, 6) == 0 {
		low := field(q, 0, 0)
		inv := 1 - low
		out[2] = uint8((low << 2) | ((field(q, 4, 4) * inv) << 1) |
			(field(q, 3, 3) * inv))
		out[1] = 4
		out[0] = 4
		return out
	}
	var c uint32
	if field(q, 1, 2) == 3 {
		out[2] = 4
		c = (field(q, 3, 4) << 3) | ((3 - field(q, 5, 6)) << 1) | field(q, 0, 0)
	} else {
		out[2] = uint8(field(q, 5, 6))
		c = field(q, 0, 4)
	}
	if field(c, 0, 2) == 5 {
		out[1] = 4
		out[0] = uint8(field(c, 3, 4))
	} else {
		out[1] = uint8(field(c, 3, 4))
		out[0] = uint8(field(c, 0, 2))
	}
	return out
}

// field is the spec's v[hi:lo] notation on a plain integer.
func field(v uint32, lo, hi int) uint32 {
	return (v >> uint(lo)) & ((1 << uint(hi-lo+1)) - 1)
}

// decodeISE unpacks count values of the given range into out, which must have
// room for count entries.
//
// A trit or quint block is always read whole, even when the sequence ends part
// way through it; the reader supplies zeros past the end of the field, which
// is exactly what the spec prescribes.
func decodeISE(r reader, count int, s rangeSpec, out []uint8) {
	if count <= 0 || len(out) < count {
		return
	}
	pos := 0
	filled := 0
	switch {
	case s.trits != 0:
		var low [5]uint32
		for filled < count {
			var packed uint32
			shift := uint(0)
			for k := 0; k < 5; k++ {
				low[k] = r.get(pos, s.bits)
				pos += s.bits
				packed |= r.get(pos, tritGroupBits[k]) << shift
				pos += tritGroupBits[k]
				shift += uint(tritGroupBits[k])
			}
			digits := decodeTrits(packed)
			for k := 0; k < 5 && filled < count; k++ {
				out[filled] = uint8((uint32(digits[k]) << uint(s.bits)) + low[k])
				filled++
			}
		}
	case s.quints != 0:
		var low [3]uint32
		for filled < count {
			var packed uint32
			shift := uint(0)
			for k := 0; k < 3; k++ {
				low[k] = r.get(pos, s.bits)
				pos += s.bits
				packed |= r.get(pos, quintGroupBits[k]) << shift
				pos += quintGroupBits[k]
				shift += uint(quintGroupBits[k])
			}
			digits := decodeQuints(packed)
			for k := 0; k < 3 && filled < count; k++ {
				out[filled] = uint8((uint32(digits[k]) << uint(s.bits)) + low[k])
				filled++
			}
		}
	default:
		for filled < count {
			out[filled] = uint8(r.get(pos, s.bits))
			pos += s.bits
			filled++
		}
	}
}
