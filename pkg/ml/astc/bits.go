package astc

import (
	"encoding/binary"
	"math/bits"
)

// ── The 128-bit block ──────────────────────────────────────────────────────
//
// Go has no uint128, so a block is two uint64 halves. The spec labels bits in
// little-endian order: the byte at the lowest address holds bits 0..7 and bit
// 0 is the least significant bit of that byte. That is exactly what
// binary.LittleEndian gives, so no shuffling is needed on the way in.
//
// Nothing here narrows a bit offset into a type that could overflow on a
// 32-bit ARM build: offsets are plain int in 0..127 and shift counts are uint.

type block struct {
	lo uint64
	hi uint64
}

func newBlock(b []byte) block {
	return block{
		lo: binary.LittleEndian.Uint64(b[0:8]),
		hi: binary.LittleEndian.Uint64(b[8:16]),
	}
}

// field returns n bits starting at bit off. n must be at most 32, which every
// caller satisfies: the widest field in the format is the 16-bit void-extent
// colour component.
func (b block) field(off, n int) uint32 {
	if n <= 0 || off >= 128 {
		return 0
	}
	var v uint64
	if off < 64 {
		v = b.lo >> uint(off)
		if off+n > 64 {
			// Go defines a shift of 64 on a uint64 as zero rather than
			// leaving it undefined, so off == 0 needs no special case.
			v |= b.hi << uint(64-off)
		}
	} else {
		v = b.hi >> uint(off-64)
	}
	return uint32(v & ((1 << uint(n)) - 1))
}

// reversed mirrors all 128 bits.
//
// The weight stream is defined the other way up from everything else: "the
// weight information is stored as a stream of bits, growing downwards from the
// most significant bit in the block. Bit n in the stream is thus bit 127-n in
// the block." Reversing the block once turns that into an ordinary forward
// stream, which means one bit-addressing scheme instead of two. bits.Reverse64
// makes it a two-instruction job on most targets and correct on all of them.
func (b block) reversed() block {
	return block{lo: bits.Reverse64(b.hi), hi: bits.Reverse64(b.lo)}
}

// reader is a bounded window onto a block, addressed from zero.
//
// The bound matters: "if there are insufficient bits in the stream to fill the
// final block, then unused (higher-order) bits are assumed to be 0 when
// decoding." A BISE block is read whole even when it holds fewer values than
// its capacity, so reads really do run past the end of the field, and they
// must return zero rather than borrow bits from the neighbouring field.
type reader struct {
	b     block
	start int
	limit int
}

func (r reader) get(off, n int) uint32 {
	if n <= 0 {
		return 0
	}
	base := r.start + off
	if base >= r.limit {
		return 0
	}
	if avail := r.limit - base; avail < n {
		n = avail
	}
	return r.b.field(base, n)
}
