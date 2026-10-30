package zstd

import (
	"encoding/binary"
	"math/bits"
)

// ═══════════════════════════════════════════════════════════════════════════
// Reverse bitstream
// ═══════════════════════════════════════════════════════════════════════════
//
// Every entropy-coded stream in zstd is written backwards: the encoder fills
// bits from the end of the buffer towards the front, so a decoder starts at
// the LAST byte and walks down. The highest set bit of the final byte is an
// end marker rather than data, and everything above it is padding.
//
// The reference C implementation keeps a 64-bit register and reloads it as a
// pointer slides backwards, with four separate status codes for the ways that
// can end. All of that exists for speed. Here the buffer is addressed directly
// and one counter tracks how many bits remain, which removes the reload logic,
// removes the 32-bit register variant the C code has to special-case, and
// makes an overrun a single comparison. Go emulates 64-bit shifts on 32-bit
// ARM, so a Termux build behaves exactly like an amd64 one.

type bitReader struct {
	data  []byte
	avail int // bits not yet consumed; goes negative if a stream is overrun
}

func newBitReader(data []byte) (*bitReader, error) {
	if len(data) == 0 {
		return nil, trunc("bitstream is empty")
	}
	last := data[len(data)-1]
	if last == 0 {
		// A zero final byte means the end marker is missing, which the format
		// forbids. Rejecting it here keeps every later shift in range.
		return nil, errf("bitstream has no end marker")
	}
	skip := 8 - (bits.Len8(last) - 1)
	return &bitReader{data: data, avail: 8*len(data) - skip}, nil
}

// load64 reads eight little-endian bytes at off, treating anything outside the
// buffer as zero. Reads near either edge are legal and simply see zeros.
func (b *bitReader) load64(off int) uint64 {
	if off >= len(b.data) {
		return 0
	}
	if off >= 0 && off+8 <= len(b.data) {
		return binary.LittleEndian.Uint64(b.data[off : off+8])
	}
	var v uint64
	for i := 0; i < 8; i++ {
		j := off + i
		if j >= 0 && j < len(b.data) {
			v |= uint64(b.data[j]) << (8 * uint(i))
		}
	}
	return v
}

// peek returns the next n bits, most significant first, without consuming
// them. n never exceeds 32 in this package: the widest field in the format is
// a 31-bit offset.
func (b *bitReader) peek(n uint8) uint32 {
	if n == 0 {
		return 0
	}
	mask := uint64(1)<<uint(n) - 1
	shift := b.avail - int(n)
	if shift >= 0 {
		return uint32((b.load64(shift>>3) >> uint(shift&7)) & mask)
	}
	// Reading past the start yields zeros in the low bits, matching what the C
	// reader produces once its register underflows. The overrun itself is
	// reported separately by overrun(), so callers can decide when it is fatal:
	// the FSE weight stream actually relies on running out of bits to know it
	// has finished.
	return uint32((b.load64(0) << uint(-shift)) & mask)
}

func (b *bitReader) skip(n uint8) {
	b.avail -= int(n)
}

func (b *bitReader) read(n uint8) uint32 {
	v := b.peek(n)
	b.avail -= int(n)
	return v
}

func (b *bitReader) overrun() bool { return b.avail < 0 }

// remaining is checked at the end of a sequences section: a well-formed stream
// finishes with exactly zero bits left over.
func (b *bitReader) remaining() int { return b.avail }

// ═══════════════════════════════════════════════════════════════════════════
// Forward bitstream
// ═══════════════════════════════════════════════════════════════════════════
//
// The FSE distribution header is the one field zstd writes forwards, least
// significant bit first, out of a sliding 32-bit window. Addressing the buffer
// by absolute bit position instead removes the reload dance entirely.

func peekForward(src []byte, at int, n uint8) uint32 {
	if n == 0 {
		return 0
	}
	off := at >> 3
	var v uint64
	// Five bytes cover any 33-bit span, and the widest read here is
	// accuracyLog+1, which is at most 10.
	for i := 0; i < 5; i++ {
		j := off + i
		if j >= 0 && j < len(src) {
			v |= uint64(src[j]) << (8 * uint(i))
		}
	}
	return uint32((v >> uint(at&7)) & (uint64(1)<<uint(n) - 1))
}
