package zstd

import "math/bits"

// ═══════════════════════════════════════════════════════════════════════════
// XXH64
// ═══════════════════════════════════════════════════════════════════════════
//
// A zstd frame optionally ends with the low four bytes of the XXH64 of its
// decoded content, seed zero. Without it a corrupted frame usually still
// decodes into something, so this is the difference between "the texture looks
// wrong" and "this file is damaged".
//
// Implemented here rather than pulled in, for the same reason as the rest of
// this package: go.mod has no dependencies and is going to stay that way.
//
// One Go-specific trap: the reference code initialises the fourth accumulator
// with 0 - PRIME1. Written as a typed constant expression that is a compile
// error in Go, because a constant cannot be negative in an unsigned type. The
// seed is therefore a runtime variable, which costs nothing and compiles.

const (
	xxhPrime1 uint64 = 11400714785074694791
	xxhPrime2 uint64 = 14029467366897019727
	xxhPrime3 uint64 = 1609587929392839161
	xxhPrime4 uint64 = 9650029242287828579
	xxhPrime5 uint64 = 2870177450012600261
)

func xxhRound(acc, input uint64) uint64 {
	acc += input * xxhPrime2
	acc = bits.RotateLeft64(acc, 31)
	return acc * xxhPrime1
}

func xxhMerge(acc, val uint64) uint64 {
	acc ^= xxhRound(0, val)
	return acc*xxhPrime1 + xxhPrime4
}

// xxhLE64 and xxhLE32 read little-endian words. Doing it by hand keeps this
// file free of encoding/binary and, more importantly, free of any alignment
// assumption: the same code is correct on x86-64, on 32-bit ARM and on a
// big-endian host, which is the whole point of not using unsafe here.
func xxhLE64(b []byte, i int) uint64 {
	return uint64(b[i]) | uint64(b[i+1])<<8 | uint64(b[i+2])<<16 |
		uint64(b[i+3])<<24 | uint64(b[i+4])<<32 | uint64(b[i+5])<<40 |
		uint64(b[i+6])<<48 | uint64(b[i+7])<<56
}

func xxhLE32(b []byte, i int) uint32 {
	return uint32(b[i]) | uint32(b[i+1])<<8 | uint32(b[i+2])<<16 | uint32(b[i+3])<<24
}

// xxh64 hashes data with seed zero, which is what the zstd frame format uses.
func xxh64(data []byte) uint64 {
	n := len(data)
	var h uint64

	if n >= 32 {
		var seed uint64 // zero, but as a variable: see the note above
		v1 := seed + xxhPrime1 + xxhPrime2
		v2 := seed + xxhPrime2
		v3 := seed
		v4 := seed - xxhPrime1

		i := 0
		for ; i+32 <= n; i += 32 {
			v1 = xxhRound(v1, xxhLE64(data, i))
			v2 = xxhRound(v2, xxhLE64(data, i+8))
			v3 = xxhRound(v3, xxhLE64(data, i+16))
			v4 = xxhRound(v4, xxhLE64(data, i+24))
		}

		h = bits.RotateLeft64(v1, 1) + bits.RotateLeft64(v2, 7) +
			bits.RotateLeft64(v3, 12) + bits.RotateLeft64(v4, 18)
		h = xxhMerge(h, v1)
		h = xxhMerge(h, v2)
		h = xxhMerge(h, v3)
		h = xxhMerge(h, v4)

		data = data[i:]
	} else {
		h = xxhPrime5
	}

	// The length of the whole input, not of the remaining tail.
	h += uint64(n)

	p := 0
	for ; p+8 <= len(data); p += 8 {
		h ^= xxhRound(0, xxhLE64(data, p))
		h = bits.RotateLeft64(h, 27)*xxhPrime1 + xxhPrime4
	}
	if p+4 <= len(data) {
		h ^= uint64(xxhLE32(data, p)) * xxhPrime1
		h = bits.RotateLeft64(h, 23)*xxhPrime2 + xxhPrime3
		p += 4
	}
	for ; p < len(data); p++ {
		h ^= uint64(data[p]) * xxhPrime5
		h = bits.RotateLeft64(h, 11) * xxhPrime1
	}

	h ^= h >> 33
	h *= xxhPrime2
	h ^= h >> 29
	h *= xxhPrime3
	h ^= h >> 32
	return h
}
