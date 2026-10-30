package zstd

import "math/bits"

// ═══════════════════════════════════════════════════════════════════════════
// Finite State Entropy
// ═══════════════════════════════════════════════════════════════════════════
//
// FSE is zstd's arithmetic-coder-grade entropy stage. A decoder holds a state
// number; each state slot names the symbol it emits, how many bits to read
// next, and the base of the state to jump to. Two things have to be exactly
// right or the output silently diverges: the order symbols are sprayed across
// the table, and the fact that low-probability symbols (count -1) are packed
// backwards from the end.
//
// Ports FSE_readNCount_body, FSE_buildDTable_internal and
// ZSTD_buildFSETable_body from zstd 1.5.7.

type fseTable struct {
	log   uint8
	sym   []uint8
	nbits []uint8
	next  []uint16
}

// seqTable is an FSE table whose slots already carry the length or offset
// baseline for their symbol, which is how the decompressor avoids a second
// lookup per sequence.
type seqTable struct {
	log   uint8
	base  []uint32
	extra []uint8
	nbits []uint8
	next  []uint16
}

// readNCount decodes a normalized distribution header. Unusually for zstd this
// one field is written forwards, least significant bit first.
func readNCount(src []byte, maxSV int, maxLog uint8) (norm []int16, sv int, log uint8, used int, err error) {
	if len(src) == 0 {
		return nil, 0, 0, 0, trunc("distribution header is missing")
	}
	maxSV1 := maxSV + 1
	norm = make([]int16, maxSV1)
	log = uint8(peekForward(src, 0, 4)) + fseMinTableLog
	if log > maxLog {
		return nil, 0, 0, 0, errf("distribution accuracy log %d exceeds the %d allowed here", log, maxLog)
	}

	bitPos := 4
	remaining := 1<<uint(log) + 1
	threshold := 1 << uint(log)
	nbBits := int(log) + 1
	charnum := 0
	previous0 := false

	for {
		if previous0 {
			// A zero count is followed by a run-length of further zeroes,
			// coded as pairs of bits where 0b11 means "three more, keep
			// reading". The slots stay at zero because norm starts zeroed.
			for {
				v := peekForward(src, bitPos, 2)
				bitPos += 2
				if v == 3 {
					charnum += 3
					if charnum > maxSV1 {
						return nil, 0, 0, 0, errf("distribution zero-run passes the last symbol")
					}
					continue
				}
				charnum += int(v)
				break
			}
			if charnum >= maxSV1 {
				break
			}
		}

		// Counts are coded with a variable width: the low values of the range
		// need one bit fewer than the high ones.
		max := (2*threshold - 1) - remaining
		v := int(peekForward(src, bitPos, uint8(nbBits)))
		var count int
		if v&(threshold-1) < max {
			count = v & (threshold - 1)
			bitPos += nbBits - 1
		} else {
			count = v & (2*threshold - 1)
			if count >= threshold {
				count -= max
			}
			bitPos += nbBits
		}

		// The stored value is biased by one so that -1 can mean "present but
		// improbable", which is a real symbol occupying a single table slot.
		count--
		if count >= 0 {
			remaining -= count
		} else {
			remaining += count
		}
		if charnum >= maxSV1 {
			return nil, 0, 0, 0, errf("distribution lists more than %d symbols", maxSV1)
		}
		norm[charnum] = int16(count)
		charnum++
		previous0 = count == 0

		if remaining < threshold {
			if remaining <= 1 {
				break
			}
			nbBits = bits.Len32(uint32(remaining))
			threshold = 1 << uint(nbBits-1)
		}
		if charnum >= maxSV1 {
			break
		}
	}

	if remaining != 1 {
		return nil, 0, 0, 0, errf("distribution counts do not add up to the table size")
	}
	if charnum == 0 {
		return nil, 0, 0, 0, errf("distribution is empty")
	}
	used = (bitPos + 7) >> 3
	if used > len(src) {
		return nil, 0, 0, 0, trunc("distribution header runs past the section")
	}
	return norm, charnum - 1, log, used, nil
}

// fseSpread lays symbols out across the decoding table. This is the part that
// has to match the C byte for byte: the stride, the wrap, and the skip over
// the region reserved for low-probability symbols.
func fseSpread(norm []int16, maxSV int, log uint8) (sym []uint8, nbits []uint8, next []uint16, err error) {
	if log == 0 || log > 15 {
		return nil, nil, nil, errf("table log %d is out of range", log)
	}
	if maxSV < 0 || maxSV >= len(norm) {
		return nil, nil, nil, errf("symbol count %d does not match the distribution", maxSV)
	}
	size := 1 << uint(log)
	high := size - 1
	sym = make([]uint8, size)
	symbolNext := make([]uint16, maxSV+1)

	// Pass one: park every improbable symbol at the top of the table, working
	// downwards, and record each symbol's starting state counter.
	for s := 0; s <= maxSV; s++ {
		c := norm[s]
		if c == -1 {
			if high < 0 {
				return nil, nil, nil, errf("more improbable symbols than table slots")
			}
			sym[high] = uint8(s)
			high--
			symbolNext[s] = 1
			continue
		}
		if c < 0 {
			return nil, nil, nil, errf("symbol %d has an invalid count %d", s, c)
		}
		if int(c) > size {
			return nil, nil, nil, errf("symbol %d claims %d of %d slots", s, c, size)
		}
		symbolNext[s] = uint16(c)
	}

	// Pass two: walk the table with a stride that is coprime with its size, so
	// a single pass visits every slot exactly once.
	step := (size >> 1) + (size >> 3) + 3
	mask := size - 1
	pos := 0
	for s := 0; s <= maxSV; s++ {
		n := int(norm[s])
		if n <= 0 {
			continue
		}
		for i := 0; i < n; i++ {
			sym[pos] = uint8(s)
			pos = (pos + step) & mask
			for pos > high {
				pos = (pos + step) & mask
			}
		}
	}
	if pos != 0 {
		return nil, nil, nil, errf("distribution does not cover the table exactly")
	}

	// Pass three: turn per-symbol counters into bit widths and jump targets.
	nbits = make([]uint8, size)
	next = make([]uint16, size)
	for u := 0; u < size; u++ {
		s := sym[u]
		nx := symbolNext[s]
		symbolNext[s] = nx + 1
		if nx == 0 {
			return nil, nil, nil, errf("table slot %d names a symbol with no counts", u)
		}
		b := int(log) - (bits.Len16(nx) - 1)
		if b < 0 {
			return nil, nil, nil, errf("table slot %d needs a negative bit width", u)
		}
		nbits[u] = uint8(b)
		next[u] = uint16(int(nx)<<uint(b) - size)
	}
	return sym, nbits, next, nil
}

func buildFSETable(norm []int16, maxSV int, log uint8) (*fseTable, error) {
	sym, nbits, next, err := fseSpread(norm, maxSV, log)
	if err != nil {
		return nil, err
	}
	return &fseTable{log: log, sym: sym, nbits: nbits, next: next}, nil
}

func buildSeqTable(norm []int16, maxSV int, log uint8, base []uint32, extra []uint8) (*seqTable, error) {
	sym, nbits, next, err := fseSpread(norm, maxSV, log)
	if err != nil {
		return nil, err
	}
	t := &seqTable{
		log:   log,
		base:  make([]uint32, len(sym)),
		extra: make([]uint8, len(sym)),
		nbits: nbits,
		next:  next,
	}
	for i, s := range sym {
		if int(s) >= len(base) || int(s) >= len(extra) {
			return nil, errf("symbol %d has no baseline in this code table", s)
		}
		t.base[i] = base[s]
		t.extra[i] = extra[s]
	}
	return t, nil
}

// buildSeqRLE makes the degenerate one-slot table used when a section says
// every sequence shares the same code.
func buildSeqRLE(symbol uint8, base []uint32, extra []uint8) (*seqTable, error) {
	if int(symbol) >= len(base) || int(symbol) >= len(extra) {
		return nil, errf("single-code section names symbol %d, which is out of range", symbol)
	}
	return &seqTable{
		log:   0,
		base:  []uint32{base[symbol]},
		extra: []uint8{extra[symbol]},
		nbits: []uint8{0},
		next:  []uint16{0},
	}, nil
}

// fseDecompress runs a plain FSE stream. zstd uses this in exactly one place:
// the Huffman weight table, when the weights are themselves entropy coded.
// The output length is not stored anywhere; the stream ends when the bit
// reader runs past its start, so the two interleaved states must be stepped in
// the same order the encoder used.
func fseDecompress(src []byte, maxOut int, maxLog uint8) ([]uint8, error) {
	norm, sv, log, used, err := readNCount(src, 255, maxLog)
	if err != nil {
		return nil, err
	}
	t, err := buildFSETable(norm, sv, log)
	if err != nil {
		return nil, err
	}
	if used >= len(src) {
		return nil, trunc("weight stream has a header but no body")
	}
	br, err := newBitReader(src[used:])
	if err != nil {
		return nil, err
	}
	size := len(t.sym)
	s1 := int(br.read(log))
	s2 := int(br.read(log))

	out := make([]uint8, 0, maxOut)
	// Each iteration consumes at least one bit per state, so the bit count
	// bounds the loop; the counter is belt and braces against a table whose
	// slots could ask for zero bits.
	guard := 4*maxOut + 64
	for {
		guard--
		if guard <= 0 {
			return nil, errf("weight stream does not terminate")
		}
		if len(out) > maxOut-2 {
			return nil, errf("weight stream describes more than %d symbols", maxOut)
		}
		if s1 >= size || s2 >= size {
			return nil, errf("FSE state left the table")
		}
		out = append(out, t.sym[s1])
		s1 = int(t.next[s1]) + int(br.read(t.nbits[s1]))
		if br.overrun() {
			if s2 >= size {
				return nil, errf("FSE state left the table")
			}
			out = append(out, t.sym[s2])
			break
		}
		out = append(out, t.sym[s2])
		s2 = int(t.next[s2]) + int(br.read(t.nbits[s2]))
		if br.overrun() {
			if s1 >= size {
				return nil, errf("FSE state left the table")
			}
			out = append(out, t.sym[s1])
			break
		}
	}
	return out, nil
}
