package zstd

import "math/bits"

// ═══════════════════════════════════════════════════════════════════════════
// Huffman literals
// ═══════════════════════════════════════════════════════════════════════════
//
// Literals are coded with a canonical Huffman tree stored as per-symbol
// weights. Weight w means the symbol's code is (tableLog + 1 - w) bits long;
// weight 0 means the symbol is absent. The final symbol's weight is never
// stored: it is whatever is needed to make the weights sum to a power of two,
// which also means a forged table is easy to detect.
//
// Ports HUF_readStats_body and HUF_readDTableX1_wksp. The rescale-for-speed
// step in the C reader is skipped on purpose: it inflates the table to a fixed
// size for cache reasons and does not change a single decoded byte.

type huffTable struct {
	log   uint8
	sym   []uint8
	nbits []uint8
}

func readHuffTable(src []byte) (*huffTable, int, error) {
	if len(src) < 1 {
		return nil, 0, trunc("Huffman table header is missing")
	}
	iSize := int(src[0])
	var weights []uint8
	var consumed int

	if iSize >= 128 {
		// Weights are stored raw, one nibble each.
		oSize := iSize - 127
		n := (oSize + 1) / 2
		if 1+n > len(src) {
			return nil, 0, trunc("Huffman weights run past the section")
		}
		weights = make([]uint8, 0, oSize)
		for i := 0; i < oSize; i += 2 {
			b := src[1+i/2]
			weights = append(weights, b>>4)
			if i+1 < oSize {
				weights = append(weights, b&15)
			}
		}
		consumed = 1 + n
	} else {
		// Weights are themselves FSE coded, with a fixed accuracy cap of 6.
		if 1+iSize > len(src) {
			return nil, 0, trunc("Huffman weight stream runs past the section")
		}
		if iSize == 0 {
			return nil, 0, errf("Huffman weight stream is empty")
		}
		w, err := fseDecompress(src[1:1+iSize], 255, 6)
		if err != nil {
			return nil, 0, err
		}
		weights = w
		consumed = 1 + iSize
	}

	if len(weights) == 0 || len(weights) > 255 {
		return nil, 0, errf("Huffman table describes %d symbols", len(weights))
	}

	var total uint32
	for _, w := range weights {
		if w > hufTableLogMax {
			return nil, 0, errf("Huffman weight %d is out of range", w)
		}
		total += (uint32(1) << uint(w)) >> 1
	}
	if total == 0 {
		return nil, 0, errf("every Huffman weight is zero")
	}
	log := uint8(bits.Len32(total))
	if log > hufTableLogMax {
		return nil, 0, errf("Huffman accuracy log %d is too large", log)
	}
	rest := uint32(1)<<uint(log) - total
	if rest == 0 || rest&(rest-1) != 0 {
		// The implied last weight must be an exact power of two. Anything else
		// means the weights were tampered with or truncated.
		return nil, 0, errf("implied final Huffman weight is not a power of two")
	}
	weights = append(weights, uint8(bits.Len32(rest)))

	rankCount := make([]int, int(log)+2)
	for _, w := range weights {
		if int(w) > int(log) {
			return nil, 0, errf("Huffman weight %d exceeds the accuracy log %d", w, log)
		}
		rankCount[w]++
	}
	if rankCount[1] < 2 || rankCount[1]&1 != 0 {
		// A canonical tree always has an even number of longest codes, at least
		// two of them. This single check rejects most malformed tables.
		return nil, 0, errf("Huffman tree has %d longest codes, which cannot be canonical", rankCount[1])
	}

	// Order the symbols by weight so the table can be filled rank by rank.
	rankStart := make([]int, int(log)+2)
	next := 0
	for w := 0; w <= int(log); w++ {
		rankStart[w] = next
		next += rankCount[w]
	}
	cursor := make([]int, len(rankStart))
	copy(cursor, rankStart)
	sorted := make([]uint8, len(weights))
	for i, w := range weights {
		sorted[cursor[w]] = uint8(i)
		cursor[w]++
	}

	size := 1 << uint(log)
	t := &huffTable{log: log, sym: make([]uint8, size), nbits: make([]uint8, size)}
	u := 0
	symIdx := rankCount[0] // weight-0 symbols are absent from the stream
	for w := 1; w <= int(log); w++ {
		count := rankCount[w]
		run := (1 << uint(w)) >> 1
		nb := uint8(int(log) + 1 - w)
		for s := 0; s < count; s++ {
			if symIdx+s >= len(sorted) {
				return nil, 0, errf("Huffman symbol order is inconsistent")
			}
			cur := sorted[symIdx+s]
			if u+run > size {
				return nil, 0, errf("Huffman table overflows its %d slots", size)
			}
			for k := 0; k < run; k++ {
				t.sym[u] = cur
				t.nbits[u] = nb
				u++
			}
		}
		symIdx += count
	}
	if u != size {
		return nil, 0, errf("Huffman table filled %d of %d slots", u, size)
	}
	return t, consumed, nil
}

// decodeStream fills dst completely from one reverse bitstream.
func (t *huffTable) decodeStream(dst []byte, src []byte) error {
	if len(dst) == 0 {
		return nil
	}
	br, err := newBitReader(src)
	if err != nil {
		return err
	}
	for i := range dst {
		idx := br.peek(t.log)
		if int(idx) >= len(t.sym) {
			return errf("Huffman lookup %d left the table", idx)
		}
		dst[i] = t.sym[idx]
		br.skip(t.nbits[idx])
	}
	if br.overrun() {
		// Running out of bits means the declared literal count and the stream
		// disagree, so every byte after the shortfall would be invented.
		return trunc("literal stream ran out of bits")
	}
	return nil
}

// decompress fills dst, either from a single stream or from the four
// independent streams zstd uses to give a decoder something to interleave.
// The four-stream layout starts with a six byte jump table holding the sizes
// of the first three streams; the fourth gets whatever is left.
func (t *huffTable) decompress(dst []byte, src []byte, four bool) error {
	if !four {
		return t.decodeStream(dst, src)
	}
	if len(src) < 6 {
		return trunc("Huffman jump table is truncated")
	}
	l1 := int(src[0]) | int(src[1])<<8
	l2 := int(src[2]) | int(src[3])<<8
	l3 := int(src[4]) | int(src[5])<<8
	used := 6 + l1 + l2 + l3
	if used > len(src) {
		return errf("Huffman jump table claims more bytes than the section holds")
	}
	l4 := len(src) - used

	// Output is split into four equal parts, the last one short.
	seg := (len(dst) + 3) / 4
	if seg*3 > len(dst) {
		return errf("literal block of %d bytes is too small to be split four ways", len(dst))
	}
	offsets := [4]int{6, 6 + l1, 6 + l1 + l2, used}
	lengths := [4]int{l1, l2, l3, l4}
	sizes := [4]int{seg, seg, seg, len(dst) - 3*seg}

	pos := 0
	for i := 0; i < 4; i++ {
		if lengths[i] == 0 {
			if sizes[i] != 0 {
				return errf("literal stream %d is empty but owes %d bytes", i+1, sizes[i])
			}
			continue
		}
		chunk := src[offsets[i] : offsets[i]+lengths[i]]
		if err := t.decodeStream(dst[pos:pos+sizes[i]], chunk); err != nil {
			return errf("literal stream %d of 4: %v", i+1, err)
		}
		pos += sizes[i]
	}
	return nil
}
