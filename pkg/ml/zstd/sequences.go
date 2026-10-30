package zstd

// ═══════════════════════════════════════════════════════════════════════════
// Sequences
// ═══════════════════════════════════════════════════════════════════════════
//
// A sequence is "copy N literals, then copy M bytes from D back in the output".
// The three numbers are entropy coded in three interleaved FSE streams sharing
// one reverse bitstream, and the order of every read matters:
//
//	states are initialised    literal length, offset, match length
//	extra bits are read       offset, match length, literal length
//	states are advanced       literal length, match length, offset
//
// Those three orders are all different, and none of them is guessable. They
// are taken from ZSTD_decodeSequence in zstd 1.5.7.
//
// The other subtlety is the repeat-offset window. Three recent distances are
// remembered, small offset codes select one of them instead of coding a
// distance, and a sequence with no literals shifts which one is meant. Getting
// that shift wrong produces plausible-looking output that diverges thousands of
// bytes later, which is why the frame checksum is verified.

const (
	modePredefined = 0
	modeRLE        = 1
	modeFSE        = 2
	modeRepeat     = 3
)

// buildOneSeqTable resolves one of the three code sections. It returns the
// table to use and how many bytes of src the section header consumed.
func buildOneSeqTable(mode uint8, src []byte, prev *seqTable, maxSV int, maxLog uint8,
	base []uint32, extra []uint8, predef *seqTable, what string) (*seqTable, int, error) {

	switch mode {
	case modePredefined:
		if predefErr != nil {
			return nil, 0, predefErr
		}
		return predef, 0, nil

	case modeRLE:
		if len(src) < 1 {
			return nil, 0, trunc("%s section uses a single code but does not give it", what)
		}
		t, err := buildSeqRLE(src[0], base, extra)
		if err != nil {
			return nil, 0, err
		}
		return t, 1, nil

	case modeFSE:
		norm, sv, log, used, err := readNCount(src, maxSV, maxLog)
		if err != nil {
			return nil, 0, errf("%s distribution: %v", what, err)
		}
		t, err := buildSeqTable(norm, sv, log, base, extra)
		if err != nil {
			return nil, 0, errf("%s table: %v", what, err)
		}
		return t, used, nil

	default: // modeRepeat
		if prev == nil {
			return nil, 0, errf("%s section reuses a table, but no table has been sent in this frame", what)
		}
		return prev, 0, nil
	}
}

// extend lengthens b by n bytes, reusing spare capacity when it exists. The
// new region keeps whatever bytes were already there; every caller overwrites
// all of it.
func extend(b []byte, n int) []byte {
	if cap(b)-len(b) >= n {
		return b[:len(b)+n]
	}
	grown := make([]byte, len(b)+n, (len(b)+n)*2)
	copy(grown, b)
	return grown
}

func (d *frameDecoder) decodeSequences(src []byte, literals []byte) error {
	if len(src) < 1 {
		return trunc("sequences section is missing")
	}

	// Sequence count: one byte below 128, two bytes below 32512, three above.
	p := 0
	nbSeq := int(src[p])
	p++
	if nbSeq > 0x7F {
		if nbSeq == 0xFF {
			if p+2 > len(src) {
				return trunc("long sequence count is truncated")
			}
			nbSeq = (int(src[p]) | int(src[p+1])<<8) + longNbSeq
			p += 2
		} else {
			if p+1 > len(src) {
				return trunc("sequence count is truncated")
			}
			nbSeq = ((nbSeq - 0x80) << 8) + int(src[p])
			p++
		}
	}

	if nbSeq == 0 {
		// A block may be literals only. The section must then end immediately;
		// trailing bytes would mean the block length is wrong.
		if p != len(src) {
			return errf("block has no sequences but %d bytes follow the count", len(src)-p)
		}
		d.out = append(d.out, literals...)
		return d.checkLimit()
	}

	if p >= len(src) {
		return trunc("sequence mode byte is missing")
	}
	modes := src[p]
	p++
	if modes&3 != 0 {
		return errf("sequence mode byte has reserved bits set")
	}
	llMode := modes >> 6
	ofMode := (modes >> 4) & 3
	mlMode := (modes >> 2) & 3

	// Table order in the stream is literal length, offset, match length.
	t, used, err := buildOneSeqTable(llMode, src[p:], d.ll, maxLL, llFSELog,
		llBase[:], llBits[:], predefLL, "literal length")
	if err != nil {
		return err
	}
	d.ll = t
	p += used
	if p > len(src) {
		return trunc("literal length table runs past the block")
	}

	t, used, err = buildOneSeqTable(ofMode, src[p:], d.of, maxOff, ofFSELog,
		ofBase[:], ofBits[:], predefOF, "offset")
	if err != nil {
		return err
	}
	d.of = t
	p += used
	if p > len(src) {
		return trunc("offset table runs past the block")
	}

	t, used, err = buildOneSeqTable(mlMode, src[p:], d.ml, maxML, mlFSELog,
		mlBase[:], mlBits[:], predefML, "match length")
	if err != nil {
		return err
	}
	d.ml = t
	p += used
	if p >= len(src) {
		return trunc("sequence bitstream is missing")
	}

	br, err := newBitReader(src[p:])
	if err != nil {
		return err
	}

	tll, tof, tml := d.ll, d.of, d.ml
	sLL := int(br.read(tll.log))
	sOF := int(br.read(tof.log))
	sML := int(br.read(tml.log))

	rep := d.rep
	litPos := 0

	for i := 0; i < nbSeq; i++ {
		if sLL >= len(tll.base) || sOF >= len(tof.base) || sML >= len(tml.base) {
			return errf("sequence %d of %d: an FSE state left its table", i+1, nbSeq)
		}

		mlLen := int(tml.base[sML])
		llLen := int(tll.base[sLL])
		ofBaseVal := tof.base[sOF]
		llExtra := tll.extra[sLL]
		mlExtra := tml.extra[sML]
		ofExtra := tof.extra[sOF]

		var offset uint32
		if ofExtra > 1 {
			// A real distance. It joins the repeat window, pushing the oldest
			// entry out.
			offset = ofBaseVal + br.read(ofExtra)
			rep[2] = rep[1]
			rep[1] = rep[0]
			rep[0] = offset
		} else {
			// A sequence with no literals means "the offset I want is one step
			// further down the list than usual".
			ll0 := 0
			if llLen == 0 {
				ll0 = 1
			}
			if ofExtra == 0 {
				offset = rep[ll0]
				rep[1] = rep[1-ll0]
				rep[0] = offset
			} else {
				idx := int(ofBaseVal) + ll0 + int(br.read(1))
				var pick uint32
				switch {
				case idx == 3:
					// The one genuinely odd case in the format: "the most
					// recent offset, minus one".
					if rep[0] == 0 {
						return errf("sequence %d of %d: repeat offset underflows", i+1, nbSeq)
					}
					pick = rep[0] - 1
				case idx == 1 || idx == 2:
					pick = rep[idx]
				default:
					return errf("sequence %d of %d: repeat offset index %d is impossible", i+1, nbSeq, idx)
				}
				if pick == 0 {
					return errf("sequence %d of %d: repeat offset resolves to zero", i+1, nbSeq)
				}
				if idx != 1 {
					rep[2] = rep[1]
				}
				rep[1] = rep[0]
				rep[0] = pick
				offset = pick
			}
		}

		if mlExtra > 0 {
			mlLen += int(br.read(mlExtra))
		}
		if llExtra > 0 {
			llLen += int(br.read(llExtra))
		}

		// The last sequence does not advance the states, because the encoder
		// never wrote those bits.
		if i != nbSeq-1 {
			nLL, bLL := tll.next[sLL], tll.nbits[sLL]
			nML, bML := tml.next[sML], tml.nbits[sML]
			nOF, bOF := tof.next[sOF], tof.nbits[sOF]
			sLL = int(nLL) + int(br.read(bLL))
			sML = int(nML) + int(br.read(bML))
			sOF = int(nOF) + int(br.read(bOF))
		}

		if litPos+llLen > len(literals) || llLen < 0 {
			return errf("sequence %d of %d: wants %d literals but only %d remain",
				i+1, nbSeq, llLen, len(literals)-litPos)
		}
		d.out = append(d.out, literals[litPos:litPos+llLen]...)
		litPos += llLen

		if offset == 0 {
			return errf("sequence %d of %d: offset is zero", i+1, nbSeq)
		}
		// Compared in uint64 because a 31-bit offset plus its baseline does not
		// fit in a 32-bit signed int, which is what int is on ARM.
		history := len(d.out) - d.frameStart
		if uint64(offset) > uint64(history) {
			return errf("sequence %d of %d: offset %d reaches %d bytes before the frame started",
				i+1, nbSeq, offset, uint64(offset)-uint64(history))
		}
		start := len(d.out) - int(offset)

		if mlLen > 0 {
			// Overlapping copies are normal, not an edge case: offset 1 with a
			// long match is how a run of one byte is coded. The copy has to go
			// forwards one byte at a time, because later bytes of the match are
			// produced by earlier bytes of the same match. A bulk copy would
			// read bytes that have not been written yet.
			base := len(d.out)
			d.out = extend(d.out, mlLen)
			for k := 0; k < mlLen; k++ {
				d.out[base+k] = d.out[start+k]
			}
		}

		if err := d.checkLimit(); err != nil {
			return err
		}
	}

	if br.remaining() > 0 {
		return errf("sequence bitstream has %d bits left unread", br.remaining())
	}
	if br.overrun() {
		return trunc("sequence bitstream ran out of bits")
	}

	d.rep = rep
	d.out = append(d.out, literals[litPos:]...)
	return d.checkLimit()
}
