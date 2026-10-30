package media

// ─── JPEG quantized DCT coefficient extraction ───────────────────────────────
//
// Steganalysis of JPEG (JSteg/JPHide-style LSB embedding) operates on the
// *quantized* DCT coefficients, not on pixels. Go's image/jpeg decodes straight
// to pixels and never exposes coefficients, so recovering them requires
// re-implementing the entropy-decoding half of a JPEG decoder: parse the frame
// header for component sampling factors, parse the Huffman tables, then
// Huffman-decode the scan data block by block.
//
// Scope is deliberately baseline/extended sequential (SOF0/SOF1) with Huffman
// coding — that covers essentially every JPEG a stego tool produces, because
// JSteg-family embedding targets baseline files. Progressive (SOF2), lossless
// and arithmetic-coded frames are reported as unsupported so the caller can
// fall back to a coarser heuristic rather than acting on garbage coefficients.
//
// Only the first scan is decoded. For baseline that is the whole image, and for
// anything else a single scan already yields a large enough coefficient
// population for a histogram test.

const (
	// jpegACHistOffset shifts signed coefficients into array indices.
	// Baseline 8-bit JPEG magnitude categories top out at 11 bits, so
	// quantized coefficients stay within ±2047.
	jpegACHistOffset = 2048
	jpegACHistSize   = 2 * jpegACHistOffset

	// jpegMaxBlocks caps decoding work on hostile or very large inputs.
	// 250k blocks is roughly a 4000x4000 luma plane — far more than any
	// histogram test needs for statistical power.
	jpegMaxBlocks = 250_000
)

// jpegACHistogram is a histogram of quantized AC coefficient values.
// DC coefficients are excluded: they are DPCM-coded across blocks and their
// distribution is dominated by image content, which would swamp the test.
type jpegACHistogram struct {
	counts [jpegACHistSize]int32
	total  int64
	blocks int
}

// at returns the number of AC coefficients that had value v.
func (h *jpegACHistogram) at(v int) int32 {
	i := v + jpegACHistOffset
	if i < 0 || i >= jpegACHistSize {
		return 0
	}
	return h.counts[i]
}

func (h *jpegACHistogram) add(v int) {
	i := v + jpegACHistOffset
	if i < 0 || i >= jpegACHistSize {
		return
	}
	h.counts[i]++
	h.total++
}

// jpegHuffTable is a canonical Huffman table in the min/max-code form used by
// the JPEG spec's DECODE procedure (ITU T.81 Annex F, figure F.16).
type jpegHuffTable struct {
	minCode [17]int32
	maxCode [17]int32 // -1 means "no codes of this length"
	valPtr  [17]int32
	vals    []byte
	valid   bool
}

func (t *jpegHuffTable) build(counts []byte, vals []byte) bool {
	if len(counts) != 16 {
		return false
	}
	var total int32
	for _, c := range counts {
		total += int32(c)
	}
	if total == 0 || int(total) > len(vals) {
		return false
	}
	t.vals = vals[:total]
	var code, k int32
	for l := 1; l <= 16; l++ {
		n := int32(counts[l-1])
		if n == 0 {
			t.maxCode[l] = -1
			code <<= 1
			continue
		}
		t.valPtr[l] = k
		t.minCode[l] = code
		code += n
		k += n
		t.maxCode[l] = code - 1
		code <<= 1
	}
	t.valid = true
	return true
}

// jpegBitReader reads MSB-first bits out of entropy-coded scan data, undoing
// the two things that make JPEG scan data not a plain bit stream: 0xFF 0x00
// byte stuffing (the escape for a literal 0xFF), and markers, which terminate
// the readable stream rather than being consumed as data.
type jpegBitReader struct {
	data   []byte
	pos    int
	bitBuf uint32
	bitCnt uint
}

func (br *jpegBitReader) fill() bool {
	if br.pos >= len(br.data) {
		return false
	}
	b := br.data[br.pos]
	br.pos++
	if b == 0xFF {
		if br.pos >= len(br.data) {
			return false
		}
		if br.data[br.pos] == 0x00 {
			br.pos++ // stuffed literal 0xFF
		} else {
			// A real marker. Rewind so restart() can inspect it and report
			// end-of-stream to the entropy decoder.
			br.pos--
			return false
		}
	}
	br.bitBuf = uint32(b)
	br.bitCnt = 8
	return true
}

func (br *jpegBitReader) readBit() (uint32, bool) {
	if br.bitCnt == 0 && !br.fill() {
		return 0, false
	}
	br.bitCnt--
	return (br.bitBuf >> br.bitCnt) & 1, true
}

// receive reads s bits as an unsigned value (T.81 F.2.2.4).
func (br *jpegBitReader) receive(s byte) (int32, bool) {
	var v int32
	for i := byte(0); i < s; i++ {
		bit, ok := br.readBit()
		if !ok {
			return 0, false
		}
		v = v<<1 | int32(bit)
	}
	return v, true
}

// restart byte-aligns the reader and consumes an RSTn marker. Returns false if
// the next marker is not a restart marker, i.e. the scan has ended.
func (br *jpegBitReader) restart() bool {
	br.bitCnt = 0
	for br.pos+1 < len(br.data) {
		if br.data[br.pos] != 0xFF {
			br.pos++
			continue
		}
		m := br.data[br.pos+1]
		if m >= 0xD0 && m <= 0xD7 {
			br.pos += 2
			return true
		}
		return false
	}
	return false
}

// extend converts an s-bit magnitude into its signed value (T.81 F.2.2.1).
func jpegExtend(v int32, s byte) int32 {
	if s == 0 {
		return 0
	}
	if v < 1<<(s-1) {
		return v - (1 << s) + 1
	}
	return v
}

type jpegComponent struct {
	id   byte
	h, v int
	dcTb int
	acTb int
	pred int32
}

// extractJPEGACHistogram Huffman-decodes the first scan of a baseline JPEG and
// returns the histogram of its quantized AC coefficients.
//
// ok is false when the file is not a Huffman-coded sequential JPEG, is
// truncated, or is malformed. A partial decode that still produced a usable
// number of blocks is reported as ok — stego tests only need a population, not
// a complete image.
func extractJPEGACHistogram(data []byte) (*jpegACHistogram, bool) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, false
	}

	var (
		dcTables      [4]jpegHuffTable
		acTables      [4]jpegHuffTable
		comps         []jpegComponent
		width, height int
		restartI      int
		sosFound      bool
		scanPos       int
		scanComp      []int // indices into comps, in scan order
	)

	pos := 2
	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			return nil, false
		}
		// Skip JPEG fill bytes (a run of 0xFF before the marker code).
		for pos+1 < len(data) && data[pos+1] == 0xFF {
			pos++
		}
		if pos+1 >= len(data) {
			return nil, false
		}
		marker := data[pos+1]

		// Standalone markers carry no length field.
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			pos += 2
			continue
		}
		if marker == 0xD9 { // EOI before any scan
			return nil, false
		}
		if pos+4 > len(data) {
			return nil, false
		}
		segLen := int(data[pos+2])<<8 | int(data[pos+3])
		if segLen < 2 || pos+2+segLen > len(data) {
			return nil, false
		}
		seg := data[pos+4 : pos+2+segLen]

		switch marker {
		case 0xC0, 0xC1: // SOF0 baseline, SOF1 extended sequential
			if len(seg) < 6 {
				return nil, false
			}
			height = int(seg[1])<<8 | int(seg[2])
			width = int(seg[3])<<8 | int(seg[4])
			nf := int(seg[5])
			if nf < 1 || nf > 4 || len(seg) < 6+3*nf {
				return nil, false
			}
			comps = make([]jpegComponent, nf)
			for i := 0; i < nf; i++ {
				b := seg[6+3*i:]
				hv := b[1]
				comps[i] = jpegComponent{
					id: b[0],
					h:  int(hv >> 4),
					v:  int(hv & 0x0F),
				}
				if comps[i].h < 1 || comps[i].h > 4 || comps[i].v < 1 || comps[i].v > 4 {
					return nil, false
				}
			}

		case 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF:
			// Progressive, lossless, differential or arithmetic-coded frame —
			// out of scope for this decoder.
			return nil, false

		case 0xC4: // DHT — one segment may define several tables
			p := 0
			for p+17 <= len(seg) {
				tc := seg[p] >> 4
				th := seg[p] & 0x0F
				if tc > 1 || th > 3 {
					return nil, false
				}
				counts := seg[p+1 : p+17]
				var n int
				for _, c := range counts {
					n += int(c)
				}
				if p+17+n > len(seg) {
					return nil, false
				}
				vals := seg[p+17 : p+17+n]
				var t *jpegHuffTable
				if tc == 0 {
					t = &dcTables[th]
				} else {
					t = &acTables[th]
				}
				if !t.build(counts, vals) {
					return nil, false
				}
				p += 17 + n
			}

		case 0xDD: // DRI
			if len(seg) < 2 {
				return nil, false
			}
			restartI = int(seg[0])<<8 | int(seg[1])

		case 0xDA: // SOS
			if len(comps) == 0 || len(seg) < 1 {
				return nil, false
			}
			ns := int(seg[0])
			if ns < 1 || ns > len(comps) || len(seg) < 1+2*ns+3 {
				return nil, false
			}
			scanComp = make([]int, 0, ns)
			for i := 0; i < ns; i++ {
				cs := seg[1+2*i]
				tds := seg[2+2*i]
				idx := -1
				for j := range comps {
					if comps[j].id == cs {
						idx = j
						break
					}
				}
				if idx < 0 {
					return nil, false
				}
				comps[idx].dcTb = int(tds >> 4)
				comps[idx].acTb = int(tds & 0x0F)
				if comps[idx].dcTb > 3 || comps[idx].acTb > 3 {
					return nil, false
				}
				scanComp = append(scanComp, idx)
			}
			scanPos = pos + 2 + segLen
			sosFound = true

		default:
			// APPn, COM, DQT, and anything else irrelevant here.
		}

		if sosFound {
			break
		}
		pos += 2 + segLen
	}

	if !sosFound || scanPos >= len(data) {
		return nil, false
	}
	for _, ci := range scanComp {
		if !dcTables[comps[ci].dcTb].valid || !acTables[comps[ci].acTb].valid {
			return nil, false
		}
	}

	// Frame geometry, captured from the SOF segment above.
	if width <= 0 || height <= 0 {
		return nil, false
	}

	hmax, vmax := 1, 1
	for _, c := range comps {
		if c.h > hmax {
			hmax = c.h
		}
		if c.v > vmax {
			vmax = c.v
		}
	}

	hist := &jpegACHistogram{}
	br := &jpegBitReader{data: data[scanPos:]}

	decodeBlock := func(c *jpegComponent) bool {
		dcT := &dcTables[c.dcTb]
		acT := &acTables[c.acTb]

		s, ok := jpegDecodeHuff(br, dcT)
		if !ok {
			return false
		}
		if s > 16 {
			return false
		}
		diff, ok := br.receive(s)
		if !ok {
			return false
		}
		c.pred += jpegExtend(diff, s)
		// DC deliberately not recorded — see jpegACHistogram doc.

		for k := 1; k < 64; {
			rs, ok := jpegDecodeHuff(br, acT)
			if !ok {
				return false
			}
			r := int(rs >> 4)
			sz := rs & 0x0F
			if sz == 0 {
				if r == 15 { // ZRL: sixteen zero coefficients
					k += 16
					continue
				}
				break // EOB
			}
			k += r
			if k > 63 {
				return false
			}
			if sz > 16 {
				return false
			}
			v, ok := br.receive(sz)
			if !ok {
				return false
			}
			hist.add(int(jpegExtend(v, sz)))
			k++
		}
		hist.blocks++
		return true
	}

	if len(scanComp) == 1 {
		// Non-interleaved scan: MCU == one block of that component.
		c := &comps[scanComp[0]]
		compW := ceilDiv(width*c.h, hmax)
		compH := ceilDiv(height*c.v, vmax)
		nx := ceilDiv(compW, 8)
		ny := ceilDiv(compH, 8)
		total := nx * ny
		for i := 0; i < total; i++ {
			if hist.blocks >= jpegMaxBlocks {
				break
			}
			if restartI > 0 && i > 0 && i%restartI == 0 {
				if !br.restart() {
					break
				}
				c.pred = 0
			}
			if !decodeBlock(c) {
				break
			}
		}
	} else {
		mcusX := ceilDiv(width, 8*hmax)
		mcusY := ceilDiv(height, 8*vmax)
		total := mcusX * mcusY
	mcuLoop:
		for m := 0; m < total; m++ {
			if hist.blocks >= jpegMaxBlocks {
				break
			}
			if restartI > 0 && m > 0 && m%restartI == 0 {
				if !br.restart() {
					break
				}
				for _, ci := range scanComp {
					comps[ci].pred = 0
				}
			}
			for _, ci := range scanComp {
				c := &comps[ci]
				for by := 0; by < c.v; by++ {
					for bx := 0; bx < c.h; bx++ {
						if !decodeBlock(c) {
							break mcuLoop
						}
					}
				}
			}
		}
	}

	// A truncated decode is still usable as long as it produced a real
	// population of coefficients; a decode that fell over immediately is not.
	if hist.blocks < 4 || hist.total == 0 {
		return nil, false
	}
	return hist, true
}

// jpegDecodeHuff implements the T.81 DECODE procedure.
func jpegDecodeHuff(br *jpegBitReader, t *jpegHuffTable) (byte, bool) {
	if !t.valid {
		return 0, false
	}
	var code int32
	for l := 1; l <= 16; l++ {
		bit, ok := br.readBit()
		if !ok {
			return 0, false
		}
		code = code<<1 | int32(bit)
		if t.maxCode[l] >= 0 && code <= t.maxCode[l] {
			idx := t.valPtr[l] + code - t.minCode[l]
			if idx < 0 || int(idx) >= len(t.vals) {
				return 0, false
			}
			return t.vals[idx], true
		}
	}
	return 0, false
}

// jpegFrameDimensions reads width/height from the first sequential SOF.
// Kept separate from extractJPEGACHistogram so callers that only need the
// frame size do not pay for a full entropy decode.
//
// This is stricter than findJPEGDimensions in exif.go, which accepts any SOFn
// including progressive and arithmetic-coded frames. Coefficient extraction
// only supports SOF0/SOF1, so it needs a check that rejects the rest.
func jpegFrameDimensions(data []byte) (width, height int, ok bool) {
	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		return 0, 0, false
	}
	pos := 2
	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			return 0, 0, false
		}
		for pos+1 < len(data) && data[pos+1] == 0xFF {
			pos++
		}
		if pos+1 >= len(data) {
			return 0, 0, false
		}
		marker := data[pos+1]
		if marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7) {
			pos += 2
			continue
		}
		if marker == 0xD9 || marker == 0xDA {
			return 0, 0, false
		}
		if pos+4 > len(data) {
			return 0, 0, false
		}
		segLen := int(data[pos+2])<<8 | int(data[pos+3])
		if segLen < 2 || pos+2+segLen > len(data) {
			return 0, 0, false
		}
		if marker == 0xC0 || marker == 0xC1 {
			seg := data[pos+4 : pos+2+segLen]
			if len(seg) < 5 {
				return 0, 0, false
			}
			height = int(seg[1])<<8 | int(seg[2])
			width = int(seg[3])<<8 | int(seg[4])
			return width, height, true
		}
		pos += 2 + segLen
	}
	return 0, 0, false
}

func ceilDiv(a, b int) int {
	if b <= 0 {
		return 0
	}
	return (a + b - 1) / b
}
