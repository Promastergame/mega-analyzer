package astc

import "fmt"

// ── One block, start to finish ───────────────────────────────────────────
//
// The layout is unusual and worth stating once. Three things share the 128
// bits and they are addressed from different ends:
//
//   bit 0 upward     block mode, partition count, seed, endpoint modes, then
//                    the colour endpoint stream growing up
//   bit 127 downward the weight stream
//   in between       extra endpoint-mode bits, then the dual-plane component
//                    selector, then whatever is left over as padding
//
// So neither stream has a fixed position: the colour stream's end depends on
// how many bits the weights took, and the weight stream's length depends on a
// grid size and a precision that are themselves packed into eleven bits. The
// order of operations below is therefore not a matter of taste.
//
// Every one of the spec's illegal-encoding conditions is checked, and each one
// paints the whole block magenta and says why in BlockInfo.Err. A decoder that
// silently produced plausible pixels for a malformed block would be worse than
// useless in an analyzer, which exists to tell you when a file is wrong.

func fillColor(out []uint8, n int, c [4]uint8) {
	for i := 0; i < n; i++ {
		out[i*4+0] = c[0]
		out[i*4+1] = c[1]
		out[i*4+2] = c[2]
		out[i*4+3] = c[3]
	}
}

func errBlock(out []uint8, n int, info BlockInfo, msg string) BlockInfo {
	info.Err = msg
	fillColor(out, n, ErrorColor)
	return info
}

// String describes a block the way a report wants to read it.
func (i BlockInfo) String() string {
	if i.Err != "" {
		return "illegal block: " + i.Err
	}
	if i.VoidExtent {
		return "void extent (single colour)"
	}
	s := fmt.Sprintf("%dx%d weight grid, weights 0..%d, colours 0..%d, %d partition",
		i.GridWidth, i.GridHeight, i.WeightRange, i.ColorRange, i.Partitions)
	if i.Partitions != 1 {
		s += "s"
	}
	if i.DualPlane {
		s += fmt.Sprintf(", dual plane on channel %d", i.CCS)
	}
	if i.HDR {
		s += ", HDR partition skipped"
	}
	return s
}

// decodeVoidExtent handles a block that is one flat colour.
//
// The extent coordinates say over what area the colour is constant, which lets
// a hardware sampler skip neighbouring blocks entirely. Decoding ignores them
// apart from the validity check, but the check matters: an inverted extent is
// on the spec's illegal list.
func decodeVoidExtent(b block, n int, out []uint8) BlockInfo {
	info := BlockInfo{VoidExtent: true, Partitions: 1}
	if b.field(10, 2) != 3 {
		return errBlock(out, n, info, "void extent reserved bits are not set")
	}
	if b.field(9, 1) != 0 {
		info.HDR = true
		return errBlock(out, n, info, "HDR void extent cannot be decoded in the LDR profile")
	}
	minS := b.field(12, 13)
	maxS := b.field(25, 13)
	minT := b.field(38, 13)
	maxT := b.field(51, 13)
	allOnes := minS == 0x1FFF && maxS == 0x1FFF && minT == 0x1FFF && maxT == 0x1FFF
	if !allOnes && (minS >= maxS || minT >= maxT) {
		return errBlock(out, n, info, "void extent coordinates are inverted")
	}
	// The colour is UNORM16; the top eight bits are the 8-bit result.
	fillColor(out, n, [4]uint8{
		uint8(b.field(64, 16) >> 8),
		uint8(b.field(80, 16) >> 8),
		uint8(b.field(96, 16) >> 8),
		uint8(b.field(112, 16) >> 8),
	})
	return info
}

// infillWeight interpolates the weight for one texel from the weight grid.
//
// The grid is usually smaller than the footprint, so weights are bilinearly
// resampled. The scale factors are the spec's exact integer expressions, not
// a floating-point equivalent: the two disagree at the rounding boundary and
// only one of them is the format.
func infillWeight(uw []uint32, gw, gh, planes, plane, fw, fh, tx, ty int) uint32 {
	if gw < 2 || gh < 2 || fw < 2 || fh < 2 {
		return 0
	}
	ds := (1024 + fw/2) / (fw - 1)
	dt := (1024 + fh/2) / (fh - 1)
	gs := (ds*tx*(gw-1) + 32) >> 6
	gt := (dt*ty*(gh-1) + 32) >> 6
	js := gs >> 4
	fs := uint32(gs & 0xF)
	jt := gt >> 4
	ft := uint32(gt & 0xF)

	at := func(k int) uint32 {
		if k < 0 {
			return 0
		}
		i := k*planes + plane
		if i >= len(uw) {
			return 0
		}
		return uw[i]
	}

	v0 := js + jt*gw
	// The corner reads can run off the end of the grid, but only when the
	// matching fractional term is zero, so the out-of-range value is always
	// multiplied by nothing. Returning 0 for it keeps that honest.
	p00 := at(v0)
	p01 := at(v0 + 1)
	p10 := at(v0 + gw)
	p11 := at(v0 + gw + 1)

	w11 := (fs*ft + 8) >> 4
	w10 := ft - w11
	w01 := fs - w11
	w00 := 16 - fs - ft + w11
	return (p00*w00 + p01*w01 + p10*w10 + p11*w11 + 8) >> 4
}

// DecodeBlock decodes one 16-byte block into out, which must hold at least
// fp.Texels()*4 bytes of RGBA. It never fails: an illegal block fills out with
// the error colour and reports why through BlockInfo.Err.
func DecodeBlock(raw []byte, fp Footprint, srgb bool, out []uint8) BlockInfo {
	n := fp.Texels()
	info := BlockInfo{Partitions: 1}
	if n <= 0 || len(raw) < blockSize || len(out) < n*4 {
		info.Err = "block or output buffer is too small"
		return info
	}

	b := newBlock(raw)
	m := parseMode(b.field(0, 11))
	if m.voidExtent {
		return decodeVoidExtent(b, n, out)
	}
	if m.reserved {
		return errBlock(out, n, info, "reserved block mode")
	}

	info.GridWidth = m.gw
	info.GridHeight = m.gh
	info.DualPlane = m.dualPlane
	info.WeightRange = m.weightMax

	if m.gw > fp.Width || m.gh > fp.Height {
		return errBlock(out, n, info, fmt.Sprintf(
			"weight grid %dx%d exceeds the %s footprint", m.gw, m.gh, fp))
	}

	nparts := int(b.field(11, 2)) + 1
	info.Partitions = nparts
	if m.dualPlane && nparts == 4 {
		return errBlock(out, n, info, "dual plane with four partitions")
	}

	planes := 1
	if m.dualPlane {
		planes = 2
	}
	nweights := m.gw * m.gh * planes
	if nweights > 64 {
		return errBlock(out, n, info, fmt.Sprintf("%d weights, limit is 64", nweights))
	}
	wspec, ok := specFor(m.weightMax)
	if !ok {
		return errBlock(out, n, info, "unknown weight range")
	}
	weightBits := iseBits(nweights, wspec)
	info.WeightBits = weightBits
	if weightBits > 96 {
		return errBlock(out, n, info, fmt.Sprintf("%d weight bits, limit is 96", weightBits))
	}
	if weightBits < 24 {
		return errBlock(out, n, info, fmt.Sprintf("%d weight bits, minimum is 24", weightBits))
	}

	// Endpoint modes, and with them the position of everything else.
	colorStart := 17
	extraCEM := 0
	var cems [4]int
	if nparts == 1 {
		cems[0] = int(b.field(13, 4))
	} else {
		info.Seed = int(b.field(13, 10))
		colorStart = 29
		sel := int(b.field(23, 2))
		if sel == 0 {
			c := int(b.field(25, 4))
			for p := 0; p < nparts; p++ {
				cems[p] = c
			}
		} else {
			// The mode field spills upward: six bits live at 23, the rest sit
			// directly under the weight stream.
			extraCEM = 3*nparts - 4
			f := b.field(23, 6) | (b.field(128-weightBits-extraCEM, extraCEM) << 6)
			base := sel - 1
			for p := 0; p < nparts; p++ {
				ci := int((f >> uint(2+p)) & 1)
				mi := int((f >> uint(2+nparts+2*p)) & 3)
				cems[p] = ((base + ci) << 2) | mi
			}
		}
	}
	info.CEMs = make([]int, nparts)
	copy(info.CEMs, cems[:nparts])

	ccsBits := 0
	if m.dualPlane {
		ccsBits = 2
		info.CCS = int(b.field(128-weightBits-extraCEM-2, 2))
	}

	nvalues := 0
	for p := 0; p < nparts; p++ {
		nvalues += cemValueCount(cems[p])
	}
	if nvalues > 18 {
		return errBlock(out, n, info, fmt.Sprintf(
			"%d colour endpoint integers, limit is 18", nvalues))
	}

	colorEnd := 128 - weightBits - extraCEM - ccsBits
	remaining := colorEnd - colorStart

	// Pick the finest colour quantization that fits. This also enforces the
	// spec's minimum: if not even range 0..5 fits, the block is illegal.
	colorMax := 0
	var cspec rangeSpec
	for k := len(colorRanges) - 1; k >= 0; k-- {
		s, sok := specFor(colorRanges[k])
		if sok && iseBits(nvalues, s) <= remaining {
			colorMax = colorRanges[k]
			cspec = s
			break
		}
	}
	if colorMax == 0 {
		return errBlock(out, n, info, fmt.Sprintf(
			"%d bits left for %d colour integers, not even range 0..5 fits",
			remaining, nvalues))
	}
	info.ColorRange = colorMax

	// Colour stream: forward from colorStart, bounded by its own packed
	// length so a partial trailing trit block reads zeros rather than
	// borrowing the padding bits above it.
	var cvals [18]uint8
	decodeISE(reader{b: b, start: colorStart,
		limit: colorStart + iseBits(nvalues, cspec)}, nvalues, cspec, cvals[:])

	// Weight stream: the block read backwards, bounded by its exact length.
	var wvals [64]uint8
	decodeISE(reader{b: b.reversed(), start: 0, limit: weightBits},
		nweights, wspec, wvals[:])
	var uw [64]uint32
	for k := 0; k < nweights; k++ {
		uw[k] = unquantWeight(uint32(wvals[k]), m.weightMax)
	}

	var e0, e1 [4][4]uint8
	var hdrPart [4]bool
	vi := 0
	for p := 0; p < nparts; p++ {
		cnt := cemValueCount(cems[p])
		var vbuf [8]uint32
		for k := 0; k < cnt && vi+k < len(cvals); k++ {
			vbuf[k] = unquantColor(uint32(cvals[vi+k]), colorMax)
		}
		vi += cnt
		if isHDRMode(cems[p]) {
			// Not a block-level error: a partitioned block may legally mix
			// HDR and LDR partitions, and only the HDR texels are lost.
			hdrPart[p] = true
			info.HDR = true
			continue
		}
		e0[p], e1[p] = decodeEndpoints(cems[p], vbuf[:cnt])
	}

	small := n < 31
	for ty := 0; ty < fp.Height; ty++ {
		for tx := 0; tx < fp.Width; tx++ {
			p := 0
			if nparts > 1 {
				p = selectPartition(info.Seed, tx, ty, 0, nparts, small)
			}
			o := (ty*fp.Width + tx) * 4
			if hdrPart[p] {
				out[o+0] = ErrorColor[0]
				out[o+1] = ErrorColor[1]
				out[o+2] = ErrorColor[2]
				out[o+3] = ErrorColor[3]
				continue
			}
			w0 := infillWeight(uw[:], m.gw, m.gh, planes, 0, fp.Width, fp.Height, tx, ty)
			w1 := w0
			if planes == 2 {
				w1 = infillWeight(uw[:], m.gw, m.gh, planes, 1, fp.Width, fp.Height, tx, ty)
			}
			for ch := 0; ch < 4; ch++ {
				w := w0
				if planes == 2 && ch == info.CCS {
					w = w1
				}
				out[o+ch] = interpolate(e0[p][ch], e1[p][ch], w, srgb && ch < 3)
			}
		}
	}
	return info
}
