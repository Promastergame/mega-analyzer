package astc

import "fmt"

// ── Working out what a bare payload is ────────────────────────────────────
//
// Compressed textures pulled out of a game are usually naked: a container was
// stripped, or the blocks were zstd-packed inside a proprietary wrapper, and
// what survives is a byte count. A decoder that demands width, height and
// footprint up front is useless in that situation.
//
// Three facts make the payload speak for itself:
//
//   1. The block mode is the low eleven bits of every block and needs nothing
//      external to parse. Reading it costs one pass and no guessing.
//   2. An encoder never emits a weight grid larger than the footprint. So the
//      largest grid seen across the payload is a hard lower bound on the
//      footprint, and the smallest legal footprint above that bound is the
//      answer - not a guess, a deduction.
//   3. Illegal block modes are common in random bytes and absent from real
//      textures, which makes the same pass a reliable "is this even ASTC"
//      test.
//
// What genuinely cannot be deduced is how the blocks are laid out in a grid:
// 64 blocks is 8x8 or 16x4 or 64x1 and the bits do not say. Mip pyramids are
// the exception, because a full chain has a distinctive total, so those get
// recognised outright.

// Probe is what one pass over the block modes revealed.
type Probe struct {
	Blocks    int
	Valid     int
	Void      int
	Reserved  int
	Malformed int
	GridMaxW  int
	GridMaxH  int
	DualPlane int
	MultiPart int
	// WeightBitsMin and WeightBitsMax bracket the weight stream lengths seen.
	WeightBitsMin int
	WeightBitsMax int
}

// probeSampleStride keeps the pass cheap on large payloads by walking at most
// this many blocks, spread evenly rather than taken from the front - a texture
// often starts with a run of flat blocks that would say nothing.
const probeSampleBlocks = 4096

// ProbeBlocks reads the block mode of every block, or an even sample of them.
func ProbeBlocks(data []byte) Probe {
	var p Probe
	total := len(data) / blockSize
	if total == 0 {
		return p
	}
	step := 1
	if total > probeSampleBlocks {
		step = total / probeSampleBlocks
	}
	p.WeightBitsMin = 1 << 30
	for i := 0; i < total; i += step {
		at := i * blockSize
		b := newBlock(data[at : at+blockSize])
		p.Blocks++
		m := parseMode(b.field(0, 11))
		if m.voidExtent {
			p.Void++
			p.Valid++
			continue
		}
		if m.reserved {
			p.Reserved++
			continue
		}
		nparts := int(b.field(11, 2)) + 1
		planes := 1
		if m.dualPlane {
			planes = 2
		}
		nw := m.gw * m.gh * planes
		spec, ok := specFor(m.weightMax)
		wb := 0
		if ok {
			wb = iseBits(nw, spec)
		}
		if !ok || nw > 64 || wb < 24 || wb > 96 || (m.dualPlane && nparts == 4) {
			p.Malformed++
			continue
		}
		p.Valid++
		if m.gw > p.GridMaxW {
			p.GridMaxW = m.gw
		}
		if m.gh > p.GridMaxH {
			p.GridMaxH = m.gh
		}
		if m.dualPlane {
			p.DualPlane++
		}
		if nparts > 1 {
			p.MultiPart++
		}
		if wb < p.WeightBitsMin {
			p.WeightBitsMin = wb
		}
		if wb > p.WeightBitsMax {
			p.WeightBitsMax = wb
		}
	}
	if p.WeightBitsMin == 1<<30 {
		p.WeightBitsMin = 0
	}
	return p
}

// ValidRate is the fraction of sampled blocks that parse as legal ASTC.
func (p Probe) ValidRate() float64 {
	if p.Blocks == 0 {
		return 0
	}
	return float64(p.Valid) / float64(p.Blocks)
}

// Summary describes the probe for a report.
func (p Probe) Summary() string {
	if p.Blocks == 0 {
		return "no blocks"
	}
	s := fmt.Sprintf("%d blocks sampled, %.1f%% legal", p.Blocks,
		p.ValidRate()*100)
	if p.GridMaxW > 0 {
		s += fmt.Sprintf(", largest weight grid %dx%d", p.GridMaxW, p.GridMaxH)
	}
	if p.Void > 0 {
		s += fmt.Sprintf(", %d flat", p.Void)
	}
	if p.DualPlane > 0 {
		s += fmt.Sprintf(", %d dual plane", p.DualPlane)
	}
	if p.MultiPart > 0 {
		s += fmt.Sprintf(", %d partitioned", p.MultiPart)
	}
	if p.Reserved > 0 || p.Malformed > 0 {
		s += fmt.Sprintf(", %d reserved and %d malformed", p.Reserved, p.Malformed)
	}
	return s
}

// minValidRate is how clean a payload has to look before it is called ASTC.
// Real encoders emit no illegal blocks at all, so this is generous; it exists
// only to tolerate a little trailing padding inside the last sampled block.
const minValidRate = 0.95

// LooksLikeBlocks reports whether a payload plausibly holds ASTC blocks.
//
// The size test alone is worth little - any 16-byte-aligned blob passes it -
// so the block modes have to agree as well.
func LooksLikeBlocks(data []byte) bool {
	if len(data) < blockSize || len(data)%blockSize != 0 {
		return false
	}
	p := ProbeBlocks(data)
	if p.Blocks == 0 || p.GridMaxW == 0 {
		return false
	}
	if p.Reserved*100 > p.Blocks {
		return false
	}
	return p.ValidRate() >= minValidRate
}

// InferFootprint returns the smallest footprint that can hold every weight
// grid the payload uses.
//
// This is a deduction, not a heuristic: a grid may never exceed its footprint,
// so any smaller footprint is impossible. It can still land below the truth
// when a texture happens not to use its full grid, which is why the caller is
// told how much slack there was.
func InferFootprint(data []byte) (Footprint, Probe, bool) {
	p := ProbeBlocks(data)
	if p.Blocks == 0 || p.GridMaxW == 0 || p.ValidRate() < minValidRate {
		return Footprint{}, p, false
	}
	best := Footprint{}
	for _, f := range footprints2D {
		if f.Width < p.GridMaxW || f.Height < p.GridMaxH {
			continue
		}
		if best.Width == 0 || f.Texels() < best.Texels() {
			best = f
		}
	}
	if best.Width == 0 {
		return Footprint{}, p, false
	}
	return best, p, true
}

// MipLevel is one level of an inferred mip pyramid.
type MipLevel struct {
	Offset int
	Length int
	Width  int
	Height int
	Blocks int
}

// Layout is a complete interpretation of a bare payload.
type Layout struct {
	Footprint Footprint
	Width     int
	Height    int
	Blocks    int
	// Mips is populated only when the payload holds a whole pyramid, in
	// which case Width and Height describe level 0.
	Mips  []MipLevel
	Probe Probe
	// Certain is true when the dimensions follow from the data rather than
	// from a preference for square textures.
	Certain bool
	Note    string
}

// mipBlocks is how many blocks a full pyramid down to 1x1 occupies.
func mipBlocks(w, h int, fp Footprint) int {
	total := 0
	for w >= 1 && h >= 1 {
		xb := (w + fp.Width - 1) / fp.Width
		yb := (h + fp.Height - 1) / fp.Height
		total += xb * yb
		if w == 1 && h == 1 {
			break
		}
		if w > 1 {
			w /= 2
		}
		if h > 1 {
			h /= 2
		}
	}
	return total
}

// mipChain builds the level list for a base size.
func mipChain(w, h int, fp Footprint) []MipLevel {
	var out []MipLevel
	off := 0
	for w >= 1 && h >= 1 {
		xb := (w + fp.Width - 1) / fp.Width
		yb := (h + fp.Height - 1) / fp.Height
		n := xb * yb
		out = append(out, MipLevel{
			Offset: off,
			Length: n * blockSize,
			Width:  w,
			Height: h,
			Blocks: n,
		})
		off += n * blockSize
		if w == 1 && h == 1 {
			break
		}
		if w > 1 {
			w /= 2
		}
		if h > 1 {
			h /= 2
		}
	}
	return out
}

// squarish scores an aspect ratio; lower is closer to square.
func squarish(xb, yb int) int {
	if xb > yb {
		return xb / yb
	}
	return yb / xb
}

func isPow2(n int) bool { return n > 0 && n&(n-1) == 0 }

// InferLayout works out how to decode a bare payload.
//
// A single mip level and a full pyramid have different block totals, so the
// pyramid case is tested first and, when it fits, gives exact dimensions. A
// single level only pins the block count, so the most square power-of-two
// arrangement wins and Certain is left false.
func InferLayout(data []byte) (Layout, bool) {
	var l Layout
	if len(data) < blockSize || len(data)%blockSize != 0 {
		return l, false
	}
	fp, p, ok := InferFootprint(data)
	if !ok {
		return l, false
	}
	l.Footprint = fp
	l.Probe = p
	l.Blocks = len(data) / blockSize

	// A whole pyramid: try power-of-two bases and the two common aspect
	// ratios. The total is distinctive enough that a hit is meaningful.
	for side := 1; side <= maxSide; side *= 2 {
		for _, hh := range []int{side, side / 2, side * 2} {
			if hh < 1 || side*hh > maxTexels {
				continue
			}
			if mipBlocks(side, hh, fp) != l.Blocks {
				continue
			}
			// One level alone can coincide with a short pyramid; a
			// pyramid worth reporting has several levels.
			chain := mipChain(side, hh, fp)
			if len(chain) < 3 {
				continue
			}
			l.Width = side
			l.Height = hh
			l.Mips = chain
			l.Certain = true
			l.Note = fmt.Sprintf(
				"%s blocks, mip pyramid of %d levels from %dx%d",
				fp, len(chain), side, hh)
			return l, true
		}
	}

	// A single level. Only the block count is known, so pick the most square
	// factorisation and prefer powers of two, which is what a texture
	// pipeline almost always produces.
	bestXB, bestYB := 0, 0
	for xb := 1; xb*xb <= l.Blocks; xb++ {
		if l.Blocks%xb != 0 {
			continue
		}
		yb := l.Blocks / xb
		for _, cand := range [][2]int{{xb, yb}, {yb, xb}} {
			if bestXB == 0 {
				bestXB, bestYB = cand[0], cand[1]
				continue
			}
			better := false
			cp := isPow2(cand[0]) && isPow2(cand[1])
			bp := isPow2(bestXB) && isPow2(bestYB)
			switch {
			case cp != bp:
				better = cp
			default:
				better = squarish(cand[0], cand[1]) <
					squarish(bestXB, bestYB)
			}
			if better {
				bestXB, bestYB = cand[0], cand[1]
			}
		}
	}
	if bestXB == 0 {
		return l, false
	}
	l.Width = bestXB * fp.Width
	l.Height = bestYB * fp.Height
	l.Note = fmt.Sprintf(
		"%s blocks, %d of them; %dx%d assumed, the block count does not "+
			"pin the aspect ratio", fp, l.Blocks, l.Width, l.Height)
	return l, true
}

// DecodeInferred decodes a bare payload by inferring its layout, returning
// level 0 when the payload turns out to be a pyramid.
func DecodeInferred(data []byte, srgb bool) (*Image, Layout, Stats, error) {
	l, ok := InferLayout(data)
	if !ok {
		return nil, l, Stats{}, fmt.Errorf(
			"%w: the payload does not look like ASTC blocks", ErrMagic)
	}
	payload := data
	if len(l.Mips) > 0 {
		top := l.Mips[0]
		if top.Offset+top.Length <= len(data) {
			payload = data[top.Offset : top.Offset+top.Length]
		}
	}
	im, st, err := DecodeWithStats(payload, l.Width, l.Height, l.Footprint, srgb)
	return im, l, st, err
}
