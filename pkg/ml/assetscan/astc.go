package assetscan

import (
	"fmt"

	"mega-analyzer/pkg/ml/astc"
	"mega-analyzer/pkg/ml/preview"
)

// ── ASTC textures ──────────────────────────────────────────────────
//
// ASTC is the format that used to fall through this scanner completely. In the
// shape that matters most it has no magic number at all: strip the container,
// or pull it out of a zstd frame, and what is left is a bare run of sixteen
// byte blocks with no header, no dimensions and nothing for a signature to
// match. Those payloads all ended up as byte maps carrying a note that a block
// decoder was missing.
//
// pkg/ml/astc closes that gap, and the block modes turn out to carry enough
// structure to identify a payload with no outside help: the largest weight
// grid is a hard lower bound on the footprint, and the total block count of a
// full mip chain is distinctive enough to recognise outright. What genuinely
// cannot be recovered is the aspect ratio of a single level, so that is
// reported as an assumption instead of being presented as a fact.

// astcVerdict phrases what was found for the one-line report entry.
func astcVerdict(l astc.Layout) string {
	if len(l.Mips) > 0 {
		return fmt.Sprintf("ASTC %s, mip pyramid of %d levels from %dx%d",
			l.Footprint, len(l.Mips), l.Width, l.Height)
	}
	return fmt.Sprintf("ASTC %s, %d blocks, %dx%d assumed",
		l.Footprint, l.Blocks, l.Width, l.Height)
}

// astcInfo turns an inferred layout and a decode into the reported block.
//
// When the payload is a pyramid the stats describe level 0 while Blocks counts
// the whole chain, which is the useful pairing: the counts say what the visible
// image is made of, and Blocks says how much more is behind it.
func astcInfo(l astc.Layout, st astc.Stats) *ASTCInfo {
	info := &ASTCInfo{
		Footprint: l.Footprint.String(),
		Width:     l.Width,
		Height:    l.Height,
		Blocks:    l.Blocks,
		MipLevels: len(l.Mips),
		Certain:   l.Certain,
		Note:      l.Note,
	}
	if st.Blocks > 0 {
		info.Illegal = st.Errors
		info.VoidExtent = st.VoidExtent
		info.DualPlane = st.DualPlane
		info.HDR = st.HDR
		return info
	}
	// Nothing was decoded, so report what the block-mode pass counted. It
	// cannot see HDR endpoint modes, which live past the mode field.
	info.Illegal = l.Probe.Reserved + l.Probe.Malformed
	info.VoidExtent = l.Probe.Void
	info.DualPlane = l.Probe.DualPlane
	return info
}

// describeASTC records the block make-up of a self-describing ASTC container.
//
// It returns quietly when the data is not ASTC, so it is safe to call on any
// file that some other signature already claimed. The counts come from a pass
// over the block modes rather than a full decode, because the preview path is
// about to decode the same bytes and doing it twice would be wasteful.
func (s *scanner) describeASTC(it *Item, data []byte) {
	if s.opts.NoASTC {
		return
	}

	var (
		fp   astc.Footprint
		w, h int
		body []byte
	)
	switch {
	case astc.IsFile(data):
		hdr, err := astc.ParseFileHeader(data)
		if err != nil || hdr.DataOffset > len(data) {
			return
		}
		fp, w, h, body = hdr.Footprint, hdr.Width, hdr.Height, data[hdr.DataOffset:]

	case astc.IsKTX2(data):
		k, err := astc.ParseKTX2(data)
		if err != nil || !k.IsASTC || len(k.Levels) == 0 {
			return
		}
		l := k.Levels[0]
		if k.SupercompressionScheme != astc.SupercompressionNone {
			// Worth saying out loud: the texture is ASTC, the wrapper just
			// needs inflating first, and that happens elsewhere.
			it.Notes = append(it.Notes, fmt.Sprintf(
				"KTX2 holds %s ASTC blocks under %s supercompression",
				k.Footprint, k.SupercompressionName()))
			return
		}
		if l.Offset+l.Length > len(data) {
			return
		}
		fp, w, h = k.Footprint, l.Width, l.Height
		body = data[l.Offset : l.Offset+l.Length]

	default:
		return
	}

	p := astc.ProbeBlocks(body)
	if p.Blocks == 0 {
		return
	}
	it.ASTC = &ASTCInfo{
		Footprint:  fp.String(),
		Width:      w,
		Height:     h,
		Blocks:     len(body) / 16,
		Certain:    true,
		Illegal:    p.Reserved + p.Malformed,
		VoidExtent: p.Void,
		DualPlane:  p.DualPlane,
		Note:       p.Summary(),
	}
}

// tryASTC identifies and renders a headerless block payload.
//
// This is the last thing tried before a payload is written off, and it is
// deliberately strict: LooksLikeBlocks demands that nearly every block mode in
// the payload be legal, which random bytes and compressed data never manage.
// Claiming a texture that is not one would be worse than the byte map it
// replaces.
func (s *scanner) tryASTC(it *Item, data []byte, source string) bool {
	if s.opts.NoASTC || !astc.LooksLikeBlocks(data) {
		return false
	}
	l, ok := astc.InferLayout(data)
	if !ok {
		return false
	}

	it.Class = ClassTexture
	it.Format = "astc"
	it.Verdict = astcVerdict(l)
	it.ASTC = astcInfo(l, astc.Stats{})
	it.Notes = append(it.Notes, l.Probe.Summary())

	if s.opts.PreviewDir == "" || s.previews >= s.opts.MaxPreviews {
		return true
	}
	res, layout, st, err := preview.RenderASTCInferred(data, false, preview.Options{
		MaxDim:     s.opts.MaxDim,
		NoFallback: true,
	})
	if err != nil {
		// The identification still stands even when rendering does not.
		it.Notes = append(it.Notes, "ASTC decode failed: "+err.Error())
		return true
	}
	it.ASTC = astcInfo(layout, st)
	s.writePreview(it, res, source, "astc")
	return true
}
