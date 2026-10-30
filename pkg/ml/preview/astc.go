package preview

import (
	"fmt"
	"image"

	"mega-analyzer/pkg/ml/astc"
)

// ── ASTC previews ───────────────────────────────────────────────────
//
// ASTC arrives in three shapes and they need different handling:
//
//   a .astc or KTX2 file  carries its own dimensions, so it joins the ordinary
//                         decode chain and Render works on it unchanged.
//   a bare block payload  carries nothing, so the caller supplies an ASTCSpec.
//   an unlabelled payload from an inflated archive, where the layout has to be
//                         worked out from the block modes themselves.
//
// Only the first goes into the automatic chain. Inference is powerful but it
// is still inference, and a byte map that admits what it is beats a texture
// that quietly invents an aspect ratio.

// ASTCSpec says how to read a bare ASTC payload.
type ASTCSpec struct {
	Width       int
	Height      int
	BlockWidth  int
	BlockHeight int
	// SRGB selects the sRGB endpoint expansion. Getting this wrong shifts
	// the midtones; it does not corrupt the image.
	SRGB bool
}

func (s ASTCSpec) footprint() astc.Footprint {
	return astc.Footprint{Width: s.BlockWidth, Height: s.BlockHeight}
}

// Complete reports whether the spec has everything a decode needs.
func (s ASTCSpec) Complete() bool {
	return s.Width > 0 && s.Height > 0 &&
		astc.ValidFootprint(s.BlockWidth, s.BlockHeight)
}

// String describes the spec for a note or a log line.
func (s ASTCSpec) String() string {
	kind := "linear"
	if s.SRGB {
		kind = "sRGB"
	}
	return fmt.Sprintf("%dx%d in %dx%d blocks, %s",
		s.Width, s.Height, s.BlockWidth, s.BlockHeight, kind)
}

// astcImage converts a decoded ASTC surface into a standard image.
//
// The pixel buffers have the same layout - tightly packed RGBA rows - so this
// is a copy rather than a conversion.
func astcImage(im *astc.Image) (*image.RGBA, error) {
	if im == nil || im.Width <= 0 || im.Height <= 0 {
		return nil, ErrBadHeader
	}
	if im.Width > maxSide || im.Height > maxSide {
		return nil, ErrUnsupported
	}
	if im.Width*im.Height > maxPixels {
		return nil, ErrUnsupported
	}
	out := image.NewRGBA(image.Rect(0, 0, im.Width, im.Height))
	if len(im.Pix) < len(out.Pix) {
		return nil, ErrTruncated
	}
	copy(out.Pix, im.Pix)
	return out, nil
}

// CanDecodeASTC reports whether data is a self-describing ASTC container.
//
// Bare block payloads deliberately do not count: recognising those takes a
// pass over the block modes and belongs to an explicit call, not to a cheap
// signature test.
func CanDecodeASTC(data []byte) bool {
	if astc.IsFile(data) {
		return len(data) > astc.FileHeaderSize
	}
	if astc.IsKTX2(data) {
		k, err := astc.ParseKTX2(data)
		return err == nil && k.IsASTC
	}
	return false
}

// DecodeASTCContainer decodes a .astc file or an uncompressed KTX2 level 0.
//
// A supercompressed KTX2 level is rejected with a message naming the scheme
// rather than silently producing noise; inflating it is the caller's job,
// because this package has no business pulling in a compression library.
func DecodeASTCContainer(data []byte) (image.Image, string, error) {
	switch {
	case astc.IsFile(data):
		im, _, err := astc.DecodeFile(data, false)
		if err != nil {
			return nil, "", err
		}
		img, err := astcImage(im)
		if err != nil {
			return nil, "", err
		}
		return img, "astc", nil

	case astc.IsKTX2(data):
		k, err := astc.ParseKTX2(data)
		if err != nil {
			return nil, "", err
		}
		if !k.IsASTC {
			return nil, "", ErrWrongFormat
		}
		if len(k.Levels) == 0 {
			return nil, "", ErrTruncated
		}
		if k.SupercompressionScheme != astc.SupercompressionNone {
			return nil, "", fmt.Errorf(
				"%w: KTX2 level 0 is %s-compressed and must be inflated first",
				ErrUnsupported, k.SupercompressionName())
		}
		l := k.Levels[0]
		if l.Offset+l.Length > len(data) {
			return nil, "", ErrTruncated
		}
		im, _, err := astc.DecodeKTX2Level(k, 0, data[l.Offset:l.Offset+l.Length])
		if err != nil {
			return nil, "", err
		}
		img, err := astcImage(im)
		if err != nil {
			return nil, "", err
		}
		return img, "astc", nil
	}
	return nil, "", ErrWrongFormat
}

// DecodeASTCBlocks decodes a bare payload with dimensions the caller knows.
func DecodeASTCBlocks(data []byte, spec ASTCSpec) (image.Image, error) {
	if !spec.Complete() {
		return nil, fmt.Errorf("%w: incomplete ASTC spec (%s)", ErrBadHeader, spec)
	}
	im, err := astc.Decode(data, spec.Width, spec.Height, spec.footprint(), spec.SRGB)
	if err != nil {
		return nil, err
	}
	return astcImage(im)
}

// specFor describes an inferred layout as a spec.
func specForLayout(l astc.Layout, srgb bool) ASTCSpec {
	return ASTCSpec{
		Width:       l.Width,
		Height:      l.Height,
		BlockWidth:  l.Footprint.Width,
		BlockHeight: l.Footprint.Height,
		SRGB:        srgb,
	}
}

// inferredNote states what was deduced and what went wrong, in that order.
func inferredNote(l astc.Layout, st astc.Stats) string {
	note := l.Note
	if st.Errors > 0 {
		note += fmt.Sprintf("; %d of %d blocks did not decode",
			st.Errors, st.Blocks)
	}
	return note
}

// DecodeASTCInferred works the layout out from the block modes and decodes
// level 0. It returns the spec it settled on so the caller can report it.
func DecodeASTCInferred(data []byte, srgb bool) (image.Image, ASTCSpec, string, error) {
	im, layout, st, err := astc.DecodeInferred(data, srgb)
	if err != nil {
		return nil, ASTCSpec{}, "", err
	}
	img, err := astcImage(im)
	if err != nil {
		return nil, ASTCSpec{}, "", err
	}
	return img, specForLayout(layout, srgb), inferredNote(layout, st), nil
}

// renderImage is the shared tail of every render: downscale, encode, describe.
func renderImage(img image.Image, decoder, note string, opts Options) (Result, error) {
	opts = opts.Normalize()
	src := img.Bounds()
	scaled := scaleTo(img, opts.MaxDim)
	enc, err := encodePNG(scaled)
	if err != nil {
		return Result{}, err
	}
	res := Result{
		PNG:       enc,
		Width:     scaled.Bounds().Dx(),
		Height:    scaled.Bounds().Dy(),
		SrcWidth:  src.Dx(),
		SrcHeight: src.Dy(),
		Decoder:   decoder,
		Note:      note,
	}
	if res.Width != res.SrcWidth || res.Height != res.SrcHeight {
		if res.Note != "" {
			res.Note += "; "
		}
		res.Note += fmt.Sprintf("downscaled from %dx%d", res.SrcWidth, res.SrcHeight)
	}
	return res, nil
}

// RenderASTC renders a bare payload with a known spec.
func RenderASTC(data []byte, spec ASTCSpec, opts Options) (Result, error) {
	img, err := DecodeASTCBlocks(data, spec)
	if err != nil {
		return Result{}, err
	}
	return renderImage(img, "astc", spec.String(), opts)
}

// RenderASTCInferred renders a payload whose layout had to be deduced, and
// hands back what was deduced along with it.
//
// The layout and stats come back with the result because a caller that reports
// on the texture needs both, and running the decode a second time to collect
// them would double the work on the largest payloads in a scan.
//
// The note always says what was assumed. A texture that looks plausible but is
// secretly 128x512 read as 256x256 is worse than one labelled honestly.
func RenderASTCInferred(data []byte, srgb bool, opts Options) (Result, astc.Layout, astc.Stats, error) {
	im, layout, st, err := astc.DecodeInferred(data, srgb)
	if err != nil {
		return Result{}, layout, st, err
	}
	img, err := astcImage(im)
	if err != nil {
		return Result{}, layout, st, err
	}
	res, err := renderImage(img, "astc", inferredNote(layout, st), opts)
	return res, layout, st, err
}
