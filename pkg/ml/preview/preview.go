package preview

import (
	"bytes"
	"fmt"
	"image"
	"image/draw"
	_ "image/gif"  // register the GIF decoder for image.Decode
	_ "image/jpeg" // register the JPEG decoder for image.Decode
	"image/png"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PREVIEW - turn any buffer into a PNG somebody can look at
//
// Everything downstream of this package speaks one format, PNG, because that
// is what a browser, a Windows GDI+ call and a Notion page all accept without
// a codec. Render never fails on unrecognised input: if no decoder claims the
// bytes it falls back to a byte map, which is still an honest picture of the
// file. Result.Lossy is the flag that separates "this is the image" from
// "this is a visualisation of bytes".
// ═══════════════════════════════════════════════════════════════════════════════

// Options controls rendering. The zero value is valid and sensible.
type Options struct {
	// MaxDim caps the longest side of the output. 0 means 1024.
	MaxDim int
	// MapWidth forces the byte-map row width. 0 selects automatically.
	MapWidth int
	// MapMaxRows caps byte-map height before sampling kicks in. 0 means 2048.
	MapMaxRows int
	// NoFallback makes Render return an error instead of a byte map when no
	// decoder recognises the input.
	NoFallback bool
}

// Normalize fills defaults. It never mutates the receiver.
func (o Options) Normalize() Options {
	if o.MaxDim <= 0 {
		o.MaxDim = 1024
	}
	if o.MapMaxRows <= 0 {
		o.MapMaxRows = 2048
	}
	return o
}

// Result is one rendered preview.
type Result struct {
	// PNG is the encoded image, ready to write to disk or serve.
	PNG []byte
	// Width and Height describe the PNG, after any downscale.
	Width  int
	Height int
	// SrcWidth and SrcHeight describe the decoded source, before downscale.
	SrcWidth  int
	SrcHeight int
	// Decoder names what produced it: png, jpeg, gif, qoi, bmp, astc or
	// bytemap.
	Decoder string
	// Lossy is true when this is a visualisation rather than the real image.
	Lossy bool
	// Note carries anything the caller should know, such as byte-map sampling.
	Note string
}

// CanDecode reports whether a real decoder claims these bytes. Useful for
// deciding whether a preview is worth writing at all.
func CanDecode(data []byte) bool {
	_, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err == nil {
		return true
	}
	if len(data) >= 4 && string(data[:4]) == "qoif" {
		return true
	}
	if len(data) >= 2 && data[0] == 'B' && data[1] == 'M' {
		return true
	}
	if CanDecodeASTC(data) {
		return true
	}
	return false
}

// decode runs the decoder chain and reports which one won.
func decode(data []byte) (image.Image, string, error) {
	// The standard library first: it is the fastest path and covers the three
	// formats that make up almost every texture actually shipped in an APK.
	if img, format, err := image.Decode(bytes.NewReader(data)); err == nil {
		return img, format, nil
	}
	if img, err := DecodeQOI(data); err == nil {
		return img, "qoi", nil
	}
	if img, err := DecodeBMP(data); err == nil {
		return img, "bmp", nil
	}
	// Block-compressed containers come last. They are the only formats here
	// whose pixels are not stored per pixel at all, and the only ones that
	// need their dimensions from a header rather than an image signature.
	if img, format, err := DecodeASTCContainer(data); err == nil {
		return img, format, nil
	}
	return nil, "", ErrWrongFormat
}

// scaleTo shrinks img so neither side exceeds maxDim, using nearest-neighbour
// sampling. This is a preview, not a resampler: a box filter would look nicer
// on photos but would smear exactly the single-pixel artefacts - alignment
// seams, dead columns, mip boundaries - that make a preview worth inspecting.
func scaleTo(img image.Image, maxDim int) *image.RGBA {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 {
		return image.NewRGBA(image.Rect(0, 0, 1, 1))
	}

	dw, dh := w, h
	if maxDim > 0 && (w > maxDim || h > maxDim) {
		if w >= h {
			dw = maxDim
			dh = h * maxDim / w
		} else {
			dh = maxDim
			dw = w * maxDim / h
		}
		if dw < 1 {
			dw = 1
		}
		if dh < 1 {
			dh = 1
		}
	}

	dst := image.NewRGBA(image.Rect(0, 0, dw, dh))
	if dw == w && dh == h {
		draw.Draw(dst, dst.Bounds(), img, b.Min, draw.Src)
		return dst
	}
	for y := 0; y < dh; y++ {
		sy := b.Min.Y + y*h/dh
		for x := 0; x < dw; x++ {
			sx := b.Min.X + x*w/dw
			dst.Set(x, y, img.At(sx, sy))
		}
	}
	return dst
}

// encodePNG serialises an image.
func encodePNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.DefaultCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Render decodes data and returns it as a PNG.
func Render(data []byte, opts Options) (Result, error) {
	opts = opts.Normalize()

	if img, format, err := decode(data); err == nil {
		src := img.Bounds()
		scaled := scaleTo(img, opts.MaxDim)
		enc, encErr := encodePNG(scaled)
		if encErr != nil {
			return Result{}, encErr
		}
		res := Result{
			PNG:       enc,
			Width:     scaled.Bounds().Dx(),
			Height:    scaled.Bounds().Dy(),
			SrcWidth:  src.Dx(),
			SrcHeight: src.Dy(),
			Decoder:   format,
		}
		if res.Width != res.SrcWidth || res.Height != res.SrcHeight {
			res.Note = fmt.Sprintf("downscaled from %dx%d", res.SrcWidth, res.SrcHeight)
		}
		return res, nil
	}

	if opts.NoFallback {
		return Result{}, ErrWrongFormat
	}

	bm, stride := RenderByteMap(data, opts.MapWidth, opts.MapMaxRows)
	src := bm.Bounds()
	scaled := scaleTo(bm, opts.MaxDim)
	enc, err := encodePNG(scaled)
	if err != nil {
		return Result{}, err
	}

	var note strings.Builder
	note.WriteString("no image decoder matched; showing a byte map")
	if stride > 1 {
		fmt.Fprintf(&note, " (every %dth byte sampled)", stride)
	}
	return Result{
		PNG:       enc,
		Width:     scaled.Bounds().Dx(),
		Height:    scaled.Bounds().Dy(),
		SrcWidth:  src.Dx(),
		SrcHeight: src.Dy(),
		Decoder:   "bytemap",
		Lossy:     true,
		Note:      note.String(),
	}, nil
}
