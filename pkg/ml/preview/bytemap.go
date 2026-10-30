package preview

import (
	"image"
	"image/color"
)

// ═══════════════════════════════════════════════════════════════════════════════
// BYTE MAP - the fallback view for data no decoder understands
//
// When a buffer is a compressed texture, an unknown container, or the output
// of a transform that only got us halfway, there is still something useful to
// look at. Painting each byte as one pixel makes structure visible instantly:
//
//   - flat black bands     => zero padding or a sparse table
//   - dense green blocks   => ASCII text, JSON, XML, symbol tables
//   - even amber noise     => compressed or encrypted payload
//   - repeating stripes    => a fixed-width record array or mip chain
//   - a bright leading row => a file header
//
// That is a genuinely different question from "what image is this", and it is
// the question that matters when you are staring at a vendor blob. The result
// is labelled Lossy so it can never be mistaken for a real decode.
// ═══════════════════════════════════════════════════════════════════════════════

// Palette shared with the analyzer UI so the two read as one product.
var (
	mapZero  = color.RGBA{R: 0x12, G: 0x11, B: 0x0f, A: 255} // 0x00 runs
	mapFull  = color.RGBA{R: 0xf0, G: 0xec, B: 0xe4, A: 255} // 0xFF runs
	mapText  = color.RGBA{R: 0x7b, G: 0xa0, B: 0x5b, A: 255} // printable ASCII
	mapCtrl  = color.RGBA{R: 0x4f, G: 0xa8, B: 0xa0, A: 255} // control bytes
	mapHighA = color.RGBA{R: 0x6b, G: 0x45, B: 0x14, A: 255} // high bytes, low end
	mapHighB = color.RGBA{R: 0xe8, G: 0xa9, B: 0x4a, A: 255} // high bytes, top end
)

// lerp8 blends two channel values. t is a 0..255 position.
func lerp8(a, b uint8, t int) uint8 {
	return uint8((int(a)*(255-t) + int(b)*t) / 255)
}

// byteColor maps one byte to a colour that separates the four regimes above.
func byteColor(b byte) color.RGBA {
	switch {
	case b == 0x00:
		return mapZero
	case b == 0xFF:
		return mapFull
	case b >= 0x20 && b <= 0x7E:
		return mapText
	case b < 0x20:
		return mapCtrl
	}
	// 0x7F..0xFE ramp. Spreading the high half across a visible gradient is
	// what makes a mip boundary or an alignment pad pop out of pure noise.
	t := (int(b) - 0x7F) * 255 / (0xFE - 0x7F)
	return color.RGBA{
		R: lerp8(mapHighA.R, mapHighB.R, t),
		G: lerp8(mapHighA.G, mapHighB.G, t),
		B: lerp8(mapHighA.B, mapHighB.B, t),
		A: 255,
	}
}

// mapWidthFor picks a row width. A fixed 256 makes 4-, 8- and 16-byte record
// strides line up into clean vertical bands, which is most of the value; tiny
// buffers get a narrower row so they are not one thin smear.
func mapWidthFor(n int) int {
	switch {
	case n <= 0:
		return 1
	case n < 1024:
		return 32
	case n < 16384:
		return 64
	default:
		return 256
	}
}

// RenderByteMap paints data one byte per pixel.
//
// width <= 0 selects an automatic width. When the buffer would produce more
// than maxRows rows the input is sampled with a fixed stride rather than
// truncated, so the picture still describes the whole file - the returned
// stride tells the caller how much was skipped.
func RenderByteMap(data []byte, width int, maxRows int) (img *image.RGBA, stride int) {
	if width <= 0 {
		width = mapWidthFor(len(data))
	}
	if maxRows <= 0 {
		maxRows = 2048
	}
	if len(data) == 0 {
		blank := image.NewRGBA(image.Rect(0, 0, 1, 1))
		blank.SetRGBA(0, 0, mapZero)
		return blank, 1
	}

	stride = 1
	capacity := width * maxRows
	for len(data)/stride > capacity {
		stride++
	}

	count := (len(data) + stride - 1) / stride
	rows := (count + width - 1) / width
	if rows < 1 {
		rows = 1
	}

	img = image.NewRGBA(image.Rect(0, 0, width, rows))
	// Background first: the final row is usually partial and an unpainted
	// remainder would render as transparent black, reading as a zero run that
	// is not in the file.
	for y := 0; y < rows; y++ {
		for x := 0; x < width; x++ {
			img.SetRGBA(x, y, color.RGBA{R: 0x08, G: 0x08, B: 0x08, A: 255})
		}
	}

	for i := 0; i < count; i++ {
		src := i * stride
		if src >= len(data) {
			break
		}
		img.SetRGBA(i%width, i/width, byteColor(data[src]))
	}
	return img, stride
}
