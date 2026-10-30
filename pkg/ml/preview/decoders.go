package preview

import (
	"encoding/binary"
	"errors"
	"image"
	"image/color"
)

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRA RASTER DECODERS
//
// The standard library covers PNG, JPEG and GIF. These two fill the gaps that
// actually show up in shipped game and app assets:
//
//   QOI - increasingly common as a fast lossless texture container, and dead
//         simple to decode correctly.
//   BMP - still the default output of a lot of texture tooling, and the format
//         an ASTC/ETC dump gets converted into.
//
// Both are pure stdlib. Adding golang.org/x/image would pull this repo's first
// dependency for two formats that fit in 150 lines.
// ═══════════════════════════════════════════════════════════════════════════════

var (
	// ErrWrongFormat means the magic did not match; try the next decoder.
	ErrWrongFormat = errors.New("preview: not this format")
	// ErrBadHeader means the magic matched but the header is nonsense.
	ErrBadHeader = errors.New("preview: header is malformed")
	// ErrTruncated means the pixel data ends early.
	ErrTruncated = errors.New("preview: pixel data is truncated")
	// ErrUnsupported means a valid but unhandled variant of the format.
	ErrUnsupported = errors.New("preview: unsupported variant")
)

// Guard rails. A corrupt or hostile header can claim a 65535x65535 image and
// ask this process to allocate 17 GB; refusing is the only correct answer.
const (
	maxSide   = 1 << 17
	maxPixels = 64 << 20
)

// ── QOI ────────────────────────────────────────────────────────────────────

const (
	qoiOpIndex = 0x00
	qoiOpDiff  = 0x40
	qoiOpLuma  = 0x80
	qoiOpRun   = 0xc0
	qoiOpRGB   = 0xfe
	qoiOpRGBA  = 0xff
	qoiMask2   = 0xc0
	qoiHeadLen = 14
)

// qoiHash is the running-index hash from the QOI specification. It is computed
// in int rather than byte purely for clarity: byte arithmetic would wrap at
// 256, and because 64 divides 256 the result is identical either way.
func qoiHash(c color.RGBA) int {
	return (int(c.R)*3 + int(c.G)*5 + int(c.B)*7 + int(c.A)*11) % 64
}

// DecodeQOI decodes a Quite OK Image buffer.
func DecodeQOI(data []byte) (image.Image, error) {
	if len(data) < qoiHeadLen || string(data[:4]) != "qoif" {
		return nil, ErrWrongFormat
	}
	w := int(binary.BigEndian.Uint32(data[4:8]))
	h := int(binary.BigEndian.Uint32(data[8:12]))
	channels := data[12]
	if w <= 0 || h <= 0 || w > maxSide || h > maxSide {
		return nil, ErrBadHeader
	}
	if channels != 3 && channels != 4 {
		return nil, ErrBadHeader
	}
	if w*h > maxPixels {
		return nil, ErrBadHeader
	}

	img := image.NewRGBA(image.Rect(0, 0, w, h))
	var index [64]color.RGBA
	cur := color.RGBA{R: 0, G: 0, B: 0, A: 255}

	p := qoiHeadLen
	run := 0
	total := w * h

	for i := 0; i < total; i++ {
		switch {
		case run > 0:
			run--
		case p < len(data):
			b1 := data[p]
			p++
			switch {
			case b1 == qoiOpRGB:
				if p+3 > len(data) {
					return nil, ErrTruncated
				}
				cur.R, cur.G, cur.B = data[p], data[p+1], data[p+2]
				p += 3
			case b1 == qoiOpRGBA:
				if p+4 > len(data) {
					return nil, ErrTruncated
				}
				cur.R, cur.G, cur.B, cur.A = data[p], data[p+1], data[p+2], data[p+3]
				p += 4
			case b1&qoiMask2 == qoiOpIndex:
				cur = index[b1&0x3f]
			case b1&qoiMask2 == qoiOpDiff:
				// Wrapping byte arithmetic is required by the format, not an
				// accident: the encoder relies on it for values near 0 and 255.
				cur.R += (b1>>4)&0x03 - 2
				cur.G += (b1>>2)&0x03 - 2
				cur.B += b1&0x03 - 2
			case b1&qoiMask2 == qoiOpLuma:
				if p >= len(data) {
					return nil, ErrTruncated
				}
				b2 := data[p]
				p++
				vg := (b1 & 0x3f) - 32
				cur.R += vg - 8 + ((b2 >> 4) & 0x0f)
				cur.G += vg
				cur.B += vg - 8 + (b2 & 0x0f)
			default: // qoiOpRun
				run = int(b1 & 0x3f)
			}
			index[qoiHash(cur)] = cur
		default:
			return nil, ErrTruncated
		}
		img.SetRGBA(i%w, i/w, cur)
	}
	return img, nil
}

// ── BMP ────────────────────────────────────────────────────────────────────

const (
	bmpFileHeadLen = 14
	bmpInfoHeadLen = 40
)

// DecodeBMP decodes an uncompressed Windows bitmap at 8, 24 or 32 bits per
// pixel. RLE and the BITFIELDS variants are rejected rather than guessed at.
func DecodeBMP(data []byte) (image.Image, error) {
	if len(data) < bmpFileHeadLen+bmpInfoHeadLen || data[0] != 'B' || data[1] != 'M' {
		return nil, ErrWrongFormat
	}
	pixOffset := int(binary.LittleEndian.Uint32(data[10:14]))
	headLen := int(binary.LittleEndian.Uint32(data[14:18]))
	if headLen < bmpInfoHeadLen || bmpFileHeadLen+headLen > len(data) {
		return nil, ErrBadHeader
	}

	w := int(int32(binary.LittleEndian.Uint32(data[18:22])))
	rawH := int(int32(binary.LittleEndian.Uint32(data[22:26])))
	bpp := int(binary.LittleEndian.Uint16(data[28:30]))
	compression := binary.LittleEndian.Uint32(data[30:34])

	if compression != 0 {
		return nil, ErrUnsupported
	}
	if bpp != 8 && bpp != 24 && bpp != 32 {
		return nil, ErrUnsupported
	}

	// A negative height means the rows are stored top-down.
	topDown := rawH < 0
	h := rawH
	if topDown {
		h = -h
	}
	if w <= 0 || h <= 0 || w > maxSide || h > maxSide || w*h > maxPixels {
		return nil, ErrBadHeader
	}

	stride := ((w*bpp + 31) / 32) * 4
	if pixOffset < 0 || pixOffset > len(data) {
		return nil, ErrBadHeader
	}
	if uint64(pixOffset)+uint64(stride)*uint64(h) > uint64(len(data)) {
		return nil, ErrTruncated
	}

	// An 8-bit bitmap carries a BGRA palette immediately after the info header.
	var palette [256]color.RGBA
	if bpp == 8 {
		base := bmpFileHeadLen + headLen
		for i := 0; i < 256; i++ {
			p := base + i*4
			if p+4 > len(data) {
				break
			}
			palette[i] = color.RGBA{R: data[p+2], G: data[p+1], B: data[p], A: 255}
		}
	}

	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		srcRow := y
		if !topDown {
			srcRow = h - 1 - y
		}
		row := data[pixOffset+srcRow*stride:]
		for x := 0; x < w; x++ {
			var c color.RGBA
			switch bpp {
			case 8:
				c = palette[row[x]]
			case 24:
				p := x * 3
				c = color.RGBA{R: row[p+2], G: row[p+1], B: row[p], A: 255}
			case 32:
				p := x * 4
				// BI_RGB at 32bpp leaves the fourth byte undefined and most
				// writers leave it zero. Honouring it would render the whole
				// image fully transparent, so it is forced opaque.
				c = color.RGBA{R: row[p+2], G: row[p+1], B: row[p], A: 255}
			}
			img.SetRGBA(x, y, c)
		}
	}
	return img, nil
}
