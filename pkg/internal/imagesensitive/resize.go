package imagesensitive

import (
	"image"
	"image/color"
)

// thumbSize is the canonical thumbnail edge size. Plan §6 mandates 64×64
// before any per-pixel work to keep RAM bounded.
const thumbSize = 64

// Resize64 returns a 64×64 RGBA image. We use plain nearest-neighbour
// sampling so the implementation is dependency-free; for sensitive
// heuristics the loss in fidelity is irrelevant.
func Resize64(src image.Image) *image.RGBA {
	if src == nil {
		return image.NewRGBA(image.Rect(0, 0, thumbSize, thumbSize))
	}
	bounds := src.Bounds()
	srcW := bounds.Dx()
	srcH := bounds.Dy()
	dst := image.NewRGBA(image.Rect(0, 0, thumbSize, thumbSize))
	if srcW == 0 || srcH == 0 {
		return dst
	}
	for y := 0; y < thumbSize; y++ {
		sy := bounds.Min.Y + (y * srcH / thumbSize)
		for x := 0; x < thumbSize; x++ {
			sx := bounds.Min.X + (x * srcW / thumbSize)
			r, g, b, a := src.At(sx, sy).RGBA()
			dst.Set(x, y, color.RGBA{
				R: uint8(r >> 8),
				G: uint8(g >> 8),
				B: uint8(b >> 8),
				A: uint8(a >> 8),
			})
		}
	}
	return dst
}
