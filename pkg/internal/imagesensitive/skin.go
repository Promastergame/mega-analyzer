package imagesensitive

import (
	"image"
	"image/color"
	"math"
)

// SkinFraction returns the proportion of pixels that fall into the
// HSV skin window defined in plan.md §6. Always returns a value in
// [0, 1]. Operates on the already-resized thumbnail.
func SkinFraction(img image.Image) float64 {
	if img == nil {
		return 0
	}
	bounds := img.Bounds()
	total := bounds.Dx() * bounds.Dy()
	if total == 0 {
		return 0
	}
	hits := 0
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := img.At(x, y)
			if isSkinPixel(c) {
				hits++
			}
		}
	}
	return float64(hits) / float64(total)
}

// DominantSkinDominance returns a soft signal based on the overall skin
// fraction rather than a binary average-colour check. This avoids false
// positives on solid beige/tan images.
func DominantSkinDominance(img image.Image) float64 {
	if img == nil {
		return 0
	}
	frac := SkinFraction(img)
	switch {
	case frac >= 0.75:
		return 1
	case frac >= 0.50:
		return 0.6
	case frac >= 0.30:
		return 0.3
	default:
		return 0
	}
}

// ColorVariance returns a simple normalised variance of pixel luminance.
// Values near 0 indicate a nearly solid-colour image. Used to suppress
// false positives on uniform skin-toned fills.
func ColorVariance(img image.Image) float64 {
	if img == nil {
		return 0
	}
	bounds := img.Bounds()
	total := bounds.Dx() * bounds.Dy()
	if total == 0 {
		return 0
	}

	var sum, sumSq float64
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			// Luminance in [0, 1].
			lum := (0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)) / 65535.0
			sum += lum
			sumSq += lum * lum
		}
	}
	n := float64(total)
	mean := sum / n
	variance := sumSq/n - mean*mean
	if variance < 0 {
		variance = 0
	}
	return variance
}

// isSkinPixel applies BOTH the HSV and YCbCr filters described in plan.md.
// A pixel is "skin" only when it satisfies both colour spaces.
func isSkinPixel(c color.Color) bool {
	r, g, b, _ := c.RGBA()
	r8, g8, b8 := uint8(r>>8), uint8(g>>8), uint8(b>>8)
	if !skinHSV(r8, g8, b8) {
		return false
	}
	return skinYCbCr(r8, g8, b8)
}

func skinHSV(r, g, b uint8) bool {
	h, s, v := rgbToHSV(r, g, b)
	return h >= 0 && h <= 50 &&
		s >= 0.23 && s <= 0.68 &&
		v >= 0.35 && v <= 1.0
}

func skinYCbCr(r, g, b uint8) bool {
	rf := float64(r)
	gf := float64(g)
	bf := float64(b)
	cb := 128 + (-37.79*rf-74.20*gf+112.0*bf)/256
	cr := 128 + (112.0*rf-93.79*gf-18.21*bf)/256
	return cb >= 77 && cb <= 127 && cr >= 133 && cr <= 173
}

// rgbToHSV converts to HSV with Hue in [0, 360), Sat/Val in [0, 1].
func rgbToHSV(r, g, b uint8) (float64, float64, float64) {
	rf := float64(r) / 255
	gf := float64(g) / 255
	bf := float64(b) / 255
	maxc := math.Max(rf, math.Max(gf, bf))
	minc := math.Min(rf, math.Min(gf, bf))
	delta := maxc - minc

	var h float64
	switch {
	case delta == 0:
		h = 0
	case maxc == rf:
		h = 60 * modF((gf-bf)/delta, 6)
	case maxc == gf:
		h = 60 * (((bf - rf) / delta) + 2)
	default:
		h = 60 * (((rf - gf) / delta) + 4)
	}
	if h < 0 {
		h += 360
	}
	var s float64
	if maxc != 0 {
		s = delta / maxc
	}
	return h, s, maxc
}

// modF is a float64 modulo that always returns a non-negative result.
func modF(a, b float64) float64 {
	r := math.Mod(a, b)
	if r < 0 {
		r += b
	}
	return r
}
