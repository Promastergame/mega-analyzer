package vision

import (
	"encoding/json"
	"fmt"
	"image"
	"math"
)

// VectorV1 is a quantized, non-spatial descriptor. It stores no pixels.
// 12 RGB histogram bins, RGB mean/std, 8 luminance bins, edge/dark/light/
// saturation, aspect and relative area. Keep in sync with regionVector in collect.html.
type VectorV1 [32]uint8

const VectorVersion = 1

func (v *VectorV1) UnmarshalJSON(data []byte) error {
	var values []uint8
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	if len(values) != len(v) {
		return fmt.Errorf("vector must contain exactly 32 integers in 0..255")
	}
	copy(v[:], values)
	return nil
}

func RegionVector(im image.Image, region image.Rectangle) VectorV1 {
	b := im.Bounds()
	region = region.Intersect(b)
	var out VectorV1
	if region.Empty() {
		return out
	}
	var sums, squares [3]float64
	var bins [20]int
	var previous [32]float64
	var edge, dark, light, sat float64
	for y := 0; y < 32; y++ {
		var left float64
		for x := 0; x < 32; x++ {
			px := region.Min.X + (2*x+1)*region.Dx()/64
			py := region.Min.Y + (2*y+1)*region.Dy()/64
			r, g, bl := rgb(im, px, py)
			channels := [3]float64{r, g, bl}
			for c, v := range channels {
				bin := min(3, int(v*4))
				bins[c*4+bin]++
				sums[c] += v
				squares[c] += v * v
			}
			l := (r + g + bl) / 3
			bins[12+min(7, int(l*8))]++
			if l < .2 {
				dark++
			}
			if l > .8 {
				light++
			}
			mx, mn := math.Max(r, math.Max(g, bl)), math.Min(r, math.Min(g, bl))
			if mx > 0 {
				sat += (mx - mn) / mx
			}
			if x > 0 {
				edge += math.Abs(l - left)
			}
			if y > 0 {
				edge += math.Abs(l - previous[x])
			}
			left, previous[x] = l, l
		}
	}
	q := func(v float64) uint8 { return uint8(math.Round(math.Max(0, math.Min(1, v)) * 255)) }
	for i := 0; i < 12; i++ {
		out[i] = q(float64(bins[i]) / 1024)
	}
	for c := 0; c < 3; c++ {
		mean := sums[c] / 1024
		out[12+c] = q(mean)
		out[15+c] = q(math.Sqrt(math.Max(0, squares[c]/1024-mean*mean)))
	}
	for i := 0; i < 8; i++ {
		out[18+i] = q(float64(bins[12+i]) / 1024)
	}
	out[26] = q(edge / 1984)
	out[27] = q(dark / 1024)
	out[28] = q(light / 1024)
	out[29] = q(sat / 1024)
	out[30] = q(float64(region.Dx()) / float64(region.Dx()+region.Dy()))
	out[31] = q(float64(region.Dx()*region.Dy()) / float64(b.Dx()*b.Dy()))
	return out
}
