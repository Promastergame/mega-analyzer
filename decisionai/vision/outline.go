// Обводка: где именно фильтр видит класс.
// ИИ получает числа: класс + прямоугольник в пикселях оригинала.

package vision

import (
	"image"
	"math"
	"sort"
)

// SensitiveBox — один найденный кусок класса.
// Координаты — в пикселях ОРИГИНАЛА (не даунсемпла), чтобы сайт мог обвести.
type SensitiveBox struct {
	Class   string   `json:"class"`
	X       int      `json:"x"`
	Y       int      `json:"y"`
	W       int      `json:"w"`
	H       int      `json:"h"`
	AreaPct float64  `json:"area_pct"`
	Score   int      `json:"score"`
	Vector  VectorV1 `json:"vector"`
	Solid   bool     `json:"solid,omitempty"`
}

const (
	outlineMaxSide   = 256
	outlineMinPixels = 12 // минимум пикселей компоненты на сетке, иначе шум
	outlineMaxBoxes  = 8  // не больше боксов на класс, чтобы JSON был маленьким
)

// sensitiveGrid строит даунсемпл-сетку признаков один раз.
func sensitiveGrid(im image.Image) (feats []sensitiveFeat, bright []float64, w, h, dx, dy int) {
	b := im.Bounds()
	dx, dy = b.Dx(), b.Dy()
	if dx <= 0 || dy <= 0 {
		return nil, nil, 0, 0, 0, 0
	}
	scale := 1.0
	if m := math.Max(float64(dx), float64(dy)); m > outlineMaxSide {
		scale = outlineMaxSide / m
	}
	w = int(math.Round(float64(dx) * scale))
	h = int(math.Round(float64(dy) * scale))
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	if w*h > outlineMaxSide*outlineMaxSide {
		w, h = outlineMaxSide, outlineMaxSide
	}
	feats = make([]sensitiveFeat, w*h)
	bright = make([]float64, w*h)
	for y := 0; y < h; y++ {
		sy := b.Min.Y + int((float64(y)+0.5)*float64(dy)/float64(h))
		if sy >= b.Max.Y {
			sy = b.Max.Y - 1
		}
		for x := 0; x < w; x++ {
			sx := b.Min.X + int((float64(x)+0.5)*float64(dx)/float64(w))
			if sx >= b.Max.X {
				sx = b.Max.X - 1
			}
			r, g, bl := rgb(im, sx, sy)
			R, G, B := r*255, g*255, bl*255
			i := y*w + x
			feats[i] = sensitiveFeats(R, G, B)
			bright[i] = (R + G + B) / 3
		}
	}
	return feats, bright, w, h, dx, dy
}

// componentsBoxes — все 4-связные компоненты маски с боксами на сетке.
// Возвращает список (размер в пикселях сетки, бокс включительно).
type gridBox struct {
	size           int
	x0, y0, x1, y1 int
	variance       float64
}

func componentsBoxes(mask []bool, w, h int) []gridBox {
	out, _ := scanComponents(mask, w, h, make([]bool, w*h), make([]int32, 0, w*h))
	return out
}

func scanComponents(mask []bool, w, h int, visited []bool, stack []int32) ([]gridBox, int) {
	return scanTexturedComponents(mask, nil, w, h, visited, stack)
}

func scanTexturedComponents(mask []bool, bright []float64, w, h int, visited []bool, stack []int32) ([]gridBox, int) {
	n := w * h
	clear(visited)
	out := make([]gridBox, 0, outlineMaxBoxes)
	best := 0
	for i := 0; i < n; i++ {
		if !mask[i] || visited[i] {
			continue
		}
		size := 0
		var mean, m2 float64
		x0, y0 := w, h
		x1, y1 := -1, -1
		stack = stack[:0]
		stack = append(stack, int32(i))
		visited[i] = true
		for len(stack) > 0 {
			v := int(stack[len(stack)-1])
			stack = stack[:len(stack)-1]
			size++
			if bright != nil {
				delta := bright[v] - mean
				mean += delta / float64(size)
				m2 += delta * (bright[v] - mean)
			}
			x, y := v%w, v/w
			if x < x0 {
				x0 = x
			}
			if x > x1 {
				x1 = x
			}
			if y < y0 {
				y0 = y
			}
			if y > y1 {
				y1 = y
			}
			if x > 0 {
				if u := v - 1; mask[u] && !visited[u] {
					visited[u] = true
					stack = append(stack, int32(u))
				}
			}
			if x+1 < w {
				if u := v + 1; mask[u] && !visited[u] {
					visited[u] = true
					stack = append(stack, int32(u))
				}
			}
			if y > 0 {
				if u := v - w; mask[u] && !visited[u] {
					visited[u] = true
					stack = append(stack, int32(u))
				}
			}
			if y+1 < h {
				if u := v + w; mask[u] && !visited[u] {
					visited[u] = true
					stack = append(stack, int32(u))
				}
			}
		}
		if size > best {
			best = size
		}
		if size >= outlineMinPixels && (len(out) < outlineMaxBoxes || size > out[len(out)-1].size) {
			if len(out) == outlineMaxBoxes {
				out = out[:len(out)-1]
			}
			out = append(out, gridBox{size: size, x0: x0, y0: y0, x1: x1, y1: y1, variance: m2 / float64(size)})
			sort.SliceStable(out, func(a, b int) bool { return out[a].size > out[b].size })
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].size > out[b].size })
	if len(out) > outlineMaxBoxes {
		out = out[:outlineMaxBoxes]
	}
	return out, best
}

// SensitiveAnalyze считает за один проход и скоры, и обводку.
// Маска строится один раз на класс — CPU как у одного ScoreSensitive.
func SensitiveAnalyze(im image.Image) (SensitiveReport, []SensitiveBox) {
	feats, bright, w, h, dx, dy := sensitiveGrid(im)
	if w == 0 || h == 0 {
		return SensitiveReport{}, nil
	}
	total := float64(w * h)
	lumVar := luminanceVariance(bright)
	rep := make(SensitiveReport, len(sensitiveOrder))
	var boxes []SensitiveBox
	mask := make([]bool, w*h)
	visited := make([]bool, w*h)
	stack := make([]int32, 0, w*h)
	for _, cls := range sensitiveOrder {
		m := sensitiveModel[cls]
		clear(mask)
		var fracCount int
		for i, f := range feats {
			if m.matches(f) {
				mask[i] = true
				fracCount++
			}
		}
		frac := float64(fracCount) / total
		if fracCount == 0 {
			sc := SensitiveScore{Ambiguous: len(m.conflict) > 0}
			if len(m.conflict) > 0 {
				sc.Conflict = append([]string{}, m.conflict...)
			}
			rep[cls] = sc
			continue
		}
		components, biggest := scanTexturedComponents(mask, bright, w, h, visited, stack)
		blob := float64(biggest) / total
		raw := math.Min(1.0, frac*2.5) * (0.5 + 0.5*math.Min(1, blob/math.Max(frac, 1e-9)))
		if cls == "skin" {
			raw *= 0.4 + 0.6*smoothFrac(bright, mask, w, h, 5)
		}
		solid := solidFill(cls, frac, lumVar) || (IsPreviewClass(cls) && maskedLuminanceVariance(bright, mask) < 80)
		if solid {
			raw *= 0.2
		}
		score := int(math.Round(raw * sensitiveWeights[cls] * 100))
		area := math.Round(frac*1000) / 10
		sc := SensitiveScore{AreaPct: area, Score: score, Ambiguous: len(m.conflict) > 0, Solid: solid}
		if len(m.conflict) > 0 {
			sc.Conflict = append([]string{}, m.conflict...)
		}
		rep[cls] = sc
		// Обводка из той же маски: координаты сетки -> оригинал.
		for _, gb := range components {
			x := gb.x0 * dx / w
			y := gb.y0 * dy / h
			x2 := (gb.x1+1)*dx/w - 1
			y2 := (gb.y1+1)*dy/h - 1
			if x2 < x {
				x2 = x
			}
			if y2 < y {
				y2 = y
			}
			if x >= dx || y >= dy {
				continue
			}
			if x2 >= dx {
				x2 = dx - 1
			}
			if y2 >= dy {
				y2 = dy - 1
			}
			boxes = append(boxes, SensitiveBox{
				Class:   cls,
				X:       x,
				Y:       y,
				W:       x2 - x + 1,
				H:       y2 - y + 1,
				AreaPct: math.Round(float64(gb.size)/total*1000) / 10,
				Score:   score,
				Solid:   IsPreviewClass(cls) && gb.variance < 80,
				Vector:  RegionVector(im, image.Rect(im.Bounds().Min.X+x, im.Bounds().Min.Y+y, im.Bounds().Min.X+x2+1, im.Bounds().Min.Y+y2+1)),
			})
		}
	}
	// Крупные сначала — сайту удобнее показывать по порядку.
	sort.Slice(boxes, func(a, b int) bool {
		if boxes[a].Score == boxes[b].Score {
			return boxes[a].AreaPct > boxes[b].AreaPct
		}
		return boxes[a].Score > boxes[b].Score
	})
	return rep, boxes
}
