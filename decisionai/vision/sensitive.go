// Package vision — sensitive color filter.
//
// Порт Python-прототипа «пипетка»: эталон для Go.
// Диапазоны строятся из POSITIVES (должно срабатывать) и NEGATIVES
// (не должно: песок, вода, красная футболка, лимон, томат).
// Запас (margin) вокруг позитивов автоматически сжимается, пока ни один
// негатив не попадает в диапазон. Неотличимый негатив — КОНФЛИКТ:
// класс остаётся, но получает низкий вес и метку ambiguous.
//
// Скор — НЕ вероятность. Честные проценты только после калибровки
// на размеченном наборе реальных кадров.
package vision

import (
	"image"
	"math"
)

// SensitiveScore — результат одного класса фильтра.
type SensitiveScore struct {
	// AreaPct — доля пикселей маски, % (1 знак после запятой).
	AreaPct float64 `json:"area_pct"`
	// Score — взвешенный скор 0..100. НЕ вероятность, калибровки нет.
	Score int `json:"score"`
	// Ambiguous — класс конфликтует с обычными цветами (см. Conflict).
	Ambiguous bool `json:"ambiguous"`
	// Solid — класс совпадает с почти однотонной заливкой: это фон или
	// иконка, а не сцена; для цензурного блюра такой класс не используется.
	Solid bool `json:"solid,omitempty"`
	// Conflict — имена негативов, неотличимых от класса.
	Conflict []string `json:"conflict,omitempty"`
}

// SensitiveReport — скор по всем классам. Ключи стабильны:
// skin, blood_dark, blood_bright, fluid_warm, fluid_yellow, fluid_white.
type SensitiveReport map[string]SensitiveScore

// Порядок классов для детерминированного вывода.
var sensitiveOrder = []string{"skin", "blood_dark", "blood_bright", "fluid_warm", "fluid_yellow", "fluid_white"}

// SensitiveOrder возвращает стабильный порядок классов.
func SensitiveOrder() []string {
	out := make([]string, len(sensitiveOrder))
	copy(out, sensitiveOrder)
	return out
}

type sensitiveRGB struct{ r, g, b float64 }

func hexToRGB(s string) sensitiveRGB {
	var v [3]float64
	for i := 0; i < 3; i++ {
		var n int
		for _, c := range s[i*2 : i*2+2] {
			n <<= 4
			switch {
			case c >= '0' && c <= '9':
				n += int(c - '0')
			case c >= 'a' && c <= 'f':
				n += int(c-'a') + 10
			case c >= 'A' && c <= 'F':
				n += int(c-'A') + 10
			}
		}
		v[i] = float64(n)
	}
	return sensitiveRGB{v[0], v[1], v[2]}
}

var sensitivePositives = map[string][]string{
	"skin":         {"4E332A", "E9D0C3", "673D24", "C39A86", "C29078", "9E7056", "8C645C"},
	"blood_dark":   {"821418", "94181A", "391515", "431515", "64000D", "750F1A", "6E0008"},
	"blood_bright": {"DF2F26"},
	"fluid_warm":   {"F0B97E", "E3970F"},
	"fluid_yellow": {"FDDD4F"},
	"fluid_white":  {"EEFFF2"},
}

var sensitiveNegatives = map[string]string{
	"песок":            "CEB9A2",
	"вода":             "D0E3EF",
	"красная футболка": "DB2927",
	"лимон":            "FCD348",
	"томат":            "FA2C06",
}

var sensitiveWeights = map[string]float64{
	"skin": 1.0, "blood_dark": 1.0, "blood_bright": 0.35,
	"fluid_warm": 0.5, "fluid_yellow": 0.3, "fluid_white": 0.2,
}

// MARGIN: hue°, Cb, Cr, S, V (максимальный запас, до сжатия).
var sensitiveMargin = [5]float64{10, 10, 10, 0.12, 0.15}

type sensitiveBox struct {
	hc, hw       float64
	cbMin, cbMax float64
	crMin, crMax float64
	sMin, sMax   float64
	vMin, vMax   float64
	rgMin, rgMax float64
	k            float64
	conflict     []string
}

type sensitiveFeat struct {
	h, s, v, cb, cr, rg float64
}

func sensitiveFeats(r, g, b float64) sensitiveFeat {
	mx := math.Max(r, math.Max(g, b))
	mn := math.Min(r, math.Min(g, b))
	d := mx - mn
	dd := math.Max(d, 1e-9)
	v := mx / 255
	var s float64
	if mx > 0 {
		s = d / math.Max(mx, 1)
	}
	var h float64
	if d == 0 {
		h = 0
	} else {
		// Порядок как в numpy-прототипе: r, затем g перезаписывает r,
		// затем b перезаписывает оба. Эквивалент: приоритет b > g > r.
		switch {
		case b == mx:
			h = (r-g)/dd + 4
		case g == mx:
			h = (b-r)/dd + 2
		default: // r == mx
			m := math.Mod((g-b)/dd, 6)
			if m < 0 {
				m += 6
			}
			h = m
		}
		h *= 60
	}
	cb := 128 - 0.168736*r - 0.331264*g + 0.5*b
	cr := 128 + 0.5*r - 0.418688*g - 0.081312*b
	rg := r / math.Max(g, 1)
	return sensitiveFeat{h, s, v, cb, cr, rg}
}

func sensitiveHueDist(h, c float64) float64 {
	return math.Mod(h-c+540, 360) - 180
}

func sensitiveMakeBox(hexes []string, k float64) sensitiveBox {
	n := len(hexes)
	feats := make([]sensitiveFeat, n)
	var sumSin, sumCos float64
	for i, hx := range hexes {
		c := hexToRGB(hx)
		f := sensitiveFeats(c.r, c.g, c.b)
		feats[i] = f
		rad := f.h * math.Pi / 180
		sumSin += math.Sin(rad)
		sumCos += math.Cos(rad)
	}
	hc := math.Atan2(sumSin/float64(n), sumCos/float64(n)) * 180 / math.Pi
	if hc < 0 {
		hc += 360
	}
	mh := sensitiveMargin[0] * k
	mcb := sensitiveMargin[1] * k
	mcr := sensitiveMargin[2] * k
	ms := sensitiveMargin[3] * k
	mv := sensitiveMargin[4] * k
	var hw float64
	cbMin, cbMax := feats[0].cb, feats[0].cb
	crMin, crMax := feats[0].cr, feats[0].cr
	sMin, sMax := feats[0].s, feats[0].s
	vMin, vMax := feats[0].v, feats[0].v
	rgMin, rgMax := feats[0].rg, feats[0].rg
	for _, f := range feats {
		if a := math.Abs(sensitiveHueDist(f.h, hc)); a > hw {
			hw = a
		}
		if f.cb < cbMin {
			cbMin = f.cb
		}
		if f.cb > cbMax {
			cbMax = f.cb
		}
		if f.cr < crMin {
			crMin = f.cr
		}
		if f.cr > crMax {
			crMax = f.cr
		}
		if f.s < sMin {
			sMin = f.s
		}
		if f.s > sMax {
			sMax = f.s
		}
		if f.v < vMin {
			vMin = f.v
		}
		if f.v > vMax {
			vMax = f.v
		}
		if f.rg < rgMin {
			rgMin = f.rg
		}
		if f.rg > rgMax {
			rgMax = f.rg
		}
	}
	hw += mh
	sMin = math.Max(0, sMin-ms)
	sMax = math.Min(1, sMax+ms)
	vMin = math.Max(0, vMin-mv)
	vMax = math.Min(1, vMax+mv)
	return sensitiveBox{
		hc: hc, hw: hw,
		cbMin: cbMin - mcb, cbMax: cbMax + mcb,
		crMin: crMin - mcr, crMax: crMax + mcr,
		sMin: sMin, sMax: sMax, vMin: vMin, vMax: vMax,
		rgMin: rgMin * (1 - .15*k), rgMax: rgMax * (1 + .15*k),
		k: k,
	}
}

func (m sensitiveBox) matches(f sensitiveFeat) bool {
	return math.Abs(sensitiveHueDist(f.h, m.hc)) <= m.hw &&
		f.cb >= m.cbMin && f.cb <= m.cbMax &&
		f.cr >= m.crMin && f.cr <= m.crMax &&
		f.s >= m.sMin && f.s <= m.sMax &&
		f.v >= m.vMin && f.v <= m.vMax &&
		f.rg >= m.rgMin && f.rg <= m.rgMax
}

func sensitiveHits(m sensitiveBox, hex string) bool {
	c := hexToRGB(hex)
	return m.matches(sensitiveFeats(c.r, c.g, c.b))
}

func sensitiveRGBDist(a, b sensitiveRGB) float64 {
	dr, dg, db := a.r-b.r, a.g-b.g, a.b-b.b
	return math.Sqrt(dr*dr + dg*dg + db*db)
}

// buildSensitiveModel выбирает самый большой запас без ложных срабатываний,
// как в прототипе: k = 1.0, .8, .6, .4, .2, 0.0.
func buildSensitiveModel() map[string]sensitiveBox {
	model := make(map[string]sensitiveBox, len(sensitivePositives))
	// Детерминированный порядок обхода негативов для стабильных conflict.
	negOrder := []string{"песок", "вода", "красная футболка", "лимон", "томат"}
	for _, cls := range sensitiveOrder {
		hexes := sensitivePositives[cls]
		var chosen *sensitiveBox
		var conflicts []string
		for _, k := range []float64{1.0, .8, .6, .4, .2, 0.0} {
			m := sensitiveMakeBox(hexes, k)
			var bad []string
			for _, n := range negOrder {
				if sensitiveHits(m, sensitiveNegatives[n]) {
					bad = append(bad, n)
				}
			}
			if len(bad) == 0 {
				chosen = &m
				break
			}
			conflicts = bad
		}
		var m sensitiveBox
		if chosen == nil {
			m = sensitiveMakeBox(hexes, 0.0)
			m.conflict = append([]string{}, conflicts...)
		} else {
			m = *chosen
		}
		// Близкие по RGB (<25) негативы тоже помечаем конфликтом:
		// одиночный образец иначе даёт "точку".
		posRGB := make([]sensitiveRGB, len(hexes))
		for i, q := range hexes {
			posRGB[i] = hexToRGB(q)
		}
		for _, n := range negOrder {
			hx := sensitiveNegatives[n]
			c := hexToRGB(hx)
			mind := math.MaxFloat64
			for _, q := range posRGB {
				if d := sensitiveRGBDist(c, q); d < mind {
					mind = d
				}
			}
			if mind < 25 {
				found := false
				for _, e := range m.conflict {
					if len(e) >= len(n) && e[:len(n)] == n {
						found = true
						break
					}
				}
				if !found {
					// Формат как в прототипе: "имя (Δ=..)".
					m.conflict = append(m.conflict, n+" (Δ="+itoa(int(math.Round(mind)))+")")
				}
			}
		}
		model[cls] = m
	}
	return model
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

var sensitiveModel = buildSensitiveModel()

// SensitiveModelInfo — отладочная сводка: запас k и конфликты по классам.
func SensitiveModelInfo() map[string]map[string]any {
	out := make(map[string]map[string]any, len(sensitiveModel))
	for cls, m := range sensitiveModel {
		out[cls] = map[string]any{
			"k":        m.k,
			"hc":       math.Round(m.hc*10) / 10,
			"hw":       math.Round(m.hw*10) / 10,
			"weight":   sensitiveWeights[cls],
			"conflict": append([]string{}, m.conflict...),
		}
	}
	return out
}

// scoreSensitiveGrid — ядро скоринга на даунсемплированной сетке.
// feats уже посчитаны; bright — средняя яркость (R+G+B)/3 0..255.
func scoreSensitiveGrid(feats []sensitiveFeat, bright []float64, w, h int) SensitiveReport {
	out := make(SensitiveReport, len(sensitiveOrder))
	total := float64(w * h)
	// Однотонные заливки (фоны, логотипы-иконки) математически совпадают с
	// любым палитровым правилом, но сценой не являются: у настоящего фото
	// яркость варьируется. Считается один раз на сетку.
	lumVar := luminanceVariance(bright)
	for _, cls := range sensitiveOrder {
		m := sensitiveModel[cls]
		mask := make([]bool, w*h)
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
			out[cls] = sc
			continue
		}
		blob := biggestBlobFrac(mask, w, h)
		raw := math.Min(1.0, frac*2.5) * (0.5 + 0.5*math.Min(1, blob/math.Max(frac, 1e-9)))
		if cls == "skin" {
			// smooth считаем только для skin: остальным классам он не нужен,
			// в прототипе тоже используется только там. Экономим CPU.
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
		out[cls] = sc
	}
	return out
}

// luminanceVariance — дисперсия яркости сетки; у сплошной заливки ≈ 0.
func luminanceVariance(bright []float64) float64 {
	if len(bright) == 0 {
		return 0
	}
	mean := 0.0
	for _, v := range bright {
		mean += v
	}
	mean /= float64(len(bright))
	var sum float64
	for _, v := range bright {
		d := v - mean
		sum += d * d
	}
	return sum / float64(len(bright))
}

// Use the matched pixels' texture, not the surrounding background. A flat red
// logo on a detailed photo must not acquire the background's variance.
func maskedLuminanceVariance(bright []float64, mask []bool) float64 {
	var count int
	var mean, m2 float64
	for i, value := range bright {
		if !mask[i] {
			continue
		}
		count++
		delta := value - mean
		mean += delta / float64(count)
		m2 += delta * (value - mean)
	}
	if count == 0 {
		return 0
	}
	return m2 / float64(count)
}

// solidFill — почти вся сетка совпала с классом при плоской яркости:
// это однотонная заливка (фон, иконка), а не сцена. skin исключён —
// у него свой smooth-гард.
func solidFill(cls string, frac, lumVar float64) bool {
	return cls != "skin" && frac > 0.85 && lumVar < 80
}

// biggestBlobFrac — доля крупнейшей 4-связной компоненты от всех пикселей.
// Порт scipy.ndimage.label (структура по умолчанию — 4-связность).
func biggestBlobFrac(mask []bool, w, h int) float64 {
	n := w * h
	visited := make([]bool, n)
	best := 0
	// Переиспользуемый стек, чтобы не аллоцировать на каждую компоненту.
	stack := make([]int, 0, 256)
	for i := 0; i < n; i++ {
		if !mask[i] || visited[i] {
			continue
		}
		size := 0
		stack = stack[:0]
		stack = append(stack, i)
		visited[i] = true
		for len(stack) > 0 {
			v := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			size++
			x, y := v%w, v/w
			if x > 0 {
				if u := v - 1; mask[u] && !visited[u] {
					visited[u] = true
					stack = append(stack, u)
				}
			}
			if x+1 < w {
				if u := v + 1; mask[u] && !visited[u] {
					visited[u] = true
					stack = append(stack, u)
				}
			}
			if y > 0 {
				if u := v - w; mask[u] && !visited[u] {
					visited[u] = true
					stack = append(stack, u)
				}
			}
			if y+1 < h {
				if u := v + w; mask[u] && !visited[u] {
					visited[u] = true
					stack = append(stack, u)
				}
			}
		}
		if size > best {
			best = size
		}
	}
	if best == 0 {
		return 0
	}
	return float64(best) / float64(n)
}

// smoothFrac — доля пикселей маски с гладкой яркостью (std 5x5 < 12).
func smoothFrac(bright []float64, mask []bool, w, h, k int) float64 {
	var cnt, smooth int
	p := k / 2
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			idx := y*w + x
			if !mask[idx] {
				continue
			}
			cnt++
			var sum, sum2 float64
			n := 0
			for dy := -p; dy <= p; dy++ {
				yy := y + dy
				if yy < 0 {
					yy = 0
				} else if yy >= h {
					yy = h - 1
				}
				for dx := -p; dx <= p; dx++ {
					xx := x + dx
					if xx < 0 {
						xx = 0
					} else if xx >= w {
						xx = w - 1
					}
					v := bright[yy*w+xx]
					sum += v
					sum2 += v * v
					n++
				}
			}
			mean := sum / float64(n)
			variance := sum2/float64(n) - mean*mean
			if variance < 0 {
				variance = 0
			}
			if math.Sqrt(variance) < 12 {
				smooth++
			}
		}
	}
	if cnt == 0 {
		return 0
	}
	return float64(smooth) / float64(cnt)
}

// ScoreSensitive считает фильтр по image.Image.
// Даунсемплирует до max_side=256 (как thumbnail в прототипе),
// композитит прозрачность на белом — как rgb() в local.go.
func ScoreSensitive(im image.Image) SensitiveReport {
	b := im.Bounds()
	dx, dy := b.Dx(), b.Dy()
	if dx <= 0 || dy <= 0 {
		return SensitiveReport{}
	}
	const maxSide = 256
	scale := 1.0
	if m := math.Max(float64(dx), float64(dy)); m > maxSide {
		scale = maxSide / m
	}
	w := int(math.Round(float64(dx) * scale))
	h := int(math.Round(float64(dy) * scale))
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	// Ограничение CPU: не более 256*256 пикселей.
	if w*h > maxSide*maxSide {
		w, h = maxSide, maxSide
	}
	feats := make([]sensitiveFeat, w*h)
	bright := make([]float64, w*h)
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
			r, g, bl := rgb(im, sx, sy) // 0..1, уже на белом
			R, G, B := r*255, g*255, bl*255
			i := y*w + x
			feats[i] = sensitiveFeats(R, G, B)
			bright[i] = (R + G + B) / 3
		}
	}
	return scoreSensitiveGrid(feats, bright, w, h)
}

// SensitiveTop возвращает максимальный взвешенный скор и его класс.
func SensitiveTop(rep SensitiveReport) (string, int) {
	best, score := "", 0
	for _, cls := range sensitiveOrder {
		if s, ok := rep[cls]; ok && s.Score > score {
			best, score = cls, s.Score
		}
	}
	return best, score
}
