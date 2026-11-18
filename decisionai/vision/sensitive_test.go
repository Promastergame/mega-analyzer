package vision

import (
	"context"
	"image"
	"image/color"
	"image/draw"
	"math/rand"
	"testing"
)

func solidImage(hex string, w, h int) image.Image {
	c := hexToRGB(hex)
	im := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.Draw(im, im.Bounds(), image.NewUniform(color.RGBA{uint8(c.r), uint8(c.g), uint8(c.b), 255}), image.Point{}, draw.Src)
	return im
}

// texturedBloodImage — имитация фото: тёмно-красная палитра с шумом.
// Дисперсия яркости высокая, поэтому флаг Solid не ставится.
func texturedBloodImage(w, h int) image.Image {
	im := image.NewRGBA(image.Rect(0, 0, w, h))
	palette := []color.RGBA{
		{0x6e, 0x00, 0x08, 255}, {0x82, 0x14, 0x18, 255}, {0x94, 0x18, 0x1a, 255},
		{0x64, 0x00, 0x0d, 255}, {0x75, 0x0f, 0x1a, 255}, {0x50, 0x0a, 0x0c, 255},
	}
	rng := rand.New(rand.NewSource(42))
	jitter := func(v uint8, m int) uint8 {
		n := int(v) + rng.Intn(2*m+1) - m
		if n < 0 {
			n = 0
		}
		if n > 255 {
			n = 255
		}
		return uint8(n)
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			base := palette[rng.Intn(len(palette))]
			im.SetRGBA(x, y, color.RGBA{jitter(base.R, 22), jitter(base.G, 10), jitter(base.B, 12), 255})
		}
	}
	return im
}

func TestSensitivePositivesHitOwnClass(t *testing.T) {
	for cls, hexes := range sensitivePositives {
		m := sensitiveModel[cls]
		for _, hx := range hexes {
			if !sensitiveHits(m, hx) {
				t.Fatalf("positive %s of class %s does not hit its own box (k=%.1f)", hx, cls, m.k)
			}
		}
	}
}

func TestSensitiveNegativesMissAll(t *testing.T) {
	for name, hx := range sensitiveNegatives {
		for cls, m := range sensitiveModel {
			if sensitiveHits(m, hx) {
				t.Fatalf("negative %s (%s) hits class %s (k=%.1f)", name, hx, cls, m.k)
			}
		}
	}
}

func TestSensitiveSolidScores(t *testing.T) {
	// Тёмная кровь сплошным полем: площадь ~100%, но это однотонная заливка —
	// скор придавлен флагом Solid и цензурный блюр не включает.
	rep := ScoreSensitive(solidImage("821418", 64, 64))
	if got := rep["blood_dark"]; got.AreaPct < 99 || got.Score >= 40 || !got.Solid {
		t.Fatalf("blood_dark solid: %+v", got)
	}
	if rep["blood_dark"].Ambiguous {
		t.Fatalf("blood_dark should not be ambiguous: %+v", rep["blood_dark"])
	}
	// Песок не должен давать кожу.
	rep = ScoreSensitive(solidImage("CEB9A2", 64, 64))
	if got := rep["skin"]; got.Score != 0 || got.AreaPct != 0 {
		t.Fatalf("sand gives skin: %+v", got)
	}
	// Лимон не должен давать fluid_yellow (запас сжат), но класс помечен ambiguous.
	rep = ScoreSensitive(solidImage("FCD348", 64, 64))
	if got := rep["fluid_yellow"]; got.Score != 0 {
		t.Fatalf("lemon gives fluid_yellow: %+v", got)
	}
	if !rep["fluid_yellow"].Ambiguous {
		t.Fatalf("fluid_yellow should be ambiguous (лимон)")
	}
	// Красная футболка не должна давать blood_bright, но класс ambiguous.
	rep = ScoreSensitive(solidImage("DB2927", 64, 64))
	if got := rep["blood_bright"]; got.Score != 0 {
		t.Fatalf("red shirt gives blood_bright: %+v", got)
	}
	if !rep["blood_bright"].Ambiguous {
		t.Fatalf("blood_bright should be ambiguous (футболка/томат)")
	}
	// Яркая кровь своим цветом срабатывает, но это однотонная заливка:
	// скор низкий, класс помечен Solid и ambiguous.
	rep = ScoreSensitive(solidImage("DF2F26", 64, 64))
	if got := rep["blood_bright"]; got.Score == 0 || got.Score > 40 || !got.Solid {
		t.Fatalf("blood_bright solid out of low-weight range: %+v", got)
	}
}

// TestSensitiveTexturedBloodScores — настоящее фото с кровью (вариативная
// яркость, разброс оттенков) сохраняет высокий скор: именно по нему
// включается цензурный блюр.
func TestSensitiveTexturedBloodScores(t *testing.T) {
	rep := ScoreSensitive(texturedBloodImage(128, 128))
	got := rep["blood_dark"]
	if got.Solid {
		t.Fatalf("textured photo marked solid: %+v", got)
	}
	if got.AreaPct < 8 || got.Score < 25 {
		t.Fatalf("textured blood photo below blur thresholds: %+v", got)
	}
}

func TestSensitiveBlobAndSmooth(t *testing.T) {
	w, h := 8, 8
	mask := make([]bool, w*h)
	// Один пиксель: blob = 1/64.
	mask[0] = true
	if got := biggestBlobFrac(mask, w, h); got != 1.0/float64(w*h) {
		t.Fatalf("single blob %v", got)
	}
	// Половина строк: крупнейший блок 4x8? Проверяем диапазон.
	for i := range mask {
		mask[i] = i < w*h/2
	}
	if got := biggestBlobFrac(mask, w, h); got < 0.49 || got > 0.51 {
		t.Fatalf("half blob %v", got)
	}
	bright := make([]float64, w*h)
	for i := range bright {
		bright[i] = 128
	}
	full := make([]bool, w*h)
	for i := range full {
		full[i] = true
	}
	if got := smoothFrac(bright, full, w, h, 5); got != 1 {
		t.Fatalf("flat smooth %v", got)
	}
	// Шахматка с контрастом: std высокого окна > 12, гладкость ~0.
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if (x+y)%2 == 0 {
				bright[y*w+x] = 0
			} else {
				bright[y*w+x] = 255
			}
		}
	}
	if got := smoothFrac(bright, full, w, h, 5); got > 0.1 {
		t.Fatalf("checker smooth %v, want ~0", got)
	}
}

func TestSensitiveInAnalyze(t *testing.T) {
	a, err := (Local{}).Analyze(context.Background(), encodeImage(texturedBloodImage(100, 100)))
	if err != nil {
		t.Fatal(err)
	}
	if a.Sensitive == nil || a.Sensitive["blood_dark"].Score < 25 || a.Sensitive["blood_dark"].Solid {
		t.Fatalf("%+v", a.Sensitive)
	}
	if len(a.ImgSHA256) != 64 {
		t.Fatalf("want 64-hex img_sha256, got %q", a.ImgSHA256)
	}
	found := false
	for _, bx := range a.Boxes {
		if bx.Class == "blood_dark" && bx.W == 100 && bx.H == 100 {
			found = true
		}
	}
	if !found {
		t.Fatalf("want full-image blood_dark box, got %+v", a.Boxes)
	}
}
