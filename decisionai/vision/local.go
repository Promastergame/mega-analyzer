package vision

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"math"
	"runtime"
	"sort"
	"strings"

	"decisionai/games"
)

// Local samples a fixed number of pixels after bounded decoding. It recognizes
// colors and specific board conventions, not arbitrary semantic photo objects.
type Local struct{}

// Analysis runs on several cores at once: each request decodes and samples
// its own image, so the only shared state is memory pressure. Bounded by
// CPU count (capped) instead of the old single slot that serialized callers.
var imageSlot = make(chan struct{}, visionWorkers())

func visionWorkers() int {
	n := runtime.NumCPU()
	if n > 8 {
		n = 8
	}
	if n < 2 {
		n = 2
	}
	return n
}

func acquire(ctx context.Context) error {
	select {
	case imageSlot <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type ColorShare struct {
	Name     string  `json:"name"`
	Fraction float64 `json:"fraction"`
}
type Analysis struct {
	Width         int             `json:"width"`
	Height        int             `json:"height"`
	ImgSHA256     string          `json:"img_sha256,omitempty"`
	Colors        []ColorShare    `json:"colors"`
	Board         *games.State    `json:"board,omitempty"`
	Sensitive     SensitiveReport `json:"sensitive,omitempty"`
	Boxes         []SensitiveBox  `json:"boxes,omitempty"`
	Scope         string          `json:"scope"`
	Vector        VectorV1        `json:"vector"`
	VectorVersion int             `json:"vector_version"`
	Preview       PreviewAssessment `json:"preview"`
}

// ImageSHA256 — hex sha256 сырых байтов картинки (тот же хеш — ключ голосов RLHF).
func ImageSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func decode(ctx context.Context, input Image) (image.Image, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := Validate([]Image{input}); err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(input.Data)
	if err != nil {
		return nil, err
	}
	im, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("corrupt image: %w", err)
	}
	return im, ctx.Err()
}

// Composite transparency over white so an invisible black RGB value is not a mark.
func rgb(im image.Image, x, y int) (float64, float64, float64) {
	var r, g, b, a uint32
	switch v := im.(type) {
	case *image.RGBA:
		c := v.RGBAAt(x, y)
		r, g, b, a = c.RGBA()
	case *image.NRGBA:
		c := v.NRGBAAt(x, y)
		r, g, b, a = c.RGBA()
	case *image.Gray:
		c := v.GrayAt(x, y)
		r, g, b, a = c.RGBA()
	case *image.YCbCr:
		c := v.YCbCrAt(x, y)
		r, g, b, a = c.RGBA()
	default:
		r, g, b, a = im.At(x, y).RGBA()
	}
	white := uint32(65535) - a
	return float64(r+white) / 65535, float64(g+white) / 65535, float64(b+white) / 65535
}
func colorName(r, g, b float64) string {
	max := math.Max(r, math.Max(g, b))
	min := math.Min(r, math.Min(g, b))
	if max < .23 {
		return "black"
	}
	if min > .84 {
		return "white"
	}
	if max-min < .15 {
		return "gray"
	}
	if r > .6 && g > .55 && b < .4 {
		return "yellow"
	}
	if r > .65 && g > .25 && g < .55 && b < .3 {
		return "orange"
	}
	if r > g*1.3 && r > b*1.25 {
		return "red"
	}
	if g > r*1.2 && g > b*1.15 {
		return "green"
	}
	if b > r*1.2 && b > g*1.1 {
		return "blue"
	}
	if r > .45 && b > .45 {
		return "purple"
	}
	return "mixed"
}

func (Local) Analyze(ctx context.Context, input Image) (Analysis, error) {
	if err := acquire(ctx); err != nil {
		return Analysis{}, err
	}
	defer func() { <-imageSlot }()
	im, err := decode(ctx, input)
	if err != nil {
		return Analysis{}, err
	}
	b := im.Bounds()
	out := Analysis{Width: b.Dx(), Height: b.Dy(), Scope: "Pixel colors, heuristic sensitive-color scores (0..100, not probabilities, uncalibrated) and supported game boards only; no general photo semantics or OCR."}
	if raw, err := base64.StdEncoding.DecodeString(input.Data); err == nil {
		out.ImgSHA256 = ImageSHA256(raw)
	}
	counts := map[string]int{}
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			r, g, bl := rgb(im, b.Min.X+x*b.Dx()/64, b.Min.Y+y*b.Dy()/64)
			counts[colorName(r, g, bl)]++
		}
	}
	for name, n := range counts {
		if n >= 40 {
			out.Colors = append(out.Colors, ColorShare{name, math.Round(float64(n)/4096*1000) / 1000})
		}
	}
	out.Sensitive, out.Boxes = SensitiveAnalyze(im)
	out.Preview = AssessPreview(out)
	out.Vector = RegionVector(im, im.Bounds())
	out.VectorVersion = VectorVersion
	sort.Slice(out.Colors, func(i, j int) bool {
		if out.Colors[i].Fraction == out.Colors[j].Fraction {
			return out.Colors[i].Name < out.Colors[j].Name
		}
		return out.Colors[i].Fraction > out.Colors[j].Fraction
	})
	if board, err := readTic(im, input.Layout); err == nil {
		out.Board = &board
	}
	layout := input.Layout
	if layout == nil {
		if b.Dx() == 240 && b.Dy() == 480 {
			layout = &Layout{Profile: "arena_tetris_v1", Rows: 20, Columns: 10}
		}
		if b.Dx() == 384 && b.Dy() == 416 {
			layout = &Layout{Profile: "arena_checkers_v1", Width: 384, Height: 384, Rows: 8, Columns: 8, Turn: &Region{Left: 176, Top: 384, Width: 32, Height: 32}}
		}
	}
	if layout != nil {
		var board games.State
		var readErr error
		switch layout.Profile {
		case "arena_tetris_v1":
			board, readErr = readTetris(im, layout)
		case "arena_checkers_v1":
			board, readErr = readCheckers(im, layout)
		default:
			readErr = fmt.Errorf("no complex game profile")
		}
		if readErr == nil {
			out.Board = &board
		}
	}
	return out, ctx.Err()
}

func (l Local) Describe(ctx context.Context, _ string, images []Image) (string, error) {
	if err := Validate(images); err != nil {
		return "", err
	}
	a, err := l.Analyze(ctx, images[0])
	if err != nil {
		return "", err
	}
	var text strings.Builder
	fmt.Fprintf(&text, "Image dimensions: %d x %d pixels. Visible sampled colors:", a.Width, a.Height)
	for _, c := range a.Colors {
		fmt.Fprintf(&text, " %s %.1f%%;", c.Name, c.Fraction*100)
	}
	if len(a.Sensitive) > 0 {
		text.WriteString(" Sensitive color filter (heuristic 0..100, not a probability, uncalibrated):")
		for _, cls := range SensitiveOrder() {
			s := a.Sensitive[cls]
			if s.Score <= 0 && s.AreaPct <= 0 {
				continue
			}
			if s.Ambiguous {
				fmt.Fprintf(&text, " %s score %d area %.1f%% (ambiguous);", cls, s.Score, s.AreaPct)
			} else {
				fmt.Fprintf(&text, " %s score %d area %.1f%%;", cls, s.Score, s.AreaPct)
			}
		}
	}
	if len(a.Boxes) > 0 {
		text.WriteString(" Outlines:")
		n := len(a.Boxes)
		if n > 6 {
			n = 6
		}
		for _, bx := range a.Boxes[:n] {
			fmt.Fprintf(&text, " %s at [%d,%d %dx%d];", bx.Class, bx.X, bx.Y, bx.W, bx.H)
		}
	}
	if a.Board != nil {
		b, _ := json.Marshal(a.Board)
		fmt.Fprintf(&text, " Recognized game board: %s.", b)
	}
	text.WriteString(" " + a.Scope)
	return text.String(), nil
}

func (Local) ReadGame(ctx context.Context, game string, images []Image) (games.State, error) {
	if err := acquire(ctx); err != nil {
		return games.State{}, err
	}
	defer func() { <-imageSlot }()
	if err := Validate(images); err != nil {
		return games.State{}, err
	}
	im, err := decode(ctx, images[0])
	if err != nil {
		return games.State{}, err
	}
	switch game {
	case "tic_tac_toe":
		return readTic(im, images[0].Layout)
	case "maze":
		return readMaze(im, images[0].Layout)
	case "tetris":
		return readTetris(im, images[0].Layout)
	case "russian_checkers":
		return readCheckers(im, images[0].Layout)
	}
	return games.State{}, fmt.Errorf("unsupported visual game %q", game)
}

func crop(im image.Image, l *Layout) (image.Rectangle, error) {
	b := im.Bounds()
	if l == nil {
		return b, nil
	}
	if l.Width == 0 && l.Height == 0 && l.Left == 0 && l.Top == 0 {
		return b, nil
	}
	if l.Left < 0 || l.Top < 0 || l.Width < 1 || l.Height < 1 || l.Left > b.Dx()-l.Width || l.Top > b.Dy()-l.Height {
		return b, fmt.Errorf("board crop is outside the image")
	}
	return image.Rect(l.Left, l.Top, l.Left+l.Width, l.Top+l.Height), nil
}

func readTic(im image.Image, l *Layout) (games.State, error) {
	s := games.State{Game: "tic_tac_toe"}
	b, err := crop(im, l)
	if err != nil {
		return s, err
	}
	if b.Dx() < 48 || b.Dy() < 48 || math.Abs(float64(b.Dx()-b.Dy())) > float64(b.Dx())*.1 {
		return s, fmt.Errorf("tic-tac-toe needs a square crop of the entire 3x3 board")
	}
	if l != nil && ((l.Rows != 0 && l.Rows != 3) || (l.Columns != 0 && l.Columns != 3)) {
		return s, fmt.Errorf("tic-tac-toe layout must be 3x3")
	}
	br, bg, bb := rgb(im, b.Min.X+b.Dx()/20, b.Min.Y+b.Dy()/20)
	ink := func(x, y int) bool {
		r, g, bl := rgb(im, x, y)
		return math.Abs(r-br)+math.Abs(g-bg)+math.Abs(bl-bb) > .65
	}
	// Require both grid separators in both directions, allowing line width/rounding.
	for n := 1; n <= 2; n++ {
		for axis := 0; axis < 2; axis++ {
			best := 0
			for offset := -2; offset <= 2; offset++ {
				count := 0
				for i := 1; i < 64; i++ {
					x, y := b.Min.X+b.Dx()*n/3+offset, b.Min.Y+b.Dy()*i/64
					if axis == 1 {
						x, y = b.Min.X+b.Dx()*i/64, b.Min.Y+b.Dy()*n/3+offset
					}
					if ink(x, y) {
						count++
					}
				}
				if count > best {
					best = count
				}
			}
			if best < 48 {
				return s, fmt.Errorf("cannot confidently locate the 3x3 grid; provide a tight board crop")
			}
		}
	}
	for row := 0; row < 3; row++ {
		cells := []byte("...")
		for col := 0; col < 3; col++ {
			var mask [32][32]bool
			count := 0
			minX, minY, maxX, maxY := 32, 32, -1, -1
			for y := 0; y < 32; y++ {
				for x := 0; x < 32; x++ {
					px := b.Min.X + col*b.Dx()/3 + int((.15+.7*(float64(x)+.5)/32)*float64(b.Dx())/3)
					py := b.Min.Y + row*b.Dy()/3 + int((.15+.7*(float64(y)+.5)/32)*float64(b.Dy())/3)
					if ink(px, py) {
						mask[y][x] = true
						count++
						if x < minX {
							minX = x
						}
						if x > maxX {
							maxX = x
						}
						if y < minY {
							minY = y
						}
						if y > maxY {
							maxY = y
						}
					}
				}
			}
			if count == 0 {
				continue
			}
			if count < 12 || maxX-minX < 8 || maxY-minY < 8 {
				return s, fmt.Errorf("uncertain mark at row %d column %d", row, col)
			}
			scores := [2]float64{}
			for kind := 0; kind < 2; kind++ {
				inter, union := 0, 0
				for y := minY; y <= maxY; y++ {
					for x := minX; x <= maxX; x++ {
						xf, yf := float64(x-minX)/float64(maxX-minX), float64(y-minY)/float64(maxY-minY)
						ideal := math.Abs(xf-yf) < .15 || math.Abs(xf+yf-1) < .15
						if kind == 1 {
							radius := math.Hypot(xf-.5, yf-.5)
							ideal = radius > .32 && radius < .55
						}
						if ideal || mask[y][x] {
							union++
						}
						if ideal && mask[y][x] {
							inter++
						}
					}
				}
				scores[kind] = float64(inter) / float64(union)
			}
			best := 0
			if scores[1] > scores[0] {
				best = 1
			}
			if scores[best] < .42 || math.Abs(scores[0]-scores[1]) < .15 {
				return s, fmt.Errorf("ambiguous X/O at row %d column %d", row, col)
			}
			cells[col] = "XO"[best]
		}
		s.Board = append(s.Board, string(cells))
	}
	if _, err := games.Solve(s); err != nil {
		return s, fmt.Errorf("visually inconsistent board: %w", err)
	}
	return s, nil
}

func readMaze(im image.Image, l *Layout) (games.State, error) {
	s := games.State{Game: "maze"}
	if l == nil || l.Rows < 1 || l.Columns < 1 || l.Rows > 128 || l.Columns > 128 {
		return s, fmt.Errorf("maze image needs layout.rows and layout.columns (1..128)")
	}
	b, err := crop(im, l)
	if err != nil {
		return s, err
	}
	if b.Dx() < l.Columns*3 || b.Dy() < l.Rows*3 {
		return s, fmt.Errorf("maze cells must be at least 3 pixels wide and high")
	}
	legend := map[string]byte{"white": '.', "black": '#', "blue": 'S', "green": 'G', "red": 'X', "yellow": '*'}
	for y := 0; y < l.Rows; y++ {
		row := make([]byte, l.Columns)
		for x := 0; x < l.Columns; x++ {
			var label byte
			for _, offset := range [][2]float64{{.35, .35}, {.65, .35}, {.5, .5}, {.35, .65}, {.65, .65}} {
				r, g, bl := rgb(im, b.Min.X+int((float64(x)+offset[0])*float64(b.Dx())/float64(l.Columns)), b.Min.Y+int((float64(y)+offset[1])*float64(b.Dy())/float64(l.Rows)))
				cell, ok := legend[colorName(r, g, bl)]
				if !ok || (label != 0 && label != cell) {
					return s, fmt.Errorf("uncertain maze cell %d,%d; use the documented solid-color palette", x, y)
				}
				label = cell
			}
			row[x] = label
		}
		s.Grid = append(s.Grid, string(row))
	}
	if _, err := games.Solve(s); err != nil {
		return s, err
	}
	return s, nil
}
