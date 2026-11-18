package vision

import (
	"fmt"
	"decisionai/games"
	"image"
	"math"
)

// These deliberately narrow profiles recognize the visible arena artwork.
// They do not infer an arbitrary website's theme or silently accept other colors.
var arenaColors = map[byte][3]float64{
	'.': {24, 32, 39}, '#': {133, 146, 157}, '@': {83, 223, 206},
	'l': {228, 220, 203}, 'd': {102, 116, 102},
	'w': {255, 247, 232}, 'b': {37, 43, 50}, 'k': {219, 167, 74},
}

func arenaPixel(im image.Image, x, y int, allowed string) byte {
	r, g, b := rgb(im, x, y)
	best, second := 1.0, 1.0
	var label byte
	for i := range allowed {
		c := arenaColors[allowed[i]]
		dr, dg, db := r-c[0]/255, g-c[1]/255, b-c[2]/255
		d := dr*dr + dg*dg + db*db
		if math.Abs(dr) < .10 && math.Abs(dg) < .10 && math.Abs(db) < .10 {
			if d < best {
				second = best
				best = d
				label = allowed[i]
			} else if d < second {
				second = d
			}
		}
	}
	if second-best < .0005 {
		return 0
	}
	return label
}

func readTetris(im image.Image, l *Layout) (games.State, error) {
	s := games.State{Game: "tetris"}
	if l == nil || l.Profile != "arena_tetris_v1" {
		return s, fmt.Errorf("tetris screenshot requires arena_tetris_v1 layout profile")
	}
	rows, cols := l.Rows, l.Columns
	if rows < 4 || rows > 24 || cols < 4 || cols > 16 {
		return s, fmt.Errorf("tetris layout needs 4..24 rows and 4..16 columns")
	}
	b, err := crop(im, l)
	if err != nil {
		return s, err
	}
	if b.Dx() < cols*12 || b.Dy() < rows*12 {
		return s, fmt.Errorf("tetris cells must be at least 12 pixels")
	}
	active := []games.Point{}
	for y := 0; y < rows; y++ {
		row := make([]byte, cols)
		for x := 0; x < cols; x++ {
			var label byte
			for sy := 0; sy < 5; sy++ {
				for sx := 0; sx < 5; sx++ {
					px := b.Min.X + int((float64(x)+.24+float64(sx)*.13)*float64(b.Dx())/float64(cols))
					py := b.Min.Y + int((float64(y)+.24+float64(sy)*.13)*float64(b.Dy())/float64(rows))
					c := arenaPixel(im, px, py, ".#@")
					if c == 0 || (label != 0 && c != label) {
						return s, fmt.Errorf("uncertain tetris cell %d,%d", x, y)
					}
					label = c
				}
			}
			row[x] = label
			if label == '@' {
				active = append(active, games.Point{X: x, Y: y})
				row[x] = '.'
			}
		}
		s.Grid = append(s.Grid, string(row))
	}
	s.Piece, s.Active, err = games.MatchTetrisCells(active)
	if err != nil {
		return s, fmt.Errorf("uncertain active piece: %w", err)
	}
	// There is no next-piece metadata in this visual profile.
	return s, nil
}

func readCheckers(im image.Image, l *Layout) (games.State, error) {
	s := games.State{Game: "russian_checkers"}
	if l == nil || l.Profile != "arena_checkers_v1" || l.Turn == nil {
		return s, fmt.Errorf("checkers screenshot requires arena_checkers_v1 and a visible turn indicator region")
	}
	if (l.Rows != 0 && l.Rows != 8) || (l.Columns != 0 && l.Columns != 8) {
		return s, fmt.Errorf("checkers layout must be 8x8")
	}
	if l.Orientation != "" && l.Orientation != "white_bottom" && l.Orientation != "black_bottom" {
		return s, fmt.Errorf("unknown board orientation")
	}
	b, err := crop(im, l)
	if err != nil {
		return s, err
	}
	if b.Dx() < 192 || b.Dy() < 192 || math.Abs(float64(b.Dx()-b.Dy())) > 2 {
		return s, fmt.Errorf("checkers needs a square board, cells at least 24 pixels")
	}
	board := [8][8]byte{}
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			sample := func(fx, fy float64, allowed string) byte {
				return arenaPixel(im, b.Min.X+int((float64(x)+fx)*float64(b.Dx())/8), b.Min.Y+int((float64(y)+fy)*float64(b.Dy())/8), allowed)
			}
			bg := byte('l')
			if (x+y)%2 == 1 {
				bg = 'd'
			}
			for _, p := range [][2]float64{{.08, .08}, {.92, .08}, {.08, .92}, {.92, .92}} {
				if sample(p[0], p[1], "ld") != bg {
					return s, fmt.Errorf("unknown checkers board at %d,%d", x, y)
				}
			}
			c := sample(.5, .5, "ldwbk")
			piece := byte('.')
			if c != bg {
				if c != 'w' && c != 'b' && c != 'k' {
					return s, fmt.Errorf("uncertain checker at %d,%d", x, y)
				}
				piece = sample(.5, .26, "wb")
				if piece == 0 {
					return s, fmt.Errorf("uncertain checker color at %d,%d", x, y)
				}
				if c != 'k' && c != piece {
					return s, fmt.Errorf("unknown checker mark")
				}
			}
			// Validate the disk silhouette and uniform body, including empty squares.
			for sy := 0; sy < 7; sy++ {
				for sx := 0; sx < 7; sx++ {
					fx, fy := .14+float64(sx)*.12, .14+float64(sy)*.12
					d := math.Hypot(fx-.5, fy-.5)
					if (d > .30 && d < .40) || d < .19 {
						continue
					}
					want := bg
					if piece != '.' && d < .30 {
						want = piece
					}
					if sample(fx, fy, "ldwb") != want {
						return s, fmt.Errorf("uncertain checker silhouette at %d,%d", x, y)
					}
				}
			}
			if piece == '.' {
				for _, p := range [][2]float64{{.38, .5}, {.62, .5}, {.5, .38}, {.5, .62}} {
					if sample(p[0], p[1], "ld") != bg {
						return s, fmt.Errorf("unknown mark on empty square")
					}
				}
			} else {
				for _, p := range [][2]float64{{.47, .5}, {.53, .5}, {.5, .47}, {.5, .53}} {
					if sample(p[0], p[1], "wbk") != c {
						return s, fmt.Errorf("ambiguous king mark")
					}
				}
				if c == 'k' {
					piece -= 32
				}
			}
			bx, by := x, y
			if l.Orientation == "black_bottom" {
				bx = 7 - x
				by = 7 - y
			}
			board[by][bx] = piece
		}
	}
	for _, row := range board {
		s.Board = append(s.Board, string(row[:]))
	}
	t := l.Turn
	tb, err := crop(im, &Layout{Left: t.Left, Top: t.Top, Width: t.Width, Height: t.Height})
	if err != nil || t.Width < 8 || t.Height < 8 || tb.Overlaps(b) {
		return s, fmt.Errorf("invalid separate turn indicator region")
	}
	var turn byte
	for _, p := range [][2]float64{{.4, .4}, {.6, .4}, {.5, .5}, {.4, .6}, {.6, .6}} {
		c := arenaPixel(im, tb.Min.X+int(p[0]*float64(tb.Dx())), tb.Min.Y+int(p[1]*float64(tb.Dy())), "wb")
		if c == 0 || (turn != 0 && c != turn) {
			return s, fmt.Errorf("uncertain visible turn indicator")
		}
		turn = c
	}
	s.Player = "white"
	if turn == 'b' {
		s.Player = "black"
	}
	return s, nil
}
