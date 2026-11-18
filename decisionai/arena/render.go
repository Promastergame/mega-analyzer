package arena

import (
	"bytes"
	"encoding/base64"
	"decisionai/games"
	"decisionai/vision"
	"image"
	"image/color"
	"image/draw"
	"image/png"
)

var background = color.RGBA{24, 32, 39, 255}
var white = color.RGBA{255, 247, 232, 255}
var black = color.RGBA{37, 43, 50, 255}
var gold = color.RGBA{219, 167, 74, 255}

func rect(im *image.RGBA, x, y, w, h int, c color.Color) {
	draw.Draw(im, image.Rect(x, y, x+w, y+h), image.NewUniform(c), image.Point{}, draw.Src)
}
func disk(im *image.RGBA, x, y, r int, c color.Color) {
	for dy := -r; dy <= r; dy++ {
		for dx := -r; dx <= r; dx++ {
			if dx*dx+dy*dy <= r*r {
				im.Set(x+dx, y+dy, c)
			}
		}
	}
}

// Render is the sole visual observation: no hidden state or metadata is encoded
// in the PNG. Layout contains only fixed screen geometry and artwork profile.
func (w *World) Render() (vision.Image, error) {
	var im *image.RGBA
	var layout *vision.Layout
	if w.State.Game == "tetris" {
		im = image.NewRGBA(image.Rect(0, 0, 240, 480))
		rect(im, 0, 0, 240, 480, background)
		layout = &vision.Layout{Profile: "arena_tetris_v1", Rows: 20, Columns: 10}
		block := func(x, y int, c color.Color) { rect(im, x*24+2, y*24+2, 20, 20, c) }
		for y, row := range w.State.Grid {
			for x, c := range row {
				if c == '#' {
					block(x, y, color.RGBA{133, 146, 157, 255})
				} else {
					im.Set(x*24, y*24, color.RGBA{55, 65, 73, 255})
				}
			}
		}
		cells, _ := games.TetrisCells(w.State.Piece, *w.State.Active)
		for _, p := range cells {
			block(p.X, p.Y, color.RGBA{83, 223, 206, 255})
		}
	} else {
		im = image.NewRGBA(image.Rect(0, 0, 384, 416))
		rect(im, 0, 0, 384, 416, background)
		layout = &vision.Layout{Profile: "arena_checkers_v1", Width: 384, Height: 384, Rows: 8, Columns: 8, Orientation: "white_bottom", Turn: &vision.Region{Left: 176, Top: 384, Width: 32, Height: 32}}
		for y, row := range w.State.Board {
			for x, p := range row {
				c := color.RGBA{228, 220, 203, 255}
				if (x+y)%2 == 1 {
					c = color.RGBA{102, 116, 102, 255}
				}
				rect(im, x*48, y*48, 48, 48, c)
				if p != '.' {
					c = black
					if p == 'w' || p == 'W' {
						c = white
					}
					disk(im, x*48+24, y*48+24, 17, c)
					if p == 'W' || p == 'B' {
						disk(im, x*48+24, y*48+24, 6, gold)
					}
				}
			}
		}
		for _, p := range w.Selected {
			x, y := p.X*48, p.Y*48
			rect(im, x+1, y+1, 46, 2, gold)
			rect(im, x+1, y+45, 46, 2, gold)
			rect(im, x+1, y+1, 2, 46, gold)
			rect(im, x+45, y+1, 2, 46, gold)
		}
		c := black
		if w.State.Player == "white" {
			c = white
		}
		disk(im, 192, 400, 12, gold)
		disk(im, 192, 400, 10, c)
		// Visible arrow points at the side-to-move disk.
		rect(im, 155, 399, 12, 2, white)
		for i := 0; i < 5; i++ {
			rect(im, 164+i, 396+i, 1, 8-2*i, white)
		}
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := enc.Encode(&buf, im); err != nil {
		return vision.Image{}, err
	}
	return vision.Image{Data: base64.StdEncoding.EncodeToString(buf.Bytes()), MIMEType: "image/png", Layout: layout}, nil
}
