package vision

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"reflect"
	"testing"
)

func encodeImage(im image.Image) Image {
	var b bytes.Buffer
	_ = png.Encode(&b, im)
	return Image{Data: base64.StdEncoding.EncodeToString(b.Bytes()), MIMEType: "image/png"}
}
func boardImage(board []string, size int) Image {
	im := image.NewRGBA(image.Rect(0, 0, size, size))
	draw.Draw(im, im.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	cell := size / 3
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if math.Abs(float64(x-cell)) < 2 || math.Abs(float64(x-2*cell)) < 2 || math.Abs(float64(y-cell)) < 2 || math.Abs(float64(y-2*cell)) < 2 {
				im.Set(x, y, color.Black)
				continue
			}
			if x/cell > 2 || y/cell > 2 {
				continue
			}
			mark := board[y/cell][x/cell]
			xf, yf := (float64(x%cell)/float64(cell)-.5)/.6+.5, (float64(y%cell)/float64(cell)-.5)/.6+.5
			if xf < 0 || yf < 0 || xf > 1 || yf > 1 {
				continue
			}
			if (mark == 'X' && (math.Abs(xf-yf) < .12 || math.Abs(xf+yf-1) < .12)) || (mark == 'O' && math.Abs(math.Hypot(xf-.5, yf-.5)-.43) < .075) {
				im.Set(x, y, color.Black)
			}
		}
	}
	return encodeImage(im)
}

func TestReadTicPixels(t *testing.T) {
	for _, size := range []int{150, 300, 600} {
		for _, board := range [][]string{{"XX.", "OO.", "..."}, {"X..", ".O.", "..X"}, {"...", "...", "..."}, {"XOX", "XOO", "OXX"}} {
			s, err := (Local{}).ReadGame(context.Background(), "tic_tac_toe", []Image{boardImage(board, size)})
			if err != nil || !reflect.DeepEqual(s.Board, board) {
				t.Fatalf("size=%d want=%v got=%v error=%v", size, board, s.Board, err)
			}
		}
	}
}
func TestReadMazePixels(t *testing.T) {
	im := image.NewRGBA(image.Rect(0, 0, 60, 40))
	palette := map[byte]color.Color{'S': color.RGBA{0, 0, 255, 255}, 'G': color.RGBA{0, 255, 0, 255}, 'X': color.RGBA{255, 0, 0, 255}, '.': color.White, '#': color.Black}
	grid := []string{"SXG", ".#."}
	for y, row := range grid {
		for x, c := range []byte(row) {
			draw.Draw(im, image.Rect(x*20, y*20, (x+1)*20, (y+1)*20), image.NewUniform(palette[c]), image.Point{}, draw.Src)
		}
	}
	input := encodeImage(im)
	input.Layout = &Layout{Rows: 2, Columns: 3}
	s, err := (Local{}).ReadGame(context.Background(), "maze", []Image{input})
	if err != nil || !reflect.DeepEqual(s.Grid, grid) {
		t.Fatalf("%+v %v", s, err)
	}
}
func TestRejectUnrecognizedImage(t *testing.T) {
	im := image.NewRGBA(image.Rect(0, 0, 100, 100))
	draw.Draw(im, im.Bounds(), image.NewUniform(color.RGBA{255, 0, 0, 255}), image.Point{}, draw.Src)
	input := encodeImage(im)
	if _, err := (Local{}).ReadGame(context.Background(), "tic_tac_toe", []Image{input}); err == nil {
		t.Fatal("invented board")
	}
	a, err := (Local{}).Analyze(context.Background(), input)
	if err != nil || len(a.Colors) != 1 || a.Colors[0].Name != "red" || a.Board != nil {
		t.Fatalf("%+v %v", a, err)
	}
	input.MIMEType = "image/jpeg"
	if err := Validate([]Image{input}); err == nil {
		t.Fatal("accepted mime mismatch")
	}
	if _, err := (Local{}).Analyze(context.Background(), encodeImage(image.NewRGBA(image.Rect(0, 0, 2048, 1024)))); err == nil {
		t.Fatal("accepted oversized image")
	}
}
func BenchmarkReadBoard(b *testing.B) {
	input := boardImage([]string{"XX.", "OO.", "..."}, 300)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := (Local{}).ReadGame(context.Background(), "tic_tac_toe", []Image{input}); err != nil {
			b.Fatal(err)
		}
	}
}
