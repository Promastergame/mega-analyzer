package arena

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"reflect"
	"testing"

	"decisionai/games"
	"decisionai/vision"
)

func TestVisualGamesPlayFromPixels(t *testing.T) {
	ctx := context.Background()
	for _, game := range []string{"tetris", "russian_checkers"} {
		t.Run(game, func(t *testing.T) {
			w, _ := New(game)
			for turn := 0; turn < 40 && w.Status == "playing"; turn++ {
				im, err := w.Render()
				if err != nil {
					t.Fatal(err)
				}
				s, err := (vision.Local{}).ReadGame(ctx, game, []vision.Image{im})
				if err != nil {
					t.Fatalf("turn %d: %v", turn, err)
				}
				if game == "tetris" {
					if !reflect.DeepEqual(s.Grid, w.State.Grid) || s.Piece != w.State.Piece || s.Next != "" {
						t.Fatalf("invented board: %+v", s)
					}
				} else if !reflect.DeepEqual(s.Board, w.State.Board) || s.Player != w.State.Player {
					t.Fatalf("wrong board: %+v", s)
				}
				d, err := games.SolveContext(ctx, s)
				if err != nil {
					t.Fatal(err)
				}
				if d.Terminal {
					break
				}
				if err := w.Apply(ctx, d); err != nil {
					t.Fatalf("turn %d: %v", turn, err)
				}
			}
			if w.Moves < 10 {
				t.Fatalf("only %d moves", w.Moves)
			}
		})
	}
}

func TestVisibleRotatedTetrominoes(t *testing.T) {
	for _, p := range []string{"I", "O", "T", "S", "Z", "J", "L"} {
		for r := 0; r < 4; r++ {
			if p == "O" && r != 0 {
				continue
			}
			w, _ := New("tetris")
			w.State.Piece = p
			w.State.Active = &games.Placement{X: 3, Y: 10, Rotation: r}
			im, _ := w.Render()
			s, err := (vision.Local{}).ReadGame(context.Background(), "tetris", []vision.Image{im})
			if err != nil {
				t.Fatal(err)
			}
			want, _ := games.TetrisCells(p, *w.State.Active)
			got, _ := games.TetrisCells(s.Piece, *s.Active)
			set := map[games.Point]bool{}
			for _, p := range want {
				set[p] = true
			}
			for _, p := range got {
				if !set[p] {
					t.Fatalf("wrong pose: %s %d %+v", s.Piece, r, s.Active)
				}
			}
			d, err := games.Solve(s)
			if err != nil {
				t.Fatal(err)
			}
			if err = w.Apply(context.Background(), d); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func recode(t *testing.T, v vision.Image, edit func(*image.RGBA), jpegImage bool) vision.Image {
	t.Helper()
	data, _ := base64.StdEncoding.DecodeString(v.Data)
	src, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	im := image.NewRGBA(src.Bounds())
	draw.Draw(im, im.Bounds(), src, image.Point{}, draw.Src)
	if edit != nil {
		edit(im)
	}
	var out bytes.Buffer
	if jpegImage {
		err = jpeg.Encode(&out, im, &jpeg.Options{Quality: 94})
		v.MIMEType = "image/jpeg"
	} else {
		err = png.Encode(&out, im)
	}
	if err != nil {
		t.Fatal(err)
	}
	v.Data = base64.StdEncoding.EncodeToString(out.Bytes())
	return v
}

func TestCheckersKingsTurnAndJPEG(t *testing.T) {
	w, _ := New("russian_checkers")
	w.State.Board = []string{"........", "..B.....", "........", "....W...", "........", "w.......", ".......b", "........"}
	w.State.Player = "black"
	im, _ := w.Render()
	for _, v := range []vision.Image{im, recode(t, im, nil, true)} {
		s, err := (vision.Local{}).ReadGame(context.Background(), "russian_checkers", []vision.Image{v})
		if err != nil || !reflect.DeepEqual(s.Board, w.State.Board) || s.Player != "black" {
			t.Fatalf("%+v %v", s, err)
		}
	}
	// A 180-degree camera orientation must preserve canonical coordinates.
	rot := recode(t, im, func(dst *image.RGBA) {
		cp := image.NewRGBA(dst.Bounds())
		copy(cp.Pix, dst.Pix)
		for y := 0; y < 384; y++ {
			for x := 0; x < 384; x++ {
				dst.Set(x, y, cp.At(383-x, 383-y))
			}
		}
	}, false)
	l := *rot.Layout
	l.Orientation = "black_bottom"
	rot.Layout = &l
	s, err := (vision.Local{}).ReadGame(context.Background(), "russian_checkers", []vision.Image{rot})
	if err != nil || !reflect.DeepEqual(s.Board, w.State.Board) {
		t.Fatalf("rotation: %+v %v", s, err)
	}
}

func TestUnknownPixelsAndMissingActiveAreRejected(t *testing.T) {
	for _, game := range []string{"tetris", "russian_checkers"} {
		w, _ := New(game)
		im, _ := w.Render()
		bad := recode(t, im, func(im *image.RGBA) {
			draw.Draw(im, image.Rect(0, 0, 24, 24), image.NewUniform(color.RGBA{255, 0, 0, 255}), image.Point{}, draw.Src)
		}, false)
		if _, err := (vision.Local{}).ReadGame(context.Background(), game, []vision.Image{bad}); err == nil {
			t.Fatal("accepted unknown pixels")
		}
	}
	w, _ := New("tetris")
	w.State.Piece = "T"
	w.State.Active = &games.Placement{X: 3, Y: -1}
	im, _ := w.Render()
	if _, err := (vision.Local{}).ReadGame(context.Background(), "tetris", []vision.Image{im}); err == nil {
		t.Fatal("invented offscreen cells")
	}
	w, _ = New("russian_checkers")
	im, _ = w.Render()
	im.Layout.Turn = nil
	if _, err := (vision.Local{}).ReadGame(context.Background(), "russian_checkers", []vision.Image{im}); err == nil {
		t.Fatal("invented side to move")
	}
}

func TestHumanCheckerChainUsesLegalRules(t *testing.T) {
	w, _ := New("russian_checkers")
	w.State.Board = []string{"........", "....b...", "........", "..b.....", ".w......", "........", "........", "........"}
	ctx := context.Background()
	for _, p := range []games.Point{{X: 1, Y: 4}, {X: 3, Y: 2}} {
		if err := w.Click(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if w.Moves != 0 {
		t.Fatal("partial capture applied")
	}
	if err := w.Click(ctx, games.Point{X: 5, Y: 0}); err != nil {
		t.Fatal(err)
	}
	if w.Moves != 1 || w.State.Board[0][5] != 'W' || w.Status != "white_wins" {
		t.Fatalf("%+v", w)
	}
}

func TestVisualCropAndScale(t *testing.T) {
	for _, game := range []string{"tetris", "russian_checkers"} {
		w, _ := New(game)
		original, _ := w.Render()
		data, _ := base64.StdEncoding.DecodeString(original.Data)
		src, _, _ := image.Decode(bytes.NewReader(data))
		for _, scale := range []float64{.75, 1.5} {
			width, height := int(float64(src.Bounds().Dx())*scale), int(float64(src.Bounds().Dy())*scale)
			im := image.NewRGBA(image.Rect(0, 0, width+26, height+34))
			for y := 0; y < height; y++ {
				for x := 0; x < width; x++ {
					im.Set(x+13, y+17, src.At(int(float64(x)/scale), int(float64(y)/scale)))
				}
			}
			l := *original.Layout
			l.Left = 13
			l.Top = 17
			l.Width = width
			l.Height = height
			if game == "russian_checkers" {
				l.Width = int(384 * scale)
				l.Height = l.Width
				l.Turn = &vision.Region{Left: 13 + int(176*scale), Top: 17 + int(384*scale), Width: int(32 * scale), Height: int(32 * scale)}
			}
			var buf bytes.Buffer
			if err := png.Encode(&buf, im); err != nil {
				t.Fatal(err)
			}
			v := vision.Image{Data: base64.StdEncoding.EncodeToString(buf.Bytes()), MIMEType: "image/png", Layout: &l}
			s, err := (vision.Local{}).ReadGame(context.Background(), game, []vision.Image{v})
			if err != nil {
				t.Fatalf("%s scale %.2f: %v", game, scale, err)
			}
			if !reflect.DeepEqual(s.Grid, w.State.Grid) || !reflect.DeepEqual(s.Board, w.State.Board) || s.Piece != w.State.Piece || s.Player != w.State.Player {
				t.Fatalf("wrong cropped state: %+v", s)
			}
		}
	}
}
