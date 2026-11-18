package games

import (
	"context"
	"strings"
	"testing"
	"time"
)

func replayTetris(t *testing.T, s State, d Decision) tetBoard {
	t.Helper()
	b, err := parseTetris(s)
	if err != nil {
		t.Fatal(err)
	}
	p := Placement{X: b.w/2 - 2, Y: -2}
	if s.Active != nil {
		p = *s.Active
	}
	shapes := rotations(s.Piece)
	for i, c := range d.Controls {
		switch c {
		case "left":
			p.X--
		case "right":
			p.X++
		case "down":
			p.Y++
		case "cw", "ccw":
			delta := 1
			if c == "ccw" {
				delta = 3
			}
			r := (p.Rotation + delta) % 4
			kicks := normalKicks[[2]int{p.Rotation, r}]
			if s.Piece == "I" {
				kicks = iKicks[[2]int{p.Rotation, r}]
			}
			found := false
			for _, k := range kicks {
				q := Placement{p.X + k.X, p.Y + k.Y, r}
				if b.fits(q, shapes[r]) {
					p = q
					found = true
					break
				}
			}
			if !found {
				t.Fatal("invalid rotation")
			}
		case "hard_drop":
			if i != len(d.Controls)-1 {
				t.Fatal("hard drop must finish controls")
			}
			for q := p; ; {
				q.Y++
				if !b.fits(q, shapes[p.Rotation]) {
					break
				}
				p = q
			}
		default:
			t.Fatalf("unknown control %q", c)
		}
		if !b.fits(p, shapes[p.Rotation]) {
			t.Fatalf("control collided: %s %+v", c, p)
		}
	}
	if d.Placement == nil || p != *d.Placement {
		t.Fatalf("unreachable target: got %+v want %+v", p, d.Placement)
	}
	after, cleared, ok := b.lock(p, shapes[p.Rotation])
	if !ok || cleared != d.Cleared {
		t.Fatal("invalid lock or wrong clear count")
	}
	return after
}
func tetrisWell() State {
	return State{Game: "tetris", Piece: "I", Next: "T", Grid: []string{"..........", "..........", "..........", "..........", "..........", "..........", "..........", "..........", "..........", "..........", "..........", "..........", "..........", "..........", "..........", "..........", "#########.", "#########.", "#########.", "#########."}}
}
func TestTetrisFourLineClear(t *testing.T) {
	s := tetrisWell()
	d, err := Solve(s)
	if err != nil {
		t.Fatal(err)
	}
	if d.Cleared != 4 {
		t.Fatalf("missed tetris: %+v", d)
	}
	replayTetris(t, s, d)
}

func TestTetrisSRSWallKicks(t *testing.T) {
	for _, tc := range []struct {
		piece       string
		x, rotation int
	}{{"T", -1, 2}, {"I", -2, 0}} {
		b := tetBoard{w: 10, h: 10}
		start := Placement{X: tc.x, Y: 2, Rotation: 1}
		budget := &searchBudget{ctx: context.Background(), deadline: time.Now().Add(time.Second), limit: 100000}
		_, nodes, complete := b.placements(tc.piece, start, budget)
		if !complete {
			t.Fatal("unexpected budget limit")
		}
		found := false
		for _, n := range nodes {
			if n.parent == 0 && n.pose == (Placement{X: 0, Y: 2, Rotation: tc.rotation}) {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing SRS wall kick for %s", tc.piece)
		}
	}
}
func TestTetrisAllPiecesAndActivePose(t *testing.T) {
	for _, piece := range []string{"I", "O", "T", "J", "L", "S", "Z"} {
		s := State{Game: "tetris", Piece: piece, Grid: []string{"..........", "..........", "..........", "..........", "...#......", "##.#......", "####...#..", "####..###."}}
		d, err := Solve(s)
		if err != nil {
			t.Fatalf("%s: %v", piece, err)
		}
		replayTetris(t, s, d)
	}
	s := State{Game: "tetris", Piece: "T", Active: &Placement{X: 2, Y: 3, Rotation: 1}, Grid: []string{"..........", "..........", "..........", "..........", "..........", "..........", "..........", "###....###"}}
	d, err := Solve(s)
	if err != nil {
		t.Fatal(err)
	}
	replayTetris(t, s, d)
}
func TestTetrisRejectsInvalidObservations(t *testing.T) {
	for _, s := range []State{
		{Game: "tetris", Piece: "Q", Grid: []string{"....", "....", "....", "...."}},
		{Game: "tetris", Piece: "I", Grid: []string{"....", "....", "....", "####"}},
		{Game: "tetris", Piece: "T", Active: &Placement{X: 0, Y: 3}, Grid: []string{"....", "....", "....", "#..."}},
		{Game: "tetris", Piece: "O", Active: &Placement{Rotation: 4}, Grid: []string{"....", "....", "....", "...."}},
	} {
		if _, err := Solve(s); err == nil {
			t.Fatalf("accepted invalid: %+v", s)
		}
	}
}
func TestTetrisNoTeleportIntoSealedCavity(t *testing.T) {
	s := State{Game: "tetris", Piece: "O", Grid: []string{"......", "......", "......", "#####.", "#..##.", "#..##."}}
	d, err := Solve(s)
	if err != nil {
		t.Fatal(err)
	}
	replayTetris(t, s, d)
	if d.Placement.Y >= 3 && d.Placement.X < 3 {
		t.Fatal("teleported below the roof")
	}
}
func TestComplexGamesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, s := range []State{tetrisWell(), initialCheckers()} {
		if _, err := SolveContext(ctx, s); err == nil {
			t.Fatal("ignored cancellation")
		}
	}
}
func TestTetrisMultiPiecePlay(t *testing.T) {
	s := State{Game: "tetris"}
	for i := 0; i < 20; i++ {
		s.Grid = append(s.Grid, "..........")
	}
	pieces := []string{"I", "O", "T", "S", "Z", "J", "L"}
	for i := 0; i < 70; i++ {
		s.Piece = pieces[i%7]
		s.Next = pieces[(i+1)%7]
		d, err := Solve(s)
		if err != nil {
			t.Fatal(err)
		}
		if d.Terminal {
			return
		}
		if !d.Heuristic || d.Search == nil || d.Search.Nodes > 16001 {
			t.Fatalf("unbounded search: %+v", d)
		}
		board := replayTetris(t, s, d)
		s.Grid = nil
		for y := 0; y < board.h; y++ {
			var row strings.Builder
			for x := 0; x < board.w; x++ {
				if board.rows[y]&(1<<x) != 0 {
					row.WriteByte('#')
				} else {
					row.WriteByte('.')
				}
			}
			s.Grid = append(s.Grid, row.String())
		}
	}
}
func BenchmarkTetrisLookahead(b *testing.B) {
	s := tetrisWell()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Solve(s); err != nil {
			b.Fatal(err)
		}
	}
}
