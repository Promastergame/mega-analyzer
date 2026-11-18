package games

import (
	"context"
	"strings"
	"testing"
	"time"
)

func checkerState(pieces map[string]byte, player string) State {
	rows := make([][]byte, 8)
	for y := range rows {
		rows[y] = []byte("........")
	}
	for name, p := range pieces {
		x, y := int(name[0]-'a'), 8-int(name[1]-'0')
		rows[y][x] = p
	}
	s := State{Game: "russian_checkers", Player: player}
	for _, row := range rows {
		s.Board = append(s.Board, string(row))
	}
	return s
}
func allCheckerMoves(t *testing.T, s State) []draughtMove {
	t.Helper()
	board, p, err := parseCheckers(s)
	if err != nil {
		t.Fatal(err)
	}
	budget := &searchBudget{ctx: context.Background(), deadline: time.Now().Add(time.Second), limit: 100000}
	moves, ok := checkerMoves(board, p, budget)
	if !ok {
		t.Fatal("move generation unexpectedly limited")
	}
	return moves
}
func TestCheckersBackwardCaptureAndChain(t *testing.T) {
	for _, tc := range []struct {
		s        State
		action   string
		captures int
	}{
		{checkerState(map[string]byte{"b6": 'w', "c5": 'b'}, "white"), "b6xd4", 1},
		{checkerState(map[string]byte{"a3": 'w', "b4": 'b', "d6": 'b', "g3": 'w'}, "white"), "a3xc5xe7", 2},
	} {
		d, err := Solve(tc.s)
		if err != nil || d.Action != tc.action || len(d.Captures) != tc.captures {
			t.Fatalf("%+v %v", d, err)
		}
	}
}
func TestCheckersFlyingKing(t *testing.T) {
	moves := allCheckerMoves(t, checkerState(map[string]byte{"b2": 'W', "d4": 'b'}, "white"))
	if len(moves) != 4 {
		t.Fatalf("want four landing squares, got %d", len(moves))
	}
	for _, m := range moves {
		if m.length != 2 || m.captured == 0 {
			t.Fatal("quiet move allowed during capture")
		}
	}
}
func TestCheckersPromotionContinuesAsKing(t *testing.T) {
	moves := allCheckerMoves(t, checkerState(map[string]byte{"b6": 'w', "c7": 'b', "f6": 'b'}, "white"))
	if len(moves) != 2 {
		t.Fatalf("want two landing choices after promotion, got %d", len(moves))
	}
	for _, m := range moves {
		last := m.path[m.length-1]
		if m.length != 3 || m.path[1] != 3 || m.board[last] != 'W' || lenCapture(m) != 2 {
			t.Fatalf("promotion chain wrong: %+v", m)
		}
	}
}
func lenCapture(m draughtMove) int {
	n := 0
	for c := m.captured; c != 0; c &= c - 1 {
		n++
	}
	return n
}
func TestCheckersCapturedPiecesBlockReverseRay(t *testing.T) {
	moves := allCheckerMoves(t, checkerState(map[string]byte{"d4": 'W', "c3": 'b', "f6": 'b'}, "white"))
	if len(moves) != 4 {
		t.Fatalf("want four single captures, got %d", len(moves))
	}
	for _, m := range moves {
		if lenCapture(m) != 1 {
			t.Fatalf("king crossed an already captured piece: %+v", m)
		}
	}
}
func TestCheckersDoesNotForceMaximumCaptureCount(t *testing.T) {
	moves := allCheckerMoves(t, checkerState(map[string]byte{"a3": 'w', "b4": 'b', "d6": 'b', "h2": 'w', "g3": 'b'}, "white"))
	short, long := false, false
	for _, m := range moves {
		short = short || lenCapture(m) == 1
		long = long || lenCapture(m) == 2
	}
	if !short || !long {
		t.Fatalf("Russian rules permit both complete chains: %+v", moves)
	}
}
func TestCheckersQuietPromotionAndTerminal(t *testing.T) {
	moves := allCheckerMoves(t, checkerState(map[string]byte{"a7": 'w', "h2": 'b'}, "white"))
	if len(moves) != 1 || moves[0].board[1] != 'W' {
		t.Fatal("quiet promotion failed")
	}
	d, err := Solve(checkerState(map[string]byte{"a3": 'w'}, "black"))
	if err != nil || !d.Terminal || d.Action != "" || d.Outcome != "white_won" {
		t.Fatalf("%+v %v", d, err)
	}
}
func TestCheckersRejectsInvalidState(t *testing.T) {
	for _, s := range []State{checkerState(map[string]byte{"a8": 'W', "b6": 'b'}, "white"), checkerState(map[string]byte{"b8": 'w', "b6": 'b'}, "white"), checkerState(map[string]byte{"a3": 'w', "b6": 'b'}, "")} {
		if _, err := Solve(s); err == nil {
			t.Fatalf("accepted %+v", s)
		}
	}
}
func initialCheckers() State {
	return State{Game: "russian_checkers", Player: "white", Board: []string{".b.b.b.b", "b.b.b.b.", ".b.b.b.b", "........", "........", "w.w.w.w.", ".w.w.w.w", "w.w.w.w."}}
}
func TestCheckersPlayoutAlwaysReturnsCompleteLegalTurn(t *testing.T) {
	s := initialCheckers()
	for turn := 0; turn < 50; turn++ {
		d, err := Solve(s)
		if err != nil {
			t.Fatal(err)
		}
		if d.Terminal {
			return
		}
		if d.Search == nil || d.Search.Nodes > 12001 || !d.Heuristic {
			t.Fatalf("unbounded/mislabelled search: %+v", d)
		}
		found := false
		for _, m := range allCheckerMoves(t, s) {
			if len(d.Path) != m.length {
				continue
			}
			equal := true
			for i, p := range d.Path {
				equal = equal && p.Y*8+p.X == m.path[i]
			}
			if equal {
				s.Board = nil
				for y := 0; y < 8; y++ {
					s.Board = append(s.Board, string(m.board[y*8:y*8+8]))
				}
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("illegal move %s on %v", d.Action, s.Board)
		}
		if s.Player == "white" {
			s.Player = "black"
		} else {
			s.Player = "white"
		}
	}
}
func BenchmarkCheckersOpening(b *testing.B) {
	s := initialCheckers()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if d, err := Solve(s); err != nil || strings.TrimSpace(d.Action) == "" {
			b.Fatalf("%+v %v", d, err)
		}
	}
}
