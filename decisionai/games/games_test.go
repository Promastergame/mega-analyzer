package games

import (
	"fmt"
	"testing"
)

func BenchmarkEmptyBoard(b *testing.B) {
	s := State{Game: "tic_tac_toe", Board: []string{"...", "...", "..."}}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Solve(s); err != nil {
			b.Fatal(err)
		}
	}
}

func TestTicTacToeTactics(t *testing.T) {
	for _, tc := range []struct {
		board          []string
		player, action string
	}{
		{[]string{"XX.", "OO.", "..."}, "X", "cell_2"},
		{[]string{"XX.", ".O.", "..."}, "O", "cell_2"},
		{[]string{"X..", ".O.", "..X"}, "O", "cell_1"},
	} {
		d, err := Solve(State{Game: "tic_tac_toe", Board: tc.board, Player: tc.player})
		if err != nil || d.Action != tc.action {
			t.Fatalf("%v: %+v %v", tc.board, d, err)
		}
	}
}

// Enumerate every opponent continuation, with the solver playing either side.
// This tests the actual policy against all legal play, including forks.
func TestTicTacToeNeverLoses(t *testing.T) {
	for _, ai := range []byte{'X', 'O'} {
		var play func([9]byte, byte)
		play = func(b [9]byte, p byte) {
			if wins(b, other(ai)) {
				t.Fatalf("AI %c lost on %s", ai, b)
			}
			if wins(b, ai) {
				return
			}
			if p != ai {
				for i, c := range b {
					if c == '.' {
						b[i] = p
						play(b, other(p))
						b[i] = '.'
					}
				}
				return
			}
			d, err := Solve(State{Game: "tic_tac_toe", Board: []string{string(b[:3]), string(b[3:6]), string(b[6:])}, Player: string(p)})
			if err != nil {
				t.Fatal(err)
			}
			if d.Terminal {
				return
			}
			var move int
			if _, err := fmt.Sscanf(d.Action, "cell_%d", &move); err != nil || move < 0 || move > 8 || b[move] != '.' {
				t.Fatalf("illegal action: %+v on %s", d, b)
			}
			b[move] = p
			play(b, other(p))
		}
		play([9]byte{'.', '.', '.', '.', '.', '.', '.', '.', '.'}, 'X')
	}
}

func TestInvalidAndTerminal(t *testing.T) {
	for _, s := range []State{
		{Game: "chess"}, {Game: "tic_tac_toe", Board: []string{"OO.", "...", "..."}},
		{Game: "tic_tac_toe", Board: []string{"XXX", "OOO", "..."}},
		{Game: "tic_tac_toe", Board: []string{"X..", "...", "..."}, Player: "X"},
		{Game: "maze", Grid: []string{"S*G"}}, {Game: "maze", Grid: []string{"S.", "G"}},
	} {
		if _, err := Solve(s); err == nil {
			t.Fatalf("accepted invalid %+v", s)
		}
	}
	for _, s := range []State{
		{Game: "tic_tac_toe", Board: []string{"XXX", "OO.", "..."}},
		{Game: "tic_tac_toe", Board: []string{"XOX", "XOO", "OXX"}},
		{Game: "maze", Grid: []string{"*"}},
	} {
		d, err := Solve(s)
		if err != nil || !d.Terminal || d.Action != "" {
			t.Fatalf("terminal: %+v %v", d, err)
		}
	}
}

func TestMazeSafeShortestPath(t *testing.T) {
	d, err := Solve(State{Game: "maze", Grid: []string{"SXG", "..."}})
	if err != nil || d.Action != "down" || len(d.Path) != 5 {
		t.Fatalf("%+v %v", d, err)
	}
	d, err = Solve(State{Game: "maze", Grid: []string{"S#G"}})
	if err != nil || d.Action != "" || d.Outcome != "unreachable" {
		t.Fatalf("%+v %v", d, err)
	}
}
