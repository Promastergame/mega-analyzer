// Package arena implements a visible local game. Its rules never call a solver.
// DecisionAI observes only Render's PNG, exactly as displayed in the browser.
package arena

import (
	"context"
	"fmt"
	"decisionai/games"
	"math/rand/v2"
	"slices"
)

type World struct {
	State        games.State
	Moves, Lines int
	Status       string
	Selected     []games.Point
	bag          []string
}

func New(game string) (*World, error) {
	w := &World{Status: "playing", State: games.State{Game: game}}
	switch game {
	case "tetris":
		for i := 0; i < 20; i++ {
			w.State.Grid = append(w.State.Grid, "..........")
		}
		w.spawn()
	case "russian_checkers":
		w.State.Board = []string{".b.b.b.b", "b.b.b.b.", ".b.b.b.b", "........", "........", "w.w.w.w.", ".w.w.w.w", "w.w.w.w."}
		w.State.Player = "white"
	default:
		return nil, fmt.Errorf("arena supports tetris and russian_checkers")
	}
	return w, nil
}

func (w *World) spawn() {
	if len(w.bag) == 0 {
		w.bag = []string{"I", "O", "T", "S", "Z", "J", "L"}
		rand.Shuffle(7, func(i, j int) { w.bag[i], w.bag[j] = w.bag[j], w.bag[i] })
	}
	w.State.Piece = w.bag[0]
	w.bag = w.bag[1:]
	w.State.Active = &games.Placement{X: 3, Y: 0}
	cells, _ := games.TetrisCells(w.State.Piece, *w.State.Active)
	for _, p := range cells {
		if w.State.Grid[p.Y][p.X] == '#' {
			w.Status = "top_out"
		}
	}
}

func (w *World) Control(controls []string, canonical bool) error {
	if w.State.Game != "tetris" || w.Status != "playing" {
		return fmt.Errorf("tetris is not running")
	}
	if len(controls) < 1 || len(controls) > 512 {
		return fmt.Errorf("need 1..512 controls")
	}
	s := w.State
	s.Grid = slices.Clone(s.Grid)
	if canonical {
		cells, _ := games.TetrisCells(s.Piece, *s.Active)
		_, pose, err := games.MatchTetrisCells(cells)
		if err != nil {
			return err
		}
		s.Active = pose
	}
	after, lines, dropped, err := games.StepTetris(s, controls)
	if err != nil {
		return err
	}
	w.State = after
	if dropped {
		w.Moves++
		w.Lines += lines
		w.spawn()
	}
	return nil
}

func (w *World) Apply(ctx context.Context, d games.Decision) error {
	if w.Status != "playing" {
		return fmt.Errorf("game is finished")
	}
	if w.State.Game == "tetris" {
		if len(d.Controls) == 0 || d.Controls[len(d.Controls)-1] != "hard_drop" {
			return fmt.Errorf("AI move must finish with hard_drop")
		}
		return w.Control(d.Controls, true)
	}
	moves, err := games.LegalCheckers(ctx, w.State)
	if err != nil {
		return err
	}
	for _, m := range moves {
		if slices.Equal(m.Path, d.Path) {
			s := w.State
			s.Board = m.Board
			if s.Player == "white" {
				s.Player = "black"
			} else {
				s.Player = "white"
			}
			next, err := games.LegalCheckers(ctx, s)
			if err != nil {
				return err
			}
			w.State = s
			w.Moves++
			w.Selected = nil
			if len(next) == 0 {
				w.Status = "white_wins"
				if s.Player == "white" {
					w.Status = "black_wins"
				}
			}
			if w.Moves >= 300 && w.Status == "playing" {
				w.Status = "move_limit"
			}
			return nil
		}
	}
	return fmt.Errorf("illegal or incomplete checker path")
}

func (w *World) Click(ctx context.Context, p games.Point) error {
	if w.State.Game != "russian_checkers" || w.Status != "playing" {
		return fmt.Errorf("checkers is not running")
	}
	if p.X < 0 || p.X >= 8 || p.Y < 0 || p.Y >= 8 {
		return fmt.Errorf("click outside board")
	}
	moves, err := games.LegalCheckers(ctx, w.State)
	if err != nil {
		return err
	}
	prefix := append(slices.Clone(w.Selected), p)
	for _, m := range moves {
		if len(m.Path) >= len(prefix) && slices.Equal(m.Path[:len(prefix)], prefix) {
			if len(m.Path) == len(prefix) {
				return w.Apply(ctx, games.Decision{Path: m.Path})
			}
			w.Selected = prefix
			return nil
		}
	}
	for _, m := range moves {
		if m.Path[0] == p {
			w.Selected = []games.Point{p}
			return nil
		}
	}
	w.Selected = nil
	return nil
}
