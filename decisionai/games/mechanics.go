package games

import (
	"context"
	"fmt"
)

// TetrisCells exposes the occupied cells, without any game-state inference.
func TetrisCells(piece string, pose Placement) ([]Point, error) {
	if _, ok := tetBase[piece]; !ok || pose.Rotation < 0 || pose.Rotation > 3 {
		return nil, fmt.Errorf("invalid tetromino")
	}
	shape := rotations(piece)[pose.Rotation]
	cells := make([]Point, 4)
	for i, p := range shape {
		cells[i] = Point{pose.X + p.X, pose.Y + p.Y}
	}
	return cells, nil
}

// MatchTetrisCells reconstructs a canonical SRS pose from four visible squares.
// Symmetric shapes have indistinguishable rotations; use the lowest matching one.
func MatchTetrisCells(cells []Point) (string, *Placement, error) {
	if len(cells) != 4 {
		return "", nil, fmt.Errorf("need all four visible active cells")
	}
	set := map[Point]bool{}
	minX, minY := cells[0].X, cells[0].Y
	for _, p := range cells {
		set[p] = true
		minX = min(minX, p.X)
		minY = min(minY, p.Y)
	}
	if len(set) != 4 {
		return "", nil, fmt.Errorf("duplicate active cells")
	}
	for _, name := range []string{"I", "O", "T", "S", "Z", "J", "L"} {
		for r, shape := range rotations(name) {
			sx, sy := shape[0].X, shape[0].Y
			for _, p := range shape {
				sx = min(sx, p.X)
				sy = min(sy, p.Y)
			}
			pose := Placement{minX - sx, minY - sy, r}
			ok := true
			for _, p := range shape {
				if !set[Point{pose.X + p.X, pose.Y + p.Y}] {
					ok = false
					break
				}
			}
			if ok {
				return name, &pose, nil
			}
		}
	}
	return "", nil, fmt.Errorf("active pixels are not a tetromino")
}

// StepTetris applies real controls for the local game. It never selects a move.
func StepTetris(s State, controls []string) (State, int, bool, error) {
	b, err := parseTetris(s)
	if err != nil || s.Active == nil {
		return s, 0, false, fmt.Errorf("invalid active tetris state: %v", err)
	}
	p := *s.Active
	if p.Rotation < 0 || p.Rotation > 3 {
		return s, 0, false, fmt.Errorf("invalid rotation")
	}
	shapes := rotations(s.Piece)
	if !b.fits(p, shapes[p.Rotation]) {
		return s, 0, false, fmt.Errorf("blocked active piece")
	}
	for i, control := range controls {
		q := p
		switch control {
		case "left":
			q.X--
		case "right":
			q.X++
		case "down":
			q.Y++
		case "cw", "ccw":
			if s.Piece == "O" {
				continue
			}
			turn := 1
			if control == "ccw" {
				turn = 3
			}
			q.Rotation = (p.Rotation + turn) % 4
			kicks := normalKicks[[2]int{p.Rotation, q.Rotation}]
			if s.Piece == "I" {
				kicks = iKicks[[2]int{p.Rotation, q.Rotation}]
			}
			found := false
			for _, k := range kicks {
				candidate := Placement{p.X + k.X, p.Y + k.Y, q.Rotation}
				if b.fits(candidate, shapes[q.Rotation]) {
					q = candidate
					found = true
					break
				}
			}
			if !found {
				return s, 0, false, fmt.Errorf("blocked rotation")
			}
		case "hard_drop":
			if i != len(controls)-1 {
				return s, 0, false, fmt.Errorf("drop must be the last control")
			}
			for b.fits(Placement{q.X, q.Y + 1, q.Rotation}, shapes[q.Rotation]) {
				q.Y++
			}
			after, lines, ok := b.lock(q, shapes[q.Rotation])
			if !ok {
				return s, 0, false, fmt.Errorf("top out")
			}
			for y := range s.Grid {
				row := make([]byte, b.w)
				for x := range row {
					row[x] = '.'
					if after.rows[y]&(1<<x) != 0 {
						row[x] = '#'
					}
				}
				s.Grid[y] = string(row)
			}
			s.Active = &q
			return s, lines, true, nil
		default:
			return s, 0, false, fmt.Errorf("unknown tetris control")
		}
		if !b.fits(q, shapes[q.Rotation]) {
			return s, 0, false, fmt.Errorf("blocked control")
		}
		p = q
	}
	s.Active = &p
	return s, 0, false, nil
}

type CheckersMove struct {
	Path  []Point  `json:"path"`
	Board []string `json:"board"`
}

// LegalCheckers enumerates game rules only, for human input and action validation.
func LegalCheckers(ctx context.Context, s State) ([]CheckersMove, error) {
	b, p, err := parseCheckers(s)
	if err != nil {
		return nil, err
	}
	moves, ok := checkerMoves(b, p, newBudget(ctx, 12000))
	if !ok {
		return nil, fmt.Errorf("move enumeration interrupted")
	}
	out := make([]CheckersMove, 0, len(moves))
	for _, m := range moves {
		v := CheckersMove{}
		for _, i := range m.path[:m.length] {
			v.Path = append(v.Path, Point{i % 8, i / 8})
		}
		for y := 0; y < 8; y++ {
			v.Board = append(v.Board, string(m.board[y*8:y*8+8]))
		}
		out = append(out, v)
	}
	return out, nil
}
