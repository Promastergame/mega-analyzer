// Package games plans legal moves from explicit, observed game states.
package games

import (
	"context"
	"fmt"
	"time"
)

type State struct {
	Game     string     `json:"game"`
	Board    []string   `json:"board,omitempty"`
	Player   string     `json:"player,omitempty"`
	Grid     []string   `json:"grid,omitempty"`
	Piece    string     `json:"piece,omitempty"`
	Next     string     `json:"next,omitempty"`
	Active   *Placement `json:"active,omitempty"`
	Revision string     `json:"revision,omitempty"`
}

type Placement struct {
	X        int `json:"x"`
	Y        int `json:"y"`
	Rotation int `json:"rotation"`
}

type SearchInfo struct {
	Nodes   int  `json:"nodes"`
	Depth   int  `json:"depth"`
	Limited bool `json:"limited"`
}

type Point struct {
	X int `json:"x"`
	Y int `json:"y"`
}
type Decision struct {
	Action    string      `json:"action,omitempty"`
	Terminal  bool        `json:"terminal"`
	Outcome   string      `json:"outcome,omitempty"`
	Reason    string      `json:"reason"`
	Path      []Point     `json:"path,omitempty"`
	Controls  []string    `json:"controls,omitempty"`
	Placement *Placement  `json:"placement,omitempty"`
	Cleared   int         `json:"cleared,omitempty"`
	Captures  []Point     `json:"captures,omitempty"`
	Heuristic bool        `json:"heuristic,omitempty"`
	Search    *SearchInfo `json:"search,omitempty"`
	Source    string      `json:"source,omitempty"`
	Observed  *State      `json:"observed,omitempty"`
}

func SupportedGames() []string { return []string{"tic_tac_toe", "maze", "tetris", "russian_checkers"} }
func Supported(game string) bool {
	for _, g := range SupportedGames() {
		if g == game {
			return true
		}
	}
	return false
}

func Solve(s State) (Decision, error) {
	return SolveContext(context.Background(), s)
}

func SolveContext(ctx context.Context, s State) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	switch s.Game {
	case "tic_tac_toe":
		return ticTacToe(s)
	case "maze":
		return maze(s)
	case "tetris":
		return solveTetris(ctx, s)
	case "russian_checkers":
		return solveCheckers(ctx, s)
	default:
		return Decision{}, fmt.Errorf("unsupported game %q; supported: %v", s.Game, SupportedGames())
	}
}

// Bounded search is local to a request: no persistent tree or growing cache.
// The deadline is best effort; OS scheduling is outside the search's control.
type searchBudget struct {
	ctx          context.Context
	deadline     time.Time
	nodes, limit int
	stopped      bool
}

func newBudget(ctx context.Context, limit int) *searchBudget {
	return &searchBudget{ctx: ctx, deadline: time.Now().Add(18 * time.Millisecond), limit: limit}
}
func (b *searchBudget) tick() bool {
	if b.stopped {
		return false
	}
	b.nodes++
	if b.nodes > b.limit || (b.nodes%16 == 0 && (b.ctx.Err() != nil || time.Now().After(b.deadline))) {
		b.stopped = true
		return false
	}
	return true
}

var lines = [8][3]int{{0, 1, 2}, {3, 4, 5}, {6, 7, 8}, {0, 3, 6}, {1, 4, 7}, {2, 5, 8}, {0, 4, 8}, {2, 4, 6}}
var moveOrder = []int{4, 0, 2, 6, 8, 1, 3, 5, 7}

func wins(b [9]byte, p byte) bool {
	for _, l := range lines {
		if b[l[0]] == p && b[l[1]] == p && b[l[2]] == p {
			return true
		}
	}
	return false
}
func other(p byte) byte {
	if p == 'X' {
		return 'O'
	}
	return 'X'
}

func ticTacToe(s State) (Decision, error) {
	var b [9]byte
	if len(s.Board) != 3 {
		return Decision{}, fmt.Errorf("board must contain three rows of X, O or .")
	}
	x, o := 0, 0
	for y, row := range s.Board {
		if len(row) != 3 {
			return Decision{}, fmt.Errorf("board rows must contain three ASCII cells")
		}
		for i := range row {
			b[y*3+i] = row[i]
			switch row[i] {
			case 'X':
				x++
			case 'O':
				o++
			case '.':
			default:
				return Decision{}, fmt.Errorf("invalid board cell %q", row[i])
			}
		}
	}
	xw, ow := wins(b, 'X'), wins(b, 'O')
	if o > x || x-o > 1 || (xw && ow) || (xw && x != o+1) || (ow && x != o) {
		return Decision{}, fmt.Errorf("unreachable board: X starts and turns alternate")
	}
	if s.Player != "" && s.Player != "X" && s.Player != "O" {
		return Decision{}, fmt.Errorf("player must be X or O")
	}
	if xw || ow {
		winner := "X"
		if ow {
			winner = "O"
		}
		return Decision{Terminal: true, Outcome: winner + "_won", Reason: "The game has ended; no move is legal."}, nil
	}
	if x+o == 9 {
		return Decision{Terminal: true, Outcome: "draw", Reason: "The board is full."}, nil
	}
	p := byte('X')
	if x > o {
		p = 'O'
	}
	if s.Player != "" && s.Player[0] != p {
		return Decision{}, fmt.Errorf("it is %c's turn, not %s's", p, s.Player)
	}
	best, move := -100, -1
	for _, i := range moveOrder {
		if b[i] != '.' {
			continue
		}
		b[i] = p
		v := -search(b, other(p), 1, -100, -best)
		b[i] = '.'
		if v > best {
			best, move = v, i
		}
	}
	outcome := "draw"
	if best > 0 {
		outcome = "win"
	}
	if best < 0 {
		outcome = "loss"
	}
	return Decision{Action: fmt.Sprintf("cell_%d", move), Outcome: outcome, Reason: "Full minimax search: expected " + outcome + " with optimal play from both sides."}, nil
}

func search(b [9]byte, p byte, depth, alpha, beta int) int {
	if wins(b, other(p)) {
		return depth - 10
	}
	best := -100
	for _, i := range moveOrder {
		if b[i] != '.' {
			continue
		}
		b[i] = p
		v := -search(b, other(p), depth+1, -beta, -alpha)
		b[i] = '.'
		if v > best {
			best = v
		}
		if v > alpha {
			alpha = v
		}
		if alpha >= beta {
			break
		}
	}
	if best == -100 {
		return 0
	}
	return best
}

func maze(s State) (Decision, error) {
	if len(s.Grid) == 0 || len(s.Grid) > 128 || len(s.Grid[0]) == 0 || len(s.Grid[0]) > 128 {
		return Decision{}, fmt.Errorf("grid must be 1..128 rows and columns")
	}
	w := len(s.Grid[0])
	start, goal := -1, -1
	for y, row := range s.Grid {
		if len(row) != w {
			return Decision{}, fmt.Errorf("grid must be rectangular")
		}
		for x := range row {
			i := y*w + x
			switch row[x] {
			case 'S':
				if start != -1 {
					return Decision{}, fmt.Errorf("multiple starts")
				}
				start = i
			case 'G':
				if goal != -1 {
					return Decision{}, fmt.Errorf("multiple goals")
				}
				goal = i
			case '*':
				if start != -1 || goal != -1 {
					return Decision{}, fmt.Errorf("duplicate start or goal")
				}
				start, goal = i, i
			case '.', '#', 'X':
			default:
				return Decision{}, fmt.Errorf("unknown grid cell %q", row[x])
			}
		}
	}
	if start < 0 || goal < 0 {
		return Decision{}, fmt.Errorf("grid needs S and G, or * when at the goal")
	}
	if start == goal {
		return Decision{Terminal: true, Outcome: "goal", Reason: "Already at the goal."}, nil
	}
	prev := make([]int, w*len(s.Grid))
	for i := range prev {
		prev[i] = -1
	}
	prev[start] = start
	queue := []int{start}
	dirs := []Point{{0, -1}, {1, 0}, {0, 1}, {-1, 0}}
	for head := 0; head < len(queue) && prev[goal] < 0; head++ {
		i := queue[head]
		for _, d := range dirs {
			x, y := i%w+d.X, i/w+d.Y
			if x < 0 || x >= w || y < 0 || y >= len(s.Grid) {
				continue
			}
			n := y*w + x
			c := s.Grid[y][x]
			if prev[n] >= 0 || c == '#' || c == 'X' {
				continue
			}
			prev[n] = i
			queue = append(queue, n)
		}
	}
	if prev[goal] < 0 {
		return Decision{Outcome: "unreachable", Reason: "No safe path to the goal; no action selected."}, nil
	}
	path := []Point{}
	for i := goal; ; i = prev[i] {
		path = append(path, Point{i % w, i / w})
		if i == start {
			break
		}
	}
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	dx, dy := path[1].X-path[0].X, path[1].Y-path[0].Y
	action := "up"
	if dx == 1 {
		action = "right"
	}
	if dx == -1 {
		action = "left"
	}
	if dy == 1 {
		action = "down"
	}
	return Decision{Action: action, Path: path, Reason: "Shortest safe path; walls (#) and hazards (X) are blocked."}, nil
}
