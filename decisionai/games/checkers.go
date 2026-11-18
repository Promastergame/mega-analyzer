package games

import (
	"context"
	"fmt"
	"math/bits"
	"sort"
	"strings"
)

type draughtBoard [64]byte
type draughtMove struct {
	board    draughtBoard
	path     [13]int
	length   int
	captured uint64
}

var diagonals = [4]Point{{-1, -1}, {1, -1}, {-1, 1}, {1, 1}}

func side(piece byte) byte {
	switch piece {
	case 'w', 'W':
		return 'w'
	case 'b', 'B':
		return 'b'
	}
	return 0
}
func enemy(player byte) byte {
	if player == 'w' {
		return 'b'
	}
	return 'w'
}
func king(piece byte) bool { return piece == 'W' || piece == 'B' }
func promote(piece byte, y int) byte {
	if piece == 'w' && y == 0 {
		return 'W'
	}
	if piece == 'b' && y == 7 {
		return 'B'
	}
	return piece
}
func square(x, y int) int {
	if x < 0 || x >= 8 || y < 0 || y >= 8 {
		return -1
	}
	return y*8 + x
}
func sideName(p byte) string {
	if p == 'w' {
		return "white"
	}
	return "black"
}

func parseCheckers(s State) (draughtBoard, byte, error) {
	var board draughtBoard
	player := byte(0)
	switch s.Player {
	case "white":
		player = 'w'
	case "black":
		player = 'b'
	default:
		return board, 0, fmt.Errorf("russian_checkers requires player white or black")
	}
	if len(s.Board) != 8 {
		return board, 0, fmt.Errorf("checkers board must contain eight rows")
	}
	counts := map[byte]int{}
	for y, row := range s.Board {
		if len(row) != 8 {
			return board, 0, fmt.Errorf("checkers rows must contain eight ASCII cells")
		}
		for x := 0; x < 8; x++ {
			p := row[x]
			if p != '.' && side(p) == 0 {
				return board, 0, fmt.Errorf("checkers cells are ., w, W, b or B")
			}
			if p != '.' {
				if (x+y)%2 != 1 {
					return board, 0, fmt.Errorf("piece at %d,%d is on a light square", x, y)
				}
				counts[side(p)]++
				if (p == 'w' && y == 0) || (p == 'b' && y == 7) {
					return board, 0, fmt.Errorf("man on promotion rank must already be a king")
				}
			}
			board[y*8+x] = p
		}
	}
	if counts['w'] > 12 || counts['b'] > 12 || counts['w']+counts['b'] == 0 {
		return board, 0, fmt.Errorf("checkers needs 1..24 pieces, at most 12 per side")
	}
	return board, player, nil
}

// Russian draughts: men capture in both directions; kings fly. Captured pieces
// stay on their squares and block rays until the complete turn has finished.
// A man crowns during a chain and continues capturing as a flying king.
func checkerMoves(board draughtBoard, player byte, budget *searchBudget) ([]draughtMove, bool) {
	moves := make([]draughtMove, 0, 16)
	var capture func(draughtBoard, int, [13]int, int, uint64) bool
	capture = func(b draughtBoard, from int, path [13]int, length int, taken uint64) bool {
		if !budget.tick() {
			return false
		}
		piece := b[from]
		found := false
		jump := func(to, victim int) bool {
			found = true
			next := b
			next[from] = '.'
			next[to] = promote(piece, to/8)
			nextPath := path
			if length >= len(nextPath) {
				budget.stopped = true
				return false
			}
			nextPath[length] = to
			return capture(next, to, nextPath, length+1, taken|(uint64(1)<<victim))
		}
		for _, d := range diagonals {
			x, y := from%8+d.X, from/8+d.Y
			if !king(piece) {
				victim, to := square(x, y), square(x+d.X, y+d.Y)
				if victim >= 0 && to >= 0 && side(b[victim]) == enemy(player) && taken&(uint64(1)<<victim) == 0 && b[to] == '.' {
					if !jump(to, victim) {
						return false
					}
				}
				continue
			}
			for square(x, y) >= 0 && b[square(x, y)] == '.' {
				x += d.X
				y += d.Y
			}
			victim := square(x, y)
			if victim < 0 || side(b[victim]) != enemy(player) || taken&(uint64(1)<<victim) != 0 {
				continue
			}
			x += d.X
			y += d.Y
			for to := square(x, y); to >= 0 && b[to] == '.'; to = square(x, y) {
				if !jump(to, victim) {
					return false
				}
				x += d.X
				y += d.Y
			}
		}
		if !found && taken != 0 {
			for bitsLeft := taken; bitsLeft != 0; bitsLeft &= bitsLeft - 1 {
				b[bits.TrailingZeros64(bitsLeft)] = '.'
			}
			moves = append(moves, draughtMove{b, path, length, taken})
			if len(moves) >= 2048 {
				budget.stopped = true
				return false
			}
		}
		return true
	}
	for from, piece := range board {
		if side(piece) == player {
			var path [13]int
			path[0] = from
			if !capture(board, from, path, 1, 0) {
				return moves, false
			}
		}
	}
	if len(moves) > 0 {
		return moves, true
	}
	for from, piece := range board {
		if side(piece) != player {
			continue
		}
		if !budget.tick() {
			return nil, false
		}
		for _, d := range diagonals {
			if !king(piece) && ((player == 'w' && d.Y > 0) || (player == 'b' && d.Y < 0)) {
				continue
			}
			x, y := from%8+d.X, from/8+d.Y
			for to := square(x, y); to >= 0 && board[to] == '.'; to = square(x, y) {
				next := board
				next[from] = '.'
				next[to] = promote(piece, y)
				moves = append(moves, draughtMove{board: next, path: [13]int{from, to}, length: 2})
				if !king(piece) {
					break
				}
				x += d.X
				y += d.Y
			}
		}
	}
	return moves, true
}

func checkerEval(board draughtBoard, player byte) int {
	score := 0
	for i, p := range board {
		if p == '.' {
			continue
		}
		v := 100
		y, x := i/8, i%8
		if king(p) {
			v = 330
		} else {
			advance := y
			if side(p) == 'w' {
				advance = 7 - y
			}
			v += advance * 4
		}
		if x >= 2 && x <= 5 && y >= 2 && y <= 5 {
			v += 7
		}
		if side(p) == player {
			score += v
		} else {
			score -= v
		}
	}
	return score
}
func orderCheckers(moves []draughtMove) {
	sort.SliceStable(moves, func(i, j int) bool {
		a, b := moves[i], moves[j]
		ac, bc := bits.OnesCount64(a.captured), bits.OnesCount64(b.captured)
		if ac != bc {
			return ac > bc
		}
		return king(a.board[a.path[a.length-1]]) && !king(b.board[b.path[b.length-1]])
	})
}
func checkerSearch(board draughtBoard, player byte, depth, ply, alpha, beta int, budget *searchBudget) (int, bool) {
	if !budget.tick() {
		return 0, false
	}
	moves, ok := checkerMoves(board, player, budget)
	if !ok {
		return 0, false
	}
	if len(moves) == 0 {
		return -100000 + ply, true
	}
	if depth == 0 {
		return checkerEval(board, player), true
	}
	orderCheckers(moves)
	best := -1000000
	for _, m := range moves {
		value, ok := checkerSearch(m.board, enemy(player), depth-1, ply+1, -beta, -alpha, budget)
		if !ok {
			return 0, false
		}
		value = -value
		if value > best {
			best = value
		}
		if value > alpha {
			alpha = value
		}
		if alpha >= beta {
			break
		}
	}
	return best, true
}

func solveCheckers(ctx context.Context, s State) (Decision, error) {
	board, player, err := parseCheckers(s)
	if err != nil {
		return Decision{}, err
	}
	budget := newBudget(ctx, 12000)
	moves, complete := checkerMoves(board, player, budget)
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if len(moves) == 0 {
		if !complete {
			return Decision{}, fmt.Errorf("checkers move generation budget exhausted")
		}
		return Decision{Terminal: true, Outcome: sideName(enemy(player)) + "_won", Reason: "The side to move has no legal moves."}, nil
	}
	// If the opponent has no pieces the game already ended, even if this side can move.
	hasOpponent := false
	for _, p := range board {
		if side(p) == enemy(player) {
			hasOpponent = true
			break
		}
	}
	if !hasOpponent {
		return Decision{Terminal: true, Outcome: sideName(player) + "_won", Reason: "The opponent has no pieces left."}, nil
	}
	orderCheckers(moves)
	best := moves[0]
	depthDone := 0
	if complete {
		for depth := 1; depth <= 6; depth++ {
			iterationBest := moves[0]
			score := -1000000
			done := true
			for _, m := range moves {
				v, ok := checkerSearch(m.board, enemy(player), depth-1, 1, -1000000, -score, budget)
				if !ok {
					done = false
					break
				}
				v = -v
				if v > score {
					score = v
					iterationBest = m
				}
			}
			if !done {
				break
			}
			best = iterationBest
			depthDone = depth
			if score >= 99900 {
				break
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	path := make([]Point, best.length)
	names := make([]string, best.length)
	for i, sq := range best.path[:best.length] {
		path[i] = Point{sq % 8, sq / 8}
		names[i] = fmt.Sprintf("%c%d", 'a'+sq%8, 8-sq/8)
	}
	separator := "-"
	if best.captured != 0 {
		separator = "x"
	}
	captures := []Point{}
	for taken := best.captured; taken != 0; taken &= taken - 1 {
		i := bits.TrailingZeros64(taken)
		captures = append(captures, Point{i % 8, i / 8})
	}
	return Decision{Action: strings.Join(names, separator), Path: path, Captures: captures, Heuristic: true, Search: &SearchInfo{Nodes: budget.nodes, Depth: depthDone, Limited: budget.stopped}, Reason: "Russian draughts: mandatory complete captures, backward man captures, flying kings and promotion during capture. Bounded iterative alpha-beta search; no strength or draw-history guarantee."}, nil
}
