package games

import (
	"context"
	"fmt"
	"sort"
)

type tetBoard struct {
	rows [24]uint32
	w, h int
}
type tetShape [4]Point

var tetBase = map[string]tetShape{
	"I": {{0, 1}, {1, 1}, {2, 1}, {3, 1}}, "O": {{1, 0}, {2, 0}, {1, 1}, {2, 1}},
	"T": {{1, 0}, {0, 1}, {1, 1}, {2, 1}}, "J": {{0, 0}, {0, 1}, {1, 1}, {2, 1}},
	"L": {{2, 0}, {0, 1}, {1, 1}, {2, 1}}, "S": {{1, 0}, {2, 0}, {0, 1}, {1, 1}}, "Z": {{0, 0}, {1, 0}, {1, 1}, {2, 1}},
}

func rotations(piece string) [4]tetShape {
	var shapes [4]tetShape
	shapes[0] = tetBase[piece]
	for r := 1; r < 4; r++ {
		for i, p := range shapes[r-1] {
			if piece == "O" {
				shapes[r][i] = p
			} else {
				center2 := 2
				if piece == "I" {
					center2 = 3
				}
				shapes[r][i] = Point{center2 - p.Y, p.X}
			}
		}
	}
	return shapes
}

// SRS kick offsets, converted to screen coordinates (positive Y is down).
var normalKicks = map[[2]int][5]Point{
	{0, 1}: {{0, 0}, {-1, 0}, {-1, -1}, {0, 2}, {-1, 2}}, {1, 0}: {{0, 0}, {1, 0}, {1, 1}, {0, -2}, {1, -2}},
	{1, 2}: {{0, 0}, {1, 0}, {1, 1}, {0, -2}, {1, -2}}, {2, 1}: {{0, 0}, {-1, 0}, {-1, -1}, {0, 2}, {-1, 2}},
	{2, 3}: {{0, 0}, {1, 0}, {1, -1}, {0, 2}, {1, 2}}, {3, 2}: {{0, 0}, {-1, 0}, {-1, 1}, {0, -2}, {-1, -2}},
	{3, 0}: {{0, 0}, {-1, 0}, {-1, 1}, {0, -2}, {-1, -2}}, {0, 3}: {{0, 0}, {1, 0}, {1, -1}, {0, 2}, {1, 2}},
}
var iKicks = map[[2]int][5]Point{
	{0, 1}: {{0, 0}, {-2, 0}, {1, 0}, {-2, 1}, {1, -2}}, {1, 0}: {{0, 0}, {2, 0}, {-1, 0}, {2, -1}, {-1, 2}},
	{1, 2}: {{0, 0}, {-1, 0}, {2, 0}, {-1, -2}, {2, 1}}, {2, 1}: {{0, 0}, {1, 0}, {-2, 0}, {1, 2}, {-2, -1}},
	{2, 3}: {{0, 0}, {2, 0}, {-1, 0}, {2, -1}, {-1, 2}}, {3, 2}: {{0, 0}, {-2, 0}, {1, 0}, {-2, 1}, {1, -2}},
	{3, 0}: {{0, 0}, {1, 0}, {-2, 0}, {1, 2}, {-2, -1}}, {0, 3}: {{0, 0}, {-1, 0}, {2, 0}, {-1, -2}, {2, 1}},
}

func parseTetris(s State) (tetBoard, error) {
	b := tetBoard{h: len(s.Grid)}
	if b.h < 4 || b.h > 24 {
		return b, fmt.Errorf("tetris grid needs 4..24 rows")
	}
	b.w = len(s.Grid[0])
	if b.w < 4 || b.w > 16 {
		return b, fmt.Errorf("tetris grid needs 4..16 columns")
	}
	if _, ok := tetBase[s.Piece]; !ok {
		return b, fmt.Errorf("piece must be I, O, T, S, Z, J or L")
	}
	if s.Next != "" {
		if _, ok := tetBase[s.Next]; !ok {
			return b, fmt.Errorf("invalid next piece")
		}
	}
	for y, row := range s.Grid {
		if len(row) != b.w {
			return b, fmt.Errorf("tetris grid must be rectangular")
		}
		for x := 0; x < b.w; x++ {
			switch row[x] {
			case '#':
				b.rows[y] |= 1 << x
			case '.':
			default:
				return b, fmt.Errorf("grid contains locked # cells and empty . cells only")
			}
		}
		if b.rows[y] == uint32(1<<b.w)-1 {
			return b, fmt.Errorf("observe tetris after completed rows have cleared")
		}
	}
	return b, nil
}
func (b tetBoard) fits(p Placement, shape tetShape) bool {
	if p.X < -3 || p.X >= b.w || p.Y < -4 || p.Y >= b.h {
		return false
	}
	for _, c := range shape {
		x, y := p.X+c.X, p.Y+c.Y
		if x < 0 || x >= b.w || y >= b.h {
			return false
		}
		if y >= 0 && b.rows[y]&(1<<x) != 0 {
			return false
		}
	}
	return true
}
func (b tetBoard) lock(p Placement, shape tetShape) (tetBoard, int, bool) {
	for _, c := range shape {
		x, y := p.X+c.X, p.Y+c.Y
		if y < 0 {
			return b, 0, false
		}
		b.rows[y] |= 1 << x
	}
	cleared, write := 0, b.h-1
	full := uint32(1<<b.w) - 1
	for y := b.h - 1; y >= 0; y-- {
		if b.rows[y] == full {
			cleared++
			continue
		}
		b.rows[write] = b.rows[y]
		write--
	}
	for ; write >= 0; write-- {
		b.rows[write] = 0
	}
	return b, cleared, true
}
func (b tetBoard) evaluate(lines int) int {
	heights := make([]int, b.w)
	holes, aggregate, maxHeight := 0, 0, 0
	for x := 0; x < b.w; x++ {
		found := false
		for y := 0; y < b.h; y++ {
			if b.rows[y]&(1<<x) != 0 {
				if !found {
					heights[x] = b.h - y
					found = true
				}
			} else if found {
				holes++
			}
		}
		aggregate += heights[x]
		if heights[x] > maxHeight {
			maxHeight = heights[x]
		}
	}
	bump, wells := 0, 0
	for x, h := range heights {
		if x > 0 {
			d := h - heights[x-1]
			if d < 0 {
				d = -d
			}
			bump += d
		}
		left, right := b.h, b.h
		if x > 0 {
			left = heights[x-1]
		}
		if x+1 < b.w {
			right = heights[x+1]
		}
		if right < left {
			left = right
		}
		if left > h {
			wells += left - h
		}
	}
	return 100*lines - 48*holes - 5*aggregate - 8*bump - 4*wells - 3*maxHeight*maxHeight
}

type tetNode struct {
	pose    Placement
	parent  int
	control string
}
type tetCandidate struct {
	pose                 Placement
	board                tetBoard
	cleared, score, node int
}

func tetIndex(p Placement, w int) int { return ((p.Y+4)*(w+3)+p.X+3)*4 + p.Rotation }

func (b tetBoard) placements(piece string, start Placement, budget *searchBudget) ([]tetCandidate, []tetNode, bool) {
	shapes := rotations(piece)
	if !b.fits(start, shapes[start.Rotation]) {
		return nil, nil, true
	}
	seen := make([]bool, (b.h+4)*(b.w+3)*4)
	landings := make([]bool, len(seen))
	seen[tetIndex(start, b.w)] = true
	nodes := []tetNode{{pose: start, parent: -1}}
	candidates := []tetCandidate{}
	for head := 0; head < len(nodes); head++ {
		if !budget.tick() {
			return candidates, nodes, false
		}
		p := nodes[head].pose
		// A hard drop is reachable immediately from every visited pose. Record it
		// before exploring deeper paths so even a short budget has a legal fallback.
		landing := p
		for q := p; ; {
			q.Y++
			if !b.fits(q, shapes[p.Rotation]) {
				break
			}
			landing = q
		}
		li := tetIndex(landing, b.w)
		if !landings[li] {
			landings[li] = true
			after, cleared, ok := b.lock(landing, shapes[p.Rotation])
			if ok {
				candidates = append(candidates, tetCandidate{landing, after, cleared, after.evaluate(cleared), head})
			}
		}
		down := p
		down.Y++
		add := func(q Placement, control string) {
			if !b.fits(q, shapes[q.Rotation]) {
				return
			}
			i := tetIndex(q, b.w)
			if !seen[i] {
				seen[i] = true
				nodes = append(nodes, tetNode{q, head, control})
			}
		}
		add(Placement{p.X - 1, p.Y, p.Rotation}, "left")
		add(Placement{p.X + 1, p.Y, p.Rotation}, "right")
		add(down, "down")
		if piece != "O" {
			for _, turn := range []int{1, 3} {
				rotation := (p.Rotation + turn) % 4
				kicks := normalKicks[[2]int{p.Rotation, rotation}]
				if piece == "I" {
					kicks = iKicks[[2]int{p.Rotation, rotation}]
				}
				for _, k := range kicks {
					q := Placement{p.X + k.X, p.Y + k.Y, rotation}
					if b.fits(q, shapes[rotation]) {
						control := "cw"
						if turn == 3 {
							control = "ccw"
						}
						add(q, control)
						break
					}
				}
			}
		}
	}
	return candidates, nodes, true
}

func solveTetris(ctx context.Context, s State) (Decision, error) {
	b, err := parseTetris(s)
	if err != nil {
		return Decision{}, err
	}
	start := Placement{X: b.w/2 - 2, Y: -2}
	if s.Active != nil {
		start = *s.Active
	}
	if start.Rotation < 0 || start.Rotation > 3 || start.X < -3 || start.X >= b.w || start.Y < -4 || start.Y >= b.h {
		return Decision{}, fmt.Errorf("invalid active piece position")
	}
	if s.Piece == "O" && start.Rotation != 0 {
		return Decision{}, fmt.Errorf("O rotation must be 0")
	}
	shapes := rotations(s.Piece)
	if !b.fits(start, shapes[start.Rotation]) {
		if s.Active != nil {
			return Decision{}, fmt.Errorf("active piece overlaps the board or boundary")
		}
		return Decision{Terminal: true, Outcome: "top_out", Reason: "The spawn position is blocked."}, nil
	}
	budget := newBudget(ctx, 16000)
	candidates, nodes, complete := b.placements(s.Piece, start, budget)
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	if len(candidates) == 0 {
		if !complete {
			return Decision{}, fmt.Errorf("tetris search budget exhausted before finding a safe placement")
		}
		return Decision{Terminal: true, Outcome: "top_out", Reason: "No reachable placement fits entirely inside the board."}, nil
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })
	best, depth := candidates[0], 1
	bestValue := -1 << 30
	if s.Next != "" && complete {
		beam := 4
		if len(candidates) < beam {
			beam = len(candidates)
		}
		all := true
		for _, candidate := range candidates[:beam] {
			next, _, ok := candidate.board.placements(s.Next, Placement{X: b.w/2 - 2, Y: -2}, budget)
			if !ok {
				all = false
				break
			}
			value := -1 << 28
			for _, n := range next {
				score := candidate.cleared*100 + n.score
				if score > value {
					value = score
				}
			}
			if value > bestValue {
				bestValue = value
				best = candidate
			}
		}
		// Avoid comparing candidates with different search horizons.
		if all {
			depth = 2
		} else {
			best = candidates[0]
		}
	}
	if err := ctx.Err(); err != nil {
		return Decision{}, err
	}
	controls := []string{}
	for i := best.node; nodes[i].parent >= 0; i = nodes[i].parent {
		controls = append(controls, nodes[i].control)
	}
	for i, j := 0, len(controls)-1; i < j; i, j = i+1, j-1 {
		controls[i], controls[j] = controls[j], controls[i]
	}
	controls = append(controls, "hard_drop")
	return Decision{Action: fmt.Sprintf("place_%d_%d_%d", best.pose.Rotation, best.pose.X, best.pose.Y), Placement: &best.pose, Controls: controls, Cleared: best.cleared, Heuristic: true, Search: &SearchInfo{Nodes: budget.nodes, Depth: depth, Limited: budget.stopped}, Reason: "Reachable SRS placement; evaluates holes, stack height, unevenness and cleared rows. Next-piece lookahead examines the four best immediate placements."}, nil
}
