package semai

import (
	"fmt"
	"math"
	"strings"
)

// reading is one way of understanding the question together with the answer it yields.
type reading struct {
	ID     string
	Title  string
	Detail string
	W      float64
	Val    float64
}

// outcome is what a solver returns: weighted readings of the question + side notes.
type outcome struct {
	Solver    string
	Unit      string
	Readings  []reading
	Notes     []string
	Certainty float64 // reliability of the underlying knowledge, 0..1
	Failure   string  // set when the solver recognised the task but cannot answer
	FailCode  string
}

func isInt(v float64) bool { return math.Abs(v-math.Round(v)) < 1e-9 }

func piece(p partCount, f float64, head bool) int {
	lo, hi := 0.0, f
	if !head {
		lo, hi = 1-f, 1
	}
	n := 0
	for r := 0; r < 4; r++ {
		a, b := math.Max(lo, regionSpan[r][0]), math.Min(hi, regionSpan[r][1])
		if b > a && (b-a)/(regionSpan[r][1]-regionSpan[r][0]) >= 0.5 {
			n += p.N[r]
		}
	}
	return n
}

var fracNames = map[float64]string{0.5: "половина", 0.25: "четверть", 0.75: "три четверти"}

func describeFrac(f float64) string {
	if s, ok := fracNames[f]; ok {
		return s
	}
	return fmt.Sprintf("%s%% особи", fmtNum(math.Round(f*1000)/10))
}

// readingsFor lists how "c items of entity" can be understood for a part.
func readingsFor(c float64, pc partCount, ent *entity) []reading {
	n := float64(pc.Total())
	if isInt(c) {
		return []reading{{ID: "whole", Title: "Целые существа", Detail: fmt.Sprintf("%s × %d", fmtNum(c), pc.Total()), W: 1, Val: math.Round(c) * n}}
	}
	k := math.Floor(c)
	f := c - k
	name := ent.Title
	rs := []reading{
		{ID: "floor", Title: "Считаем только целых", Detail: fmt.Sprintf("%s целых — остаток (%s) не считается: %s × %d", fmtNum(k), describeFrac(f), fmtNum(k), pc.Total()), Val: k * n},
		{ID: "ceil", Title: "Часть считается за целое", Detail: fmt.Sprintf("неполный экземпляр (%s) тоже «%s»: %s × %d", describeFrac(f), name, fmtNum(k+1), pc.Total()), Val: (k + 1) * n},
		{ID: "prop", Title: "Продольный разрез (вертикально)", Detail: fmt.Sprintf("делим вдоль: от каждой детали остаётся доля %s → %s × %d", fmtNum(math.Round(f*1000)/1000), fmtNum(c), pc.Total()), Val: c * n},
	}
	if pc.Regional {
		h, t := float64(piece(pc, f, true)), float64(piece(pc, f, false))
		rs = append(rs,
			reading{ID: "head", Title: "Поперечный разрез — осталась голова", Detail: fmt.Sprintf("%s целых + передняя часть (%s) с головой: %s×%d + %d", fmtNum(k), describeFrac(f), fmtNum(k), pc.Total(), int(h)), Val: k*n + h},
			reading{ID: "tail", Title: "Поперечный разрез — головы нет", Detail: fmt.Sprintf("%s целых + задняя часть (%s) без головы: %s×%d + %d", fmtNum(k), describeFrac(f), fmtNum(k), pc.Total(), int(t)), Val: k*n + t})
		w := []float64{.15, .15, .2, .25, .25}
		for i := range rs {
			rs[i].W = w[i]
		}
	} else {
		w := []float64{.3, .3, .4}
		for i := range rs {
			rs[i].W = w[i]
		}
	}
	return rs
}

type pair struct {
	Count   float64
	Ent     *entity
	Assumed bool
	Surface string
}

// solvePartCount answers "how many <part> do <N> <thing> have" with ambiguity-aware readings.
func solvePartCount(stemText string) *outcome {
	toks := tokens(stemText)
	var pk *partKind
	pIdx := -1
	for i, t := range toks {
		if isWord(t) {
			if p := findPart(t); p != nil {
				// the first part word wins unless it is also an entity
				if findEntity(t) == nil {
					pk, pIdx = p, i
					break
				}
			}
		}
	}
	if pk == nil {
		return nil
	}
	nums := FindNumbers(toks)
	var pairs []pair
	for i, t := range toks {
		if i == pIdx || !isWord(t) {
			continue
		}
		ent := findEntity(t)
		if ent == nil {
			continue
		}
		pr := pair{Count: 1, Ent: ent, Assumed: true, Surface: t}
		for _, n := range nums {
			if n.T1 <= i && i-n.T1 <= 2 {
				pr.Count, pr.Assumed = n.Val, false
			}
		}
		pairs = append(pairs, pr)
	}
	if len(pairs) == 0 {
		asksCount := len(nums) > 0
		for _, t := range toks {
			if t == "сколько" || t == "how" || t == "many" {
				asksCount = true
			}
		}
		if !asksCount {
			return nil
		}
		return &outcome{Solver: "part_count", Unit: pk.Title, FailCode: "missing_subject", Failure: fmt.Sprintf("Не указано, у кого или у чего считать «%s» — без объекта вопрос не определён (у мыши, паука, человека ответы разные).", pk.Title)}
	}
	if len(pairs) > 4 {
		pairs = pairs[:4]
	}
	out := &outcome{Solver: "part_count", Unit: pk.Title, Certainty: 0.97}
	dist := []reading{{ID: "", W: 1}}
	var titles []string
	for _, pr := range pairs {
		pc, ok := pr.Ent.Parts[pk.ID]
		if !ok {
			out.FailCode = "no_knowledge"
			out.Failure = fmt.Sprintf("В базе знаний нет данных, сколько «%s» у «%s».", pk.Title, pr.Ent.Title)
			return out
		}
		if pr.Assumed {
			out.Notes = append(out.Notes, fmt.Sprintf("Количество «%s» не указано — принято 1.", pr.Surface))
		}
		out.Notes = append(out.Notes, fmt.Sprintf("Знание: %s → %s: %d на экземпляр.", pr.Ent.Title, pk.Title, pc.Total()))
		rs := readingsFor(pr.Count, pc, pr.Ent)
		if len(rs) > 1 {
			titles = append(titles, pr.Ent.Title)
		}
		var next []reading
		for _, a := range dist {
			for _, b := range rs {
				id, title, detail := b.ID, b.Title, b.Detail
				if a.ID != "" {
					id, title, detail = a.ID+"+"+b.ID, a.Title+" · "+b.Title, a.Detail+"; "+b.Detail
				}
				next = append(next, reading{ID: id, Title: title, Detail: detail, W: a.W * b.W, Val: a.Val + b.Val})
			}
		}
		dist = next
	}
	if len(pairs) > 1 && len(dist) == 1 {
		dist[0].Title = "Сумма по всем объектам"
		var parts []string
		for _, pr := range pairs {
			pc := pr.Ent.Parts[pk.ID]
			parts = append(parts, fmt.Sprintf("%s×%d", fmtNum(pr.Count), pc.Total()))
		}
		dist[0].Detail = strings.Join(parts, " + ")
	}
	_ = titles
	out.Readings = dist
	return out
}
