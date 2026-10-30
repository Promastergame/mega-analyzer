package ml

import (
	"container/heap"
	"math"
	"sort"
)

// rankedPatchPoints retains the best FINAL candidates in O(n log k) time and
// O(k) memory. Input/worker order never decides a tied result. Identity includes
// the descriptor, so overloaded methods remain distinct.
type rankedPatchPoints struct {
	items     []PatchPoint
	positions map[string]int
	limit     int
	rank      func(*PatchPoint) float64
}

func newRankedPatchPoints(limit int, rank func(*PatchPoint) float64) *rankedPatchPoints {
	if limit < 0 {
		limit = 0
	}
	return &rankedPatchPoints{limit: limit, rank: rank, positions: make(map[string]int)}
}
func patchPointIdentity(p *PatchPoint) string {
	return patchLookupKey(p.FilePath, p.MethodName, p.MethodSignature) + "\x00" + p.ClassName + "\x00" + string(p.Category) + "\x00" + p.PatternID
}
func finiteRank(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return math.Inf(-1)
	}
	return v
}
func betterPatchPoint(a, b *PatchPoint, rank func(*PatchPoint) float64) bool {
	ar, br := finiteRank(rank(a)), finiteRank(rank(b))
	if ar != br {
		return ar > br
	}
	as, bs := finiteRank(a.RiskScore), finiteRank(b.RiskScore)
	if as != bs {
		return as > bs
	}
	ac, bc := finiteRank(a.Confidence), finiteRank(b.Confidence)
	if ac != bc {
		return ac > bc
	}
	return patchPointIdentity(a) < patchPointIdentity(b)
}
func (r *rankedPatchPoints) Len() int { return len(r.items) }
func (r *rankedPatchPoints) Less(i, j int) bool {
	return betterPatchPoint(&r.items[j], &r.items[i], r.rank)
}
func (r *rankedPatchPoints) Swap(i, j int) {
	r.items[i], r.items[j] = r.items[j], r.items[i]
	r.positions[patchPointIdentity(&r.items[i])] = i
	r.positions[patchPointIdentity(&r.items[j])] = j
}
func (r *rankedPatchPoints) Push(x any) {
	p := x.(PatchPoint)
	r.positions[patchPointIdentity(&p)] = len(r.items)
	r.items = append(r.items, p)
}
func (r *rankedPatchPoints) Pop() any {
	n := len(r.items) - 1
	p := r.items[n]
	delete(r.positions, patchPointIdentity(&p))
	r.items[n] = PatchPoint{}
	r.items = r.items[:n]
	return p
}
func (r *rankedPatchPoints) Add(p *PatchPoint) {
	if p == nil || r.limit <= 0 {
		return
	}
	key := patchPointIdentity(p)
	if i, ok := r.positions[key]; ok {
		if betterPatchPoint(p, &r.items[i], r.rank) {
			r.items[i] = *p
			heap.Fix(r, i)
		}
		return
	}
	if len(r.items) < r.limit {
		heap.Push(r, *p)
		return
	}
	if betterPatchPoint(p, &r.items[0], r.rank) {
		heap.Pop(r)
		heap.Push(r, *p)
	}
}
func (r *rankedPatchPoints) Sorted() []PatchPoint {
	out := append([]PatchPoint(nil), r.items...)
	sort.Slice(out, func(i, j int) bool { return betterPatchPoint(&out[i], &out[j], r.rank) })
	if out == nil {
		return []PatchPoint{}
	}
	return out
}
