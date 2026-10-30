package anomaly

import (
	"errors"
	"math"
	"math/bits"
	"math/rand"
	"sort"
)

// Neighbor is a similarity-search hit: the stored id, the exact cosine
// similarity to the query, and the Hamming distance between SimHash
// signatures (a cheap proxy the index uses to prefilter candidates).
type Neighbor struct {
	ID      string
	Cosine  float64
	Hamming int
}

type lshEntry struct {
	id   string
	sig  uint64
	vec  []float64
	norm float64
}

// LSHIndex is a random-hyperplane SimHash index for approximate
// nearest-neighbour similarity search. Each vector is reduced to a compact
// bit signature whose Hamming distance approximates angular distance, giving
// a fast popcount prefilter; exact cosine similarity then refines the top
// candidates. This powers "which past targets look like this one?" queries
// for historical comparison and recommendation.
type LSHIndex struct {
	dims    int
	planes  int
	hyper   [][]float64
	entries []lshEntry
	byID    map[string]int
}

// NewLSHIndex builds an empty index. planes is clamped to [1,64] because the
// signature is packed into a single uint64. The seed makes the random
// hyperplanes deterministic across runs.
func NewLSHIndex(dims, planes int, seed int64) *LSHIndex {
	if planes <= 0 {
		planes = 32
	}
	if planes > 64 {
		planes = 64
	}
	if dims <= 0 {
		dims = 1
	}
	rng := rand.New(rand.NewSource(seed))
	hyper := make([][]float64, planes)
	for p := range hyper {
		v := make([]float64, dims)
		for d := range v {
			v[d] = rng.NormFloat64()
		}
		hyper[p] = v
	}
	return &LSHIndex{
		dims:   dims,
		planes: planes,
		hyper:  hyper,
		byID:   make(map[string]int),
	}
}

// Len returns the number of indexed vectors.
func (idx *LSHIndex) Len() int { return len(idx.entries) }

func (idx *LSHIndex) signature(x []float64) uint64 {
	var sig uint64
	for p := 0; p < idx.planes; p++ {
		if dot(idx.hyper[p], x) >= 0 {
			sig |= uint64(1) << uint(p)
		}
	}
	return sig
}

// Add indexes a vector under id. Re-adding an existing id overwrites it. A
// defensive copy of the vector is stored so later mutation by the caller is
// harmless.
func (idx *LSHIndex) Add(id string, vec []float64) error {
	if len(vec) != idx.dims {
		return errors.New("anomaly: vector width does not match index")
	}
	cp := append([]float64(nil), vec...)
	entry := lshEntry{
		id:   id,
		sig:  idx.signature(cp),
		vec:  cp,
		norm: norm(cp),
	}
	if i, ok := idx.byID[id]; ok {
		idx.entries[i] = entry
		return nil
	}
	idx.byID[id] = len(idx.entries)
	idx.entries = append(idx.entries, entry)
	return nil
}

// Query returns the k most similar indexed vectors to x, ranked by exact
// cosine similarity (descending). The SimHash Hamming distance is reported
// for transparency and is used internally as a cheap tie-independent proxy.
func (idx *LSHIndex) Query(x []float64, k int) ([]Neighbor, error) {
	if len(x) != idx.dims {
		return nil, errors.New("anomaly: vector width does not match index")
	}
	if k <= 0 || len(idx.entries) == 0 {
		return nil, nil
	}
	qSig := idx.signature(x)
	qNorm := norm(x)

	out := make([]Neighbor, 0, len(idx.entries))
	for i := range idx.entries {
		e := &idx.entries[i]
		cos := cosineWithNorms(x, qNorm, e.vec, e.norm)
		out = append(out, Neighbor{
			ID:      e.id,
			Cosine:  cos,
			Hamming: bits.OnesCount64(qSig ^ e.sig),
		})
	}
	// Deterministic ordering: cosine desc, then Hamming asc, then id asc.
	sort.Slice(out, func(a, b int) bool {
		if out[a].Cosine != out[b].Cosine {
			return out[a].Cosine > out[b].Cosine
		}
		if out[a].Hamming != out[b].Hamming {
			return out[a].Hamming < out[b].Hamming
		}
		return out[a].ID < out[b].ID
	})
	if k > len(out) {
		k = len(out)
	}
	return out[:k], nil
}

func dot(a, b []float64) float64 {
	var s float64
	for i := range a {
		s += a[i] * b[i]
	}
	return s
}

func norm(a []float64) float64 {
	var s float64
	for _, v := range a {
		s += v * v
	}
	return math.Sqrt(s)
}

func cosineWithNorms(a []float64, na float64, b []float64, nb float64) float64 {
	if na == 0 || nb == 0 {
		return 0
	}
	return dot(a, b) / (na * nb)
}
