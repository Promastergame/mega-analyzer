package s1

import (
	"crypto/sha256"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"decisionai/semai"
)

// Judgement is a three-way entailment verdict for (premise, hypothesis).
type Judgement struct{ Entail, Neutral, Contra float64 }

// Pair is one premise/hypothesis evaluation unit.
type Pair struct{ Premise, Hypothesis string }

// Backend scores many pairs at once. Implementations must be safe for concurrent use.
type Backend interface {
	Name() string
	JudgeBatch(pairs []Pair) []Judgement
	Tokens(text string) int
}

// NLIBackend runs the bundled Transformer NLI cross-encoder over a worker pool with an LRU-ish cache.
type NLIBackend struct {
	enc     *semai.Encoder
	workers int
	mu      sync.Mutex
	cache   map[[32]byte]Judgement
	calls   atomic.Int64
	hits    atomic.Int64
}

const cacheCap = 1 << 15

func NewNLIBackend(enc *semai.Encoder, workers int) *NLIBackend {
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	return &NLIBackend{enc: enc, workers: workers, cache: map[[32]byte]Judgement{}}
}

func (b *NLIBackend) Name() string               { return "nli-cross-encoder:" + b.enc.Source }
func (b *NLIBackend) Tokens(text string) int     { return b.enc.TokenCount(text) }
func (b *NLIBackend) Stats() (calls, hits int64) { return b.calls.Load(), b.hits.Load() }

func key(p Pair) [32]byte { return sha256.Sum256([]byte(p.Premise + "\x00" + p.Hypothesis)) }

func (b *NLIBackend) JudgeBatch(pairs []Pair) []Judgement {
	out := make([]Judgement, len(pairs))
	todo := make([]int, 0, len(pairs))
	b.mu.Lock()
	for i, p := range pairs {
		if j, ok := b.cache[key(p)]; ok {
			out[i] = j
			b.hits.Add(1)
		} else {
			todo = append(todo, i)
		}
	}
	b.mu.Unlock()
	var next atomic.Int64
	var wg sync.WaitGroup
	w := b.workers
	if w > len(todo) {
		w = len(todo)
	}
	for k := 0; k < w; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n := int(next.Add(1)) - 1
				if n >= len(todo) {
					return
				}
				i := todo[n]
				r := b.enc.Classify(pairs[i].Premise, pairs[i].Hypothesis)
				out[i] = Judgement{r.Entailment, r.Neutral, r.Contradiction}
				b.calls.Add(1)
			}
		}()
	}
	wg.Wait()
	b.mu.Lock()
	if len(b.cache) > cacheCap {
		b.cache = map[[32]byte]Judgement{}
	}
	for _, i := range todo {
		b.cache[key(pairs[i])] = out[i]
	}
	b.mu.Unlock()
	return out
}

// LexicalBackend is a weight-free fallback: stemmed token overlap with negation awareness.
// It is deliberately conservative (probabilities stay near the middle) and its answers
// are routed to "human" by the engine.
type LexicalBackend struct{}

func (LexicalBackend) Name() string        { return "lexical-fallback" }
func (LexicalBackend) Tokens(t string) int { return len(lexTokens(t)) }
func (LexicalBackend) JudgeBatch(pairs []Pair) []Judgement {
	out := make([]Judgement, len(pairs))
	for i, p := range pairs {
		ps, hs := lexTokens(p.Premise), lexTokens(p.Hypothesis)
		set := map[string]bool{}
		for _, t := range ps {
			set[t] = true
		}
		hit, n := 0, 0
		for _, t := range hs {
			if len([]rune(t)) < 3 {
				continue
			}
			n++
			if set[t] {
				hit++
			}
		}
		ov := 0.0
		if n > 0 {
			ov = float64(hit) / float64(n)
		}
		neg := hasNeg(p.Premise) != hasNeg(p.Hypothesis)
		e, c := 0.15+0.6*ov, 0.1
		if neg && ov > 0.3 {
			e, c = 0.1, 0.15+0.6*ov
		}
		out[i] = Judgement{e, clamp01(1 - e - c), c}
	}
	return out
}

func lexTokens(s string) []string {
	f := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	for i, w := range f {
		r := []rune(w)
		if len(r) > 5 {
			f[i] = string(r[:5]) // crude stemming for RU/EN inflection
		}
	}
	return f
}

func hasNeg(s string) bool {
	s = " " + strings.ToLower(s) + " "
	for _, n := range []string{" не ", " нет ", " ни ", " not ", " no ", " never ", "n't", " без ", " failed", " fail ", "ошибк", "упал"} {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}
