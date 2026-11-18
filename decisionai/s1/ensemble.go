package s1

import (
	"strings"
	"sync"
)

// EnsembleBackend averages the judgements of several backends (v1.11: two distilled
// System One encoders trained on different data mixes). Members run in parallel.
type EnsembleBackend struct {
	Members []Backend
	Label   string // display name (default: ensemble(member | member))
}

func (e EnsembleBackend) Name() string {
	if e.Label != "" {
		return e.Label
	}
	n := make([]string, len(e.Members))
	for i, m := range e.Members {
		n[i] = m.Name()
	}
	return "ensemble(" + strings.Join(n, " | ") + ")"
}

func (e EnsembleBackend) Tokens(t string) int {
	n := 0
	for _, member := range e.Members {
		n = max(n, member.Tokens(t))
	}
	return n
}

func (e EnsembleBackend) JudgeBatch(pairs []Pair) []Judgement {
	res := make([][]Judgement, len(e.Members))
	var wg sync.WaitGroup
	for i, m := range e.Members {
		wg.Add(1)
		go func(i int, m Backend) { defer wg.Done(); res[i] = m.JudgeBatch(pairs) }(i, m)
	}
	wg.Wait()
	out := make([]Judgement, len(pairs))
	k := float64(len(e.Members))
	for _, r := range res {
		for j, v := range r {
			out[j].Entail += v.Entail / k
			out[j].Neutral += v.Neutral / k
			out[j].Contra += v.Contra / k
		}
	}
	return out
}
