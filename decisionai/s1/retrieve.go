package s1

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"unicode"
)

var retrievalStop = func() map[string]bool {
	m := map[string]bool{}
	for _, word := range strings.Fields("the a an is are was were does do did will would could should can this that these those what which who how and or not of to in on at for with from by ли это этот эта эти как какой какая какое что кто где чем для при или без уже еще ещё так если then than into about") {
		m[word] = true
	}
	return m
}()

func retrievalTerms(text string) map[string]float64 {
	out := map[string]float64{}
	for _, word := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if retrievalStop[word] {
			continue
		}
		rs := []rune(word)
		if len(rs) < 2 && !unicode.IsDigit(rs[0]) {
			continue
		}
		out["exact:"+word] = 1
		if len(rs) > 5 {
			out["stem:"+string(rs[:5])] = .35
		}
	}
	return out
}

// tokenWindows enforces the actual encoder budget even for a single long
// sentence. It never passes an oversized window to Encode's silent truncation.
func tokenWindows(text string, limit int, count func(string) int) []string {
	if limit <= 0 || count(text) <= limit {
		return []string{text}
	}
	// Split an oversized lexical item instead of silently discarding its tail.
	var words []string
	for _, word := range strings.Fields(text) {
		if count(word) <= limit {
			words = append(words, word)
			continue
		}
		remaining := []rune(word)
		for len(remaining) > 0 {
			lo, hi := 1, len(remaining)
			for lo < hi {
				mid := (lo + hi + 1) / 2
				if count(string(remaining[:mid])) <= limit {
					lo = mid
				} else {
					hi = mid - 1
				}
			}
			words = append(words, string(remaining[:lo]))
			remaining = remaining[lo:]
		}
	}
	var out []string
	for start := 0; start < len(words); {
		lo, hi := start+1, len(words)
		for lo < hi {
			mid := (lo + hi + 1) / 2
			if count(strings.Join(words[start:mid], " ")) <= limit {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		end := lo
		out = append(out, strings.Join(words[start:end], " "))
		if end == len(words) {
			break
		}
		overlap := min(8, (end-start)/4)
		start = end - overlap
	}
	return out
}

// contextChunks returns a union of per-question retrieval results. The engine
// scores only the selected pairs; many questions cannot crowd each other's
// evidence out of a shared head/tail cap.
// Legacy callers (plan export) use a background context.
func (e *Engine) contextChunks(state string, questions []compiled) ([]string, [][]int, []bool) {
	chunks, selected, missing, _ := e.contextChunksContext(context.Background(), state, questions)
	return chunks, selected, missing
}

const DefaultContextCacheBytes int64 = 4 << 20

type contextIndex struct {
	candidates []string
	terms      []map[string]float64
	df         map[string]int
}
type contextIndexCache struct {
	mu      sync.Mutex
	entries weightedCache[[32]byte, *contextIndex]
}

func (e *Engine) SetContextCacheLimit(bytes int64) {
	// Configure before serving; NewEngine always supplies this shared cache.
	if e.contextCache == nil {
		e.contextCache = &contextIndexCache{}
	}
	e.contextCache.mu.Lock()
	defer e.contextCache.mu.Unlock()
	e.contextCache.entries.resize(bytes)
}
func (e *Engine) ContextCacheUsage() CacheUsage {
	if e.contextCache == nil {
		return CacheUsage{}
	}
	e.contextCache.mu.Lock()
	defer e.contextCache.mu.Unlock()
	return e.contextCache.entries.usage()
}

func (e *Engine) contextIndexFor(ctx context.Context, state string) (*contextIndex, error) {
	model := backendFingerprint(e.Backend)
	var header [24]byte
	binary.LittleEndian.PutUint64(header[:8], uint64(e.MaxChunkWords))
	binary.LittleEndian.PutUint64(header[8:16], uint64(e.MaxChunkTokens))
	binary.LittleEndian.PutUint64(header[16:], uint64(len(model)))
	hash := sha256.New()
	hash.Write(header[:])
	hash.Write([]byte(model))
	hash.Write([]byte(state))
	var key [32]byte
	hash.Sum(key[:0])
	if e.contextCache != nil {
		e.contextCache.mu.Lock()
		index, ok := e.contextCache.entries.get(key)
		e.contextCache.mu.Unlock()
		if ok {
			return index, ctx.Err()
		}
	}
	candidates := []string{}
	seen := map[string]bool{}
	for _, chunk := range Chunk(state, e.MaxChunkWords, 0) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		for _, part := range tokenWindows(chunk, e.MaxChunkTokens, e.Backend.Tokens) {
			if e.MaxChunkTokens > 0 && e.Backend.Tokens(part) > e.MaxChunkTokens {
				return nil, fmt.Errorf("context token budget too small for a Unicode character; increase MaxChunkTokens")
			}
			if !seen[part] {
				seen[part] = true
				candidates = append(candidates, strings.Clone(part))
			}
		}
	}
	terms := make([]map[string]float64, len(candidates))
	df := map[string]int{}
	for i, chunk := range candidates {
		terms[i] = retrievalTerms(chunk)
		for word := range terms[i] {
			df[word]++
		}
	}
	index := &contextIndex{candidates: candidates, terms: terms, df: df}
	cost := int64(256)
	for i, c := range candidates {
		cost += int64(len(c) + 128)
		for term := range terms[i] {
			cost += int64(128 + len(term))
		}
	}
	for term := range df {
		cost += int64(128 + len(term))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.contextCache != nil {
		e.contextCache.mu.Lock()
		if cost <= e.contextCache.entries.limit {
			e.contextCache.entries.put(key, index, cost)
		}
		e.contextCache.mu.Unlock()
	}
	return index, nil
}

func (e *Engine) contextChunksContext(ctx context.Context, state string, questions []compiled) ([]string, [][]int, []bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	index, err := e.contextIndexFor(ctx, state)
	if err != nil {
		return nil, nil, nil, err
	}
	candidates, terms, df := index.candidates, index.terms, index.df
	idf := func(word string) float64 { return 1 + math.Log(1+float64(len(candidates))/float64(1+df[word])) }
	var chunks []string
	global := map[int]int{}
	selected := make([][]int, len(questions))
	missing := make([]bool, len(questions))
	for qi, q := range questions {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, err
		}
		indices := make([]int, len(candidates))
		for i := range indices {
			indices[i] = i
		}
		if e.MaxChunks > 0 && len(candidates) > e.MaxChunks {
			query := retrievalTerms(q.Instr)
			for word, w := range query {
				query[word] = 2 * w
			}
			for _, option := range q.Options {
				for word, w := range retrievalTerms(option.Text) {
					if query[word] == 0 {
						query[word] = w
					}
				}
			}
			scores := make([]float64, len(candidates))
			score := func(query map[string]float64, weight float64) {
				queryKeys := make([]string, 0, len(query))
				for word := range query {
					queryKeys = append(queryKeys, word)
				}
				sort.Strings(queryKeys)
				for i, words := range terms {
					for _, word := range queryKeys {
						w := query[word]
						if words[word] > 0 {
							scores[i] += weight * w * words[word] * idf(word)
						}
					}
				}
			}
			score(query, 1)
			sort.SliceStable(indices, func(i, j int) bool { return scores[indices[i]] > scores[indices[j]] })
			if scores[indices[0]] == 0 {
				missing[qi] = true
				indices = indices[:e.MaxChunks]
			} else {
				// A second hop brings in related names/objects from the strongest
				// evidence. Terms common to most windows cannot dominate expansion.
				expand := map[string]float64{}
				for _, i := range indices[:min(2, len(indices))] {
					if scores[i] == 0 {
						continue
					}
					for word := range terms[i] {
						if query[word] == 0 && df[word] <= max(2, len(candidates)/4) {
							expand[word] = 1
						}
					}
				}
				score(expand, .35)
				sort.SliceStable(indices, func(i, j int) bool { return scores[indices[i]] > scores[indices[j]] })
				kept := indices[:0]
				for _, i := range indices {
					if scores[i] > 0 && len(kept) < e.MaxChunks {
						kept = append(kept, i)
					}
				}
				indices = kept
			}
			sort.Ints(indices)
		}
		for _, index := range indices {
			g, ok := global[index]
			if !ok {
				g = len(chunks)
				chunks = append(chunks, candidates[index])
				global[index] = g
			}
			selected[qi] = append(selected[qi], g)
		}
	}
	return chunks, selected, missing, nil
}
