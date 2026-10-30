package matcher

import "sync"

// ═══════════════════════════════════════════════════════════════════════════════
// AHO-CORASICK AUTOMATON
// ═══════════════════════════════════════════════════════════════════════════════
//
// Ищет ВСЕ ключевые слова за ОДИН проход по тексту — O(N + M),
// где N = длина текста, M = количество совпадений.
//
// Сравнение:
//   strings.Contains × K keywords = O(N × K)   ← было
//   AhoCorasick.Search             = O(N)       ← стало
//
// Для 50 keywords на файле 100 КБ:
//   Раньше:  50 × 100 000 = 5 000 000 операций
//   Теперь:  1 × 100 000  =   100 000 операций
//   Ускорение: ~50x !

type acEdge struct {
	b    byte
	next int
}

type acNode struct {
	dense *[256]int32 // dense transitions for high-fanout nodes; nil otherwise
	edges []acEdge // только существующие переходы; типично их значительно меньше 256
	fail  int      // суффиксная ссылка
	out   []int    // индексы найденных паттернов
}

type ahoScratch struct {
	seen []uint32 // поколение последнего появления каждого паттерна
	gen  uint32   // текущее поколение (инкрементируется каждый Search)
}

// AhoCorasick — автомат для поиска множества строк.
type AhoCorasick struct {
	nodes       []acNode
	patterns    []string  // оригинальные паттерны (без пустых)
	scratchPool sync.Pool // пул scratch-буферов для горутин
}

func newACNode() acNode {
	return acNode{}
}

func (n *acNode) transition(b byte) int {
	// pprof (Phase 0): this linear edge scan was 47.9% flat of detector time.
	// High-fanout nodes carry a dense table, so the hot path is one indexed
	// load instead of a loop. Same transition function, same -1 for misses.
	if n.dense != nil {
		return int(n.dense[b])
	}
	for _, edge := range n.edges {
		if edge.b == b {
			return edge.next
		}
	}
	return -1
}

func (n *acNode) setTransition(b byte, next int) {
	if n.dense != nil {
		n.dense[b] = int32(next)
	}
	for i := range n.edges {
		if n.edges[i].b == b {
			n.edges[i].next = next
			return
		}
	}
	n.edges = append(n.edges, acEdge{b: b, next: next})
}

// denseEdgeThreshold - minimum out-degree at which a node gets a dense
// [256]int32 transition table (1 KiB per node).
const denseEdgeThreshold = 4

// buildDenseTransitions materialises dense tables for the root and for
// branching nodes. Built from the same edges after the trie is complete, so
// the automaton's behaviour is unchanged.
func (ac *AhoCorasick) buildDenseTransitions() {
	for i := range ac.nodes {
		if i != 0 && len(ac.nodes[i].edges) < denseEdgeThreshold {
			continue
		}
		table := new([256]int32)
		for j := range table {
			table[j] = -1
		}
		for _, edge := range ac.nodes[i].edges {
			table[edge.b] = int32(edge.next)
		}
		ac.nodes[i].dense = table
	}
}

// NewAhoCorasick строит автомат по ключевым словам.
// Пустые строки автоматически пропускаются.
func NewAhoCorasick(patterns []string) *AhoCorasick {
	// Фильтруем пустые паттерны
	filtered := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if len(p) > 0 {
			filtered = append(filtered, p)
		}
	}

	ac := &AhoCorasick{
		nodes:    make([]acNode, 1, len(filtered)*4+1), // примерный размер
		patterns: filtered,
	}
	ac.nodes[0] = newACNode()

	// ── Шаг 1: Построение trie ───────────────────────────────────────────
	for idx, pat := range filtered {
		node := 0
		for i := 0; i < len(pat); i++ {
			b := pat[i]
			next := ac.nodes[node].transition(b)
			if next == -1 {
				ac.nodes = append(ac.nodes, newACNode())
				next = len(ac.nodes) - 1
				ac.nodes[node].setTransition(b, next)
			}
			node = next
		}
		ac.nodes[node].out = append(ac.nodes[node].out, idx)
	}

	// ── Шаг 2: Построение fail-ссылок (BFS) ─────────────────────────────
	queue := make([]int, 0, len(ac.nodes))
	for _, edge := range ac.nodes[0].edges {
		ac.nodes[edge.next].fail = 0
		queue = append(queue, edge.next)
	}

	for head := 0; head < len(queue); head++ {
		v := queue[head]
		for _, edge := range ac.nodes[v].edges {
			u := edge.next
			failState := ac.nextState(ac.nodes[v].fail, edge.b)
			ac.nodes[u].fail = failState
			// Мерджим output из fail-ссылки
			if len(ac.nodes[failState].out) > 0 {
				ac.nodes[u].out = append(ac.nodes[u].out, ac.nodes[failState].out...)
			}
			queue = append(queue, u)
		}
	}

	// -- Step 2b: dense transition tables for hot nodes --
	ac.buildDenseTransitions()

	// ── Шаг 3: Пул scratch-буферов ──────────────────────────────────────
	patCount := len(filtered)
	ac.scratchPool.New = func() interface{} {
		return &ahoScratch{
			seen: make([]uint32, patCount),
		}
	}

	return ac
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCRATCH — переиспользуемые буферы для многопоточности
// ═══════════════════════════════════════════════════════════════════════════════

// nextState follows suffix links until a matching explicit transition is found.
// Keeping only explicit edges removes the former 2 KiB transition matrix from
// every trie node while retaining the standard Aho–Corasick state machine.
func (ac *AhoCorasick) nextState(state int, b byte) int {
	for {
		if next := ac.nodes[state].transition(b); next >= 0 {
			return next
		}
		if state == 0 {
			return 0
		}
		state = ac.nodes[state].fail
	}
}

func (ac *AhoCorasick) getScratch() *ahoScratch {
	scratch := ac.scratchPool.Get().(*ahoScratch)
	if len(scratch.seen) < len(ac.patterns) {
		scratch.seen = make([]uint32, len(ac.patterns))
	} else {
		scratch.seen = scratch.seen[:len(ac.patterns)]
	}
	return scratch
}

func (ac *AhoCorasick) putScratch(scratch *ahoScratch) {
	ac.scratchPool.Put(scratch)
}

// advanceGen увеличивает поколение и сбрасывает при переполнении
func (s *ahoScratch) advanceGen() {
	s.gen++
	if s.gen == 0 {
		// uint32 переполнился — сбрасываем всё
		for i := range s.seen {
			s.seen[i] = 0
		}
		s.gen = 1
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SEARCH — найти ВСЕ паттерны (уникальные)
// ═══════════════════════════════════════════════════════════════════════════════

// Search возвращает индексы паттернов, найденных в тексте (без повторов).
// Безопасен для вызова из нескольких горутин одновременно.
func (ac *AhoCorasick) Search(text string) []int {
	if len(text) == 0 || len(ac.patterns) == 0 {
		return nil
	}

	scratch := ac.getScratch()
	defer ac.putScratch(scratch)
	scratch.advanceGen()

	results := make([]int, 0, 8)
	state := 0

	for i := 0; i < len(text); i++ {
		state = ac.nextState(state, text[i])

		if len(ac.nodes[state].out) == 0 {
			continue
		}

		for _, idx := range ac.nodes[state].out {
			if idx < 0 || idx >= len(scratch.seen) {
				continue
			}
			if scratch.seen[idx] == scratch.gen {
				continue // уже нашли этот паттерн
			}
			scratch.seen[idx] = scratch.gen
			results = append(results, idx)
		}
	}

	return results
}

// ═══════════════════════════════════════════════════════════════════════════════
// SEARCH BYTES — поиск по []byte без конвертации в string
// ═══════════════════════════════════════════════════════════════════════════════

// SearchBytes — аналог Search, но принимает []byte.
// Не создаёт копию данных — работает напрямую с байтами.
//
// Полезно для детекторов, которые работают с []byte (content, contentLower).
func (ac *AhoCorasick) SearchBytes(data []byte) []int {
	if len(data) == 0 || len(ac.patterns) == 0 {
		return nil
	}

	scratch := ac.getScratch()
	defer ac.putScratch(scratch)
	scratch.advanceGen()

	results := make([]int, 0, 8)
	state := 0

	for i := 0; i < len(data); i++ {
		state = ac.nextState(state, data[i])

		if len(ac.nodes[state].out) == 0 {
			continue
		}

		for _, idx := range ac.nodes[state].out {
			if idx < 0 || idx >= len(scratch.seen) {
				continue
			}
			if scratch.seen[idx] == scratch.gen {
				continue
			}
			scratch.seen[idx] = scratch.gen
			results = append(results, idx)
		}
	}

	return results
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTAINS ANY — быстрая проверка "есть хоть одно совпадение?"
// ═══════════════════════════════════════════════════════════════════════════════

// ContainsAny возвращает true при ПЕРВОМ же совпадении.
// Быстрее Search, когда нужен только ответ да/нет.
func (ac *AhoCorasick) ContainsAny(text string) bool {
	if len(text) == 0 || len(ac.patterns) == 0 {
		return false
	}

	state := 0
	for i := 0; i < len(text); i++ {
		state = ac.nextState(state, text[i])
		if len(ac.nodes[state].out) > 0 {
			return true
		}
	}
	return false
}

// ContainsAnyBytes — аналог ContainsAny для []byte.
func (ac *AhoCorasick) ContainsAnyBytes(data []byte) bool {
	if len(data) == 0 || len(ac.patterns) == 0 {
		return false
	}

	state := 0
	for i := 0; i < len(data); i++ {
		state = ac.nextState(state, data[i])
		if len(ac.nodes[state].out) > 0 {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// SEARCH WITH POSITIONS — найти совпадения С позициями
// ═══════════════════════════════════════════════════════════════════════════════

// ACMatch — совпадение с позицией в тексте
type ACMatch struct {
	PatternIndex int // индекс паттерна в исходном списке
	Position     int // байтовая позиция КОНЦА совпадения в тексте
}

// SearchWithPositions возвращает все совпадения с их позициями.
// Полезно когда нужно знать ГДЕ найдено (для номера строки).
func (ac *AhoCorasick) SearchWithPositions(text string) []ACMatch {
	if len(text) == 0 || len(ac.patterns) == 0 {
		return nil
	}

	results := make([]ACMatch, 0, 8)
	state := 0

	for i := 0; i < len(text); i++ {
		state = ac.nextState(state, text[i])

		if len(ac.nodes[state].out) == 0 {
			continue
		}

		for _, idx := range ac.nodes[state].out {
			if idx >= 0 && idx < len(ac.patterns) {
				results = append(results, ACMatch{
					PatternIndex: idx,
					Position:     i, // конец совпадения
				})
			}
		}
	}

	return results
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATS — для отладки и мониторинга
// ═══════════════════════════════════════════════════════════════════════════════

// PatternCount возвращает количество паттернов в автомате
func (ac *AhoCorasick) PatternCount() int {
	return len(ac.patterns)
}

// NodeCount возвращает количество узлов (для оценки потребления памяти).
// Узел хранит только реально существующие переходы.
func (ac *AhoCorasick) NodeCount() int {
	return len(ac.nodes)
}

// MemoryEstimate возвращает примерную оценку памяти автомата в байтах.
func (ac *AhoCorasick) MemoryEstimate() int64 {
	// Базовый узел: edges/out slice headers + fail; к нему добавляются только
	// реально существующие рёбра и сохранённые индексы совпадений.
	const baseNodeSize = int64(24 + 24 + 8)
	const edgeSize = int64(16) // byte + padding + int on 64-bit platforms
	const outputIndexSize = int64(8)
	estimate := int64(len(ac.nodes)) * baseNodeSize
	for _, node := range ac.nodes {
		estimate += int64(len(node.edges)) * edgeSize
		estimate += int64(len(node.out)) * outputIndexSize
	}
	return estimate
}

// Pattern возвращает паттерн по индексу (для получения текста найденного keyword)
func (ac *AhoCorasick) Pattern(index int) string {
	if index >= 0 && index < len(ac.patterns) {
		return ac.patterns[index]
	}
	return ""
}
