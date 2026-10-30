package matcher

import (
	"runtime"
	"sort"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// parallelThreshold — минимальный размер файла для параллельного матчинга.
	// Для маленьких файлов overhead от горутин больше, чем выигрыш.
	//
	// Эмпирически: параллельный матчинг выгоден от ~200KB+
	parallelThreshold = 200 * 1024 // 200 KB

	// minChunkLines — минимальный размер чанка в строках.
	// Слишком мелкие чанки = overhead от горутин > пользы.
	minChunkLines = 512

	// maxParallelWorkers — лимит воркеров для матчинга одного файла.
	// Больше 8 обычно не даёт прироста (bottleneck в regex engine).
	maxParallelWorkers = 8
)

// ═══════════════════════════════════════════════════════════════════════════════
// AUTO-PARALLEL — автоматический выбор стратегии
// ═══════════════════════════════════════════════════════════════════════════════

// ShouldUseParallel определяет, стоит ли использовать параллельный матчинг.
//
// Критерии:
//   - Файл достаточно большой (>200KB)
//   - Есть хотя бы 2 CPU
//   - Кандидатов (паттернов) достаточно много для распараллеливания
func ShouldUseParallel(contentLen int, candidateCount int) bool {
	return contentLen >= parallelThreshold &&
		runtime.NumCPU() >= 2 &&
		candidateCount >= 4 // меньше 4 паттернов — overhead не окупается
}

// ═══════════════════════════════════════════════════════════════════════════════
// MATCH CONTENT PARALLEL
// ═══════════════════════════════════════════════════════════════════════════════

// MatchContentParallel матчит контент параллельно по чанкам строк.
//
// Для автоматического использования вызывай через MatchContentWithFilterLower —
// он сам решит, использовать ли параллельный матчинг.
//
// Принимает ГОТОВЫЙ lowercase — не делает ToLower повторно!
func (m *Matcher) MatchContentParallel(
	content, contentLower string,
	filePath string,
	isAppCode bool,
	workers int,
) []types.Match {
	if m.config.MaxMatchesPerFile <= 0 || len(content) == 0 {
		return nil
	}

	// ── Prefilter — один раз на весь контент ─────────────────────────────
	fileIsSDK := isSDKPath(filePath)
	candidates := m.prefilterPatterns(contentLower, isAppCode, fileIsSDK)
	if len(candidates) == 0 {
		return nil
	}

	// ── Строим line index ОДИН раз ──────────────────────────────────────
	li := buildLineIndex(content)
	totalLines := li.lineCount()
	if totalLines == 0 {
		return nil
	}

	contentIsASCII := isASCII(content)

	// ── Определяем количество воркеров ───────────────────────────────────
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > maxParallelWorkers {
		workers = maxParallelWorkers
	}
	if workers > totalLines {
		workers = totalLines
	}

	// ── CPU governor ──────────────────────────────────────────────
	// The caller (matchInternal) already owns one CPU token for this file. Borrow
	// at most (workers-1) EXTRA tokens for additional chunk workers, without
	// blocking; when the spare cores are already busy with other files we get
	// none and fall back to a single-worker (sequential) scan below. This caps
	// total CPU-bound matching goroutines across the whole process at GOMAXPROCS
	// instead of the previous NumCPU-per-file blow-up. Matches are identical.
	extra := cpuBudget().tryAcquire(workers - 1)
	if extra > 0 {
		defer cpuBudget().release(extra)
	}
	if workers > extra+1 {
		workers = extra + 1
	}

	chunkSize := totalLines / workers
	if chunkSize < minChunkLines {
		chunkSize = minChunkLines
		workers = (totalLines + chunkSize - 1) / chunkSize
		if workers <= 0 {
			workers = 1
		}
		if workers > extra+1 {
			workers = extra + 1
		}
	}

	// Если в итоге 1 воркер — нет смысла в параллелизме
	if workers <= 1 {
		return m.scanLines(content, contentLower, filePath, isAppCode, candidates, contentIsASCII, li, fileIsSDK)
	}

	// ── Запускаем параллельный матчинг ───────────────────────────────────
	return m.parallelScanLines(
		content, contentLower, filePath,
		candidates, contentIsASCII,
		li, totalLines, workers, chunkSize,
		fileIsSDK,
	)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PARALLEL SCAN — внутренняя реализация
// ═══════════════════════════════════════════════════════════════════════════════

type chunkJob struct {
	idx   int // индекс чанка для сохранения порядка
	start int // начальная строка (0-indexed)
	end   int // конечная строка (exclusive)
}

type chunkResult struct {
	idx     int
	matches []types.Match
}

func (m *Matcher) parallelScanLines(
	content, contentLower, filePath string,
	candidates []*CompiledPattern,
	contentIsASCII bool,
	li *lineIndex,
	totalLines, workers, chunkSize int,
	fileIsSDK bool,
) []types.Match {

	maxMatches := m.config.MaxMatchesPerFile
	maxStrLen := m.config.MaxStringLength
	contextLines := m.config.ContextLines

	jobs := make(chan chunkJob, workers)
	results := make(chan chunkResult, workers)

	// ── Workers ──────────────────────────────────────────────────────────
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Переиспользуемая карта — одна на воркер, clear на каждой строке
			matchedCats := make(map[types.Category]struct{}, 8)

			for j := range jobs {
				chunkMatches := m.processChunk(
					content, contentLower, filePath,
					candidates, contentIsASCII,
					li, j.start, j.end,
					maxMatches, maxStrLen, contextLines,
					matchedCats, fileIsSDK,
				)
				results <- chunkResult{idx: j.idx, matches: chunkMatches}
			}
		}()
	}

	// ── Closer ───────────────────────────────────────────────────────────
	go func() {
		wg.Wait()
		close(results)
	}()

	// ── Producer: отправляем чанки ───────────────────────────────────────
	jobCount := 0
	for start := 0; start < totalLines; start += chunkSize {
		end := start + chunkSize
		if end > totalLines {
			end = totalLines
		}
		jobs <- chunkJob{idx: jobCount, start: start, end: end}
		jobCount++
	}
	close(jobs)

	// ── Collector: собираем и сортируем результаты ───────────────────────
	collected := make([]chunkResult, 0, jobCount)
	for res := range results {
		collected = append(collected, res)
	}

	// Сортируем по индексу чанка (сохраняем порядок строк в файле)
	sort.Slice(collected, func(i, j int) bool {
		return collected[i].idx < collected[j].idx
	})

	// Объединяем с глобальным лимитом
	// Per-file category limits (defaultMaxPerCatFile / maxPerCategoryPerFile)
	// are applied HERE, in file line order: chunks cannot see each other's
	// counters. This reproduces scanLines semantics exactly — the FIRST N
	// matches of each category across the whole file are kept.
	catFileCount := make(map[types.Category]int, 16)
	allMatches := make([]types.Match, 0, minInt(maxMatches, jobCount*16))
mergeLoop:
	for _, res := range collected {
		for i := range res.matches {
			if len(allMatches) >= maxMatches {
				break mergeLoop
			}
			cat := res.matches[i].Category
			catLimit := defaultMaxPerCatFile
			if lim, ok := maxPerCategoryPerFile[cat]; ok {
				catLimit = lim
			}
			if catFileCount[cat] >= catLimit {
				continue
			}
			catFileCount[cat]++
			allMatches = append(allMatches, res.matches[i])
		}
	}

	// Batch stats
	if len(allMatches) > 0 {
		m.batchUpdateStats(allMatches)
		m.totalMatched.Add(int64(len(allMatches)))
	}

	m.totalScanned.Add(1)

	return allMatches
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROCESS CHUNK — обработка одного чанка строк
// ═══════════════════════════════════════════════════════════════════════════════

func (m *Matcher) processChunk(
	content, contentLower, filePath string,
	candidates []*CompiledPattern,
	contentIsASCII bool,
	li *lineIndex,
	startLine, endLine int,
	maxMatches, maxStrLen, contextLines int,
	matchedCats map[types.Category]struct{},
	fileIsSDK bool,
) []types.Match {
	matches := make([]types.Match, 0, 16)
	// Chunk-local category counter. Keeping only the FIRST catLimit matches
	// per category per chunk is lossless: the merge step selects the first
	// catLimit per category in file order, which is always a prefix of what
	// each chunk kept.
	catChunkCount := make(map[types.Category]int, 16)

	for lineIdx := startLine; lineIdx < endLine; lineIdx++ {
		lineNum := lineIdx + 1

		// ── Получаем строку из lineIndex ─────────────────────────────────
		start := li.starts[lineIdx]
		var end int
		if lineIdx+1 < li.lineCount() {
			end = li.starts[lineIdx+1]
			if end > start && content[end-1] == '\n' {
				end--
			}
		} else {
			end = len(content)
		}

		if start >= end {
			continue
		}

		line := content[start:end]

		if isSkippableLine(line) {
			continue
		}

		if len(matches) >= maxMatches {
			break
		}

		// ── Lowercase строки ─────────────────────────────────────────────
		var lineLower string
		if contentIsASCII || len(content) == len(contentLower) {
			lineLower = contentLower[start:end]
		} else {
			lineLower = strings.ToLower(line)
		}

		// ── Очищаем карту (переиспользуем!) ──────────────────────────────
		clear(matchedCats)

		for _, pat := range candidates {
			if _, seen := matchedCats[pat.Category]; seen {
				continue
			}

			catLimit := defaultMaxPerCatFile
			if lim, ok := maxPerCategoryPerFile[pat.Category]; ok {
				catLimit = lim
			}
			if catChunkCount[pat.Category] >= catLimit {
				continue
			}

			if m.capReachedID(pat.CatIdx, pat.Category) {
				continue
			}

			// Keyword check
			if len(pat.KeywordsLower) > 0 {
				hasKW := false
				for _, kw := range pat.KeywordsLower {
					if strings.Contains(lineLower, kw) {
						hasKW = true
						break
					}
				}
				if !hasKW {
					continue
				}
			}

			if pat.GateLiteral != "" {
				if pat.GateFold {
					if !strings.Contains(lineLower, pat.GateLiteral) {
						continue
					}
				} else if !strings.Contains(line, pat.GateLiteral) {
					continue
				}
			}

			// Regex match
			if pat.Regex != nil && pat.Regex.MatchString(line) {
				ctx := extractContextFast(content, li, lineNum, contextLines)

				if shouldSuppress(pat.Category, line, filePath, ctx) {
					m.suppressedCount.Add(1)
					continue
				}

				info := types.GetCategoryInfo(pat.Category)

				score := float64(info.Priority)
				isCritical := info.IsCritical
				if fileIsSDK {
					score *= 0.1
					isCritical = false
				}

				matches = append(matches, types.Match{
					SourceLocation: types.SourceLocation{
						File: filePath,
						Line: lineNum,
					},
					Categorized: types.Categorized{Category: pat.Category},
					Scored:      types.Scored{Score: score},
					Text:        types.TruncateString(line, maxStrLen),
					Pattern:     pat.Description,
					Context:     ctx,
					IsCritical:  isCritical,
				})

				matchedCats[pat.Category] = struct{}{}
				catChunkCount[pat.Category]++

				if len(matches) >= maxMatches {
					break
				}
			}
		}
	}

	return matches
}

// minInt — для совместимости (может быть определён в helpers)
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
