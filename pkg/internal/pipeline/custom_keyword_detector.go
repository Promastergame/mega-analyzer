// pkg/internal/pipeline/custom_keyword_detector.go
package pipeline

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"mega-analyzer/pkg/internal/configs"
	"mega-analyzer/pkg/internal/matcher"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// KEYWORD ENTRY
// ═══════════════════════════════════════════════════════════════════════════════

// keywordEntry represents a single keyword with optional metadata.
type keywordEntry struct {
	Pattern     []byte         // lowercased keyword to search for
	Original    string         // keyword as written (before lowering)
	Tag         string         // optional label: "framework", "hooking", "c2"
	Suspicious  bool           // inherently suspicious (e.g. malware IOC)
	Mode        keywordMode    // matching behavior
	Regex       *regexp.Regexp // compiled for regex mode
	Severity    types.Severity // optional severity override
	HasSeverity bool
}

type keywordMode int

const (
	keywordModeSubstring keywordMode = iota
	keywordModeWord
	keywordModeRegex
)

type hitKey struct {
	kwIdx int
	line  int
}

// ═══════════════════════════════════════════════════════════════════════════════
// CUSTOM KEYWORD DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════
//
// Ищет пользовательские ключевые слова/IOC в текстовых файлах.
//
// ОПТИМИЗАЦИЯ v2: Aho-Corasick для substring/word keywords
//
//   Раньше: K keywords × N байт = O(N × K) операций bytes.Index
//     50 keywords × 100KB = 5 000 000 сравнений
//
//   Теперь: 1 проход Aho-Corasick = O(N) операций
//     50 keywords × 100KB = 100 000 сравнений
//     Ускорение: ~50x!
//
// Regex keywords обрабатываются отдельно (AC для них не работает).

type CustomKeywordDetector struct {
	keywords []keywordEntry

	// ── Aho-Corasick (строится ОДИН раз при инициализации) ───────────────
	// Автомат для всех non-regex keywords (substring + word mode).
	automaton *matcher.AhoCorasick
	// acToKeyword[acPatternIndex] → index в d.keywords
	acToKeyword []int

	// Индексы regex-mode keywords (обрабатываются отдельно)
	regexIndices []int

	// Настройки
	maxPerFile    int
	maxPerKeyword int
	minLength     int
	contextRadius int
	loader        KeywordLoader
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEYWORD LOADERS
// ═══════════════════════════════════════════════════════════════════════════════

type KeywordLoader interface {
	Load() ([]byte, error)
}

type FileKeywordLoader struct {
	Paths []string
	// Embedded is used when none of Paths exist on disk, so the analyzer still
	// has its keyword list when run as a standalone binary.
	Embedded []byte
}

func (f *FileKeywordLoader) Load() ([]byte, error) {
	for _, p := range f.Paths {
		data, err := os.ReadFile(p)
		if err == nil && len(data) > 0 {
			return data, nil
		}
	}
	if len(f.Embedded) > 0 {
		return f.Embedded, nil
	}
	return nil, nil
}

type BytesKeywordLoader struct {
	Data []byte
}

func (b *BytesKeywordLoader) Load() ([]byte, error) {
	return b.Data, nil
}

var defaultSearchPaths = []string{
	"pkg/internal/configs/custom_keywords.txt",
	"pkg/internal/configs/custom_keywords.json",
	"pkg/internal/resources/custom_keywords.txt",
	"internal/resources/custom_keywords.txt",
	"resources/custom_keywords.txt",
	"custom_keywords.txt",
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTRUCTORS
// ═══════════════════════════════════════════════════════════════════════════════

func NewCustomKeywordDetector() *CustomKeywordDetector {
	d := &CustomKeywordDetector{
		maxPerFile:    50,
		maxPerKeyword: 5,
		minLength:     3,
		contextRadius: 40,
		loader: &FileKeywordLoader{
			Paths:    defaultSearchPaths,
			Embedded: configs.CustomKeywords(),
		},
	}
	d.loadKeywords()
	d.buildAutomaton() // строим AC ОДИН раз
	return d
}

func NewCustomKeywordDetectorWithLoader(loader KeywordLoader) *CustomKeywordDetector {
	d := &CustomKeywordDetector{
		maxPerFile:    50,
		maxPerKeyword: 5,
		minLength:     3,
		contextRadius: 40,
		loader:        loader,
	}
	d.loadKeywords()
	d.buildAutomaton()
	return d
}

func (d *CustomKeywordDetector) Name() string { return "custom_keyword" }

func (d *CustomKeywordDetector) KeywordCount() int {
	return len(d.keywords)
}

func (d *CustomKeywordDetector) Keywords() []string {
	out := make([]string, len(d.keywords))
	for i, k := range d.keywords {
		out[i] = k.Original
	}
	return out
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADD / LOAD KEYWORDS (с автоматическим перестроением AC)
// ═══════════════════════════════════════════════════════════════════════════════

func (d *CustomKeywordDetector) AddKeyword(pattern, tag string, suspicious bool) {
	pattern = strings.TrimSpace(pattern)
	if len(pattern) < d.minLength {
		return
	}
	d.keywords = append(d.keywords, keywordEntry{
		Pattern:    []byte(strings.ToLower(pattern)),
		Original:   pattern,
		Tag:        tag,
		Suspicious: suspicious,
		Mode:       keywordModeSubstring,
	})
	// Перестраиваем AC после добавления keyword
	d.buildAutomaton()
}

func (d *CustomKeywordDetector) LoadKeywordsFromBytes(data []byte) {
	parsed := parseKeywordData(data, d.minLength)
	d.keywords = append(d.keywords, parsed...)
	// Перестраиваем AC после загрузки
	d.buildAutomaton()
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUILD AUTOMATON — строим Aho-Corasick из non-regex keywords
// ═══════════════════════════════════════════════════════════════════════════════
//
// Вызывается ОДИН раз при инициализации (и при AddKeyword/LoadKeywordsFromBytes).
// Разделяет keywords на:
//   - AC-совместимые (substring + word) → один автомат
//   - Regex → отдельный список для ручной обработки

func (d *CustomKeywordDetector) buildAutomaton() {
	d.automaton = nil
	d.acToKeyword = nil
	d.regexIndices = nil

	if len(d.keywords) == 0 {
		return
	}

	var acPatterns []string

	for i, kw := range d.keywords {
		if len(kw.Pattern) < d.minLength {
			continue
		}

		if kw.Mode == keywordModeRegex {
			// Regex нельзя искать через AC
			d.regexIndices = append(d.regexIndices, i)
			continue
		}

		// substring и word — оба идут в AC
		// (word проверяет границы слов ПОСЛЕ нахождения через AC)
		acPatterns = append(acPatterns, string(kw.Pattern))
		d.acToKeyword = append(d.acToKeyword, i)
	}

	if len(acPatterns) > 0 {
		d.automaton = matcher.NewAhoCorasick(acPatterns)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DETECT — главный метод поиска
// ═══════════════════════════════════════════════════════════════════════════════
//
// Архитектура v2:
//
//   Phase 1: Aho-Corasick  — один проход, ВСЕ substring/word keywords → O(N)
//   Phase 2: Regex         — отдельно для каждого regex keyword
//
// Раньше (v1):
//   Для каждого из K keywords: bytes.Index по всему файлу → O(N × K)
//
// Теперь (v2):
//   AC: O(N) + Regex: O(R × N) где R << K (обычно 0-3 regex из 50 keywords)

func (d *CustomKeywordDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	if len(d.keywords) == 0 {
		return
	}
	if ctx.FileType == types.FileTypeNative {
		return
	}
	// A runtime-looking path alone must never suppress findings.
	if len(ctx.ContentLower) == 0 {
		return
	}
	if !isLikelyTextContent(ctx.Content) {
		return
	}
	if isLocalizationAsset(ctx.Path) {
		// Translation bundles are natural language: Swedish "magisk"
		// (= magical) is not Magisk, Esperanto "monero" (= coin) is not
		// Monero. Never keyword-scan localization files.
		return
	}

	totalHits := 0

	// Per-keyword hit counter — slice вместо map (быстрее, cache-friendly)
	kwHitCount := make([]int, len(d.keywords))

	// Дедупликация: (keyword_index, line) → уже видели?
	seen := make(map[hitKey]struct{}, 32)

	// ── Phase 1: Aho-Corasick для substring + word keywords ──────────────
	if d.automaton != nil {
		totalHits = d.detectWithAC(ctx, analysis, kwHitCount, seen, totalHits)
		if d.maxPerFile > 0 && totalHits >= d.maxPerFile {
			return
		}
	}

	// ── Phase 2: Regex keywords (не могут использовать AC) ───────────────
	if len(d.regexIndices) > 0 {
		d.detectRegex(ctx, analysis, kwHitCount, seen, totalHits)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 1: AHO-CORASICK — один проход по файлу, все keywords сразу
// ═══════════════════════════════════════════════════════════════════════════════

func (d *CustomKeywordDetector) detectWithAC(
	ctx *FileDetectContext,
	analysis *types.FileAnalysis,
	kwHitCount []int,
	seen map[hitKey]struct{},
	totalHits int,
) int {
	// Один проход по контенту — O(N) вместо O(N×K)!
	// SearchWithPositions возвращает ВСЕ вхождения с позициями
	contentLowerStr := string(ctx.ContentLower) // одна аллокация (вместо K × bytes.Index)
	hits := d.automaton.SearchWithPositions(contentLowerStr)

	for _, hit := range hits {
		if hit.PatternIndex < 0 || hit.PatternIndex >= len(d.acToKeyword) {
			continue
		}

		kwIdx := d.acToKeyword[hit.PatternIndex]
		kw := &d.keywords[kwIdx]

		// Per-keyword лимит — пропускаем если уже набрали максимум
		if d.maxPerKeyword > 0 && kwHitCount[kwIdx] >= d.maxPerKeyword {
			continue
		}

		// Вычисляем начальную позицию
		// hit.Position = позиция ПОСЛЕДНЕГО байта совпадения
		// startPos = позиция ПЕРВОГО байта
		patLen := len(kw.Pattern)
		startPos := hit.Position - patLen + 1
		if startPos < 0 || startPos+patLen > len(ctx.ContentLower) {
			continue
		}

		// Word-mode: проверяем границы слова ПОСЛЕ нахождения через AC
		if kw.Mode == keywordModeWord && !isWholeWord(ctx.ContentLower, startPos, patLen) {
			continue
		}

		// Определяем строку
		line := lineAt(ctx.LineOffsets, startPos)

		// Дедупликация по (keyword, line)
		hk := hitKey{kwIdx: kwIdx, line: line}
		if _, dup := seen[hk]; dup {
			continue
		}
		seen[hk] = struct{}{}

		// Создаём match
		desc := d.buildDescription(*kw)
		snippet := d.extractSnippet(ctx.Content, startPos, patLen)

		m := newMatch(
			types.CategoryCustomKeyword,
			analysis.Path, line,
			desc, kw.Original,
			kw.Suspicious,
		)
		m.Text = snippet
		applyKeywordSeverity(&m, *kw)
		analysis.Matches = append(analysis.Matches, m)

		totalHits++
		kwHitCount[kwIdx]++

		if d.maxPerFile > 0 && totalHits >= d.maxPerFile {
			return totalHits
		}
	}

	return totalHits
}

// ═══════════════════════════════════════════════════════════════════════════════
// PHASE 2: REGEX — отдельная обработка для regex keywords
// ═══════════════════════════════════════════════════════════════════════════════

func (d *CustomKeywordDetector) detectRegex(
	ctx *FileDetectContext,
	analysis *types.FileAnalysis,
	kwHitCount []int,
	seen map[hitKey]struct{},
	totalHits int,
) {
	for _, kwIdx := range d.regexIndices {
		kw := &d.keywords[kwIdx]
		if kw.Regex == nil {
			continue
		}

		kwHits := kwHitCount[kwIdx]
		searchFrom := 0

		for searchFrom <= len(ctx.Content) {
			loc := kw.Regex.FindIndex(ctx.Content[searchFrom:])
			if loc == nil {
				break
			}

			absIdx := searchFrom + loc[0]
			matchLen := loc[1] - loc[0]
			if matchLen <= 0 {
				searchFrom = absIdx + 1
				continue
			}

			line := lineAt(ctx.LineOffsets, absIdx)

			hk := hitKey{kwIdx: kwIdx, line: line}
			if _, dup := seen[hk]; !dup {
				seen[hk] = struct{}{}

				desc := d.buildDescription(*kw)
				snippet := d.extractSnippet(ctx.Content, absIdx, matchLen)

				m := newMatch(
					types.CategoryCustomKeyword,
					analysis.Path, line,
					desc, kw.Original,
					kw.Suspicious,
				)
				m.Text = snippet
				applyKeywordSeverity(&m, *kw)
				analysis.Matches = append(analysis.Matches, m)

				totalHits++
				kwHits++

				if d.maxPerFile > 0 && totalHits >= d.maxPerFile {
					return
				}
				if d.maxPerKeyword > 0 && kwHits >= d.maxPerKeyword {
					break
				}
			}

			searchFrom = absIdx + matchLen
		}

		kwHitCount[kwIdx] = kwHits
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// DESCRIPTION & SNIPPET
// ═══════════════════════════════════════════════════════════════════════════════

func (d *CustomKeywordDetector) buildDescription(kw keywordEntry) string {
	if kw.Tag != "" {
		return "Custom keyword [" + kw.Tag + "]"
	}
	return "Custom keyword hit"
}

func (d *CustomKeywordDetector) extractSnippet(content []byte, idx, kwLen int) string {
	start := idx - d.contextRadius
	if start < 0 {
		start = 0
	}
	end := idx + kwLen + d.contextRadius
	if end > len(content) {
		end = len(content)
	}

	snippet := content[start:end]
	localIdx := idx - start
	localEnd := localIdx + kwLen

	if localIdx < 0 {
		localIdx = 0
	}
	if localIdx > len(snippet) {
		localIdx = len(snippet)
	}
	if nlBefore := bytes.LastIndexByte(snippet[:localIdx], '\n'); nlBefore >= 0 {
		snippet = snippet[nlBefore+1:]
		localIdx -= nlBefore + 1
		if localIdx < 0 {
			localIdx = 0
		}
		localEnd = localIdx + kwLen
	}
	if localEnd > len(snippet) {
		localEnd = len(snippet)
	}
	if nlAfter := bytes.IndexByte(snippet[localEnd:], '\n'); nlAfter >= 0 {
		snippet = snippet[:localEnd+nlAfter]
	}

	s := strings.TrimSpace(string(snippet))

	const maxSnippet = 120
	if len(s) > maxSnippet {
		s = s[:maxSnippet] + "..."
	}

	return s
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEYWORD LOADING
// ═══════════════════════════════════════════════════════════════════════════════

func (d *CustomKeywordDetector) loadKeywords() {
	if d.loader == nil {
		return
	}
	data, err := d.loader.Load()
	if err != nil || len(data) == 0 {
		return
	}
	d.keywords = parseKeywordData(data, d.minLength)
}

// ═══════════════════════════════════════════════════════════════════════════════
// JSON PARSING
// ═══════════════════════════════════════════════════════════════════════════════

type jsonKeyword struct {
	Pattern    string `json:"pattern"`
	Tag        string `json:"tag,omitempty"`
	Suspicious bool   `json:"suspicious,omitempty"`
	Mode       string `json:"mode,omitempty"`
	WholeWord  bool   `json:"whole_word,omitempty"`
	Regex      bool   `json:"regex,omitempty"`
	Severity   string `json:"severity,omitempty"`
}

func parseKeywordData(data []byte, minLen int) []keywordEntry {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil
	}

	if trimmed[0] == '[' {
		if entries := parseJSON(trimmed, minLen); entries != nil {
			return entries
		}
	}

	return parsePlainText(data, minLen)
}

func parseJSON(data []byte, minLen int) []keywordEntry {
	var items []jsonKeyword
	if err := json.Unmarshal(data, &items); err != nil {
		return nil
	}

	seen := make(map[string]struct{}, len(items))
	out := make([]keywordEntry, 0, len(items))

	for _, item := range items {
		pattern := strings.TrimSpace(item.Pattern)
		if len(pattern) < minLen {
			continue
		}
		lower := strings.ToLower(pattern)
		if _, dup := seen[lower]; dup {
			continue
		}
		seen[lower] = struct{}{}

		mode := parseKeywordMode(item)
		entry := keywordEntry{
			Pattern:    []byte(lower),
			Original:   pattern,
			Tag:        strings.TrimSpace(item.Tag),
			Suspicious: item.Suspicious,
			Mode:       mode,
		}
		if mode == keywordModeRegex {
			re, err := compileKeywordRegex(pattern)
			if err != nil {
				continue
			}
			entry.Regex = re
		}
		if sev, ok := parseSeverity(item.Severity); ok {
			entry.Severity = sev
			entry.HasSeverity = true
		}
		out = append(out, entry)
	}

	return out
}

// ═══════════════════════════════════════════════════════════════════════════════
// PLAIN TEXT PARSING
// ═══════════════════════════════════════════════════════════════════════════════

func parsePlainText(data []byte, minLen int) []keywordEntry {
	lines := strings.Split(string(data), "\n")
	seen := make(map[string]struct{}, len(lines))
	out := make([]keywordEntry, 0, len(lines))

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || line[0] == '#' {
			continue
		}

		var tag, pattern string

		if strings.Contains(line, "://") {
			pattern = line
		} else if colonIdx := strings.Index(line, ":"); colonIdx > 0 && colonIdx < len(line)-1 {
			prefix := line[:colonIdx]
			if !strings.Contains(prefix, " ") && !strings.Contains(prefix, "/") {
				tag = prefix
				pattern = strings.TrimSpace(line[colonIdx+1:])
			} else {
				pattern = line
			}
		} else {
			pattern = line
		}

		if len(pattern) < minLen {
			continue
		}

		lower := strings.ToLower(pattern)
		if _, dup := seen[lower]; dup {
			continue
		}
		seen[lower] = struct{}{}

		out = append(out, keywordEntry{
			Pattern:    []byte(lower),
			Original:   pattern,
			Tag:        tag,
			Suspicious: false,
			Mode:       keywordModeSubstring,
		})
	}

	return out
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func parseKeywordMode(item jsonKeyword) keywordMode {
	mode := strings.ToLower(strings.TrimSpace(item.Mode))
	switch mode {
	case "word", "whole", "whole_word", "whole-word":
		return keywordModeWord
	case "regex":
		return keywordModeRegex
	case "substr", "substring", "":
		// default
	}

	if item.Regex {
		return keywordModeRegex
	}
	if item.WholeWord {
		return keywordModeWord
	}
	return keywordModeSubstring
}

func compileKeywordRegex(pattern string) (*regexp.Regexp, error) {
	expr := pattern
	if !strings.HasPrefix(expr, "(?i)") {
		expr = "(?i)" + expr
	}
	return regexp.Compile(expr)
}

func parseSeverity(s string) (types.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return types.SeverityCritical, true
	case "high":
		return types.SeverityHigh, true
	case "medium":
		return types.SeverityMedium, true
	case "low":
		return types.SeverityLow, true
	case "info":
		return types.SeverityInfo, true
	default:
		return types.SeverityInfo, false
	}
}

func scoreForSeverity(sev types.Severity) float64 {
	switch sev {
	case types.SeverityCritical:
		return 10
	case types.SeverityHigh:
		return 9
	case types.SeverityMedium:
		return 7
	case types.SeverityLow:
		return 4
	default:
		return 1
	}
}

func applyKeywordSeverity(m *types.Match, kw keywordEntry) {
	if !kw.HasSeverity {
		return
	}
	m.Score = scoreForSeverity(kw.Severity)
	if m.Metadata == nil {
		m.Metadata = map[string]string{}
	}
	m.Metadata["severity"] = kw.Severity.String()
	if kw.Severity == types.SeverityCritical {
		m.IsCritical = true
	}
}

func isWordChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '_':
		return true
	default:
		return false
	}
}

func isWholeWord(content []byte, start, length int) bool {
	if start < 0 || length <= 0 || start+length > len(content) {
		return false
	}
	if start > 0 && isWordChar(content[start-1]) {
		return false
	}
	end := start + length
	if end < len(content) && isWordChar(content[end]) {
		return false
	}
	return true
}

// isLocalizationAsset reports whether a path is a natural-language
// translation bundle (e.g. assets/messages/**/actors_sv.properties).
// Keyword-scanning such files yields systematic false positives: Swedish
// "magisk" (= magical) hits the Magisk root keyword, Esperanto "monero"
// (= coin) hits the Monero crypto keyword, Czech "obraze" contains
// "braze", etc.
func isLocalizationAsset(p string) bool {
	lp := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	if !strings.HasSuffix(lp, ".properties") && !strings.HasSuffix(lp, ".po") &&
		!strings.HasSuffix(lp, ".arb") && !strings.HasSuffix(lp, ".xlf") {
		return false
	}
	if strings.Contains(lp, "/messages/") || strings.Contains(lp, "/locale") ||
		strings.Contains(lp, "/i18n/") || strings.Contains(lp, "/lang/") ||
		strings.Contains(lp, "/translations/") {
		return true
	}
	// name_xx.properties / name_xx_YY.properties language-suffix convention.
	base := lp
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	if n := len(base); n >= 3 && base[n-3] == '_' {
		return true
	}
	return false
}
