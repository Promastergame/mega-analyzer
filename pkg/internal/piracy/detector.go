// Package piracy — detector.go
// Основной детектор пиратства
package piracy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/logger"
)

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

// MaxAnalysisSize — максимальный размер файла для анализа (защита от OOM).
const MaxAnalysisSize = 10 * 1024 * 1024 // 10 MB

// ═══════════════════════════════════════════════════════════════════════════════
// SCOPE BITSET — замена линейного поиска по []PatternScope
// ═══════════════════════════════════════════════════════════════════════════════

// scopeMask битовая маска для быстрой проверки scope.
type scopeMask uint8

const (
	scopePath     scopeMask = 1 << iota // ScopePath
	scopeFilename                       // ScopeFilename
	scopeContent                        // ScopeContent
	scopeResource                       // ScopeResource
	scopeAll      = scopePath | scopeFilename | scopeContent | scopeResource
)

// toScopeMask конвертирует слайс PatternScope в битовую маску.
// Пустой слайс означает «все scopes».
func toScopeMask(scopes []PatternScope) scopeMask {
	if len(scopes) == 0 {
		return scopeAll
	}
	var m scopeMask
	for _, s := range scopes {
		switch s {
		case ScopePath:
			m |= scopePath
		case ScopeFilename:
			m |= scopeFilename
		case ScopeContent:
			m |= scopeContent
		case ScopeResource:
			m |= scopeResource
		}
	}
	return m
}

func (m scopeMask) has(flag scopeMask) bool { return m&flag != 0 }

// ═══════════════════════════════════════════════════════════════════════════════
// DETECTOR
// ═══════════════════════════════════════════════════════════════════════════════

// Detector — детектор пиратства. Потокобезопасен.
type Detector struct {
	config       Config
	scopeCache   []scopeMask     // scopeCache[i] — маска для config.Sites[i]
	prefilter    *prefilterIndex // literal anchors for the one-pass content prefilter
	deobfuscator *DeobfuscationEngineV2
	scorer       *ScoringEngine
	cache        *ResultCache // keyed on path+content, invalidated via configGen
	configGen    int
	mu           sync.RWMutex
}

// resultCacheSize bounds the analysis-result cache's memory footprint. No TTL:
// NewResultCache skips the background cleanup goroutine when ttl is 0, and
// the LRU eviction in Set already bounds memory, so every Detector is
// cache-equipped without needing a Close() lifecycle.
const resultCacheSize = 2000

// NewDetector создаёт детектор с дефолтным конфигом.
func NewDetector() *Detector {
	d := &Detector{config: DefaultConfig, scorer: NewScoringEngine(), cache: NewResultCache(resultCacheSize, 0)}

	if err := CompileConfig(&d.config); err != nil {
		logger.Error("Failed to compile default piracy config", "error", err)
	}

	d.rebuildCaches()
	return d
}

// NewDetectorFromFile создаёт детектор из JSON-файла.
func NewDetectorFromFile(configPath string) (*Detector, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return newDetectorFromBytes(data, configPath)
}

// NewDetectorFromBytes builds a Detector from in-memory config JSON (e.g. the
// embedded piracy_sites.json), so the analyzer works without on-disk files.
func NewDetectorFromBytes(data []byte) (*Detector, error) {
	return newDetectorFromBytes(data, "embedded")
}

func newDetectorFromBytes(data []byte, src string) (*Detector, error) {
	if len(data) > MaxAnalysisSize {
		return nil, fmt.Errorf("config file too large: %d bytes", len(data))
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if config.SchemaVersion < SchemaVersion {
		logger.Warn("Migrating piracy config",
			"from", config.SchemaVersion, "to", SchemaVersion)
	}

	NormalizeConfig(&config)
	if err := CompileConfig(&config); err != nil {
		return nil, fmt.Errorf("compile config: %w", err)
	}

	logger.Info("Loaded piracy config",
		"path", src, "sites", len(config.Sites))

	d := &Detector{config: config, scorer: NewScoringEngine(), cache: NewResultCache(resultCacheSize, 0)}
	d.rebuildCaches()
	return d, nil
}

// rebuildCaches перестраивает внутренние кеши после изменения конфига.
// Вызывать под write-lock или до первого использования.
func (d *Detector) rebuildCaches() {
	d.scopeCache = make([]scopeMask, len(d.config.Sites))
	for i := range d.config.Sites {
		d.scopeCache[i] = toScopeMask(d.config.Sites[i].Scope)
	}
	d.prefilter = buildPrefilter(&d.config)
	d.deobfuscator = NewDeobfuscationEngineV2(d.config.Sites)
	// Bump the generation so any Analyze result cached under the old config
	// (e.g. before an AddSite) is treated as stale rather than reused.
	d.configGen++
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYSIS CONTEXT
// ═══════════════════════════════════════════════════════════════════════════════

// analysisContext — контекст анализа одного файла.
type analysisContext struct {
	path          string
	pathLower     []byte
	pathSegments  []string
	filename      string
	filenameLower []byte

	content      []byte
	contentLower []byte
	lineOffsets  *types.LineOffsets

	fileType   types.FileType
	isTextFile bool
	isResource bool

	// Дедупликация
	seenFindings map[string]struct{}
	seenFamilies map[string]struct{} // семья+location
	sitesFound   map[string]struct{}
	modFound     map[string]struct{}
	riskTags     map[string]struct{}

	// Кешированные false-positive данные
	fpContentLower string // ленивый кеш для isFalsePositive
	fpContentReady bool
}

func newAnalysisContext(
	path string,
	content []byte,
	fileType types.FileType,
	isText, isResource bool,
) *analysisContext {
	pathLower := []byte(strings.ToLower(path))
	filename := filepath.Base(path)

	actx := &analysisContext{
		path:          path,
		pathLower:     pathLower,
		pathSegments:  strings.Split(path, "/"),
		filename:      filename,
		filenameLower: []byte(strings.ToLower(filename)),
		fileType:      fileType,
		isTextFile:    isText,
		isResource:    isResource,
		seenFindings:  make(map[string]struct{}, 16),
		seenFamilies:  make(map[string]struct{}, 8),
		sitesFound:    make(map[string]struct{}, 4),
		modFound:      make(map[string]struct{}, 4),
		riskTags:      make(map[string]struct{}, 4),
	}

	if isText && len(content) > 0 {
		actx.content = content
		actx.contentLower = bytes.ToLower(content)
		actx.lineOffsets = types.NewLineOffsets(content)
	}

	return actx
}

// findingKey возвращает уникальный ключ для дедупликации.
// Используем strings.Builder вместо конкатенации для снижения аллокаций.
func (c *analysisContext) findingKey(typ, pattern, location string) string {
	var b strings.Builder
	b.Grow(len(typ) + len(pattern) + len(location) + 2)
	b.WriteString(typ)
	b.WriteByte('|')
	b.WriteString(pattern)
	b.WriteByte('|')
	b.WriteString(location)
	return b.String()
}

// locationKey формирует ключ «path:line».
func (c *analysisContext) locationKey(line int) string {
	return fmt.Sprintf("%s:%d", c.path, line)
}

// getContentLowerString возвращает кешированную lowercase-версию контента
// для проверки false positives (единожды).
func (c *analysisContext) getContentLowerString() string {
	if !c.fpContentReady {
		if len(c.contentLower) > 0 {
			// contentLower уже готов, переиспользуем
			c.fpContentLower = string(c.contentLower)
		} else {
			c.fpContentLower = strings.ToLower(c.path)
		}
		c.fpContentReady = true
	}
	return c.fpContentLower
}

// isDuplicate проверяет и регистрирует находку. Возвращает true если дубль.
func (c *analysisContext) isDuplicate(key string) bool {
	if _, exists := c.seenFindings[key]; exists {
		return true
	}
	c.seenFindings[key] = struct{}{}
	return false
}

// registerFamily регистрирует семью паттерна; возвращает true если уже была.
func (c *analysisContext) registerFamily(typ, family, location string) bool {
	fk := c.findingKey(typ, family, location)
	if _, exists := c.seenFamilies[fk]; exists {
		return true
	}
	c.seenFamilies[fk] = struct{}{}
	return false
}

// shouldSkipByFamily проверяет, нужно ли пропустить catch-all паттерн.
func (c *analysisContext) shouldSkipByFamily(typ, pattern, location string) bool {
	family := getPatternFamily(pattern)
	fk := c.findingKey(typ, family, location)
	if _, exists := c.seenFamilies[fk]; !exists {
		return false
	}
	// Catch-all паттерны всегда уступают специфичным
	return isCatchAllPattern(pattern)
}

// trackSite регистрирует обнаруженный сайт и его risk tags.
func (c *analysisContext) trackSite(name string, tags []string) {
	c.sitesFound[name] = struct{}{}
	for _, tag := range tags {
		c.riskTags[tag] = struct{}{}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN FAMILY — группировка семантически связанных паттернов
// ═══════════════════════════════════════════════════════════════════════════════

// patternFamilyRule описывает правило определения семьи.
type patternFamilyRule struct {
	family    string
	matchFunc func(lower string) bool
}

var patternFamilyRules = []patternFamilyRule{
	{"androeed_family", func(s string) bool { return strings.Contains(s, "androeed") }},
	{"happymod_family", func(s string) bool {
		return strings.Contains(s, "happy") && strings.Contains(s, "mod")
	}},
	{"acmarket_family", func(s string) bool {
		return strings.Contains(s, "acmarket") || strings.Contains(s, "ac_market")
	}},
	{"luckypatcher_family", func(s string) bool {
		return strings.Contains(s, "lucky") && strings.Contains(s, "patcher")
	}},
}

func getPatternFamily(pattern string) string {
	lower := strings.ToLower(pattern)

	// unlocked семья
	if lower == "_unlocked" || lower == "unlocked" || strings.HasSuffix(lower, "_unlocked") {
		return "unlocked_family"
	}

	for _, rule := range patternFamilyRules {
		if rule.matchFunc(lower) {
			return rule.family
		}
	}

	return pattern
}

// isCatchAllPattern определяет «обобщённые» паттерны,
// которые должны уступать более специфичным.
func isCatchAllPattern(pattern string) bool {
	return pattern == "_unlocked" || pattern == "unlocked"
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENFORCE MAX FINDINGS
// ═══════════════════════════════════════════════════════════════════════════════

func enforceMaxFindings(actx *analysisContext, result *Result) bool {
	if len(result.Findings) < MaxFindingsPerFile {
		return false
	}

	// Освобождаем место для предупреждения
	if MaxFindingsPerFile > 1 {
		result.Findings = result.Findings[:MaxFindingsPerFile-1]
	}

	key := actx.findingKey("warning", "max_findings_reached", actx.path)
	if !actx.isDuplicate(key) {
		result.Findings = append(result.Findings, Finding{
			Type:        "warning",
			Source:      "system",
			Pattern:     "max_findings_reached",
			Location:    actx.path,
			Confidence:  1.0,
			Description: "Too many findings, analysis truncated",
		})
	}

	return true
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

// piracyCacheKey folds path, file type and content into a fixed 32-byte
// lookup key. The previous form allocated a full copy of every scanned file
// just to build the key, and the cache then hashed that copy again - two
// O(file) passes plus one file-sized allocation per Analyze call, on cache
// hits too. piracy was 80.8% of detector time in the Phase 2 measurement.
func piracyCacheKey(path string, fileType types.FileType, content []byte) []byte {
	h := sha256.New()
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write([]byte(string(fileType)))
	h.Write([]byte{0})
	h.Write(content)
	return h.Sum(nil)
}

// Analyze анализирует файл на предмет пиратства.
func (d *Detector) Analyze(
	ctx context.Context,
	path string,
	content []byte,
	fileType types.FileType,
) (*Result, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if len(content) > MaxAnalysisSize {
		content = content[:MaxAnalysisSize]
	}

	d.mu.RLock()
	config := d.config
	scopes := d.scopeCache
	prefilter := d.prefilter
	deobfuscator := d.deobfuscator
	cache := d.cache
	configGen := d.configGen
	d.mu.RUnlock()

	// Same bytes can score differently depending on where they live (path is
	// itself a signal, see analyzePathAndName) and how they're interpreted, so
	// the cache key folds in path and fileType alongside the content.
	cacheKey := piracyCacheKey(path, fileType, content)
	if cache != nil {
		if cached, ok := cache.Get(cacheKey, configGen); ok {
			return cached, nil
		}
	}

	isText := isTextFileType(fileType)
	isResource := fileType == types.FileTypeResource

	actx := newAnalysisContext(path, content, fileType, isText, isResource)

	result := &Result{
		Findings:      make([]Finding, 0, 8),
		SitesFound:    make([]string, 0, 4),
		ModIndicators: make([]string, 0, 4),
		RiskTags:      make([]string, 0, 4),
	}

	// 1. Анализ пути и имени файла (всегда)
	d.analyzePathAndName(ctx, actx, &config, scopes, result)
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 2. Анализ текстового содержимого
	if isText && len(content) > 0 {
		if err := d.analyzeTextContent(ctx, actx, &config, scopes, prefilter, result); err != nil {
			return nil, err
		}
		if err := d.analyzeObfuscatedURLs(ctx, actx, deobfuscator, result); err != nil {
			return nil, err
		}
	}

	// 3. Анализ ресурсов
	if isResource {
		d.analyzeResource(ctx, actx, &config, scopes, result)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	// 4. Вычисление итогового результата
	d.calculateResult(result, actx)

	if cache != nil {
		cache.Set(cacheKey, result, configGen)
	}

	return result, nil
}

func isTextFileType(ft types.FileType) bool {
	switch ft {
	case types.FileTypeSmali, types.FileTypeXML, types.FileTypeJSON,
		types.FileTypeText, types.FileTypeProperties:
		return true
	default:
		return false
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATH & NAME ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func (d *Detector) analyzePathAndName(
	ctx context.Context,
	actx *analysisContext,
	config *Config,
	scopes []scopeMask,
	result *Result,
) {
	for i := range config.Sites {
		select {
		case <-ctx.Done():
			return
		default:
		}

		site := &config.Sites[i]
		if site.IsLegitMirror {
			continue
		}
		sm := scopes[i]

		checkPath := sm.has(scopePath)
		checkFilename := sm.has(scopeFilename)
		if !checkPath && !checkFilename {
			continue
		}

		for _, cp := range site.CompiledPatterns {
			found, matchedIn := d.matchPathOrFilename(
				cp, actx.pathLower, actx.filenameLower,
				checkPath, checkFilename,
			)
			if !found {
				continue
			}

			// Avoid false positive on xposed vs exposed
			if strings.Contains(strings.ToLower(cp.Original), "xposed") {
				if matchedIn == "path" {
					idx := d.findPatternIndex(cp, actx.pathLower)
					if idx > 0 && actx.pathLower[idx-1] == 'e' {
						continue
					}
				} else if matchedIn == "filename" {
					idx := d.findPatternIndex(cp, actx.filenameLower)
					if idx > 0 && actx.filenameLower[idx-1] == 'e' {
						continue
					}
				}
			}

			key := actx.findingKey("path", cp.Original, actx.path)
			if actx.isDuplicate(key) {
				continue
			}

			if d.isFalsePositivePath(site, actx.path) {
				continue
			}

			result.Findings = append(result.Findings, Finding{
				Type:       "path",
				Source:     site.Name,
				Pattern:    cp.Original,
				Location:   actx.path,
				Confidence: site.Confidence * cp.Weight * 0.8,
				Weight:     cp.Weight,
				Description: fmt.Sprintf(
					"%s contains %s reference (%s)",
					matchedIn, site.Name, site.Description,
				),
				SiteName:   site.Name,
				SiteDomain: firstDomain(site),
				SiteType:   site.Type,
				RiskTags:   site.RiskTags,
			})
			if enforceMaxFindings(actx, result) {
				return
			}

			actx.trackSite(site.Name, site.RiskTags)
		}
	}

	// Mod-паттерны в пути
	for _, cp := range config.ModCompiled {
		if !d.matchPattern(cp, actx.pathLower) && !d.matchPattern(cp, actx.filenameLower) {
			continue
		}

		key := actx.findingKey("path_mod", cp.Original, actx.path)
		if actx.isDuplicate(key) {
			continue
		}

		result.Findings = append(result.Findings, Finding{
			Type:        "path_mod",
			Source:      "mod_indicator",
			Pattern:     cp.Original,
			Location:    actx.path,
			Confidence:  0.6 * cp.Weight,
			Weight:      cp.Weight,
			Description: fmt.Sprintf("Path contains MOD indicator: %s", cp.Original),
		})
		if enforceMaxFindings(actx, result) {
			return
		}

		actx.modFound[cp.Original] = struct{}{}
	}
}

// matchPathOrFilename проверяет паттерн по пути и/или имени файла.
func (d *Detector) matchPathOrFilename(
	cp *CompiledPattern,
	pathLower, filenameLower []byte,
	checkPath, checkFilename bool,
) (found bool, matchedIn string) {
	if checkPath && d.matchPattern(cp, pathLower) {
		return true, "path"
	}
	if checkFilename && d.matchPattern(cp, filenameLower) {
		return true, "filename"
	}
	return false, ""
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEXT CONTENT ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func (d *Detector) analyzeTextContent(
	ctx context.Context,
	actx *analysisContext,
	config *Config,
	scopes []scopeMask,
	prefilter *prefilterIndex,
	result *Result,
) error {
	// One automaton pass over the file feeds every pattern loop below.
	hits := prefilter.hits(actx.contentLower)

	if err := d.analyzeSitePatterns(ctx, actx, config, scopes, prefilter, hits, result); err != nil {
		return err
	}

	if err := d.analyzeModPatterns(ctx, actx, config, prefilter, hits, result); err != nil {
		return err
	}
	if err := d.analyzeCrackPatterns(ctx, actx, config, prefilter, hits, result); err != nil {
		return err
	}

	return nil
}

// analyzeSitePatterns — поиск паттернов пиратских сайтов в содержимом.
func (d *Detector) analyzeSitePatterns(
	ctx context.Context,
	actx *analysisContext,
	config *Config,
	scopes []scopeMask,
	prefilter *prefilterIndex,
	hits []bool,
	result *Result,
) error {
	for i := range config.Sites {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		site := &config.Sites[i]
		if site.IsLegitMirror {
			continue
		}
		if !scopes[i].has(scopeContent) {
			continue
		}

		// Compiled string patterns
		patternAnchors := prefilter.patternAnchors(i)
		for j, cp := range site.CompiledPatterns {
			if anchorMiss(hits, anchorAt(patternAnchors, j)) {
				continue
			}

			idx := d.findPatternIndex(cp, actx.contentLower)
			if idx < 0 {
				continue
			}

			// Avoid false positive on xposed vs exposed
			if strings.Contains(strings.ToLower(cp.Original), "xposed") {
				for idx >= 0 && idx < len(actx.contentLower) {
					if idx > 0 && actx.contentLower[idx-1] == 'e' {
						nextIdx := bytes.Index(actx.contentLower[idx+len(cp.Lower):], cp.Lower)
						if nextIdx < 0 {
							idx = -1
							break
						}
						idx = idx + len(cp.Lower) + nextIdx
					} else {
						break
					}
				}
				if idx < 0 {
					continue
				}
			}

			line := actx.lineAt(idx)
			locKey := actx.locationKey(line)

			if actx.shouldSkipByFamily("site_line", cp.Original, locKey) {
				continue
			}

			key := actx.findingKey("site_line", site.Name, locKey)
			if actx.isDuplicate(key) {
				continue
			}

			// Регистрируем семью
			family := getPatternFamily(cp.Original)
			actx.registerFamily("site_line", family, locKey)

			if d.isFalsePositiveContent(site, actx, idx) {
				continue
			}

			result.Findings = append(result.Findings, Finding{
				Type:       "site",
				Source:     site.Name,
				Pattern:    cp.Original,
				Location:   actx.path,
				Line:       line,
				Confidence: site.Confidence * cp.Weight,
				Weight:     cp.Weight,
				Description: fmt.Sprintf(
					"Reference to %s (%s)", site.Name, site.Description,
				),
				SiteName:   site.Name,
				SiteDomain: firstDomain(site),
				SiteType:   site.Type,
				RiskTags:   site.RiskTags,
			})
			if enforceMaxFindings(actx, result) {
				return nil
			}

			actx.trackSite(site.Name, site.RiskTags)
		}

		// Compiled regex patterns
		regexAnchorIDs := prefilter.regexAnchorIDs(i)
		for j, re := range site.CompiledRegex {
			if anchorsMiss(hits, anchorListAt(regexAnchorIDs, j)) {
				continue
			}

			loc := re.FindIndex(actx.content)
			if loc == nil {
				continue
			}

			// Avoid false positive on xposed vs exposed
			if strings.Contains(strings.ToLower(re.String()), "xposed") {
				for loc != nil {
					start := loc[0]
					if start > 0 && (actx.content[start-1] == 'e' || actx.content[start-1] == 'E') {
						offset := start + 1
						if offset >= len(actx.content) {
							loc = nil
							break
						}
						nextLoc := re.FindIndex(actx.content[offset:])
						if nextLoc == nil {
							loc = nil
							break
						}
						loc = []int{offset + nextLoc[0], offset + nextLoc[1]}
					} else {
						break
					}
				}
				if loc == nil {
					continue
				}
			}

			line := actx.lineAt(loc[0])
			locKey := actx.locationKey(line)
			if d.isFalsePositiveContent(site, actx, loc[0]) {
				continue
			}

			key := actx.findingKey("site_line", site.Name, locKey)
			if actx.isDuplicate(key) {
				continue
			}

			family := getPatternFamily(site.Name)
			actx.registerFamily("site_line", family, locKey)

			result.Findings = append(result.Findings, Finding{
				Type:        "site",
				Source:      site.Name,
				Pattern:     re.String(),
				Location:    actx.path,
				Line:        line,
				Confidence:  site.Confidence,
				Description: fmt.Sprintf("Regex match for %s", site.Name),
				SiteName:    site.Name,
				SiteDomain:  firstDomain(site),
				SiteType:    site.Type,
				RiskTags:    site.RiskTags,
			})
			if enforceMaxFindings(actx, result) {
				return nil
			}

			actx.sitesFound[site.Name] = struct{}{}
		}
	}
	return nil
}

// analyzeModPatterns — поиск модификационных индикаторов.
func (d *Detector) analyzeModPatterns(
	ctx context.Context,
	actx *analysisContext,
	config *Config,
	prefilter *prefilterIndex,
	hits []bool,
	result *Result,
) error {
	for i, cp := range config.ModCompiled {
		if err := ctx.Err(); err != nil {
			return err
		}
		if prefilter != nil && anchorMiss(hits, anchorAt(prefilter.mod, i)) {
			continue
		}

		idx := d.findPatternIndex(cp, actx.contentLower)
		if idx < 0 {
			continue
		}

		line := actx.lineAt(idx)
		locKey := actx.locationKey(line)

		if actx.shouldSkipByFamily("mod", cp.Original, locKey) {
			continue
		}

		key := actx.findingKey("mod", cp.Original, locKey)
		if actx.isDuplicate(key) {
			continue
		}

		family := getPatternFamily(cp.Original)
		actx.registerFamily("mod", family, locKey)

		strength := inferModStrength(actx, cp.Original, idx)

		result.Findings = append(result.Findings, Finding{
			Type:        "mod",
			Source:      "mod_indicator",
			Pattern:     cp.Original,
			Location:    actx.path,
			Line:        line,
			Confidence:  0.7 * cp.Weight,
			Weight:      cp.Weight,
			Strength:    strength,
			Description: fmt.Sprintf("MOD indicator: %s", cp.Original),
		})
		if enforceMaxFindings(actx, result) {
			return nil
		}

		actx.modFound[cp.Original] = struct{}{}
	}
	return nil
}

// analyzeCrackPatterns — поиск индикаторов взлома.
func (d *Detector) analyzeCrackPatterns(
	ctx context.Context,
	actx *analysisContext,
	config *Config,
	prefilter *prefilterIndex,
	hits []bool,
	result *Result,
) error {
	for i, cp := range config.CrackCompiled {
		if err := ctx.Err(); err != nil {
			return err
		}
		if prefilter != nil && anchorMiss(hits, anchorAt(prefilter.crack, i)) {
			continue
		}

		idx := d.findPatternIndex(cp, actx.contentLower)
		if idx < 0 {
			continue
		}

		key := actx.findingKey("crack", cp.Original, actx.path)
		if actx.isDuplicate(key) {
			continue
		}

		line := actx.lineAt(idx)

		result.Findings = append(result.Findings, Finding{
			Type:        "crack",
			Source:      "crack_indicator",
			Pattern:     cp.Original,
			Location:    actx.path,
			Line:        line,
			Confidence:  0.9 * cp.Weight,
			Weight:      cp.Weight,
			Description: fmt.Sprintf("Crack indicator: %s", cp.Original),
			RiskTags:    []string{"crack", "bypass"},
		})
		if enforceMaxFindings(actx, result) {
			return nil
		}

		actx.riskTags["crack"] = struct{}{}
	}
	return nil
}

// analyzeObfuscatedURLs turns successfully decoded references to known piracy
// domains into ordinary evidence. The deobfuscator is deliberately invoked only
// for text content and has its own size/depth limits, so this closes the
// obfuscation blind spot without changing binary-resource handling.
func (d *Detector) analyzeObfuscatedURLs(
	ctx context.Context,
	actx *analysisContext,
	deobfuscator *DeobfuscationEngineV2,
	result *Result,
) error {
	if deobfuscator == nil || len(actx.content) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	for _, decoded := range deobfuscator.Detect(actx.content) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if decoded.Domain == "" {
			continue
		}
		// Anti double-count: one watermark must not be billed twice per file.
		// When the decoded domain is also present as plain text, the site
		// pattern scan has already recorded it (as one or more "Reference
		// to ..." findings), so a separate "recovered via ... encoding"
		// finding would count the decode AND every plain mention of the very
		// same watermark.
		if len(actx.contentLower) > 0 &&
			bytes.Contains(actx.contentLower, []byte(strings.ToLower(decoded.Domain))) {
			continue
		}
		if siteAlreadyFound(result, actx.path, decoded.Domain) {
			continue
		}
		key := actx.findingKey("obfuscated_site", decoded.Domain, actx.path)
		if actx.isDuplicate(key) {
			continue
		}

		confidence := decoded.Confidence
		if confidence <= 0 {
			confidence = 0.9
		}
		result.Findings = append(result.Findings, Finding{
			Type:        "site",
			Source:      "deobfuscation",
			Pattern:     decoded.Domain,
			Location:    actx.path,
			Confidence:  confidence,
			Strength:    StrengthStrong,
			Description: fmt.Sprintf("Known piracy domain recovered via %s encoding", decoded.Method),
			SiteName:    decoded.Domain,
			SiteDomain:  decoded.Domain,
			RiskTags:    []string{"obfuscated", "piracy"},
		})
		actx.trackSite(decoded.Domain, []string{"obfuscated", "piracy"})
		if enforceMaxFindings(actx, result) {
			return nil
		}
	}
	return nil
}

// siteAlreadyFound reports whether the direct pattern scan already recorded
// a finding for the same piracy site/domain in this file. Used to avoid
// counting one watermark as both a decode event and N plain references.
func siteAlreadyFound(result *Result, path, domain string) bool {
	d := strings.ToLower(domain)
	label := d
	if i := strings.IndexByte(d, '.'); i > 0 {
		label = d[:i]
	}
	for i := range result.Findings {
		f := &result.Findings[i]
		if f.Location != path || f.Source == "deobfuscation" {
			continue
		}
		sd := strings.ToLower(f.SiteDomain)
		sn := strings.ToLower(f.SiteName)
		if (sd != "" && sd == d) || (sn != "" && sn == d) {
			return true
		}
		// Match by registrable label ("androeed" vs "androeed.ru"); short
		// labels are skipped to avoid accidental collisions.
		if len(label) >= 5 && (sn == label || strings.HasPrefix(sd, label+".")) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// RESOURCE ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func (d *Detector) analyzeResource(
	ctx context.Context,
	actx *analysisContext,
	config *Config,
	scopes []scopeMask,
	result *Result,
) {
	// Site watermarks
	for i := range config.Sites {
		select {
		case <-ctx.Done():
			return
		default:
		}

		site := &config.Sites[i]
		if site.IsLegitMirror {
			continue
		}
		if !scopes[i].has(scopeResource) {
			continue
		}

		for _, wm := range site.Watermarks {
			if !d.matchWatermark(wm, actx.filenameLower, actx.pathLower) {
				continue
			}

			key := actx.findingKey("watermark", wm.Value, actx.path)
			if actx.isDuplicate(key) {
				continue
			}

			confidence := wm.Confidence
			if confidence == 0 {
				confidence = site.Confidence * 0.9
			}

			result.Findings = append(result.Findings, Finding{
				Type:        "watermark",
				Source:      site.Name,
				Pattern:     wm.Value,
				Location:    actx.path,
				Confidence:  confidence,
				Description: fmt.Sprintf("Possible %s watermark image", site.Name),
				SiteName:    site.Name,
				SiteDomain:  firstDomain(site),
				SiteType:    site.Type,
			})
			if enforceMaxFindings(actx, result) {
				return
			}

			actx.sitesFound[site.Name] = struct{}{}
		}
	}

	// Global watermark patterns
	for _, wm := range config.WatermarkPatterns {
		wmLower := []byte(strings.ToLower(wm.Value))
		if !bytes.Contains(actx.filenameLower, wmLower) {
			continue
		}

		key := actx.findingKey("watermark", wm.Value, actx.path)
		if actx.isDuplicate(key) {
			continue
		}

		confidence := wm.Confidence
		if confidence == 0 {
			confidence = 0.6
		}

		result.Findings = append(result.Findings, Finding{
			Type:        "watermark",
			Source:      "watermark_image",
			Pattern:     wm.Value,
			Location:    actx.path,
			Confidence:  confidence,
			Description: fmt.Sprintf("Possible watermark image: %s", wm.Value),
		})
		if enforceMaxFindings(actx, result) {
			return
		}
	}
}

// matchWatermark проверяет наличие watermark в имени файла или пути.
func (d *Detector) matchWatermark(wm WatermarkPattern, filenameLower, pathLower []byte) bool {
	wmLower := []byte(strings.ToLower(wm.Value))
	return bytes.Contains(filenameLower, wmLower) || bytes.Contains(pathLower, wmLower)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN MATCHING
// ═══════════════════════════════════════════════════════════════════════════════

func (d *Detector) matchPattern(cp *CompiledPattern, content []byte) bool {
	switch cp.Mode {
	case MatchExact:
		return bytes.Equal(content, cp.Lower)
	case MatchWord:
		if cp.Regex != nil {
			return cp.Regex.Match(content)
		}
		return wordIndex(content, cp.Lower) >= 0
	case MatchRegex:
		if cp.Regex != nil {
			return cp.Regex.Match(content)
		}
		return bytes.Contains(content, cp.Lower)
	default:
		return bytes.Contains(content, cp.Lower)
	}
}

func (d *Detector) findPatternIndex(cp *CompiledPattern, content []byte) int {
	switch cp.Mode {
	case MatchWord:
		if cp.Regex != nil {
			if loc := cp.Regex.FindIndex(content); loc != nil {
				return loc[0]
			}
			return -1
		}
		return wordIndex(content, cp.Lower)
	case MatchRegex:
		if cp.Regex != nil {
			if loc := cp.Regex.FindIndex(content); loc != nil {
				return loc[0]
			}
			return -1
		}
		return bytes.Index(content, cp.Lower)
	default:
		return bytes.Index(content, cp.Lower)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// FALSE POSITIVE DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

// isFalsePositivePath проверяет false positives для пути (дешёвая операция).
func (d *Detector) isFalsePositivePath(site *Site, path string) bool {
	if len(site.FalsePositiveWords) == 0 {
		return false
	}
	pathLower := strings.ToLower(path)
	for _, fp := range falsePositiveWordsLower(site) {
		if strings.Contains(pathLower, fp) {
			return true
		}
	}
	return false
}

// isFalsePositiveContent проверяет false positives для содержимого.
// Использует кешированную lowercase-версию.
func (d *Detector) isFalsePositiveContent(site *Site, actx *analysisContext, matchOffset int) bool {
	if len(site.FalsePositiveWords) == 0 {
		return false
	}
	content := actx.getContentLowerString()
	// A file may contain an unrelated disclaimer or test fixture. Only a
	// nearby suppressor can invalidate this particular match.
	const contextWindow = 200
	if matchOffset >= 0 && matchOffset < len(content) {
		start := matchOffset - contextWindow
		if start < 0 {
			start = 0
		}
		end := matchOffset + contextWindow
		if end > len(content) {
			end = len(content)
		}
		content = content[start:end]
	}
	for _, fp := range falsePositiveWordsLower(site) {
		if strings.Contains(content, fp) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI STRENGTH INFERENCE
// ═══════════════════════════════════════════════════════════════════════════════

// inferUnlockedStrength определяет силу сигнала для *_unlocked паттернов.
func inferUnlockedStrength(actx *analysisContext, pattern string, idx int) SignalStrength {
	if actx == nil {
		return ""
	}

	if pattern != "premium_unlocked" && !strings.HasSuffix(pattern, "_unlocked") {
		return ""
	}

	// UI strings в ресурсах — слабый сигнал
	if actx.fileType == types.FileTypeXML && isResValuesPath(actx.pathLower) {
		return StrengthWeak
	}

	// Эвристика только для smali
	if actx.fileType != types.FileTypeSmali || idx < 0 || len(actx.content) == 0 {
		return ""
	}

	lineStart, lineEnd := lineBoundsAt(actx.content, idx)
	line := trimLine(actx.content[lineStart:lineEnd])

	// Always-true branch: const/4 vX, 0x1 → (sput/iput)-boolean vX
	if reg := regFromBoolStore(line); reg != "" {
		if hasConstTrueInPrevLines(actx.content, lineStart, reg, 2) {
			return StrengthStrong
		}
	}

	// If-condition: (sget/iget)-boolean vX → if-<op> vX, :label
	if reg := regFromBoolLoad(line); reg != "" {
		if hasIfConditionInNextLines(actx.content, lineEnd, reg, 3) {
			return StrengthMedium
		}
	}

	return ""
}

func isResValuesPath(pathLower []byte) bool {
	return bytes.Contains(pathLower, []byte("res/values")) ||
		bytes.Contains(pathLower, []byte("res\\values"))
}

// ═══════════════════════════════════════════════════════════════════════════════
// LINE UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

// lineAt возвращает номер строки по позиции в контенте.
func (c *analysisContext) lineAt(idx int) int {
	if c.lineOffsets != nil {
		return c.lineOffsets.LineAt(idx)
	}
	return 0
}

func lineBoundsAt(content []byte, idx int) (start, end int) {
	if idx < 0 {
		return 0, 0
	}
	if idx > len(content) {
		idx = len(content)
	}
	start = bytes.LastIndexByte(content[:idx], '\n')
	if start == -1 {
		start = 0
	} else {
		start++
	}
	endRel := bytes.IndexByte(content[idx:], '\n')
	if endRel == -1 {
		end = len(content)
	} else {
		end = idx + endRel
	}
	return start, end
}

func prevLineBounds(content []byte, currentStart int) (start, end int, ok bool) {
	if currentStart <= 0 {
		return 0, 0, false
	}
	end = currentStart - 1
	start = bytes.LastIndexByte(content[:end], '\n')
	if start == -1 {
		start = 0
	} else {
		start++
	}
	return start, end, true
}

func nextLineBounds(content []byte, currentEnd int) (start, end int, ok bool) {
	if currentEnd >= len(content) {
		return 0, 0, false
	}
	start = currentEnd + 1
	if start >= len(content) {
		return 0, 0, false
	}
	endRel := bytes.IndexByte(content[start:], '\n')
	if endRel == -1 {
		end = len(content)
	} else {
		end = start + endRel
	}
	return start, end, true
}

func trimLine(line []byte) []byte {
	return bytes.TrimSpace(bytes.TrimRight(line, "\r"))
}

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI REGISTER ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func regFromBoolStore(line []byte) string {
	if !bytes.Contains(line, []byte("put-boolean")) {
		return ""
	}
	return firstRegister(line)
}

func regFromBoolLoad(line []byte) string {
	if !bytes.Contains(line, []byte("get-boolean")) {
		return ""
	}
	return firstRegister(line)
}

func firstRegister(line []byte) string {
	for i := 0; i < len(line); i++ {
		if line[i] != 'v' && line[i] != 'p' {
			continue
		}
		j := i + 1
		for j < len(line) && line[j] >= '0' && line[j] <= '9' {
			j++
		}
		if j == i+1 {
			continue
		}
		if (i == 0 || !isWordChar(line[i-1])) && (j >= len(line) || !isWordChar(line[j])) {
			return string(line[i:j])
		}
		i = j
	}
	return ""
}

func hasConstTrueInPrevLines(content []byte, lineStart int, reg string, maxLines int) bool {
	start := lineStart
	for i := 0; i < maxLines; i++ {
		prevStart, prevEnd, ok := prevLineBounds(content, start)
		if !ok {
			return false
		}
		if isConstTrueForReg(trimLine(content[prevStart:prevEnd]), reg) {
			return true
		}
		start = prevStart
	}
	return false
}

func hasIfConditionInNextLines(content []byte, lineEnd int, reg string, maxLines int) bool {
	end := lineEnd
	for i := 0; i < maxLines; i++ {
		nextStart, nextEnd, ok := nextLineBounds(content, end)
		if !ok {
			return false
		}
		if isIfLineWithReg(trimLine(content[nextStart:nextEnd]), reg) {
			return true
		}
		end = nextEnd
	}
	return false
}

func isConstTrueForReg(line []byte, reg string) bool {
	return len(line) > 0 &&
		bytes.HasPrefix(line, []byte("const")) &&
		containsWord(line, reg) &&
		containsWord(line, "0x1")
}

func isIfLineWithReg(line []byte, reg string) bool {
	return len(line) > 0 &&
		bytes.HasPrefix(line, []byte("if-")) &&
		containsWord(line, reg)
}

func containsWord(line []byte, token string) bool {
	if token == "" {
		return false
	}
	tokenBytes := []byte(token)
	idx := bytes.Index(line, tokenBytes)
	for idx >= 0 {
		beforeOk := idx == 0 || !isWordChar(line[idx-1])
		after := idx + len(tokenBytes)
		afterOk := after >= len(line) || !isWordChar(line[after])
		if beforeOk && afterOk {
			return true
		}
		next := bytes.Index(line[after:], tokenBytes)
		if next < 0 {
			break
		}
		idx = after + next
	}
	return false
}

func isWordChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '_'
}

// ═══════════════════════════════════════════════════════════════════════════════
// RESULT CALCULATION
// ═══════════════════════════════════════════════════════════════════════════════

func (d *Detector) calculateResult(result *Result, actx *analysisContext) {
	if len(result.Findings) == 0 {
		result.IsPirated = false
		result.Confidence = 0
		result.RiskLevel = "low"
		return
	}

	result.SitesFound = sortedKeys(actx.sitesFound)
	result.ModIndicators = sortedKeys(actx.modFound)
	result.RiskTags = sortedKeys(actx.riskTags)

	// The scoring engine accounts for signal type, strength, duplicate decay and
	// corroborating combinations. The former count-based formula could turn many
	// copies of one weak token into a high-risk verdict.
	if d.scorer != nil {
		scored := d.scorer.CalculateScore(result.Findings)
		result.Confidence = scored.FinalConfidence
		result.RiskLevel = string(scored.RiskLevel)
		result.IsPirated = scored.FinalConfidence >= 0.5
		return
	}

	// Defensive fallback for manually constructed legacy detectors.
	var maxConf float64
	for i := range result.Findings {
		if result.Findings[i].Confidence > maxConf {
			maxConf = result.Findings[i].Confidence
		}
	}
	result.Confidence = maxConf
	result.IsPirated = result.Confidence >= 0.5
	result.RiskLevel = riskLevelFromConfidence(result.Confidence)
}

// inferModStrength keeps generic feature/configuration terms from carrying the
// same severity as an actual entitlement bypass. They remain visible as weak
// evidence and can still contribute when corroborated by an independent signal.
func inferModStrength(actx *analysisContext, pattern string, idx int) SignalStrength {
	if strength := inferUnlockedStrength(actx, pattern, idx); strength != "" {
		return strength
	}
	switch strings.ToLower(pattern) {
	case "no_ads", "ad_free", "adfree", "headshot", "aimbot", "aim_bot",
		"autoaim", "auto_aim", "root_hide", "no_root", "антибан", "anti_ban", "antiban", "взлом":
		return StrengthWeak
	default:
		return StrengthMedium
	}
}

func riskLevelFromConfidence(conf float64) string {
	switch {
	case conf >= 0.9:
		return "critical"
	case conf >= 0.7:
		return "high"
	case conf >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

// sortedKeys возвращает отсортированные ключи map[string]struct{}.
func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// firstDomain возвращает первый домен сайта или пустую строку.
func firstDomain(site *Site) string {
	if len(site.Domains) > 0 {
		return site.Domains[0]
	}
	return ""
}

// ═══════════════════════════════════════════════════════════════════════════════
// MANAGEMENT METHODS
// ═══════════════════════════════════════════════════════════════════════════════

// AddSite добавляет сайт. Потокобезопасно.
func (d *Detector) AddSite(site Site) error {
	if err := CompileSite(&site); err != nil {
		return err
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.config.Sites = append(d.config.Sites, site)
	// New domains must be added to both the content prefilter and the
	// deobfuscator's known-domain set; updating only scopeCache left dynamic
	// configuration partially active.
	d.rebuildCaches()
	return nil
}

// ExportConfig экспортирует конфиг в JSON.
func (d *Detector) ExportConfig(path string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	data, err := json.MarshalIndent(d.config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0640)
}

// GetSiteCount возвращает количество сайтов.
func (d *Detector) GetSiteCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.config.Sites)
}

// GetConfig возвращает копию конфига (read-only).
func (d *Detector) GetConfig() Config {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.config
}

// falsePositiveWordsLower returns the false-positive words pre-lowercased at
// compile time, falling back to lowering them on the fly for hand-built
// configs that never went through CompileSite.
func falsePositiveWordsLower(site *Site) []string {
	if len(site.FalsePositiveLower) == len(site.FalsePositiveWords) {
		return site.FalsePositiveLower
	}
	out := make([]string, 0, len(site.FalsePositiveWords))
	for _, fp := range site.FalsePositiveWords {
		out = append(out, strings.ToLower(fp))
	}
	return out
}
