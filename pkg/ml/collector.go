package ml

import (
	"sort"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/filter"
)

// ═══════════════════════════════════════════════════════════════════════════════
// DAMPENING THRESHOLDS — из конфигурации, не магические числа!
// ═══════════════════════════════════════════════════════════════════════════════

// DampeningThresholds хранит пороги из ScoringConfig
type DampeningThresholds struct {
	Floor   float64
	Ceiling float64
}

// DefaultDampeningThresholds — fallback если config не передан
var DefaultDampeningThresholds = DampeningThresholds{
	Floor:   0.2,
	Ceiling: 1.5,
}

// ═══════════════════════════════════════════════════════════════════════════════
// COLLECTOR
// ═══════════════════════════════════════════════════════════════════════════════

type Collector struct {
	mu sync.Mutex

	// Настройки
	apkName   string
	apkHash   string
	pkg       string
	profile   string
	startTime time.Time

	// 🆕 Из конфигурации (не хардкод!)
	dampeningThresholds DampeningThresholds
	maxTopFiles         int

	// Счётчики
	totalFiles    int
	analyzedFiles int
	totalMatches  int
	criticalCount int
	fastPathHits  int
	savedFromFP   int

	// Аккумуляторы
	keywordStats  map[string]*KeywordFeedback
	libraryStats  map[string]*LibraryFeedback
	categoryStats map[string]*CategoryFeedback
	topFiles      []FileFeedback
	dampeningAcc  *dampeningAccumulator
}

type dampeningAccumulator struct {
	totalDampened int
	totalBoosted  int
	sumDampening  float64
	floorHits     int
	ceilingHits   int
	sources       map[string]int
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTRUCTOR
// ═══════════════════════════════════════════════════════════════════════════════

// CollectorOption — functional option для настройки collector
type CollectorOption func(*Collector)

// WithDampeningThresholds устанавливает пороги из config
func WithDampeningThresholds(floor, ceiling float64) CollectorOption {
	return func(c *Collector) {
		c.dampeningThresholds = DampeningThresholds{Floor: floor, Ceiling: ceiling}
	}
}

// WithMaxTopFiles устанавливает максимум top files
func WithMaxTopFiles(n int) CollectorOption {
	return func(c *Collector) {
		c.maxTopFiles = n
	}
}

func NewCollector(apkName, pkg, profile string, opts ...CollectorOption) *Collector {
	c := &Collector{
		apkName:             apkName,
		pkg:                 pkg,
		profile:             profile,
		startTime:           time.Now(),
		maxTopFiles:         50,
		dampeningThresholds: DefaultDampeningThresholds,
		keywordStats:        make(map[string]*KeywordFeedback),
		libraryStats:        make(map[string]*LibraryFeedback),
		categoryStats:       make(map[string]*CategoryFeedback),
		topFiles:            make([]FileFeedback, 0, 64),
		dampeningAcc: &dampeningAccumulator{
			sources: make(map[string]int),
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// ═══════════════════════════════════════════════════════════════════════════════
// SETTERS
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Collector) SetAPKHash(hash string) {
	c.mu.Lock()
	c.apkHash = hash
	c.mu.Unlock()
}

func (c *Collector) SetTotalFiles(total int) {
	c.mu.Lock()
	c.totalFiles = total
	c.mu.Unlock()
}

func (c *Collector) SetCacheStats(stats filter.CacheStats) {
	c.mu.Lock()
	c.fastPathHits = int(stats.FastPathHits)
	c.savedFromFP = int(stats.SavedFromFastPath)
	c.mu.Unlock()
}

// ═══════════════════════════════════════════════════════════════════════════════
// RECORD — thread-safe сбор данных
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Collector) RecordClassification(path string, result *filter.ClassificationResult) {
	if result == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.analyzedFiles++

	for _, match := range result.MatchedKeywords {
		c.recordKeyword(match, result)
	}

	if result.IsLibrary && result.MatchedLibrary != nil {
		c.recordLibrary(path, result)
	}

	for _, cat := range result.Categories {
		c.recordCategory(cat, result)
	}

	matchCount := len(result.MatchedKeywords) + len(result.MatchedHighValue)
	if matchCount > 0 {
		c.totalMatches += matchCount
	}
	if result.Importance >= 8 {
		c.criticalCount++
	}

	c.recordDampening(result)

	if result.Importance >= 3 || len(result.MatchedHighValue) > 0 {
		c.recordTopFile(path, result)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// RECORD HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Collector) recordKeyword(match filter.KeywordMatch, result *filter.ClassificationResult) {
	kf, ok := c.keywordStats[match.Keyword]
	if !ok {
		kf = &KeywordFeedback{
			Keyword:  match.Keyword,
			Contexts: make(map[string]int),
		}
		c.keywordStats[match.Keyword] = kf
	}

	kf.Triggered++

	if result.IsAppCode && !result.IsLibrary {
		kf.InAppCode++
	}
	if result.IsLibrary {
		kf.InLibrary++
	}
	if match.Dampened {
		kf.Dampened++
	}

	ctxName := match.Context.String()
	kf.Contexts[ctxName]++

	if match.Context == filter.ContextFileName {
		kf.InFileName++
	}

	// 🆕 Суммы вместо running average
	kf.SumImportance += float64(result.Importance)
	kf.SumRawImportance += float64(result.RawImportance)

	for _, comb := range match.Combinators {
		c.recordCombinator(kf, comb)
	}
}

func (c *Collector) recordCombinator(kf *KeywordFeedback, combinator string) {
	for i := range kf.TopCombinators {
		if kf.TopCombinators[i].Combinator == combinator {
			kf.TopCombinators[i].Count++
			return
		}
	}
	kf.TopCombinators = append(kf.TopCombinators, CombinatorStat{
		Combinator: combinator,
		Count:      1,
	})
}

func (c *Collector) recordLibrary(_ string, result *filter.ClassificationResult) {
	prefix := result.MatchedLibrary.Pattern

	lf, ok := c.libraryStats[prefix]
	if !ok {
		lf = &LibraryFeedback{
			Prefix:   prefix,
			Category: result.MatchedLibrary.Category,
			Keywords: make(map[string]int),
		}
		c.libraryStats[prefix] = lf
	}

	lf.TotalFiles++

	if len(result.MatchedKeywords) > 0 {
		lf.MatchedFiles++
	}
	if len(result.MatchedHighValue) > 0 {
		lf.HighValueFiles++
	}

	// 🆕 Сумма вместо running average
	lf.SumImportance += float64(result.Importance)

	for _, match := range result.MatchedKeywords {
		lf.Keywords[match.Keyword]++
		if match.Dampened {
			lf.DampenedMatches++
		}
	}
}

func (c *Collector) recordCategory(cat string, result *filter.ClassificationResult) {
	cf, ok := c.categoryStats[cat]
	if !ok {
		cf = &CategoryFeedback{Category: cat}
		c.categoryStats[cat] = cf
	}

	cf.Files++
	cf.Matches += len(result.MatchedKeywords) + len(result.MatchedHighValue)
	if result.Importance >= 8 {
		cf.Critical++
	}
}

func (c *Collector) recordDampening(result *filter.ClassificationResult) {
	if result.TotalDampening < 1.0 {
		c.dampeningAcc.totalDampened++
		c.dampeningAcc.sumDampening += result.TotalDampening
	} else if result.TotalDampening > 1.0 {
		c.dampeningAcc.totalBoosted++
	}

	// 🆕 Используем thresholds из config вместо магических чисел!
	epsilon := 0.001
	if result.TotalDampening <= c.dampeningThresholds.Floor+epsilon {
		c.dampeningAcc.floorHits++
	}
	if result.TotalDampening >= c.dampeningThresholds.Ceiling-epsilon {
		c.dampeningAcc.ceilingHits++
	}

	for _, src := range result.DampeningSources {
		name := src
		if idx := strings.Index(src, "("); idx > 0 {
			name = src[:idx]
		}
		c.dampeningAcc.sources[name]++
	}
}

func (c *Collector) recordTopFile(path string, result *filter.ClassificationResult) {
	ff := FileFeedback{
		Path:              path,
		Importance:        result.Importance,
		RawImportance:     result.RawImportance,
		Confidence:        result.Confidence,
		IsLibrary:         result.IsLibrary,
		IsAppCode:         result.IsAppCode,
		Categories:        result.Categories,
		TotalDampening:    result.TotalDampening,
		RawStrength:       result.RawStrength.String(),
		EffectiveStrength: result.EffectiveStrength.String(),
	}

	for _, match := range result.MatchedKeywords {
		ff.MatchedKeywords = append(ff.MatchedKeywords, match.Keyword)
	}
	for _, hv := range result.MatchedHighValue {
		ff.MatchedHighValue = append(ff.MatchedHighValue, hv.Pattern)
	}

	c.topFiles = append(c.topFiles, ff)
}

// ═══════════════════════════════════════════════════════════════════════════════
// FINALIZE
// ═══════════════════════════════════════════════════════════════════════════════

func (c *Collector) Finalize() *AnalysisFeedback {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Сортируем top files
	sort.Slice(c.topFiles, func(i, j int) bool {
		if c.topFiles[i].Importance != c.topFiles[j].Importance {
			return c.topFiles[i].Importance > c.topFiles[j].Importance
		}
		return c.topFiles[i].RawImportance > c.topFiles[j].RawImportance
	})
	if len(c.topFiles) > c.maxTopFiles {
		c.topFiles = c.topFiles[:c.maxTopFiles]
	}

	// Сортируем и обрезаем combinators
	for _, kf := range c.keywordStats {
		sort.Slice(kf.TopCombinators, func(i, j int) bool {
			return kf.TopCombinators[i].Count > kf.TopCombinators[j].Count
		})
		if len(kf.TopCombinators) > 5 {
			kf.TopCombinators = kf.TopCombinators[:5]
		}
	}

	var avgDampening float64
	if c.dampeningAcc.totalDampened > 0 {
		avgDampening = c.dampeningAcc.sumDampening / float64(c.dampeningAcc.totalDampened)
	}

	return &AnalysisFeedback{
		ID:            GenerateFeedbackID(c.apkName, c.startTime),
		APKHash:       c.apkHash,
		APKName:       c.apkName,
		Package:       c.pkg,
		Timestamp:     c.startTime,
		TotalFiles:    c.totalFiles,
		AnalyzedFiles: c.analyzedFiles,
		TotalMatches:  c.totalMatches,
		CriticalCount: c.criticalCount,
		FastPathHits:  c.fastPathHits,
		SavedFromFP:   c.savedFromFP,
		Profile:       c.profile,
		KeywordStats:  c.keywordStats,
		LibraryStats:  c.libraryStats,
		CategoryStats: c.categoryStats,
		TopFiles:      c.topFiles,
		DampeningStats: &DampeningFeedback{
			TotalDampened: c.dampeningAcc.totalDampened,
			TotalBoosted:  c.dampeningAcc.totalBoosted,
			AvgDampening:  avgDampening,
			FloorHits:     c.dampeningAcc.floorHits,
			CeilingHits:   c.dampeningAcc.ceilingHits,
			Sources:       c.dampeningAcc.sources,
		},
	}
}
