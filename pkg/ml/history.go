package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultMaxHistory = 1000
	DefaultHistoryDir = ".analyzer"
	HistoryFileName   = "history.json"
)

type AnalysisHistory struct {
	mu       sync.Mutex // 🆕 Lock вместо RWMutex (Save мутирует dirty)
	path     string
	records  []*AnalysisFeedback
	maxItems int
	dirty    bool
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOAD / SAVE
// ═══════════════════════════════════════════════════════════════════════════════

func DefaultHistoryPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, DefaultHistoryDir, HistoryFileName), nil
}

func LoadHistory(path string) (*AnalysisHistory, error) {
	h := &AnalysisHistory{
		path:     path,
		maxItems: DefaultMaxHistory,
		records:  make([]*AnalysisFeedback, 0),
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return h, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, &h.records); err != nil {
		return nil, fmt.Errorf("corrupt history file: %w", err)
	}

	return h, nil
}

// LoadHistoryDefault загружает историю из дефолтного пути
func LoadHistoryDefault() (*AnalysisHistory, error) {
	path, err := DefaultHistoryPath()
	if err != nil {
		return nil, err
	}
	return LoadHistory(path)
}

// 🆕 Fix: Lock (не RLock!) + dirty=false после успешной записи + 0600
// 🆕 Fix: Используем уникальный .tmp файл + гарантированная очистка
func (h *AnalysisHistory) Save() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.dirty {
		return nil
	}

	dir := filepath.Dir(h.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(h.records, "", "  ")
	if err != nil {
		return err
	}

	// 🆕 FIX: Уникальное имя .tmp файла (избегаем коллизий на Windows)
	tmpPath := fmt.Sprintf("%s.%d.tmp", h.path, time.Now().UnixNano())

	// 🆕 FIX: Гарантированная очистка .tmp при любом исходе
	defer os.Remove(tmpPath)

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()

	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}

	if err := os.Rename(tmpPath, h.path); err != nil {
		return err
	}

	h.dirty = false
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// MUTATIONS
// ═══════════════════════════════════════════════════════════════════════════════

func (h *AnalysisHistory) Append(feedback *AnalysisFeedback) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.records = append(h.records, feedback)

	if len(h.records) > h.maxItems {
		h.records = h.records[len(h.records)-h.maxItems:]
	}

	h.dirty = true
}

func (h *AnalysisHistory) AddUserOverride(override UserOverride) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	override.Action = normalizeFeedbackAction(override.Action)
	if !validFeedbackAction(override.Action) {
		return fmt.Errorf("invalid feedback action %q", override.Action)
	}
	if userOverrideKey(override) == "" {
		return fmt.Errorf("feedback target cannot be empty")
	}

	// If there are no analysis records, create a fully initialized placeholder.
	if len(h.records) == 0 {
		h.records = append(h.records, &AnalysisFeedback{
			APKName:       "_user_feedback_",
			Timestamp:     time.Now(),
			KeywordStats:  make(map[string]*KeywordFeedback),
			LibraryStats:  make(map[string]*LibraryFeedback),
			CategoryStats: make(map[string]*CategoryFeedback),
			UserOverrides: []UserOverride{},
		})
	}

	last := h.records[len(h.records)-1]
	if last == nil {
		last = &AnalysisFeedback{
			APKName:       "_user_feedback_",
			Timestamp:     time.Now(),
			KeywordStats:  make(map[string]*KeywordFeedback),
			LibraryStats:  make(map[string]*LibraryFeedback),
			CategoryStats: make(map[string]*CategoryFeedback),
		}
		h.records[len(h.records)-1] = last
	}
	if override.Timestamp.IsZero() {
		override.Timestamp = time.Now()
	}
	if override.APKName == "" {
		override.APKName = last.APKName
	}
	// Label-only repeats are idempotent, while a new feature vector from another
	// APK is valuable ensemble training data and must remain in the journal.
	if IsDuplicateUserOverride(h.records, override) {
		return nil
	}
	last.UserOverrides = append(last.UserOverrides, override)

	if override.Keyword != "" {
		for keyword, kf := range last.KeywordStats {
			if kf == nil || NormalizeFeedbackTarget(keyword) != NormalizeFeedbackTarget(override.Keyword) {
				continue
			}
			switch override.Action {
			case FeedbackRelevant:
				kf.MarkedRelevant++
			case FeedbackNoise:
				kf.MarkedNoise++
			}
			break
		}
	}

	h.dirty = true
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUERIES
// ═══════════════════════════════════════════════════════════════════════════════

func (h *AnalysisHistory) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.records)
}

func (h *AnalysisHistory) Last() *AnalysisFeedback {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.records) == 0 {
		return nil
	}
	return h.records[len(h.records)-1]
}

func (h *AnalysisHistory) LastN(n int) []*AnalysisFeedback {
	h.mu.Lock()
	defer h.mu.Unlock()

	if n > len(h.records) {
		n = len(h.records)
	}

	result := make([]*AnalysisFeedback, n)
	copy(result, h.records[len(h.records)-n:])
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// Snapshot возвращает потокобезопасную копию всех записей
func (h *AnalysisHistory) Snapshot() []*AnalysisFeedback {
	h.mu.Lock()
	defer h.mu.Unlock()

	result := make([]*AnalysisFeedback, len(h.records))
	copy(result, h.records)
	return result
}

// AGGREGATION
// ═══════════════════════════════════════════════════════════════════════════════

type AggregatedKeywordStats struct {
	Keyword         string
	TotalTriggered  int
	TotalInLibrary  int
	TotalDampened   int
	TotalInAppCode  int
	TotalInFileName int
	TotalRelevant   int
	TotalNoise      int

	// 🆕 Суммы для точного пересчёта
	SumImportance    float64
	SumRawImportance float64

	NoiseRatio float64 // computed
	Precision  float64 // computed, -1 если нет данных
	SeenInAPKs int
}

// AvgImportance вычисляет среднее
func (a *AggregatedKeywordStats) AvgImportance() float64 {
	if a.TotalTriggered == 0 {
		return 0
	}
	return a.SumImportance / float64(a.TotalTriggered)
}

func (h *AnalysisHistory) AggregateKeywordStats() map[string]*AggregatedKeywordStats {
	h.mu.Lock()
	defer h.mu.Unlock()

	result := make(map[string]*AggregatedKeywordStats)

	for _, record := range h.records {
		if record == nil {
			continue
		}
		seenInThisAPK := make(map[string]bool)

		for keyword, kf := range record.KeywordStats {
			if kf == nil {
				continue
			}
			agg, ok := result[keyword]
			if !ok {
				agg = &AggregatedKeywordStats{Keyword: keyword}
				result[keyword] = agg
			}

			agg.TotalTriggered += kf.Triggered
			agg.TotalInLibrary += kf.InLibrary
			agg.TotalDampened += kf.Dampened
			agg.TotalInAppCode += kf.InAppCode
			agg.TotalInFileName += kf.InFileName
			agg.TotalRelevant += kf.MarkedRelevant
			agg.TotalNoise += kf.MarkedNoise

			// 🆕 Суммы
			agg.SumImportance += kf.SumImportance
			agg.SumRawImportance += kf.SumRawImportance

			if !seenInThisAPK[keyword] {
				agg.SeenInAPKs++
				seenInThisAPK[keyword] = true
			}
		}
	}

	for _, agg := range result {
		if agg.TotalTriggered > 0 {
			agg.NoiseRatio = float64(agg.TotalInLibrary+agg.TotalDampened) / float64(agg.TotalTriggered)
		}
		total := agg.TotalRelevant + agg.TotalNoise
		if total > 0 {
			agg.Precision = float64(agg.TotalRelevant) / float64(total)
		} else {
			agg.Precision = -1
		}
	}

	// Human corrections are decisions, not votes. Reconcile legacy duplicated
	// overrides and make the latest decision authoritative for hard labels.
	byNormalizedKeyword := make(map[string]*AggregatedKeywordStats, len(result))
	for keyword, agg := range result {
		byNormalizedKeyword[NormalizeFeedbackTarget(keyword)] = agg
	}
	for _, decision := range ResolveUserOverrideDecisions(h.records) {
		if decision.Keyword == "" {
			continue
		}
		agg := byNormalizedKeyword[NormalizeFeedbackTarget(decision.Keyword)]
		if agg == nil {
			continue
		}
		agg.TotalRelevant = 0
		agg.TotalNoise = 0
		switch decision.Action {
		case FeedbackRelevant:
			agg.TotalRelevant = 1
			agg.Precision = 1
		case FeedbackNoise:
			agg.TotalNoise = 1
			agg.Precision = 0
		case FeedbackNeutral:
			agg.Precision = -1
		}
	}

	return result
}

type AggregatedLibraryStats struct {
	Prefix           string
	Category         string
	TotalFiles       int
	TotalMatched     int
	TotalDampened    int
	TotalHighValue   int
	SumImportance    float64 // 🆕
	AlwaysNoiseCount int
	SeenInAPKs       int
}

func (a *AggregatedLibraryStats) AvgImportance() float64 {
	if a.TotalFiles == 0 {
		return 0
	}
	return a.SumImportance / float64(a.TotalFiles)
}

func (h *AnalysisHistory) AggregateLibraryStats() map[string]*AggregatedLibraryStats {
	h.mu.Lock()
	defer h.mu.Unlock()

	result := make(map[string]*AggregatedLibraryStats)

	for _, record := range h.records {
		if record == nil {
			continue
		}
		seenInThisAPK := make(map[string]bool)

		for prefix, lf := range record.LibraryStats {
			if lf == nil {
				continue
			}
			// 🆕 Нормализуем prefix для корректной агрегации
			normalizedPrefix := normalizeLibraryPrefix(prefix)

			agg, ok := result[normalizedPrefix]
			if !ok {
				agg = &AggregatedLibraryStats{
					Prefix:   normalizedPrefix,
					Category: lf.Category,
				}
				result[normalizedPrefix] = agg
			}

			agg.TotalFiles += lf.TotalFiles
			agg.TotalMatched += lf.MatchedFiles
			agg.TotalDampened += lf.DampenedMatches
			agg.TotalHighValue += lf.HighValueFiles
			agg.SumImportance += lf.SumImportance // 🆕

			if lf.IsAlwaysNoise() {
				agg.AlwaysNoiseCount++
			}

			if !seenInThisAPK[normalizedPrefix] {
				agg.SeenInAPKs++
				seenInThisAPK[normalizedPrefix] = true
			}
		}
	}

	return result
}

// 🆕 normalizeLibraryPrefix — канонический формат для агрегации
func normalizeLibraryPrefix(prefix string) string {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	prefix = strings.TrimPrefix(prefix, "smali/")
	prefix = strings.ReplaceAll(prefix, "\\", "/")

	// Trailing slash
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix = prefix + "/"
	}
	return prefix
}

func (h *AnalysisHistory) TopNoisyKeywords(n int) []*AggregatedKeywordStats {
	stats := h.AggregateKeywordStats()

	ranked := make([]*AggregatedKeywordStats, 0, len(stats))
	for _, agg := range stats {
		if agg.TotalTriggered >= 5 {
			ranked = append(ranked, agg)
		}
	}

	sort.Slice(ranked, func(i, j int) bool {
		return ranked[i].NoiseRatio > ranked[j].NoiseRatio
	})

	if len(ranked) > n {
		ranked = ranked[:n]
	}
	return ranked
}

func (h *AnalysisHistory) AlwaysNoiseLibraries(minAPKs int) []*AggregatedLibraryStats {
	stats := h.AggregateLibraryStats()

	result := make([]*AggregatedLibraryStats, 0)
	for _, agg := range stats {
		if agg.SeenInAPKs >= minAPKs && agg.AlwaysNoiseCount == agg.SeenInAPKs {
			result = append(result, agg)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalFiles > result[j].TotalFiles
	})

	return result
}
