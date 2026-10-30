package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/piracy"
	"mega-analyzer/pkg/ml/ensemble"
)

// ═══════════════════════════════════════════════════════════════════════════════
// 🆕 BUILT-IN NOISE PATTERNS — авто-фильтр репакеров
// ═══════════════════════════════════════════════════════════════════════════════

var (
	// KnownWatermarks — репакерские/warez watermark-строки, авто-подавляемые
	// как шум (damp 0.01). Источник истины — пакет piracy (его DefaultConfig:
	// домены/алиасы/watermark'и 30+ пиратских сайтов), а НЕ хардкод в ml.
	// Раньше здесь лежал ручной список из 9 доменов; теперь он вынесен в
	// piracy.WatermarkKeywords() и расширяется добавлением сайта в один пакет.
	KnownWatermarks = piracy.WatermarkKeywords()

	KnownLibraryPrefixes = map[string]float64{
		"Landroidx/": 0.1, "Lcom/google/android/gms": 0.1,
		"Lcom/google/android/material": 0.1, "Lkotlin/": 0.15,
		"Lorg/jetbrains/": 0.15, "Lokhttp3/": 0.2,
		"Lb0/": 0.05, "La1/": 0.05, "Li0/": 0.05, "Ld0/": 0.05,
		"Ln/": 0.05, "Lv/": 0.05, "Lw0/": 0.05, "Lk/": 0.05,
	}

	sortedKnownLibraryPrefixes []struct {
		prefix string
		damp   float64
	}
)

func init() {
	sortedKnownLibraryPrefixes = make([]struct {
		prefix string
		damp   float64
	}, 0, len(KnownLibraryPrefixes))
	for k, v := range KnownLibraryPrefixes {
		sortedKnownLibraryPrefixes = append(sortedKnownLibraryPrefixes, struct {
			prefix string
			damp   float64
		}{k, v})
	}
	sort.Slice(sortedKnownLibraryPrefixes, func(i, j int) bool {
		return len(sortedKnownLibraryPrefixes[i].prefix) > len(sortedKnownLibraryPrefixes[j].prefix)
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYSIS FEEDBACK — что собираем при каждом анализе
// ═══════════════════════════════════════════════════════════════════════════════

type AnalysisFeedback struct {
	// ── Идентификация ────────────────────────────────────────────
	ID        string    `json:"id"`
	APKHash   string    `json:"apk_hash"`
	APKName   string    `json:"apk_name"`
	Package   string    `json:"package"`
	Timestamp time.Time `json:"timestamp"`

	// ── Общая статистика ─────────────────────────────────────────
	TotalFiles    int `json:"total_files"`
	AnalyzedFiles int `json:"analyzed_files"`
	TotalMatches  int `json:"total_matches"`
	CriticalCount int `json:"critical_count"`
	FastPathHits  int `json:"fast_path_hits"`
	SavedFromFP   int `json:"saved_from_fast_path"`

	// ── Profile ──────────────────────────────────────────────────
	Profile string `json:"profile"`

	// ── Core stats ───────────────────────────────────────────────
	KeywordStats   map[string]*KeywordFeedback  `json:"keyword_stats"`
	LibraryStats   map[string]*LibraryFeedback  `json:"library_stats"`
	CategoryStats  map[string]*CategoryFeedback `json:"category_stats"`
	TopFiles       []FileFeedback               `json:"top_files"`
	DampeningStats *DampeningFeedback           `json:"dampening_stats"`
	UserOverrides  []UserOverride               `json:"user_overrides,omitempty"`

	// MethodFeatures snapshots the ensemble feature vector of every scored
	// method from this run's --ml-patch pass (nil when --ml-patch wasn't run).
	// A later --mark-relevant/--mark-noise call matches its target against
	// these snapshots to attach a labeled feature vector to the resulting
	// UserOverride — see UserOverride.Features and markFeedback.
	MethodFeatures []MethodFeatureSnapshot `json:"method_features,omitempty"`

	// ── 🆕 Threat intelligence ───────────────────────────────────
	ThreatStats        *ThreatFeedback          `json:"threat_stats,omitempty"`
	AccessibilityStats *AccessibilityFeedback   `json:"accessibility_stats,omitempty"`
	BehavioralStats    *BehavioralFeedback      `json:"behavioral_stats,omitempty"`
	CorrelationMatrix  *CorrelationFeedback     `json:"correlation_matrix,omitempty"`
	ModelConfidence    *ModelConfidenceFeedback `json:"model_confidence,omitempty"`

	// 🆕 Watermark detection
	WatermarkStats *WatermarkFeedback `json:"watermark_stats,omitempty"`
}

// 🆕 WatermarkFeedback — обнаружение репаков
type WatermarkFeedback struct {
	DetectedWatermarks []string `json:"detected_watermarks"`
	WatermarkDensity   float64  `json:"watermark_density"` // matches / files
	IsRepacked         bool     `json:"is_repacked"`
	PrimarySource      string   `json:"primary_source"`
	ConfidencePenalty  float64  `json:"confidence_penalty"` // 0..1
}

// ═══════════════════════════════════════════════════════════════════════════════
// KEYWORD FEEDBACK
// ═══════════════════════════════════════════════════════════════════════════════

type KeywordFeedback struct {
	Keyword string `json:"keyword"`

	Triggered  int `json:"triggered"`
	InAppCode  int `json:"in_app_code"`
	InLibrary  int `json:"in_library"`
	Dampened   int `json:"dampened"`
	InFileName int `json:"in_file_name"`

	SumImportance    float64 `json:"sum_importance"`
	SumRawImportance float64 `json:"sum_raw_importance"`
	SumImportanceSq  float64 `json:"sum_importance_sq"` // для variance

	Contexts       map[string]int   `json:"contexts"`
	TopCombinators []CombinatorStat `json:"top_combinators,omitempty"`

	MarkedRelevant int `json:"marked_relevant"`
	MarkedNoise    int `json:"marked_noise"`

	// ── 🆕 Temporal ──────────────────────────────────────────────
	FirstSeen  time.Time `json:"first_seen,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	APKsSeenIn int       `json:"apks_seen_in"`

	// ── 🆕 Context-aware ─────────────────────────────────────────
	ImportanceByContext map[string]float64 `json:"importance_by_context,omitempty"`

	// ── 🆕 Threat correlation ────────────────────────────────────
	ThreatRelevance float64  `json:"threat_relevance"`
	CoOccursWith    []string `json:"co_occurs_with,omitempty"`

	// 🆕 Watermark metrics
	FilesSpread    int     `json:"files_spread"` // в скольких файлах
	UniqueFiles    int     `json:"unique_files"`
	WatermarkScore float64 `json:"watermark_score"` // 0..1
}

type CombinatorStat struct {
	Combinator string `json:"combinator"`
	Count      int    `json:"count"`
}

func (kf *KeywordFeedback) AvgImportance() float64 {
	if kf.Triggered == 0 {
		return 0
	}
	return kf.SumImportance / float64(kf.Triggered)
}

func (kf *KeywordFeedback) AvgRawImportance() float64 {
	if kf.Triggered == 0 {
		return 0
	}
	return kf.SumRawImportance / float64(kf.Triggered)
}

func (kf *KeywordFeedback) Precision() float64 {
	total := kf.MarkedRelevant + kf.MarkedNoise
	if total == 0 {
		return -1
	}
	return float64(kf.MarkedRelevant) / float64(total)
}

func (kf *KeywordFeedback) NoiseRatio() float64 {
	if kf.Triggered == 0 {
		return 0
	}
	return float64(kf.InLibrary+kf.Dampened) / float64(kf.Triggered)
}

// 🆕 ImportanceStdDev — стандартное отклонение importance
func (kf *KeywordFeedback) ImportanceStdDev() float64 {
	if kf.Triggered < 2 {
		return 0
	}
	mean := kf.AvgImportance()
	variance := (kf.SumImportanceSq / float64(kf.Triggered)) - (mean * mean)
	if variance < 0 {
		variance = 0
	}
	return math.Sqrt(variance)
}

// KeywordRelevanceFeatureNames is the fixed, ordered feature list shared by the
// trainer (pkg/ml/training) and the live scorer. The order is part of the
// on-disk model contract: never reorder existing entries, append only.
//
// Only fields present in BOTH KeywordFeedback and AggregatedKeyword are used,
// so the features computed at training time exactly match those computed at
// serving time (recalculateWeights operates on AggregatedKeyword). This avoids
// train/serve skew. threat_relevance / watermark / context features are
// intentionally excluded because they are absent from AggregatedKeyword (and
// are all-zero across the current history corpus anyway).
var KeywordRelevanceFeatureNames = []string{
	"log_triggered",       // log1p(Triggered)
	"in_app_ratio",        // InAppCode / Triggered
	"in_library_ratio",    // InLibrary / Triggered  (noise proxy)
	"avg_importance",      // SumImportance / Triggered
	"log_apks_seen",       // log1p(APKsSeenIn)
	"app_minus_lib_ratio", // (InAppCode - InLibrary) / Triggered
	"importance_x_app",    // avg_importance * in_app_ratio
	"log_sum_importance",  // log1p(SumImportance)
}

// ToFeatureVector converts this keyword's aggregate stats into the
// KeywordRelevanceFeatureNames-ordered feature vector consumed by the relevance
// model. Pure math, no allocations beyond the result slice. The same logic is
// reused at serving time by converting AggregatedKeyword into a transient
// KeywordFeedback (see AggregatedKeyword.toFeedback in the scoring path).
func (kf *KeywordFeedback) ToFeatureVector() []float64 {
	t := float64(kf.Triggered)
	inApp := float64(kf.InAppCode)
	inLib := float64(kf.InLibrary)
	safe := func(x float64) float64 {
		if t == 0 {
			return 0
		}
		return x / t
	}
	avgImp := safe(kf.SumImportance)
	inAppRatio := safe(inApp)
	return []float64{
		math.Log1p(t),
		inAppRatio,
		safe(inLib),
		avgImp,
		math.Log1p(float64(kf.APKsSeenIn)),
		safe(inApp - inLib),
		avgImp * inAppRatio,
		math.Log1p(kf.SumImportance),
	}
}

// KeywordRelevanceScorer is implemented by training.KeywordScorer. It is
// declared here (in package ml) to break the import cycle: the training package
// imports ml, so ml must not import training. The LearningEngine consumes a
// trained model only through this interface, keeping the heuristic fallback the
// default when no model is wired in.
type KeywordRelevanceScorer interface {
	// ScoreKeyword returns a calibrated probability in [0,1] that the keyword
	// is relevant (1) rather than noise (0).
	ScoreKeyword(kf *KeywordFeedback) float64
	// IsLoaded reports whether a trained model backs this scorer.
	IsLoaded() bool
}

// 🆕 IsWatermark — детектор репакера
func (kf *KeywordFeedback) IsWatermark(totalFiles int) bool {
	// 1. Известный вотермарк
	if _, ok := KnownWatermarks[strings.ToLower(kf.Keyword)]; ok {
		return true
	}
	if totalFiles == 0 {
		return false
	}

	// 2. Spread > 30% файлов + низкая важность
	spread := float64(kf.FilesSpread) / float64(totalFiles)
	if spread > 0.3 && kf.AvgImportance() < 1.0 {
		return true
	}

	// 3. >100 файлов, почти всегда в либах
	if kf.FilesSpread > 100 && kf.NoiseRatio() > 0.9 {
		return true
	}

	return false
}

// 🆕 IsStableNoise — стабильно шумный keyword (УЛУЧШЕННЫЙ)
func (kf *KeywordFeedback) IsStableNoise(threshold float64, totalFiles int) bool {
	// Быстрый выход для вотермарков
	if kf.IsWatermark(totalFiles) {
		return true
	}

	return kf.Triggered >= 5 && // было 10
		kf.AvgImportance() < threshold &&
		kf.ImportanceStdDev() < 1.5 && // было 1.0
		kf.NoiseRatio() > 0.6 // было 0.7
}

// 🆕 IsContextDependent — importance зависит от контекста
func (kf *KeywordFeedback) IsContextDependent() bool {
	if len(kf.ImportanceByContext) < 2 {
		return false
	}
	var minVal, maxVal float64
	first := true
	for _, v := range kf.ImportanceByContext {
		if first {
			minVal, maxVal = v, v
			first = false
			continue
		}
		if v < minVal {
			minVal = v
		}
		if v > maxVal {
			maxVal = v
		}
	}
	return (maxVal - minVal) > 3.0
}

// 🆕 SignalQuality — оценка качества сигнала (0..1) с watermark penalty
func (kf *KeywordFeedback) SignalQuality(totalFiles int) float64 {
	if kf.Triggered == 0 {
		return 0
	}

	// Мгновенный штраф за вотермарк
	if kf.IsWatermark(totalFiles) {
		return 0.01
	}

	quality := 0.0

	precision := kf.Precision()
	if precision >= 0 {
		quality += precision * 0.4
	} else {
		quality += 0.2
	}

	if avg := kf.AvgImportance(); avg > 5.0 {
		quality += 0.3
	} else if avg > 2.0 {
		quality += 0.15
	}

	appCodeRatio := float64(kf.InAppCode) / float64(kf.Triggered)
	quality += appCodeRatio * 0.3

	return math.Min(quality, 1.0)
}

// ═══════════════════════════════════════════════════════════════════════════════
// LIBRARY FEEDBACK
// ═══════════════════════════════════════════════════════════════════════════════

type LibraryFeedback struct {
	Prefix          string         `json:"prefix"`
	TotalFiles      int            `json:"total_files"`
	MatchedFiles    int            `json:"matched_files"`
	DampenedMatches int            `json:"dampened_matches"`
	HighValueFiles  int            `json:"high_value_files"`
	SumImportance   float64        `json:"sum_importance"`
	Keywords        map[string]int `json:"keywords"`
	Category        string         `json:"category"`

	// 🆕
	APKsSeenIn      int     `json:"apks_seen_in"`
	MaxImportance   float64 `json:"max_importance"`
	HasCriticalHits bool    `json:"has_critical_hits"`
}

func (lf *LibraryFeedback) AvgImportance() float64 {
	if lf.TotalFiles == 0 {
		return 0
	}
	return lf.SumImportance / float64(lf.TotalFiles)
}

// 🆕 IsAlwaysNoise — с проверкой known prefixes
func (lf *LibraryFeedback) IsAlwaysNoise() bool {
	// Проверка по известным префиксам
	if damp, ok := KnownLibraryPrefixes[lf.Prefix]; ok && damp < 0.2 {
		return lf.HighValueFiles == 0
	}
	return lf.HighValueFiles == 0 && lf.MatchedFiles > 0 && lf.DampenedMatches == lf.MatchedFiles
}

// 🆕 DampeningEfficiency
func (lf *LibraryFeedback) DampeningEfficiency() float64 {
	if lf.MatchedFiles == 0 {
		return 0
	}
	return float64(lf.DampenedMatches) / float64(lf.MatchedFiles)
}

// 🆕 ShouldIncreaseDampening (более агрессивный)
func (lf *LibraryFeedback) ShouldIncreaseDampening() bool {
	return lf.AvgImportance() < 1.5 && // было 1.0
		lf.HighValueFiles == 0 &&
		lf.DampeningEfficiency() < 0.7 && // было 0.5
		lf.TotalFiles >= 10 // было 20
}

// 🆕 GetPreDampening — возвращает заранее известный dampening (детерминированно)
func (lf *LibraryFeedback) GetPreDampening() float64 {
	for _, item := range sortedKnownLibraryPrefixes {
		if strings.HasPrefix(lf.Prefix, item.prefix) {
			return item.damp
		}
	}
	return 1.0
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY / FILE / DAMPENING / USER OVERRIDE
// ═══════════════════════════════════════════════════════════════════════════════

type CategoryFeedback struct {
	Category       string  `json:"category"`
	Files          int     `json:"files"`
	Matches        int     `json:"matches"`
	Critical       int     `json:"critical"`
	AvgScore       float64 `json:"avg_score"`
	MaxScore       float64 `json:"max_score"`
	FalsePositives int     `json:"false_positives"`
	TruePositives  int     `json:"true_positives"`
}

func (cf *CategoryFeedback) Precision() float64 {
	total := cf.FalsePositives + cf.TruePositives
	if total == 0 {
		return -1
	}
	return float64(cf.TruePositives) / float64(total)
}

type FileFeedback struct {
	Path              string   `json:"path"`
	Importance        int      `json:"importance"`
	RawImportance     int      `json:"raw_importance"`
	Confidence        float64  `json:"confidence"`
	IsLibrary         bool     `json:"is_library"`
	IsAppCode         bool     `json:"is_app_code"`
	Categories        []string `json:"categories"`
	MatchedKeywords   []string `json:"matched_keywords"`
	MatchedHighValue  []string `json:"matched_high_value"`
	TotalDampening    float64  `json:"total_dampening"`
	RawStrength       string   `json:"raw_strength"`
	EffectiveStrength string   `json:"effective_strength"`

	// 🆕
	ThreatTypes    []string `json:"threat_types,omitempty"`
	ThreatScore    float64  `json:"threat_score"`
	IsThreatSource bool     `json:"is_threat_source"`
}

// UnmarshalJSON tolerates history files whose numeric int fields were written
// as JSON floats (e.g. "importance": 54.0). Older schema versions and external
// tools that round-trip the file through a generic JSON library serialize every
// number as a float, which the default decoder rejects for an int field
// ("cannot unmarshal number 54.0 into ... of type int"), corrupting the whole
// ML history load. We decode those fields as json.Number and round to int, so a
// single float-encoded value can no longer poison the entire history.
func (ff *FileFeedback) UnmarshalJSON(data []byte) error {
	type alias FileFeedback // avoid infinite recursion
	aux := &struct {
		Importance    json.Number `json:"importance"`
		RawImportance json.Number `json:"raw_importance"`
		*alias
	}{alias: (*alias)(ff)}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	ff.Importance = flexNumberToInt(aux.Importance)
	ff.RawImportance = flexNumberToInt(aux.RawImportance)
	return nil
}

// flexNumberToInt parses a JSON number that may be an integer or a float
// literal, rounding floats to the nearest int. Empty/invalid input yields 0.
func flexNumberToInt(n json.Number) int {
	if n == "" {
		return 0
	}
	if i, err := n.Int64(); err == nil {
		return int(i)
	}
	if f, err := n.Float64(); err == nil {
		return int(math.Round(f))
	}
	return 0
}

type DampeningFeedback struct {
	TotalDampened      int            `json:"total_dampened"`
	TotalBoosted       int            `json:"total_boosted"`
	AvgDampening       float64        `json:"avg_dampening"`
	FloorHits          int            `json:"floor_hits"`
	CeilingHits        int            `json:"ceiling_hits"`
	Sources            map[string]int `json:"sources"`
	OverDampenedCount  int            `json:"over_dampened"`
	UnderDampenedCount int            `json:"under_dampened"`
}

type UserOverride struct {
	Path           string    `json:"path"`
	Action         string    `json:"action"`
	Keyword        string    `json:"keyword,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
	Reason         string    `json:"reason,omitempty"`
	Category       string    `json:"category,omitempty"`
	APKName        string    `json:"apk_name,omitempty"`
	WasAutoApplied bool      `json:"was_auto_applied"`

	// Features is the ensemble feature vector of the method this override
	// refers to, captured at analysis time (see MethodFeatureSnapshot). Nil
	// unless markFeedback found exactly one MethodFeatures entry matching the
	// override's target — ambiguous or missing matches are left unlabeled
	// rather than guessed at. This is the (features, label) pair the ensemble
	// trainer (pkg/ml/training) consumes once enough accumulate.
	Features *ensemble.Features `json:"features,omitempty"`
}

// MethodFeatureSnapshot records one scored method's ensemble feature vector
// from a --ml-patch run, identified well enough for a later CLI invocation
// (which no longer has the in-memory PatchPrediction) to match it against a
// --mark-relevant/--mark-noise target string.
type MethodFeatureSnapshot struct {
	Path       string            `json:"path"`
	ClassName  string            `json:"class_name,omitempty"`
	MethodName string            `json:"method_name"`
	Signature  string            `json:"signature,omitempty"`
	Features   ensemble.Features `json:"features"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🆕 PATTERN FEEDBACK — Task 20: Pattern-specific feedback
// ═══════════════════════════════════════════════════════════════════════════════

type PatternFeedback struct {
	PatternID       string    `json:"pattern_id"`
	MethodPath      string    `json:"method_path"`
	APKHash         string    `json:"apk_hash"`
	IsTruePositive  bool      `json:"is_true_positive"`
	IsFalsePositive bool      `json:"is_false_positive"`
	CausedCrash     bool      `json:"caused_crash"`
	UserNotes       string    `json:"user_notes,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

type AggregatedPatternFeedback struct {
	PatternID         string    `json:"pattern_id"`
	TotalDetections   int       `json:"total_detections"`
	TruePositives     int       `json:"true_positives"`
	FalsePositives    int       `json:"false_positives"`
	CrashCount        int       `json:"crash_count"`
	TruePositiveRate  float64   `json:"true_positive_rate"`
	FalsePositiveRate float64   `json:"false_positive_rate"`
	CrashRate         float64   `json:"crash_rate"`
	APKsSeenIn        int       `json:"apks_seen_in"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	IsFlagged         bool      `json:"is_flagged"`
	FlagReason        string    `json:"flag_reason,omitempty"`
}

func (apf *AggregatedPatternFeedback) CalculateRates() {
	total := apf.TruePositives + apf.FalsePositives

	if total > 0 {
		apf.TruePositiveRate = float64(apf.TruePositives) / float64(total)
		apf.FalsePositiveRate = float64(apf.FalsePositives) / float64(total)
	} else {
		apf.TruePositiveRate = 0.0
		apf.FalsePositiveRate = 0.0
	}

	if apf.TotalDetections > 0 {
		apf.CrashRate = float64(apf.CrashCount) / float64(apf.TotalDetections)
	} else {
		apf.CrashRate = 0.0
	}
}

type FeedbackCollector struct {
	mu            sync.RWMutex
	feedbacks     []*PatternFeedback
	aggregated    map[string]*AggregatedPatternFeedback
	apksByPattern map[string]map[string]bool
	// Исходы конкретных стратегий (P2#7): дедуп по outcomeKey.
	strategyOutcomes            map[string]*StrategyOutcome
	strategyOutcomeStats        map[string]*StrategyStats
	strategyOutcomeVersionStats map[string]*StrategyStats
}

func NewFeedbackCollector() *FeedbackCollector {
	return &FeedbackCollector{
		feedbacks:     make([]*PatternFeedback, 0),
		aggregated:    make(map[string]*AggregatedPatternFeedback),
		apksByPattern: make(map[string]map[string]bool),
	}
}

func (fc *FeedbackCollector) RecordPatternFeedback(feedback *PatternFeedback) error {
	if feedback == nil {
		return fmt.Errorf("feedback cannot be nil")
	}
	if feedback.PatternID == "" {
		return fmt.Errorf("pattern ID cannot be empty")
	}

	if feedback.Timestamp.IsZero() {
		feedback.Timestamp = time.Now()
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.feedbacks = append(fc.feedbacks, feedback)
	fc.updateAggregated(feedback)

	return nil
}

func (fc *FeedbackCollector) updateAggregated(feedback *PatternFeedback) {
	agg, ok := fc.aggregated[feedback.PatternID]
	if !ok {
		agg = &AggregatedPatternFeedback{
			PatternID: feedback.PatternID,
			FirstSeen: feedback.Timestamp,
		}
		fc.aggregated[feedback.PatternID] = agg
		fc.apksByPattern[feedback.PatternID] = make(map[string]bool)
	}

	agg.TotalDetections++
	if feedback.IsTruePositive {
		agg.TruePositives++
	}
	if feedback.IsFalsePositive {
		agg.FalsePositives++
	}
	if feedback.CausedCrash {
		agg.CrashCount++
	}

	agg.LastSeen = feedback.Timestamp

	if feedback.APKHash != "" {
		if !fc.apksByPattern[feedback.PatternID][feedback.APKHash] {
			fc.apksByPattern[feedback.PatternID][feedback.APKHash] = true
			agg.APKsSeenIn++
		}
	}

	agg.CalculateRates()

	if agg.FalsePositives > 10 && !agg.IsFlagged {
		agg.IsFlagged = true
		agg.FlagReason = fmt.Sprintf("Pattern has received %d false positive reports", agg.FalsePositives)
	}
}

func (fc *FeedbackCollector) GetPatternFeedback(patternID string) *AggregatedPatternFeedback {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.aggregated[patternID]
}

// GetMetrics implements FeedbackStore over the live aggregated feedback.
// found is true only when real observations exist — never synthesize counts.
func (fc *FeedbackCollector) GetMetrics(patternID string) (total, tp, fp, crash, apks int, found bool) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	agg := fc.aggregated[patternID]
	if agg == nil || agg.TotalDetections == 0 {
		return 0, 0, 0, 0, 0, false
	}
	return agg.TotalDetections, agg.TruePositives, agg.FalsePositives, agg.CrashCount, agg.APKsSeenIn, true
}

func (fc *FeedbackCollector) GetAllPatternFeedback() map[string]*AggregatedPatternFeedback {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.aggregated
}

func (fc *FeedbackCollector) AutoAdjustWeights() map[string]float64 {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	adjustments := make(map[string]float64)
	const minSampleSize = 20

	for patternID, agg := range fc.aggregated {
		if agg.TotalDetections < minSampleSize {
			continue
		}

		adjustment := fc.calculateWeightAdjustment(agg)
		if adjustment != 0.0 {
			adjustments[patternID] = adjustment
		}
	}

	return adjustments
}

func (fc *FeedbackCollector) calculateWeightAdjustment(agg *AggregatedPatternFeedback) float64 {
	if agg.TruePositiveRate > 0.8 && agg.CrashRate < 0.05 {
		return 0.2
	}
	if agg.TruePositiveRate >= 0.6 && agg.TruePositiveRate <= 0.8 && agg.CrashRate < 0.1 {
		return 0.1
	}
	if agg.TruePositiveRate < 0.6 {
		return -0.3
	}
	if agg.FalsePositiveRate > 0.4 {
		return -0.5
	}
	if agg.CrashRate > 0.1 {
		return -0.4
	}
	return 0.0
}

func (fc *FeedbackCollector) GetFlaggedPatterns() []*AggregatedPatternFeedback {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	flagged := make([]*AggregatedPatternFeedback, 0)
	for _, agg := range fc.aggregated {
		if agg.IsFlagged {
			flagged = append(flagged, agg)
		}
	}
	return flagged
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🆕 THREAT FEEDBACK
// ═══════════════════════════════════════════════════════════════════════════════

type ThreatFeedback struct {
	TotalThreatsDetected int                            `json:"total_threats"`
	MaxThreatScore       float64                        `json:"max_threat_score"`
	AvgThreatScore       float64                        `json:"avg_threat_score"`
	ThreatsByType        map[string]*ThreatTypeFeedback `json:"threats_by_type"`
	DangerousCombosFound []string                       `json:"dangerous_combos"`
	ComboCount           int                            `json:"combo_count"`
	PermissionThreatMap  map[string][]string            `json:"permission_threat_map"`
}

type ThreatTypeFeedback struct {
	Type       string  `json:"type"`
	Count      int     `json:"count"`
	MaxScore   float64 `json:"max_score"`
	SumScore   float64 `json:"sum_score"`
	FilesFound int     `json:"files_found"`
	Confirmed  int     `json:"confirmed"`
	Dismissed  int     `json:"dismissed"`
}

func (tf *ThreatTypeFeedback) AvgScore() float64 {
	if tf.Count == 0 {
		return 0
	}
	return tf.SumScore / float64(tf.Count)
}

func (tf *ThreatTypeFeedback) Precision() float64 {
	total := tf.Confirmed + tf.Dismissed
	if total == 0 {
		return -1
	}
	return float64(tf.Confirmed) / float64(total)
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🆕 ACCESSIBILITY FEEDBACK
// ═══════════════════════════════════════════════════════════════════════════════

type AccessibilityFeedback struct {
	HasAccessibilityService bool `json:"has_service"`
	HasOverlayCombo         bool `json:"has_overlay_combo"`
	HasDeviceAdminCombo     bool `json:"has_admin_combo"`
	HasSMSCombo             bool `json:"has_sms_combo"`
	HasNotificationCombo    bool `json:"has_notification_combo"`

	HasFinancialContext  bool `json:"has_financial_context"`
	HasCryptoContext     bool `json:"has_crypto_context"`
	HasCredentialContext bool `json:"has_credential_context"`
	HasGeoTargeting      bool `json:"has_geo_targeting"`

	APICallCount      int `json:"api_call_count"`
	ClickSimulations  int `json:"click_simulations"`
	ScreenScrapings   int `json:"screen_scrapings"`
	KeylogPatterns    int `json:"keylog_patterns"`
	PackageMonitors   int `json:"package_monitors"`
	GestureInjections int `json:"gesture_injections"`

	ThreatScore     float64  `json:"threat_score"`
	DangerousCombos []string `json:"dangerous_combos"`

	IsMalicious  bool   `json:"is_malicious"`
	IsLegitimate bool   `json:"is_legitimate"`
	ThreatType   string `json:"threat_type"`
	UserVerdict  string `json:"user_verdict"`
}

func (af *AccessibilityFeedback) RiskLevel() string {
	if !af.HasAccessibilityService {
		return "NONE"
	}
	comboCount := boolCount(af.HasOverlayCombo, af.HasDeviceAdminCombo,
		af.HasSMSCombo, af.HasNotificationCombo)
	ctxCount := boolCount(af.HasFinancialContext, af.HasCryptoContext,
		af.HasCredentialContext)

	switch {
	case comboCount >= 2 && ctxCount >= 1:
		return "CRITICAL"
	case comboCount >= 1 && ctxCount >= 1:
		return "HIGH"
	case comboCount >= 1 || ctxCount >= 1:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🆕 BEHAVIORAL FEEDBACK
// ═══════════════════════════════════════════════════════════════════════════════

type BehavioralFeedback struct {
	HasDataExfiltration bool `json:"has_data_exfiltration"`
	HasAutoGrant        bool `json:"has_auto_grant"`
	HasSilentInstall    bool `json:"has_silent_install"`
	HasPersistence      bool `json:"has_persistence"`
	HasStealth          bool `json:"has_stealth"`
	HasAntiAnalysis     bool `json:"has_anti_analysis"`

	BehaviorChains  []BehaviorChain `json:"behavior_chains,omitempty"`
	BootPersistence bool            `json:"boot_persistence"`
	DelayedExec     bool            `json:"delayed_execution"`
	PeriodicExec    bool            `json:"periodic_execution"`
}

type BehaviorChain struct {
	Steps       []string `json:"steps"`
	ThreatType  string   `json:"threat_type"`
	Confidence  float64  `json:"confidence"`
	Description string   `json:"description"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🆕 CORRELATION FEEDBACK — с нормализацией
// ═══════════════════════════════════════════════════════════════════════════════

type CorrelationFeedback struct {
	PairCounts         map[string]int    `json:"pair_counts"`
	PairAPKCounts      map[string]int    `json:"pair_apk_counts"`
	KeywordFrequency   map[string]int    `json:"keyword_frequency"`
	StrongCorrelations []CorrelationPair `json:"strong_correlations,omitempty"`
}

type CorrelationPair struct {
	KeywordA              string  `json:"keyword_a"`
	KeywordB              string  `json:"keyword_b"`
	CoOccurrence          float64 `json:"co_occurrence"`
	APKCount              int     `json:"apk_count"`
	AvgCombinedImportance float64 `json:"avg_combined_importance"`
}

func (cf *CorrelationFeedback) AddPair(a, b string) {
	if cf.PairCounts == nil {
		cf.PairCounts = make(map[string]int)
	}
	cf.PairCounts[correlationKey(a, b)]++
}

func (cf *CorrelationFeedback) RecordKeyword(keyword string) {
	if cf.KeywordFrequency == nil {
		cf.KeywordFrequency = make(map[string]int)
	}
	cf.KeywordFrequency[keyword]++
}

func (cf *CorrelationFeedback) ComputeCoOccurrence(a, b string) float64 {
	if cf.PairCounts == nil || cf.KeywordFrequency == nil {
		return 0
	}
	key := correlationKey(a, b)
	pairCount, ok := cf.PairCounts[key]
	if !ok || pairCount == 0 {
		return 0
	}
	freqA := cf.KeywordFrequency[a]
	freqB := cf.KeywordFrequency[b]
	minFreq := freqA
	if freqB < minFreq {
		minFreq = freqB
	}
	if minFreq == 0 {
		return 0
	}
	return float64(pairCount) / float64(minFreq)
}

func (cf *CorrelationFeedback) RebuildStrongCorrelations(threshold float64, topN int) {
	cf.StrongCorrelations = nil

	for key := range cf.PairCounts {
		a, b := splitCorrelationKey(key)
		coOcc := cf.ComputeCoOccurrence(a, b)
		if coOcc < threshold {
			continue
		}
		cf.StrongCorrelations = append(cf.StrongCorrelations, CorrelationPair{
			KeywordA:     a,
			KeywordB:     b,
			CoOccurrence: coOcc,
			APKCount:     cf.PairCounts[key],
		})
	}

	sort.Slice(cf.StrongCorrelations, func(i, j int) bool {
		return cf.StrongCorrelations[i].CoOccurrence > cf.StrongCorrelations[j].CoOccurrence
	})

	if topN > 0 && len(cf.StrongCorrelations) > topN {
		cf.StrongCorrelations = cf.StrongCorrelations[:topN]
	}
}

func correlationKey(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "|" + b
}

func splitCorrelationKey(key string) (string, string) {
	for i := 0; i < len(key); i++ {
		if key[i] == '|' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🆕 MODEL CONFIDENCE
// ═══════════════════════════════════════════════════════════════════════════════

type ModelConfidenceFeedback struct {
	OverallConfidence     float64 `json:"overall_confidence"`
	KeywordConfidence     float64 `json:"keyword_confidence"`
	LibraryConfidence     float64 `json:"library_confidence"`
	ThreatConfidence      float64 `json:"threat_confidence"`
	CorrelationConfidence float64 `json:"correlation_confidence"`

	PredictedRisk    float64 `json:"predicted_risk"`
	ActualRisk       float64 `json:"actual_risk"`
	CalibrationError float64 `json:"calibration_error"`
	BrierScore       float64 `json:"brier_score"`

	DatasetSize  int     `json:"dataset_size"`
	UniqueAPKs   int     `json:"unique_apks"`
	LearningRate float64 `json:"learning_rate"`
	Stability    float64 `json:"stability"`
}

func (mc *ModelConfidenceFeedback) Update(predicted, actual float64) {
	mc.DatasetSize++
	mc.PredictedRisk = predicted
	mc.ActualRisk = actual

	absError := math.Abs(predicted - actual)
	mc.CalibrationError += (absError - mc.CalibrationError) / float64(mc.DatasetSize)

	brierError := (predicted - actual) * (predicted - actual)
	mc.BrierScore += (brierError - mc.BrierScore) / float64(mc.DatasetSize)

	mc.Stability = math.Max(0, 1.0-mc.CalibrationError)
	mc.OverallConfidence = mc.computeOverallConfidence()
}

func (mc *ModelConfidenceFeedback) computeOverallConfidence() float64 {
	dataMat := math.Min(0.3, float64(mc.DatasetSize)/100.0*0.3)
	calComp := 0.0
	if mc.DatasetSize >= 5 {
		calComp = math.Max(0, 0.4*(1.0-mc.CalibrationError*5))
	}
	stabComp := mc.Stability * 0.3
	return math.Min(1.0, dataMat+calComp+stabComp)
}

func (mc *ModelConfidenceFeedback) IsCalibrated() bool {
	return mc.DatasetSize >= 20 && mc.CalibrationError < 0.15 && mc.Stability > 0.7
}

func (mc *ModelConfidenceFeedback) NeedsMoreData() bool {
	return mc.DatasetSize < 10 || mc.UniqueAPKs < 5
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🆕 FEATURE VECTOR
// ═══════════════════════════════════════════════════════════════════════════════

type FeatureVector struct {
	KeywordQualityAvg   float64 `json:"kw_quality_avg"`
	KeywordNoiseRatio   float64 `json:"kw_noise_ratio"`
	KeywordStdDevAvg    float64 `json:"kw_stddev_avg"`
	HighQualityKeywords int     `json:"high_quality_keywords"`

	ThreatDensity     float64 `json:"threat_density"`
	CriticalRatio     float64 `json:"critical_ratio"`
	AccessibilityRisk float64 `json:"accessibility_risk"`

	LibraryNoiseLevel  float64 `json:"library_noise_level"`
	EffectiveDampening float64 `json:"effective_dampening"`

	DangerousComboCount int     `json:"dangerous_combo_count"`
	PermissionRiskScore float64 `json:"permission_risk_score"`

	SignalToNoiseRatio float64 `json:"snr"`
	AnalysisConfidence float64 `json:"analysis_confidence"`
}

func ExtractFeatures(fb *AnalysisFeedback) *FeatureVector {
	fv := &FeatureVector{}

	if len(fb.KeywordStats) > 0 {
		var qualitySum, noiseSum, stddevSum float64
		count := 0
		for _, kw := range fb.KeywordStats {
			qualitySum += kw.SignalQuality(fb.TotalFiles)
			noiseSum += kw.NoiseRatio()
			stddevSum += kw.ImportanceStdDev()
			if kw.SignalQuality(fb.TotalFiles) > 0.6 {
				fv.HighQualityKeywords++
			}
			count++
		}
		if count > 0 {
			fv.KeywordQualityAvg = qualitySum / float64(count)
			fv.KeywordNoiseRatio = noiseSum / float64(count)
			fv.KeywordStdDevAvg = stddevSum / float64(count)
		}
	}

	if fb.AnalyzedFiles > 0 {
		if fb.ThreatStats != nil {
			fv.ThreatDensity = float64(fb.ThreatStats.TotalThreatsDetected) / float64(fb.AnalyzedFiles)
			fv.DangerousComboCount = fb.ThreatStats.ComboCount
		}
		if fb.TotalMatches > 0 {
			fv.CriticalRatio = float64(fb.CriticalCount) / float64(fb.TotalMatches)
		}
	}

	if fb.AccessibilityStats != nil {
		fv.AccessibilityRisk = fb.AccessibilityStats.ThreatScore
	}

	if len(fb.LibraryStats) > 0 {
		var noiseSum float64
		var dampSum float64
		count := 0
		for _, lib := range fb.LibraryStats {
			if lib.TotalFiles > 0 {
				if lib.IsAlwaysNoise() {
					noiseSum += 1.0
				}
				dampSum += lib.DampeningEfficiency()
				count++
			}
		}
		if count > 0 {
			fv.LibraryNoiseLevel = noiseSum / float64(count)
			fv.EffectiveDampening = dampSum / float64(count)
		}
	}

	if fb.TotalMatches > 0 && fb.AnalyzedFiles > 0 {
		signal := float64(fb.CriticalCount)
		noise := float64(fb.TotalMatches - fb.CriticalCount)
		if noise > 0 {
			fv.SignalToNoiseRatio = signal / noise
		} else {
			fv.SignalToNoiseRatio = signal
		}
	}

	if fb.ModelConfidence != nil {
		fv.AnalysisConfidence = fb.ModelConfidence.OverallConfidence
	}

	return fv
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🆕 AGGREGATION — FIXED
// ═══════════════════════════════════════════════════════════════════════════════

type AggregatedStats struct {
	TotalAPKs     int `json:"total_apks"`
	TotalMatches  int `json:"total_matches"`
	TotalCritical int `json:"total_critical"`

	KeywordStats    map[string]*AggregatedKeyword    `json:"keyword_stats"`
	LibraryStats    map[string]*AggregatedLibrary    `json:"library_stats"`
	ThreatTypeStats map[string]*AggregatedThreatType `json:"threat_type_stats"`

	APKsWithAccessibility       int `json:"apks_with_accessibility"`
	APKsAccessibilityMalicious  int `json:"apks_accessibility_malicious"`
	APKsAccessibilityLegitimate int `json:"apks_accessibility_legitimate"`
}

type AggregatedKeyword struct {
	Keyword        string  `json:"keyword"`
	TotalTriggers  int     `json:"total_triggers"`
	TotalInAppCode int     `json:"total_in_app_code"`
	TotalInLibrary int     `json:"total_in_library"`
	APKsSeenIn     int     `json:"apks_seen_in"`
	SumImportance  float64 `json:"sum_importance"`
	MarkedRelevant int     `json:"marked_relevant"`
	MarkedNoise    int     `json:"marked_noise"`
}

func (ak *AggregatedKeyword) AvgImportance() float64 {
	if ak.TotalTriggers == 0 {
		return 0
	}
	return ak.SumImportance / float64(ak.TotalTriggers)
}

func (ak *AggregatedKeyword) GlobalNoiseRatio() float64 {
	if ak.TotalTriggers == 0 {
		return 0
	}
	return float64(ak.TotalInLibrary) / float64(ak.TotalTriggers)
}

// toFeedback projects an AggregatedKeyword onto a transient KeywordFeedback
// populated with exactly the fields used by KeywordRelevanceFeatureNames. This
// guarantees that features computed at serving time (from merged history) match
// those computed at training time (from raw KeywordFeedback records).
func (ak *AggregatedKeyword) toFeedback() *KeywordFeedback {
	return &KeywordFeedback{
		Keyword:       ak.Keyword,
		Triggered:     ak.TotalTriggers,
		InAppCode:     ak.TotalInAppCode,
		InLibrary:     ak.TotalInLibrary,
		SumImportance: ak.SumImportance,
		APKsSeenIn:    ak.APKsSeenIn,
	}
}

type AggregatedLibrary struct {
	Prefix        string  `json:"prefix"`
	TotalFiles    int     `json:"total_files"`
	APKsSeenIn    int     `json:"apks_seen_in"`
	SumImportance float64 `json:"sum_importance"`
}

type AggregatedThreatType struct {
	Type            string  `json:"type"`
	TotalDetections int     `json:"total_detections"`
	APKsSeenIn      int     `json:"apks_seen_in"`
	SumScore        float64 `json:"sum_score"`
	Confirmed       int     `json:"confirmed"`
	Dismissed       int     `json:"dismissed"`
}

func (at *AggregatedThreatType) Precision() float64 {
	total := at.Confirmed + at.Dismissed
	if total == 0 {
		return -1
	}
	return float64(at.Confirmed) / float64(total)
}

func MergeFeedbacks(feedbacks []*AnalysisFeedback) *AggregatedStats {
	stats := &AggregatedStats{
		TotalAPKs:       len(feedbacks),
		KeywordStats:    make(map[string]*AggregatedKeyword),
		LibraryStats:    make(map[string]*AggregatedLibrary),
		ThreatTypeStats: make(map[string]*AggregatedThreatType),
	}

	keywordAPKs := make(map[string]map[string]bool)
	libraryAPKs := make(map[string]map[string]bool)
	threatAPKs := make(map[string]map[string]bool)

	for _, fb := range feedbacks {
		stats.TotalMatches += fb.TotalMatches
		stats.TotalCritical += fb.CriticalCount

		apkID := fb.APKHash
		if apkID == "" {
			apkID = fb.ID
		}

		for name, kw := range fb.KeywordStats {
			agg, ok := stats.KeywordStats[name]
			if !ok {
				agg = &AggregatedKeyword{Keyword: name}
				stats.KeywordStats[name] = agg
				keywordAPKs[name] = make(map[string]bool)
			}
			agg.TotalTriggers += kw.Triggered
			agg.TotalInAppCode += kw.InAppCode
			agg.TotalInLibrary += kw.InLibrary
			agg.SumImportance += kw.SumImportance
			agg.MarkedRelevant += kw.MarkedRelevant
			agg.MarkedNoise += kw.MarkedNoise

			if !keywordAPKs[name][apkID] {
				keywordAPKs[name][apkID] = true
				agg.APKsSeenIn++
			}
		}

		for prefix, lib := range fb.LibraryStats {
			agg, ok := stats.LibraryStats[prefix]
			if !ok {
				agg = &AggregatedLibrary{Prefix: prefix}
				stats.LibraryStats[prefix] = agg
				libraryAPKs[prefix] = make(map[string]bool)
			}
			agg.TotalFiles += lib.TotalFiles
			agg.SumImportance += lib.SumImportance

			if !libraryAPKs[prefix][apkID] {
				libraryAPKs[prefix][apkID] = true
				agg.APKsSeenIn++
			}
		}

		if fb.ThreatStats != nil {
			for typeName, tt := range fb.ThreatStats.ThreatsByType {
				agg, ok := stats.ThreatTypeStats[typeName]
				if !ok {
					agg = &AggregatedThreatType{Type: typeName}
					stats.ThreatTypeStats[typeName] = agg
					threatAPKs[typeName] = make(map[string]bool)
				}
				agg.TotalDetections += tt.Count
				agg.SumScore += tt.SumScore
				agg.Confirmed += tt.Confirmed
				agg.Dismissed += tt.Dismissed

				if !threatAPKs[typeName][apkID] {
					threatAPKs[typeName][apkID] = true
					agg.APKsSeenIn++
				}
			}
		}

		if fb.AccessibilityStats != nil && fb.AccessibilityStats.HasAccessibilityService {
			stats.APKsWithAccessibility++
			if fb.AccessibilityStats.IsMalicious {
				stats.APKsAccessibilityMalicious++
			}
			if fb.AccessibilityStats.IsLegitimate {
				stats.APKsAccessibilityLegitimate++
			}
		}
	}

	return stats
}

// ═══════════════════════════════════════════════════════════════════════════════
// 🆕 LEARNING ENGINE — с decay и watermark detection
// ═══════════════════════════════════════════════════════════════════════════════

type LearningEngine struct {
	Stats      *AggregatedStats `json:"stats"`
	Decay      float64          `json:"decay"`
	Version    int              `json:"version"`
	LastUpdate time.Time        `json:"last_update"`
	MaxHistory int              `json:"max_history"`

	WeightAdj  map[string]float64       `json:"weight_adjustments"`
	DampenAdj  map[string]float64       `json:"dampening_adjustments"`
	Confidence *ModelConfidenceFeedback `json:"confidence"`

	// MLScorer, when set and loaded, replaces the hand-tuned heuristic branch in
	// recalculateWeights with a trained, calibrated relevance model. nil (the
	// default) keeps the original heuristic behaviour. Not serialized.
	MLScorer KeywordRelevanceScorer `json:"-"`
}

// SetMLScorer wires a trained relevance model into the engine. Passing nil (or
// a scorer whose IsLoaded() is false) leaves the heuristic path active.
func (le *LearningEngine) SetMLScorer(s KeywordRelevanceScorer) {
	le.MLScorer = s
}

func NewLearningEngine(decay float64, maxHistory int) *LearningEngine {
	if decay <= 0 || decay > 1 {
		decay = 0.95
	}
	if maxHistory <= 0 {
		maxHistory = 100
	}

	le := &LearningEngine{
		Decay:      decay,
		MaxHistory: maxHistory,
		WeightAdj:  make(map[string]float64),
		DampenAdj:  make(map[string]float64),
		Confidence: &ModelConfidenceFeedback{},
	}

	// 🆕 Pre-load known noise
	for kw, weight := range KnownWatermarks {
		le.WeightAdj[kw] = weight
	}
	for prefix, damp := range KnownLibraryPrefixes {
		le.DampenAdj[prefix] = damp
	}

	return le
}

func (le *LearningEngine) Update(feedback *AnalysisFeedback) {
	le.Version++
	le.LastUpdate = time.Now()

	if le.Stats == nil {
		le.Stats = MergeFeedbacks([]*AnalysisFeedback{feedback})
	} else {
		le.mergeIncremental(feedback)
	}

	le.recalculateWeights()
	le.recalculateDampening()

	// 🆕 Auto-detect watermarks
	le.detectWatermarks(feedback)
}

// 🆕 Автоматическое обнаружение вотермарков
func (le *LearningEngine) detectWatermarks(fb *AnalysisFeedback) {
	if fb.WatermarkStats == nil {
		fb.WatermarkStats = &WatermarkFeedback{}
	}

	watermarks := []string{}
	totalWM := 0

	for kw, stats := range fb.KeywordStats {
		if stats.IsWatermark(fb.TotalFiles) {
			watermarks = append(watermarks, kw)
			totalWM += stats.Triggered
			// Авто-понижение веса
			le.WeightAdj[strings.ToLower(kw)] = 0.01
		}
	}

	fb.WatermarkStats.DetectedWatermarks = watermarks
	if fb.TotalFiles > 0 {
		fb.WatermarkStats.WatermarkDensity = float64(totalWM) / float64(fb.TotalFiles)
	}
	fb.WatermarkStats.IsRepacked = len(watermarks) > 0 && fb.WatermarkStats.WatermarkDensity > 0.1
	if len(watermarks) > 0 {
		fb.WatermarkStats.PrimarySource = watermarks[0]
		fb.WatermarkStats.ConfidencePenalty = math.Min(fb.WatermarkStats.WatermarkDensity*2, 0.5)
	}
}

func (le *LearningEngine) mergeIncremental(fb *AnalysisFeedback) {
	le.Stats.TotalAPKs++
	le.Stats.TotalMatches += fb.TotalMatches
	le.Stats.TotalCritical += fb.CriticalCount

	for name, kw := range fb.KeywordStats {
		agg, ok := le.Stats.KeywordStats[name]
		if !ok {
			agg = &AggregatedKeyword{Keyword: name}
			le.Stats.KeywordStats[name] = agg
		}
		agg.TotalTriggers = int(float64(agg.TotalTriggers)*le.Decay) + kw.Triggered
		agg.TotalInAppCode = int(float64(agg.TotalInAppCode)*le.Decay) + kw.InAppCode
		agg.TotalInLibrary = int(float64(agg.TotalInLibrary)*le.Decay) + kw.InLibrary
		agg.SumImportance = agg.SumImportance*le.Decay + kw.SumImportance
		agg.APKsSeenIn++
	}

	le.trimKeywords()
}

// УЛУЧШЕННЫЙ recalculateWeights с авто-подавлением вотермарков
func (le *LearningEngine) recalculateWeights() {
	mlActive := le.MLScorer != nil && le.MLScorer.IsLoaded()
	for keyword, stats := range le.Stats.KeywordStats {
		// 🆕 Мгновенное подавление вотермарков
		if _, isWM := KnownWatermarks[strings.ToLower(keyword)]; isWM {
			le.WeightAdj[keyword] = 0.01
			continue
		}

		// 🆕 Trained relevance model on the hot path. When loaded, the
		// calibrated probability replaces the threshold heuristics below.
		// prob→0 means noise (suppress), prob→1 means relevant (boost); the
		// uncertain middle band falls back to the engine default weight.
		if mlActive {
			prob := le.MLScorer.ScoreKeyword(stats.toFeedback())
			switch {
			case prob < 0.30:
				// Strong noise: scale into [0.02, 0.17].
				le.WeightAdj[keyword] = 0.02 + prob*0.5
			case prob > 0.70:
				// Strong relevance: scale into (1.0, ~1.5].
				le.WeightAdj[keyword] = 1.0 + (prob-0.70)*1.67
			default:
				delete(le.WeightAdj, keyword)
			}
			continue
		}

		avg := stats.AvgImportance()
		noise := stats.GlobalNoiseRatio()

		switch {
		case avg < 0.5 && stats.APKsSeenIn >= 2: // было 3
			le.WeightAdj[keyword] = 0.05 // было 0.1
		case avg < 1.0 && noise > 0.6: // было 0.7
			le.WeightAdj[keyword] = 0.2 // было 0.3
		case avg < 2.0 && stats.APKsSeenIn >= 3: // было 5
			le.WeightAdj[keyword] = 0.4 // было 0.5
		case avg > 5.0 && noise < 0.3:
			le.WeightAdj[keyword] = 1.5
		default:
			delete(le.WeightAdj, keyword)
		}
	}
}

func (le *LearningEngine) recalculateDampening() {
	for prefix, stats := range le.Stats.LibraryStats {
		avgImp := 0.0
		if stats.TotalFiles > 0 {
			avgImp = stats.SumImportance / float64(stats.TotalFiles)
		}

		switch {
		case avgImp < 0.5 && stats.APKsSeenIn >= 3:
			le.DampenAdj[prefix] = 0.1
		case avgImp < 1.0:
			le.DampenAdj[prefix] = 0.2
		case avgImp < 2.0:
			le.DampenAdj[prefix] = 0.4
		default:
			delete(le.DampenAdj, prefix)
		}
	}
}

func (le *LearningEngine) trimKeywords() {
	if len(le.Stats.KeywordStats) <= le.MaxHistory {
		return
	}

	type kwSort struct {
		name string
		imp  float64
	}
	var sorted []kwSort
	for name, stats := range le.Stats.KeywordStats {
		sorted = append(sorted, kwSort{name, stats.AvgImportance()})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].imp < sorted[j].imp
	})

	toRemove := len(sorted) - le.MaxHistory
	for i := 0; i < toRemove; i++ {
		delete(le.Stats.KeywordStats, sorted[i].name)
		delete(le.WeightAdj, sorted[i].name)
	}
}

// 🆕 Bulk mark watermarks as noise
func (le *LearningEngine) BulkMarkNoise(keywords []string) int {
	count := 0
	for _, kw := range keywords {
		le.WeightAdj[strings.ToLower(kw)] = 0.01
		count++
	}
	return count
}

func (le *LearningEngine) ExportModel() *MLModel {
	return &MLModel{
		Version:    le.Version,
		Weights:    copyMap(le.WeightAdj),
		Dampening:  copyMap(le.DampenAdj),
		Confidence: le.Confidence.OverallConfidence,
		DataSize:   le.Stats.TotalAPKs,
		LastUpdate: le.LastUpdate,
	}
}

type MLModel struct {
	Version    int                `json:"version"`
	Weights    map[string]float64 `json:"weights"`
	Dampening  map[string]float64 `json:"dampening"`
	Confidence float64            `json:"confidence"`
	DataSize   int                `json:"data_size"`
	LastUpdate time.Time          `json:"last_update"`
}

func (le *LearningEngine) EvaluateCalibration() string {
	mc := le.Confidence
	switch {
	case mc.IsCalibrated():
		return "CALIBRATED"
	case mc.NeedsMoreData():
		return "NEEDS_DATA"
	case mc.CalibrationError > 0.3:
		return "POORLY_CALIBRATED"
	default:
		return "CONVERGING"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func GenerateFeedbackID(apkName string, timestamp time.Time) string {
	data := fmt.Sprintf("%s:%d", apkName, timestamp.UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])[:16]
}

func HashAPKFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() == 0 {
		return "", fmt.Errorf("empty file: %s", path)
	}

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func boolCount(flags ...bool) int {
	c := 0
	for _, f := range flags {
		if f {
			c++
		}
	}
	return c
}

func copyMap(m map[string]float64) map[string]float64 {
	out := make(map[string]float64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
