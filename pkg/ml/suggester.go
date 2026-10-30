package ml

import (
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

// --- Local Persona for compatibility ---
type Persona struct {
	Name  string `json:"name"`
	Level int    `json:"level"`
}

func NewPersona(name string, level int) *Persona {
	return &Persona{Name: name, Level: level}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUGGESTION TYPES — type-safe константы
// ═══════════════════════════════════════════════════════════════════════════════

type SuggestionType string

const (
	TypeKeywordDampening SuggestionType = "keyword_dampening"
	TypeKeywordWeight    SuggestionType = "keyword_weight"
	TypeLibraryFastpath  SuggestionType = "library_fastpath"
	TypeLibraryDampening SuggestionType = "library_dampening"
	TypePerformance      SuggestionType = "performance"
	TypeScoring          SuggestionType = "scoring"
	TypePattern          SuggestionType = "pattern"
)

type RiskLevel string

const (
	RiskHigh   RiskLevel = "High"
	RiskMedium RiskLevel = "Medium"
	RiskLow    RiskLevel = "Low"
)

func (st SuggestionType) Risk() RiskLevel {
	switch st {
	case TypeScoring:
		return RiskHigh
	case TypeLibraryFastpath, TypeKeywordDampening:
		return RiskMedium
	default:
		return RiskLow
	}
}

var suggestionTypeIcons = map[SuggestionType]string{
	TypeKeywordDampening: "~",
	TypeKeywordWeight:    "=",
	TypeLibraryFastpath:  ">",
	TypeLibraryDampening: "#",
	TypePerformance:      "*",
	TypeScoring:          "!",
	TypePattern:          "&",
}

func (st SuggestionType) Icon() string {
	if icon, ok := suggestionTypeIcons[st]; ok {
		return icon
	}
	return "?"
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML-SUGGESTER — Adaptive analysis engine (stateless)
// ═══════════════════════════════════════════════════════════════════════════════

type MLSuggester struct {
	history *AnalysisHistory
	config  SuggesterConfig
	output  io.Writer
	persona *Persona

	// relevance, when set and loaded, is a trained keyword-relevance model used
	// to refine keyword suggestions (skip demoting keywords the model considers
	// genuinely relevant, and annotate confidence). nil keeps legacy behaviour.
	relevance KeywordRelevanceScorer
}

// analysisContext — локальный контекст одного вызова Analyze()
type analysisContext struct {
	snapshot     []*AnalysisFeedback
	aggKeywords  map[string]*AggregatedKeywordStats
	aggLibraries map[string]*AggregatedLibraryStats

	// Глобальные keyword counts (для всех TopFiles)
	globalKeywordCounts map[string]int
	globalTotalFiles    int

	importanceCache map[string]float64
}

type SuggesterConfig struct {
	NoiseThreshold      float64
	MinSampleSize       int
	ConfidenceThreshold float64

	LibraryMinAPKs  int
	LibraryMinFiles int

	SigmoidSlope float64

	MaxDisplaySuggestions int
	MaxCoOccurrences      int
	MaxWrappedWidth       int
}

func DefaultSuggesterConfig() SuggesterConfig {
	return SuggesterConfig{
		NoiseThreshold:        0.7,
		MinSampleSize:         10,
		ConfidenceThreshold:   0.5,
		LibraryMinAPKs:        3,
		LibraryMinFiles:       20,
		SigmoidSlope:          6.0,
		MaxDisplaySuggestions: 10,
		MaxCoOccurrences:      20,
		MaxWrappedWidth:       60,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIDENCE LEVELS
// ═══════════════════════════════════════════════════════════════════════════════

type ConfidenceLevel string

const (
	ConfidenceStrong   ConfidenceLevel = "Strong"
	ConfidenceHigh     ConfidenceLevel = "High"
	ConfidenceModerate ConfidenceLevel = "Moderate"
	ConfidenceWeak     ConfidenceLevel = "Weak"
)

func classifyConfidence(c float64) ConfidenceLevel {
	switch {
	case c >= 0.90:
		return ConfidenceStrong
	case c >= 0.75:
		return ConfidenceHigh
	case c >= 0.60:
		return ConfidenceModerate
	default:
		return ConfidenceWeak
	}
}

func confidenceStability(level ConfidenceLevel, samples int) string {
	switch level {
	case ConfidenceStrong:
		return "statistically robust"
	case ConfidenceHigh:
		if samples > 50 {
			return "statistically stable"
		}
		return "converging"
	case ConfidenceModerate:
		return "requires more data"
	default:
		return "limited data"
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUGGESTION STRUCT
// ═══════════════════════════════════════════════════════════════════════════════

type Suggestion struct {
	Type       SuggestionType `json:"type"`
	Target     string         `json:"target"`
	Action     string         `json:"action"`
	Confidence float64        `json:"confidence"`
	Samples    int            `json:"samples"`
	RiskImpact RiskLevel      `json:"risk_impact"`

	Observation    string   `json:"observation"`
	Recommendation string   `json:"recommendation"`
	ExpectedEffect string   `json:"expected_effect"`
	Reasoning      []string `json:"reasoning"`

	Config string `json:"config,omitempty"`
}

func (sg Suggestion) Level() ConfidenceLevel {
	return classifyConfidence(sg.Confidence)
}

func (sg Suggestion) Stability() string {
	return confidenceStability(sg.Level(), sg.Samples)
}

// Weight — взвешенная сила suggestion (для InsightStrength)
func (sg Suggestion) Weight() float64 {
	base := sg.Confidence * math.Log1p(float64(sg.Samples))

	// Risk multiplier
	switch sg.RiskImpact {
	case RiskHigh:
		base *= 1.5
	case RiskMedium:
		base *= 1.2
	}

	return base
}

// ═══════════════════════════════════════════════════════════════════════════════
// SUGGESTION SET
// ═══════════════════════════════════════════════════════════════════════════════

type SuggestionSet struct {
	Timestamp        string       `json:"timestamp"`
	TotalAPKs        int          `json:"total_apks"`
	Suggestions      []Suggestion `json:"suggestions"`
	Stats            MLStats      `json:"stats"`
	Maturity         float64      `json:"maturity"`
	InsightStrength  float64      `json:"insight_strength"`
	SystemConfidence float64      `json:"system_confidence"`
	SignalEntropy    float64      `json:"signal_entropy"`
	Reflection       Reflection   `json:"reflection"`
}

type MLStats struct {
	AvgNoiseRatio      float64 `json:"avg_noise_ratio"`
	TotalKeywords      int     `json:"total_keywords"`
	NoisyKeywords      int     `json:"noisy_keywords"`
	TotalLibraries     int     `json:"total_libraries"`
	AlwaysNoiseLibs    int     `json:"always_noise_libs"`
	EstimatedReduction float64 `json:"estimated_reduction"`
	CurrentDeepScan    float64 `json:"current_deep_scan"`   // baseline (100%)
	OptimizedDeepScan  float64 `json:"optimized_deep_scan"` // после оптимизации
	SignalClarity      string  `json:"signal_clarity"`
}

type Reflection struct {
	NoiseTrend       string `json:"noise_trend"`
	KeywordStability string `json:"keyword_stability"`
	LibraryFiltering string `json:"library_filtering"`
	SignalDiversity  string `json:"signal_diversity"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTRUCTOR
// ═══════════════════════════════════════════════════════════════════════════════

func NewMLSuggester(history *AnalysisHistory, opts ...func(*MLSuggester)) *MLSuggester {
	s := &MLSuggester{
		history: history,
		config:  DefaultSuggesterConfig(),
		output:  os.Stdout,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.persona == nil {
		s.persona = NewPersona("ML-chan", 1)
	}
	return s
}

func WithSuggesterConfig(cfg SuggesterConfig) func(*MLSuggester) {
	return func(s *MLSuggester) {
		s.config = cfg
	}
}

func WithOutput(w io.Writer) func(*MLSuggester) {
	return func(s *MLSuggester) {
		s.output = w
	}
}

func WithPersona(name string, level int) func(*MLSuggester) {
	return func(s *MLSuggester) {
		s.persona = NewPersona(name, level)
	}
}

// WithRelevanceScorer wires a trained keyword-relevance model into the
// suggester. When the scorer reports a keyword as relevant, the suggester will
// not recommend demoting it, reducing false "add dampening" advice.
func WithRelevanceScorer(scorer KeywordRelevanceScorer) func(*MLSuggester) {
	return func(s *MLSuggester) {
		if scorer != nil && scorer.IsLoaded() {
			s.relevance = scorer
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func (s *MLSuggester) Analyze() *SuggestionSet {
	ctx := s.buildContext()

	suggestions := make([]Suggestion, 0, 32)
	suggestions = append(suggestions, s.analyzeKeywords(ctx)...)
	suggestions = append(suggestions, s.analyzeLibraries(ctx)...)
	suggestions = append(suggestions, s.analyzePerformance(ctx)...)
	suggestions = append(suggestions, s.analyzePatterns(ctx)...)

	// 🆕 v8.1.0 - Enhanced ML analysis
	suggestions = s.applyEnhancements(ctx, suggestions)

	// 🆕 v8.1.0 - Filter already applied suggestions
	suggestions = s.filterAlreadyApplied(ctx, suggestions)

	// Фильтрация по ConfidenceThreshold
	filtered := make([]Suggestion, 0, len(suggestions))
	for _, sugg := range suggestions {
		if sugg.Confidence >= s.config.ConfidenceThreshold {
			filtered = append(filtered, sugg)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Confidence > filtered[j].Confidence
	})

	stats := s.calculateStats(ctx)
	maturity := s.calculateMaturity(ctx)
	insightStrength := calculateWeightedInsightStrength(filtered)
	signalEntropy := calculateSignalEntropy(filtered)

	return &SuggestionSet{
		Timestamp:        time.Now().Format(time.RFC3339),
		TotalAPKs:        len(ctx.snapshot),
		Suggestions:      filtered,
		Stats:            stats,
		Maturity:         maturity,
		InsightStrength:  insightStrength,
		SystemConfidence: maturity * insightStrength,
		SignalEntropy:    signalEntropy,
		Reflection:       s.buildReflection(ctx, stats, signalEntropy),
	}
}

func (s *MLSuggester) buildContext() *analysisContext {
	snapshot := s.history.Snapshot()

	ctx := &analysisContext{
		snapshot:            snapshot,
		aggKeywords:         aggregateKeywordsFromRecords(snapshot),
		aggLibraries:        aggregateLibrariesFromRecords(snapshot),
		globalKeywordCounts: make(map[string]int),
	}

	// NOTE: Сейчас co-occurrence считается только по TopFiles.
	// Если нужна полная точность — следует считать по всем файлам из ClassificationResult,
	// но это требует изменений в collector.go для сохранения полного списка.
	seen := make(map[string]bool, 32)
	for _, record := range snapshot {
		for _, file := range record.TopFiles {
			ctx.globalTotalFiles++
			for k := range seen {
				delete(seen, k)
			}
			for _, kw := range file.MatchedKeywords {
				if !seen[kw] {
					seen[kw] = true
					ctx.globalKeywordCounts[kw]++
				}
			}
		}
	}

	return ctx
}

// ═══════════════════════════════════════════════════════════════════════════════
// INSIGHT STRENGTH & ENTROPY
// ═══════════════════════════════════════════════════════════════════════════════

// calculateWeightedInsightStrength — взвешенная сила инсайтов
// Учитывает confidence, samples и risk
func calculateWeightedInsightStrength(suggestions []Suggestion) float64 {
	if len(suggestions) == 0 {
		return 0
	}

	var totalWeight float64
	var weightedSum float64

	for _, sg := range suggestions {
		w := sg.Weight()
		totalWeight += w
		weightedSum += sg.Confidence * w
	}

	if totalWeight == 0 {
		return 0
	}

	return clamp01(weightedSum / totalWeight)
}

// calculateSignalEntropy — оценка разнообразия suggestions
// Высокая entropy = balanced, низкая = перекошена к одному типу
func calculateSignalEntropy(suggestions []Suggestion) float64 {
	if len(suggestions) == 0 {
		return 0
	}

	// Подсчёт по типам
	typeCounts := make(map[SuggestionType]int)
	for _, sg := range suggestions {
		typeCounts[sg.Type]++
	}

	if len(typeCounts) <= 1 {
		return 0 // Только один тип — нет разнообразия
	}

	// Shannon entropy, нормализованная к [0,1]
	n := float64(len(suggestions))
	var entropy float64

	for _, count := range typeCounts {
		if count > 0 {
			p := float64(count) / n
			entropy -= p * math.Log2(p)
		}
	}

	// Нормализация: max entropy = log2(количество типов)
	maxEntropy := math.Log2(float64(len(typeCounts)))
	if maxEntropy == 0 {
		return 0
	}

	return clamp01(entropy / maxEntropy)
}

// ═══════════════════════════════════════════════════════════════════════════════
// SNAPSHOT-BASED AGGREGATION
// ═══════════════════════════════════════════════════════════════════════════════

func aggregateKeywordsFromRecords(records []*AnalysisFeedback) map[string]*AggregatedKeywordStats {
	result := make(map[string]*AggregatedKeywordStats)

	for _, record := range records {
		seenInThisAPK := make(map[string]bool)

		for keyword, kf := range record.KeywordStats {
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

	return result
}

func aggregateLibrariesFromRecords(records []*AnalysisFeedback) map[string]*AggregatedLibraryStats {
	result := make(map[string]*AggregatedLibraryStats)

	for _, record := range records {
		seenInThisAPK := make(map[string]bool)

		for prefix, lf := range record.LibraryStats {
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
			agg.SumImportance += lf.SumImportance

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

// ═══════════════════════════════════════════════════════════════════════════════
// KEYWORD ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func (s *MLSuggester) analyzeKeywords(ctx *analysisContext) []Suggestion {
	suggestions := []Suggestion{}

	for _, kw := range ctx.aggKeywords {
		if kw.TotalTriggered < s.config.MinSampleSize {
			continue
		}

		// Trained relevance model veto: if the model is confident this keyword
		// is genuinely relevant, do not recommend demoting/dampening it.
		var relProb float64 = -1
		if s.relevance != nil {
			relProb = s.relevance.ScoreKeyword(&KeywordFeedback{
				Keyword:       kw.Keyword,
				Triggered:     kw.TotalTriggered,
				InAppCode:     kw.TotalInAppCode,
				InLibrary:     kw.TotalInLibrary,
				SumImportance: kw.SumImportance,
				APKsSeenIn:    kw.SeenInAPKs,
			})
			if relProb >= 0.70 {
				continue // model says relevant → skip both dampening & weight cuts
			}
		}

		// Высокий уровень шума → dampening
		if kw.NoiseRatio > s.config.NoiseThreshold {
			confidence := s.calculateConfidence(kw.NoiseRatio, kw.TotalTriggered)
			if relProb >= 0 && relProb < 0.30 {
				// Model agrees it's noise → reinforce confidence (capped).
				confidence = math.Min(1.0, confidence*1.15)
			}

			libPct := safePercent(kw.TotalInLibrary, kw.TotalTriggered)
			dampenedPct := safePercent(kw.TotalDampened, kw.TotalTriggered)

			reasoning := []string{
				fmt.Sprintf("Observed %d total occurrences across %d APKs",
					kw.TotalTriggered, kw.SeenInAPKs),
				fmt.Sprintf("%.0f%% of matches originate from library code", libPct),
			}
			if dampenedPct > 0 {
				reasoning = append(reasoning,
					fmt.Sprintf("%.0f%% already dampened by existing rules", dampenedPct))
			}
			if kw.TotalInAppCode > 0 {
				reasoning = append(reasoning,
					fmt.Sprintf("Only %d occurrences in actual application code",
						kw.TotalInAppCode))
			}

			sugg := Suggestion{
				Type:       TypeKeywordDampening,
				Target:     kw.Keyword,
				Action:     "add_dampening",
				Confidence: confidence,
				Samples:    kw.TotalTriggered,
				RiskImpact: TypeKeywordDampening.Risk(),
				Observation: fmt.Sprintf(
					"This keyword behaves predominantly as noise. "+
						"%.0f%% of occurrences originate from library code, "+
						"suggesting low semantic value in app logic.",
					libPct,
				),
				Recommendation: "Introduce contextual dampening (factor 0.3) for library contexts.",
				ExpectedEffect: fmt.Sprintf(
					"Reduced false positives by approximately %d matches per analysis.",
					kw.TotalInLibrary/maxInt(kw.SeenInAPKs, 1),
				),
				Reasoning: reasoning,
				Config:    s.generateDampeningRule(kw),
			}
			suggestions = append(suggestions, sugg)
		}

		// Низкая важность → снизить вес
		avgImp := kw.AvgImportance()
		if avgImp < 2.0 && kw.TotalTriggered > 20 {
			confidence := s.calculateConfidence(1.0-avgImp/10.0, kw.TotalTriggered)

			sugg := Suggestion{
				Type:       TypeKeywordWeight,
				Target:     kw.Keyword,
				Action:     "reduce_weight",
				Confidence: confidence,
				Samples:    kw.TotalTriggered,
				RiskImpact: TypeKeywordWeight.Risk(),
				Observation: fmt.Sprintf(
					"Observed importance remains persistently low (avg %.2f), "+
						"indicating weak discriminative power.",
					avgImp,
				),
				Recommendation: "Reduce keyword weight to minimize score inflation.",
				ExpectedEffect: "More accurate importance distribution across findings.",
				Reasoning: []string{
					fmt.Sprintf("Average importance: %.2f (threshold: 2.0)", avgImp),
					fmt.Sprintf("Sample size: %d occurrences", kw.TotalTriggered),
					fmt.Sprintf("Seen in %d independent APKs", kw.SeenInAPKs),
				},
				Config: s.generateWeightRule(kw),
			}
			suggestions = append(suggestions, sugg)
		}
	}

	return suggestions
}

// ═══════════════════════════════════════════════════════════════════════════════
// LIBRARY ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func (s *MLSuggester) analyzeLibraries(ctx *analysisContext) []Suggestion {
	suggestions := []Suggestion{}

	for _, lib := range ctx.aggLibraries {
		if lib.TotalFiles < s.config.LibraryMinFiles {
			continue
		}

		// Всегда шум → fast-path
		if lib.AlwaysNoiseCount == lib.SeenInAPKs &&
			lib.SeenInAPKs >= s.config.LibraryMinAPKs {

			confidence := s.calculateConfidence(
				float64(lib.AlwaysNoiseCount)/float64(maxInt(lib.SeenInAPKs, 1)),
				lib.TotalFiles,
			)

			filesPerAPK := lib.TotalFiles / maxInt(lib.SeenInAPKs, 1)

			sugg := Suggestion{
				Type:       TypeLibraryFastpath,
				Target:     lib.Prefix,
				Action:     "add_to_fastpath",
				Confidence: confidence,
				Samples:    lib.TotalFiles,
				RiskImpact: TypeLibraryFastpath.Risk(),
				Observation: fmt.Sprintf(
					"This library prefix consistently produces no actionable signals. "+
						"Across %d independent analyses it yielded zero high-value findings.",
					lib.SeenInAPKs,
				),
				Recommendation: "Add to fast-path skip list to bypass deep analysis.",
				ExpectedEffect: fmt.Sprintf(
					"Up to %d fewer files evaluated in deep scan stage per APK.",
					filesPerAPK,
				),
				Reasoning: []string{
					fmt.Sprintf("Observed in %d APKs, always noise", lib.SeenInAPKs),
					fmt.Sprintf("Total files scanned: %d", lib.TotalFiles),
					"High-value findings: 0",
					fmt.Sprintf("Category: %s", lib.Category),
				},
				Config: s.generateLibraryRule(lib),
			}
			suggestions = append(suggestions, sugg)
		}

		// Низкая важность → увеличить dampening
		avgImp := lib.AvgImportance()
		if avgImp < 1.0 && lib.TotalMatched > 0 {
			dampenRatio := safeRatio(lib.TotalDampened, lib.TotalMatched)
			if dampenRatio < 0.5 {
				confidence := s.calculateConfidence(1.0-avgImp/5.0, lib.TotalFiles)

				sugg := Suggestion{
					Type:       TypeLibraryDampening,
					Target:     lib.Prefix,
					Action:     "increase_dampening",
					Confidence: confidence,
					Samples:    lib.TotalFiles,
					RiskImpact: TypeLibraryDampening.Risk(),
					Observation: fmt.Sprintf(
						"Library matches carry low semantic weight (avg importance %.2f). "+
							"Current dampening covers only %.0f%% of matches.",
						avgImp, dampenRatio*100,
					),
					Recommendation: "Increase dampening factor to 0.2 for this prefix.",
					ExpectedEffect: "Reduce library noise without losing critical signals.",
					Reasoning: []string{
						fmt.Sprintf("Average importance: %.2f", avgImp),
						fmt.Sprintf("Matched files: %d", lib.TotalMatched),
						fmt.Sprintf("Currently dampened: %.0f%%", dampenRatio*100),
					},
					Config: s.generateLibraryDampeningRule(lib),
				}
				suggestions = append(suggestions, sugg)
			}
		}
	}

	return suggestions
}

// ═══════════════════════════════════════════════════════════════════════════════
// PERFORMANCE ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

func (s *MLSuggester) analyzePerformance(ctx *analysisContext) []Suggestion {
	suggestions := []Suggestion{}

	if len(ctx.snapshot) == 0 {
		return suggestions
	}

	last := ctx.snapshot[len(ctx.snapshot)-1]

	// Fast-path эффективность
	if last.TotalFiles > 0 && last.FastPathHits > 0 {
		hitRate := float64(last.FastPathHits) / float64(last.TotalFiles)
		if hitRate < 0.3 {
			sugg := Suggestion{
				Type:       TypePerformance,
				Target:     "fast_path",
				Action:     "optimize_patterns",
				Confidence: 0.8,
				Samples:    last.TotalFiles,
				RiskImpact: TypePerformance.Risk(),
				Observation: fmt.Sprintf(
					"Fast-path currently intercepts only %.1f%% of files. "+
						"Significant analysis time is spent on files that yield no findings.",
					hitRate*100,
				),
				Recommendation: "Expand fast-path patterns based on library analysis.",
				ExpectedEffect: fmt.Sprintf(
					"Estimated %.0f%% fewer files entering deep scan stage.",
					(0.3-hitRate)*100,
				),
				Reasoning: []string{
					fmt.Sprintf("Current fast-path hit rate: %.1f%%", hitRate*100),
					fmt.Sprintf("Total files: %d, fast-path hits: %d",
						last.TotalFiles, last.FastPathHits),
					fmt.Sprintf("Saved from fast-path: %d files", last.SavedFromFP),
				},
			}
			suggestions = append(suggestions, sugg)
		}
	}

	// Слишком много критических
	if last.AnalyzedFiles > 0 && last.CriticalCount > 100 {
		critRate := safePercent(last.CriticalCount, last.AnalyzedFiles)
		sugg := Suggestion{
			Type:       TypeScoring,
			Target:     "critical_threshold",
			Action:     "recalibrate",
			Confidence: 0.7,
			Samples:    last.AnalyzedFiles,
			RiskImpact: TypeScoring.Risk(),
			Observation: fmt.Sprintf(
				"Critical findings constitute %.1f%% of analyzed files (%d out of %d). "+
					"This dilutes the meaning of 'critical' classification.",
				critRate, last.CriticalCount, last.AnalyzedFiles,
			),
			Recommendation: "Consider raising the critical threshold or adding contextual filters.",
			ExpectedEffect: "More meaningful prioritization of findings.",
			Reasoning: []string{
				fmt.Sprintf("Critical count: %d", last.CriticalCount),
				fmt.Sprintf("Analyzed files: %d", last.AnalyzedFiles),
				"High critical ratio suggests threshold is too permissive",
			},
		}
		suggestions = append(suggestions, sugg)
	}

	return suggestions
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATTERN DISCOVERY
// ═══════════════════════════════════════════════════════════════════════════════

func (s *MLSuggester) analyzePatterns(ctx *analysisContext) []Suggestion {
	suggestions := []Suggestion{}

	cooccurrence := s.findCoOccurrences(ctx)

	for _, co := range cooccurrence {
		if co.Support < 5 || co.Lift < 1.5 {
			continue
		}

		confidence := s.calculateConfidence(
			math.Min(co.Lift/5.0, 1.0),
			co.Support,
		)

		sugg := Suggestion{
			Type:       TypePattern,
			Target:     co.KeywordA + " + " + co.KeywordB,
			Action:     "create_combined_rule",
			Confidence: confidence,
			Samples:    co.Support,
			RiskImpact: TypePattern.Risk(),
			Observation: fmt.Sprintf(
				"Recurring keyword interaction detected. "+
					"Combination appears in %d independent files "+
					"with lift %.2f, indicating structural coupling.",
				co.Support, co.Lift,
			),
			Recommendation: "Create a combined detection rule with boosted weight.",
			ExpectedEffect: "More accurate detection of this specific pattern.",
			Reasoning: []string{
				fmt.Sprintf("Co-occurrence count: %d files", co.Support),
				fmt.Sprintf("Lift: %.2f (>1 means positive correlation)", co.Lift),
				fmt.Sprintf("Keyword A frequency: %d", co.CountA),
				fmt.Sprintf("Keyword B frequency: %d", co.CountB),
			},
			Config: fmt.Sprintf(`{
  "keywords": ["%s", "%s"],
  "boost": 1.5,
  "reason": "ML: co-occurrence lift %.2f, support %d"
}`, co.KeywordA, co.KeywordB, co.Lift, co.Support),
		}
		suggestions = append(suggestions, sugg)
	}

	return suggestions
}

// ═══════════════════════════════════════════════════════════════════════════════
// CO-OCCURRENCE ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

type CoOccurrence struct {
	KeywordA string
	KeywordB string
	Support  int
	CountA   int
	CountB   int
	Lift     float64
}

func (s *MLSuggester) findCoOccurrences(ctx *analysisContext) []CoOccurrence {
	if ctx.globalTotalFiles == 0 {
		return nil
	}

	pairCounts := make(map[[2]string]int)
	seen := make(map[string]bool, 32)
	uniqueBuf := make([]string, 0, 32)

	for _, record := range ctx.snapshot {
		for _, file := range record.TopFiles {
			if len(file.MatchedKeywords) < 2 {
				continue
			}

			for k := range seen {
				delete(seen, k)
			}
			unique := uniqueBuf[:0]
			for _, kw := range file.MatchedKeywords {
				if !seen[kw] {
					seen[kw] = true
					unique = append(unique, kw)
				}
			}
			uniqueBuf = unique

			sort.Strings(unique)
			for i := 0; i < len(unique); i++ {
				for j := i + 1; j < len(unique); j++ {
					pair := [2]string{unique[i], unique[j]}
					pairCounts[pair]++
				}
			}
		}
	}

	n := float64(ctx.globalTotalFiles)
	results := make([]CoOccurrence, 0, len(pairCounts))

	for pair, support := range pairCounts {
		countA := ctx.globalKeywordCounts[pair[0]]
		countB := ctx.globalKeywordCounts[pair[1]]

		pA := float64(countA) / n
		pB := float64(countB) / n
		pAB := float64(support) / n

		var lift float64
		if denom := pA * pB; denom > 0 {
			lift = pAB / denom
		}

		results = append(results, CoOccurrence{
			KeywordA: pair[0],
			KeywordB: pair[1],
			Support:  support,
			CountA:   countA,
			CountB:   countB,
			Lift:     lift,
		})
	}

	type scoredCo struct {
		co    CoOccurrence
		score float64
	}
	scored := make([]scoredCo, len(results))
	for i, r := range results {
		scored[i] = scoredCo{
			co:    r,
			score: r.Lift * math.Log1p(float64(r.Support)),
		}
	}
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})
	for i := range scored {
		results[i] = scored[i].co
	}

	if len(results) > s.config.MaxCoOccurrences {
		results = results[:s.config.MaxCoOccurrences]
	}

	return results
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIDENCE & MATURITY — defensive programming
// ═══════════════════════════════════════════════════════════════════════════════

func (s *MLSuggester) calculateConfidence(signal float64, samples int) float64 {
	// Defensive: clamp signal
	signal = clamp01(signal)

	base := 1.0 / (1.0 + math.Exp(-s.config.SigmoidSlope*(signal-0.5)))

	// Defensive: clamp base (теоретически уже [0,1], но на случай float errors)
	base = clamp01(base)

	sampleFactor := math.Min(1.0, math.Log1p(float64(samples))/math.Log1p(200.0))

	result := base * sampleFactor

	// Final clamp
	return clamp01(result)
}

func (s *MLSuggester) calculateMaturity(ctx *analysisContext) float64 {
	n := len(ctx.snapshot)
	if n == 0 {
		return 0
	}
	return clamp01(math.Log1p(float64(n)) / math.Log1p(200.0))
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATS & REFLECTION
// ═══════════════════════════════════════════════════════════════════════════════

func (s *MLSuggester) calculateStats(ctx *analysisContext) MLStats {
	var totalNoise float64
	var noisyCount int
	var kwWithData int

	for _, kw := range ctx.aggKeywords {
		if kw.TotalTriggered > 0 {
			kwWithData++
			totalNoise += kw.NoiseRatio
			if kw.NoiseRatio > s.config.NoiseThreshold {
				noisyCount++
			}
		}
	}

	alwaysNoise := 0
	var totalLibFiles int
	var skippableFiles int

	for _, lib := range ctx.aggLibraries {
		if lib.AlwaysNoiseCount == lib.SeenInAPKs && lib.SeenInAPKs > 0 {
			alwaysNoise++
			skippableFiles += lib.TotalFiles
		}
		totalLibFiles += lib.TotalFiles
	}

	avgNoise := 0.0
	if kwWithData > 0 {
		avgNoise = totalNoise / float64(kwWithData)
	}

	estimatedReduction := 0.0
	if totalLibFiles > 0 {
		estimatedReduction = float64(skippableFiles) / float64(totalLibFiles) * 100
	}

	// Baseline всегда 100%, optimized = 100 - reduction
	currentDeepScan := 100.0
	optimizedDeepScan := currentDeepScan - estimatedReduction

	return MLStats{
		AvgNoiseRatio:      avgNoise,
		TotalKeywords:      len(ctx.aggKeywords),
		NoisyKeywords:      noisyCount,
		TotalLibraries:     len(ctx.aggLibraries),
		AlwaysNoiseLibs:    alwaysNoise,
		EstimatedReduction: estimatedReduction,
		CurrentDeepScan:    currentDeepScan,
		OptimizedDeepScan:  optimizedDeepScan,
		SignalClarity:      s.assessSignalClarity(ctx),
	}
}

func (s *MLSuggester) assessSignalClarity(ctx *analysisContext) string {
	if len(ctx.snapshot) < 3 {
		return "insufficient data"
	}

	mid := len(ctx.snapshot) / 2
	noiseFirst := avgNoiseFromRecords(ctx.snapshot[:mid])
	noiseSecond := avgNoiseFromRecords(ctx.snapshot[mid:])

	diff := noiseSecond - noiseFirst
	switch {
	case diff < -0.05:
		return "improving"
	case diff > 0.05:
		return "degrading"
	default:
		return "stable"
	}
}

func (s *MLSuggester) buildReflection(ctx *analysisContext, stats MLStats, entropy float64) Reflection {
	noiseTrend := stats.SignalClarity

	// Keyword stability
	keywordStability := "unknown"
	if len(ctx.aggKeywords) > 0 {
		var variance float64
		var count int
		for _, kw := range ctx.aggKeywords {
			if kw.TotalTriggered >= s.config.MinSampleSize {
				diff := kw.NoiseRatio - stats.AvgNoiseRatio
				variance += diff * diff
				count++
			}
		}
		if count > 0 {
			variance /= float64(count)
			switch {
			case variance < 0.02:
				keywordStability = "highly consistent"
			case variance < 0.05:
				keywordStability = "increasing"
			case variance < 0.10:
				keywordStability = "moderate"
			default:
				keywordStability = "volatile"
			}
		}
	}

	// Library filtering
	libFiltering := "unknown"
	if stats.TotalLibraries > 0 {
		noiseRatio := safeRatio(stats.AlwaysNoiseLibs, stats.TotalLibraries)
		switch {
		case noiseRatio > 0.7:
			libFiltering = "highly effective"
		case noiseRatio > 0.4:
			libFiltering = "effective"
		case noiseRatio > 0.1:
			libFiltering = "partial"
		default:
			libFiltering = "minimal impact"
		}
	}

	// Signal diversity (based on entropy)
	signalDiversity := "unknown"
	switch {
	case entropy >= 0.8:
		signalDiversity = "well balanced"
	case entropy >= 0.5:
		signalDiversity = "moderate"
	case entropy >= 0.2:
		signalDiversity = "concentrated"
	case entropy > 0:
		signalDiversity = "highly skewed"
	default:
		signalDiversity = "no data"
	}

	return Reflection{
		NoiseTrend:       noiseTrend,
		KeywordStability: keywordStability,
		LibraryFiltering: libFiltering,
		SignalDiversity:  signalDiversity,
	}
}

func avgNoiseFromRecords(records []*AnalysisFeedback) float64 {
	if len(records) == 0 {
		return 0
	}

	var total float64
	var count int

	for _, r := range records {
		for _, kf := range r.KeywordStats {
			if kf.Triggered > 0 {
				total += kf.NoiseRatio()
				count++
			}
		}
	}

	if count == 0 {
		return 0
	}
	return total / float64(count)
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG GENERATION
// ═══════════════════════════════════════════════════════════════════════════════

func (s *MLSuggester) generateDampeningRule(kw *AggregatedKeywordStats) string {
	if kw.TotalTriggered == 0 {
		return "{}"
	}

	contexts := []string{}
	if safeRatio(kw.TotalInLibrary, kw.TotalTriggered) > 0.5 {
		contexts = append(contexts, `"library"`)
	}
	if safeRatio(kw.TotalInFileName, kw.TotalTriggered) > 0.3 {
		contexts = append(contexts, `"filename"`)
	}

	return fmt.Sprintf(`{
  "keyword": "%s",
  "contexts": [%s],
  "factor": 0.3,
  "reason": "ML: noise ratio %.0f%%, %d samples"
}`, kw.Keyword, strings.Join(contexts, ", "), kw.NoiseRatio*100, kw.TotalTriggered)
}

func (s *MLSuggester) generateWeightRule(kw *AggregatedKeywordStats) string {
	newWeight := 1
	avg := kw.AvgImportance()
	if avg < 1.0 {
		newWeight = 0
	}

	return fmt.Sprintf(`{
  "keyword": "%s",
  "weight": %d,
  "reason": "ML: avg importance %.2f, %d samples"
}`, kw.Keyword, newWeight, avg, kw.TotalTriggered)
}

func (s *MLSuggester) generateLibraryRule(lib *AggregatedLibraryStats) string {
	return fmt.Sprintf(`{
  "pattern": "%s",
  "category": "%s",
  "action": "skip",
  "reason": "ML: always noise across %d APKs, %d files"
}`, lib.Prefix, lib.Category, lib.SeenInAPKs, lib.TotalFiles)
}

func (s *MLSuggester) generateLibraryDampeningRule(lib *AggregatedLibraryStats) string {
	return fmt.Sprintf(`{
  "pattern": "%s",
  "dampening": 0.2,
  "reason": "ML: avg importance %.2f, %d files"
}`, lib.Prefix, lib.AvgImportance(), lib.TotalFiles)
}

// ═══════════════════════════════════════════════════════════════════════════════
// INTERACTIVE DISPLAY — Intelligence Report
// ═══════════════════════════════════════════════════════════════════════════════

func (s *MLSuggester) InteractiveSuggest() {
	result := s.Analyze()
	w := s.output

	// Header
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(w, "  ║           INTELLIGENCE REPORT            ║")
	fmt.Fprintln(w, "  ║            Adaptive Analysis             ║")
	fmt.Fprintln(w, "  ╚══════════════════════════════════════════╝")
	fmt.Fprintln(w)

	// System State
	fmt.Fprintln(w, "  System State")
	fmt.Fprintln(w, "  ─────────────")
	fmt.Fprintf(w, "  Dataset size        : %d APKs\n", result.TotalAPKs)
	fmt.Fprintf(w, "  Learning maturity   : %.0f%%\n", result.Maturity*100)
	fmt.Fprintf(w, "  Signal clarity      : %s\n", result.Stats.SignalClarity)
	fmt.Fprintf(w, "  Noise baseline      : %.0f%%\n", result.Stats.AvgNoiseRatio*100)
	fmt.Fprintf(w, "  Insight strength    : %.0f%%\n", result.InsightStrength*100)
	fmt.Fprintf(w, "  System confidence   : %.0f%%\n", result.SystemConfidence*100)

	if result.Stats.EstimatedReduction > 0 {
		fmt.Fprintf(w, "  Est. deep-scan load : %.0f%% → %.0f%% after optimization\n",
			result.Stats.CurrentDeepScan, result.Stats.OptimizedDeepScan)
	}

	fmt.Fprintln(w)

	if len(result.Suggestions) == 0 {
		fmt.Fprintln(w, "  No actionable suggestions at current confidence level.")
		fmt.Fprintln(w, "  Continue collecting data to improve signal clarity.")
		s.renderReflection(w, result.Reflection)
		return
	}

	fmt.Fprintf(w, "  Found %d actionable suggestions:\n", len(result.Suggestions))
	fmt.Fprintln(w)

	displayCount := s.config.MaxDisplaySuggestions
	if len(result.Suggestions) < displayCount {
		displayCount = len(result.Suggestions)
	}

	for i := 0; i < displayCount; i++ {
		s.renderSuggestion(w, i+1, result.Suggestions[i])
	}

	remaining := len(result.Suggestions) - displayCount
	if remaining > 0 {
		fmt.Fprintf(w, "  ... and %d more suggestions\n", remaining)
	}

	s.renderReflection(w, result.Reflection)
}

func (s *MLSuggester) renderSuggestion(w io.Writer, index int, sugg Suggestion) {
	icon := sugg.Type.Icon()
	level := sugg.Level()
	stability := sugg.Stability()

	// Разделитель между suggestions — двойная линия
	fmt.Fprintln(w, "  ════════════════════════════════════════")
	fmt.Fprintf(w, "  %s  #%d  %s\n", icon, index, sugg.Target)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "  Observation:")
	fmt.Fprintln(w, "  ─────────────")
	printWrapped(w, sugg.Observation, 4, s.config.MaxWrappedWidth)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "  Recommendation:")
	fmt.Fprintln(w, "  ─────────────")
	printWrapped(w, sugg.Recommendation, 4, s.config.MaxWrappedWidth)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "  Expected effect:")
	fmt.Fprintln(w, "  ─────────────")
	printWrapped(w, sugg.ExpectedEffect, 4, s.config.MaxWrappedWidth)
	fmt.Fprintln(w)

	if len(sugg.Reasoning) > 0 {
		fmt.Fprintln(w, "  Reasoning:")
		fmt.Fprintln(w, "  ─────────────")
		for _, r := range sugg.Reasoning {
			fmt.Fprintf(w, "      • %s\n", r)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "  ─────────────")
	fmt.Fprintf(w, "  Confidence   : %s (%.0f%%) — %s\n", level, sugg.Confidence*100, stability)
	fmt.Fprintf(w, "  Risk impact  : %s\n", sugg.RiskImpact)
	fmt.Fprintln(w)
}

func (s *MLSuggester) renderReflection(w io.Writer, ref Reflection) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  ════════════════════════════════════════")
	fmt.Fprintln(w, "  System Reflection")
	fmt.Fprintln(w, "  ─────────────────")
	fmt.Fprintf(w, "  Noise trend        : %s\n", ref.NoiseTrend)
	fmt.Fprintf(w, "  Keyword stability  : %s\n", ref.KeywordStability)
	fmt.Fprintf(w, "  Library filtering  : %s\n", ref.LibraryFiltering)
	fmt.Fprintf(w, "  Signal diversity   : %s\n", ref.SignalDiversity)
	fmt.Fprintln(w)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PURE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func printWrapped(w io.Writer, text string, indent int, maxWidth int) {
	prefix := strings.Repeat(" ", indent+2)
	words := strings.Fields(text)
	line := prefix
	lineLen := 0

	for _, word := range words {
		if lineLen+len(word)+1 > maxWidth && lineLen > 0 {
			fmt.Fprintln(w, line)
			line = prefix
			lineLen = 0
		}
		if lineLen > 0 {
			line += " "
			lineLen++
		}
		line += word
		lineLen += len(word)
	}
	if lineLen > 0 {
		fmt.Fprintln(w, line)
	}
}

func safeRatio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func safePercent(numerator, denominator int) float64 {
	return safeRatio(numerator, denominator) * 100
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// clamp01 — defensive bounds [0, 1]
func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENHANCED ML v8.1.0 - Integration
// ═══════════════════════════════════════════════════════════════════════════════

func (s *MLSuggester) applyEnhancements(ctx *analysisContext, suggestions []Suggestion) []Suggestion {
	enhanced := make([]Suggestion, 0, len(suggestions))

	// Улучшаем каждую рекомендацию
	for _, sugg := range suggestions {
		improved := s.enhanceSuggestion(ctx, sugg)
		enhanced = append(enhanced, improved)
	}

	// Добавляем рекомендации по кластерам
	clusterSuggestions := s.generateClusterSuggestions(ctx)
	enhanced = append(enhanced, clusterSuggestions...)

	return enhanced
}

// ═══════════════════════════════════════════════════════════════════════════════
// FILTER ALREADY APPLIED - v8.1.0
// ═══════════════════════════════════════════════════════════════════════════════

// filterAlreadyApplied убирает рекомендации которые уже применены пользователем
func (s *MLSuggester) filterAlreadyApplied(ctx *analysisContext, suggestions []Suggestion) []Suggestion {
	// Собираем все user overrides из истории
	appliedPatterns := make(map[string]bool)

	for _, override := range ResolveUserOverrides(ctx.snapshot) {
		// Нормализуем паттерн для сравнения
		pattern := normalizePattern(UserOverrideTarget(override))
		if pattern != "" {
			appliedPatterns[pattern] = true
		}
	}

	if len(appliedPatterns) == 0 {
		return suggestions
	}

	// Фильтруем suggestions
	filtered := make([]Suggestion, 0, len(suggestions))
	for _, sugg := range suggestions {
		normalized := normalizePattern(sugg.Target)
		if !appliedPatterns[normalized] {
			filtered = append(filtered, sugg)
		}
	}

	return filtered
}

// normalizePattern нормализует паттерн для сравнения
func normalizePattern(pattern string) string {
	// Убираем trailing slash
	pattern = strings.TrimSuffix(pattern, "/")

	// Убираем regex символы для сравнения
	pattern = strings.TrimSuffix(pattern, "/.*")
	pattern = strings.TrimPrefix(pattern, "L")

	return strings.ToLower(pattern)
}
