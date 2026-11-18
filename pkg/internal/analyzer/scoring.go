// Package analyzer — scoring.go v4.0
//
// Архитектура:
//   - Весовая система с именованными правилами
//   - Нормализация через soft-cap (логарифмическая)
//   - FileScorecard — полная разбивка скора для дебага
//   - Thread-safe (immutable weights, sync.Map cache)
//   - Стабильная сортировка hotspots с 4 уровнями tie-breaking
package analyzer

import (
	"fmt"
	"math"
	"sort"
	"sync"

	"mega-analyzer/pkg/internal/config"
	"mega-analyzer/pkg/internal/filter"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SCORING WEIGHTS — именованные, конфигурируемые
// ═══════════════════════════════════════════════════════════════════════════════

// ScoringWeights определяет веса для каждого фактора.
type ScoringWeights struct {
	ImportanceMultiplier float64 // базовый множитель важности пути
	CriticalPriority     float64 // множитель приоритета критической категории
	DecisionPointValue   float64 // вес одной decision point
	NonCriticalLog       float64 // множитель log2 для некритических
	EntropyBase          float64 // базовый бонус за высокую энтропию
	EntropyCriticalBoost float64 // доп. бонус энтропии при наличии критических
	SuspiciousDivisor    float64 // делитель для suspicious score
	SuspiciousThreshold  float64 // порог suspicious score
}

// DefaultWeights — веса по умолчанию.
var DefaultWeights = ScoringWeights{
	ImportanceMultiplier: 2.0,
	CriticalPriority:     3.0,
	DecisionPointValue:   10.0,
	NonCriticalLog:       2.0,
	EntropyBase:          2.0,
	EntropyCriticalBoost: 5.0,
	SuspiciousDivisor:    5.0,
	SuspiciousThreshold:  10.0,
}

// CategoryRiskMultipliers — насколько "горячая" категория для реверсера.
// GoogleLVL и TamperDetection — первые цели при взломе.
var CategoryRiskMultipliers = map[types.Category]float64{
	types.CategoryGoogleLVL:       2.5, // единственный official механизм Google
	types.CategoryTamperDetection: 2.2, // крекеры обходят в первую очередь
	types.CategorySignatureCheck:  2.0, // критично для integrity
	types.CategoryLicenseCheck:    1.8, // прямая проверка лицензии
	types.CategoryLicenseCallback: 1.7, // callback от license server
	types.CategoryPurchaseVerify:  1.6, // верификация покупки
	types.CategoryBillingCallback: 1.5, // callback от billing
	types.CategorySubscription:    1.3, // подписочная модель
	types.CategoryPremiumCheck:    1.2, // базовая premium проверка
	types.CategoryPremiumUnlock:   1.2,
}

// getCategoryRiskMultiplier возвращает multiplier для категории (1.0 если не найден).
func getCategoryRiskMultiplier(cat types.Category) float64 {
	if m, ok := CategoryRiskMultipliers[cat]; ok {
		return m
	}
	return 1.0
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORE BREAKDOWN — для отчётов и дебага
// ═══════════════════════════════════════════════════════════════════════════════

// ScoreBreakdown — детальная разбивка скора файла.
type ScoreBreakdown struct {
	BaseScore          float64  `json:"base_score"`
	CriticalBonus      float64  `json:"critical_bonus"`
	DecisionBonus      float64  `json:"decision_bonus"`
	NonCriticalBonus   float64  `json:"non_critical_bonus"`
	EntropyBonus       float64  `json:"entropy_bonus"`
	SuspiciousBonus    float64  `json:"suspicious_bonus"`
	RawTotal           float64  `json:"raw_total"`
	NormalizedTotal    float64  `json:"normalized_total"`
	CriticalCount      int      `json:"critical_count"`
	UniqueCategories   int      `json:"unique_categories"`
	DecisionPointCount int      `json:"decision_point_count"`
	Reasons            []string `json:"reasons"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORER
// ═══════════════════════════════════════════════════════════════════════════════

// Scorer вычисляет скоры файлов и определяет hotspots.
// Thread-safe: можно использовать из нескольких goroutine.
type Scorer struct {
	config  *config.Config
	filter  *filter.Filter
	weights ScoringWeights

	// Thread-safe cache
	categoryCache sync.Map // map[types.Category]types.CategoryInfo
}

// NewScorer создаёт scorer с дефолтными весами.
func NewScorer(cfg *config.Config, f *filter.Filter) *Scorer {
	return &Scorer{
		config:  cfg,
		filter:  f,
		weights: DefaultWeights,
	}
}

// NewScorerWithWeights создаёт scorer с кастомными весами.
func NewScorerWithWeights(cfg *config.Config, f *filter.Filter, w ScoringWeights) *Scorer {
	return &Scorer{
		config:  cfg,
		filter:  f,
		weights: w,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// CATEGORY INFO CACHE — thread-safe
// ═══════════════════════════════════════════════════════════════════════════════

func (s *Scorer) getCategoryInfo(cat types.Category) types.CategoryInfo {
	if cached, ok := s.categoryCache.Load(cat); ok {
		return cached.(types.CategoryInfo)
	}
	info := types.GetCategoryInfo(cat)
	s.categoryCache.Store(cat, info)
	return info
}

// ═══════════════════════════════════════════════════════════════════════════════
// SCORE FILE — с детальной разбивкой
// ═══════════════════════════════════════════════════════════════════════════════

// ScoreFile вычисляет скор файла.
// Возвращает (score, reasons) для обратной совместимости.
func (s *Scorer) ScoreFile(analysis *types.FileAnalysis) (float64, []string) {
	bd := s.ScoreFileDetailed(analysis)
	return bd.NormalizedTotal, bd.Reasons
}

// ScoreFileDetailed вычисляет скор с полной разбивкой.
func (s *Scorer) ScoreFileDetailed(analysis *types.FileAnalysis) ScoreBreakdown {
	var bd ScoreBreakdown
	w := s.weights

	// ── Guard: пропускаем библиотечный код ───────────────────────────────────
	if !analysis.IsAppCode {
		bd.Reasons = append(bd.Reasons, "Library code — skipped")
		return bd
	}
	if s.filter != nil && s.filter.IsStandardLibrary(analysis.Path) {
		bd.Reasons = append(bd.Reasons, "Standard library — skipped")
		return bd
	}

	// ── 1. Base score: важность пути ─────────────────────────────────────────
	bd.BaseScore = float64(analysis.Importance) * w.ImportanceMultiplier

	// ── 2. Critical categories ───────────────────────────────────────────────
	seenCritical := make(map[types.Category]struct{}, 8)

	for i := range analysis.Matches {
		info := s.getCategoryInfo(analysis.Matches[i].Category)
		// Use the match's own calibrated criticality, not the category
		// default: a non-critical match in a "critical" category (e.g.
		// plain getPackageInfo under SIGNATURE_CHECK) must not inflate
		// the file score into the CRITICAL band.
		if analysis.Matches[i].IsCritical {
			bd.CriticalCount++
			if _, seen := seenCritical[analysis.Matches[i].Category]; !seen {
				bd.CriticalBonus += float64(info.Priority) * w.CriticalPriority
				seenCritical[analysis.Matches[i].Category] = struct{}{}
				bd.Reasons = appendReason(bd.Reasons,
					fmt.Sprintf("%s %s: CRITICAL (×%.0f)",
						info.Icon, info.Name, w.CriticalPriority))
			}
		}
	}
	bd.UniqueCategories = len(seenCritical)

	if bd.CriticalCount > 0 {
		bd.Reasons = appendReason(bd.Reasons,
			fmt.Sprintf("%d critical matches across %d categories",
				bd.CriticalCount, bd.UniqueCategories))
	}

	// ── 3. Decision points — самый важный фактор ─────────────────────────────
	bd.DecisionPointCount = len(analysis.DecisionPoints)
	if bd.DecisionPointCount > 0 {
		bd.DecisionBonus = float64(bd.DecisionPointCount) * w.DecisionPointValue
		bd.Reasons = appendReason(bd.Reasons,
			fmt.Sprintf("⚡ %d decision points (×%.0f each)",
				bd.DecisionPointCount, w.DecisionPointValue))
	}

	// ── 4. Non-critical matches — логарифмическое сглаживание ────────────────
	nonCritical := len(analysis.Matches) - bd.CriticalCount
	if nonCritical > 0 {
		bd.NonCriticalBonus = math.Log2(float64(nonCritical)+1) * w.NonCriticalLog
	}

	// ── 5. Entropy — бонус зависит от контекста ──────────────────────────────
	// Entropy only corroborates suspicious content. Smali text sits at ~5.1
	// bits/byte across the board (uniform character distribution), so the
	// bonus fired on essentially every obfuscated file and manufactured the
	// "Unknown, 0 matches" hotspots. A file with zero matches has no signal
	// for entropy to amplify.
	if analysis.Entropy > s.config.MinEntropyThreshold && len(analysis.Matches) > 0 {
		if bd.CriticalCount > 0 {
			bd.EntropyBonus = w.EntropyCriticalBoost
		} else {
			bd.EntropyBonus = w.EntropyBase
		}
		bd.Reasons = appendReason(bd.Reasons,
			fmt.Sprintf("🔥 High entropy: %.2f", analysis.Entropy))
	}

	// ── 6. Suspicious methods ────────────────────────────────────────────────
	// Only meaningful alongside a real signal: on a clean app these are
	// ordinary accessors, not evidence of protection/malice.
	if analysis.SuspiciousScore > w.SuspiciousThreshold && bd.CriticalCount > 0 {
		bd.SuspiciousBonus = analysis.SuspiciousScore / w.SuspiciousDivisor
		bd.Reasons = appendReason(bd.Reasons,
			fmt.Sprintf("Suspicious methods score: %.0f", analysis.SuspiciousScore))
	}

	// ── Total Base ───────────────────────────────────────────────────────────
	bd.RawTotal = bd.BaseScore +
		bd.CriticalBonus +
		bd.DecisionBonus +
		bd.NonCriticalBonus +
		bd.EntropyBonus +
		bd.SuspiciousBonus

	// ── 7. Category risk multipliers — критические категории весят больше ────
	var riskMultiplierBonus float64
	for i := range analysis.Matches {
		cat := analysis.Matches[i].Category
		mult := getCategoryRiskMultiplier(cat)
		if mult > 1.0 {
			// Бонус = (multiplier-1) × base_match_value
			riskMultiplierBonus += (mult - 1.0) * 3.0
		}
	}
	if riskMultiplierBonus > 0 {
		bd.RawTotal += riskMultiplierBonus
		bd.Reasons = appendReason(bd.Reasons,
			fmt.Sprintf("Risk multiplier bonus: +%.1f (high-priority categories)", riskMultiplierBonus))
	}

	// ── 8. Obfuscation density bonus ─────────────────────────────────────────
	// Если >40% методов в файле имеют короткое имя (≤2 символа) → сильная обфускация.
	// Обфускация = что-то скрывают → повышаем приоритет файла.
	// R8/ProGuard short names are universal in release builds; only treat as
	// suspicious when corroborated by a real critical signal in the file.
	if analysis.ObfuscationDensity > 0.40 && bd.CriticalCount > 0 {
		obfuscBonus := analysis.ObfuscationDensity * 18.0 // max ~18 при density=1.0
		bd.RawTotal += obfuscBonus
		bd.Reasons = appendReason(bd.Reasons,
			fmt.Sprintf("Obfuscation density: %.0f%% short names (+%.1f)",
				analysis.ObfuscationDensity*100, obfuscBonus))
	}

	// ── 9. Method role diversity bonus ───────────────────────────────────────
	// Если файл содержит checker + enforcer + handler = профессиональная
	// многоуровневая защита → резко поднимаем приоритет.
	if analysis.HasCheckerRole && analysis.HasEnforcerRole && analysis.HasHandlerRole {
		bd.RawTotal += 20.0
		bd.Reasons = appendReason(bd.Reasons,
			"Multi-role protection: checker+enforcer+handler (+20)")
	} else if analysis.HasCheckerRole && analysis.HasEnforcerRole {
		bd.RawTotal += 10.0
		bd.Reasons = appendReason(bd.Reasons,
			"Dual-role protection: checker+enforcer (+10)")
	}

	// ── Normalization: soft cap ──────────────────────────────────────────────
	bd.NormalizedTotal = normalize(bd.RawTotal, s.config.ScoreNormalizationCap)

	return bd
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOTSPOTS
// ═══════════════════════════════════════════════════════════════════════════════

// CalculateHotspots вычисляет и ранжирует горячие точки.
func (s *Scorer) CalculateHotspots(files map[string]*types.FileAnalysis, topN int) []types.Hotspot {
	if topN <= 0 {
		topN = 50
	}

	hotspots := make([]types.Hotspot, 0, min(len(files), topN*2))

	for path, analysis := range files {
		if hs, ok := s.fileToHotspot(path, analysis); ok {
			hotspots = append(hotspots, hs)
		}
	}

	// Стабильная сортировка с 4 уровнями
	sortHotspots(hotspots)

	// Trim
	if len(hotspots) > topN {
		hotspots = hotspots[:topN]
	}

	return hotspots
}

// fileToHotspot конвертирует FileAnalysis в Hotspot (если подходит).
func (s *Scorer) fileToHotspot(path string, analysis *types.FileAnalysis) (types.Hotspot, bool) {
	// Skip non-app code
	if !analysis.IsAppCode {
		return types.Hotspot{}, false
	}
	if s.filter != nil && s.filter.IsStandardLibrary(path) {
		return types.Hotspot{}, false
	}

	// Score
	bd := s.ScoreFileDetailed(analysis)

	// A file with zero matches carries no evidence: importance and entropy
	// alone manufactured "Unknown, 0 matches" hotspots in the 18-22 band.
	// Decision points and criticals both imply at least one match.
	if len(analysis.Matches) == 0 && bd.DecisionPointCount == 0 {
		return types.Hotspot{}, false
	}

	// Bare keyword hits are not evidence either: a file whose only matches
	// are generic Custom Keyword strings (setAccessible, loadUrl,
	// shouldOverrideUrlLoading — the vocabulary of every obfuscated androidx
	// class) produced 16 of 19 hotspots on an obfuscated-library-heavy APK.
	// A hotspot needs a corroborating signal: a critical match, a decision
	// point, or a non-keyword category.
	if bd.CriticalCount == 0 && bd.DecisionPointCount == 0 {
		onlyKeyword := true
		for i := range analysis.Matches {
			if analysis.Matches[i].Category != types.CategoryCustomKeyword {
				onlyKeyword = false
				break
			}
		}
		if onlyKeyword && len(analysis.Matches) > 0 {
			return types.Hotspot{}, false
		}
	}

	// Minimum threshold
	if bd.NormalizedTotal < 10 && bd.CriticalCount == 0 && bd.DecisionPointCount == 0 {
		return types.Hotspot{}, false
	}

	// Collect unique categories (sorted by priority)
	categories := s.uniqueCategories(analysis.Matches)

	return types.Hotspot{
		Path:           path,
		Score:          bd.NormalizedTotal,
		MatchCount:     len(analysis.Matches),
		CriticalCount:  bd.CriticalCount,
		Categories:     categories,
		Reasons:        bd.Reasons,
		DecisionPoints: analysis.DecisionPoints,
		IsAppCode:      analysis.IsAppCode,
		Importance:     analysis.Importance,
	}, true
}

// uniqueCategories собирает уникальные категории, отсортированные по приоритету.
func (s *Scorer) uniqueCategories(matches []types.Match) []types.Category {
	seen := make(map[types.Category]struct{}, len(matches))
	cats := make([]types.Category, 0, 8)

	for i := range matches {
		cat := matches[i].Category
		if _, ok := seen[cat]; !ok {
			seen[cat] = struct{}{}
			cats = append(cats, cat)
		}
	}

	// Sort: priority desc, name asc
	sort.Slice(cats, func(i, j int) bool {
		pi := s.getCategoryInfo(cats[i]).Priority
		pj := s.getCategoryInfo(cats[j]).Priority
		if pi != pj {
			return pi > pj
		}
		return string(cats[i]) < string(cats[j])
	})

	return cats
}

// ═══════════════════════════════════════════════════════════════════════════════
// SORTING — стабильная с 4 уровнями tie-breaking
// ═══════════════════════════════════════════════════════════════════════════════

func sortHotspots(hotspots []types.Hotspot) {
	sort.SliceStable(hotspots, func(i, j int) bool {
		a, b := &hotspots[i], &hotspots[j]

		// Level 1: критические находки
		if a.CriticalCount != b.CriticalCount {
			return a.CriticalCount > b.CriticalCount
		}

		// Level 2: decision points
		dpA, dpB := len(a.DecisionPoints), len(b.DecisionPoints)
		if dpA != dpB {
			return dpA > dpB
		}

		// Level 3: общий скор
		if a.Score != b.Score {
			return a.Score > b.Score
		}

		// Level 4: путь (детерминизм)
		return a.Path < b.Path
	})
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// normalize применяет soft-cap нормализацию.
// Ниже cap — линейно, выше — логарифмически.
func normalize(score, cap float64) float64 {
	if cap <= 0 {
		return score
	}
	if score <= cap {
		return score
	}
	excess := score - cap
	return cap + math.Log2(excess+1)
}

// appendReason добавляет причину с лимитом.
const maxReasons = 8

func appendReason(reasons []string, reason string) []string {
	if len(reasons) >= maxReasons {
		return reasons
	}
	return append(reasons, reason)
}

// min returns the smaller of two ints.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
