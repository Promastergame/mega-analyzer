package ml

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ENHANCED ML SUGGESTER v8.1.0
// Улучшения: контекстная важность, кластеризация, анти-паттерны, категории, корреляции
// ═══════════════════════════════════════════════════════════════════════════════

// #1 - Контекстная важность паттернов
func (ctx *analysisContext) calculateContextImportance(kw *AggregatedKeywordStats) float64 {
	if kw.TotalTriggered == 0 {
		return 0
	}
	if ctx.importanceCache == nil {
		ctx.importanceCache = make(map[string]float64)
	}
	if val, ok := ctx.importanceCache[kw.Keyword]; ok {
		return val
	}

	// Соотношение важности в app code vs library
	appImportance := 0.0
	libImportance := 0.0

	for _, fb := range ctx.snapshot {
		if kwFb, ok := fb.KeywordStats[kw.Keyword]; ok {
			if kwFb.InAppCode > 0 {
				appImportance += kwFb.SumImportance / float64(kwFb.InAppCode)
			}
			if kwFb.InLibrary > 0 {
				libImportance += kwFb.SumImportance / float64(kwFb.InLibrary)
			}
		}
	}

	res := 0.0
	// Если в app code важность высокая, а в библиотеках низкая → хороший сигнал
	if libImportance > 0 {
		ratio := appImportance / libImportance
		if ratio > 2.0 {
			res = 1.0 // Сильный сигнал
		} else if ratio > 1.5 {
			res = 0.7 // Средний сигнал
		}
	} else if appImportance > 0 && libImportance == 0 {
		// Если только в app code → тоже хороший сигнал
		res = 0.9
	}

	ctx.importanceCache[kw.Keyword] = res
	return res
}

// #3 - Кластеризация похожих паттернов
type PatternCluster struct {
	CommonPrefix  string
	Patterns      []string
	TotalCount    int
	AvgImportance float64
	Confidence    float64
}

func (ctx *analysisContext) clusterPatterns(keywords map[string]*AggregatedKeywordStats) []PatternCluster {
	// Группируем по префиксам
	prefixGroups := make(map[string][]string)

	for kw := range keywords {
		// Ищем общий префикс (до последнего /)
		prefix := extractPrefix(kw)
		if prefix != "" && len(prefix) > 5 { // Минимум 5 символов
			prefixGroups[prefix] = append(prefixGroups[prefix], kw)
		}
	}

	// Создаем кластеры
	clusters := make([]PatternCluster, 0)
	for prefix, patterns := range prefixGroups {
		if len(patterns) < 3 { // Минимум 3 паттерна для кластера
			continue
		}

		totalCount := 0
		sumImportance := 0.0

		for _, pattern := range patterns {
			if kw, ok := keywords[pattern]; ok {
				totalCount += kw.TotalTriggered
				sumImportance += kw.AvgImportance() * float64(kw.TotalTriggered)
			}
		}

		avgImportance := 0.0
		if totalCount > 0 {
			avgImportance = sumImportance / float64(totalCount)
		}

		// Confidence зависит от количества паттернов и их согласованности
		confidence := math.Min(0.95, 0.7+float64(len(patterns))*0.05)

		clusters = append(clusters, PatternCluster{
			CommonPrefix:  prefix,
			Patterns:      patterns,
			TotalCount:    totalCount,
			AvgImportance: avgImportance,
			Confidence:    confidence,
		})
	}

	// Сортируем по количеству паттернов
	sort.Slice(clusters, func(i, j int) bool {
		return len(clusters[i].Patterns) > len(clusters[j].Patterns)
	})

	return clusters
}

func extractPrefix(pattern string) string {
	res := ""

	// Handle L prefix
	clean := pattern
	if strings.HasPrefix(pattern, "L") {
		clean = pattern[1:]
	}

	if strings.Contains(clean, "/") {
		parts := strings.Split(clean, "/")
		if len(parts) >= 2 {
			res = strings.Join(parts[:len(parts)-1], "/")
		}
	}

	if len(res) < 5 {
		return ""
	}

	return res
}

// #4 - Анти-паттерны (что НЕ noise)
func (ctx *analysisContext) isAntiPattern(kw *AggregatedKeywordStats) (bool, string) {
	// Проверяем встречаемость в критических находках
	criticalCount := 0
	totalInCritical := 0

	for _, fb := range ctx.snapshot {
		if kwFb, ok := fb.KeywordStats[kw.Keyword]; ok {
			// Проверяем контексты на критические категории
			for context, count := range kwFb.Contexts {
				if isCriticalContext(context) {
					criticalCount++
					totalInCritical += count
				}
			}
		}
	}

	// Если часто встречается в критических контекстах → не noise
	if criticalCount > 0 {
		criticalRatio := float64(totalInCritical) / float64(kw.TotalTriggered)
		if criticalRatio > 0.3 {
			return true, "High co-occurrence with critical findings"
		}
		if criticalRatio > 0.15 {
			return true, "Moderate co-occurrence with critical findings"
		}
	}

	// Если средняя важность высокая → не noise
	if kw.AvgImportance() > 5.0 {
		return true, "High average importance score"
	}

	return false, ""
}

func isCriticalContext(context string) bool {
	criticalContexts := []string{
		"PREMIUM_CHECK", "SUBSCRIPTION", "LICENSE_CHECK",
		"ROOT_DETECTION", "EMULATOR_DETECTION", "DEBUGGER_DETECTION",
		"BILLING_CLIENT", "PURCHASE_VERIFY", "PLAY_INTEGRITY",
		"ENCRYPTION", "OBFUSCATION", "NATIVE_CODE",
	}

	contextUpper := strings.ToUpper(context)
	for _, critical := range criticalContexts {
		if strings.Contains(contextUpper, critical) {
			return true
		}
	}

	return false
}

// #6 - Категориальный анализ
func (ctx *analysisContext) analyzeCategoryDistribution(kw *AggregatedKeywordStats) map[string]float64 {
	categoryDist := make(map[string]int)
	total := 0

	for _, fb := range ctx.snapshot {
		if kwFb, ok := fb.KeywordStats[kw.Keyword]; ok {
			for context, count := range kwFb.Contexts {
				// Пропускаем технические контексты
				if context == "app_code" || context == "library" {
					continue
				}
				categoryDist[context] += count
				total += count
			}
		}
	}

	// Нормализуем в проценты
	result := make(map[string]float64)
	if total > 0 {
		for cat, count := range categoryDist {
			result[cat] = float64(count) / float64(total)
		}
	}

	return result
}

func (ctx *analysisContext) getCategoryRecommendation(categoryDist map[string]float64) (string, float64) {
	// Если >70% в одной категории → сильная рекомендация
	for cat, ratio := range categoryDist {
		if ratio > 0.7 {
			if isNoiseCategory(cat) {
				return "noise", 0.9
			}
			if isRelevantCategory(cat) {
				return "relevant", 0.9
			}
		}
	}

	// Если >50% в noise категориях → средняя рекомендация
	noiseRatio := 0.0
	relevantRatio := 0.0

	for cat, ratio := range categoryDist {
		if isNoiseCategory(cat) {
			noiseRatio += ratio
		}
		if isRelevantCategory(cat) {
			relevantRatio += ratio
		}
	}

	if noiseRatio > 0.5 {
		return "noise", 0.7
	}
	if relevantRatio > 0.5 {
		return "relevant", 0.7
	}

	return "", 0.0
}

func isNoiseCategory(category string) bool {
	noiseCategories := []string{
		"ANALYTICS", "AD_NETWORK", "TRACKING",
		"FIREBASE", "CRASHLYTICS", "APPSFLYER",
	}

	catUpper := strings.ToUpper(category)
	for _, noise := range noiseCategories {
		if strings.Contains(catUpper, noise) {
			return true
		}
	}

	return false
}

func isRelevantCategory(category string) bool {
	relevantCategories := []string{
		"PREMIUM_CHECK", "SUBSCRIPTION", "LICENSE",
		"ROOT_DETECTION", "EMULATOR", "DEBUGGER",
		"BILLING", "PURCHASE", "INTEGRITY",
	}

	catUpper := strings.ToUpper(category)
	for _, relevant := range relevantCategories {
		if strings.Contains(catUpper, relevant) {
			return true
		}
	}

	return false
}

// #8 - Корреляция с другими паттернами
type KeywordCorrelation struct {
	Keyword     string
	Coefficient float64
}

func (ctx *analysisContext) findCorrelatedPatterns(kw *AggregatedKeywordStats, _ map[string]*AggregatedKeywordStats) []KeywordCorrelation {
	correlations := make([]KeywordCorrelation, 0)

	// Для каждого APK смотрим какие паттерны встречаются вместе
	coOccurrence := make(map[string]int)

	for _, fb := range ctx.snapshot {
		if _, hasTarget := fb.KeywordStats[kw.Keyword]; hasTarget {
			// Этот APK содержит наш паттерн, смотрим что еще есть
			for otherKw := range fb.KeywordStats {
				if otherKw != kw.Keyword {
					coOccurrence[otherKw]++
				}
			}
		}
	}

	// Вычисляем корреляцию
	totalAPKsWithTarget := 0
	for _, fb := range ctx.snapshot {
		if _, has := fb.KeywordStats[kw.Keyword]; has {
			totalAPKsWithTarget++
		}
	}

	if totalAPKsWithTarget == 0 {
		return correlations
	}

	for otherKw, coCount := range coOccurrence {
		// Корреляция = сколько раз встречаются вместе / сколько раз встречается target
		correlation := float64(coCount) / float64(totalAPKsWithTarget)

		if correlation > 0.7 { // Сильная корреляция
			correlations = append(correlations, KeywordCorrelation{
				Keyword:     otherKw,
				Coefficient: correlation,
			})
		}
	}

	// Сортируем по корреляции
	sort.Slice(correlations, func(i, j int) bool {
		return correlations[i].Coefficient > correlations[j].Coefficient
	})

	// Ограничиваем топ-5
	if len(correlations) > 5 {
		correlations = correlations[:5]
	}

	return correlations
}

// Интеграция в основной suggester - УДАЛЕНО
// Эта функция не нужна, т.к. интеграция происходит через applyEnhancements() в suggester.go

func (sg *MLSuggester) enhanceSuggestion(ctx *analysisContext, sugg Suggestion) Suggestion {
	// Находим keyword stats
	kwStats, ok := ctx.aggKeywords[sugg.Target]
	if !ok {
		return sugg
	}

	// #1 - Контекстная важность
	contextScore := ctx.calculateContextImportance(kwStats)
	if contextScore > 0.7 {
		sugg.Reasoning = append(sugg.Reasoning,
			fmt.Sprintf("High context importance: %.1f (app code vs library)", contextScore))
	}

	// #4 - Проверка анти-паттернов
	isAnti, reason := ctx.isAntiPattern(kwStats)
	if isAnti {
		sugg.Reasoning = append(sugg.Reasoning,
			fmt.Sprintf("⚠ Anti-pattern detected: %s", reason))
	}

	// #6 - Категориальный анализ
	var hasRelevantCategory bool
	categoryDist := ctx.analyzeCategoryDistribution(kwStats)
	if len(categoryDist) > 0 {
		action, catConfidence := ctx.getCategoryRecommendation(categoryDist)
		if action != "" && catConfidence > 0.7 {
			if action == "relevant" {
				hasRelevantCategory = true
			}
			sugg.Confidence = math.Max(sugg.Confidence, catConfidence)
			sugg.Reasoning = append(sugg.Reasoning,
				fmt.Sprintf("Category analysis suggests: %s (%.0f%% confidence)", action, catConfidence*100))
		}
	}

	// Flip dampening/reduce_weight to increase_weight if the keyword is actually an anti-pattern or relevant category
	if isAnti || hasRelevantCategory {
		if sugg.Action == "reduce_weight" || sugg.Action == "add_dampening" {
			sugg.Action = "increase_weight"
			sugg.Confidence = math.Min(0.95, sugg.Confidence*1.5) // Boost confidence due to positive validation of its relevance
			sugg.RiskImpact = RiskHigh
			sugg.Observation = fmt.Sprintf(
				"Although observed average importance is low (avg %.2f), this keyword acts as a critical anchor/indicator for relevant or high-risk features.",
				kwStats.AvgImportance(),
			)
			sugg.Recommendation = "Increase keyword weight or boost its score to improve detection sensitivity."
			sugg.ExpectedEffect = "Higher visibility and more reliable detection of critical code blocks."
		}
	} else if isAnti {
		sugg.Confidence *= 0.5 // Снижаем confidence для обычных шумов если антипаттерн ложный
	}

	// #8 - Корреляции
	correlations := ctx.findCorrelatedPatterns(kwStats, ctx.aggKeywords)
	if len(correlations) > 0 {
		// Проверяем сколько коррелированных паттернов являются noise
		noiseCorrelations := 0
		for _, corr := range correlations {
			if otherStats, ok := ctx.aggKeywords[corr.Keyword]; ok {
				if otherStats.NoiseRatio > 0.8 {
					noiseCorrelations++
				}
			}
		}

		if noiseCorrelations >= 3 {
			sugg.Confidence = math.Min(1.0, sugg.Confidence*1.2)
			sugg.Reasoning = append(sugg.Reasoning,
				fmt.Sprintf("Strongly correlated with %d noise patterns", noiseCorrelations))
		}
	}

	return sugg
}

func (sg *MLSuggester) generateClusterSuggestions(ctx *analysisContext) []Suggestion {
	suggestions := make([]Suggestion, 0)

	clusters := ctx.clusterPatterns(ctx.aggKeywords)

	for i, cluster := range clusters {
		if i >= 5 { // Максимум 5 кластеров
			break
		}

		if cluster.AvgImportance < 1.0 && cluster.TotalCount > 50 {
			sugg := Suggestion{
				Type:       TypePattern,
				Target:     cluster.CommonPrefix + "/.*",
				Action:     "noise",
				Confidence: cluster.Confidence,
				Samples:    cluster.TotalCount,
				RiskImpact: RiskLow,
				Observation: fmt.Sprintf("Detected pattern cluster with %d similar patterns (avg importance: %.2f)",
					len(cluster.Patterns), cluster.AvgImportance),
				Recommendation: fmt.Sprintf("Mark entire prefix '%s/.*' as noise instead of %d individual patterns",
					cluster.CommonPrefix, len(cluster.Patterns)),
				ExpectedEffect: "Reduce noise with single regex pattern",
				Reasoning: []string{
					fmt.Sprintf("Cluster size: %d patterns", len(cluster.Patterns)),
					fmt.Sprintf("Total occurrences: %d", cluster.TotalCount),
					fmt.Sprintf("Average importance: %.2f", cluster.AvgImportance),
					fmt.Sprintf("Examples: %s, %s, ...", cluster.Patterns[0], cluster.Patterns[1]),
				},
			}
			suggestions = append(suggestions, sugg)
		}
	}

	return suggestions
}
