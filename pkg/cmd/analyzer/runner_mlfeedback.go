package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/pipeline"
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ml"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ML HISTORY — УЛУЧШЕННЫЙ СБОР ДАННЫХ
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) buildMLFeedback(result *types.AnalysisResult, targetPath string) *ml.AnalysisFeedback {
	apkName := filepath.Base(targetPath)

	var apkHash string
	if strings.HasSuffix(strings.ToLower(a.opts.Target), ".apk") {
		apkHash, _ = ml.HashAPKFile(a.opts.Target)
	}

	feedback := &ml.AnalysisFeedback{
		ID:            ml.GenerateFeedbackID(apkName, time.Now()),
		APKHash:       apkHash,
		APKName:       apkName,
		Package:       result.AppPackage,
		Timestamp:     time.Now(),
		Profile:       string(a.opts.Profile),
		TotalFiles:    result.Stats.TotalFiles,
		AnalyzedFiles: result.Stats.AnalyzedFiles,
		TotalMatches:  result.Stats.TotalMatches,
		CriticalCount: countCritical(result),
		KeywordStats:  make(map[string]*ml.KeywordFeedback),
		LibraryStats:  make(map[string]*ml.LibraryFeedback),
		CategoryStats: make(map[string]*ml.CategoryFeedback),
		TopFiles:      buildTopFiles(result),
		DampeningStats: &ml.DampeningFeedback{
			Sources: make(map[string]int),
		},
	}

	// 🆕 Собираем keyword stats из файлов
	a.extractKeywordStats(result, feedback)

	// 🆕 Собираем library stats из файлов
	a.extractLibraryStats(result, feedback)

	// Собираем статистику по категориям
	for _, match := range result.RuleMatches {
		cat := string(match.Category)
		if feedback.CategoryStats[cat] == nil {
			feedback.CategoryStats[cat] = &ml.CategoryFeedback{Category: cat}
		}
		feedback.CategoryStats[cat].Matches++
		if match.IsCritical {
			feedback.CategoryStats[cat].Critical++
		}
	}

	// 🆕 Добавляем категории из MatchesByCategory
	for cat, count := range result.MatchesByCategory {
		catStr := cat.String()
		if feedback.CategoryStats[catStr] == nil {
			feedback.CategoryStats[catStr] = &ml.CategoryFeedback{Category: catStr}
		}
		feedback.CategoryStats[catStr].Matches += count
	}

	if len(a.lastPatchPoints) > 0 {
		seen := make(map[string]bool)
		for _, p := range a.lastPatchPoints {
			if p.EnsembleScore != nil {
				key := fmt.Sprintf("%s|%s|%s|%s", p.FilePath, p.ClassName, p.MethodName, p.MethodSignature)
				if !seen[key] {
					seen[key] = true
					feedback.MethodFeatures = append(feedback.MethodFeatures, ml.MethodFeatureSnapshot{
						Path:       p.FilePath,
						ClassName:  p.ClassName,
						MethodName: p.MethodName,
						Signature:  p.MethodSignature,
						Features:   p.EnsembleScore.Features,
					})
				}
			}
		}
	}

	return feedback
}

// 🆕 extractKeywordStats извлекает статистику по keywords из результата анализа
func (a *App) extractKeywordStats(result *types.AnalysisResult, feedback *ml.AnalysisFeedback) {
	for path, fa := range result.Files {
		if fa == nil {
			continue
		}

		for _, match := range fa.Matches {
			keyword := match.Pattern
			if keyword == "" {
				keyword = match.Text
			}
			if keyword == "" {
				continue
			}

			// Нормализуем keyword (берём первые 50 символов)
			if len(keyword) > 50 {
				keyword = keyword[:50]
			}

			kf, ok := feedback.KeywordStats[keyword]
			if !ok {
				kf = &ml.KeywordFeedback{
					Keyword:  keyword,
					Contexts: make(map[string]int),
				}
				feedback.KeywordStats[keyword] = kf
			}

			kf.Triggered++
			kf.SumImportance += float64(fa.Importance)

			// Определяем контекст
			if fa.IsAppCode {
				kf.InAppCode++
				kf.Contexts["app_code"]++
			}
			if isLibraryPath(path) {
				kf.InLibrary++
				kf.Contexts["library"]++
			}

			// Категория как контекст
			if match.Category != "" {
				kf.Contexts[match.Category.String()]++
			}
		}
	}
}

// 🆕 extractLibraryStats извлекает статистику по библиотекам
func (a *App) extractLibraryStats(result *types.AnalysisResult, feedback *ml.AnalysisFeedback) {
	// Группируем файлы по library prefix
	libraryFiles := make(map[string][]*types.FileAnalysis)

	for path, fa := range result.Files {
		if fa == nil {
			continue
		}

		prefix := extractLibraryPrefix(path)
		if prefix == "" {
			continue
		}

		libraryFiles[prefix] = append(libraryFiles[prefix], fa)
	}

	// Создаём статистику для каждой библиотеки
	for prefix, files := range libraryFiles {
		lf := &ml.LibraryFeedback{
			Prefix:     prefix,
			TotalFiles: len(files),
			Keywords:   make(map[string]int),
			Category:   categorizeLibrary(prefix),
		}

		for _, fa := range files {
			if len(fa.Matches) > 0 {
				lf.MatchedFiles++
			}

			lf.SumImportance += float64(fa.Importance)

			// Считаем high-value файлы
			if fa.Importance >= 5 || fa.CriticalMatchCount() > 0 {
				lf.HighValueFiles++
			}

			// Собираем keywords
			for _, match := range fa.Matches {
				kw := match.Pattern
				if kw == "" {
					kw = match.Text
				}
				if kw != "" && len(kw) <= 50 {
					lf.Keywords[kw]++
				}
			}
		}

		feedback.LibraryStats[prefix] = lf
	}
}

// 🆕 isLibraryPath определяет, является ли путь библиотечным
func isLibraryPath(path string) bool {
	pathLower := strings.ToLower(path)

	libraryPrefixes := []string{
		"com/google/", "com/facebook/", "com/android/",
		"androidx/", "android/support/",
		"com/squareup/", "com/jakewharton/",
		"org/apache/", "org/json/",
		"io/reactivex/", "rx/",
		"okhttp3/", "retrofit2/",
		"com/crashlytics/", "com/flurry/",
		"com/unity3d/", "com/applovin/",
		"com/chartboost/", "com/inmobi/",
		"com/mopub/", "com/tapjoy/",
	}

	for _, prefix := range libraryPrefixes {
		if strings.Contains(pathLower, prefix) {
			return true
		}
	}

	return false
}

// extractLibraryPrefix извлекает prefix библиотеки из пути
func extractLibraryPrefix(path string) string {
	// Нормализуем путь
	path = strings.ReplaceAll(path, "\\", "/")

	// Убираем smali/ prefix
	for _, prefix := range []string{"smali/", "smali_classes2/", "smali_classes3/", "smali_classes4/"} {
		path = strings.TrimPrefix(path, prefix)
	}

	// Убираем .smali суффикс для анализа пути
	pathForAnalysis := strings.TrimSuffix(path, ".smali")

	// Находим library prefix (первые 2-3 компонента пути)
	parts := strings.Split(pathForAnalysis, "/")
	if len(parts) < 2 {
		return ""
	}

	// Известные library prefixes (проверяем от более специфичных к общим)
	knownPrefixes := []struct {
		prefix   string
		minParts int
	}{
		{"com/google/android/gms/", 4},
		{"com/google/android/play/", 4},
		{"com/google/firebase/", 3},
		{"com/google/ads/", 3},
		{"com/android/vending/", 3},
		{"com/facebook/", 2},
		{"com/squareup/", 2},
		{"com/mopub/", 2},
		{"com/inmobi/", 2},
		{"com/greystripe/", 2},
		{"com/millennialmedia/", 2},
		{"com/flurry/", 2},
		{"com/chartboost/", 2},
		{"com/applovin/", 2},
		{"com/unity3d/", 2},
		{"com/tapjoy/", 2},
		{"com/twitter/", 2},
		{"androidx/", 1},
		{"android/support/", 2},
		{"org/apache/", 2},
		{"io/reactivex/", 2},
		{"okhttp3/", 1},
		{"retrofit2/", 1},
		{"twitter4j/", 1},
	}

	pathLower := strings.ToLower(pathForAnalysis + "/")

	for _, kp := range knownPrefixes {
		if strings.HasPrefix(pathLower, kp.prefix) {
			// Возвращаем prefix в оригинальном регистре
			if len(parts) >= kp.minParts {
				return strings.Join(parts[:kp.minParts], "/") + "/"
			}
		}
	}

	// Для остальных com/xxx/ org/xxx/ io/xxx/ — берём первые 2 части
	if len(parts) >= 2 {
		firstPart := strings.ToLower(parts[0])
		if firstPart == "com" || firstPart == "org" || firstPart == "io" || firstPart == "net" {
			return strings.Join(parts[:2], "/") + "/"
		}
	}

	return ""
}

// 🆕 categorizeLibrary определяет категорию библиотеки
func categorizeLibrary(prefix string) string {
	prefixLower := strings.ToLower(prefix)

	categories := map[string][]string{
		"ads": {
			"com/google/android/gms/ads/",
			"com/facebook/ads/",
			"com/applovin/",
			"com/chartboost/",
			"com/inmobi/",
			"com/mopub/",
			"com/tapjoy/",
			"com/unity3d/ads/",
			"com/vungle/",
			"com/ironsource/",
		},
		"analytics": {
			"com/google/firebase/analytics/",
			"com/flurry/",
			"com/crashlytics/",
			"com/mixpanel/",
			"com/amplitude/",
			"com/segment/",
		},
		"google": {
			"com/google/android/gms/",
			"com/google/firebase/",
			"com/google/android/play/",
		},
		"support": {
			"androidx/",
			"android/support/",
		},
		"network": {
			"okhttp3/",
			"retrofit2/",
			"com/squareup/okhttp/",
		},
		"social": {
			"com/facebook/",
			"com/twitter/",
			"com/vk/",
		},
	}

	for category, prefixes := range categories {
		for _, p := range prefixes {
			if strings.HasPrefix(prefixLower, p) {
				return category
			}
		}
	}

	return "other"
}

// ═══════════════════════════════════════════════════════════════════════════════
// ML HISTORY — сохранение результатов для обучения
// ═══════════════════════════════════════════════════════════════════════════════

func (a *App) saveToMLHistory(result *types.AnalysisResult, targetPath string) {
	// Не сохраняем если quiet mode
	if a.opts.Quiet {
		return
	}

	historyPath, err := ml.DefaultHistoryPath()
	if err != nil {
		a.output.Debug("ML history path error: %v", err)
		return
	}

	history, err := ml.LoadHistory(historyPath)
	if err != nil {
		a.output.Debug("ML history load error: %v", err)
		return
	}

	// Создаём feedback из результата анализа
	feedback := a.buildMLFeedback(result, targetPath)

	history.Append(feedback)

	if err := history.Save(); err != nil {
		a.output.Debug("ML history save error: %v", err)
		return
	}

	a.output.Debug("Saved analysis to ML history (%d total records)", history.Len())
}

// countCritical подсчитывает критические находки
func countCritical(result *types.AnalysisResult) int {
	count := 0
	for _, match := range result.RuleMatches {
		if match.IsCritical {
			count++
		}
	}
	return count
}

// buildTopFiles собирает топ файлов с находками
func buildTopFiles(result *types.AnalysisResult) []ml.FileFeedback {
	// Собираем файлы с находками
	fileMap := make(map[string]*ml.FileFeedback)

	// Из RuleMatches
	for _, match := range result.RuleMatches {
		path := match.File
		if path == "" && match.Pattern == "" {
			continue
		}
		if path == "" {
			path = "rule:" + match.Pattern
		}

		ff, ok := fileMap[path]
		if !ok {
			ff = &ml.FileFeedback{
				Path:       path,
				Categories: []string{},
			}
			fileMap[path] = ff
		}

		ff.Importance++

		// Добавляем категорию если ещё нет
		cat := string(match.Category)
		if cat != "" {
			found := false
			for _, c := range ff.Categories {
				if c == cat {
					found = true
					break
				}
			}
			if !found {
				ff.Categories = append(ff.Categories, cat)
			}
		}
	}

	// Из Files
	for path, fa := range result.Files {
		if fa == nil || len(fa.Matches) == 0 {
			continue
		}

		ff, ok := fileMap[path]
		if !ok {
			ff = &ml.FileFeedback{
				Path:       path,
				Categories: []string{},
			}
			fileMap[path] = ff
		}

		ff.Importance += fa.Importance
		ff.RawImportance = fa.Importance
		ff.IsAppCode = fa.IsAppCode
		ff.IsLibrary = !fa.IsAppCode && isLibraryPath(path)

		for _, match := range fa.Matches {
			ff.MatchedKeywords = append(ff.MatchedKeywords, match.Pattern)

			cat := string(match.Category)
			if cat != "" {
				found := false
				for _, c := range ff.Categories {
					if c == cat {
						found = true
						break
					}
				}
				if !found {
					ff.Categories = append(ff.Categories, cat)
				}
			}
		}
	}

	// Конвертируем в slice и сортируем
	files := make([]ml.FileFeedback, 0, len(fileMap))
	for _, ff := range fileMap {
		files = append(files, *ff)
	}

	// Сортировка по importance (убывание)
	for i := 0; i < len(files)-1; i++ {
		for j := i + 1; j < len(files); j++ {
			if files[j].Importance > files[i].Importance {
				files[i], files[j] = files[j], files[i]
			}
		}
	}

	// Топ-50
	if len(files) > 50 {
		files = files[:50]
	}

	return files
}

// ═══════════════════════════════════════════════════════════════════════════════
// USER FEEDBACK APPLICATION - v9.0.0
// ═══════════════════════════════════════════════════════════════════════════════

// applyUserFeedbackToResults применяет user overrides к результатам анализа
func (a *App) applyUserFeedbackToResults(result *types.AnalysisResult) error {
	// Загружаем историю
	historyPath, err := ml.DefaultHistoryPath()
	if err != nil {
		return err
	}

	history, err := ml.LoadHistory(historyPath)
	if err != nil || history.Len() == 0 {
		return nil // Нет истории - ничего не делаем
	}

	// Собираем все user overrides
	noisePatterns := make([]string, 0)
	relevantPatterns := make([]string, 0)
	noiseKeywords := make(map[string]bool)
	relevantKeywords := make(map[string]bool)

	for _, override := range ml.ResolveUserOverrides(history.Snapshot()) {
		switch override.Action {
		case ml.FeedbackNoise:
			if override.Keyword != "" {
				noiseKeywords[ml.NormalizeFeedbackTarget(override.Keyword)] = true
			} else if override.Path != "" {
				noisePatterns = append(noisePatterns, override.Path)
			}
		case ml.FeedbackRelevant:
			if override.Keyword != "" {
				relevantKeywords[ml.NormalizeFeedbackTarget(override.Keyword)] = true
			} else if override.Path != "" {
				relevantPatterns = append(relevantPatterns, override.Path)
			}
		}
	}

	if len(noisePatterns) == 0 && len(relevantPatterns) == 0 &&
		len(noiseKeywords) == 0 && len(relevantKeywords) == 0 {
		return nil // Нет overrides
	}

	// Применяем фильтрацию
	filteredFiles := make(map[string]*types.FileAnalysis)
	removedCount := 0
	boostedCount := 0

	for path, file := range result.Files {
		// Проверяем noise patterns
		isNoise := false
		for _, pattern := range noisePatterns {
			if matchesPattern(path, pattern) {
				isNoise = true
				break
			}
		}

		// Проверяем noise keywords в matches
		if !isNoise {
			for i := range file.Matches {
				if noiseKeywords[ml.NormalizeFeedbackTarget(file.Matches[i].Pattern)] {
					isNoise = true
					break
				}
			}
		}

		if isNoise {
			removedCount++
			result.Stats.TotalMatches -= len(file.Matches)
			if file.Importance >= 7 {
				result.Stats.CriticalMatches -= countCriticalMatches(file)
			}
			continue // Пропускаем noise файл
		}

		// Проверяем relevant patterns - boost importance
		isRelevant := false
		for _, pattern := range relevantPatterns {
			if matchesPattern(path, pattern) {
				isRelevant = true
				break
			}
		}

		// Проверяем relevant keywords
		if !isRelevant {
			for i := range file.Matches {
				if relevantKeywords[ml.NormalizeFeedbackTarget(file.Matches[i].Pattern)] {
					isRelevant = true
					break
				}
			}
		}

		if isRelevant {
			// Boost importance на 20%
			file.Importance = int(float64(file.Importance) * 1.2)
			boostedCount++
		}

		filteredFiles[path] = file
	}

	// Обновляем результаты
	result.Files = filteredFiles
	result.Stats.AnalyzedFiles = len(filteredFiles)

	if removedCount > 0 || boostedCount > 0 {
		a.output.Info("Applied user feedback: removed %d noise files, boosted %d relevant files",
			removedCount, boostedCount)
	}

	return nil
}

// matchesPattern проверяет соответствие пути паттерну
func matchesPattern(path, pattern string) bool {
	// Нормализуем пути
	path = strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	pattern = strings.ToLower(strings.ReplaceAll(pattern, "\\", "/"))

	// Убираем L префикс если есть
	pattern = strings.TrimPrefix(pattern, "l")
	path = strings.TrimPrefix(path, "l")

	// Проверяем regex паттерн
	if strings.HasSuffix(pattern, "/.*") {
		prefix := strings.TrimSuffix(pattern, "/.*")
		return strings.Contains(path, prefix)
	}

	// Проверяем точное совпадение или префикс
	return strings.Contains(path, pattern)
}

// countCriticalMatches подсчитывает критические matches в файле
func countCriticalMatches(file *types.FileAnalysis) int {
	count := 0
	for i := range file.Matches {
		if file.Matches[i].IsCritical {
			count++
		}
	}
	return count
}

// ═══════════════════════════════════════════════════════════════════════════════
// USER FEEDBACK INTEGRATION - v9.0.0
// ═══════════════════════════════════════════════════════════════════════════════

// loadUserFeedbackToPipeline загружает user overrides из ML history в pipeline
func (a *App) loadUserFeedbackToPipeline(p *pipeline.Pipeline) error {
	// Получаем путь к истории
	historyPath, err := ml.DefaultHistoryPath()
	if err != nil {
		return fmt.Errorf("failed to get history path: %w", err)
	}

	// Загружаем историю
	history, err := ml.LoadHistory(historyPath)
	if err != nil {
		// История может не существовать - это нормально
		return nil
	}

	if history.Len() == 0 {
		return nil
	}

	// Создаем фильтр
	filter := pipeline.NewUserFeedbackFilter()

	// Reconcile the append-only journal once. This prevents copied legacy
	// records and corrected labels from installing contradictory filters.
	snapshot := history.Snapshot()
	noiseCount := 0
	relevantCount := 0

	for _, override := range ml.ResolveUserOverrides(snapshot) {
		switch override.Action {
		case ml.FeedbackNoise:
			if override.Keyword != "" {
				filter.AddNoiseKeyword(override.Keyword)
				noiseCount++
			} else if override.Path != "" {
				filter.AddNoisePattern(override.Path)
				noiseCount++
			}
		case ml.FeedbackRelevant:
			if override.Keyword != "" {
				filter.AddRelevantKeyword(override.Keyword)
				relevantCount++
			} else if override.Path != "" {
				filter.AddRelevantPattern(override.Path)
				relevantCount++
			}
		}
	}

	if noiseCount > 0 || relevantCount > 0 {
		p.SetUserFeedback(filter)
		a.output.Info("Loaded user feedback: %d noise, %d relevant patterns", noiseCount, relevantCount)
	}

	return nil
}
