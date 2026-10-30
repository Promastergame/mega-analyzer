package ml

import (
	"fmt"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FEEDBACK SUGGESTIONS - автоматические рекомендации по маркировке
// ═══════════════════════════════════════════════════════════════════════════════

// FeedbackSuggestion - рекомендация по маркировке
type FeedbackSuggestion struct {
	Pattern       string  `json:"pattern"`
	Action        string  `json:"action"` // "noise" or "relevant"
	Reason        string  `json:"reason"`
	Confidence    float64 `json:"confidence"`     // 0-1
	AffectedCount int     `json:"affected_count"` // сколько результатов затронет
}

// SuggestFeedback анализирует результаты и предлагает маркировки
func (pp *PatchPredictor) SuggestFeedback(prediction *PatchPrediction) []FeedbackSuggestion {
	suggestions := make([]FeedbackSuggestion, 0)

	// Собираем все результаты
	allPoints := append(prediction.HighRisk, prediction.MediumRisk...)
	allPoints = append(allPoints, prediction.LowRisk...)

	if len(allPoints) == 0 {
		return suggestions
	}

	// 1. Анализируем частые префиксы (потенциальные библиотеки)
	prefixCounts := make(map[string]int)
	for _, point := range allPoints {
		prefix := extractPackagePrefix(point.FilePath, 1) // первый уровень для библиотек
		if prefix != "" {
			prefixCounts[prefix]++
		}
	}

	// Предлагаем префиксы, которые встречаются часто
	for prefix, count := range prefixCounts {
		if count >= 5 && isLikelyLibrary(prefix) {
			suggestions = append(suggestions, FeedbackSuggestion{
				Pattern:       prefix,
				Action:        "noise",
				Reason:        "Library prefix appears frequently",
				Confidence:    calculateLibraryConfidence(prefix, count, len(allPoints)),
				AffectedCount: count,
			})
		}
	}

	// 2. Анализируем obfuscated паттерны
	obfuscatedPrefixes := findObfuscatedPrefixes(allPoints)
	for prefix, count := range obfuscatedPrefixes {
		if count >= 3 {
			suggestions = append(suggestions, FeedbackSuggestion{
				Pattern:       prefix,
				Action:        "noise",
				Reason:        "Obfuscated library code (short package names)",
				Confidence:    0.8,
				AffectedCount: count,
			})
		}
	}

	// 3. Анализируем app code с высоким риском
	appCodeHighRisk := make(map[string]int)
	for _, point := range prediction.HighRisk {
		if point.IsAppCode {
			prefix := extractPackagePrefix(point.FilePath, 2) // 2 уровня для app code
			if prefix != "" {
				appCodeHighRisk[prefix]++
			}
		}
	}

	for prefix, count := range appCodeHighRisk {
		if count >= 2 {
			suggestions = append(suggestions, FeedbackSuggestion{
				Pattern:       prefix,
				Action:        "relevant",
				Reason:        "App code with multiple high-risk findings",
				Confidence:    0.7,
				AffectedCount: count,
			})
		}
	}

	// Сортируем по confidence и affected count
	sort.Slice(suggestions, func(i, j int) bool {
		if suggestions[i].Confidence != suggestions[j].Confidence {
			return suggestions[i].Confidence > suggestions[j].Confidence
		}
		return suggestions[i].AffectedCount > suggestions[j].AffectedCount
	})

	// Ограничиваем до топ-10
	if len(suggestions) > 10 {
		suggestions = suggestions[:10]
	}

	return suggestions
}

// extractPackagePrefix извлекает префикс пакета
func extractPackagePrefix(path string, levels int) string {
	// Нормализуем путь
	path = strings.ReplaceAll(path, "\\", "/")
	path = strings.TrimPrefix(path, "smali/")
	path = strings.TrimSuffix(path, ".smali")
	path = strings.Trim(path, "/")

	if path == "" {
		return ""
	}

	parts := strings.Split(path, "/")
	if len(parts) < levels {
		levels = len(parts)
	}

	if levels == 0 {
		return ""
	}

	prefix := strings.Join(parts[:levels], "/")
	return prefix + "/"
}

// isLikelyLibrary проверяет, похож ли префикс на библиотеку
func isLikelyLibrary(prefix string) bool {
	lowerPrefix := strings.ToLower(prefix)

	// Известные библиотечные префиксы
	libraryPrefixes := []string{
		"android/",
		"androidx/",
		"landroidx/", // case-insensitive
		"com/google/",
		"com/facebook/",
		"kotlin/",
		"kotlinx/",
		"okhttp",
		"retrofit",
		"glide/",
		"picasso/",
		"gson/",
		"jackson/",
	}

	for _, libPrefix := range libraryPrefixes {
		if strings.HasPrefix(lowerPrefix, libPrefix) {
			return true
		}
	}

	// Проверяем паттерны библиотек
	if strings.Contains(lowerPrefix, "/internal/") {
		return true
	}

	if strings.Contains(lowerPrefix, "/support/") {
		return true
	}

	return false
}

// calculateLibraryConfidence вычисляет уверенность, что это библиотека
func calculateLibraryConfidence(prefix string, count, total int) float64 {
	// Базовая уверенность на основе частоты
	frequency := float64(count) / float64(total)
	confidence := frequency * 0.5 // 50% веса от частоты

	// Бонус за известные префиксы
	if isLikelyLibrary(prefix) {
		confidence += 0.3
	}

	// Бонус за большое количество
	if count >= 10 {
		confidence += 0.1
	}

	if count >= 20 {
		confidence += 0.1
	}

	// Ограничиваем 0-1
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// findObfuscatedPrefixes находит obfuscated префиксы
func findObfuscatedPrefixes(points []PatchPoint) map[string]int {
	counts := make(map[string]int)

	for _, point := range points {
		prefix := extractPackagePrefix(point.FilePath, 1)
		if prefix == "" {
			continue
		}

		// Проверяем признаки obfuscation
		// 1. Короткое имя (1-2 символа)
		// 2. Только буквы
		// 3. Не похоже на стандартные пакеты

		prefixName := strings.TrimSuffix(prefix, "/")
		if len(prefixName) <= 2 && isAlphaOnly(prefixName) {
			// Исключаем стандартные короткие пакеты
			if prefixName != "io" && prefixName != "os" {
				counts[prefix]++
			}
		}
	}

	return counts
}

// isAlphaOnly проверяет, состоит ли строка только из букв
func isAlphaOnly(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return len(s) > 0
}

// RenderSuggestions выводит рекомендации в терминал
func (pp *PatchPredictor) RenderSuggestions(suggestions []FeedbackSuggestion) {
	if len(suggestions) == 0 {
		return
	}

	w := pp.output

	fmt.Fprintln(w)
	fmt.Fprintln(w, "  ╔══════════════════════════════════════════╗")
	fmt.Fprintln(w, "  ║      FEEDBACK SUGGESTIONS                ║")
	fmt.Fprintln(w, "  ║   Improve future analysis results       ║")
	fmt.Fprintln(w, "  ╚══════════════════════════════════════════╝")
	fmt.Fprintln(w)

	noiseSuggestions := 0
	relevantSuggestions := 0

	for _, s := range suggestions {
		if s.Action == "noise" {
			noiseSuggestions++
		} else {
			relevantSuggestions++
		}
	}

	fmt.Fprintf(w, "  Found %d suggestions (%d noise, %d relevant)\n\n",
		len(suggestions), noiseSuggestions, relevantSuggestions)

	// Noise suggestions
	if noiseSuggestions > 0 {
		fmt.Fprintln(w, "  🔇 NOISE PATTERNS (filter out)")
		fmt.Fprintln(w, "  ════════════════════════════")
		for i, s := range suggestions {
			if s.Action != "noise" {
				continue
			}

			fmt.Fprintf(w, "  %d. %s\n", i+1, s.Pattern)
			fmt.Fprintf(w, "     Reason:     %s\n", s.Reason)
			fmt.Fprintf(w, "     Confidence: %.0f%%\n", s.Confidence*100)
			fmt.Fprintf(w, "     Affects:    %d results\n", s.AffectedCount)
			fmt.Fprintf(w, "     Command:    analyzer --mark-noise \"%s\"\n", s.Pattern)
			fmt.Fprintln(w)
		}
	}

	// Relevant suggestions
	if relevantSuggestions > 0 {
		fmt.Fprintln(w, "  ⭐ RELEVANT PATTERNS (boost score)")
		fmt.Fprintln(w, "  ═══════════════════════════════")
		for i, s := range suggestions {
			if s.Action != "relevant" {
				continue
			}

			fmt.Fprintf(w, "  %d. %s\n", i+1, s.Pattern)
			fmt.Fprintf(w, "     Reason:     %s\n", s.Reason)
			fmt.Fprintf(w, "     Confidence: %.0f%%\n", s.Confidence*100)
			fmt.Fprintf(w, "     Affects:    %d results\n", s.AffectedCount)
			fmt.Fprintf(w, "     Command:    analyzer --mark-relevant \"%s\"\n", s.Pattern)
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintln(w, "  💡 TIP: Apply suggestions to improve future analysis")
	fmt.Fprintln(w)
}
