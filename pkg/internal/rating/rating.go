package rating

import (
	"math"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// CategoryName константы для 6 основных категорий рейтингов
const (
	CatMalware    = "MALWARE"
	CatPiracy     = "PIRACY"
	CatCrackPoint = "CRACK_POINT"
	CatSecurity   = "SECURITY"
	CatBilling    = "BILLING"
	CatPrivacy    = "PRIVACY"
)

// CategoryRating хранит результаты расчёта по одной категории
type CategoryRating struct {
	Category string  `json:"category"`
	Name     string  `json:"name"`
	Score    int     `json:"score"` // 0-10
	Level    string  `json:"level"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Color    string  `json:"color"` // Hex-цвет для UI
	Count    int     `json:"count"` // Количество уникальных находок
	MaxScore float64 `json:"max_score"`
}

// RiskProfile содержит профиль безопасности по 6 категориям и итоговый индекс
type RiskProfile struct {
	OverallScore int                       `json:"overall_score"` // 0-100% (для спидометра)
	OverallLevel string                    `json:"overall_level"` // "SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Categories   map[string]CategoryRating `json:"categories"`
	PrimaryRisk  string                    `json:"primary_risk"` // Самая критичная категория
}

// MapCategory приводит категорию из Finding к одной из 6 базовых категорий
func MapCategory(rawCategory types.Category) string {
	catStr := strings.ToUpper(string(rawCategory))

	switch {
	case strings.Contains(catStr, "MALWARE") || strings.Contains(catStr, "THREAT") || strings.Contains(catStr, "C2"):
		return CatMalware
	case strings.Contains(catStr, "PIRACY") || strings.Contains(catStr, "WAREZ") || strings.Contains(catStr, "WATERMARK") || strings.Contains(catStr, "MOD_"):
		return CatPiracy
	case strings.Contains(catStr, "CRACK") || strings.Contains(catStr, "PATCH") || strings.Contains(catStr, "LICENSE") || strings.Contains(catStr, "LVL"):
		return CatCrackPoint
	case strings.Contains(catStr, "SECURITY") || strings.Contains(catStr, "SIGNATURE") || strings.Contains(catStr, "TAMPER") || strings.Contains(catStr, "ROOT"):
		return CatSecurity
	case strings.Contains(catStr, "BILLING") || strings.Contains(catStr, "PURCHASE") || strings.Contains(catStr, "SUBSCRIPTION") || strings.Contains(catStr, "PRO_FEATURE"):
		return CatBilling
	case strings.Contains(catStr, "PRIVACY") || strings.Contains(catStr, "TRACKER") || strings.Contains(catStr, "PERMISSION") || strings.Contains(catStr, "EXFIL"):
		return CatPrivacy
	default:
		return CatSecurity
	}
}

// ComputeProfile рассчитывает вектор оценок по 6 категориям на основе классифицированных находок
func ComputeProfile(findings []types.ClassifiedFinding) RiskProfile {
	counts := make(map[string]int)
	maxScores := make(map[string]float64)

	// Дедупликация и расчёт максимальных оценок по категориям.
	// Считаем уникальные паттерны и плавно учитываем повторения одного паттерна.
	seenFingerprints := make(map[string]bool)
	patternCounts := make(map[string]int) // Key: category:pattern

	for _, f := range findings {
		// Игнорируем подавленный SDK шум при подсчёте рисков приложения
		if f.Verdict == types.VerdictSDKNoiseSuppressed || f.Verdict == types.VerdictGenericNoiseSuppressed {
			continue
		}

		orig := f.Original
		if orig == nil {
			continue
		}

		mappedCat := MapCategory(orig.Category)
		fp := orig.File + ":" + string(orig.Category) + ":" + orig.Pattern + ":" + orig.Text

		if !seenFingerprints[fp] {
			seenFingerprints[fp] = true
			if f.FinalScore > maxScores[mappedCat] {
				maxScores[mappedCat] = f.FinalScore
			}

			patKey := mappedCat + ":" + orig.Pattern
			if orig.Pattern == "" {
				patKey = mappedCat + ":" + orig.Text
			}
			patternCounts[patKey]++
		}
	}

	// Рассчитываем эквивалентное количество находок для каждой категории
	for patKey, occCount := range patternCounts {
		parts := strings.SplitN(patKey, ":", 2)
		cat := parts[0]
		// 1 уникальный паттерн дает +1 к счетчику, а каждые N повторений добавляют угасающую прибавку log10(occCount)
		weightedInc := 1.0 + 0.3*math.Log10(float64(occCount))
		counts[cat] += int(math.Round(weightedInc))
	}

	catRatings := make(map[string]CategoryRating)
	categoriesList := []struct {
		key   string
		name  string
		color string
	}{
		{CatMalware, "Malware & Threats", "#ef4444"},
		{CatPiracy, "Piracy & Warez", "#8b5cf6"},
		{CatCrackPoint, "Crack-Points", "#f59e0b"},
		{CatSecurity, "Security & Protection", "#3b82f6"},
		{CatBilling, "Billing & Purchases", "#eab308"},
		{CatPrivacy, "Privacy & Leaks", "#10b981"},
	}

	maxOverallScore := 0
	primaryCat := "SAFE"

	for _, cDef := range categoriesList {
		cnt := counts[cDef.key]
		mScore := maxScores[cDef.key]

		// Логарифмическая формула подсчёта очков категории (0 - 10)
		score := 0
		if cnt > 0 {
			baseScore := mScore / 10.0 // Нормализация к 0-10
			if baseScore > 10.0 {
				baseScore = 10.0
			}
			logBoost := 2.5 * math.Log10(float64(cnt))
			score = int(math.Min(10.0, math.Round(baseScore+logBoost)))
			// Пол только снизу от отрицательных значений: категория с
			// нулевым риском — это 0/SAFE, а не 1/LOW. Старый пол (score<1
			// → 1) превращал безрисковые находки в PRIMARY_RISK и зажигал
			// спидометр.
			if score < 0 {
				score = 0
			}
		}

		level := "LOW"
		switch {
		case score >= 9:
			level = "CRITICAL"
		case score >= 7:
			level = "HIGH"
		case score >= 4:
			level = "MEDIUM"
		case score > 0:
			level = "LOW"
		default:
			level = "SAFE"
		}

		if score > maxOverallScore {
			maxOverallScore = score
			primaryCat = cDef.name
		}

		catRatings[cDef.key] = CategoryRating{
			Category: cDef.key,
			Name:     cDef.name,
			Score:    score,
			Level:    level,
			Color:    cDef.color,
			Count:    cnt,
			MaxScore: mScore,
		}
	}

	// Спидометр 0-100%
	overallScorePct := int(math.Min(100.0, float64(maxOverallScore)*10.0))
	overallLevel := "SAFE"
	switch {
	case overallScorePct >= 85:
		overallLevel = "CRITICAL"
	case overallScorePct >= 65:
		overallLevel = "HIGH"
	case overallScorePct >= 35:
		overallLevel = "MEDIUM"
	case overallScorePct > 0:
		overallLevel = "LOW"
	}

	return RiskProfile{
		OverallScore: overallScorePct,
		OverallLevel: overallLevel,
		Categories:   catRatings,
		PrimaryRisk:  primaryCat,
	}
}
