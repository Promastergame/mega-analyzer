package pipeline

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// TYPOSQUATTING / FAKE PACKAGE DETECTOR
// Обнаруживает похожие имена пакетов (com.paypol вместо com.paypal)
// ═══════════════════════════════════════════════════════════════════════════════

type TyposquattingDetector struct {
	popularyApps []PopularApp
}

type PopularApp struct {
	ID       string
	Name     string
	Packages []string
	Risk     string // low, medium, high
}

func NewTyposquattingDetector() *TyposquattingDetector {
	return &TyposquattingDetector{
		popularyApps: getPopularAppsDatabase(),
	}
}

func (d *TyposquattingDetector) Name() string {
	return "typosquatting_detector"
}

func (d *TyposquattingDetector) SupportsFile(fileType types.FileType, path string) bool {
	return fileType == types.FileTypeXML && strings.Contains(strings.ToLower(path), "androidmanifest")
}

func (d *TyposquattingDetector) Detect(ctx *FileDetectContext, analysis *types.FileAnalysis) {
	// Только проверяем манифест где определен пакет приложения
	if !strings.Contains(ctx.Path, "AndroidManifest") {
		return
	}

	// Извлекаем package name из контекста
	packageName := d.extractPackageName(ctx, analysis)
	if packageName == "" {
		return
	}

	d.checkTyposquatting(packageName, analysis)
}

// extractPackageName извлекает package name из файла
func (d *TyposquattingDetector) extractPackageName(ctx *FileDetectContext, _ *types.FileAnalysis) string {
	contentStr := string(ctx.Content)
	startIdx := strings.Index(contentStr, `package="`)
	if startIdx < 0 {
		return ""
	}
	startIdx += len(`package="`)
	endIdx := strings.Index(contentStr[startIdx:], `"`)
	if endIdx < 0 {
		return ""
	}
	return contentStr[startIdx : startIdx+endIdx]
}

// checkTyposquatting проверяет package на typosquatting
func (d *TyposquattingDetector) checkTyposquatting(pkgName string, analysis *types.FileAnalysis) {
	for _, app := range d.popularyApps {
		for _, legit := range app.Packages {
			distance := levenshteinDistance(pkgName, legit)
			maxLen := maxInt(len(pkgName), len(legit))

			// Если расстояние маленькое (< 30% от длины), это подозрительно
			if maxLen > 0 && float64(distance) < float64(maxLen)*0.3 && distance > 0 {
				analysis.Matches = append(analysis.Matches, newMatch(
					types.CategorySecurity,
					analysis.Path,
					0,
					"Potential Typosquatting/Spoofing of "+app.Name,
					"Actual: "+pkgName+" | Legitimate: "+legit+" | Distance: "+string(rune(distance)),
					true,
				))
			}
		}
	}
}

// levenshteinDistance вычисляет расстояние Левенштейна между двумя строками
func levenshteinDistance(s1, s2 string) int {
	len1, len2 := len(s1), len(s2)
	if len1 == 0 {
		return len2
	}
	if len2 == 0 {
		return len1
	}

	d := make([][]int, len1+1)
	for i := range d {
		d[i] = make([]int, len2+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}

	for i := 1; i <= len1; i++ {
		for j := 1; j <= len2; j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}
			d[i][j] = min3(
				d[i-1][j]+1,      // deletion
				d[i][j-1]+1,      // insertion
				d[i-1][j-1]+cost, // substitution
			)
		}
	}
	return d[len1][len2]
}

// УДАЛЕНЫ функции min3 и maxInt - они теперь в helpers.go

// ═══════════════════════════════════════════════════════════════════════════════
// POPULAR APPS DATABASE
// ═══════════════════════════════════════════════════════════════════════════════

func getPopularAppsDatabase() []PopularApp {
	return []PopularApp{
		{
			ID:   "google",
			Name: "Google Services",
			Packages: []string{
				"com.google.android.gms",
				"com.google.android.apps",
				"com.google.android",
			},
			Risk: "high",
		},
		{
			ID:   "paypal",
			Name: "PayPal",
			Packages: []string{
				"com.paypal.android.p2pmobile",
				"com.paypal",
			},
			Risk: "critical",
		},
		{
			ID:   "whatsapp",
			Name: "WhatsApp",
			Packages: []string{
				"com.whatsapp",
			},
			Risk: "high",
		},
		{
			ID:   "sberbank",
			Name: "Sberbank",
			Packages: []string{
				"ru.sberbankmobile",
				"com.sberbank",
			},
			Risk: "critical",
		},
		{
			ID:   "yandex",
			Name: "Yandex Services",
			Packages: []string{
				"com.yandex",
				"ru.yandex",
			},
			Risk: "high",
		},
		{
			ID:   "instagram",
			Name: "Instagram",
			Packages: []string{
				"com.instagram.android",
			},
			Risk: "high",
		},
		{
			ID:   "spotify",
			Name: "Spotify",
			Packages: []string{
				"com.spotify.music",
			},
			Risk: "medium",
		},
		{
			ID:   "facebook",
			Name: "Facebook",
			Packages: []string{
				"com.facebook.katana",
			},
			Risk: "high",
		},
	}
}
