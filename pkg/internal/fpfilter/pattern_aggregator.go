package fpfilter

import (
	"sort"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// PatternLocation содержат точный путь к файлу и номер строки
type PatternLocation struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// AggregatedPatternFinding агрегирует массовые водяные знаки или одинаковые патерны (например androeed.ru, 5play.ru)
type AggregatedPatternFinding struct {
	PatternID    string            `json:"pattern_id"` // "androeed.ru", "5play.ru" и т.д.
	Category     string            `json:"category"`
	TotalCount   int               `json:"total_count"`
	SamplePaths  []string          `json:"sample_paths"` // Первые 5 примеров для UI
	AllLocations []PatternLocation `json:"all_locations"`
	IsSDKNoise   bool              `json:"is_sdk_noise"`
}

// Aggregator собирает многократные детекты одного патерна и группирует их
type Aggregator struct {
	minThreshold int
}

func NewAggregator(minThreshold int) *Aggregator {
	if minThreshold <= 0 {
		minThreshold = 3
	}
	return &Aggregator{
		minThreshold: minThreshold,
	}
}

// AggregateFindings группирует классифицированные находки
func (a *Aggregator) AggregateFindings(findings []types.ClassifiedFinding) []AggregatedPatternFinding {
	groups := make(map[string]*AggregatedPatternFinding)

	for _, f := range findings {
		orig := f.Original
		if orig == nil || orig.Pattern == "" {
			continue
		}

		pat := strings.ToLower(orig.Pattern)
		// Только водяные знаки пиратства, репак-метки и домены из БД
		if !isAggregatablePattern(string(orig.Category), pat, orig.Text) {
			continue
		}

		group, ok := groups[pat]
		if !ok {
			group = &AggregatedPatternFinding{
				PatternID:    orig.Pattern,
				Category:     string(orig.Category),
				TotalCount:   0,
				SamplePaths:  make([]string, 0, 5),
				AllLocations: make([]PatternLocation, 0),
			}
			groups[pat] = group
		}

		group.TotalCount++
		loc := PatternLocation{
			File: orig.File,
			Line: orig.Line,
		}
		group.AllLocations = append(group.AllLocations, loc)

		if len(group.SamplePaths) < 5 {
			group.SamplePaths = append(group.SamplePaths, orig.File)
		}

		if f.Verdict == types.VerdictSDKNoiseSuppressed || strings.Contains(orig.File, "androidx/") || strings.Contains(orig.File, "android/support/") {
			group.IsSDKNoise = true
		}
	}

	result := make([]AggregatedPatternFinding, 0, len(groups))
	for _, g := range groups {
		if g.TotalCount >= a.minThreshold {
			result = append(result, *g)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].TotalCount > result[j].TotalCount
	})

	return result
}

func isAggregatablePattern(cat string, patternLower, text string) bool {
	catLower := strings.ToLower(cat)
	if catLower == "piracy" || catLower == "repack" || catLower == "watermark" {
		return true
	}

	piracyKeywords := []string{
		"androeed", "5play", "an1", "repack", "happymod", "moddroid",
		"apkpure", "apkmirror", "lenov", "mobilism", "apkmody", "vmod",
		"luckypatcher", "lucky_patcher", "chelpus", "freedom",
	}

	for _, d := range piracyKeywords {
		if strings.Contains(patternLower, d) || strings.Contains(strings.ToLower(text), d) {
			return true
		}
	}

	return false
}
