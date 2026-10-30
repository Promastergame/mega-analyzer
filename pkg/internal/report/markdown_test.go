package report

import (
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/types"
)

func TestBuildMarkdown_EmptyResult(t *testing.T) {
	result := &types.AnalysisResult{
		Timestamp: time.Now(),
		Duration:  types.Duration(time.Second * 5),
		TargetDir: "/test/app",
		Stats: types.AnalysisStats{
			TotalFiles:    0,
			AnalyzedFiles: 0,
		},
	}

	md := BuildMarkdown(result, DefaultOptions())

	// Должны быть секции
	if !strings.Contains(md, "# 🔥 APK LICENSE ANALYSIS REPORT") {
		t.Error("Missing header")
	}
	if !strings.Contains(md, "## 📌 Quick Summary") {
		t.Error("Missing quick summary")
	}
	if !strings.Contains(md, "*No hotspots detected.*") {
		t.Error("Should show no hotspots message")
	}
}

func TestBuildMarkdown_SingleHotspot(t *testing.T) {
	result := &types.AnalysisResult{
		Timestamp: time.Now(),
		Duration:  types.Duration(time.Second * 10),
		TargetDir: "/test/app",
		Stats: types.AnalysisStats{
			TotalFiles:    100,
			AnalyzedFiles: 50,
			TotalMatches:  5,
		},
		Hotspots: []types.Hotspot{
			{
				Path:          "smali/com/example/License.smali",
				Score:         45.5,
				MatchCount:    1,
				CriticalCount: 1,
				Categories:    []types.Category{types.CategoryLicenseCheck},
				Reasons:       []string{"License check", "Boolean return"},
			},
		},
		MatchesByCategory: map[types.Category]int{
			types.CategoryLicenseCheck: 5,
		},
		FilesByType: map[types.FileType]int{
			types.FileTypeSmali: 50,
		},
	}

	md := BuildMarkdown(result, DefaultOptions())

	// Hotspot должен быть в таблице
	if !strings.Contains(md, "License.smali") {
		t.Error("Hotspot file not found")
	}
	if !strings.Contains(md, "45.5") {
		t.Error("Score not found")
	}
}

func TestBuildMarkdown_StableOrder(t *testing.T) {
	result := &types.AnalysisResult{
		Timestamp: time.Now(),
		MatchesByCategory: map[types.Category]int{
			types.CategoryLicenseCheck:   10,
			types.CategoryBillingClient:  5,
			types.CategoryIntegrityCheck: 3,
		},
		FilesByType: map[types.FileType]int{
			types.FileTypeSmali: 100,
			types.FileTypeXML:   50,
		},
	}

	// Генерируем 10 раз
	var outputs []string
	for i := 0; i < 10; i++ {
		outputs = append(outputs, BuildMarkdown(result, DefaultOptions()))
	}

	// Все должны быть идентичны
	for i := 1; i < len(outputs); i++ {
		if outputs[i] != outputs[0] {
			t.Error("Output is not deterministic!")
		}
	}
}

func TestBuildMarkdown_LongPaths(t *testing.T) {
	longPath := "smali/com/very/long/package/name/that/exceeds/normal/limits/SomeClass.smali"

	result := &types.AnalysisResult{
		Timestamp: time.Now(),
		Hotspots: []types.Hotspot{
			{
				Path:  longPath,
				Score: 30,
			},
		},
	}

	opts := DefaultOptions()
	opts.MaxPathLen = 40

	md := BuildMarkdown(result, opts)

	// Полный путь НЕ должен быть в таблице
	if strings.Contains(md, longPath) && strings.Contains(md, "| `"+longPath+"`") {
		t.Error("Long path should be truncated in table")
	}
	// Но обрезанный должен
	if !strings.Contains(md, "...") {
		t.Error("Should contain truncated path with ...")
	}
}

func TestBuildMarkdown_Unicode(t *testing.T) {
	result := &types.AnalysisResult{
		Timestamp: time.Now(),
		Hotspots: []types.Hotspot{
			{
				Path:    "smali/com/example/Тест.smali",
				Score:   25,
				Reasons: []string{"Проверка лицензии", "中文测试"},
			},
		},
	}

	// Не должно паниковать
	md := BuildMarkdown(result, DefaultOptions())

	if !strings.Contains(md, "Тест.smali") {
		t.Error("Unicode path should be preserved")
	}
}

func TestBuildMarkdown_ManyHotspots(t *testing.T) {
	var hotspots []types.Hotspot
	for i := 0; i < 100; i++ {
		hotspots = append(hotspots, types.Hotspot{
			Path:  "smali/test/File" + string(rune('A'+i%26)) + ".smali",
			Score: float64(100 - i),
		})
	}

	result := &types.AnalysisResult{
		Timestamp: time.Now(),
		Hotspots:  hotspots,
	}

	opts := DefaultOptions()
	opts.MaxHotspots = 20

	md := BuildMarkdown(result, opts)

	// Должно быть ровно 20 строк в таблице hotspots
	lines := strings.Split(md, "\n")
	hotspotTableLines := 0
	inTable := false

	for _, line := range lines {
		if strings.HasPrefix(line, "| # | Score") {
			inTable = true
			continue
		}
		if inTable && strings.HasPrefix(line, "| ") {
			hotspotTableLines++
		}
		if inTable && !strings.HasPrefix(line, "|") {
			break
		}
	}

	if hotspotTableLines != 20 {
		t.Errorf("Expected 20 hotspot rows, got %d", hotspotTableLines)
	}
}

func TestShortReportOptions(t *testing.T) {
	opts := ShortReportOptions()

	if opts.MaxHotspots != 10 {
		t.Errorf("Short report should have 10 hotspots, got %d", opts.MaxHotspots)
	}
	if opts.ShowMethods {
		t.Error("Short report should not show methods")
	}
}

func TestBuildView_ReturnsStructuredData(t *testing.T) {
	result := &types.AnalysisResult{
		Timestamp: time.Now(),
		Hotspots: []types.Hotspot{
			{Path: "test.smali", Score: 50},
		},
	}

	reporter := NewMarkdownReporter(result)
	view := reporter.BuildView()

	if len(view.Hotspots) != 1 {
		t.Error("View should contain 1 hotspot")
	}
	if view.Hotspots[0].Score != 50 {
		t.Error("Score mismatch")
	}
}
