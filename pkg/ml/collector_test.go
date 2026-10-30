package ml

import (
	"sync"
	"testing"

	"mega-analyzer/pkg/internal/filter"
)

// ═══════════════════════════════════════════════════════════════════════════════
// COLLECTOR TESTS
// ═══════════════════════════════════════════════════════════════════════════════

func TestNewCollector(t *testing.T) {
	c := NewCollector("test.apk", "com.test.app", "balanced")

	if c.apkName != "test.apk" {
		t.Errorf("apkName = %q, want %q", c.apkName, "test.apk")
	}
	if c.pkg != "com.test.app" {
		t.Errorf("pkg = %q, want %q", c.pkg, "com.test.app")
	}
	if c.profile != "balanced" {
		t.Errorf("profile = %q, want %q", c.profile, "balanced")
	}
	if c.maxTopFiles != 50 {
		t.Errorf("maxTopFiles = %d, want 50", c.maxTopFiles)
	}
	if c.dampeningThresholds.Floor != 0.2 {
		t.Errorf("dampeningThresholds.Floor = %f, want 0.2", c.dampeningThresholds.Floor)
	}
	if c.dampeningThresholds.Ceiling != 1.5 {
		t.Errorf("dampeningThresholds.Ceiling = %f, want 1.5", c.dampeningThresholds.Ceiling)
	}
}

func TestNewCollector_WithOptions(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "aggressive",
		WithDampeningThresholds(0.1, 2.0),
		WithMaxTopFiles(100),
	)

	if c.dampeningThresholds.Floor != 0.1 {
		t.Errorf("dampeningThresholds.Floor = %f, want 0.1", c.dampeningThresholds.Floor)
	}
	if c.dampeningThresholds.Ceiling != 2.0 {
		t.Errorf("dampeningThresholds.Ceiling = %f, want 2.0", c.dampeningThresholds.Ceiling)
	}
	if c.maxTopFiles != 100 {
		t.Errorf("maxTopFiles = %d, want 100", c.maxTopFiles)
	}
}

func TestCollector_SetAPKHash(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")
	c.SetAPKHash("abc123def456")

	if c.apkHash != "abc123def456" {
		t.Errorf("apkHash = %q, want %q", c.apkHash, "abc123def456")
	}
}

func TestCollector_SetTotalFiles(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")
	c.SetTotalFiles(1000)

	if c.totalFiles != 1000 {
		t.Errorf("totalFiles = %d, want 1000", c.totalFiles)
	}
}

func TestCollector_SetCacheStats(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	stats := filter.CacheStats{
		FastPathHits:      500,
		SavedFromFastPath: 50,
	}
	c.SetCacheStats(stats)

	if c.fastPathHits != 500 {
		t.Errorf("fastPathHits = %d, want 500", c.fastPathHits)
	}
	if c.savedFromFP != 50 {
		t.Errorf("savedFromFP = %d, want 50", c.savedFromFP)
	}
}

func TestCollector_RecordClassification_Nil(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	// Не должен паниковать
	c.RecordClassification("path/to/file.smali", nil)

	if c.analyzedFiles != 0 {
		t.Errorf("analyzedFiles should be 0 for nil result")
	}
}

func TestCollector_RecordClassification_Basic(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	result := &filter.ClassificationResult{
		IsAppCode:  true,
		IsLibrary:  false,
		Importance: 5,
		MatchedKeywords: []filter.KeywordMatch{
			{
				Keyword:  "license",
				Bonus:    7,
				Context:  filter.ContextFileName,
				Dampened: false,
			},
		},
		Categories:     []string{"licensing"},
		TotalDampening: 1.0,
	}

	c.RecordClassification("com/app/LicenseManager.smali", result)

	if c.analyzedFiles != 1 {
		t.Errorf("analyzedFiles = %d, want 1", c.analyzedFiles)
	}
	if c.totalMatches != 1 {
		t.Errorf("totalMatches = %d, want 1", c.totalMatches)
	}

	kf := c.keywordStats["license"]
	if kf == nil {
		t.Fatal("license keyword should be recorded")
	}
	if kf.Triggered != 1 {
		t.Errorf("kf.Triggered = %d, want 1", kf.Triggered)
	}
	if kf.InAppCode != 1 {
		t.Errorf("kf.InAppCode = %d, want 1", kf.InAppCode)
	}
	if kf.InFileName != 1 {
		t.Errorf("kf.InFileName = %d, want 1", kf.InFileName)
	}
}

func TestCollector_RecordClassification_Library(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	result := &filter.ClassificationResult{
		IsAppCode:  false,
		IsLibrary:  true,
		Importance: 2,
		MatchedLibrary: &filter.LibraryPattern{
			Pattern:  "com/google/gson/",
			Category: "json",
		},
		MatchedKeywords: []filter.KeywordMatch{
			{
				Keyword:  "serial",
				Bonus:    3,
				Context:  filter.ContextLibraryPath,
				Dampened: true,
			},
		},
		Categories:     []string{"json"},
		TotalDampening: 0.4,
	}

	c.RecordClassification("com/google/gson/Serializer.smali", result)

	// Проверяем library stats
	lf := c.libraryStats["com/google/gson/"]
	if lf == nil {
		t.Fatal("library should be recorded")
	}
	if lf.TotalFiles != 1 {
		t.Errorf("lf.TotalFiles = %d, want 1", lf.TotalFiles)
	}
	if lf.MatchedFiles != 1 {
		t.Errorf("lf.MatchedFiles = %d, want 1", lf.MatchedFiles)
	}
	if lf.Category != "json" {
		t.Errorf("lf.Category = %q, want %q", lf.Category, "json")
	}
	if lf.DampenedMatches != 1 {
		t.Errorf("lf.DampenedMatches = %d, want 1", lf.DampenedMatches)
	}

	// Проверяем keyword в библиотеке
	kf := c.keywordStats["serial"]
	if kf == nil {
		t.Fatal("serial keyword should be recorded")
	}
	if kf.InLibrary != 1 {
		t.Errorf("kf.InLibrary = %d, want 1", kf.InLibrary)
	}
	if kf.Dampened != 1 {
		t.Errorf("kf.Dampened = %d, want 1", kf.Dampened)
	}

	// Проверяем dampening stats
	if c.dampeningAcc.totalDampened != 1 {
		t.Errorf("totalDampened = %d, want 1", c.dampeningAcc.totalDampened)
	}
}

func TestCollector_RecordClassification_Critical(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	result := &filter.ClassificationResult{
		IsAppCode:      true,
		Importance:     9,
		RawImportance:  10,
		Confidence:     0.95,
		TotalDampening: 0.9,
		MatchedKeywords: []filter.KeywordMatch{
			{Keyword: "license", Bonus: 10, Context: filter.ContextFileName},
			{Keyword: "verify", Bonus: 5, Context: filter.ContextFileName},
		},
		MatchedHighValue: []filter.HighValuePattern{
			{Pattern: "license", Weight: 8},
		},
		Categories:        []string{"licensing", "security"},
		RawStrength:       filter.SignalCritical,
		EffectiveStrength: filter.SignalCritical,
	}

	c.RecordClassification("com/app/LicenseVerify.smali", result)

	if c.criticalCount != 1 {
		t.Errorf("criticalCount = %d, want 1", c.criticalCount)
	}

	// 2 keywords + 1 high-value = 3 matches
	if c.totalMatches != 3 {
		t.Errorf("totalMatches = %d, want 3", c.totalMatches)
	}

	// Должен быть в topFiles
	if len(c.topFiles) != 1 {
		t.Errorf("len(topFiles) = %d, want 1", len(c.topFiles))
	}
}

func TestCollector_RecordClassification_Combinators(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	result := &filter.ClassificationResult{
		IsAppCode:  true,
		Importance: 7,
		MatchedKeywords: []filter.KeywordMatch{
			{
				Keyword:     "license",
				Bonus:       8,
				Context:     filter.ContextFileName,
				Combinators: []string{"check", "verify", "manager"},
			},
		},
		Categories:     []string{"licensing"},
		TotalDampening: 1.0,
	}

	c.RecordClassification("com/app/LicenseCheckVerifyManager.smali", result)

	kf := c.keywordStats["license"]
	if kf == nil {
		t.Fatal("license keyword should exist")
	}

	if len(kf.TopCombinators) != 3 {
		t.Errorf("len(TopCombinators) = %d, want 3", len(kf.TopCombinators))
	}

	// Добавляем ещё один файл с теми же combinators
	c.RecordClassification("com/app/LicenseCheck.smali", result)

	// Проверяем что счётчики увеличились
	foundCheck := false
	for _, cs := range kf.TopCombinators {
		if cs.Combinator == "check" && cs.Count == 2 {
			foundCheck = true
			break
		}
	}
	if !foundCheck {
		t.Error("check combinator should have count=2")
	}
}

func TestCollector_RecordClassification_DampeningBoosted(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	result := &filter.ClassificationResult{
		IsAppCode:        true,
		Importance:       8,
		TotalDampening:   1.2, // boosted!
		DampeningSources: []string{"correlation(×1.2)"},
		Categories:       []string{"licensing"},
	}

	c.RecordClassification("com/app/License.smali", result)

	if c.dampeningAcc.totalBoosted != 1 {
		t.Errorf("totalBoosted = %d, want 1", c.dampeningAcc.totalBoosted)
	}

	if c.dampeningAcc.sources["correlation"] != 1 {
		t.Errorf("correlation source count = %d, want 1", c.dampeningAcc.sources["correlation"])
	}
}

func TestCollector_RecordClassification_DampeningFloorCeiling(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced",
		WithDampeningThresholds(0.2, 1.5),
	)

	// Floor hit
	result1 := &filter.ClassificationResult{
		IsAppCode:      true,
		Importance:     3,
		TotalDampening: 0.2, // exactly at floor
		Categories:     []string{"test"},
	}
	c.RecordClassification("file1.smali", result1)

	// Ceiling hit
	result2 := &filter.ClassificationResult{
		IsAppCode:      true,
		Importance:     8,
		TotalDampening: 1.5, // exactly at ceiling
		Categories:     []string{"test"},
	}
	c.RecordClassification("file2.smali", result2)

	if c.dampeningAcc.floorHits != 1 {
		t.Errorf("floorHits = %d, want 1", c.dampeningAcc.floorHits)
	}
	if c.dampeningAcc.ceilingHits != 1 {
		t.Errorf("ceilingHits = %d, want 1", c.dampeningAcc.ceilingHits)
	}
}

func TestCollector_RecordClassification_HighValue(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	result := &filter.ClassificationResult{
		IsAppCode:  false,
		IsLibrary:  true,
		Importance: 5,
		MatchedLibrary: &filter.LibraryPattern{
			Pattern:  "com/billing/",
			Category: "billing",
		},
		MatchedHighValue: []filter.HighValuePattern{
			{Pattern: "purchase", Weight: 8},
			{Pattern: "billing", Weight: 7},
		},
		Categories:     []string{"billing"},
		TotalDampening: 0.5,
	}

	c.RecordClassification("com/billing/Purchase.smali", result)

	lf := c.libraryStats["com/billing/"]
	if lf == nil {
		t.Fatal("library should exist")
	}
	if lf.HighValueFiles != 1 {
		t.Errorf("HighValueFiles = %d, want 1", lf.HighValueFiles)
	}

	// Файл должен быть в topFiles (high-value)
	if len(c.topFiles) != 1 {
		t.Errorf("len(topFiles) = %d, want 1", len(c.topFiles))
	}
	if len(c.topFiles[0].MatchedHighValue) != 2 {
		t.Errorf("MatchedHighValue count = %d, want 2", len(c.topFiles[0].MatchedHighValue))
	}
}

func TestCollector_Finalize(t *testing.T) {
	c := NewCollector("test.apk", "com.test.app", "balanced")
	c.SetAPKHash("hash123")
	c.SetTotalFiles(100)
	c.SetCacheStats(filter.CacheStats{FastPathHits: 50, SavedFromFastPath: 5})

	// Записываем несколько файлов
	for i := 0; i < 10; i++ {
		result := &filter.ClassificationResult{
			IsAppCode:  true,
			Importance: 5 + i%5,
			MatchedKeywords: []filter.KeywordMatch{
				{Keyword: "license", Bonus: 5},
			},
			Categories:     []string{"licensing"},
			TotalDampening: 0.8,
		}
		c.RecordClassification("file"+string(rune('0'+i))+".smali", result)
	}

	fb := c.Finalize()

	if fb.ID == "" {
		t.Error("ID should not be empty")
	}
	if fb.APKHash != "hash123" {
		t.Errorf("APKHash = %q, want %q", fb.APKHash, "hash123")
	}
	if fb.APKName != "test.apk" {
		t.Errorf("APKName = %q, want %q", fb.APKName, "test.apk")
	}
	if fb.Package != "com.test.app" {
		t.Errorf("Package = %q, want %q", fb.Package, "com.test.app")
	}
	if fb.Profile != "balanced" {
		t.Errorf("Profile = %q, want %q", fb.Profile, "balanced")
	}
	if fb.TotalFiles != 100 {
		t.Errorf("TotalFiles = %d, want 100", fb.TotalFiles)
	}
	if fb.AnalyzedFiles != 10 {
		t.Errorf("AnalyzedFiles = %d, want 10", fb.AnalyzedFiles)
	}
	if fb.FastPathHits != 50 {
		t.Errorf("FastPathHits = %d, want 50", fb.FastPathHits)
	}
	if fb.SavedFromFP != 5 {
		t.Errorf("SavedFromFP = %d, want 5", fb.SavedFromFP)
	}

	// Проверяем keyword stats
	if fb.KeywordStats["license"] == nil {
		t.Error("license keyword should exist in feedback")
	}

	// Проверяем dampening stats
	if fb.DampeningStats == nil {
		t.Fatal("DampeningStats should not be nil")
	}
	if fb.DampeningStats.TotalDampened != 10 {
		t.Errorf("TotalDampened = %d, want 10", fb.DampeningStats.TotalDampened)
	}
}

func TestCollector_Finalize_TopFilesSorted(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced",
		WithMaxTopFiles(3),
	)

	// Записываем файлы с разным importance
	importances := []int{3, 9, 5, 7, 4, 8}
	for i, imp := range importances {
		result := &filter.ClassificationResult{
			IsAppCode:      true,
			Importance:     imp,
			RawImportance:  imp + 1,
			Categories:     []string{"test"},
			TotalDampening: 1.0,
		}
		c.RecordClassification("file"+string(rune('A'+i))+".smali", result)
	}

	fb := c.Finalize()

	// Должны быть только 3 файла (maxTopFiles=3)
	if len(fb.TopFiles) != 3 {
		t.Fatalf("len(TopFiles) = %d, want 3", len(fb.TopFiles))
	}

	// Должны быть отсортированы по importance DESC
	expectedImportances := []int{9, 8, 7}
	for i, exp := range expectedImportances {
		if fb.TopFiles[i].Importance != exp {
			t.Errorf("TopFiles[%d].Importance = %d, want %d", i, fb.TopFiles[i].Importance, exp)
		}
	}
}

func TestCollector_Finalize_CombinatorsSorted(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	// Создаём много combinators
	combinators := []string{"check", "verify", "manager", "helper", "util", "service", "handler"}

	for i := 0; i < 10; i++ {
		result := &filter.ClassificationResult{
			IsAppCode:  true,
			Importance: 5,
			MatchedKeywords: []filter.KeywordMatch{
				{
					Keyword:     "license",
					Bonus:       5,
					Combinators: combinators[:i%len(combinators)+1], // разное количество
				},
			},
			Categories:     []string{"licensing"},
			TotalDampening: 1.0,
		}
		c.RecordClassification("file.smali", result)
	}

	fb := c.Finalize()

	kf := fb.KeywordStats["license"]
	if kf == nil {
		t.Fatal("license keyword should exist")
	}

	// Должно быть максимум 5 combinators
	if len(kf.TopCombinators) > 5 {
		t.Errorf("len(TopCombinators) = %d, want <= 5", len(kf.TopCombinators))
	}

	// Должны быть отсортированы по count DESC
	for i := 1; i < len(kf.TopCombinators); i++ {
		if kf.TopCombinators[i].Count > kf.TopCombinators[i-1].Count {
			t.Errorf("TopCombinators not sorted: [%d].Count=%d > [%d].Count=%d",
				i, kf.TopCombinators[i].Count, i-1, kf.TopCombinators[i-1].Count)
		}
	}
}

func TestCollector_Finalize_AvgDampening(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	dampenings := []float64{0.4, 0.5, 0.6}
	for i, d := range dampenings {
		result := &filter.ClassificationResult{
			IsAppCode:      true,
			Importance:     5,
			TotalDampening: d,
			Categories:     []string{"test"},
		}
		c.RecordClassification("file"+string(rune('0'+i))+".smali", result)
	}

	fb := c.Finalize()

	// Avg = (0.4 + 0.5 + 0.6) / 3 = 0.5
	expectedAvg := 0.5
	if fb.DampeningStats.AvgDampening != expectedAvg {
		t.Errorf("AvgDampening = %f, want %f", fb.DampeningStats.AvgDampening, expectedAvg)
	}
}

func TestCollector_ThreadSafety(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	var wg sync.WaitGroup

	// Параллельная запись
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			result := &filter.ClassificationResult{
				IsAppCode:  true,
				Importance: n % 10,
				MatchedKeywords: []filter.KeywordMatch{
					{Keyword: "license", Bonus: 5},
				},
				Categories:     []string{"test"},
				TotalDampening: 0.5,
			}
			c.RecordClassification("file.smali", result)
		}(i)
	}

	// Параллельные SetXXX
	for i := 0; i < 10; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			c.SetTotalFiles(1000)
		}()
		go func() {
			defer wg.Done()
			c.SetAPKHash("hash")
		}()
		go func() {
			defer wg.Done()
			c.SetCacheStats(filter.CacheStats{FastPathHits: 100})
		}()
	}

	wg.Wait()

	// Finalize должен работать
	fb := c.Finalize()
	if fb == nil {
		t.Error("Finalize should return non-nil")
	}
	if c.analyzedFiles != 100 {
		t.Errorf("analyzedFiles = %d, want 100", c.analyzedFiles)
	}
}

func TestCollector_CategoryStats(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	result := &filter.ClassificationResult{
		IsAppCode:  true,
		Importance: 9,
		MatchedKeywords: []filter.KeywordMatch{
			{Keyword: "license"},
			{Keyword: "verify"},
		},
		MatchedHighValue: []filter.HighValuePattern{
			{Pattern: "license"},
		},
		Categories:     []string{"licensing", "security"},
		TotalDampening: 1.0,
	}

	c.RecordClassification("file.smali", result)

	fb := c.Finalize()

	licensing := fb.CategoryStats["licensing"]
	if licensing == nil {
		t.Fatal("licensing category should exist")
	}
	if licensing.Files != 1 {
		t.Errorf("licensing.Files = %d, want 1", licensing.Files)
	}
	if licensing.Matches != 3 { // 2 keywords + 1 high-value
		t.Errorf("licensing.Matches = %d, want 3", licensing.Matches)
	}
	if licensing.Critical != 1 { // importance >= 8
		t.Errorf("licensing.Critical = %d, want 1", licensing.Critical)
	}

	security := fb.CategoryStats["security"]
	if security == nil {
		t.Fatal("security category should exist")
	}
}

func TestCollector_TopFilesThreshold(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	// Importance < 3 и нет high-value — НЕ должен попасть в topFiles
	lowResult := &filter.ClassificationResult{
		IsAppCode:      true,
		Importance:     2,
		Categories:     []string{"test"},
		TotalDampening: 1.0,
	}
	c.RecordClassification("low.smali", lowResult)

	// Importance >= 3 — должен попасть
	midResult := &filter.ClassificationResult{
		IsAppCode:      true,
		Importance:     3,
		Categories:     []string{"test"},
		TotalDampening: 1.0,
	}
	c.RecordClassification("mid.smali", midResult)

	// Importance < 3, но есть high-value — должен попасть
	hvResult := &filter.ClassificationResult{
		IsAppCode:  true,
		Importance: 2,
		MatchedHighValue: []filter.HighValuePattern{
			{Pattern: "license"},
		},
		Categories:     []string{"test"},
		TotalDampening: 1.0,
	}
	c.RecordClassification("hv.smali", hvResult)

	fb := c.Finalize()

	if len(fb.TopFiles) != 2 {
		t.Errorf("len(TopFiles) = %d, want 2", len(fb.TopFiles))
	}
}

func TestCollector_KeywordContexts(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	contexts := []filter.KeywordContext{
		filter.ContextFileName,
		filter.ContextPackagePath,
		filter.ContextLibraryPath,
		filter.ContextUnknown,
	}

	for _, ctx := range contexts {
		result := &filter.ClassificationResult{
			IsAppCode:  true,
			Importance: 5,
			MatchedKeywords: []filter.KeywordMatch{
				{Keyword: "license", Context: ctx},
			},
			Categories:     []string{"test"},
			TotalDampening: 1.0,
		}
		c.RecordClassification("file.smali", result)
	}

	fb := c.Finalize()

	kf := fb.KeywordStats["license"]
	if kf == nil {
		t.Fatal("license keyword should exist")
	}

	// Проверяем что все контексты записаны
	expectedContexts := map[string]int{
		"FileName":    1,
		"PackagePath": 1,
		"LibraryPath": 1,
		"Unknown":     1,
	}

	for ctx, count := range expectedContexts {
		if kf.Contexts[ctx] != count {
			t.Errorf("Contexts[%q] = %d, want %d", ctx, kf.Contexts[ctx], count)
		}
	}
}

func TestCollector_LibraryKeywords(t *testing.T) {
	c := NewCollector("test.apk", "com.test", "balanced")

	result := &filter.ClassificationResult{
		IsAppCode:  false,
		IsLibrary:  true,
		Importance: 3,
		MatchedLibrary: &filter.LibraryPattern{
			Pattern:  "com/google/gson/",
			Category: "json",
		},
		MatchedKeywords: []filter.KeywordMatch{
			{Keyword: "serial", Dampened: true},
			{Keyword: "convert", Dampened: false},
			{Keyword: "serial", Dampened: true}, // дубликат
		},
		Categories:     []string{"json"},
		TotalDampening: 0.4,
	}

	c.RecordClassification("com/google/gson/Serializer.smali", result)

	fb := c.Finalize()

	lf := fb.LibraryStats["com/google/gson/"]
	if lf == nil {
		t.Fatal("library should exist")
	}

	// 2 разных keyword
	if lf.Keywords["serial"] != 2 {
		t.Errorf("Keywords[serial] = %d, want 2", lf.Keywords["serial"])
	}
	if lf.Keywords["convert"] != 1 {
		t.Errorf("Keywords[convert] = %d, want 1", lf.Keywords["convert"])
	}

	// 2 dampened
	if lf.DampenedMatches != 2 {
		t.Errorf("DampenedMatches = %d, want 2", lf.DampenedMatches)
	}
}
