package ml

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// 🆕 Атомарный счётчик для уникальных путей между итерациями
var testCounter atomic.Int64

func tempHistoryPath(t *testing.T) string {
	t.Helper()
	dir := testTempDir(t)

	// 🆕 Уникальный подкаталог для каждого вызова
	uniqueID := testCounter.Add(1)
	subdir := filepath.Join(dir, fmt.Sprintf("run_%d", uniqueID))

	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	// 🆕 Своё подчистение с повторными попытками, чтобы избежать редких ENOTEMPTY на Windows
	t.Cleanup(func() {
		retryRemoveAll(t, subdir, "tempHistoryPath")
	})

	return filepath.Join(subdir, "test_history.json")
}

// 🆕 Удаление с коротким ретраем — помогает при ленивом освобождении дескрипторов на Windows.
func retryRemoveAll(t *testing.T, dir, label string) {
	deadline := time.Now().Add(300 * time.Millisecond)
	for {
		err := os.RemoveAll(dir)
		if err == nil || os.IsNotExist(err) {
			return
		}

		if time.Now().After(deadline) {
			t.Logf("%s cleanup: %v", label, err)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func makeFeedback(name string, triggered int, noiseRatio float64) *AnalysisFeedback {
	inLibrary := int(float64(triggered) * noiseRatio)

	return &AnalysisFeedback{
		ID:            GenerateFeedbackID(name, time.Now()),
		APKName:       name,
		Package:       "com.test." + name,
		Timestamp:     time.Now(),
		Profile:       "balanced",
		TotalFiles:    100,
		AnalyzedFiles: 80,
		TotalMatches:  triggered,
		CriticalCount: 5,
		KeywordStats: map[string]*KeywordFeedback{
			"crypto": {
				Keyword:       "crypto",
				Triggered:     triggered,
				InLibrary:     inLibrary,
				InAppCode:     triggered - inLibrary,
				Dampened:      0,
				SumImportance: float64(triggered) * 3.0,
			},
		},
		LibraryStats: map[string]*LibraryFeedback{
			"com/google/ads/": {
				Prefix:          "com/google/ads/",
				TotalFiles:      20,
				MatchedFiles:    5,
				DampenedMatches: 5,
				HighValueFiles:  0,
				SumImportance:   10,
				Category:        "ads",
				Keywords:        map[string]int{"ad": 5},
			},
		},
		CategoryStats: map[string]*CategoryFeedback{
			"crypto": {Category: "crypto", Files: 10, Matches: triggered, Critical: 2},
		},
		TopFiles: []FileFeedback{
			{
				Path:            "com/app/Crypto.smali",
				Importance:      7,
				MatchedKeywords: []string{"crypto", "encrypt"},
				Categories:      []string{"crypto"},
			},
		},
	}
}

func makeFeedbackWithKeywords(name string, keywords map[string]int) *AnalysisFeedback {
	fb := makeFeedback(name, 10, 0.5)
	fb.KeywordStats = make(map[string]*KeywordFeedback)

	for kw, count := range keywords {
		fb.KeywordStats[kw] = &KeywordFeedback{
			Keyword:       kw,
			Triggered:     count,
			InLibrary:     count / 2,
			InAppCode:     count / 2,
			SumImportance: float64(count) * 2.0,
		}
	}
	return fb
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOAD / SAVE
// ═══════════════════════════════════════════════════════════════════════════════

func TestLoadHistory_NotExists(t *testing.T) {
	path := tempHistoryPath(t)

	h, err := LoadHistory(path)
	if err != nil {
		t.Fatal(err)
	}

	if h.Len() != 0 {
		t.Errorf("new history should be empty, got %d", h.Len())
	}
}

func TestLoadHistory_Exists(t *testing.T) {
	path := tempHistoryPath(t)

	// Записываем данные
	records := []*AnalysisFeedback{
		makeFeedback("test1", 10, 0.5),
		makeFeedback("test2", 20, 0.3),
	}

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	h, err := LoadHistory(path)
	if err != nil {
		t.Fatal(err)
	}

	if h.Len() != 2 {
		t.Errorf("expected 2 records, got %d", h.Len())
	}
}

func TestLoadHistory_Corrupt(t *testing.T) {
	path := tempHistoryPath(t)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not json!!!"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadHistory(path)
	if err == nil {
		t.Error("corrupt file should return error")
	}
}

func TestSave_CreatesDir(t *testing.T) {
	dir := testTempDir(t)
	uniqueID := testCounter.Add(1)
	path := filepath.Join(dir, fmt.Sprintf("subdir_%d", uniqueID), "nested", "history.json")
	t.Cleanup(func() {
		retryRemoveAll(t, filepath.Join(dir, fmt.Sprintf("subdir_%d", uniqueID)), "TestSave_CreatesDir")
	})

	h, _ := LoadHistory(path)
	h.Append(makeFeedback("test", 10, 0.5))

	if err := h.Save(); err != nil {
		t.Fatal(err)
	}

	// Проверяем что файл создан
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file should exist: %v", err)
	}
}

func TestSave_DirtyFlag(t *testing.T) {
	path := tempHistoryPath(t)

	h, _ := LoadHistory(path)

	// Без изменений — не должен писать
	if err := h.Save(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("no changes = no file should be created")
	}

	// С изменениями — должен записать
	h.Append(makeFeedback("test", 10, 0.5))

	if err := h.Save(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Error("after append, file should exist")
	}

	// Повторный save без изменений — не должен перезаписывать
	info1, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)

	if err := h.Save(); err != nil {
		t.Fatal(err)
	}

	info2, _ := os.Stat(path)
	if info1.ModTime() != info2.ModTime() {
		t.Error("save without changes should not modify file")
	}
}

func TestSave_Roundtrip(t *testing.T) {
	path := tempHistoryPath(t)

	// Save
	h1, _ := LoadHistory(path)
	fb := makeFeedback("roundtrip", 42, 0.7)
	h1.Append(fb)

	if err := h1.Save(); err != nil {
		t.Fatal(err)
	}

	// Load
	h2, err := LoadHistory(path)
	if err != nil {
		t.Fatal(err)
	}

	if h2.Len() != 1 {
		t.Fatalf("expected 1 record, got %d", h2.Len())
	}

	loaded := h2.Last()
	if loaded.APKName != "roundtrip" {
		t.Errorf("APKName = %q, want %q", loaded.APKName, "roundtrip")
	}
	if loaded.TotalMatches != 42 {
		t.Errorf("TotalMatches = %d, want 42", loaded.TotalMatches)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MUTATIONS
// ═══════════════════════════════════════════════════════════════════════════════

func TestAppend(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	h.Append(makeFeedback("app1", 10, 0.5))
	h.Append(makeFeedback("app2", 20, 0.3))

	if h.Len() != 2 {
		t.Errorf("expected 2 records, got %d", h.Len())
	}
}

func TestAppend_MaxItems(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)
	h.maxItems = 5

	for i := 0; i < 10; i++ {
		h.Append(makeFeedback("app", i, 0.5))
	}

	if h.Len() != 5 {
		t.Errorf("should cap at maxItems=5, got %d", h.Len())
	}

	// Проверяем что оставлены последние
	last := h.Last()
	if last.TotalMatches != 9 {
		t.Errorf("last should be #9, got %d", last.TotalMatches)
	}
}

func TestAddUserOverride(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	h.Append(makeFeedback("test", 10, 0.5))

	err := h.AddUserOverride(UserOverride{
		Path:    "com/app/Crypto.smali",
		Action:  "relevant",
		Keyword: "crypto",
	})

	if err != nil {
		t.Fatal(err)
	}

	last := h.Last()
	if len(last.UserOverrides) != 1 {
		t.Fatalf("expected 1 override, got %d", len(last.UserOverrides))
	}

	if last.UserOverrides[0].Action != "relevant" {
		t.Errorf("action = %q, want %q", last.UserOverrides[0].Action, "relevant")
	}

	// Keyword feedback should be updated
	kf := last.KeywordStats["crypto"]
	if kf == nil {
		t.Fatal("crypto keyword stats should exist")
	}
	if kf.MarkedRelevant != 1 {
		t.Errorf("MarkedRelevant = %d, want 1", kf.MarkedRelevant)
	}
}

func TestAddUserOverride_Noise(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	h.Append(makeFeedback("test", 10, 0.5))

	err := h.AddUserOverride(UserOverride{
		Action:  "noise",
		Keyword: "crypto",
	})

	if err != nil {
		t.Fatal(err)
	}

	kf := h.Last().KeywordStats["crypto"]
	if kf.MarkedNoise != 1 {
		t.Errorf("MarkedNoise = %d, want 1", kf.MarkedNoise)
	}
}

func TestAddUserOverride_NoRecords(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	// Should NOT fail - it creates a placeholder record when empty
	err := h.AddUserOverride(UserOverride{Path: "test-pattern", Action: "relevant"})
	if err != nil {
		t.Errorf("should NOT fail with no records: %v", err)
	}
	if h.Last() == nil || len(h.Last().UserOverrides) != 1 {
		t.Fatal("placeholder should persist the first feedback decision")
	}
}

func TestAddUserOverrideRejectsEmptyTarget(t *testing.T) {
	h, _ := LoadHistory(tempHistoryPath(t))
	if err := h.AddUserOverride(UserOverride{Action: FeedbackRelevant}); err == nil {
		t.Fatal("empty feedback target must be rejected")
	}
}

func TestAddUserOverrideIsIdempotentAndAllowsCorrection(t *testing.T) {
	h, _ := LoadHistory(tempHistoryPath(t))
	h.Append(makeFeedback("test", 10, 0.5))

	first := UserOverride{Keyword: "crypto", Action: FeedbackNoise}
	if err := h.AddUserOverride(first); err != nil {
		t.Fatal(err)
	}
	if err := h.AddUserOverride(first); err != nil {
		t.Fatal(err)
	}
	if got := len(h.Last().UserOverrides); got != 1 {
		t.Fatalf("duplicate decision should be a no-op, got %d events", got)
	}
	if err := h.AddUserOverride(UserOverride{Keyword: "CRYPTO", Action: FeedbackRelevant}); err != nil {
		t.Fatal(err)
	}
	active := ResolveUserOverrides(h.Snapshot())
	if len(active) != 1 || active[0].Action != FeedbackRelevant {
		t.Fatalf("correction should replace active label, got %+v", active)
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUERIES
// ═══════════════════════════════════════════════════════════════════════════════

func TestLast_Empty(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	if h.Last() != nil {
		t.Error("Last() on empty should return nil")
	}
}

func TestLast_WithRecords(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	h.Append(makeFeedback("first", 1, 0.5))
	h.Append(makeFeedback("second", 2, 0.5))

	last := h.Last()
	if last.APKName != "second" {
		t.Errorf("Last() = %q, want %q", last.APKName, "second")
	}
}

func TestLastN(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	for i := 0; i < 5; i++ {
		h.Append(makeFeedback("app", i, 0.5))
	}

	records := h.LastN(3)
	if len(records) != 3 {
		t.Errorf("LastN(3) returned %d records", len(records))
	}

	// Должны быть последние 3
	if records[0].TotalMatches != 2 {
		t.Errorf("first of LastN(3) should be #2, got %d", records[0].TotalMatches)
	}
}

func TestLastN_MoreThanAvailable(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	h.Append(makeFeedback("only", 1, 0.5))

	records := h.LastN(100)
	if len(records) != 1 {
		t.Errorf("LastN(100) with 1 record should return 1, got %d", len(records))
	}
}

func TestLastN_Zero(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	h.Append(makeFeedback("test", 1, 0.5))

	records := h.LastN(0)
	if len(records) != 0 {
		t.Errorf("LastN(0) should return 0 records, got %d", len(records))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// SNAPSHOT
// ═══════════════════════════════════════════════════════════════════════════════

func TestSnapshot(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	h.Append(makeFeedback("app1", 10, 0.5))
	h.Append(makeFeedback("app2", 20, 0.3))

	snap := h.Snapshot()

	if len(snap) != 2 {
		t.Errorf("snapshot should have 2 records, got %d", len(snap))
	}

	// Мутация snapshot не должна влиять на history
	snap[0] = nil

	if h.Last() == nil {
		t.Error("mutating snapshot should not affect history")
	}
}

func TestSnapshot_ThreadSafe(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	// Заполняем
	for i := 0; i < 10; i++ {
		h.Append(makeFeedback("app", i, 0.5))
	}

	var wg sync.WaitGroup
	errors := make(chan error, 100)

	// Параллельные Snapshot + Append
	for i := 0; i < 50; i++ {
		wg.Add(2)

		go func(n int) {
			defer wg.Done()
			snap := h.Snapshot()
			if snap == nil {
				errors <- nil // первые вызовы могут получить пустой
			}
		}(i)

		go func(n int) {
			defer wg.Done()
			h.Append(makeFeedback("concurrent", n, 0.5))
		}(i)
	}

	wg.Wait()
	close(errors)

	// Не должно быть паник
	for err := range errors {
		if err != nil {
			t.Errorf("concurrent error: %v", err)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// AGGREGATION
// ═══════════════════════════════════════════════════════════════════════════════

func TestAggregateKeywordStats(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	h.Append(makeFeedbackWithKeywords("app1", map[string]int{
		"crypto":  20,
		"license": 10,
	}))
	h.Append(makeFeedbackWithKeywords("app2", map[string]int{
		"crypto":  30,
		"network": 15,
	}))

	stats := h.AggregateKeywordStats()

	// crypto: 20+30 = 50
	crypto := stats["crypto"]
	if crypto == nil {
		t.Fatal("crypto should exist in stats")
	}
	if crypto.TotalTriggered != 50 {
		t.Errorf("crypto.TotalTriggered = %d, want 50", crypto.TotalTriggered)
	}
	if crypto.SeenInAPKs != 2 {
		t.Errorf("crypto.SeenInAPKs = %d, want 2", crypto.SeenInAPKs)
	}

	// license: 10 (only in app1)
	license := stats["license"]
	if license == nil {
		t.Fatal("license should exist")
	}
	if license.SeenInAPKs != 1 {
		t.Errorf("license.SeenInAPKs = %d, want 1", license.SeenInAPKs)
	}

	// network: 15 (only in app2)
	if stats["network"] == nil {
		t.Error("network should exist")
	}
}

func TestAggregateKeywordStats_NoiseRatio(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	fb := makeFeedback("test", 10, 0.5)
	fb.KeywordStats["noisy"] = &KeywordFeedback{
		Keyword:   "noisy",
		Triggered: 100,
		InLibrary: 80,
		Dampened:  10,
	}
	h.Append(fb)

	stats := h.AggregateKeywordStats()

	noisy := stats["noisy"]
	if noisy == nil {
		t.Fatal("noisy should exist")
	}

	// NoiseRatio = (80+10)/100 = 0.9
	if noisy.NoiseRatio != 0.9 {
		t.Errorf("NoiseRatio = %f, want 0.9", noisy.NoiseRatio)
	}
}

func TestAggregateKeywordStats_Precision(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	fb := makeFeedback("test", 10, 0.5)
	fb.KeywordStats["tested"] = &KeywordFeedback{
		Keyword:        "tested",
		Triggered:      20,
		MarkedRelevant: 8,
		MarkedNoise:    2,
	}
	h.Append(fb)

	stats := h.AggregateKeywordStats()
	tested := stats["tested"]

	// Precision = 8 / (8+2) = 0.8
	if tested.Precision != 0.8 {
		t.Errorf("Precision = %f, want 0.8", tested.Precision)
	}
}

func TestAggregateLibraryStats(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	h.Append(makeFeedback("app1", 10, 0.5))
	h.Append(makeFeedback("app2", 20, 0.3))

	stats := h.AggregateLibraryStats()

	// "com/google/ads/" присутствует в обоих
	ads := stats["com/google/ads/"]
	if ads == nil {
		t.Fatal("ads library should exist")
	}

	if ads.SeenInAPKs != 2 {
		t.Errorf("SeenInAPKs = %d, want 2", ads.SeenInAPKs)
	}

	// TotalFiles = 20 + 20 = 40
	if ads.TotalFiles != 40 {
		t.Errorf("TotalFiles = %d, want 40", ads.TotalFiles)
	}
}

func TestTopNoisyKeywords(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	fb := makeFeedback("test", 10, 0.5)
	fb.KeywordStats = map[string]*KeywordFeedback{
		"very_noisy": {Keyword: "very_noisy", Triggered: 100, InLibrary: 95},
		"medium":     {Keyword: "medium", Triggered: 50, InLibrary: 25},
		"clean":      {Keyword: "clean", Triggered: 30, InLibrary: 1},
		"too_few":    {Keyword: "too_few", Triggered: 3, InLibrary: 3}, // <5 = filtered
	}
	h.Append(fb)

	noisy := h.TopNoisyKeywords(2)

	if len(noisy) != 2 {
		t.Fatalf("expected 2 results, got %d", len(noisy))
	}

	if noisy[0].Keyword != "very_noisy" {
		t.Errorf("first should be very_noisy, got %q", noisy[0].Keyword)
	}
}

func TestAlwaysNoiseLibraries(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	// Library that's always noise across 3 APKs
	for i := 0; i < 3; i++ {
		fb := makeFeedback("app", i, 0.5)
		fb.LibraryStats = map[string]*LibraryFeedback{
			"com/noise/lib/": {
				Prefix:          "com/noise/lib/",
				TotalFiles:      10,
				MatchedFiles:    5,
				DampenedMatches: 5,
				HighValueFiles:  0, // always noise
				Category:        "ads",
			},
		}
		h.Append(fb)
	}

	result := h.AlwaysNoiseLibraries(2) // minAPKs=2

	if len(result) != 1 {
		t.Fatalf("expected 1 always-noise library, got %d", len(result))
	}

	if result[0].Prefix != "com/noise/lib/" {
		t.Errorf("prefix = %q, want %q", result[0].Prefix, "com/noise/lib/")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// NORMALIZE LIBRARY PREFIX
// ═══════════════════════════════════════════════════════════════════════════════

func TestNormalizeLibraryPrefix(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"com/google/ads", "com/google/ads/"},
		{"com/google/ads/", "com/google/ads/"},
		{"COM/Google/Ads/", "com/google/ads/"},
		{"smali/com/google/ads/", "com/google/ads/"},
		{" com/google/ads ", "com/google/ads/"},
		{"com\\google\\ads", "com/google/ads/"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeLibraryPrefix(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeLibraryPrefix(%q) = %q, want %q",
					tt.input, got, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// THREAD SAFETY
// ═══════════════════════════════════════════════════════════════════════════════

func TestHistory_ConcurrentReadWrite(t *testing.T) {
	path := tempHistoryPath(t)
	h, _ := LoadHistory(path)

	var wg sync.WaitGroup

	// Writers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			h.Append(makeFeedback("concurrent", n, 0.5))
		}(i)
	}

	// Readers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = h.Len()
			_ = h.Last()
			_ = h.LastN(5)
			_ = h.Snapshot()
		}()
	}

	wg.Wait()

	// Не должно быть паники
	if h.Len() != 20 {
		t.Errorf("expected 20 records, got %d", h.Len())
	}
}
