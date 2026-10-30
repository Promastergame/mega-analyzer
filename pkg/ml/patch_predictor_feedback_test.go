package ml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPatchPredictor_ApplyUserFeedback(t *testing.T) {
	// Создаём временную историю
	tmpDir := testTempDir(t)
	historyPath := filepath.Join(tmpDir, "history.json")

	history := &AnalysisHistory{
		path:     historyPath,
		maxItems: 10,
		records:  make([]*AnalysisFeedback, 0),
	}

	// Добавляем запись с user overrides
	feedback := &AnalysisFeedback{
		ID:        "test-feedback",
		APKName:   "test.apk",
		Timestamp: time.Now(),
		UserOverrides: []UserOverride{
			{
				Path:      "Landroidx/",
				Action:    "noise",
				Timestamp: time.Now(),
				Reason:    "test",
			},
			{
				Path:      "smellymoo/sand/Sand",
				Action:    "relevant",
				Timestamp: time.Now(),
				Reason:    "test",
			},
			{
				Keyword:   "androeed.ru",
				Action:    "noise",
				Timestamp: time.Now(),
				Reason:    "test",
			},
		},
		KeywordStats:  make(map[string]*KeywordFeedback),
		LibraryStats:  make(map[string]*LibraryFeedback),
		CategoryStats: make(map[string]*CategoryFeedback),
	}

	history.Append(feedback)
	if err := history.Save(); err != nil {
		t.Fatalf("Failed to save history: %v", err)
	}

	// Загружаем историю
	loadedHistory, err := LoadHistory(historyPath)
	if err != nil {
		t.Fatalf("Failed to load history: %v", err)
	}

	// Создаём предиктор с историей
	predictor := &PatchPredictor{
		analyzer: NewPatchAnalyzer(),
		scorer:   NewPatchScorer(NewPatchAnalyzer()),
		output:   os.Stdout,
		config:   DefaultPredictorConfig(),
		history:  loadedHistory,
	}

	// Создаём тестовые scored methods
	scored := []ScoredMethod{
		{
			ClassPath: "Landroidx/core/app/ActivityCompat.smali",
			ClassName: "Landroidx/core/app/ActivityCompat",
			Method: MethodInfo{
				Name:       "checkSelfPermission",
				ReturnType: "I",
			},
			Score: ScoreResult{
				FinalScore:   80.0,
				Confidence:   0.9,
				MatchedParts: []string{"permission"},
			},
		},
		{
			ClassPath: "smellymoo/sand/Sand.smali",
			ClassName: "smellymoo/sand/Sand",
			Method: MethodInfo{
				Name:       "isPremium",
				ReturnType: "Z",
			},
			Score: ScoreResult{
				FinalScore:   70.0,
				Confidence:   0.8,
				MatchedParts: []string{"premium"},
			},
		},
		{
			ClassPath: "com/example/app/MainActivity.smali",
			ClassName: "com/example/app/MainActivity",
			Method: MethodInfo{
				Name:       "onCreate",
				ReturnType: "V",
			},
			Score: ScoreResult{
				FinalScore:   60.0,
				Confidence:   0.7,
				MatchedParts: []string{"androeed.ru"},
			},
		},
		{
			ClassPath: "com/example/app/Helper.smali",
			ClassName: "com/example/app/Helper",
			Method: MethodInfo{
				Name:       "doSomething",
				ReturnType: "V",
			},
			Score: ScoreResult{
				FinalScore:   50.0,
				Confidence:   0.6,
				MatchedParts: []string{"helper"},
			},
		},
	}

	// Применяем фидбек
	filtered := predictor.applyUserFeedback(scored)

	// Проверяем результаты
	if len(filtered) != 2 {
		t.Errorf("Expected 2 results after filtering, got %d", len(filtered))
	}

	// Проверяем, что Landroidx отфильтрован
	for _, sm := range filtered {
		if sm.ClassPath == "Landroidx/core/app/ActivityCompat.smali" {
			t.Error("Landroidx should be filtered out as noise")
		}
		if sm.ClassPath == "com/example/app/MainActivity.smali" {
			t.Error("File with androeed.ru keyword should be filtered out as noise")
		}
	}

	// Проверяем, что smellymoo/sand/Sand получил буст
	foundRelevant := false
	for _, sm := range filtered {
		if sm.ClassPath == "smellymoo/sand/Sand.smali" {
			foundRelevant = true
			if sm.Score.FinalScore <= 70.0 {
				t.Errorf("Relevant item should have boosted score, got %.2f", sm.Score.FinalScore)
			}
			if sm.Score.Confidence <= 0.8 {
				t.Errorf("Relevant item should have boosted confidence, got %.2f", sm.Score.Confidence)
			}
		}
	}

	if !foundRelevant {
		t.Error("Relevant item (smellymoo/sand/Sand) should be in results")
	}

	// Проверяем, что обычный файл остался без изменений
	foundNormal := false
	for _, sm := range filtered {
		if sm.ClassPath == "com/example/app/Helper.smali" {
			foundNormal = true
			if sm.Score.FinalScore != 50.0 {
				t.Errorf("Normal item should have unchanged score, got %.2f", sm.Score.FinalScore)
			}
		}
	}

	if !foundNormal {
		t.Error("Normal item (Helper) should be in results")
	}
}

func TestPatchPredictor_NoFeedback(t *testing.T) {
	// Создаём предиктор без истории
	predictor := &PatchPredictor{
		analyzer: NewPatchAnalyzer(),
		scorer:   NewPatchScorer(NewPatchAnalyzer()),
		output:   os.Stdout,
		config:   DefaultPredictorConfig(),
		history:  nil,
	}

	scored := []ScoredMethod{
		{
			ClassPath: "com/example/Test.smali",
			ClassName: "com/example/Test",
			Method: MethodInfo{
				Name:       "test",
				ReturnType: "V",
			},
			Score: ScoreResult{
				FinalScore: 80.0,
				Confidence: 0.9,
			},
		},
	}

	// Применяем фидбек (должен вернуть без изменений)
	filtered := predictor.applyUserFeedback(scored)

	if len(filtered) != len(scored) {
		t.Errorf("Without feedback, all items should remain, got %d/%d", len(filtered), len(scored))
	}

	if filtered[0].Score.FinalScore != scored[0].Score.FinalScore {
		t.Error("Without feedback, scores should remain unchanged")
	}
}

func TestPatchPredictor_EmptyHistory(t *testing.T) {
	// Создаём пустую историю
	history := &AnalysisHistory{
		path:     "test.json",
		maxItems: 10,
		records:  make([]*AnalysisFeedback, 0),
	}

	predictor := &PatchPredictor{
		analyzer: NewPatchAnalyzer(),
		scorer:   NewPatchScorer(NewPatchAnalyzer()),
		output:   os.Stdout,
		config:   DefaultPredictorConfig(),
		history:  history,
	}

	scored := []ScoredMethod{
		{
			ClassPath: "com/example/Test.smali",
			ClassName: "com/example/Test",
			Method: MethodInfo{
				Name:       "test",
				ReturnType: "V",
			},
			Score: ScoreResult{
				FinalScore: 80.0,
				Confidence: 0.9,
			},
		},
	}

	// Применяем фидбек (должен вернуть без изменений)
	filtered := predictor.applyUserFeedback(scored)

	if len(filtered) != len(scored) {
		t.Errorf("With empty history, all items should remain, got %d/%d", len(filtered), len(scored))
	}
}

func TestPatchPredictor_MatchesAnyPattern(t *testing.T) {
	predictor := &PatchPredictor{
		analyzer: NewPatchAnalyzer(),
		scorer:   NewPatchScorer(NewPatchAnalyzer()),
		output:   os.Stdout,
		config:   DefaultPredictorConfig(),
	}

	tests := []struct {
		name     string
		sm       ScoredMethod
		patterns []string
		want     bool
	}{
		{
			name: "matches class path",
			sm: ScoredMethod{
				ClassPath: "Landroidx/core/app/ActivityCompat.smali",
				ClassName: "Landroidx/core/app/ActivityCompat",
			},
			patterns: []string{"Landroidx/"},
			want:     true,
		},
		{
			name: "matches class name",
			sm: ScoredMethod{
				ClassPath: "com/example/Test.smali",
				ClassName: "com/example/Test",
			},
			patterns: []string{"example"},
			want:     true,
		},
		{
			name: "matches method name",
			sm: ScoredMethod{
				ClassPath: "com/example/Test.smali",
				ClassName: "com/example/Test",
				Method: MethodInfo{
					Name: "isPremium",
				},
			},
			patterns: []string{"Premium"},
			want:     true,
		},
		{
			name: "matches keyword in matched parts",
			sm: ScoredMethod{
				ClassPath: "com/example/Test.smali",
				ClassName: "com/example/Test",
				Score: ScoreResult{
					MatchedParts: []string{"androeed.ru", "billing"},
				},
			},
			patterns: []string{"androeed"},
			want:     true,
		},
		{
			name: "no match",
			sm: ScoredMethod{
				ClassPath: "com/example/Test.smali",
				ClassName: "com/example/Test",
				Method: MethodInfo{
					Name: "doSomething",
				},
			},
			patterns: []string{"Landroidx/", "Google"},
			want:     false,
		},
		{
			name: "empty patterns",
			sm: ScoredMethod{
				ClassPath: "com/example/Test.smali",
			},
			patterns: []string{},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := predictor.matchesAnyPattern(tt.sm, tt.patterns)
			if got != tt.want {
				t.Errorf("matchesAnyPattern() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPatchPredictor_MultipleOverrides(t *testing.T) {
	// Создаём историю с несколькими записями и overrides
	tmpDir := testTempDir(t)
	historyPath := filepath.Join(tmpDir, "history.json")

	history := &AnalysisHistory{
		path:     historyPath,
		maxItems: 10,
		records:  make([]*AnalysisFeedback, 0),
	}

	// Первая запись
	feedback1 := &AnalysisFeedback{
		ID:        "test-1",
		APKName:   "test1.apk",
		Timestamp: time.Now(),
		UserOverrides: []UserOverride{
			{Path: "Landroidx/", Action: "noise", Timestamp: time.Now()},
			{Path: "Lcom/google/", Action: "noise", Timestamp: time.Now()},
		},
		KeywordStats:  make(map[string]*KeywordFeedback),
		LibraryStats:  make(map[string]*LibraryFeedback),
		CategoryStats: make(map[string]*CategoryFeedback),
	}

	// Вторая запись
	feedback2 := &AnalysisFeedback{
		ID:        "test-2",
		APKName:   "test2.apk",
		Timestamp: time.Now(),
		UserOverrides: []UserOverride{
			{Path: "myapp/premium", Action: "relevant", Timestamp: time.Now()},
			{Keyword: "debug", Action: "noise", Timestamp: time.Now()},
		},
		KeywordStats:  make(map[string]*KeywordFeedback),
		LibraryStats:  make(map[string]*LibraryFeedback),
		CategoryStats: make(map[string]*CategoryFeedback),
	}

	history.Append(feedback1)
	history.Append(feedback2)
	history.Save()

	loadedHistory, _ := LoadHistory(historyPath)

	predictor := &PatchPredictor{
		analyzer: NewPatchAnalyzer(),
		scorer:   NewPatchScorer(NewPatchAnalyzer()),
		output:   os.Stdout,
		config:   DefaultPredictorConfig(),
		history:  loadedHistory,
	}

	scored := []ScoredMethod{
		{ClassPath: "Landroidx/Test.smali", ClassName: "Landroidx/Test", Score: ScoreResult{FinalScore: 80}},
		{ClassPath: "Lcom/google/Test.smali", ClassName: "Lcom/google/Test", Score: ScoreResult{FinalScore: 75}},
		{ClassPath: "myapp/premium/Check.smali", ClassName: "myapp/premium/Check", Score: ScoreResult{FinalScore: 70, Confidence: 0.8}},
		{ClassPath: "myapp/Helper.smali", ClassName: "myapp/Helper", Score: ScoreResult{FinalScore: 60, MatchedParts: []string{"debug"}}},
		{ClassPath: "myapp/Main.smali", ClassName: "myapp/Main", Score: ScoreResult{FinalScore: 50}},
	}

	filtered := predictor.applyUserFeedback(scored)

	// Должны остаться только myapp/premium (boosted) и myapp/Main
	if len(filtered) != 2 {
		t.Errorf("Expected 2 results, got %d", len(filtered))
	}

	// Проверяем буст для relevant
	foundBoosted := false
	for _, sm := range filtered {
		if strings.Contains(sm.ClassPath, "premium") {
			foundBoosted = true
			if sm.Score.FinalScore <= 70 {
				t.Errorf("Relevant should be boosted, got %.2f", sm.Score.FinalScore)
			}
		}
	}

	if !foundBoosted {
		t.Error("Relevant item should be in results with boost")
	}
}

func TestPatchPredictor_LatestFeedbackWins(t *testing.T) {
	t0 := time.Date(2026, 7, 23, 1, 0, 0, 0, time.UTC)
	history := &AnalysisHistory{
		maxItems: 10,
		records: []*AnalysisFeedback{
			{UserOverrides: []UserOverride{{Path: "Lcom/example/", Action: FeedbackNoise, Timestamp: t0}}},
			// Simulate a copied legacy event; its old timestamp must not win.
			{UserOverrides: []UserOverride{{Path: "Lcom/example/", Action: FeedbackNoise, Timestamp: t0}}},
			{UserOverrides: []UserOverride{{Path: "lcom\\example\\", Action: FeedbackRelevant, Timestamp: t0.Add(time.Hour)}}},
		},
	}
	predictor := &PatchPredictor{history: history}
	scored := []ScoredMethod{{
		ClassPath: "Lcom/example/Main.smali",
		Score:     ScoreResult{FinalScore: 50, Confidence: 0.5},
	}}

	got := predictor.applyUserFeedback(scored)
	if len(got) != 1 {
		t.Fatalf("corrected relevant decision must not be filtered, got %d results", len(got))
	}
	if got[0].Score.FinalScore <= 50 || got[0].Score.Confidence <= 0.5 {
		t.Fatalf("corrected relevant decision must boost score, got %+v", got[0].Score)
	}
}

func TestPatchPredictor_PredictFromCandidates_WithFeedback(t *testing.T) {
	// Создаём историю с фидбеком
	tmpDir := testTempDir(t)
	historyPath := filepath.Join(tmpDir, "history.json")

	history := &AnalysisHistory{
		path:     historyPath,
		maxItems: 10,
		records:  make([]*AnalysisFeedback, 0),
	}

	feedback := &AnalysisFeedback{
		ID:        "test",
		APKName:   "test.apk",
		Timestamp: time.Now(),
		UserOverrides: []UserOverride{
			{Path: "android/support/", Action: "noise", Timestamp: time.Now()},
		},
		KeywordStats:  make(map[string]*KeywordFeedback),
		LibraryStats:  make(map[string]*LibraryFeedback),
		CategoryStats: make(map[string]*CategoryFeedback),
	}

	history.Append(feedback)
	history.Save()

	loadedHistory, _ := LoadHistory(historyPath)

	predictor := &PatchPredictor{
		analyzer: NewPatchAnalyzer(),
		scorer:   NewPatchScorer(NewPatchAnalyzer()),
		output:   os.Stdout,
		config:   DefaultPredictorConfig(),
		history:  loadedHistory,
	}

	// Создаём тестовые кандидаты
	candidates := []AnalysisCandidate{
		{
			FilePath:  "android/support/Test.smali",
			Content:   []byte(".class public Landroid/support/Test;\n.method public isPremium()Z\nreturn v0\n.end method"),
			IsAppCode: false,
		},
		{
			FilePath:  "com/myapp/Premium.smali",
			Content:   []byte(".class public Lcom/myapp/Premium;\n.method public checkLicense()Z\nreturn v0\n.end method"),
			IsAppCode: true,
		},
	}

	prediction := predictor.PredictFromCandidates(candidates)

	// android/support должен быть отфильтрован
	allPoints := append(prediction.HighRisk, prediction.MediumRisk...)
	allPoints = append(allPoints, prediction.LowRisk...)

	for _, point := range allPoints {
		if strings.Contains(point.FilePath, "android/support") {
			t.Error("android/support should be filtered out by feedback")
		}
	}
}

func TestMinFloat(t *testing.T) {
	tests := []struct {
		name string
		a, b float64
		want float64
	}{
		{"a smaller", 1.0, 2.0, 1.0},
		{"b smaller", 5.0, 3.0, 3.0},
		{"equal", 4.0, 4.0, 4.0},
		{"negative", -1.0, 2.0, -1.0},
		{"zero", 0.0, 1.0, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := minFloat(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("minFloat(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestPatchPredictor_ConfigOptions(t *testing.T) {
	config := PredictorConfig{
		MaxHighRisk:      5,
		MaxMediumRisk:    10,
		MaxLowRisk:       15,
		MinScore:         40.0,
		IncludeLibraries: true,
	}

	predictor := NewPatchPredictorWithConfig(os.Stdout, config)

	if predictor.config.MaxHighRisk != 5 {
		t.Errorf("MaxHighRisk = %d, want 5", predictor.config.MaxHighRisk)
	}

	if predictor.config.MinScore != 40.0 {
		t.Errorf("MinScore = %.1f, want 40.0", predictor.config.MinScore)
	}

	if !predictor.config.IncludeLibraries {
		t.Error("IncludeLibraries should be true")
	}
}

func TestDefaultPredictorConfig(t *testing.T) {
	config := DefaultPredictorConfig()

	if config.MaxHighRisk <= 0 {
		t.Error("MaxHighRisk should be positive")
	}

	if config.MinScore < 0 || config.MinScore > 100 {
		t.Error("MinScore should be between 0 and 100")
	}

	if config.IncludeLibraries {
		t.Error("IncludeLibraries should be false by default")
	}
}
