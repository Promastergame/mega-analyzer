package ml

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkApplyUserFeedback(b *testing.B) {
	// Создаём историю с фидбеком
	tmpDir := b.TempDir()
	historyPath := filepath.Join(tmpDir, "history.json")

	history := &AnalysisHistory{
		path:     historyPath,
		maxItems: 10,
		records:  make([]*AnalysisFeedback, 0),
	}

	feedback := &AnalysisFeedback{
		ID:        "bench",
		APKName:   "bench.apk",
		Timestamp: time.Now(),
		UserOverrides: []UserOverride{
			{Path: "Landroidx/", Action: "noise", Timestamp: time.Now()},
			{Path: "Lcom/google/", Action: "noise", Timestamp: time.Now()},
			{Path: "Lkotlin/", Action: "noise", Timestamp: time.Now()},
			{Path: "myapp/premium", Action: "relevant", Timestamp: time.Now()},
			{Keyword: "androeed.ru", Action: "noise", Timestamp: time.Now()},
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

	// Создаём тестовый набор из 100 методов
	scored := make([]ScoredMethod, 100)
	for i := 0; i < 100; i++ {
		var classPath string
		switch i % 5 {
		case 0:
			classPath = "Landroidx/core/Test.smali"
		case 1:
			classPath = "Lcom/google/Test.smali"
		case 2:
			classPath = "Lkotlin/Test.smali"
		case 3:
			classPath = "myapp/premium/Check.smali"
		default:
			classPath = "myapp/Main.smali"
		}

		scored[i] = ScoredMethod{
			ClassPath: classPath,
			ClassName: classPath,
			Method: MethodInfo{
				Name:       "testMethod",
				ReturnType: "V",
			},
			Score: ScoreResult{
				FinalScore:   float64(50 + i%50),
				Confidence:   0.8,
				MatchedParts: []string{"test"},
			},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = predictor.applyUserFeedback(scored)
	}
}

func BenchmarkMatchesAnyPattern(b *testing.B) {
	predictor := &PatchPredictor{
		analyzer: NewPatchAnalyzer(),
		scorer:   NewPatchScorer(NewPatchAnalyzer()),
		output:   os.Stdout,
		config:   DefaultPredictorConfig(),
	}

	sm := ScoredMethod{
		ClassPath: "com/example/app/MainActivity.smali",
		ClassName: "com/example/app/MainActivity",
		Method: MethodInfo{
			Name: "onCreate",
		},
		Score: ScoreResult{
			MatchedParts: []string{"onCreate", "Bundle", "Activity"},
		},
	}

	patterns := []string{
		"Landroidx/",
		"Lcom/google/",
		"Lkotlin/",
		"example",
		"test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = predictor.matchesAnyPattern(sm, patterns)
	}
}

func BenchmarkApplyUserFeedback_NoHistory(b *testing.B) {
	predictor := &PatchPredictor{
		analyzer: NewPatchAnalyzer(),
		scorer:   NewPatchScorer(NewPatchAnalyzer()),
		output:   os.Stdout,
		config:   DefaultPredictorConfig(),
		history:  nil,
	}

	scored := make([]ScoredMethod, 100)
	for i := 0; i < 100; i++ {
		scored[i] = ScoredMethod{
			ClassPath: "com/example/Test.smali",
			ClassName: "com/example/Test",
			Score: ScoreResult{
				FinalScore: float64(50 + i%50),
			},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = predictor.applyUserFeedback(scored)
	}
}

func BenchmarkApplyUserFeedback_LargeDataset(b *testing.B) {
	tmpDir := b.TempDir()
	historyPath := filepath.Join(tmpDir, "history.json")

	history := &AnalysisHistory{
		path:     historyPath,
		maxItems: 10,
		records:  make([]*AnalysisFeedback, 0),
	}

	// Создаём много overrides
	overrides := make([]UserOverride, 50)
	for i := 0; i < 50; i++ {
		overrides[i] = UserOverride{
			Path:      "Ltest" + string(rune('a'+i%26)) + "/",
			Action:    "noise",
			Timestamp: time.Now(),
		}
	}

	feedback := &AnalysisFeedback{
		ID:            "bench-large",
		APKName:       "bench.apk",
		Timestamp:     time.Now(),
		UserOverrides: overrides,
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

	// Большой набор данных - 1000 методов
	scored := make([]ScoredMethod, 1000)
	for i := 0; i < 1000; i++ {
		scored[i] = ScoredMethod{
			ClassPath: "com/example/Test" + string(rune('a'+i%26)) + ".smali",
			ClassName: "com/example/Test",
			Score: ScoreResult{
				FinalScore: float64(30 + i%70),
			},
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = predictor.applyUserFeedback(scored)
	}
}
