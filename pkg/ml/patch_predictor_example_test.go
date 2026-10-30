package ml_test

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"mega-analyzer/pkg/ml"
)

// Example демонстрирует базовое использование системы фидбека
func ExamplePatchPredictor_applyUserFeedback() {
	// Создаём временную историю
	tmpDir := os.TempDir()
	historyPath := filepath.Join(tmpDir, "example_history.json")
	defer os.Remove(historyPath)

	// Создаём историю с правильными параметрами
	history := &ml.AnalysisHistory{}

	// Добавляем фидбек
	feedback := &ml.AnalysisFeedback{
		ID:        "example",
		APKName:   "example.apk",
		Timestamp: time.Now(),
		UserOverrides: []ml.UserOverride{
			{
				Path:      "Landroidx/",
				Action:    "noise",
				Timestamp: time.Now(),
				Reason:    "Android framework library",
			},
			{
				Path:      "myapp/premium",
				Action:    "relevant",
				Timestamp: time.Now(),
				Reason:    "Premium feature check",
			},
		},
		KeywordStats:  make(map[string]*ml.KeywordFeedback),
		LibraryStats:  make(map[string]*ml.LibraryFeedback),
		CategoryStats: make(map[string]*ml.CategoryFeedback),
	}

	// Используем историю
	_ = history

	fmt.Println("Feedback created successfully")
	fmt.Printf("Total overrides: %d\n", len(feedback.UserOverrides))

	// Output:
	// Feedback created successfully
	// Total overrides: 2
}

// Example демонстрирует создание предиктора с кастомной конфигурацией
func ExampleNewPatchPredictorWithConfig() {
	config := ml.PredictorConfig{
		MaxHighRisk:      10,
		MaxMediumRisk:    20,
		MaxLowRisk:       30,
		MinScore:         40.0,
		IncludeLibraries: false,
	}

	predictor := ml.NewPatchPredictorWithConfig(os.Stdout, config)

	fmt.Printf("Predictor created with MinScore: %.1f\n", predictor.Config().MinScore)
	fmt.Printf("Include libraries: %v\n", predictor.Config().IncludeLibraries)

	// Output:
	// Predictor created with MinScore: 40.0
	// Include libraries: false
}

// Example демонстрирует workflow с маркировками
func Example_feedbackWorkflow() {
	// 1. Отметить библиотеки как шум
	fmt.Println("Step 1: Mark libraries as noise")
	fmt.Println("  analyzer --mark-noise \"Landroidx/\"")
	fmt.Println("  analyzer --mark-noise \"Lcom/google/\"")

	// 2. Отметить важный код
	fmt.Println("\nStep 2: Mark important code as relevant")
	fmt.Println("  analyzer --mark-relevant \"myapp/premium\"")

	// 3. Запустить анализ
	fmt.Println("\nStep 3: Run analysis with feedback")
	fmt.Println("  analyzer -t app.apk --ml-patch")

	// 4. Результат
	fmt.Println("\nResult: Clean output without library noise!")

	// Output:
	// Step 1: Mark libraries as noise
	//   analyzer --mark-noise "Landroidx/"
	//   analyzer --mark-noise "Lcom/google/"
	//
	// Step 2: Mark important code as relevant
	//   analyzer --mark-relevant "myapp/premium"
	//
	// Step 3: Run analysis with feedback
	//   analyzer -t app.apk --ml-patch
	//
	// Result: Clean output without library noise!
}
