package apkloader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// REGRESSION TESTING FRAMEWORK (Task 369)
// ═══════════════════════════════════════════════════════════════════════════════

func TestPipelineRegression_GoldenFiles(t *testing.T) {
	goldenDir := "testdata/golden"
	// Ensure golden dir exists
	_ = os.MkdirAll(goldenDir, 0755)

	testCases := []struct {
		Name string
		MIR  []MIRInsn
	}{
		{
			Name: "basic_math",
			MIR: NewMIRBuilder().
				Const(0, 10).
				Const(1, 20).
				Binary(MIR_ADD, 2, 0, 1).
				Return(2).
				Build(),
		},
		{
			Name: "string_ops",
			MIR: NewMIRBuilder().
				Const(0, "hello").
				Const(1, "world").
				Return(0).
				Build(),
		},
	}

	config := DefaultPipelineConfig()
	pipeline := NewDeobfuscationPipeline(config)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			builder := NewMIRBuilder()
			builder.insns = tc.MIR
			task := CreateSampleMethodTask("Ltest/Regression;", tc.Name, builder)
			code, err := MockMethodAnalysis(pipeline, task)
			if err != nil {
				t.Fatalf("Analysis failed: %v", err)
			}

			actual := code.Code
			goldenPath := filepath.Join(goldenDir, tc.Name+".smali")

			// If golden file doesn't exist, create it (bootstrap)
			if _, err := os.Stat(goldenPath); os.IsNotExist(err) {
				t.Logf("Creating golden file for %s", tc.Name)
				if err := os.WriteFile(goldenPath, []byte(actual), 0644); err != nil {
					t.Fatalf("Failed to create golden file: %v", err)
				}
				return
			}

			// Compare with golden file
			expected, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("Failed to read golden file: %v", err)
			}

			normalize := func(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }
			if normalize(actual) != normalize(string(expected)) {
				t.Errorf("Regression detected for %s!\nDIFF:\nActual:\n%s\nExpected:\n%s", tc.Name, actual, string(expected))

				// Optional: auto-update golden files if a flag is set
				if os.Getenv("UPDATE_GOLDEN") == "true" {
					_ = os.WriteFile(goldenPath, []byte(actual), 0644)
				}
			}
		})
	}
}
