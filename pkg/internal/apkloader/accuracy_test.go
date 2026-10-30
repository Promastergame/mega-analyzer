package apkloader

import (
	"strings"
	"testing"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ACCURACY MEASUREMENT FRAMEWORK (Task 368)
// ═══════════════════════════════════════════════════════════════════════════════

type AccuracyTestCase struct {
	Name           string
	MIR            []MIRInsn
	ExpectedTokens []string
}

func TestPipelineAccuracy_PatternRecovery(t *testing.T) {
	testCases := []AccuracyTestCase{
		{
			Name: "Constant String Concatenation",
			MIR: NewMIRBuilder().
				Const(0, "java.net.").
				Const(1, "URL").
				Invoke(2, 10, 0, 1). // some imaginary concat
				Return(2).
				Build(),
			ExpectedTokens: []string{"java.net.URL"},
		},
		{
			Name: "Dead Code Elimination Accuracy",
			MIR: NewMIRBuilder().
				Const(0, 1).
				Const(1, 0).
				Binary(MIR_ADD, 2, 0, 1).
				Return(2).
				// Add some unreachable instructions
				Const(3, 999).
				Build(),
			ExpectedTokens: []string{"v2"},
		},
	}

	config := DefaultPipelineConfig()
	pipeline := NewDeobfuscationPipeline(config)

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			builder := NewMIRBuilder()
			builder.insns = tc.MIR
			task := CreateSampleMethodTask("Ltest/Accuracy;", "run", builder)
			code, err := MockMethodAnalysis(pipeline, task)
			if err != nil {
				t.Fatalf("Analysis failed: %v", err)
			}

			output := code.Code
			for _, token := range tc.ExpectedTokens {
				if !strings.Contains(output, token) {
					t.Errorf("Accuracy check failed: expected token %q not found in output:\n%s", token, output)
				}
			}
		})
	}
}

// CalculateAccuracyScore computes a percentage score based on recovered symbols.
func CalculateAccuracyScore(recovered, total int) float64 {
	if total == 0 {
		return 100.0
	}
	return (float64(recovered) / float64(total)) * 100.0
}
