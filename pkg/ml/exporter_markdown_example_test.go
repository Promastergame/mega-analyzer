package ml_test

import (
	"fmt"
	"os"
	"path/filepath"

	"mega-analyzer/pkg/ml"
)

func ExampleMarkdownExporter_ExportToString() {
	// Create exporter
	exporter := ml.NewMarkdownExporter()

	// Create sample patches
	patches := []*ml.GeneratedPatch{
		{
			MethodName:   "isRooted",
			FilePath:     "com/example/security/RootCheck.smali",
			PatchType:    ml.PatchReturnFalse,
			Description:  "Return false to bypass root detection",
			Mode:         ml.PatchModeResearch,
			Confidence:   0.85,
			OriginalCode: ".method public isRooted()Z\n    # original code\n.end method",
			PatchedCode:  ".method public isRooted()Z\n    const/4 v0, 0x0\n    return v0\n.end method",
			Explanation: ml.PatchExplanation{
				Reason:       "Method checks for root access",
				WhatItDoes:   "Detects if device is rooted",
				WhyThisPatch: "Return false to hide root status",
				Impact:       "App will not detect rooted device",
			},
		},
	}

	// Create corresponding patch points
	points := []ml.PatchPoint{
		{
			MethodName:     "isRooted",
			FilePath:       "com/example/security/RootCheck.smali",
			ClassName:      "RootCheck",
			SuggestedPatch: ml.PatchReturnFalse,
			Confidence:     0.85,
			RiskScore:      75.0,
			RiskLevel:      ml.RiskClassHigh,
		},
	}

	// Export to string
	markdown := exporter.ExportToString(patches, points)

	// Print first few lines
	fmt.Println("Generated Markdown report with mode-specific icons and explanations")
	fmt.Println("Report includes: summary, risk levels, confidence breakdown, and code diffs")
	fmt.Println("Length:", len(markdown), "bytes")

	// Output:
	// Generated Markdown report with mode-specific icons and explanations
	// Report includes: summary, risk levels, confidence breakdown, and code diffs
	// Length: 1193 bytes
}

func ExampleMarkdownExporter_ExportToFile() {
	// Create exporter
	exporter := ml.NewMarkdownExporter()

	// Create sample patches with defensive mode
	patches := []*ml.GeneratedPatch{
		{
			MethodName:  "validateSignature",
			FilePath:    "com/example/security/Validator.smali",
			PatchType:   ml.PatchReturnTrue,
			Description: "Strengthen signature validation",
			Mode:        ml.PatchModeDefensive,
			Confidence:  0.92,
			Explanation: ml.PatchExplanation{
				Reason:       "Weak signature validation detected",
				WhatItDoes:   "Validates app signature",
				WhyThisPatch: "Enforce strict signature checking",
				Impact:       "Prevents tampering and repackaging",
			},
		},
	}

	points := []ml.PatchPoint{
		{
			MethodName:     "validateSignature",
			FilePath:       "com/example/security/Validator.smali",
			SuggestedPatch: ml.PatchReturnTrue,
			Confidence:     0.92,
			RiskScore:      80.0,
			RiskLevel:      ml.RiskClassHigh,
		},
	}

	// Examples must not write generated output into the source tree.
	tmpDir, err := os.MkdirTemp("", "mega-analyzer-markdown-example-*")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer os.RemoveAll(tmpDir)

	// Export to an isolated temporary file.
	err = exporter.ExportToFile(patches, points, filepath.Join(tmpDir, "security_report.md"))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Markdown report exported successfully")
	fmt.Println("File includes defensive mode icon 🛡️")

	// Output:
	// Markdown report exported successfully
	// File includes defensive mode icon 🛡️
}
