package ml

import (
	"fmt"
	"log"
)

// ExampleJSONExporter_ExportToString demonstrates basic JSON export usage
func ExampleJSONExporter_ExportToString() {
	// Create exporter
	exporter := NewJSONExporter()

	// Create sample patches
	patches := []*GeneratedPatch{
		{
			MethodName:   "isLicensed",
			FilePath:     "com/example/License.smali",
			PatchType:    PatchReturnTrue,
			Description:  "Return true for license check",
			OriginalCode: ".method public isLicensed()Z\n    const/4 v0, 0x0\n    return v0\n.end method",
			PatchedCode:  ".method public isLicensed()Z\n    .registers 1\n\n    const/4 v0, 0x1\n    return v0\n.end method",
			DiffView:     "--- original\n+++ patched\n-    const/4 v0, 0x0\n+    const/4 v0, 0x1",
			Mode:         PatchModeResearch,
			Confidence:   0.85,
			Explanation: PatchExplanation{
				Reason:       "Method name matches license check pattern",
				WhatItDoes:   "Returns false, denying license",
				WhyThisPatch: "Return true to bypass license check",
				Impact:       "App will think it's licensed",
				Signals:      []string{"name_match", "return_type"},
			},
		},
	}

	// Create corresponding points
	points := []PatchPoint{
		{
			FilePath:        "com/example/License.smali",
			ClassName:       "License",
			MethodName:      "isLicensed",
			MethodSignature: "()Z",
			RiskScore:       85.0,
			RiskLevel:       RiskClassHigh,
			Confidence:      0.85,
			Category:        PatchCatLicense,
			CategoryName:    "License Check",
			SuggestedPatch:  PatchReturnTrue,
			PatchDesc:       "Return true",
		},
	}

	// Export to string
	_, err := exporter.ExportToString(patches, points)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("JSON export successful")
	fmt.Printf("Export contains patches: %d\n", len(patches))

	// Output:
	// JSON export successful
	// Export contains patches: 1
}

// ExampleJSONExporter_ExportToFile demonstrates file export usage
func ExampleJSONExporter_ExportToFile() {
	// Create exporter
	_ = NewJSONExporter()

	// In real usage:
	// exporter.ExportToFile(patches, points, "patches.json")

	fmt.Println("Exported to patches.json")

	// Output:
	// Exported to patches.json
}
