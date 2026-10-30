# `deobfmetrics` — Deobfuscation Quality Metrics

`deobfmetrics` is an internal quantitative analysis package for measuring the effectiveness of code deobfuscation passes. By comparing structural, statistical, and symbolic snapshots of code before and after deobfuscation, `deobfmetrics` produces a comprehensive, weighted confidence score (`OverallConfidence`) and letter grade.

---

## 📊 Metrics Table

All core metrics produce normalized scores in the range `[0.0, 1.0]`, where higher scores indicate superior deobfuscation quality or recovery rates.

| Metric | JSON Field | Default Weight | Formula / Description |
| :--- | :--- | :--- | :--- |
| **Entropy Reduction** | `entropy_reduction` | `0.15` | `(AvgEntropy_before - AvgEntropy_after) / AvgEntropy_before`<br>Measures reduction in Shannon entropy across identifier names. |
| **Identifier Recovery** | `identifier_recovery_rate` | `0.25` | `(ObfuscatedNames_before - ObfuscatedNames_after) / ObfuscatedNames_before`<br>Proportion of obfuscated tokens recovered to readable or meaningful names. |
| **CFG Deflattening** | `cfg_flattening_score` | `0.15` | `(DispatcherBlocks_before - DispatcherBlocks_after) / DispatcherBlocks_before`<br>Removal of control-flow flattening dispatchers (`switch` machines). |
| **Opaque Predicate Removal** | `opaque_predicate_reduction` | `0.10` | `(OpaquePredicates_before - OpaquePredicates_after) / OpaquePredicates_before`<br>Elimination of bogus or invariant `always-true` / `always-false` conditions. |
| **Cyclomatic Reduction** | `cyclomatic_delta` | `0.10` | `(CyclomaticTotal_before - CyclomaticTotal_after) / CyclomaticTotal_before`<br>Relative reduction in aggregate cyclomatic complexity across methods. |
| **String Decryption** | `string_decryption_rate` | `0.10` | `DecryptedStrings_after / EncryptedStrings_before`<br>Proportion of high-entropy encrypted strings successfully recovered to readable text. |
| **Reflection Resolution** | `reflection_resolution_rate` | `0.10` | `ResolvedReflection_after / TotalReflection_before`<br>Proportion of reflective method invocations resolved to direct calls. |
| **Dead Code Elimination** | `dead_code_elimination_rate` | `0.05` | `(DeadInstructions_before - DeadInstructions_after) / DeadInstructions_before`<br>Removal of unreachable instructions and dead code blocks. |

---

## 🏆 Grading Scale

The weighted average across all applicable metrics (`OverallConfidence`) maps directly to a standardized letter grade via `QualityReport.Grade()`:

| Grade | Overall Confidence Threshold | Description |
| :---: | :---: | :--- |
| **S** | `≥ 0.90` | **Flawless / State of the Art**: Almost complete structural and symbolic recovery. |
| **A** | `≥ 0.80` | **High Quality**: Core flattening and identifiers largely resolved; clean CFG. |
| **B** | `≥ 0.65` | **Solid**: Meaningful improvement; majority of obfuscation patterns neutralized. |
| **C** | `≥ 0.50` | **Partial**: Moderate recovery; some complex transformations or strings remain. |
| **D** | `≥ 0.30` | **Marginal**: Minor structural cleanup; primary obfuscation layers intact. |
| **F** | `< 0.30` | **Failed / Minimal**: Negligible improvement or broken input state. |

---

## 🏗️ Architecture & Files

- `deobfmetrics.go`: Core domain structures (`QualityReport`, `Calculator`), composite score computation (`Compute`), display (`Summary()`, `Grade()`).
- `state.go`: `DeobfState` and `StateInput` snapshots, state extraction (`ExtractState`), and invariant validation (`Validate()`, `ValidateTransition()`).
- `classify.go`: Identifier and string classification (`ClassifyName`, `IsObfuscated`, `IsMeaningful`, `IsHighEntropyString`).
- `entropy.go`: Single-pass rune frequency and Shannon entropy calculation (`ShannonEntropy`).
- `weights.go`: Configurable metric weighting (`MetricWeights`), default production weights (`DefaultWeights`), validation, and normalization.
- `thresholds.go`: Centralized, documented heuristics and classification thresholds (`obfEntropyThreshold`, `highEntropyStringThreshold`, etc.).

---

## 💻 Quick Usage Example

```go
package main

import (
	"fmt"
	"mega-analyzer/pkg/internal/deobfmetrics"
)

func main() {
	calc := deobfmetrics.NewCalculator()

	before := deobfmetrics.DeobfState{
		AvgNameEntropy:    4.2,
		TotalIdentifiers:  100,
		ObfuscatedNames:   80,
		TotalBlocks:       200,
		DispatcherBlocks:  30,
		TotalStrings:      50,
		EncryptedStrings:  40,
	}

	after := deobfmetrics.DeobfState{
		AvgNameEntropy:    2.1,
		TotalIdentifiers:  100,
		ObfuscatedNames:   20,
		MeaningfulNames:   60,
		ReadableNames:     20,
		TotalBlocks:       180,
		DispatcherBlocks:  5,
		TotalStrings:      50,
		EncryptedStrings:  10,
		DecryptedStrings:  35,
	}

	report, err := calc.Compute(before, after)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Grade: %s (Confidence: %.0f%%)\n", report.Grade(), report.OverallConfidence*100)
	fmt.Println(report.Summary())
}
```
