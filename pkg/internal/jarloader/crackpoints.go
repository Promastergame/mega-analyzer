package jarloader

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/internal/crackpoint"
	"mega-analyzer/pkg/internal/types"
	llmkeys "mega-analyzer/pkg/ml/llm_but_this_ml_lol"
)

// ═══════════════════════════════════════════════════════════════════════════════
// JAR CRACK POINTS + OFFLINE SECRET CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════════════
//
// JAR archives have no Dalvik CFG, so the CFG-based crack-point finder can't run.
// Instead we feed each class's referenced methods and string constants through
// the format-agnostic symbol scanner (crackpoint.FindCrackPointsInSymbols). This
// flags classes that *invoke* license / premium / tamper gates (isPremium,
// verifyLicense, SafetyNet, …) — a useful crack target even though the constant
// pool shows called methods, not the gate's own declaration.
//
// The llmkeys classifier adds entropy/family-based secret detection over the
// constant pool, complementing the regex provider scanner in analyzer.go.

// detectCrackPoints scans one parsed class for license/premium/tamper gates and
// returns them in the slim report type used across the whole tool.
func detectCrackPoints(finder *crackpoint.Finder, cf *ClassFile, entry string) []types.CrackPoint {
	if finder == nil || cf == nil {
		return nil
	}
	res := finder.FindCrackPointsInSymbols(classFileSymbols(cf), cf.ThisClass, crackpoint.PlatformJVM)
	return convertJVMCrackPoints(res, entry)
}

// classFileSymbols turns a class's referenced methods and (short) string
// literals into crack-point symbols. Literals come from secretScanStrings
// so gate names resolve through the same literal pool as secret scanning.
func classFileSymbols(cf *ClassFile) []crackpoint.SymbolRef {
	strs := secretScanStrings(cf)
	syms := make([]crackpoint.SymbolRef, 0, len(cf.MethodRefs)+len(strs))
	for _, ref := range cf.MethodRefs {
		syms = append(syms, crackpoint.SymbolRef{
			Name:  ref.Name,
			Kind:  crackpoint.SymbolMethod,
			Class: cf.ThisClass,
			Raw:   ref.FullName(),
		})
	}
	for _, s := range strs {
		// Gate names are short identifiers; skip long constants (likely data).
		if len(s) == 0 || len(s) > 200 {
			continue
		}
		syms = append(syms, crackpoint.SymbolRef{
			Name:  s,
			Kind:  crackpoint.SymbolString,
			Class: cf.ThisClass,
			Raw:   s,
		})
	}
	return syms
}

// convertJVMCrackPoints maps the crackpoint engine result into []types.CrackPoint.
func convertJVMCrackPoints(res *crackpoint.AnalysisResult, entry string) []types.CrackPoint {
	if res == nil || len(res.CrackPoints) == 0 {
		return nil
	}
	out := make([]types.CrackPoint, 0, len(res.CrackPoints))
	for _, cp := range res.CrackPoints {
		out = append(out, types.CrackPoint{
			Location:   types.SourceLocation{File: entry, Method: cp.MethodName},
			ClassName:  cp.ClassName,
			Method:     cp.MethodName,
			Category:   cp.Category,
			Confidence: cp.Confidence,
			Impact:     cp.Impact,
			Suggestion: cp.SuggestedAction,
			PatchRisk:  cp.PatchRisk,
		})
	}
	return out
}

// classifyStringSecret runs the offline credential classifier over a single
// constant-pool string. It is only called for strings no regex provider matched,
// so it surfaces bare high-entropy / known-family tokens without double-reporting.
func classifyStringSecret(str, className, entry string) (types.Match, bool) {
	v := strings.TrimSpace(str)
	if len(v) < 12 || len(v) > 512 {
		return types.Match{}, false
	}
	// ClassifyCached memoizes across all classes in the JAR: constant pools
	// repeat the same string constants heavily, so caching avoids reclassifying
	// identical values while returning identical verdicts.
	verdict := llmkeys.ClassifyCached(v)
	// Require a known credential family or high confidence: constant pools are
	// full of identifier-like strings, so the medium-entropy tier is too noisy
	// to surface as a secret here.
	if !verdict.IsSecret || (verdict.Family == "" && verdict.Confidence < 0.8) {
		return types.Match{}, false
	}
	masked := maskSecret(v)
	reason := "Embedded credential detected by offline classifier"
	if verdict.Family != "" {
		reason += " (" + verdict.Family + " family)"
	}
	reason += ". " + verdict.Reason
	return types.Match{
		SourceLocation:    types.SourceLocation{File: entry},
		Categorized:       types.Categorized{Category: types.CategoryAPIKey},
		Text:              masked,
		Pattern:           "llmkeys-classifier",
		Context:           "constant-pool string in " + className,
		ClassName:         className,
		Severity:          secretSeverity(verdict.Confidence),
		IsCritical:        verdict.Confidence >= 0.85,
		Confidence:        fmt.Sprintf("%.2f", verdict.Confidence),
		ReasonForSeverity: reason,
		Metadata: map[string]string{
			"family":  verdict.Family,
			"masked":  masked,
			"rule_id": "llmkeys-classifier",
			"entropy": fmt.Sprintf("%.2f", verdict.Entropy),
		},
	}, true
}

func secretSeverity(confidence float64) types.Severity {
	switch {
	case confidence >= 0.9:
		return types.SeverityHigh
	case confidence >= 0.7:
		return types.SeverityMedium
	default:
		return types.SeverityLow
	}
}

// maskSecret keeps a short prefix/suffix and hides the body so a leaked value is
// never written verbatim into a report.
func maskSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", 6) + s[len(s)-2:]
}
