package deobfuscation

import (
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PROGUARD MAP APPLIER — resolves obfuscated names in AnalysisResult
// ═══════════════════════════════════════════════════════════════════════════════

// ApplyProGuardMap walks the most common name-bearing containers inside
// AnalysisResult and replaces obfuscated class / method names with their
// original counterparts from the supplied mapping.
func ApplyProGuardMap(r *types.AnalysisResult, m *ProGuardMap) {
	if m == nil || r == nil {
		return
	}

	// 1. CrackPoints
	if r.CrackPoint != nil {
		for i := range r.CrackPoint.Points {
			p := &r.CrackPoint.Points[i]
			obfClass := p.ClassName
			p.ClassName = m.ResolveClass(obfClass)
			p.Method = resolveMethodName(m, obfClass, p.Method)
		}
	}

	// 2. Deobfuscation insights
	if r.Deobfuscation != nil {
		for i := range r.Deobfuscation.Methods {
			dm := &r.Deobfuscation.Methods[i]
			obfClass := dm.ClassName
			dm.ClassName = m.ResolveClass(obfClass)
			dm.MethodName = resolveMethodName(m, obfClass, dm.MethodName)
		}
	}

	// 4. RuleMatches — resolved_context often holds class::method strings
	for i := range r.RuleMatches {
		rm := &r.RuleMatches[i]
		if rm.ResolvedContext != "" {
			rm.ResolvedContext = resolveContextString(m, rm.ResolvedContext)
		}
	}

	// 5. Correlations — description may contain obfuscated names
	for i := range r.Correlations {
		c := &r.Correlations[i]
		c.Description = resolveContextString(m, c.Description)
	}

	// 6. Recommendations — free-text title / description
	for i := range r.Recommendations {
		rec := &r.Recommendations[i]
		rec.Title = resolveContextString(m, rec.Title)
		rec.Description = resolveContextString(m, rec.Description)
		for j := range rec.Steps {
			rec.Steps[j] = resolveContextString(m, rec.Steps[j])
		}
	}
}

// resolveMethodName extracts the bare method name from a ProGuard signature.
func resolveMethodName(m *ProGuardMap, obfClass, obfMethod string) string {
	sig := m.ResolveMethod(obfClass, obfMethod)
	if sig == obfMethod {
		return obfMethod
	}
	if idx := strings.Index(sig, " "); idx >= 0 {
		sig = sig[idx+1:]
	}
	if idx := strings.Index(sig, "("); idx >= 0 {
		return sig[:idx]
	}
	return sig
}

// resolveContextString replaces any "ObfClass->obfMethod" patterns found in
// free-text descriptions with their resolved counterparts.
func resolveContextString(m *ProGuardMap, s string) string {
	// Quick heuristic: look for smali-style class separators
	parts := strings.Split(s, "->")
	if len(parts) != 2 {
		return s
	}
	cls := strings.TrimSpace(parts[0])
	meth := strings.TrimSpace(parts[1])
	// Strip any trailing descriptor from method
	if idx := strings.Index(meth, "("); idx >= 0 {
		meth = meth[:idx]
	}
	resolvedClass := m.ResolveClass(cls)
	resolvedMethod := resolveMethodName(m, cls, meth)
	if resolvedClass == cls && resolvedMethod == meth {
		return s
	}
	return resolvedClass + "->" + resolvedMethod
}
