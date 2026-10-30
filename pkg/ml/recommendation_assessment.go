package ml

import "strings"

// RecommendationAssessment separates a scored method from the validity of an
// intended rewrite. Compatibility is only a local contract check, NOT proof that
// replacing the method preserves caller expectations or application behavior.
type RecommendationAssessment struct {
	Status     string   `json:"status"` // compatible | needs_review | reject | audit_only
	ReturnType string   `json:"return_type,omitempty"`
	Reasons    []string `json:"reasons,omitempty"`
}

func assessRecommendation(point *PatchPoint, mi *MethodInfo) *RecommendationAssessment {
	a := &RecommendationAssessment{Status: "compatible"}
	if point == nil || mi == nil {
		a.Status = "reject"
		a.Reasons = []string{"missing method metadata"}
		return a
	}
	if economyNeedsTransactionReview(point.Economy) {
		a.Status = "audit_only"
		a.Reasons = []string{"resource transaction/validation requires a specific edit that preserves its effects"}
		return a
	}
	if point.VulnSignals.HasAny() && !(isEconomyCandidate(point.Economy) && onlyEconomySignals(point.VulnSignals)) {
		a.Status = "audit_only"
		a.Reasons = []string{"static audit signal is not an automatic rewrite authorization"}
		return a
	}
	rt := strings.TrimSpace(mi.ReturnType)
	sigRT := ""
	if i := strings.LastIndex(mi.FullSignature, ")"); i >= 0 {
		sigRT = strings.TrimSpace(mi.FullSignature[i+1:])
	}
	if rt == "" {
		rt = sigRT
	}
	a.ReturnType = rt
	if rt != "" && sigRT != "" && rt != sigRT {
		a.Status = "reject"
		a.Reasons = append(a.Reasons, "conflicting return descriptors")
		return a
	}
	if !validRecommendationReturn(rt) {
		a.Status = "reject"
		a.Reasons = append(a.Reasons, "missing or malformed return descriptor")
		return a
	}
	review := func(reason string) {
		if a.Status != "reject" {
			a.Status = "needs_review"
		}
		a.Reasons = append(a.Reasons, reason)
	}
	if isEconomyCandidate(point.Economy) { review("resource identified; caller expectations and server authority need review") }
	nonConcrete := mi.IsAbstract
	for _, word := range strings.Fields(mi.MethodHeader) {
		if word == "native" || word == "abstract" {
			nonConcrete = true
		}
	}
	hasInstruction := false
	for _, line := range mi.RawBody {
		f := strings.Fields(line)
		if len(f) > 0 && !strings.HasPrefix(f[0], ".") && !strings.HasPrefix(f[0], ":") && !strings.HasPrefix(f[0], "#") {
			hasInstruction = true
			break
		}
	}
	if nonConcrete || !hasInstruction {
		a.Status = "reject"
		a.Reasons = append(a.Reasons, "no concrete smali implementation to rewrite")
		return a
	}
	if mi.IsConstructor || mi.Name == "<init>" || mi.Name == "<clinit>" {
		a.Status = "reject"
		a.Reasons = append(a.Reasons, "initializer invariants must be preserved")
		return a
	}
	switch point.SuggestedPatch {
	case PatchReturnTrue, PatchReturnFalse:
		if rt != "Z" && rt != "Ljava/lang/Boolean;" {
			review("boolean intent on non-boolean return; typed fallback changes the requested semantics")
		}
	case PatchReturnVoid:
		if rt != "V" {
			review("void intent on non-void return requires an explicit replacement contract")
		}
	case PatchReturnMaxInt:
		if !isEconomyNumber(rt) {
			review("maximum-integer intent is not defined for this return type")
		}
	case PatchReturnZero:
		if !strings.Contains("ZBSCIJFD", rt) || len(rt) != 1 {
			review("numeric-zero intent on non-numeric return")
		}
	case PatchNop, PatchRemoveCheck, PatchConstReplace:
		review("instruction-level change requires an exact target; a whole-method score is insufficient")
	case "":
		review("no concrete patch strategy selected")
	default:
		a.Status = "reject"
		a.Reasons = append(a.Reasons, "unknown patch strategy")
		return a
	}
	// Do not claim that a type-correct stub preserves writes, synchronization,
	// callbacks or arbitrary callee effects. Constants mentioning opcodes are not
	// instructions and therefore do not trigger this check.
	for _, line := range mi.RawBody {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		op := f[0]
		if strings.HasPrefix(op, "iput") || strings.HasPrefix(op, "sput") || strings.HasPrefix(op, "aput") || strings.HasPrefix(op, "invoke-") || op == "monitor-enter" || op == "monitor-exit" || op == "throw" {
			review("whole-method replacement may discard observable effects; inspect callers and side effects")
			break
		}
	}
	return a
}
func validRecommendationReturn(rt string) bool {
	if len(rt) == 1 {
		return strings.Contains("VZBSCIJFD", rt)
	}
	if strings.HasPrefix(rt, "[") {
		element := strings.TrimLeft(rt, "[")
		return element != "V" && element != "" && validRecommendationReturn(element)
	}
	return strings.HasPrefix(rt, "L") && strings.HasSuffix(rt, ";") && len(rt) > 2 && !strings.ContainsAny(rt[1:len(rt)-1], ";() \t\r\n")
}
func applyRecommendationAssessment(point *PatchPoint, mi *MethodInfo) {
	a := assessRecommendation(point, mi)
	point.RecommendationAssessment = a
	if a.Status == "compatible" {
		return
	}
	if point.RuntimeConfidence == nil {
		point.RuntimeConfidence = &RuntimeConfidence{Probability: point.Confidence}
	}
	point.RuntimeConfidence.NeedsReview = true
	point.RuntimeConfidence.Reasons = append(append([]string(nil), point.RuntimeConfidence.Reasons...), a.Reasons...)
	switch a.Status {
	case "reject":
		point.RuntimeDecision = "reject"
	case "audit_only":
		point.RuntimeDecision = "needs_review"
		point.SuggestedPatch = ""
		point.PatchDesc = "Static audit finding; no automatic rewrite"
	default:
		if point.RuntimeDecision != "reject" {
			point.RuntimeDecision = "needs_review"
		}
	}
}

func (pp *PatchPredictor) auditOnlyPoint(sm *ScoredMethod, reason string) PatchPoint {
	p := PatchPoint{FilePath: sm.ClassPath, ClassName: sm.ClassName, MethodName: sm.Method.Name, MethodSignature: sm.Method.FullSignature, ReturnType: sm.Method.ReturnType, SourceLanguage: sm.Method.SourceLanguage, RiskScore: sm.Score.FinalScore, RiskLevel: pp.classifyRisk(sm.Score.PatchCategory, sm.Score.FinalScore), Confidence: sm.Score.Confidence, Category: sm.Score.PatchCategory, CategoryName: string(sm.Score.PatchCategory), IsAppCode: sm.Method.IsAppCode, IsLibraryCode: !sm.Method.IsAppCode || sm.Method.IsLibrary, VulnSignals: sm.Score.VulnerabilitySignals, WhyVulnerable: append([]string(nil), sm.Score.Reasons...), MatchedParts: append([]string(nil), sm.Score.MatchedParts...), Warnings: []string{"Not an automatic rewrite target: " + reason}, MethodHeader: sm.Method.MethodHeader, MethodBody: sm.Method.RawBody}
	p.Economy = economyForMethod(&sm.Method)
	if p.VulnSignals.HasAny() {
		p.WhyVulnerable = append(p.WhyVulnerable, p.VulnSignals.Explain()...)
	}
	pp.scorer.FinalizeConfidence(&p, sm)
	applyRecommendationAssessment(&p, &sm.Method)
	p.SuggestedPatch = ""
	p.RuntimeDecision = "needs_review"
	p.RecommendationAssessment.Status = "audit_only"
	return p
}
