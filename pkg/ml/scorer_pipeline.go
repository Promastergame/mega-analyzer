package ml

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SCORE METHOD — главная функция скоринга
// ═══════════════════════════════════════════════════════════════════════════════

// ScoreMethod считает risk score для одного метода
func (ps *PatchScorer) ScoreMethod(mi *MethodInfo) *ScoreResult {
	result := &ScoreResult{
		Reasons:      make([]string, 0, 8),
		Warnings:     make([]string, 0, 4),
		MatchedParts: make([]string, 0, 8),
	}

	// ── Step 1: Quick reject ─────────────────────────────────────
	if !ps.analyzer.IsWorthAnalyzing(mi) {
		result.RiskLevel = RiskClassNone
		return result
	}

	// ── Step 1.5: Detect obfuscation (Task 12.1) ────────────────
	obfInfo := DetectObfuscation(mi)
	result.ObfuscationInfo = &obfInfo
	result.MatchStrategy = obfInfo.RecommendedStrategy

	if obfInfo.IsObfuscated {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Obfuscated code detected (%s, confidence: %.2f)",
				obfInfo.ObfuscationType, obfInfo.Confidence))
	}

	// ── Step 2: Match vulnerable patterns ────────────────────────
	ps.scoreVulnerablePatterns(mi, result)
	ps.scoreEconomyEvidence(mi, result)

	// ── Step 2.3: Match cross-language patterns (Task 19) ────────
	ps.scoreCrossLanguagePatterns(mi, result)

	// ── Step 2.5: Apply structural matching (Task 12.2) ──────────
	if obfInfo.IsObfuscated || result.BaseScore < 20 {
		ps.scoreStructuralMatching(mi, result)
	}

	// ── Step 3: Structural bonuses ───────────────────────────────
	ps.scoreStructure(mi, result)

	// ── Step 4: Safe pattern penalties ───────────────────────────
	ps.scoreSafePatterns(mi, result)

	// ── Step 5: Library penalty ──────────────────────────────────
	ps.scoreLibrary(mi, result)

	rep := CheckReputation(mi)

	// ── Step 6: Context bonuses ──────────────────────────────────
	ps.scoreContext(mi, result, rep)

	// ── Step 6.5: Vulnerability/audit signals ────────────────────
	ps.scoreVulnerabilitySignals(mi, result)

	// ── Step 6.6: Optional anomaly signal ────────────────────────
	ps.applyOptionalModels(mi, result)

	// ── Step 6.7: Suppress known framework/runtime non-gates ──────
	if suppressNoisyPatchCandidate(mi, result.PatchCategory) {
		result.BaseScore = 0
		result.StructuralBonus = 0
		result.ContextBonus = 0
		result.CategoryWeight = 0
		result.PatchCategory = ""
		result.SuggestedPatch = ""
		result.Reasons = append(result.Reasons, "Suppressed noisy framework/runtime helper; not a patchable security gate")
	}

	// ── Step 7: Calculate final score ────────────────────────────
	ps.calculateFinal(mi, result, rep)

	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 2: VULNERABLE PATTERN MATCHING
// ═══════════════════════════════════════════════════════════════════════════════

func (ps *PatchScorer) scoreVulnerablePatterns(mi *MethodInfo, result *ScoreResult) {
	matches := ps.analyzer.MatchVulnerablePatterns(mi)
	result.AllMatches = matches

	if len(matches) == 0 {
		// Нет совпадений с паттернами — пробуем generic matching
		ps.scoreGenericPatterns(mi, result)
		return
	}

	// Сортируем по score (лучший первый)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].MatchScore > matches[j].MatchScore
	})

	// Лучший паттерн
	best := matches[0]
	result.BestPattern = best.Pattern
	result.PatternScore = best.MatchScore
	result.BaseScore = best.MatchScore
	result.SuggestedPatch = best.Pattern.PatchType
	result.PatchCategory = best.Pattern.Category

	// Собираем matched parts
	result.MatchedParts = append(result.MatchedParts, best.MatchedParts...)

	// Описываем причины
	catInfo, hasCat := GetCategoryInfo(best.Pattern.Category)
	if hasCat {
		result.Reasons = append(result.Reasons,
			fmt.Sprintf("Matches '%s' pattern: %s", catInfo.Name, best.Pattern.Description))
		result.CategoryWeight = catInfo.Weight
	} else {
		result.CategoryWeight = 1.0
	}

	// Бонус за множественные совпадения
	if len(matches) > 1 {
		multiBonus := economyPatternBonus(matches)
		result.BaseScore += multiBonus
		result.Reasons = append(result.Reasons,
			fmt.Sprintf("Matches %d vulnerability patterns (+%.0f)", len(matches), multiBonus))
	}
}

// scoreGenericPatterns — fallback если не совпало с конкретными паттернами
func (ps *PatchScorer) scoreGenericPatterns(mi *MethodInfo, result *ScoreResult) {
	var genericScore float64

	// Boolean + check-prefix — generic indicator
	if mi.ReturnsBoolean && mi.HasCheckPrefix {
		genericScore += 15
		result.Reasons = append(result.Reasons, "Boolean method with check/verify prefix")
	}

	// Security-related name без конкретного паттерна
	if mi.HasSecurityName {
		genericScore += 12
		for _, part := range mi.MatchedNameParts {
			result.MatchedParts = append(result.MatchedParts, part)
		}
		result.Reasons = append(result.Reasons, "Method name contains security-related keywords")
	}

	// Security API calls
	if mi.HasSecurityAPI {
		genericScore += 10
		for _, call := range mi.SecurityCalls {
			result.MatchedParts = append(result.MatchedParts, "call:"+call)
		}
		result.Reasons = append(result.Reasons, "Contains security-related API calls")
	}

	// Security strings
	if mi.HasSecurityStrings {
		genericScore += 8
		for _, s := range mi.SecurityStrings {
			if len(s) <= 50 {
				result.MatchedParts = append(result.MatchedParts, "string:"+s)
			}
		}
		result.Reasons = append(result.Reasons, "Contains security-related string constants")
	}

	result.BaseScore = genericScore
	result.CategoryWeight = 1.0

	// Определяем patch type по return
	if mi.ReturnsBoolean {
		// Определяем: return true или return false?
		result.SuggestedPatch = ps.guessDesiredReturn(mi)
	} else if mi.ReturnsVoid {
		result.SuggestedPatch = PatchReturnVoid
	} else if mi.ReturnsInt {
		result.SuggestedPatch = PatchReturnMaxInt
	} else if strings.HasPrefix(mi.ReturnType, "L") || strings.HasPrefix(mi.ReturnType, "[") {
		result.SuggestedPatch = PatchReturnFalse
	}
}

// guessDesiredReturn определяет, нужен ли return true или false
func (ps *PatchScorer) guessDesiredReturn(mi *MethodInfo) PatchType {
	nameLower := mi.NameLower

	// Методы детекции: нужен return false (не обнаружено)
	falsePatterns := []string{
		"root", "emulat", "debug", "tamper", "hook",
		"frida", "xposed", "magisk", "expired", "trial",
		"locked", "modified", "altered",
	}
	for _, p := range falsePatterns {
		if strings.Contains(nameLower, p) {
			return PatchReturnFalse
		}
	}

	// Методы проверки: нужен return true (разрешено)
	// По умолчанию для boolean — return true
	return PatchReturnTrue
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 2.3: CROSS-LANGUAGE PATTERN MATCHING (Task 19)
// ═══════════════════════════════════════════════════════════════════════════════

func (ps *PatchScorer) scoreCrossLanguagePatterns(mi *MethodInfo, result *ScoreResult) {
	// Skip if language is unknown or Java (Java patterns are already covered)
	if mi.SourceLanguage == LanguageUnknown || mi.SourceLanguage == LanguageJava {
		return
	}

	// Match cross-language patterns
	matches := MatchCrossLanguagePatterns(mi, mi.SourceLanguage)
	if len(matches) == 0 {
		return
	}

	// Apply the highest-scoring cross-language pattern
	var bestMatch *CrossLanguagePattern
	var bestScore float64

	for i := range matches {
		pattern := &matches[i]
		score := pattern.Weight * 10.0 // Base score from weight

		if score > bestScore {
			bestScore = score
			bestMatch = pattern
		}
	}

	if bestMatch != nil {
		// Add to base score
		result.BaseScore += bestScore

		// Set category and weight
		result.PatchCategory = bestMatch.Category
		result.CategoryWeight = bestMatch.Weight

		// Add to reasons
		result.Reasons = append(result.Reasons,
			fmt.Sprintf("%s pattern: %s", mi.SourceLanguage, bestMatch.Description))
		result.MatchedParts = append(result.MatchedParts,
			fmt.Sprintf("cross-lang:%s", mi.SourceLanguage))

		// Add language info to warnings
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Source language: %s", GetLanguageDescription(mi.SourceLanguage)))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 2.5: STRUCTURAL MATCHING (Task 12.2)
// ═══════════════════════════════════════════════════════════════════════════════

func (ps *PatchScorer) scoreStructuralMatching(mi *MethodInfo, result *ScoreResult) {
	// Apply structural matching rules
	structuralMatches, structuralScore := MatchStructuralRules(mi)
	result.StructuralMatchScore = structuralScore

	if len(structuralMatches) == 0 {
		return
	}

	// Add structural matches to reasons
	for _, match := range structuralMatches {
		result.Reasons = append(result.Reasons,
			fmt.Sprintf("Structural pattern: %s", match.Description))
		result.MatchedParts = append(result.MatchedParts,
			fmt.Sprintf("structural:%s", match.Type))
	}

	// Apply hybrid matching strategy (Task 12.3)
	if result.ObfuscationInfo != nil && result.ObfuscationInfo.IsObfuscated {
		hybridResult := ApplyHybridMatching(mi, result.BaseScore)

		// Adjust base score based on strategy
		switch hybridResult.Strategy {
		case StrategyStructural:
			// Heavily obfuscated: rely on structural matching
			result.BaseScore = hybridResult.TotalScore
			result.Confidence = hybridResult.Confidence
			result.Reasons = append(result.Reasons,
				"Using structural matching due to heavy obfuscation")

		case StrategyHybrid:
			// Partially obfuscated: balance both
			result.BaseScore = hybridResult.TotalScore
			result.Confidence = hybridResult.Confidence
			result.Reasons = append(result.Reasons,
				"Using hybrid matching (name + structural)")
		}
	} else {
		// Not obfuscated but low name match: boost with structural
		if result.BaseScore < 20 && structuralScore > 15 {
			result.BaseScore += structuralScore * 0.5
			result.Reasons = append(result.Reasons,
				fmt.Sprintf("Structural matching boost (+%.1f)", structuralScore*0.5))
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 3: STRUCTURAL BONUSES
// ═══════════════════════════════════════════════════════════════════════════════

func (ps *PatchScorer) scoreStructure(mi *MethodInfo, result *ScoreResult) {
	var bonus float64

	// Boolean return
	if mi.ReturnsBoolean {
		bonus += StructuralBonuses[0].Bonus * ps.config.StructuralWeight
		result.MatchedParts = append(result.MatchedParts, "structure:boolean_return")
	}

	// Dual return (true + false paths)
	if mi.HasDualReturn {
		bonus += StructuralBonuses[1].Bonus * ps.config.StructuralWeight
		result.Reasons = append(result.Reasons, "Has both true/false return paths")
	}

	// Short method (3-30 instructions)
	if mi.IsShortMethod {
		bonus += StructuralBonuses[2].Bonus * ps.config.StructuralWeight
	}

	// If with return
	if mi.HasIfWithReturn {
		bonus += StructuralBonuses[3].Bonus * ps.config.StructuralWeight
		result.Reasons = append(result.Reasons, "Contains if-check followed by return")
	}

	// App code bonus
	if mi.IsAppCode {
		bonus += StructuralBonuses[4].Bonus * ps.config.StructuralWeight
		result.MatchedParts = append(result.MatchedParts, "context:app_code")
	}

	// Check prefix in name
	if mi.HasCheckPrefix {
		bonus += StructuralBonuses[6].Bonus * ps.config.StructuralWeight * 0.5
	}

	// Multiple if-checks (complex verification logic)
	if mi.IfCheckCount >= 3 && mi.ReturnsBoolean {
		bonus += 8 * ps.config.StructuralWeight
		result.Reasons = append(result.Reasons,
			fmt.Sprintf("Complex verification logic (%d conditional checks)", mi.IfCheckCount))
	}

	// Public method = более интересная цель
	if mi.IsPublic {
		bonus += 3
	}

	result.StructuralBonus = bonus
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 4: SAFE PATTERN PENALTIES
// ═══════════════════════════════════════════════════════════════════════════════

func (ps *PatchScorer) scoreSafePatterns(mi *MethodInfo, result *ScoreResult) {
	if isResourceValueMethod(mi) { return }
	isSafe, penalty, safeName := ps.analyzer.MatchSafePatterns(mi)

	if !isSafe {
		return
	}

	// Если метод совпал с safe pattern, но ТАКЖЕ совпал с vulnerable pattern —
	// уменьшаем penalty (security context перевешивает)
	if result.BaseScore > 20 && (mi.HasSecurityName || mi.HasSecurityAPI) {
		penalty *= 0.3 // значительно уменьшаем penalty
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Matches safe pattern '%s' but has security context — reduced penalty", safeName))
	} else {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Matches safe pattern: %s", safeName))
	}

	result.SafePenalty = penalty * ps.config.SafePatternScale
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 5: LIBRARY PENALTY
// ═══════════════════════════════════════════════════════════════════════════════

func (ps *PatchScorer) scoreLibrary(mi *MethodInfo, result *ScoreResult) {
	if !mi.IsLibrary {
		return
	}

	result.LibraryPenalty = LibraryPenalty * ps.config.LibraryPenaltyScale
	result.Warnings = append(result.Warnings, "Located in library code (less likely patch target)")
}

// ═══════════════════════════════════════════════════════════════════════════════
// STEP 6: CONTEXT BONUSES
// ═══════════════════════════════════════════════════════════════════════════════

var securityPathKeywords = []string{
	"license", "security", "checker", "validator",
	"verifier", "protector", "guard", "shield",
	"integrity", "tamper", "billing", "purchase",
	"premium", "subscription", "trial",
}

func (ps *PatchScorer) scoreContext(mi *MethodInfo, result *ScoreResult, rep *ReputationVerdict) {
	var bonus float64

	// ── Phase 6: Skip context bonuses for trusted frameworks ─────
	// Если метод в trusted framework — context bonuses не применяются.
	if rep != nil && rep.IsTrusted {
		result.ContextBonus = 0
		return
	}

	// Бонус за security-related класс (другие методы тоже security)
	// Это проверяется через ClassInfo.HasSecurityContext
	// На уровне метода — проверяем имя файла
	pathLower := strings.ToLower(mi.FilePath)

	for _, name := range securityPathKeywords {
		if strings.Contains(pathLower, name) {
			bonus += 8 * ps.config.ContextWeight
			result.Reasons = append(result.Reasons,
				fmt.Sprintf("Located in security-related class (path contains '%s')", name))
			break
		}
	}

	// Бонус за комбинацию: boolean + security name + security calls
	securitySignals := 0
	if mi.ReturnsBoolean {
		securitySignals++
	}
	if mi.HasSecurityName {
		securitySignals++
	}
	if mi.HasSecurityAPI {
		securitySignals++
	}
	if mi.HasSecurityStrings {
		securitySignals++
	}
	if mi.HasCheckPrefix {
		securitySignals++
	}

	if securitySignals >= 3 {
		comboBonus := float64(securitySignals-2) * 8.0
		bonus += comboBonus
		result.Reasons = append(result.Reasons,
			fmt.Sprintf("Strong security signal combination (%d/5 indicators)", securitySignals))
	}

	result.ContextBonus = bonus
}

func (ps *PatchScorer) scoreVulnerabilitySignals(mi *MethodInfo, result *ScoreResult) {
	vs := AnalyzeVulnerabilitySignals(mi)
	if vs == nil || !vs.HasAny() {
		return
	}
	result.VulnerabilitySignals = vs

	// Audit signals win over name-pattern guesses: a confirmed signal knows
	// exactly which boolean gate the method implements.
	if pt, ok := signalSuggestedPatch(vs); ok {
		result.SuggestedPatch = pt
		result.Reasons = append(result.Reasons,
			fmt.Sprintf("Audit signal drives suggested patch: %s", pt))
	}

	boost := 0.0
	for _, signal := range vs.Signals {
		switch signal.Severity {
		case VulnSeverityCritical:
			boost += 42.0 * signal.Confidence
		case VulnSeverityHigh:
			boost += 32.0 * signal.Confidence
		case VulnSeverityMedium:
			boost += 22.0 * signal.Confidence
		case VulnSeverityLow:
			boost += 8.0 * signal.Confidence
		}
		result.Reasons = append(result.Reasons,
			fmt.Sprintf("Audit signal [%s]: %s", signal.Severity, signal.Description))
		result.MatchedParts = append(result.MatchedParts, fmt.Sprintf("vuln:%s", signal.Kind))
	}
	if boost > 55.0 {
		boost = 55.0
	}

	if result.BaseScore < boost {
		result.BaseScore = boost
	} else {
		result.ContextBonus += boost * 0.35
	}

	// Confirmed semantic signals take precedence over broad pattern guesses.
	// This prevents an age gate containing generic "ad" context from being
	// reported as Ad Control.
	signalCategory := categoryForVulnSignals(vs)
	if signalCategory != "" {
		result.PatchCategory = signalCategory
		if info, ok := GetCategoryInfo(result.PatchCategory); ok {
			result.CategoryWeight = info.Weight
		}
	}
}

// signalSuggestedPatch maps confirmed audit signals to the exact patch type
// the gated method needs: detection gates (root/emulator/debug/tamper/trial
// expiry) want return_false, access gates (auth/age/premium/license/biometric/
// payment) want return_true. Non-boolean signals leave the patch type alone.
func signalSuggestedPatch(vs *VulnerabilitySignals) (PatchType, bool) {
	if vs == nil {
		return "", false
	}
	for _, s := range vs.Signals {
		if pt, ok := vulnKindPatchType(s.Kind); ok {
			return pt, true
		}
	}
	return "", false
}

// vulnKindPatchType returns the patch type a confirmed signal calls for.
func vulnKindPatchType(kind VulnKind) (PatchType, bool) {
	switch kind {
	case VulnRootDetectionBypass, VulnEmulatorCheckBypass, VulnDebugCheckBypass,
		VulnTamperCheckBypass, VulnTrialPeriodCheck, VulnFridaArtifacts:
		return PatchReturnFalse, true
	case VulnAuthCheckBypass, VulnAgeVerification, VulnPremiumFeatureGate,
		VulnLicenseLocalOnly, VulnBiometricLocalOnly, VulnPaymentClientSide:
		return PatchReturnTrue, true
	}
	return "", false
}

func categoryForVulnSignals(vs *VulnerabilitySignals) PatchCategory {
	if vs == nil || len(vs.Signals) == 0 {
		return PatchCatTamper
	}
	for _, signal := range vs.Signals {
		if signal.Kind == VulnAgeVerification {
			return PatchCatAgeVerification
		}
	}
	switch vs.Signals[0].Kind {
	case VulnClientSideCurrency:
		return PatchCatCurrency
	case VulnLicenseCheckClient, VulnLicenseLocalOnly:
		// Do not relabel a licensing audit signal as generic tamper detection.
		return PatchCatLicense
	case VulnHTTPSCertBypass, VulnInsecureTransport, VulnEndpointOverride, VulnDebugBackend, VulnWeakJWTHandling:
		return PatchCatServerAuth
	case VulnClientAccountTrust, VulnHardcodedSecret, VulnWeakCrypto, VulnUnsafeDeserialization:
		return PatchCatIntegrity
	case VulnWebViewBridge, VulnWebViewConfig, VulnMutablePendingIntent, VulnDynamicCodeLoading, VulnReflectionWithCrypto, VulnRuntimeExec, VulnRootCommandExec,
		VulnNativeExternalLoad, VulnAntiVMParanoid, VulnAppDropper:
		return PatchCatTamper
	default:
		return PatchCatTamper
	}
}

func (ps *PatchScorer) applyOptionalModels(mi *MethodInfo, result *ScoreResult) {
	if ps == nil || mi == nil || result == nil || ps.anomalyScorer == nil {
		return
	}
	score := ps.anomalyScorer.Score(methodMLFeatures(mi, result))
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return
	}
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	result.AnomalyScore = score
	if score >= 0.6 {
		bonus := math.Min(score*8.0, 8.0)
		result.ContextBonus += bonus
		result.Reasons = append(result.Reasons, fmt.Sprintf("anomaly model signal (+%.1f)", bonus))
	}
}

func suppressNoisyPatchCandidate(mi *MethodInfo, category PatchCategory) bool {
	if mi == nil {
		return false
	}
	ctx := strings.ToLower(mi.ClassName + " " + mi.FilePath + " " + mi.Name)
	name := strings.ToLower(mi.Name)
	if strings.Contains(ctx, "billingclient/api/billingclientimpl") && name == "isready" {
		return true
	}
	if strings.Contains(ctx, "badlogic/gdx/utils") || strings.Contains(ctx, "application/csoundplayer") {
		return true
	}
	if category == PatchCatServerAuth && (name == "equal" || name == "isonwifi") {
		return true
	}
	if strings.Contains(ctx, "extensions/cruninappandroid") && strings.HasPrefix(name, "exp") {
		return true
	}
	if category == PatchCatFeatureGate || category == PatchCatBilling {
		if name == "checkcpu" || name == "checkmask" {
			return true
		}
	}
	return false
}
