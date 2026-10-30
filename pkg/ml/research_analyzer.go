package ml

import (
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// RESEARCH ANALYZER - анализ защит для исследований
//
// ⚠️ ВАЖНО: Только анализ и рекомендации, БЕЗ автопатча!
// Для легитимных security research, penetration testing, vulnerability analysis
// ═══════════════════════════════════════════════════════════════════════════════

// ProtectionType тип защиты
type ProtectionType int

const (
	PROTECTION_UNKNOWN ProtectionType = iota
	PROTECTION_ROOT_DETECTION
	PROTECTION_EMULATOR_DETECTION
	PROTECTION_DEBUGGER_DETECTION
	PROTECTION_TAMPER_DETECTION
	PROTECTION_SSL_PINNING
	PROTECTION_OBFUSCATION
	PROTECTION_ANTI_HOOK
	PROTECTION_INTEGRITY_CHECK
	PROTECTION_LICENSE_CHECK
	PROTECTION_PREMIUM_CHECK
	PROTECTION_SERVER_VALIDATION
)

// ProtectionStrength сила защиты
type ProtectionStrength int

const (
	STRENGTH_WEAK ProtectionStrength = iota
	STRENGTH_MEDIUM
	STRENGTH_STRONG
	STRENGTH_VERY_STRONG
)

// ProtectionAnalysis результат анализа защиты
type ProtectionAnalysis struct {
	// Identification
	Type         ProtectionType     `json:"type"`
	TypeName     string             `json:"type_name"`
	Strength     ProtectionStrength `json:"strength"`
	StrengthName string             `json:"strength_name"`

	// Location
	MethodName string `json:"method_name"`
	ClassName  string `json:"class_name"`
	FilePath   string `json:"file_path"`

	// Analysis
	Description string   `json:"description"`
	Indicators  []string `json:"indicators"`
	Weaknesses  []string `json:"weaknesses"`

	// Research insights (БЕЗ конкретных патчей!)
	AnalysisNotes    string   `json:"analysis_notes"`
	ResearchPointers []string `json:"research_pointers"`
	RelatedMethods   []string `json:"related_methods"`

	// Scoring
	BypassDifficulty int     `json:"bypass_difficulty"` // 1-10
	Confidence       float64 `json:"confidence"`
}

// ResearchAnalyzer анализатор защит для исследований
type ResearchAnalyzer struct {
	// Configuration
	enableDeepAnalysis bool
	includeWeaknesses  bool
	includePointers    bool
}

// NewResearchAnalyzer создает analyzer для research
func NewResearchAnalyzer() *ResearchAnalyzer {
	return &ResearchAnalyzer{
		enableDeepAnalysis: true,
		includeWeaknesses:  true,
		includePointers:    true,
	}
}

// Analyze анализирует метод на предмет защит
func (ra *ResearchAnalyzer) Analyze(mi *MethodInfo) *ProtectionAnalysis {
	analysis := &ProtectionAnalysis{
		MethodName:       mi.Name,
		ClassName:        mi.ClassName,
		FilePath:         mi.FilePath,
		Indicators:       []string{},
		Weaknesses:       []string{},
		ResearchPointers: []string{},
		RelatedMethods:   []string{},
	}

	// Detect protection type
	analysis.Type = ra.detectProtectionType(mi)
	analysis.TypeName = ra.getProtectionTypeName(analysis.Type)

	if analysis.Type == PROTECTION_UNKNOWN {
		return nil
	}

	// Analyze strength
	analysis.Strength = ra.analyzeStrength(mi, analysis.Type)
	analysis.StrengthName = ra.getStrengthName(analysis.Strength)

	// Build description
	analysis.Description = ra.buildDescription(mi, analysis.Type)

	// Extract indicators
	analysis.Indicators = ra.extractIndicators(mi, analysis.Type)

	// Analyze weaknesses (для research)
	if ra.includeWeaknesses {
		analysis.Weaknesses = ra.analyzeWeaknesses(mi, analysis.Type, analysis.Strength)
	}

	// Add research pointers (БЕЗ конкретных патчей!)
	if ra.includePointers {
		analysis.ResearchPointers = ra.buildResearchPointers(mi, analysis.Type, analysis.Strength)
	}

	// Calculate bypass difficulty
	analysis.BypassDifficulty = ra.calculateBypassDifficulty(analysis.Strength, len(analysis.Indicators))

	// Build analysis notes
	analysis.AnalysisNotes = ra.buildAnalysisNotes(mi, analysis)

	// Calculate confidence
	analysis.Confidence = ra.calculateConfidence(mi, analysis)

	return analysis
}

// detectProtectionType определяет тип защиты
func (ra *ResearchAnalyzer) detectProtectionType(mi *MethodInfo) ProtectionType {
	nameLower := strings.ToLower(mi.Name)
	classLower := strings.ToLower(mi.ClassName)

	// License/Premium check (проверяем ПЕРВЫМ, т.к. может содержать "verify")
	licenseKeywords := []string{"license", "premium", "subscription", "entitlement", "billing"}
	for _, kw := range licenseKeywords {
		if strings.Contains(nameLower, kw) || strings.Contains(classLower, kw) {
			return PROTECTION_LICENSE_CHECK
		}
	}

	// Root detection
	rootKeywords := []string{"root", "su", "superuser", "magisk"}
	for _, kw := range rootKeywords {
		if strings.Contains(nameLower, kw) || strings.Contains(classLower, kw) {
			return PROTECTION_ROOT_DETECTION
		}
	}

	// Emulator detection
	emuKeywords := []string{"emulator", "emu", "virtual", "qemu", "genymotion"}
	for _, kw := range emuKeywords {
		if strings.Contains(nameLower, kw) || strings.Contains(classLower, kw) {
			return PROTECTION_EMULATOR_DETECTION
		}
	}

	// Debugger detection
	debugKeywords := []string{"debug", "debugger", "traced", "ptrace"}
	for _, kw := range debugKeywords {
		if strings.Contains(nameLower, kw) || strings.Contains(classLower, kw) {
			return PROTECTION_DEBUGGER_DETECTION
		}
	}

	// Tamper detection
	tamperKeywords := []string{"tamper", "integrity", "checksum", "hash"}
	for _, kw := range tamperKeywords {
		if strings.Contains(nameLower, kw) || strings.Contains(classLower, kw) {
			return PROTECTION_TAMPER_DETECTION
		}
	}

	// SSL Pinning
	sslKeywords := []string{"pin", "certificate", "trustmanager", "sslcontext"}
	for _, kw := range sslKeywords {
		if strings.Contains(nameLower, kw) || strings.Contains(classLower, kw) {
			return PROTECTION_SSL_PINNING
		}
	}

	// Anti-hook
	hookKeywords := []string{"hook", "xposed", "frida", "substrate"}
	for _, kw := range hookKeywords {
		if strings.Contains(nameLower, kw) || strings.Contains(classLower, kw) {
			return PROTECTION_ANTI_HOOK
		}
	}

	return PROTECTION_UNKNOWN
}

// analyzeStrength анализирует силу защиты
func (ra *ResearchAnalyzer) analyzeStrength(mi *MethodInfo, protType ProtectionType) ProtectionStrength {
	_ = protType // Acknowledge parameter usage for future implementation
	score := 0

	// Check complexity
	if mi.InstructionCount > 100 {
		score += 2
	} else if mi.InstructionCount > 50 {
		score += 1
	}

	// Check multiple checks
	if mi.IfCheckCount > 5 {
		score += 2
	} else if mi.IfCheckCount > 2 {
		score += 1
	}

	// Check native calls
	for _, call := range mi.Calls {
		if strings.Contains(call.FullCall, "native") {
			score += 2
			break
		}
	}

	// Check obfuscation
	if mi.IsSynthetic || len(mi.Name) < 3 {
		score += 1
	}

	// Check multiple layers
	if len(mi.Calls) > 10 {
		score += 1
	}

	// Determine strength
	if score >= 6 {
		return STRENGTH_VERY_STRONG
	} else if score >= 4 {
		return STRENGTH_STRONG
	} else if score >= 2 {
		return STRENGTH_MEDIUM
	}
	return STRENGTH_WEAK
}

// extractIndicators извлекает индикаторы защиты
func (ra *ResearchAnalyzer) extractIndicators(mi *MethodInfo, protType ProtectionType) []string {
	indicators := []string{}

	// Check method calls
	for _, call := range mi.Calls {
		callLower := strings.ToLower(call.FullCall)

		switch protType {
		case PROTECTION_ROOT_DETECTION:
			if strings.Contains(callLower, "file") ||
				strings.Contains(callLower, "exec") ||
				strings.Contains(callLower, "runtime") {
				indicators = append(indicators, fmt.Sprintf("Suspicious call: %s", call.Method))
			}

		case PROTECTION_EMULATOR_DETECTION:
			if strings.Contains(callLower, "build") ||
				strings.Contains(callLower, "system") ||
				strings.Contains(callLower, "property") {
				indicators = append(indicators, fmt.Sprintf("System property check: %s", call.Method))
			}

		case PROTECTION_DEBUGGER_DETECTION:
			if strings.Contains(callLower, "debug") ||
				strings.Contains(callLower, "applicationinfo") {
				indicators = append(indicators, fmt.Sprintf("Debug check: %s", call.Method))
			}
		}
	}

	// Check string constants
	for _, str := range mi.StringConsts {
		strLower := strings.ToLower(str)

		switch protType {
		case PROTECTION_ROOT_DETECTION:
			rootStrings := []string{"/su", "supersu", "magisk", "busybox"}
			for _, rs := range rootStrings {
				if strings.Contains(strLower, rs) {
					indicators = append(indicators, fmt.Sprintf("Root indicator string: %s", str))
					break
				}
			}

		case PROTECTION_EMULATOR_DETECTION:
			emuStrings := []string{"generic", "goldfish", "emulator", "sdk"}
			for _, es := range emuStrings {
				if strings.Contains(strLower, es) {
					indicators = append(indicators, fmt.Sprintf("Emulator indicator: %s", str))
					break
				}
			}
		}
	}

	return indicators
}

// analyzeWeaknesses анализирует слабости защиты
func (ra *ResearchAnalyzer) analyzeWeaknesses(mi *MethodInfo, protType ProtectionType, strength ProtectionStrength) []string {
	weaknesses := []string{}

	// Weak protection patterns
	if strength == STRENGTH_WEAK {
		weaknesses = append(weaknesses, "Simple boolean return - easy to bypass")
		weaknesses = append(weaknesses, "No obfuscation detected")
		weaknesses = append(weaknesses, "Single-layer check")
	}

	// Check for common mistakes
	if mi.ReturnsBoolean && mi.IsShortMethod {
		weaknesses = append(weaknesses, "Short boolean method - likely simple check")
	}

	if len(mi.Calls) < 3 {
		weaknesses = append(weaknesses, "Few method calls - limited verification")
	}

	// Type-specific weaknesses
	switch protType {
	case PROTECTION_ROOT_DETECTION:
		if !ra.hasNativeCalls(mi) {
			weaknesses = append(weaknesses, "Pure Java implementation - easier to analyze")
		}
		if !ra.hasMultipleChecks(mi) {
			weaknesses = append(weaknesses, "Single check method - no redundancy")
		}

	case PROTECTION_SSL_PINNING:
		if ra.hasEmptyTrustManager(mi) {
			weaknesses = append(weaknesses, "Empty TrustManager implementation detected")
		}
	}

	return weaknesses
}

// buildResearchPointers создает указатели для исследования (БЕЗ патчей!)
func (ra *ResearchAnalyzer) buildResearchPointers(mi *MethodInfo, protType ProtectionType, strength ProtectionStrength) []string {
	_ = mi // Acknowledge parameter usage for future implementation
	pointers := []string{}

	// General research directions
	pointers = append(pointers, "Analyze call chain to understand full protection flow")
	pointers = append(pointers, "Check for multiple protection layers")
	pointers = append(pointers, "Look for server-side validation")

	// Type-specific pointers
	switch protType {
	case PROTECTION_ROOT_DETECTION:
		pointers = append(pointers, "Research: Common root detection methods and their limitations")
		pointers = append(pointers, "Research: File system checks vs runtime checks")
		pointers = append(pointers, "Research: Native vs Java implementation differences")

	case PROTECTION_EMULATOR_DETECTION:
		pointers = append(pointers, "Research: System property fingerprinting techniques")
		pointers = append(pointers, "Research: Hardware characteristic checks")
		pointers = append(pointers, "Research: Timing-based detection methods")

	case PROTECTION_DEBUGGER_DETECTION:
		pointers = append(pointers, "Research: ptrace-based detection mechanisms")
		pointers = append(pointers, "Research: Debug flag checks in ApplicationInfo")
		pointers = append(pointers, "Research: TracerPid monitoring techniques")

	case PROTECTION_SSL_PINNING:
		pointers = append(pointers, "Research: Certificate pinning implementation patterns")
		pointers = append(pointers, "Research: TrustManager customization approaches")
		pointers = append(pointers, "Research: Network security configuration")

	case PROTECTION_LICENSE_CHECK:
		pointers = append(pointers, "Research: License validation flow")
		pointers = append(pointers, "Research: Server-side vs client-side validation")
		pointers = append(pointers, "Research: Token/signature verification methods")
	}

	// Strength-specific pointers
	if strength >= STRENGTH_STRONG {
		pointers = append(pointers, "Advanced: Multi-layer protection analysis required")
		pointers = append(pointers, "Advanced: Consider native code analysis")
		pointers = append(pointers, "Advanced: Look for anti-tampering mechanisms")
	}

	return pointers
}

// buildAnalysisNotes создает заметки для анализа
func (ra *ResearchAnalyzer) buildAnalysisNotes(mi *MethodInfo, analysis *ProtectionAnalysis) string {
	var notes strings.Builder

	notes.WriteString(fmt.Sprintf("Protection Type: %s\n", analysis.TypeName))
	notes.WriteString(fmt.Sprintf("Strength: %s\n", analysis.StrengthName))
	notes.WriteString(fmt.Sprintf("Bypass Difficulty: %d/10\n", analysis.BypassDifficulty))
	notes.WriteString("\n")

	notes.WriteString("Method Characteristics:\n")
	notes.WriteString(fmt.Sprintf("- Instructions: %d\n", mi.InstructionCount))
	notes.WriteString(fmt.Sprintf("- Conditional checks: %d\n", mi.IfCheckCount))
	notes.WriteString(fmt.Sprintf("- Method calls: %d\n", len(mi.Calls)))
	notes.WriteString(fmt.Sprintf("- Return type: %s\n", mi.ReturnType))
	notes.WriteString("\n")

	if len(analysis.Indicators) > 0 {
		notes.WriteString("Key Indicators:\n")
		for _, ind := range analysis.Indicators {
			notes.WriteString(fmt.Sprintf("- %s\n", ind))
		}
		notes.WriteString("\n")
	}

	if len(analysis.Weaknesses) > 0 {
		notes.WriteString("Identified Weaknesses:\n")
		for _, weak := range analysis.Weaknesses {
			notes.WriteString(fmt.Sprintf("- %s\n", weak))
		}
		notes.WriteString("\n")
	}

	notes.WriteString("Research Approach:\n")
	notes.WriteString("1. Map complete protection flow\n")
	notes.WriteString("2. Identify all validation points\n")
	notes.WriteString("3. Analyze server-side dependencies\n")
	notes.WriteString("4. Document protection mechanisms\n")

	return notes.String()
}

// calculateBypassDifficulty вычисляет сложность обхода
func (ra *ResearchAnalyzer) calculateBypassDifficulty(strength ProtectionStrength, indicatorCount int) int {
	base := 0

	switch strength {
	case STRENGTH_WEAK:
		base = 2
	case STRENGTH_MEDIUM:
		base = 4
	case STRENGTH_STRONG:
		base = 7
	case STRENGTH_VERY_STRONG:
		base = 9
	}

	// Adjust based on indicators
	bonus := indicatorCount / 3
	if bonus > 2 {
		bonus = 2
	}

	difficulty := base + bonus
	if difficulty > 10 {
		difficulty = 10
	}

	return difficulty
}

// calculateConfidence вычисляет уверенность в анализе
func (ra *ResearchAnalyzer) calculateConfidence(mi *MethodInfo, analysis *ProtectionAnalysis) float64 {
	confidence := 0.5

	// Boost for indicators
	if len(analysis.Indicators) > 0 {
		confidence += 0.1 * float64(len(analysis.Indicators))
	}

	// Boost for clear naming
	if strings.Contains(strings.ToLower(mi.Name), strings.ToLower(analysis.TypeName)) {
		confidence += 0.2
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// Helper methods

func (ra *ResearchAnalyzer) hasNativeCalls(mi *MethodInfo) bool {
	for _, call := range mi.Calls {
		if strings.Contains(strings.ToLower(call.FullCall), "native") {
			return true
		}
	}
	return false
}

func (ra *ResearchAnalyzer) hasMultipleChecks(mi *MethodInfo) bool {
	return mi.IfCheckCount > 2
}

func (ra *ResearchAnalyzer) hasEmptyTrustManager(mi *MethodInfo) bool {
	// Check if TrustManager methods are empty
	return mi.InstructionCount < 5 && strings.Contains(strings.ToLower(mi.ClassName), "trustmanager")
}

func (ra *ResearchAnalyzer) getProtectionTypeName(t ProtectionType) string {
	switch t {
	case PROTECTION_ROOT_DETECTION:
		return "Root Detection"
	case PROTECTION_EMULATOR_DETECTION:
		return "Emulator Detection"
	case PROTECTION_DEBUGGER_DETECTION:
		return "Debugger Detection"
	case PROTECTION_TAMPER_DETECTION:
		return "Tamper Detection"
	case PROTECTION_SSL_PINNING:
		return "SSL Pinning"
	case PROTECTION_OBFUSCATION:
		return "Obfuscation"
	case PROTECTION_ANTI_HOOK:
		return "Anti-Hook"
	case PROTECTION_INTEGRITY_CHECK:
		return "Integrity Check"
	case PROTECTION_LICENSE_CHECK:
		return "License Check"
	case PROTECTION_PREMIUM_CHECK:
		return "Premium Check"
	case PROTECTION_SERVER_VALIDATION:
		return "Server Validation"
	default:
		return "Unknown"
	}
}

func (ra *ResearchAnalyzer) getStrengthName(s ProtectionStrength) string {
	switch s {
	case STRENGTH_WEAK:
		return "Weak"
	case STRENGTH_MEDIUM:
		return "Medium"
	case STRENGTH_STRONG:
		return "Strong"
	case STRENGTH_VERY_STRONG:
		return "Very Strong"
	default:
		return "Unknown"
	}
}

func (ra *ResearchAnalyzer) buildDescription(mi *MethodInfo, protType ProtectionType) string {
	_ = mi // Acknowledge parameter usage for future implementation
	switch protType {
	case PROTECTION_ROOT_DETECTION:
		return "Detects if device is rooted by checking for su binaries, root management apps, or system modifications"
	case PROTECTION_EMULATOR_DETECTION:
		return "Detects if app is running in emulator by checking system properties and hardware characteristics"
	case PROTECTION_DEBUGGER_DETECTION:
		return "Detects if debugger is attached by checking debug flags or ptrace status"
	case PROTECTION_SSL_PINNING:
		return "Implements certificate pinning to prevent MITM attacks"
	case PROTECTION_LICENSE_CHECK:
		return "Validates license or premium status"
	default:
		return "Security protection mechanism"
	}
}
