package ml

import (
	"context"
	"sort"
	"strings"
	"unicode"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH ANALYZER — парсит smali методы и извлекает структурные признаки
//
// Анализирует:
//   - Структуру метода (return type, if-checks, branches)
//   - Имена методов и классов
//   - API вызовы (invoke-*)
//   - Строковые константы (const-string)
//   - Контекст (app code vs library)
// ═══════════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════════
// METHOD INFO — извлечённая информация о методе
// ═══════════════════════════════════════════════════════════════════════════════

// MethodInfo — полная информация о smali методе для scoring
type MethodInfo struct {
	// ── Идентификация ────────────────────────────────────────────
	Name          string `json:"name"`
	ClassName     string `json:"class_name"`
	FilePath      string `json:"file_path"`
	FullSignature string `json:"full_signature"`
	LineStart     int    `json:"line_start,omitempty"` // 1-based physical smali line
	LineEnd       int    `json:"line_end,omitempty"`

	// ── Return type ──────────────────────────────────────────────
	ReturnType     string `json:"return_type"` // Z, V, I, J, Ljava/lang/String;
	ReturnsBoolean bool   `json:"returns_boolean"`
	ReturnsVoid    bool   `json:"returns_void"`
	ReturnsInt     bool   `json:"returns_int"`

	// ── Access flags ─────────────────────────────────────────────
	IsPublic    bool `json:"is_public"`
	IsPrivate   bool `json:"is_private"`
	IsStatic    bool `json:"is_static"`
	IsFinal     bool `json:"is_final"`
	IsAbstract  bool `json:"is_abstract"`
	IsSynthetic bool `json:"is_synthetic"`

	// ── Структура ────────────────────────────────────────────────
	InstructionCount int  `json:"instruction_count"`
	RegisterCount    int  `json:"register_count"`
	ReturnCount      int  `json:"return_count"`
	IfCheckCount     int  `json:"if_check_count"`
	HasDualReturn    bool `json:"has_dual_return"`    // return true + return false
	HasIfWithReturn  bool `json:"has_if_with_return"` // if-eqz → return
	IsShortMethod    bool `json:"is_short_method"`    // 3-20 инструкций

	// ── Вызовы (invoke-*) ────────────────────────────────────────
	Calls          []CallInfo `json:"calls"`
	SecurityCalls  []string   `json:"security_calls"`
	HasSecurityAPI bool       `json:"has_security_api"`

	// ── Строковые константы ──────────────────────────────────────
	StringConsts       []string `json:"string_consts"`
	SecurityStrings    []string `json:"security_strings"`
	HasSecurityStrings bool     `json:"has_security_strings"`

	// ── Контекст ─────────────────────────────────────────────────
	IsAppCode     bool `json:"is_app_code"`
	IsLibrary     bool `json:"is_library"`
	IsConstructor bool `json:"is_constructor"`
	IsAccessor    bool `json:"is_accessor"` // access$000
	IsCallback    bool `json:"is_callback"` // onClick, onResume

	// ── Name analysis ────────────────────────────────────────────
	NameLower        string   `json:"name_lower"`
	ClassNameLower   string   `json:"class_name_lower"`   // 🆕 кэшированная lowercase версия класса
	HasCheckPrefix   bool     `json:"has_check_prefix"`   // is*, check*, verify*
	HasSecurityName  bool     `json:"has_security_name"`  // имя связано с security
	MatchedNameParts []string `json:"matched_name_parts"` // какие части имени совпали

	// ── Cross-language support ───────────────────────────────────
	SourceLanguage SourceLanguage `json:"source_language"` // Java, Kotlin, React Native, Flutter, Unity
	ClassPath      string         `json:"class_path"`      // Full class path for language detection

	// ── Raw body (для генерации патча) ───────────────────────────
	RawBody           []string `json:"-"` // строки тела метода
	MethodHeader      string   `json:"-"` // .method public isLicensed()Z
	MethodFooter      string   `json:"-"` // .end method
	cachedMetaContext string   `json:"-"`
	Economy           *EconomyInfo `json:"economy,omitempty"`
	economyScanned    bool
}

// CallInfo — информация о вызове
type CallInfo struct {
	Type              string `json:"type"` // virtual, static, direct, interface
	Class             string `json:"class"`
	Method            string `json:"method"`
	FullCall          string `json:"full_call"`
	Signature         string `json:"signature,omitempty"` // exact, case-preserving DEX descriptor
	Line              int    `json:"line,omitempty"`      // 1-based physical smali line
	IsSecurityRelated bool   `json:"is_security_related"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLASS INFO — информация о всём файле/классе
// ═══════════════════════════════════════════════════════════════════════════════

// ClassInfo — информация о smali классе
type ClassInfo struct {
	FilePath     string       `json:"file_path"`
	ClassName    string       `json:"class_name"`
	SuperClass   string       `json:"super_class"`
	Interfaces   []string     `json:"interfaces,omitempty"`
	IsAppCode    bool         `json:"is_app_code"`
	IsLibrary    bool         `json:"is_library"`
	Methods      []MethodInfo `json:"methods"`
	TotalMethods int          `json:"total_methods"`

	// Агрегированные метрики
	SecurityMethodCount int  `json:"security_method_count"`
	BooleanMethodCount  int  `json:"boolean_method_count"`
	HasSecurityContext  bool `json:"has_security_context"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

// PatchAnalyzer анализирует smali файлы для поиска патч-точек
type PatchAnalyzer struct {
	// Предвычисленные lowercase паттерны для быстрого поиска
	securityCallPatterns   []string
	securityStringPatterns []string
	checkPrefixes          []string
	callbackPrefixes       []string

	// String interning pool для уменьшения аллокаций
	internPool map[string]string

	// Pattern index для O(1) lookup (Task 4.2)
	patternIndex *PatternIndex
	economyIndex economyResolver
}

// NewPatchAnalyzer создаёт анализатор
func NewPatchAnalyzer() *PatchAnalyzer {
	pa := &PatchAnalyzer{
		checkPrefixes: []string{
			"is", "has", "can", "check", "verify", "validate",
			"should", "allow", "detect", "test",
		},
		callbackPrefixes: []string{
			"on", "handle", "dispatch", "process",
			"callback", "listener",
		},
		internPool:   make(map[string]string, 1024),
		patternIndex: GetPatternIndex(), // Task 4.2: Indexed lookup
	}

	// Собираем все security-related вызовы из VulnerablePatterns
	callSet := make(map[string]bool)
	stringSet := make(map[string]bool)

	for _, vp := range VulnerablePatterns {
		for _, call := range vp.RequiredCalls {
			lower := strings.ToLower(call)
			if !callSet[lower] {
				callSet[lower] = true
				// Pre-lowercase и intern security patterns
				pa.securityCallPatterns = append(pa.securityCallPatterns, pa.intern(lower))
			}
		}
		for _, s := range vp.StringPatterns {
			lower := strings.ToLower(s)
			if !stringSet[lower] {
				stringSet[lower] = true
				// Pre-lowercase и intern security patterns
				pa.securityStringPatterns = append(pa.securityStringPatterns, pa.intern(lower))
			}
		}
	}

	// Pre-intern common strings
	commonStrings := []string{
		"Z", "V", "I", "J", "F", "D", "B", "C", "S",
		"public", "private", "static", "final", "abstract", "synthetic",
		"<init>", "<clinit>",
		"virtual", "static", "direct", "interface", "super",
		"boolean", "void", "int", "long",
	}
	for _, s := range commonStrings {
		pa.intern(s)
	}

	return pa
}

// intern возвращает интернированную строку из пула
func (pa *PatchAnalyzer) intern(s string) string {
	if interned, ok := pa.internPool[s]; ok {
		return interned
	}
	pa.internPool[s] = s
	return s
}

// GetPatterns returns all vulnerable patterns for feedback integration
// Requirements: 12.3
func (pa *PatchAnalyzer) GetPatterns() []VulnerablePattern {
	if pa == nil || pa.patternIndex == nil {
		return nil
	}
	patterns := make([]VulnerablePattern, 0, len(pa.patternIndex.AllPatterns))
	for _, pattern := range pa.patternIndex.AllPatterns {
		if pattern != nil {
			patterns = append(patterns, *pattern)
		}
	}
	return patterns
}

// GetIndexedPatterns returns the live pattern objects used by matching. It is
// intentionally separate from GetPatterns, which returns defensive copies for
// reporting callers. Feedback integration must update these live objects or
// learned weights never reach MatchVulnerablePatterns.
func (pa *PatchAnalyzer) GetIndexedPatterns() []*VulnerablePattern {
	if pa == nil || pa.patternIndex == nil {
		return nil
	}
	return pa.patternIndex.AllPatterns
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYZE FILE — главная точка входа
// ═══════════════════════════════════════════════════════════════════════════════

// AnalyzeSmaliContent анализирует содержимое smali файла
func (pa *PatchAnalyzer) AnalyzeSmaliContent(filePath string, content []byte) *ClassInfo {
	return pa.analyzeSmaliContent(filePath, content, false)
}

// analyzeSmaliContent optionally retains only methods that are useful to the
// batch patch pipeline. The exported API keeps complete class information so
// callers that need confidence, obfuscation, or safe-method analysis do not
// silently lose methods.
func (pa *PatchAnalyzer) analyzeSmaliContent(filePath string, content []byte, retainOnlyCandidates bool) *ClassInfo {
	lineBuf := splitLinesPooled(content)
	defer PutLineBuffer(lineBuf)
	lines := lineBuf.Lines

	// Task 6.1: Get ClassInfo from pool
	classInfo := GetClassInfo()
	classInfo.FilePath = filePath

	// Парсим заголовок класса
	pa.parseClassHeader(classInfo, lines)

	// Определяем app code / library
	normalizedPath := normalizePath(filePath)
	classInfo.IsLibrary = IsLibraryPath(normalizedPath)
	classInfo.IsAppCode = !classInfo.IsLibrary

	// Парсим методы (сохраняя только кандидаты для анализа)
	pa.extractMethodsFiltered(classInfo, lines, retainOnlyCandidates)

	for i := range classInfo.Methods {
		m := &classInfo.Methods[i]
		m.FilePath = filePath
		m.ClassName = classInfo.ClassName
		m.ClassNameLower = strings.ToLower(classInfo.ClassName) // 🆕 кэшируем lowercase
		m.ClassPath = classInfo.ClassName                       // Set ClassPath for language detection
		m.IsAppCode = classInfo.IsAppCode
		m.IsLibrary = classInfo.IsLibrary
	}
	classInfo.HasSecurityContext = classInfo.SecurityMethodCount > 0

	return classInfo
}

// ═══════════════════════════════════════════════════════════════════════════════
// PARSE CLASS HEADER
// ═══════════════════════════════════════════════════════════════════════════════

func (pa *PatchAnalyzer) parseClassHeader(ci *ClassInfo, lines []string) {
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if hasSmaliDirective(trimmed, ".class") {
			ci.ClassName = pa.intern(extractLastToken(smaliCodeLine(trimmed)))
		} else if hasSmaliDirective(trimmed, ".super") {
			ci.SuperClass = pa.intern(extractLastToken(smaliCodeLine(trimmed)))
		} else if hasSmaliDirective(trimmed, ".implements") {
			ci.Interfaces = append(ci.Interfaces, pa.intern(extractLastToken(smaliCodeLine(trimmed))))
		}

		// После .super обычно идут поля/методы
		if hasSmaliDirective(trimmed, ".field") || hasSmaliDirective(trimmed, ".method") {
			break
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACT METHODS — находит все методы в файле
// ═══════════════════════════════════════════════════════════════════════════════

func (pa *PatchAnalyzer) extractMethods(ci *ClassInfo, lines []string) {
	pa.extractMethodsFiltered(ci, lines, false)
}

func (pa *PatchAnalyzer) extractMethodsFiltered(ci *ClassInfo, lines []string, retainOnlyCandidates bool) {
	inMethod := false
	var methodLines []string
	var methodHeader string
	methodStart := 0

	for lineIndex, line := range lines {
		trimmed := smaliCodeLine(line)

		if hasSmaliDirective(trimmed, ".method") {
			inMethod = true
			methodHeader = trimmed
			methodStart = lineIndex
			methodLines = make([]string, 0, 32)
			methodLines = append(methodLines, line)
			continue
		}

		if strings.Join(strings.Fields(trimmed), " ") == ".end method" && inMethod {
			methodLines = append(methodLines, line)

			// Анализируем метод
			mi := pa.analyzeMethod(methodHeader, methodLines)
			if mi != nil {
				mi.LineStart, mi.LineEnd = methodStart+1, lineIndex+1
				mi.FilePath, mi.ClassName, mi.ClassPath = ci.FilePath, ci.ClassName, ci.ClassName
				mi.ClassNameLower = strings.ToLower(ci.ClassName)
				mi.IsAppCode, mi.IsLibrary = ci.IsAppCode, ci.IsLibrary
				mi.Economy, _ = analyzeEconomyMethod(mi, pa.economyIndex)
				mi.economyScanned = true
				for j := range mi.Calls {
					mi.Calls[j].Line += methodStart
				}
				ci.TotalMethods++
				if mi.ReturnsBoolean {
					ci.BooleanMethodCount++
				}
				if mi.HasSecurityAPI || mi.HasSecurityStrings || mi.HasSecurityName {
					ci.SecurityMethodCount++
				}
				if !retainOnlyCandidates || pa.IsWorthAnalyzing(mi) {
					// Transfer ownership: a shallow copy followed by pool reuse used to
					// overwrite earlier methods with the last method's calls/strings.
					ci.Methods = append(ci.Methods, *mi)
					*mi = MethodInfo{}
				}
				PutMethodInfo(mi)
			}

			inMethod = false
			methodLines = nil
			continue
		}

		if inMethod {
			methodLines = append(methodLines, line)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYZE METHOD — детальный анализ одного метода
// ═══════════════════════════════════════════════════════════════════════════════

func (pa *PatchAnalyzer) analyzeMethod(header string, body []string) *MethodInfo {
	// Task 6.1: Get MethodInfo from pool instead of allocating
	mi := GetMethodInfo()
	mi.RawBody = body
	mi.MethodHeader = header
	mi.MethodFooter = ".end method"

	// ── Парсим заголовок метода ──────────────────────────────────
	pa.parseMethodHeader(mi, header)

	// ── Парсим тело метода ───────────────────────────────────────
	pa.parseMethodBody(mi, body)

	// ── Анализируем имя метода ───────────────────────────────────
	pa.analyzeMethodName(mi)

	// ── Структурный анализ ───────────────────────────────────────
	pa.analyzeStructure(mi)

	// ── Матчим security паттерны ─────────────────────────────────
	pa.matchSecurityPatterns(mi)

	// ── Определяем source language ───────────────────────────────
	mi.SourceLanguage = DetectSourceLanguage(mi)

	return mi
}

// ═══════════════════════════════════════════════════════════════════════════════
// PARSE METHOD HEADER
// ═══════════════════════════════════════════════════════════════════════════════

func (pa *PatchAnalyzer) parseMethodHeader(mi *MethodInfo, header string) {
	// .method public static isRooted()Z
	header = smaliCodeLine(header)
	header = strings.Join(strings.Fields(header), " ")
	headerLower := strings.ToLower(header)

	// Access flags
	mi.IsPublic = strings.Contains(headerLower, " public ")
	mi.IsPrivate = strings.Contains(headerLower, " private ")
	mi.IsStatic = strings.Contains(headerLower, " static ")
	mi.IsFinal = strings.Contains(headerLower, " final ")
	mi.IsAbstract = strings.Contains(headerLower, " abstract")
	mi.IsSynthetic = strings.Contains(headerLower, " synthetic ")

	// Извлекаем имя метода и return type
	// Формат: .method [flags] name(params)ReturnType
	if idx := strings.LastIndex(header, ")"); idx >= 0 {
		mi.ReturnType = pa.intern(strings.TrimSpace(header[idx+1:]))
	}

	// Имя метода — между последним пробелом и первой скобкой
	if parenIdx := strings.Index(header, "("); parenIdx >= 0 {
		beforeParen := header[:parenIdx]
		if spaceIdx := strings.LastIndex(beforeParen, " "); spaceIdx >= 0 {
			mi.Name = pa.intern(beforeParen[spaceIdx+1:])
		}
	}

	mi.NameLower = pa.intern(strings.ToLower(mi.Name))

	// FullSignature
	mi.FullSignature = mi.Name + "(" + extractParamsFromHeader(header) + ")" + mi.ReturnType

	// Return type flags
	mi.ReturnsBoolean = mi.ReturnType == "Z"
	mi.ReturnsVoid = mi.ReturnType == "V"
	mi.ReturnsInt = mi.ReturnType == "I" || mi.ReturnType == "J"

	// Constructor check
	mi.IsConstructor = mi.Name == "<init>" || mi.Name == "<clinit>"

	// Accessor check
	mi.IsAccessor = strings.HasPrefix(mi.NameLower, "access$")
}

// ═══════════════════════════════════════════════════════════════════════════════
// PARSE METHOD BODY
// ═══════════════════════════════════════════════════════════════════════════════

func (pa *PatchAnalyzer) parseMethodBody(mi *MethodInfo, body []string) {
	returnTrueCount := 0
	returnFalseCount := 0
	lastWasIf := false
	prevInstructionWasConst0 := false
	prevInstructionWasConst1 := false
	previousConstRegister := ""
	var nonCode smaliNonCodeState

	for lineIndex, line := range body {
		trimmed := smaliCodeLine(line)
		if nonCode.skip(trimmed) {
			continue
		}
		trimmedLower := strings.ToLower(trimmed)

		// Пропускаем пустые строки, комментарии, директивы
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, ".") {
			// Директивы: .registers, .locals, .line, .param, etc.
			if hasSmaliDirective(trimmed, ".registers") {
				mi.RegisterCount = extractIntAfter(strings.Join(strings.Fields(trimmed), " "), ".registers ")
			} else if hasSmaliDirective(trimmed, ".locals") {
				if mi.RegisterCount == 0 {
					mi.RegisterCount = extractIntAfter(strings.Join(strings.Fields(trimmed), " "), ".locals ")
				}
			}
			continue
		}
		if strings.HasPrefix(trimmed, ":") {
			// Labels
			continue
		}

		mi.InstructionCount++

		// ── invoke-* вызовы ────���─────────────────────────────────
		if strings.HasPrefix(trimmedLower, "invoke-") {
			call := pa.parseInvoke(trimmed)
			if call != nil {
				call.Line = lineIndex + 1
				mi.Calls = append(mi.Calls, *call)
			}
		}

		// ── const-string ─────────────────────────────────────────
		if strings.HasPrefix(trimmedLower, "const-string") {
			str := extractConstString(trimmed)
			if str != "" {
				mi.StringConsts = append(mi.StringConsts, str)
			}
		}

		// ── if-* проверки ────────────────────────────────────────
		if strings.HasPrefix(trimmedLower, "if-") {
			mi.IfCheckCount++
			lastWasIf = true
		} else {
			if lastWasIf && (strings.HasPrefix(trimmedLower, "const/4 v") ||
				strings.HasPrefix(trimmedLower, "const/16 v")) {
				// if → const → вероятно return
			}
			lastWasIf = false
		}

		// ── return ───────────────────────────────────────────────
		if strings.HasPrefix(trimmedLower, "return") {
			mi.ReturnCount++

			// Отслеживаем return true / return false
			returnFields := strings.Fields(trimmed)
			sameRegister := len(returnFields) == 2 && returnFields[1] == previousConstRegister
			if prevInstructionWasConst1 && sameRegister {
				returnTrueCount++
			}
			if prevInstructionWasConst0 && sameRegister {
				returnFalseCount++
			}
		}

		// ── Отслеживаем const/4 v0, 0x0 и const/4 v0, 0x1 ──────
		prevInstructionWasConst0 = false
		prevInstructionWasConst1 = false
		previousConstRegister = ""
		if strings.HasPrefix(trimmedLower, "const/") || strings.HasPrefix(trimmedLower, "const ") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				previousConstRegister = strings.TrimSuffix(fields[1], ",")
			}
			if strings.HasSuffix(trimmedLower, "0x0") || strings.HasSuffix(trimmedLower, ", 0") {
				prevInstructionWasConst0 = true
			}
			if strings.HasSuffix(trimmedLower, "0x1") || strings.HasSuffix(trimmedLower, ", 1") {
				prevInstructionWasConst1 = true
			}
		}
	}

	// Dual return detection
	mi.HasDualReturn = returnTrueCount > 0 && returnFalseCount > 0

	// If with return detection
	mi.HasIfWithReturn = mi.IfCheckCount > 0 && mi.ReturnCount >= 2
}

// ═══════════════════════════════════════════════════════════════════════════════
// PARSE INVOKE
// ═══════════════════════════════════════════════════════════════════════════════

func (pa *PatchAnalyzer) parseInvoke(line string) *CallInfo {
	line = smaliCodeLine(line)
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "invoke-") {
		return nil
	}
	closeBrace := strings.IndexByte(line, '}')
	if closeBrace < 0 {
		return nil
	}
	reference := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line[closeBrace+1:]), ","))
	arrow := strings.Index(reference, ";->")
	if arrow < 1 || reference[0] != 'L' {
		return nil
	}
	owner := reference[1:arrow]
	tail := reference[arrow+3:]
	paren := strings.IndexByte(tail, '(')
	end := strings.IndexByte(tail, ')')
	if paren <= 0 || end < paren || end+1 >= len(tail) {
		return nil
	}
	// Preserve the exact overload for call-graph joins. FullCall remains the
	// historical lowercase owner+name projection used by existing rule matchers.
	signature := reference
	if i := strings.IndexAny(signature, " \t,"); i >= 0 {
		signature = signature[:i]
	}
	call := &CallInfo{
		Type:  pa.intern(strings.TrimSuffix(strings.TrimPrefix(fields[0], "invoke-"), "/range")),
		Class: pa.intern(owner), Method: pa.intern(tail[:paren]), Signature: pa.intern(signature),
	}
	switch call.Type {
	case "virtual", "static", "direct", "interface", "super":
	default:
		call.Type = "unknown" // legacy classification; Signature still preserves the target
	}
	call.FullCall = pa.intern(strings.ToLower(call.Class + ";->" + call.Method))
	call.IsSecurityRelated = pa.isSecurityCall(call.FullCall)
	return call
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYZE METHOD NAME
// ═══════════════════════════════════════════════════════════════════════════════
//
// DEPRECATED: Use SecurityNameKeywords from security_keywords.go for new code.
// This variable is kept for backward compatibility.
var securityNameKeywords = SecurityNameKeywords

func (pa *PatchAnalyzer) analyzeMethodName(mi *MethodInfo) {
	nameLower := mi.NameLower
	// Task 6.1: MatchedNameParts already pre-allocated in pool

	// Проверяем check-префиксы
	for _, prefix := range pa.checkPrefixes {
		if strings.HasPrefix(nameLower, prefix) {
			mi.HasCheckPrefix = true
			mi.MatchedNameParts = append(mi.MatchedNameParts, "prefix:"+prefix)
			break
		}
	}

	// Проверяем callback-префиксы
	for _, prefix := range pa.callbackPrefixes {
		if strings.HasPrefix(nameLower, prefix) {
			mi.IsCallback = true
			break
		}
	}

	// Проверяем security-related имена
	for _, sec := range securityNameKeywords {
		if strings.Contains(nameLower, sec) {
			mi.HasSecurityName = true
			mi.MatchedNameParts = append(mi.MatchedNameParts, "name:"+sec)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYZE STRUCTURE
// ═══════════════════════════════════════════════════════════════════════════════

func (pa *PatchAnalyzer) analyzeStructure(mi *MethodInfo) {
	// Short method: типичная check-функция имеет 3-20 инструкций
	mi.IsShortMethod = mi.InstructionCount >= 3 && mi.InstructionCount <= 30

	// If with return: if-eqz/if-nez сразу перед return
	if mi.IfCheckCount > 0 && mi.ReturnCount >= 2 {
		mi.HasIfWithReturn = true
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// MATCH SECURITY PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

func (pa *PatchAnalyzer) matchSecurityPatterns(mi *MethodInfo) {
	// Security calls
	mi.SecurityCalls = make([]string, 0, 4)
	for _, call := range mi.Calls {
		if call.IsSecurityRelated {
			mi.SecurityCalls = append(mi.SecurityCalls, call.FullCall)
			mi.HasSecurityAPI = true
		}
	}

	// Security strings
	mi.SecurityStrings = make([]string, 0, 4)
	for _, str := range mi.StringConsts {
		strLower := strings.ToLower(str)
		for _, pattern := range pa.securityStringPatterns {
			if strings.Contains(strLower, pattern) {
				mi.SecurityStrings = append(mi.SecurityStrings, str)
				mi.HasSecurityStrings = true
				break
			}
		}
	}
}

// isSecurityCall проверяет, является ли вызов security-related
func (pa *PatchAnalyzer) isSecurityCall(fullCallLower string) bool {
	for _, pattern := range pa.securityCallPatterns {
		if strings.Contains(fullCallLower, pattern) {
			return true
		}
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// MATCH AGAINST VULNERABLE PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

// PatternMatch — результат матчинга метода с паттерном
type PatternMatch struct {
	Pattern      *VulnerablePattern `json:"pattern"`
	MatchScore   float64            `json:"match_score"`
	MatchedParts []string           `json:"matched_parts"`
}

// MatchVulnerablePatterns матчит метод со всеми уязвимыми паттернами
// Task 4.2: Использует indexed lookup вместо линейного поиска
func (pa *PatchAnalyzer) MatchVulnerablePatterns(mi *MethodInfo) []PatternMatch {
	matches := make([]PatternMatch, 0, 4)

	// Task 4.2: O(1) lookup вместо O(N) линейного поиска
	candidates := pa.patternIndex.FindCandidates(mi)

	for _, vp := range candidates {
		pm := pa.matchSinglePattern(mi, vp)
		if pm != nil && pm.MatchScore >= vp.MinMatchScore {
			matches = append(matches, *pm)
		}
	}

	// Сортируем по MatchScore descending, чтобы лучший паттерн был первым
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].MatchScore > matches[j].MatchScore
	})

	return matches
}

func (pa *PatchAnalyzer) matchSinglePattern(mi *MethodInfo, vp *VulnerablePattern) *PatternMatch {
	if !economyPatternFits(mi, vp) { return nil }
	pm := &PatternMatch{
		Pattern:      vp,
		MatchedParts: make([]string, 0, 8),
	}

	var score float64

	// ── 1. Method name match ─────────────────────────────────────
	nameMatched := false
	for _, name := range vp.MethodNames {
		if strings.Contains(mi.NameLower, strings.ToLower(name)) {
			score += 20 * vp.Weight
			pm.MatchedParts = append(pm.MatchedParts, "method_name:"+name)
			nameMatched = true
			break
		}
	}

	// ── 2. Class/path match ──────────────────────────────────────
	classMatched := false
	pathLower := strings.ToLower(normalizePath(mi.FilePath))
	classLower := strings.ToLower(mi.ClassName)
	for _, pattern := range vp.ClassPatterns {
		patternLower := strings.ToLower(pattern)
		if strings.Contains(pathLower, patternLower) || strings.Contains(classLower, patternLower) {
			score += 15 * vp.Weight
			pm.MatchedParts = append(pm.MatchedParts, "class:"+pattern)
			classMatched = true
			break
		}
	}

	// ── 3. Required calls match ──────────────────────────────────
	callMatchCount := 0
	for _, reqCall := range vp.RequiredCalls {
		for _, call := range mi.Calls {
			if strings.Contains(call.FullCall, reqCall) {
				score += 12 * vp.Weight
				pm.MatchedParts = append(pm.MatchedParts, "call:"+reqCall)
				callMatchCount++
				break
			}
		}
	}

	// ── 4. String patterns match ─────────────────────────────────
	stringMatchCount := 0
	for _, strPattern := range vp.StringPatterns {
		for _, constStr := range mi.StringConsts {
			if strings.Contains(strings.ToLower(constStr), strPattern) {
				score += 8 * vp.Weight
				pm.MatchedParts = append(pm.MatchedParts, "string:"+strPattern)
				stringMatchCount++
				break
			}
		}
		// Также проверяем в пути файла и имени класса
		if strings.Contains(pathLower, strPattern) {
			score += 5 * vp.Weight
			stringMatchCount++
		}
	}

	// ── 5. Return type match ─────────────────────────────────────
	if vp.ReturnType != "" {
		if patternReturnCompatible(vp, mi.ReturnType) {
			score += 10
			pm.MatchedParts = append(pm.MatchedParts, "return_type:"+vp.ReturnType)
		} else {
			// Неправильный return type — сильный штраф
			score -= 15
		}
	}

	// ── 6. Structural bonuses ────────────────────────────────────
	if mi.ReturnsBoolean && mi.HasDualReturn {
		score += 8
		pm.MatchedParts = append(pm.MatchedParts, "structure:dual_return")
	}
	if mi.HasIfWithReturn {
		score += 6
		pm.MatchedParts = append(pm.MatchedParts, "structure:if_with_return")
	}
	if mi.IsShortMethod {
		score += 4
		pm.MatchedParts = append(pm.MatchedParts, "structure:short_method")
	}

	// ── 7. Minimum viability check ───────────────────────────────
	// Нужно хотя бы одно совпадение имени ИЛИ вызовов
	if !nameMatched && callMatchCount == 0 && stringMatchCount == 0 && !classMatched {
		return nil
	}
	// Generic storage calls are shared by every setting in an app. They are
	// supporting evidence only; a counter must not become a subscription gate.
	if !nameMatched && !classMatched && stringMatchCount == 0 && onlyGenericPatternCalls(pm.MatchedParts) {
		return nil
	}

	pm.MatchScore = score
	return pm
}

// ═══════════════════════════════════════════════════════════════════════════════
// MATCH SAFE PATTERNS — проверка что метод безопасный
// ═══════════════════════════════════════════════════════════════════════════════

// MatchSafePatterns проверяет, является ли метод безопасным (не патч-точкой)
func (pa *PatchAnalyzer) MatchSafePatterns(mi *MethodInfo) (bool, float64, string) {
	// Быстрые проверки - конструкторы и синтетические методы ВСЕГДА безопасны
	if mi.IsConstructor {
		return true, SafePatterns[1].Penalty, "constructor"
	}
	if mi.IsAccessor {
		return true, SafePatterns[2].Penalty, "synthetic_accessor"
	}
	if mi.IsSynthetic {
		return true, SafePatterns[2].Penalty, "synthetic"
	}
	if mi.IsAbstract {
		return true, -40, "abstract_method"
	}

	// Улучшенная проверка getter/setter.
	// ВАЖНО: короткие boolean/int-геттеры вида isPremium/isUnlocked/isOwned/
	// hasEnoughCoins/getCoins/getGems — это РОВНО наши цели, а не «безопасные»
	// аксессоры. Раньше они попадали под getter-правило и глушились штрафом,
	// из-за чего терялись реальные детекции (особенно игровая экономика).
	// Поэтому НЕ считаем метод safe-геттером, если у него есть security/economy
	// сигнал в имени, security-API или check-префикс.
	hasGateSignal := mi.HasSecurityName || mi.HasSecurityAPI || mi.HasCheckPrefix
	if !hasGateSignal &&
		(strings.HasPrefix(mi.NameLower, "get") ||
			strings.HasPrefix(mi.NameLower, "is") ||
			strings.HasPrefix(mi.NameLower, "has")) &&
		mi.InstructionCount < 10 {
		// Простой нейтральный getter (getName/isEmpty/isVisible) — не патч-точка
		return true, SafePatterns[0].Penalty, "getter"
	}

	// Setter: начинается с set/put/add и короткий — тот же guard.
	if !hasGateSignal &&
		(strings.HasPrefix(mi.NameLower, "set") ||
			strings.HasPrefix(mi.NameLower, "put") ||
			strings.HasPrefix(mi.NameLower, "add")) &&
		mi.InstructionCount < 10 {
		// Простой нейтральный setter — не патч-точка
		return true, SafePatterns[0].Penalty, "setter"
	}

	// Проверяем каждый safe pattern
	for _, sp := range SafePatterns {
		for _, indicator := range sp.Indicators {
			indicatorLower := strings.ToLower(indicator)

			// Проверяем в имени метода
			if strings.Contains(mi.NameLower, indicatorLower) {
				// UI callbacks безопасны только если нет security контекста
				if sp.Name == "ui_callback" {
					if mi.HasSecurityName || mi.HasSecurityAPI {
						// UI callback с security контекстом - может быть патч-точкой
						continue
					}
				}
				return true, sp.Penalty, sp.Name
			}

			// Проверяем в вызовах
			for _, call := range mi.Calls {
				if strings.Contains(call.FullCall, indicatorLower) {
					// Но только если нет security контекста!
					if !mi.HasSecurityName && !mi.HasSecurityAPI {
						return true, sp.Penalty, sp.Name + " (via call)"
					}
				}
			}
		}
	}

	return false, 0, ""
}

// ═══════════════════════════════════════════════════════════════════════════════
// QUICK CHECK — быстрая проверка стоит ли анализировать метод глубже
// ═══════════════════════════════════════════════════════════════════════════════

// IsWorthAnalyzing быстро определяет, стоит ли метод детального анализа
func (pa *PatchAnalyzer) IsWorthAnalyzing(mi *MethodInfo) bool {
	if mi == nil { return false }
	economy := economyForMethod(mi)
	resourceCandidate := isEconomyCandidate(economy)
	// Пропускаем конструкторы, синтетические, абстрактные
	if mi.IsConstructor || mi.IsAbstract || ((mi.IsSynthetic || mi.IsAccessor) && !resourceCandidate) {
		return false
	}

	// Пропускаем слишком короткие (1-2 инструкции — просто return)
	if mi.InstructionCount < 2 {
		return false
	}

	// Слишком длинные методы обычно не «простые проверки», НО обфускация,
	// инлайнинг и разматывание циклов легко раздувают настоящий gate за 100
	// инструкций. Жёстко режем только очень большие тела; средние (100..400)
	// оставляем, если есть хоть один security/economy-сигнал или boolean
	// dual-return — иначе теряем самые «жирные» обфусцированные цели.
	if mi.InstructionCount > 400 {
		return false
	}
	if resourceCandidate { return true }
	if economy != nil && economy.Operation == EconomyDisplay && !mi.HasSecurityAPI { return false }
	if mi.InstructionCount > 100 {
		if !(mi.HasSecurityName || mi.HasSecurityAPI || mi.HasSecurityStrings ||
			(mi.ReturnsBoolean && mi.HasDualReturn)) {
			return false
		}
	}

	// Проверяем: boolean return + check-имя = точно стоит
	if mi.ReturnsBoolean && mi.HasCheckPrefix {
		return true
	}

	// Security-related имя = стоит
	if mi.HasSecurityName {
		return true
	}

	// Security API calls = стоит
	if mi.HasSecurityAPI {
		return true
	}

	// Security strings = стоит
	if mi.HasSecurityStrings {
		return true
	}

	// Boolean с if и dual return = стоит
	if mi.ReturnsBoolean && mi.HasDualReturn {
		return true
	}

	// Callback-методы обычно не патч-точки
	if mi.IsCallback {
		return false
	}

	return false
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// splitLines разбивает контент на строки (без аллокации string)
// splitLines splits content into lines (Task 6.2: optimized with buffer reuse)
func splitLines(content []byte) []string {
	if len(content) == 0 {
		return nil
	}

	// Считаем строки для предаллокации
	lineCount := 1
	for _, b := range content {
		if b == '\n' {
			lineCount++
		}
	}

	lines := make([]string, 0, lineCount)
	start := 0
	for i, b := range content {
		if b == '\n' {
			line := string(content[start:i])
			line = strings.TrimRight(line, "\r")
			lines = append(lines, line)
			start = i + 1
		}
	}
	// Последняя строка
	if start < len(content) {
		line := string(content[start:])
		line = strings.TrimRight(line, "\r")
		lines = append(lines, line)
	}

	return lines
}

// splitLinesPooled splits content into lines using buffer pool (Task 6.2)
// Returns a buffer that MUST be returned to pool with PutLineBuffer()
func splitLinesPooled(content []byte) *LineBuffer {
	buf := GetLineBuffer()

	if len(content) == 0 {
		return buf
	}

	start := 0
	for i, b := range content {
		if b == '\n' {
			line := string(content[start:i])
			line = strings.TrimRight(line, "\r")
			buf.Lines = append(buf.Lines, line)
			start = i + 1
		}
	}
	// Последняя строка
	if start < len(content) {
		line := string(content[start:])
		line = strings.TrimRight(line, "\r")
		buf.Lines = append(buf.Lines, line)
	}

	return buf
}

// normalizePath нормализует путь для сравнения
func normalizePath(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	path = strings.TrimPrefix(path, "smali/")
	path = strings.TrimPrefix(path, "smali_classes2/")
	path = strings.TrimPrefix(path, "smali_classes3/")
	path = strings.TrimPrefix(path, "smali_classes4/")
	return path
}

// extractLastToken извлекает последний токен из строки
func extractLastToken(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// extractParamsFromHeader извлекает параметры из заголовка метода
func extractParamsFromHeader(header string) string {
	openParen := strings.Index(header, "(")
	closeParen := strings.Index(header, ")")
	if openParen < 0 || closeParen < 0 || closeParen <= openParen {
		return ""
	}
	return header[openParen+1 : closeParen]
}

// extractConstString извлекает строку из const-string инструкции
func extractConstString(line string) string {
	line = smaliCodeLine(line)
	start := strings.IndexByte(line, '"')
	if start < 0 {
		return ""
	}
	escaped := false
	for i := start + 1; i < len(line); i++ {
		if escaped {
			escaped = false
			continue
		}
		if line[i] == '\\' {
			escaped = true
			continue
		}
		if line[i] == '"' {
			return decodeSmaliLiteral(line[start+1 : i])
		}
	}
	return ""
}

// extractIntAfter извлекает число после указанного префикса
func extractIntAfter(line, prefix string) int {
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return 0
	}
	numStr := strings.TrimSpace(line[idx+len(prefix):])
	// Парсим число
	result := 0
	for _, c := range numStr {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		} else {
			break
		}
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════════════════
// BATCH ANALYSIS — анализ множества файлов
// ═══════════════════════════════════════════════════════════════════════════════

// AnalysisCandidate — кандидат для анализа (из pipeline результата)
type AnalysisCandidate struct {
	FilePath  string
	FullPath  string
	Content   []byte
	IsAppCode bool
}

// BatchAnalyzeResult — результат пакетного анализа
type BatchAnalyzeResult struct {
	InputFiles      int
	FilesSkipped    int
	FilesTooLarge   int
	FileReadErrors  int
	Diagnostics     []string
	Cancelled       bool
	Classes         []*ClassInfo
	TotalFiles      int
	TotalMethods    int
	AnalyzedMethods int
	SkippedMethods  int
	FilteredMethods int      // 🔥 NEW: количество отфильтрованных методов
	FilterReasons   []string // 🔥 NEW: причины фильтрации
}

// BatchAnalyze анализирует пакет smali файлов
func (pa *PatchAnalyzer) BatchAnalyze(candidates []AnalysisCandidate) *BatchAnalyzeResult {
	return pa.BatchAnalyzeContext(context.Background(), candidates)
}

// ═══════════════════════════════════════════════════════════════════════════════
// DISPLAY HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

// ShortClassName возвращает короткое имя класса
func ShortClassName(fullName string) string {
	// Lcom/app/security/LicenseChecker; → LicenseChecker
	fullName = strings.TrimPrefix(fullName, "L")
	fullName = strings.TrimSuffix(fullName, ";")
	if idx := strings.LastIndex(fullName, "/"); idx >= 0 {
		return fullName[idx+1:]
	}
	return fullName
}

// ShortFilePath возвращает короткий путь файла
func ShortFilePath(path string) string {
	path = normalizePath(path)
	// Убираем .smali
	path = strings.TrimSuffix(path, ".smali")
	// Максимум 60 символов
	if len(path) > 60 {
		return "..." + path[len(path)-57:]
	}
	return path
}

// MethodSignatureShort возвращает короткую сигнатуру
func MethodSignatureShort(mi *MethodInfo) string {
	ret := mi.ReturnType
	switch ret {
	case "Z":
		ret = "boolean"
	case "V":
		ret = "void"
	case "I":
		ret = "int"
	case "J":
		ret = "long"
	}

	// Убираем первый символ 'L' и последний ';' из return type
	if strings.HasPrefix(ret, "L") {
		ret = strings.TrimPrefix(ret, "L")
		ret = strings.TrimSuffix(ret, ";")
		if idx := strings.LastIndex(ret, "/"); idx >= 0 {
			ret = ret[idx+1:]
		}
	}

	return mi.Name + "() → " + ret
}

// IsUpperCaseStart проверяет начинается ли строка с заглавной
func IsUpperCaseStart(s string) bool {
	if len(s) == 0 {
		return false
	}
	return unicode.IsUpper(rune(s[0]))
}
