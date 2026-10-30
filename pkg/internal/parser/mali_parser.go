package parser

// SmaliParser — the single text-based smali parser used by the pipeline
// (parser.NewSmaliParser), consumed by pipeline/workers.go. The duplicate
// FSM implementation (parser.go + parallel/analyzer/patterns/quickcheck/
// config + its tests) was removed: zero production callers, pinned only by
// its own tests. Its sole live symbol, UnescapeSmaliString, was moved here.
// types.go stays as the legacy type bag behind pipeline's ParseResult alias.

import (
	"regexp"
	"strconv"
	"strings"

	"mega-analyzer/pkg/internal/types"
)

// ============================================================================
// REGEX PATTERNS
// ============================================================================

var (
	// Class header
	classRegex = regexp.MustCompile(
		`\.class\s+((?:public|private|protected|final|abstract|static|synchronized|declared-synchronized|bridge|varargs|native|strictfp|interface|annotation|enum|synthetic|constructor)\s+)*L([^;]+);`)
	superRegex      = regexp.MustCompile(`\.super\s+L([^;]+);`)
	sourceRegex     = regexp.MustCompile(`\.source\s+"([^"]+)"`)
	implementsRegex = regexp.MustCompile(`\.implements\s+L([^;]+);`)

	// Fields
	fieldRegex = regexp.MustCompile(
		`\.field\s+((?:public|private|protected|static|final|volatile|transient|synthetic|enum)\s+)*([^\s:]+):(\S+)`)

	// Methods
	methodStartRegex = regexp.MustCompile(
		`\.method\s+((?:public|private|protected|static|final|abstract|native|synchronized|bridge|varargs|declared-synchronized|synthetic|constructor)\s+)*([^\s(]+)\(([^)]*)\)(\S+)`)
	localsRegex    = regexp.MustCompile(`\.locals\s+(\d+)`)
	registersRegex = regexp.MustCompile(`\.registers\s+(\d+)`)

	// Instructions
	invokeRegex = regexp.MustCompile(
		`invoke-(\w+)(?:/range)?\s+\{([^}]*)\},\s*L([^;]+);->([^\(]+)\(([^)]*)\)(.*)`)
	conditionRegex = regexp.MustCompile(
		`^(if-\w+)\s+([^,]+)(?:,\s*([^,]+))?,\s*(:[\w_]+)`)
	// Escape-aware: matches up to the real closing quote, so trailing
	// comment text and escaped quotes inside the literal survive.
	constStringRegex = regexp.MustCompile(
		`const-string(?:/jumbo)?\s+([vp]\d+),\s*"((?:[^"\\]|\\.)*)"`)
	fieldAccessRegex = regexp.MustCompile(
		`([si](?:get|put)(?:-\w+)?)\s+(\w+)(?:,\s*(\w+))?,\s*L([^;]+);->([^:]+):(.+)`)
	returnRegex = regexp.MustCompile(
		`^(return(?:-void|-object|-wide)?)\s*(\w+)?`)
	labelRegex  = regexp.MustCompile(`^(:\S+)`)
	switchRegex = regexp.MustCompile(
		`(packed-switch|sparse-switch)\s+(\w+),\s*(:[\w_]+)`)
	catchRegex = regexp.MustCompile(
		`\.catch\s+L([^;]+);\s+\{([^}]+)\}\s*(:[\w_]+)`)
	catchAllRegex = regexp.MustCompile(
		`\.catchall\s+\{([^}]+)\}\s*(:[\w_]+)`)

	// Generic instruction
	opcodeRegex = regexp.MustCompile(`^\s*([a-z][a-z0-9-]*(?:/[a-z0-9]+)?)\s*(.*)`)
)

// ============================================================================
// KNOWN API TAGS
// ============================================================================

var knownAPITags = map[string][]string{
	// Billing
	"com/android/vending/billing":   {"billing", "iap"},
	"com.android.billingclient.api": {"billing", "iap"},
	"BillingClient":                 {"billing"},
	"Purchase":                      {"billing", "purchase"},
	"SkuDetails":                    {"billing"},

	// License
	"com/google/android/vending/licensing": {"license", "lvl"},
	"LicenseChecker":                       {"license"},
	"LicenseValidator":                     {"license"},

	// Package Manager
	"PackageManager":          {"package-manager"},
	"getPackageInfo":          {"package-info"},
	"getInstallerPackageName": {"installer-check"},
	"checkSignatures":         {"signature-check"},

	// Security
	"Signature":     {"signature", "security"},
	"MessageDigest": {"crypto", "hash"},
	"Cipher":        {"crypto", "encryption"},
	"SecretKey":     {"crypto", "key"},

	// System
	"System;->getProperty": {"system-property"},
	"Build;":               {"device-info"},
	"TelephonyManager":     {"device-info", "phone"},

	// Reflection
	"Class;->forName":   {"reflection"},
	"Method;->invoke":   {"reflection"},
	"getDeclaredMethod": {"reflection"},
	"getDeclaredField":  {"reflection"},
	"setAccessible":     {"reflection", "access-bypass"},

	// Debug detection
	"Debug;":              {"debug-detection"},
	"isDebuggerConnected": {"debug-detection"},

	// Root detection
	"/su":                     {"root-detection"},
	"/system/app/Superuser":   {"root-detection"},
	"com.noshufou.android.su": {"root-detection"},
	"eu.chainfire.supersu":    {"root-detection"},
}

// ============================================================================
// PARSER
// ============================================================================

type SmaliParser struct {
	content string
	lines   []string
}

func NewSmaliParser(content string) *SmaliParser {
	return &SmaliParser{
		content: content,
		lines:   strings.Split(content, "\n"),
	}
}

// Lines returns the immutable source lines shared by parsing and downstream
// analysis. Callers must not modify the slice or its entries.
func (p *SmaliParser) Lines() []string { return p.lines }

// Parse - ONLY parsing, NO analysis!
func (p *SmaliParser) Parse() (*types.SmaliClass, error) {
	class := &types.SmaliClass{
		Interfaces: make([]string, 0),
		Fields:     make([]types.SmaliField, 0),
		Methods:    make([]types.SmaliMethod, 0),
	}

	p.parseClassHeader(class)
	p.extractClassMetadata(class)
	p.parseFields(class)
	p.parseMethods(class)

	return class, nil
}

// ============================================================================
// CLASS HEADER PARSING
// ============================================================================

func (p *SmaliParser) parseClassHeader(class *types.SmaliClass) {
	for _, line := range p.lines {
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, ".class"):
			if matches := classRegex.FindStringSubmatch(trimmed); len(matches) > 2 {
				modifiers := strings.Fields(matches[1])
				class.Access = types.ParseAccessFlags(modifiers)
				class.Name = strings.ReplaceAll(matches[2], "/", ".")
			}

		case strings.HasPrefix(trimmed, ".super"):
			if matches := superRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				class.SuperClass = strings.ReplaceAll(matches[1], "/", ".")
			}

		case strings.HasPrefix(trimmed, ".source"):
			if matches := sourceRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				class.Source = matches[1]
			}

		case strings.HasPrefix(trimmed, ".implements"):
			if matches := implementsRegex.FindStringSubmatch(trimmed); len(matches) > 1 {
				class.Interfaces = append(class.Interfaces, strings.ReplaceAll(matches[1], "/", "."))
			}

		case strings.HasPrefix(trimmed, ".field"), strings.HasPrefix(trimmed, ".method"):
			return // Done with header
		}
	}
}

func (p *SmaliParser) extractClassMetadata(class *types.SmaliClass) {
	// Package name
	if idx := strings.LastIndex(class.Name, "."); idx != -1 {
		class.PackageName = class.Name[:idx]
		class.SimpleName = class.Name[idx+1:]
	} else {
		class.SimpleName = class.Name
	}

	// Library detection
	class.IsLibrary = p.detectLibrary(class.Name)
	class.IsAppCode = !class.IsLibrary

	// Obfuscation detection (basic)
	class.IsObfuscated = p.detectObfuscation(class.SimpleName)
}

func (p *SmaliParser) detectLibrary(className string) bool {
	libraryPrefixes := []string{
		"android.",
		"androidx.",
		"com.google.",
		"kotlin.",
		"kotlinx.",
		"org.apache.",
		"org.json.",
		"java.",
		"javax.",
		"okhttp3.",
		"retrofit2.",
		"io.reactivex.",
		"com.squareup.",
		"com.facebook.",
		"com.crashlytics.",
		"io.fabric.",
		"com.google.firebase.",
		"com.google.android.gms.",
		"com.adjust.",
		"com.appsflyer.",
		"com.unity3d.",
	}

	for _, prefix := range libraryPrefixes {
		if strings.HasPrefix(className, prefix) {
			return true
		}
	}
	return false
}

func (p *SmaliParser) detectObfuscation(name string) bool {
	// Single letter or very short name
	if len(name) <= 2 {
		return true
	}

	// Common obfuscation patterns
	if matched, _ := regexp.MatchString(`^[a-z]{1,2}\d*$`, name); matched {
		return true
	}
	if matched, _ := regexp.MatchString(`^[A-Z][a-z]?\d*$`, name); matched {
		return true
	}

	return false
}

// ============================================================================
// FIELD PARSING
// ============================================================================

func (p *SmaliParser) parseFields(class *types.SmaliClass) {
	for i, line := range p.lines {
		trimmed := strings.TrimSpace(line)

		if !strings.HasPrefix(trimmed, ".field") {
			continue
		}

		matches := fieldRegex.FindStringSubmatch(trimmed)
		if len(matches) < 4 {
			continue
		}

		modifiers := strings.Fields(strings.TrimSpace(matches[1]))

		field := types.SmaliField{
			SourceLocation: types.SourceLocation{Line: i + 1},
			Name:           matches[2],
			Type:           matches[3],
			Access:         types.ParseAccessFlags(modifiers),
		}

		// Type classification
		field.TypeKind, field.BaseType = p.classifyType(field.Type)

		// Value extraction
		if idx := strings.Index(trimmed, " = "); idx != -1 {
			field.Value = strings.TrimSpace(trimmed[idx+3:])
		}

		class.Fields = append(class.Fields, field)
	}
}

func (p *SmaliParser) classifyType(typeStr string) (kind, baseType string) {
	switch {
	case strings.HasPrefix(typeStr, "["):
		return "array", strings.TrimLeft(typeStr, "[")
	case strings.HasPrefix(typeStr, "L"):
		return "object", strings.Trim(typeStr, "L;")
	case len(typeStr) == 1:
		return "primitive", typeStr
	default:
		return "unknown", typeStr
	}
}

// ============================================================================
// METHOD PARSING
// ============================================================================

func (p *SmaliParser) parseMethods(class *types.SmaliClass) {
	var currentMethod *types.SmaliMethod
	methodStartLine := 0

	for i, line := range p.lines {
		trimmed := strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(trimmed, ".method"):
			currentMethod = p.parseMethodStart(trimmed, i+1)
			methodStartLine = i

		case trimmed == ".end method" && currentMethod != nil:
			currentMethod.LineEnd = i + 1
			p.parseMethodBody(currentMethod, p.lines[methodStartLine:i+1], methodStartLine)
			p.calculateMetrics(currentMethod)
			p.analyzeSuspicion(currentMethod)
			class.Methods = append(class.Methods, *currentMethod)
			currentMethod = nil

		case currentMethod != nil:
			p.parseMethodDirective(currentMethod, trimmed)
		}
	}
}

func (p *SmaliParser) parseMethodStart(line string, lineNum int) *types.SmaliMethod {
	matches := methodStartRegex.FindStringSubmatch(line)
	if len(matches) < 5 {
		return nil
	}

	modifiers := strings.Fields(strings.TrimSpace(matches[1]))

	method := &types.SmaliMethod{
		SourceRange:    types.SourceRange{LineStart: lineNum},
		Name:           matches[2],
		Params:         matches[3],
		ReturnType:     matches[4],
		Access:         types.ParseAccessFlags(modifiers),
		ReturnsBoolean: matches[4] == "Z",
		Invokes:        make([]types.Invoke, 0),
		Conditions:     make([]types.Condition, 0),
		Instructions:   make([]types.Instruction, 0),
		StringConsts:   make([]types.StringConstant, 0),
		FieldAccesses:  make([]types.FieldAccess, 0),
		Labels:         make([]types.Label, 0),
		Returns:        make([]types.Return, 0),
		Switches:       make([]types.Switch, 0),
		TryCatches:     make([]types.TryCatch, 0),
	}

	return method
}

func (p *SmaliParser) parseMethodDirective(method *types.SmaliMethod, line string) {
	switch {
	case strings.HasPrefix(line, ".locals"):
		if matches := localsRegex.FindStringSubmatch(line); len(matches) > 1 {
			method.Locals, _ = strconv.Atoi(matches[1])
		}
	case strings.HasPrefix(line, ".registers"):
		if matches := registersRegex.FindStringSubmatch(line); len(matches) > 1 {
			method.Registers, _ = strconv.Atoi(matches[1])
		}
	case strings.HasPrefix(line, ".catch"):
		method.HasTryCatch = true
	}
}

func (p *SmaliParser) parseMethodBody(method *types.SmaliMethod, body []string, baseLineNum int) {
	for i, line := range body {
		lineNum := baseLineNum + i + 1
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ".") {
			// Handle special directives
			if strings.HasPrefix(trimmed, ".catch") {
				p.parseCatch(method, trimmed)
			}
			continue
		}

		// Parse different instruction types
		switch {
		case strings.HasPrefix(trimmed, "invoke-"):
			if inv := p.parseInvoke(trimmed, lineNum); inv != nil {
				method.Invokes = append(method.Invokes, *inv)
				method.Instructions = append(method.Instructions, types.Instruction{
					SourceLocation: types.SourceLocation{Line: lineNum},
					Opcode:         firstToken(trimmed),
					Raw:            trimmed,
					Category:       types.InstrCategoryInvoke,
				})
			}

		case strings.HasPrefix(trimmed, "if-"):
			if cond := p.parseCondition(trimmed, lineNum); cond != nil {
				method.Conditions = append(method.Conditions, *cond)
				method.Instructions = append(method.Instructions, types.Instruction{
					SourceLocation: types.SourceLocation{Line: lineNum},
					Opcode:         firstToken(trimmed),
					Raw:            trimmed,
					Category:       types.InstrCategoryIf,
				})
			}

		case strings.HasPrefix(trimmed, "const-string"):
			if str := p.parseConstString(trimmed, lineNum); str != nil {
				method.StringConsts = append(method.StringConsts, *str)
				method.Instructions = append(method.Instructions, types.Instruction{
					SourceLocation: types.SourceLocation{Line: lineNum},
					Opcode:         "const-string",
					Raw:            trimmed,
					Category:       types.InstrCategoryConst,
				})
			}

		case p.isFieldAccess(trimmed):
			if fa := p.parseFieldAccess(trimmed, lineNum); fa != nil {
				method.FieldAccesses = append(method.FieldAccesses, *fa)
				category := types.InstrCategoryFieldGet
				if fa.IsWrite {
					category = types.InstrCategoryFieldPut
				}
				method.Instructions = append(method.Instructions, types.Instruction{
					SourceLocation: types.SourceLocation{Line: lineNum},
					Opcode:         fa.Op,
					Raw:            trimmed,
					Category:       category,
				})
			}

		case strings.HasPrefix(trimmed, "return"):
			if ret := p.parseReturn(trimmed, lineNum); ret != nil {
				method.Returns = append(method.Returns, *ret)
				method.Instructions = append(method.Instructions, types.Instruction{
					SourceLocation: types.SourceLocation{Line: lineNum},
					Opcode:         ret.Op,
					Raw:            trimmed,
					Category:       types.InstrCategoryReturn,
				})
			}

		case strings.HasPrefix(trimmed, ":"):
			method.Labels = append(method.Labels, types.Label{
				SourceLocation: types.SourceLocation{Line: lineNum},
				Name:           trimmed,
			})

		case strings.HasPrefix(trimmed, "packed-switch") || strings.HasPrefix(trimmed, "sparse-switch"):
			if sw := p.parseSwitch(trimmed, lineNum); sw != nil {
				method.Switches = append(method.Switches, *sw)
			}

		default:
			if instr := p.parseGenericInstruction(trimmed, lineNum); instr != nil {
				method.Instructions = append(method.Instructions, *instr)
			}
		}
	}
}

// ============================================================================
// INSTRUCTION PARSERS
// ============================================================================

func (p *SmaliParser) parseInvoke(line string, lineNum int) *types.Invoke {
	matches := invokeRegex.FindStringSubmatch(line)
	if len(matches) < 7 {
		return nil
	}

	opcode := "invoke-" + matches[1]
	invokeType := types.ParseInvokeType(opcode)

	invoke := &types.Invoke{
		SourceLocation: types.SourceLocation{Line: lineNum},
		Type:           invokeType,
		Registers:      p.parseRegisters(matches[2]),
		Class:          strings.ReplaceAll(matches[3], "/", "."),
		Method:         matches[4],
		Params:         matches[5],
		ReturnType:     matches[6],
		Raw:            line,
		Tags:           make([]string, 0),
	}

	// Auto-tag known APIs
	for pattern, tags := range knownAPITags {
		if strings.Contains(invoke.Class, pattern) || strings.Contains(invoke.Method, pattern) {
			invoke.Tags = append(invoke.Tags, tags...)
		}
	}

	return invoke
}

func (p *SmaliParser) parseCondition(line string, lineNum int) *types.Condition {
	matches := conditionRegex.FindStringSubmatch(line)
	if len(matches) < 3 {
		// Fallback for simpler conditions
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			opStr := parts[0]
			return &types.Condition{
				SourceLocation: types.SourceLocation{Line: lineNum},
				Op:             types.ParseConditionOp(opStr),
				Operands:       []string{strings.Trim(parts[1], ",")},
				Target:         parts[len(parts)-1],
				Negated:        isNegatedCondition(opStr),
			}
		}
		return nil
	}

	opStr := matches[1]
	cond := &types.Condition{
		SourceLocation: types.SourceLocation{Line: lineNum},
		Op:             types.ParseConditionOp(opStr),
		Operands:       []string{strings.Trim(matches[2], ",")},
		Target:         matches[4],
		Negated:        isNegatedCondition(opStr),
	}

	if matches[3] != "" {
		cond.Operands = append(cond.Operands, strings.Trim(matches[3], ","))
	}

	return cond
}

func isNegatedCondition(op string) bool {
	if strings.HasSuffix(op, "z") {
		return strings.Contains(op, "nez") || strings.Contains(op, "gtz") || strings.Contains(op, "ltz")
	}
	return op == "if-ne"
}

func (p *SmaliParser) parseConstString(line string, lineNum int) *types.StringConstant {
	matches := constStringRegex.FindStringSubmatch(line)
	if len(matches) < 3 {
		return nil
	}

	str := &types.StringConstant{
		SourceLocation: types.SourceLocation{Line: lineNum},
		Register:       matches[1],
		Value:          unescapeSmaliString(matches[2]),
		Raw:            line,
	}

	// Analyze string content (on the unescaped value).
	value := strings.ToLower(str.Value)
	var flags types.StringConstFlags
	if str.Value == "" {
		flags |= types.StringFlagEmpty
	}
	if strings.HasPrefix(str.Value, "http") || strings.Contains(str.Value, "://") {
		flags |= types.StringFlagLooksURL
	}
	if strings.Count(str.Value, ".") >= 2 && !strings.Contains(str.Value, " ") {
		flags |= types.StringFlagLooksPackage
	}
	if len(str.Value) > 20 && p.isBase64Like(str.Value) {
		flags |= types.StringFlagLooksBase64
	}
	if strings.Contains(value, "key") || strings.Contains(value, "secret") ||
		strings.Contains(value, "token") || strings.Contains(value, "api") {
		flags |= types.StringFlagLooksKey
	}
	str.Flags = flags

	return str
}

func (p *SmaliParser) isBase64Like(s string) bool {
	if len(s) < 4 || len(s)%4 != 0 {
		return false
	}
	base64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	for _, c := range s {
		if !strings.ContainsRune(base64Chars, c) {
			return false
		}
	}
	return true
}

func (p *SmaliParser) parseFieldAccess(line string, lineNum int) *types.FieldAccess {
	matches := fieldAccessRegex.FindStringSubmatch(line)
	if len(matches) < 7 {
		return nil
	}

	fa := &types.FieldAccess{
		SourceLocation: types.SourceLocation{Line: lineNum},
		Op:             matches[1],
		Register:       matches[2],
		Class:          strings.ReplaceAll(matches[4], "/", "."),
		Field:          matches[5],
		Type:           matches[6],
	}

	if matches[3] != "" {
		fa.Object = matches[3]
	}

	fa.IsStatic = strings.HasPrefix(fa.Op, "s")
	fa.IsRead = strings.Contains(fa.Op, "get")
	fa.IsWrite = strings.Contains(fa.Op, "put")

	return fa
}

func (p *SmaliParser) parseReturn(line string, lineNum int) *types.Return {
	matches := returnRegex.FindStringSubmatch(line)
	if len(matches) < 2 {
		return nil
	}

	ret := &types.Return{
		SourceLocation: types.SourceLocation{Line: lineNum},
		Op:             matches[1],
		IsVoid:         matches[1] == "return-void",
	}

	if len(matches) > 2 && matches[2] != "" {
		ret.Register = matches[2]
	}

	return ret
}

func (p *SmaliParser) parseSwitch(line string, lineNum int) *types.Switch {
	matches := switchRegex.FindStringSubmatch(line)
	if len(matches) < 4 {
		return nil
	}

	return &types.Switch{
		SourceLocation: types.SourceLocation{Line: lineNum},
		Type:           matches[1],
		Register:       matches[2],
		Targets:        []string{matches[3]},
	}
}

func (p *SmaliParser) parseCatch(method *types.SmaliMethod, line string) {
	if matches := catchRegex.FindStringSubmatch(line); len(matches) > 3 {
		// Parse range from {start .. end}
		rangeStr := matches[2]
		parts := strings.Split(rangeStr, " .. ")
		if len(parts) == 2 {
			method.TryCatches = append(method.TryCatches, types.TryCatch{
				StartLabel:    strings.TrimSpace(parts[0]),
				EndLabel:      strings.TrimSpace(parts[1]),
				HandlerLabel:  matches[3],
				ExceptionType: strings.ReplaceAll(matches[1], "/", "."),
			})
		}
	} else if matches := catchAllRegex.FindStringSubmatch(line); len(matches) > 2 {
		rangeStr := matches[1]
		parts := strings.Split(rangeStr, " .. ")
		if len(parts) == 2 {
			method.TryCatches = append(method.TryCatches, types.TryCatch{
				StartLabel:    strings.TrimSpace(parts[0]),
				EndLabel:      strings.TrimSpace(parts[1]),
				HandlerLabel:  matches[2],
				ExceptionType: "*",
			})
		}
	}
}

func (p *SmaliParser) isFieldAccess(line string) bool {
	return strings.HasPrefix(line, "iget") || strings.HasPrefix(line, "iput") ||
		strings.HasPrefix(line, "sget") || strings.HasPrefix(line, "sput")
}

func (p *SmaliParser) parseGenericInstruction(line string, lineNum int) *types.Instruction {
	matches := opcodeRegex.FindStringSubmatch(line)
	if len(matches) < 2 {
		return nil
	}

	instr := &types.Instruction{
		SourceLocation: types.SourceLocation{Line: lineNum},
		Opcode:         matches[1],
		Raw:            line,
	}

	if len(matches) > 2 {
		instr.Operands = strings.Split(matches[2], ",")
		for i := range instr.Operands {
			instr.Operands[i] = strings.TrimSpace(instr.Operands[i])
		}
	}

	// Categorize
	switch {
	case strings.HasPrefix(instr.Opcode, "move"):
		instr.Category = types.InstrCategoryMove
	case strings.HasPrefix(instr.Opcode, "const"):
		instr.Category = types.InstrCategoryConst
	case strings.HasPrefix(instr.Opcode, "goto"):
		instr.Category = types.InstrCategoryGoto
	case strings.HasPrefix(instr.Opcode, "throw"):
		instr.Category = types.InstrCategoryThrow
	case strings.HasPrefix(instr.Opcode, "check-cast"):
		instr.Category = types.InstrCategoryCheckCast
	case strings.HasPrefix(instr.Opcode, "instance-of"):
		instr.Category = types.InstrCategoryInstanceOf
	case strings.HasPrefix(instr.Opcode, "if-"):
		instr.Category = types.InstrCategoryIf
	case strings.HasPrefix(instr.Opcode, "aget"):
		instr.Category = types.InstrCategoryArrayGet
	case strings.HasPrefix(instr.Opcode, "aput"):
		instr.Category = types.InstrCategoryArrayPut
	case strings.HasPrefix(instr.Opcode, "cmp"):
		instr.Category = types.InstrCategoryCompare
	case strings.HasPrefix(instr.Opcode, "add") ||
		strings.HasPrefix(instr.Opcode, "sub") ||
		strings.HasPrefix(instr.Opcode, "mul") ||
		strings.HasPrefix(instr.Opcode, "div") ||
		strings.HasPrefix(instr.Opcode, "rem") ||
		strings.HasPrefix(instr.Opcode, "and") ||
		strings.HasPrefix(instr.Opcode, "or") ||
		strings.HasPrefix(instr.Opcode, "xor") ||
		strings.HasPrefix(instr.Opcode, "shl") ||
		strings.HasPrefix(instr.Opcode, "shr") ||
		strings.HasPrefix(instr.Opcode, "ushr"):
		instr.Category = types.InstrCategoryBinaryOp
	case strings.HasPrefix(instr.Opcode, "neg") ||
		strings.HasPrefix(instr.Opcode, "not") ||
		strings.HasPrefix(instr.Opcode, "int-to") ||
		strings.HasPrefix(instr.Opcode, "float-to") ||
		strings.HasPrefix(instr.Opcode, "double-to") ||
		strings.HasPrefix(instr.Opcode, "long-to"):
		instr.Category = types.InstrCategoryUnaryOp
	default:
		instr.Category = types.InstrCategoryUnknown
	}

	return instr
}

func (p *SmaliParser) parseRegisters(regStr string) []string {
	regStr = strings.TrimSpace(regStr)
	if regStr == "" {
		return nil
	}

	parts := strings.Split(regStr, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// ============================================================================
// METRICS CALCULATION
// ============================================================================

func (p *SmaliParser) calculateMetrics(method *types.SmaliMethod) {
	m := &method.Metrics

	m.InstructionCount = len(method.Instructions)
	m.InvokeCount = len(method.Invokes)
	m.ConditionCount = len(method.Conditions)
	m.StringConstCount = len(method.StringConsts)
	m.FieldAccessCount = len(method.FieldAccesses)
	m.ReturnCount = len(method.Returns)
	m.LabelCount = len(method.Labels)
	m.TryCatchCount = len(method.TryCatches)

	// Count invoke types
	for _, inv := range method.Invokes {
		idx := int(inv.Type)
		if idx >= 0 && idx < len(m.InvokesByType) {
			m.InvokesByType[idx]++
		}
	}

	// Basic cyclomatic complexity
	m.CyclomaticComplexity = m.ConditionCount + len(method.Switches) + 1
}

// ============================================================================
// SUSPICION SCORING
// ============================================================================

func (p *SmaliParser) analyzeSuspicion(method *types.SmaliMethod) {
	score := 0
	reasons := make([]string, 0)

	suspiciousNames := []string{
		"license", "premium", "pro", "paid", "trial",
		"check", "verify", "validate", "unlock", "activate",
	}

	nameLower := strings.ToLower(method.Name)
	for _, sus := range suspiciousNames {
		if strings.Contains(nameLower, sus) {
			score += 3
			reasons = append(reasons, "Suspicious name: "+sus)
			break
		}
	}

	if method.ReturnsBoolean {
		score++
		reasons = append(reasons, "Returns boolean")
	}

	if len(method.Name) <= 2 && method.Name != "<init>" && method.Name != "<clinit>" {
		score++
		reasons = append(reasons, "Short name (obfuscated?)")
	}

	if len(method.Conditions) > 3 {
		score++
		reasons = append(reasons, "Many conditions")
	}

	method.SuspicionScore = score
	method.SuspicionReasons = reasons
}

// GetSuspiciousMethods returns methods with suspicion score >= minScore.
func (p *SmaliParser) GetSuspiciousMethods(class *types.SmaliClass, minScore int) []types.SmaliMethod {
	result := make([]types.SmaliMethod, 0)
	for _, method := range class.Methods {
		if method.SuspicionScore >= minScore {
			result = append(result, method)
		}
	}
	return result
}

func firstToken(line string) string {
	if fields := strings.Fields(line); len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// ============================================================================
// SMALI STRING UNESCAPING
// ============================================================================

// UnescapeSmaliString is the exported form of unescapeSmaliString for
// consumers outside the parser package (e.g. the dexir text adapter).
// Moved here from the deleted FSM parser (parser.go): it was the only
// symbol of that implementation with live callers.
func UnescapeSmaliString(s string) string { return unescapeSmaliString(s) }

// unescapeSmaliString decodes escape sequences in a smali string.
func unescapeSmaliString(s string) string {
	// Fast path: no escapes, return as-is.
	if !strings.ContainsRune(s, '\\') {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}

		i++ // skip backslash
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		case '0':
			b.WriteByte(0)
		case 'u':
			// Unicode escape: \uXXXX
			if i+4 < len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+5], 16, 32); err == nil {
					b.WriteRune(rune(v))
					i += 4
				} else {
					b.WriteByte('\\')
					b.WriteByte('u')
				}
			} else {
				b.WriteByte('\\')
				b.WriteByte('u')
			}
		default:
			// Unknown escape — keep both characters.
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}

	return b.String()
}
