package types

import (
	"encoding/json"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ENUMS: ZERO-ALLOCATION + PRECOMPUTED MAP LOOKUP
// ═══════════════════════════════════════════════════════════════════════════════

// ───────────────────────────────────────────────────────────────────────────────
// FileType
// ───────────────────────────────────────────────────────────────────────────────

type FileType uint8

const (
	FileTypeUnknown FileType = iota
	FileTypeSmali
	FileTypeXML
	FileTypeJSON
	FileTypeProperties
	FileTypeText
	FileTypeNative
	FileTypeResource
	FileTypeDex
	FileTypeArchive
	FileTypeSignature
	FileTypeCache
	FileTypePatch
	FileTypeMedia // New: Phase 6 Media files
	fileTypeCount
)

var (
	fileTypeNames = [fileTypeCount]string{
		"unknown", "smali", "xml", "json", "properties", "text", "native", "resource",
		"dex", "archive", "signature", "cache", "patch", "media",
	}
	// Precomputed map for O(1) unmarshal
	fileTypeByName = func() map[string]FileType {
		m := make(map[string]FileType, fileTypeCount)
		for i, name := range fileTypeNames {
			m[name] = FileType(i)
		}
		return m
	}()
	// Precomputed JSON bytes (zero-alloc marshal)
	fileTypeJSON = func() [fileTypeCount][]byte {
		var result [fileTypeCount][]byte
		for i, name := range fileTypeNames {
			result[i], _ = json.Marshal(name)
		}
		return result
	}()
)

func (ft FileType) String() string {
	if ft < fileTypeCount {
		return fileTypeNames[ft]
	}
	return "unknown"
}

func (ft FileType) IsValid() bool { return ft < fileTypeCount }

func (ft FileType) MarshalJSON() ([]byte, error) {
	if ft < fileTypeCount {
		return fileTypeJSON[ft], nil
	}
	return fileTypeJSON[0], nil
}

func (ft *FileType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if v, ok := fileTypeByName[s]; ok {
		*ft = v
	} else {
		*ft = FileTypeUnknown
	}
	return nil
}

// ───────────────────────────────────────────────────────────────────────────────
// RiskLevel
// ───────────────────────────────────────────────────────────────────────────────

type RiskLevel uint8

const (
	RiskNone RiskLevel = iota
	RiskLow
	RiskMedium
	RiskHigh
	RiskCritical
	riskLevelCount
)

var (
	riskLevelNames  = [riskLevelCount]string{"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	riskLevelEmojis = [riskLevelCount]string{"⚪", "🟢", "🟡", "🟠", "🔴"}
	riskLevelColors = [riskLevelCount]string{"gray", "green", "yellow", "orange", "red"}
	riskLevelByName = func() map[string]RiskLevel {
		m := make(map[string]RiskLevel, riskLevelCount)
		for i, name := range riskLevelNames {
			m[name] = RiskLevel(i)
		}
		return m
	}()
	riskLevelJSON = func() [riskLevelCount][]byte {
		var result [riskLevelCount][]byte
		for i, name := range riskLevelNames {
			result[i], _ = json.Marshal(name)
		}
		return result
	}()
)

func (r RiskLevel) String() string {
	if r < riskLevelCount {
		return riskLevelNames[r]
	}
	return "UNKNOWN"
}

func (r RiskLevel) Emoji() string {
	if r < riskLevelCount {
		return riskLevelEmojis[r]
	}
	return "❓"
}

func (r RiskLevel) Color() string {
	if r < riskLevelCount {
		return riskLevelColors[r]
	}
	return "gray"
}

func (r RiskLevel) IsValid() bool        { return r < riskLevelCount }
func (r RiskLevel) IsCritical() bool     { return r == RiskCritical }
func (r RiskLevel) IsHigh() bool         { return r >= RiskHigh }
func (r RiskLevel) RequiresAction() bool { return r >= RiskMedium }

func (r RiskLevel) MarshalJSON() ([]byte, error) {
	if r < riskLevelCount {
		return riskLevelJSON[r], nil
	}
	return riskLevelJSON[0], nil
}

func (r *RiskLevel) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if v, ok := riskLevelByName[s]; ok {
		*r = v
	} else {
		*r = RiskNone
	}
	return nil
}

// ───────────────────────────────────────────────────────────────────────────────
// Priority
// ───────────────────────────────────────────────────────────────────────────────

type Priority uint8

const (
	PriorityInfo Priority = iota
	PriorityLow
	PriorityMedium
	PriorityHigh
	PriorityCritical
	priorityCount
)

var (
	priorityNames  = [priorityCount]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
	priorityEmojis = [priorityCount]string{"ℹ️", "🟢", "🟡", "🟠", "🔴"}
	priorityByName = func() map[string]Priority {
		m := make(map[string]Priority, priorityCount)
		for i, name := range priorityNames {
			m[name] = Priority(i)
		}
		return m
	}()
	priorityJSON = func() [priorityCount][]byte {
		var result [priorityCount][]byte
		for i, name := range priorityNames {
			result[i], _ = json.Marshal(name)
		}
		return result
	}()
)

func (p Priority) String() string {
	if p < priorityCount {
		return priorityNames[p]
	}
	return "UNKNOWN"
}

func (p Priority) Emoji() string {
	if p < priorityCount {
		return priorityEmojis[p]
	}
	return "❓"
}

func (p Priority) IsValid() bool { return p < priorityCount }

func (p Priority) MarshalJSON() ([]byte, error) {
	if p < priorityCount {
		return priorityJSON[p], nil
	}
	return priorityJSON[0], nil
}

func (p *Priority) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if v, ok := priorityByName[s]; ok {
		*p = v
	} else {
		*p = PriorityInfo
	}
	return nil
}

// ───────────────────────────────────────────────────────────────────────────────
// DecisionType
// ───────────────────────────────────────────────────────────────────────────────

type DecisionType uint8

const (
	DecisionUnknown DecisionType = iota
	DecisionBooleanReturn
	DecisionConditional
	DecisionCallback
	DecisionSwitch
	DecisionException
	decisionTypeCount
)

var (
	decisionTypeNames = [decisionTypeCount]string{
		"unknown", "boolean_return", "conditional", "callback", "switch", "exception",
	}
	decisionTypeByName = func() map[string]DecisionType {
		m := make(map[string]DecisionType, decisionTypeCount)
		for i, name := range decisionTypeNames {
			m[name] = DecisionType(i)
		}
		return m
	}()
)

func (d DecisionType) String() string {
	if d < decisionTypeCount {
		return decisionTypeNames[d]
	}
	return "unknown"
}

func (d DecisionType) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *DecisionType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if v, ok := decisionTypeByName[s]; ok {
		*d = v
	} else {
		*d = DecisionUnknown
	}
	return nil
}

// ───────────────────────────────────────────────────────────────────────────────
// Severity
// ───────────────────────────────────────────────────────────────────────────────

type Severity uint8

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
	severityCount
)

var (
	severityNames  = [severityCount]string{"info", "low", "medium", "high", "critical"}
	severityByName = func() map[string]Severity {
		m := make(map[string]Severity, severityCount)
		for i, name := range severityNames {
			m[name] = Severity(i)
		}
		return m
	}()
)

func (s Severity) String() string {
	if s < severityCount {
		return severityNames[s]
	}
	return "unknown"
}

func (s Severity) ToRiskLevel() RiskLevel { return RiskLevel(s) }

func (s Severity) Emoji() string {
	switch s {
	case SeverityCritical:
		return "🔴"
	case SeverityHigh:
		return "🟠"
	case SeverityMedium:
		return "🟡"
	case SeverityLow:
		return "🔵"
	default:
		return "⚪"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	if v, ok := severityByName[str]; ok {
		*s = v
	} else {
		*s = SeverityInfo
	}
	return nil
}

// ───────────────────────────────────────────────────────────────────────────────
// InstructionCategory
// ───────────────────────────────────────────────────────────────────────────────

type InstructionCategory uint8

const (
	InstrCategoryUnknown InstructionCategory = iota
	InstrCategoryMove
	InstrCategoryReturn
	InstrCategoryConst
	InstrCategoryMonitor
	InstrCategoryCheckCast
	InstrCategoryInstanceOf
	InstrCategoryArrayOp
	InstrCategoryThrow
	InstrCategoryGoto
	InstrCategorySwitch
	InstrCategoryCompare
	InstrCategoryIf
	InstrCategoryArrayGet
	InstrCategoryArrayPut
	InstrCategoryFieldGet
	InstrCategoryFieldPut
	InstrCategoryInvoke
	InstrCategoryUnaryOp
	InstrCategoryBinaryOp
	instrCategoryCount
)

var instrCategoryNames = [instrCategoryCount]string{
	"unknown", "move", "return", "const", "monitor", "check_cast", "instance_of",
	"array_op", "throw", "goto", "switch", "compare", "if", "array_get", "array_put",
	"field_get", "field_put", "invoke", "unary_op", "binary_op",
}

func (c InstructionCategory) String() string {
	if c < instrCategoryCount {
		return instrCategoryNames[c]
	}
	return "unknown"
}

// ───────────────────────────────────────────────────────────────────────────────
// ConditionOp — GLOBAL MAP (фикс бага #6)
// ───────────────────────────────────────────────────────────────────────────────

type ConditionOp uint8

const (
	CondOpUnknown ConditionOp = iota
	CondOpEq
	CondOpNe
	CondOpLt
	CondOpGe
	CondOpGt
	CondOpLe
	CondOpEqz
	CondOpNez
	CondOpLtz
	CondOpGez
	CondOpGtz
	CondOpLez
	condOpCount
)

var (
	condOpNames = [condOpCount]string{
		"unknown", "eq", "ne", "lt", "ge", "gt", "le", "eqz", "nez", "ltz", "gez", "gtz", "lez",
	}
	// GLOBAL: precomputed map (фикс бага #6)
	condOpByName = map[string]ConditionOp{
		"if-eq": CondOpEq, "if-ne": CondOpNe, "if-lt": CondOpLt,
		"if-ge": CondOpGe, "if-gt": CondOpGt, "if-le": CondOpLe,
		"if-eqz": CondOpEqz, "if-nez": CondOpNez, "if-ltz": CondOpLtz,
		"if-gez": CondOpGez, "if-gtz": CondOpGtz, "if-lez": CondOpLez,
	}
	// Precomputed negate table
	condOpNegate = [condOpCount]ConditionOp{
		CondOpUnknown, CondOpNe, CondOpEq, CondOpGe, CondOpLt, CondOpLe, CondOpGt,
		CondOpNez, CondOpEqz, CondOpGez, CondOpLtz, CondOpLez, CondOpGtz,
	}
)

func (c ConditionOp) String() string {
	if c < condOpCount {
		return condOpNames[c]
	}
	return "unknown"
}

func (c ConditionOp) IsZeroCheck() bool {
	return c >= CondOpEqz && c <= CondOpLez
}

func (c ConditionOp) Negate() ConditionOp {
	if c < condOpCount {
		return condOpNegate[c]
	}
	return c
}

// ───────────────────────────────────────────────────────────────────────────────
// InvokeType
// ───────────────────────────────────────────────────────────────────────────────

type InvokeType uint8

const (
	InvokeUnknown InvokeType = iota
	InvokeVirtual
	InvokeSuper
	InvokeDirect
	InvokeStatic
	InvokeInterface
	InvokePolymorphic
	InvokeCustom
	invokeTypeCount
)

var (
	invokeTypeNames = [invokeTypeCount]string{
		"unknown", "virtual", "super", "direct", "static", "interface", "polymorphic", "custom",
	}
	// GLOBAL precomputed map
	invokeTypeByPrefix = map[string]InvokeType{
		"invoke-virtual":           InvokeVirtual,
		"invoke-virtual/range":     InvokeVirtual,
		"invoke-super":             InvokeSuper,
		"invoke-super/range":       InvokeSuper,
		"invoke-direct":            InvokeDirect,
		"invoke-direct/range":      InvokeDirect,
		"invoke-static":            InvokeStatic,
		"invoke-static/range":      InvokeStatic,
		"invoke-interface":         InvokeInterface,
		"invoke-interface/range":   InvokeInterface,
		"invoke-polymorphic":       InvokePolymorphic,
		"invoke-polymorphic/range": InvokePolymorphic,
		"invoke-custom":            InvokeCustom,
		"invoke-custom/range":      InvokeCustom,
	}
)

func (i InvokeType) String() string {
	if i < invokeTypeCount {
		return invokeTypeNames[i]
	}
	return "unknown"
}

func (i InvokeType) IsStatic() bool { return i == InvokeStatic }

// ═══════════════════════════════════════════════════════════════════════════════
// ACCESS FLAGS — uint32 (фикс бага: overflow)
// ═══════════════════════════════════════════════════════════════════════════════

// AccessFlags — битовые флаги доступа.
// uint32 для поддержки AccessConstructor (0x10000).
type AccessFlags uint32

const (
	AccessPublic               AccessFlags = 1 << iota // 0x0001
	AccessPrivate                                      // 0x0002
	AccessProtected                                    // 0x0004
	AccessStatic                                       // 0x0008
	AccessFinal                                        // 0x0010
	AccessSynchronized                                 // 0x0020
	AccessVolatile                                     // 0x0040
	AccessTransient                                    // 0x0080
	AccessNative                                       // 0x0100
	AccessInterface                                    // 0x0200
	AccessAbstract                                     // 0x0400
	AccessStrict                                       // 0x0800
	AccessSynthetic                                    // 0x1000
	AccessAnnotation                                   // 0x2000
	AccessEnum                                         // 0x4000
	_                                                  // 0x8000 (reserved)
	AccessConstructor                                  // 0x10000
	AccessDeclaredSynchronized                         // 0x20000
)

func (a AccessFlags) IsPublic() bool      { return a&AccessPublic != 0 }
func (a AccessFlags) IsPrivate() bool     { return a&AccessPrivate != 0 }
func (a AccessFlags) IsProtected() bool   { return a&AccessProtected != 0 }
func (a AccessFlags) IsStatic() bool      { return a&AccessStatic != 0 }
func (a AccessFlags) IsFinal() bool       { return a&AccessFinal != 0 }
func (a AccessFlags) IsNative() bool      { return a&AccessNative != 0 }
func (a AccessFlags) IsAbstract() bool    { return a&AccessAbstract != 0 }
func (a AccessFlags) IsSynthetic() bool   { return a&AccessSynthetic != 0 }
func (a AccessFlags) IsInterface() bool   { return a&AccessInterface != 0 }
func (a AccessFlags) IsConstructor() bool { return a&AccessConstructor != 0 }

// Ordered slice для детерминированного вывода (фикс #13)
var accessFlagOrder = []AccessFlags{
	AccessPublic, AccessPrivate, AccessProtected, AccessStatic,
	AccessFinal, AccessSynchronized, AccessVolatile, AccessTransient,
	AccessNative, AccessInterface, AccessAbstract, AccessStrict,
	AccessSynthetic, AccessAnnotation, AccessEnum, AccessConstructor,
}

var accessFlagToString = map[AccessFlags]string{
	AccessPublic:       "public",
	AccessPrivate:      "private",
	AccessProtected:    "protected",
	AccessStatic:       "static",
	AccessFinal:        "final",
	AccessSynchronized: "synchronized",
	AccessVolatile:     "volatile",
	AccessTransient:    "transient",
	AccessNative:       "native",
	AccessInterface:    "interface",
	AccessAbstract:     "abstract",
	AccessStrict:       "strictfp",
	AccessSynthetic:    "synthetic",
	AccessAnnotation:   "annotation",
	AccessEnum:         "enum",
	AccessConstructor:  "constructor",
}

var stringToAccessFlag = func() map[string]AccessFlags {
	m := make(map[string]AccessFlags, len(accessFlagToString)*2)
	for flag, name := range accessFlagToString {
		m[name] = flag
	}
	// Aliases
	m["bridge"] = AccessVolatile
	m["varargs"] = AccessTransient
	return m
}()

// ToStrings — детерминированный порядок вывода (фикс #13).
func (a AccessFlags) ToStrings() []string {
	if a == 0 {
		return nil
	}
	result := make([]string, 0, 4)
	for _, flag := range accessFlagOrder {
		if a&flag != 0 {
			if name, ok := accessFlagToString[flag]; ok {
				result = append(result, name)
			}
		}
	}
	return result
}
