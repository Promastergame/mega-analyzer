package parser

import (
	"context"
	"fmt"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════
// SOURCE LOCATION
// ═══════════════════════════════════════════════════════════════════

// SourceLocation — позиция в исходном файле.
type SourceLocation struct {
	Line   int
	Column int
	Offset int // байтовое смещение в файле
}

func (s SourceLocation) String() string {
	if s.Column > 0 {
		return fmt.Sprintf("%d:%d", s.Line, s.Column)
	}
	return fmt.Sprintf("%d", s.Line)
}

// SourceRange — диапазон строк [Start, End].
type SourceRange struct {
	Start SourceLocation
	End   SourceLocation
}

func (r SourceRange) LineCount() int {
	if r.End.Line < r.Start.Line {
		return 0
	}
	return r.End.Line - r.Start.Line + 1
}

// ═══════════════════════════════════════════════════════════════════
// ACCESS FLAGS (DEX-совместимые битовые флаги)
// ═══════════════════════════════════════════════════════════════════

// AccessFlags — битовая маска модификаторов доступа DEX формата.
type AccessFlags uint32

const (
	AccPublic       AccessFlags = 0x0001
	AccPrivate      AccessFlags = 0x0002
	AccProtected    AccessFlags = 0x0004
	AccStatic       AccessFlags = 0x0008
	AccFinal        AccessFlags = 0x0010
	AccSynchronized AccessFlags = 0x0020
	AccVolatile     AccessFlags = 0x0040 // для полей
	AccBridge       AccessFlags = 0x0040 // для методов
	AccTransient    AccessFlags = 0x0080 // для полей
	AccVarargs      AccessFlags = 0x0080 // для методов
	AccNative       AccessFlags = 0x0100
	AccInterface    AccessFlags = 0x0200
	AccAbstract     AccessFlags = 0x0400
	AccStrict       AccessFlags = 0x0800
	AccSynthetic    AccessFlags = 0x1000
	AccAnnotation   AccessFlags = 0x2000
	AccEnum         AccessFlags = 0x4000
	AccConstructor  AccessFlags = 0x10000
	AccDeclaredSync AccessFlags = 0x20000
)

func (f AccessFlags) Has(flag AccessFlags) bool { return f&flag != 0 }
func (f AccessFlags) IsPublic() bool            { return f.Has(AccPublic) }
func (f AccessFlags) IsPrivate() bool           { return f.Has(AccPrivate) }
func (f AccessFlags) IsProtected() bool         { return f.Has(AccProtected) }
func (f AccessFlags) IsStatic() bool            { return f.Has(AccStatic) }
func (f AccessFlags) IsFinal() bool             { return f.Has(AccFinal) }
func (f AccessFlags) IsSynthetic() bool         { return f.Has(AccSynthetic) }
func (f AccessFlags) IsAbstract() bool          { return f.Has(AccAbstract) }
func (f AccessFlags) IsNative() bool            { return f.Has(AccNative) }

// Visibility возвращает строку видимости: "public", "private", "protected" или "package".
func (f AccessFlags) Visibility() string {
	switch {
	case f.Has(AccPublic):
		return "public"
	case f.Has(AccPrivate):
		return "private"
	case f.Has(AccProtected):
		return "protected"
	default:
		return "package"
	}
}

func (f AccessFlags) String() string {
	var parts []string
	flagNames := []struct {
		flag AccessFlags
		name string
	}{
		{AccPublic, "public"},
		{AccPrivate, "private"},
		{AccProtected, "protected"},
		{AccStatic, "static"},
		{AccFinal, "final"},
		{AccSynchronized, "synchronized"},
		{AccNative, "native"},
		{AccAbstract, "abstract"},
		{AccSynthetic, "synthetic"},
		{AccEnum, "enum"},
		{AccInterface, "interface"},
		{AccAnnotation, "annotation"},
	}

	for _, fn := range flagNames {
		if f.Has(fn.flag) {
			parts = append(parts, fn.name)
		}
	}
	return "[" + strings.Join(parts, " ") + "]"
}

var accessFlagMap = map[string]AccessFlags{
	"public":                AccPublic,
	"private":               AccPrivate,
	"protected":             AccProtected,
	"static":                AccStatic,
	"final":                 AccFinal,
	"synchronized":          AccSynchronized,
	"volatile":              AccVolatile,
	"bridge":                AccBridge,
	"transient":             AccTransient,
	"varargs":               AccVarargs,
	"native":                AccNative,
	"interface":             AccInterface,
	"abstract":              AccAbstract,
	"strictfp":              AccStrict,
	"synthetic":             AccSynthetic,
	"annotation":            AccAnnotation,
	"enum":                  AccEnum,
	"constructor":           AccConstructor,
	"declared-synchronized": AccDeclaredSync,
}

// ParseAccessFlags парсит список строковых модификаторов в битовую маску.
func ParseAccessFlags(modifiers []string) AccessFlags {
	var flags AccessFlags
	for _, mod := range modifiers {
		if f, ok := accessFlagMap[mod]; ok {
			flags |= f
		}
	}
	return flags
}

// ═══════════════════════════════════════════════════════════════════
// TYPE INFO — структурированное представление DEX-типа
// ═══════════════════════════════════════════════════════════════════

// TypeKind — вид типа в DEX.
type TypeKind uint8

const (
	TypeKindPrimitive TypeKind = iota
	TypeKindObject
	TypeKindArray
	TypeKindVoid
	TypeKindUnknown
)

func (k TypeKind) String() string {
	names := [...]string{"primitive", "object", "array", "void", "unknown"}
	if int(k) < len(names) {
		return names[k]
	}
	return "unknown"
}

// TypeInfo — структурированная информация о DEX-типе.
type TypeInfo struct {
	Raw         string // оригинальная строка: [Ljava/lang/String;
	Kind        TypeKind
	BaseType    string // человекочитаемый базовый тип
	ClassName   string // для объектов: java.lang.String
	ArrayDepth  int    // размерность массива
	IsPrimitive bool
}

// primitiveTypes — таблица для O(1) маппинга дескрипторов примитивов.
var primitiveTypes = [256]struct {
	name  string
	valid bool
}{
	'V': {"void", true},
	'Z': {"boolean", true},
	'B': {"byte", true},
	'C': {"char", true},
	'S': {"short", true},
	'I': {"int", true},
	'J': {"long", true},
	'F': {"float", true},
	'D': {"double", true},
}

// ParseType парсит DEX-дескриптор типа в TypeInfo.
//
// Примеры:
//   - "I" → TypeKindPrimitive, BaseType="int"
//   - "Ljava/lang/String;" → TypeKindObject, ClassName="java.lang.String"
//   - "[I" → TypeKindArray, ArrayDepth=1, BaseType="int"
//   - "[[Ljava/lang/Object;" → TypeKindArray, ArrayDepth=2, ClassName="java.lang.Object"
func ParseType(raw string) TypeInfo {
	ti := TypeInfo{Raw: raw}

	s := raw

	// Считаем размерность массива
	for len(s) > 0 && s[0] == '[' {
		ti.ArrayDepth++
		s = s[1:]
	}

	if len(s) == 0 {
		ti.Kind = TypeKindUnknown
		return ti
	}

	ch := s[0]

	// Проверяем примитив через lookup table
	if prim := primitiveTypes[ch]; prim.valid {
		ti.IsPrimitive = true
		ti.BaseType = prim.name
		if ch == 'V' {
			ti.Kind = TypeKindVoid
		} else if ti.ArrayDepth > 0 {
			ti.Kind = TypeKindArray
		} else {
			ti.Kind = TypeKindPrimitive
		}
		return ti
	}

	// Объектный тип: Ljava/lang/String;
	if ch == 'L' {
		if ti.ArrayDepth > 0 {
			ti.Kind = TypeKindArray
		} else {
			ti.Kind = TypeKindObject
		}
		if len(s) > 2 && s[len(s)-1] == ';' {
			ti.ClassName = normalizeClassName(s[1 : len(s)-1])
			ti.BaseType = ti.ClassName
		} else {
			// Malformed, но не падаем
			ti.BaseType = s
		}
		return ti
	}

	ti.Kind = TypeKindUnknown
	ti.BaseType = s
	return ti
}

// String возвращает человекочитаемое представление типа.
func (ti TypeInfo) String() string {
	var b strings.Builder
	name := ti.BaseType
	if name == "" {
		name = ti.Raw
	}
	b.WriteString(name)
	for i := 0; i < ti.ArrayDepth; i++ {
		b.WriteString("[]")
	}
	return b.String()
}

// ═══════════════════════════════════════════════════════════════════
// INVOKE TYPE
// ═══════════════════════════════════════════════════════════════════

// InvokeType — тип вызова метода в DEX bytecode.
type InvokeType uint8

const (
	InvokeVirtual InvokeType = iota
	InvokeSuper
	InvokeDirect
	InvokeStatic
	InvokeInterface
	InvokeVirtualRange
	InvokeSuperRange
	InvokeDirectRange
	InvokeStaticRange
	InvokeInterfaceRange
	InvokePolymorphic
	InvokePolymorphicRange
	InvokeCustom
	InvokeCustomRange
	InvokeUnknown
)

var invokeTypeNames = [...]string{
	"virtual", "super", "direct", "static", "interface",
	"virtual/range", "super/range", "direct/range", "static/range", "interface/range",
	"polymorphic", "polymorphic/range", "custom", "custom/range", "unknown",
}

func (t InvokeType) String() string {
	if int(t) < len(invokeTypeNames) {
		return invokeTypeNames[t]
	}
	return "unknown"
}

func (t InvokeType) IsRange() bool {
	return t >= InvokeVirtualRange && t <= InvokeCustomRange
}

// IsStatic возвращает true для static и static/range.
func (t InvokeType) IsStatic() bool {
	return t == InvokeStatic || t == InvokeStaticRange
}

var invokeTypeMap = map[string]InvokeType{
	"invoke-virtual":           InvokeVirtual,
	"invoke-super":             InvokeSuper,
	"invoke-direct":            InvokeDirect,
	"invoke-static":            InvokeStatic,
	"invoke-interface":         InvokeInterface,
	"invoke-virtual/range":     InvokeVirtualRange,
	"invoke-super/range":       InvokeSuperRange,
	"invoke-direct/range":      InvokeDirectRange,
	"invoke-static/range":      InvokeStaticRange,
	"invoke-interface/range":   InvokeInterfaceRange,
	"invoke-polymorphic":       InvokePolymorphic,
	"invoke-polymorphic/range": InvokePolymorphicRange,
	"invoke-custom":            InvokeCustom,
	"invoke-custom/range":      InvokeCustomRange,
}

// ParseInvokeType парсит opcode строку в InvokeType.
func ParseInvokeType(opcode string) InvokeType {
	if t, ok := invokeTypeMap[opcode]; ok {
		return t
	}
	return InvokeUnknown
}

// ═══════════════════════════════════════════════════════════════════
// INSTRUCTION CATEGORY
// ═══════════════════════════════════════════════════════════════════

// InstructionCategory — категория инструкции DEX bytecode.
type InstructionCategory uint8

const (
	InstrCategoryUnknown InstructionCategory = iota
	InstrCategoryNop
	InstrCategoryMove
	InstrCategoryConst
	InstrCategoryMonitor
	InstrCategoryCheckCast
	InstrCategoryInstanceOf
	InstrCategoryArrayLength
	InstrCategoryNewInstance
	InstrCategoryNewArray
	InstrCategoryFilledNewArray
	InstrCategoryFillArrayData
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
	InstrCategoryReturn
)

var instrCategoryNames = [...]string{
	"unknown", "nop", "move", "const", "monitor",
	"check-cast", "instance-of", "array-length",
	"new-instance", "new-array", "filled-new-array", "fill-array-data",
	"throw", "goto", "switch", "compare", "if",
	"array-get", "array-put", "field-get", "field-put",
	"invoke", "unary-op", "binary-op", "return",
}

func (c InstructionCategory) String() string {
	if int(c) < len(instrCategoryNames) {
		return instrCategoryNames[c]
	}
	return "unknown"
}

// IsControlFlow возвращает true для инструкций управления потоком.
func (c InstructionCategory) IsControlFlow() bool {
	switch c {
	case InstrCategoryGoto, InstrCategoryIf, InstrCategorySwitch,
		InstrCategoryReturn, InstrCategoryThrow:
		return true
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════
// STRING FLAGS — битовые флаги для классификации строковых констант
// ═══════════════════════════════════════════════════════════════════

// StringFlags — битовая маска характеристик строковой константы.
type StringFlags uint16

const (
	StringFlagEmpty      StringFlags = 1 << iota
	StringFlagURL                    // содержит URL
	StringFlagPackage                // похоже на имя пакета
	StringFlagBase64                 // похоже на Base64
	StringFlagHex                    // похоже на hex-строку
	StringFlagKey                    // содержит ключевые слова: key, secret, token...
	StringFlagPath                   // содержит путь файловой системы
	StringFlagSQL                    // содержит SQL-запрос
	StringFlagJSON                   // похоже на JSON
	StringFlagXML                    // похоже на XML
	StringFlagCrypto                 // содержит crypto-related термины
	StringFlagSuspicious             // содержит подозрительные термины
)

func (f StringFlags) Has(flag StringFlags) bool { return f&flag != 0 }

// IsSensitive возвращает true если строка содержит потенциально чувствительные данные.
func (f StringFlags) IsSensitive() bool {
	return f.Has(StringFlagKey) || f.Has(StringFlagCrypto) || f.Has(StringFlagSuspicious)
}

func (f StringFlags) String() string {
	if f == 0 {
		return "none"
	}
	var parts []string
	flagNames := []struct {
		flag StringFlags
		name string
	}{
		{StringFlagEmpty, "empty"},
		{StringFlagURL, "url"},
		{StringFlagPackage, "package"},
		{StringFlagBase64, "base64"},
		{StringFlagHex, "hex"},
		{StringFlagKey, "key"},
		{StringFlagPath, "path"},
		{StringFlagSQL, "sql"},
		{StringFlagJSON, "json"},
		{StringFlagXML, "xml"},
		{StringFlagCrypto, "crypto"},
		{StringFlagSuspicious, "suspicious"},
	}
	for _, fn := range flagNames {
		if f.Has(fn.flag) {
			parts = append(parts, fn.name)
		}
	}
	return strings.Join(parts, "|")
}

// ═══════════════════════════════════════════════════════════════════
// PARSED ENTITIES
// ═══════════════════════════════════════════════════════════════════

// Invoke — вызов метода.
type Invoke struct {
	SourceLocation
	Type       InvokeType
	Opcode     string
	Registers  []string
	Class      string // нормализованный: com.example.Class
	RawClass   string // оригинальный: Lcom/example/Class;
	Method     string
	Params     []TypeInfo
	ParamsRaw  string
	ReturnType TypeInfo
	Raw        string
	Tags       []string // автоматические теги (billing, crypto, etc.)
}

// FullSignature возвращает полную сигнатуру вызова: Class.Method(params)ReturnType.
func (inv *Invoke) FullSignature() string {
	return inv.Class + "." + inv.Method + "(" + inv.ParamsRaw + ")" + inv.ReturnType.Raw
}

// Condition — условный переход.
type Condition struct {
	SourceLocation
	Opcode   string
	Operands []string
	Target   string // метка перехода
	Negated  bool   // if-nez, if-ne, etc.
	Raw      string
}

// StringConstant — строковая константа.
type StringConstant struct {
	SourceLocation
	Register string
	Value    string // декодированное значение
	RawValue string // оригинальное значение из smali
	Flags    StringFlags
	Raw      string
}

// FieldAccess — обращение к полю.
type FieldAccess struct {
	SourceLocation
	Opcode   string
	Register string
	Object   string // регистр объекта (для instance fields)
	Class    string // нормализованный
	RawClass string
	Field    string
	Type     TypeInfo
	IsStatic bool
	IsRead   bool
	IsWrite  bool
	Raw      string
}

// Return — инструкция возврата.
type Return struct {
	SourceLocation
	Opcode   string
	Register string
	IsVoid   bool
	Raw      string
}

// Throw — инструкция выброса исключения.
type Throw struct {
	SourceLocation
	Register string
	Raw      string
}

// Label — метка в коде метода.
type Label struct {
	SourceLocation
	Name string
}

// Switch — инструкция переключения.
type Switch struct {
	SourceLocation
	Type     string // packed-switch, sparse-switch
	Register string
	Label    string
	Cases    []SwitchCase
	Raw      string
}

// SwitchCase — один case в switch.
type SwitchCase struct {
	Key   int
	Label string
}

// TryCatch — блок обработки исключений.
type TryCatch struct {
	SourceLocation
	StartLabel    string
	EndLabel      string
	HandlerLabel  string
	ExceptionType string // "*" для catchall
	IsCatchAll    bool
	Raw           string
}

// Instruction — одна инструкция байткода.
type Instruction struct {
	SourceLocation
	Opcode   string
	Operands []string
	Category InstructionCategory
	Raw      string
}

// ═══════════════════════════════════════════════════════════════════
// FIELD
// ═══════════════════════════════════════════════════════════════════

// SmaliField — поле класса.
type SmaliField struct {
	SourceLocation
	Name        string
	Type        TypeInfo
	Access      AccessFlags
	Value       string // начальное значение
	Annotations []Annotation
	Raw         string
}

// ═══════════════════════════════════════════════════════════════════
// METHOD METRICS
// ═══════════════════════════════════════════════════════════════════

// MethodMetrics — вычисленные метрики метода.
type MethodMetrics struct {
	InstructionCount int
	InvokeCount      int
	ConditionCount   int
	StringConstCount int
	FieldAccessCount int
	ReturnCount      int
	ThrowCount       int
	LabelCount       int
	TryCatchCount    int
	SwitchCount      int

	InvokesByType [16]int // по типам invoke

	CyclomaticComplexity int
	NestingDepth         int

	CodeSize      int // количество инструкций (не директив)
	RegisterCount int
}

// ═══════════════════════════════════════════════════════════════════
// METHOD
// ═══════════════════════════════════════════════════════════════════

// SmaliMethod — метод smali-класса с полностью разобранным телом.
type SmaliMethod struct {
	SourceRange
	Name       string
	Params     []TypeInfo
	ParamsRaw  string
	ReturnType TypeInfo
	Access     AccessFlags
	Locals     int
	Registers  int

	// Разобранные элементы тела метода
	Instructions  []Instruction
	Invokes       []Invoke
	Conditions    []Condition
	StringConsts  []StringConstant
	FieldAccesses []FieldAccess
	Returns       []Return
	Throws        []Throw
	Labels        []Label
	Switches      []Switch
	TryCatches    []TryCatch
	Annotations   []Annotation

	// Результаты анализа
	Metrics          MethodMetrics
	SuspicionScore   int
	SuspicionReasons []string
	Tags             []string

	// Флаги
	HasTryCatch    bool
	ReturnsBoolean bool
	IsConstructor  bool
	IsClassInit    bool

	Raw string
}

// FullSignature возвращает полную сигнатуру: name(params)returnType.
func (m *SmaliMethod) FullSignature() string {
	return m.Name + "(" + m.ParamsRaw + ")" + m.ReturnType.Raw
}

// IsSuspicious возвращает true если Score >= threshold.
func (m *SmaliMethod) IsSuspicious(threshold int) bool {
	return m.SuspicionScore >= threshold
}

// ═══════════════════════════════════════════════════════════════════
// ANNOTATION
// ═══════════════════════════════════════════════════════════════════

// Annotation — аннотация класса или метода.
type Annotation struct {
	SourceRange
	Type   string
	Values map[string]string
	Raw    string
}

// ═══════════════════════════════════════════════════════════════════
// CLASS
// ═══════════════════════════════════════════════════════════════════

// SmaliClass — полностью разобранный smali-класс.
type SmaliClass struct {
	SourceRange
	Name        string // нормализованный: com.example.MyClass
	RawName     string // оригинальный: Lcom/example/MyClass;
	PackageName string
	SimpleName  string // MyClass
	OuterClass  string // для inner classes
	SuperClass  string
	Source      string // .source filename
	Access      AccessFlags
	Interfaces  []string
	Fields      []SmaliField
	Methods     []SmaliMethod
	Annotations []Annotation

	// Metadata
	IsInterface  bool
	IsEnum       bool
	IsAnnotation bool
	IsInnerClass bool
	IsAnonymous  bool
	IsLibrary    bool
	IsObfuscated bool
}

// FriendlyName возвращает читаемое имя класса.
func (c *SmaliClass) FriendlyName() string {
	if c.IsInnerClass && c.OuterClass != "" {
		return c.OuterClass + "$" + c.SimpleName
	}
	return c.Name
}

// FindMethodsByName ищет методы по имени.
func (c *SmaliClass) FindMethodsByName(name string) []*SmaliMethod {
	var result []*SmaliMethod
	for i := range c.Methods {
		if c.Methods[i].Name == name {
			result = append(result, &c.Methods[i])
		}
	}
	return result
}

// ═══════════════════════════════════════════════════════════════════
// PARSE ERROR
// ═══════════════════════════════════════════════════════════════════

// ErrorSeverity — уровень серьёзности ошибки парсинга.
type ErrorSeverity uint8

const (
	SeverityWarning ErrorSeverity = iota
	SeverityError
	SeverityFatal
)

func (s ErrorSeverity) String() string {
	names := [...]string{"WARNING", "ERROR", "FATAL"}
	if int(s) < len(names) {
		return names[s]
	}
	return "UNKNOWN"
}

// ParseError — ошибка парсинга.
type ParseError struct {
	SourceLocation
	Message  string
	Raw      string
	Severity ErrorSeverity
}

func (e ParseError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", e.Severity, e.SourceLocation, e.Message)
}

// ═══════════════════════════════════════════════════════════════════
// PARSE RESULT
// ═══════════════════════════════════════════════════════════════════

// ParseStats — статистика парсинга.
type ParseStats struct {
	LinesTotal   int
	LinesParsed  int
	LinesSkipped int
	ParseTimeNs  int64
	MethodCount  int
	FieldCount   int
	InvokeCount  int
}

// ParseResult — результат парсинга одного smali-файла.
type ParseResult struct {
	Class    *SmaliClass
	Errors   []ParseError
	Warnings []ParseError
	Stats    ParseStats
}

func (r *ParseResult) HasErrors() bool {
	return len(r.Errors) > 0
}

func (r *ParseResult) HasFatalErrors() bool {
	for _, e := range r.Errors {
		if e.Severity == SeverityFatal {
			return true
		}
	}
	return false
}

// ErrorCount возвращает количество ошибок заданной серьёзности.
func (r *ParseResult) ErrorCount(severity ErrorSeverity) int {
	count := 0
	for _, e := range r.Errors {
		if e.Severity == severity {
			count++
		}
	}
	return count
}

// ═══════════════════════════════════════════════════════════════════
// ANALYSIS RULE — правило для анализа методов при парсинге
// ═══════════════════════════════════════════════════════════════════

// AnalysisRule — правило анализа, применяемое к разобранному методу.
type AnalysisRule struct {
	Name        string
	Description string
	Evaluate    func(method *SmaliMethod) (score int, reasons []string)
}

// ═══════════════════════════════════════════════════════════════════
// PARSE OPTIONS
// ═══════════════════════════════════════════════════════════════════

// ParseOptions — настройки парсера.
type ParseOptions struct {
	Context context.Context

	// Лимиты
	MaxLines        int
	MaxMethods      int
	MaxInstructions int

	// Что парсить
	SkipMethodBodies bool
	SkipAnnotations  bool
	SkipDebugInfo    bool

	// Анализ
	EnableAnalysis     bool
	AnalysisRules      []AnalysisRule
	SuspicionThreshold int

	// Логирование
	Logger  Logger
	Verbose bool

	// Прогресс (вызывается периодически)
	OnProgress func(linesParsed, linesTotal int)
}

// DefaultParseOptions возвращает настройки по умолчанию.
func DefaultParseOptions() ParseOptions {
	return ParseOptions{
		Context:            context.Background(),
		MaxLines:           1_000_000,
		MaxMethods:         10_000,
		MaxInstructions:    100_000,
		EnableAnalysis:     true,
		SuspicionThreshold: 3,
	}
}

// ═══════════════════════════════════════════════════════════════════
// LOGGER INTERFACE
// ═══════════════════════════════════════════════════════════════════

// Logger — интерфейс логирования.
type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

// NopLogger — логгер-заглушка.
type NopLogger struct{}

func (NopLogger) Debug(msg string, args ...any) {}
func (NopLogger) Info(msg string, args ...any)  {}
func (NopLogger) Warn(msg string, args ...any)  {}
func (NopLogger) Error(msg string, args ...any) {}

// ═══════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════

// normalizeClassName заменяет / на . в именах классов DEX.
func normalizeClassName(raw string) string {
	return strings.ReplaceAll(raw, "/", ".")
}
