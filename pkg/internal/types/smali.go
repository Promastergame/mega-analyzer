package types

import (
	"encoding/json"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SMALI STRUCTURES
// ═══════════════════════════════════════════════════════════════════════════════

// SmaliClass — распарсенный Smali класс.
type SmaliClass struct {
	Name         string        `json:"name"`
	SuperClass   string        `json:"super_class"`
	Source       string        `json:"source,omitempty"`
	Interfaces   []string      `json:"interfaces,omitempty"`
	Fields       []SmaliField  `json:"fields,omitempty"`
	Methods      []SmaliMethod `json:"methods,omitempty"`
	PackageName  string        `json:"package_name,omitempty"`
	SimpleName   string        `json:"simple_name,omitempty"`
	Access       AccessFlags   `json:"access_flags"`
	IsAppCode    bool          `json:"is_app_code"`
	IsLibrary    bool          `json:"is_library,omitempty"`
	IsObfuscated bool          `json:"is_obfuscated,omitempty"`
}

func (c *SmaliClass) IsInterface() bool { return c.Access.IsInterface() }
func (c *SmaliClass) IsAbstract() bool  { return c.Access.IsAbstract() }

// SmaliField — поле класса.
type SmaliField struct {
	SourceLocation
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	Value    string      `json:"value,omitempty"`
	Access   AccessFlags `json:"access_flags,omitempty"`
	TypeKind string      `json:"type_kind,omitempty"`
	BaseType string      `json:"base_type,omitempty"`
}

// SmaliMethod — метод класса.
// Thread-safety: immutable после парсинга.
type SmaliMethod struct {
	SourceRange
	Name             string           `json:"name"`
	Params           string           `json:"params"`
	ReturnType       string           `json:"return_type"`
	Access           AccessFlags      `json:"access_flags,omitempty"`
	Locals           int              `json:"locals"`
	Registers        int              `json:"registers"`
	Body             []string         `json:"body,omitempty"`
	Invokes          []Invoke         `json:"invokes,omitempty"`
	Conditions       []Condition      `json:"conditions,omitempty"`
	Instructions     []Instruction    `json:"instructions,omitempty"`
	StringConsts     []StringConstant `json:"string_consts,omitempty"`
	FieldAccesses    []FieldAccess    `json:"field_accesses,omitempty"`
	Labels           []Label          `json:"labels,omitempty"`
	Returns          []Return         `json:"returns,omitempty"`
	Switches         []Switch         `json:"switches,omitempty"`
	TryCatches       []TryCatch       `json:"try_catches,omitempty"`
	Metrics          MethodMetrics    `json:"metrics,omitempty"`
	ReturnsBoolean   bool             `json:"returns_boolean,omitempty"`
	HasTryCatch      bool             `json:"has_try_catch,omitempty"`
	SuspicionScore   int              `json:"suspicion_score,omitempty"`
	SuspicionReasons []string         `json:"suspicion_reasons,omitempty"`
}

func (m *SmaliMethod) IsConstructor() bool {
	return m.Name == "<init>" || m.Name == "<clinit>" || m.Access.IsConstructor()
}

// FullSignature возвращает полную сигнатуру метода.
// Оптимизировано с strings.Builder.
func (m *SmaliMethod) FullSignature(className string) string {
	var b strings.Builder
	b.Grow(len(className) + len(m.Name) + len(m.Params) + len(m.ReturnType) + 4)
	b.WriteString(className)
	b.WriteString("->")
	b.WriteString(m.Name)
	b.WriteByte('(')
	b.WriteString(m.Params)
	b.WriteByte(')')
	b.WriteString(m.ReturnType)
	return b.String()
}

// Invoke — вызов метода.
type Invoke struct {
	SourceLocation
	Type       InvokeType `json:"type"`
	Class      string     `json:"class"`
	Method     string     `json:"method"`
	Params     string     `json:"params"`
	ReturnType string     `json:"return_type"`
	Registers  []string   `json:"registers,omitempty"`
	Raw        string     `json:"raw,omitempty"`
	Tags       []string   `json:"tags,omitempty"`
}

// FullSignature возвращает полную сигнатуру вызова.
func (i Invoke) FullSignature() string {
	var b strings.Builder
	b.Grow(len(i.Class) + len(i.Method) + len(i.Params) + len(i.ReturnType) + 4)
	b.WriteString(i.Class)
	b.WriteString("->")
	b.WriteString(i.Method)
	b.WriteByte('(')
	b.WriteString(i.Params)
	b.WriteByte(')')
	b.WriteString(i.ReturnType)
	return b.String()
}

// Instruction — smali инструкция.
type Instruction struct {
	SourceLocation
	Opcode   string              `json:"opcode"`
	Operands []string            `json:"operands,omitempty"`
	Raw      string              `json:"raw"`
	Category InstructionCategory `json:"category,omitempty"`
}

// Condition — условие перехода.
type Condition struct {
	SourceLocation
	Op       ConditionOp `json:"op"`
	Operands []string    `json:"operands,omitempty"`
	Target   string      `json:"target"`
	Negated  bool        `json:"negated,omitempty"`
}

func (c Condition) IsZeroCheck() bool { return c.Op.IsZeroCheck() }
func (c Condition) IsEqualityCheck() bool {
	return c.Op == CondOpEq || c.Op == CondOpNe || c.Op == CondOpEqz || c.Op == CondOpNez
}

// StringConstant — строковая константа.
type StringConstant struct {
	SourceLocation
	Register string           `json:"register"`
	Value    string           `json:"value"`
	Raw      string           `json:"raw,omitempty"`
	Flags    StringConstFlags `json:"flags,omitempty"`
}

type StringConstFlags uint8

const (
	StringFlagEmpty StringConstFlags = 1 << iota
	StringFlagLooksURL
	StringFlagLooksPackage
	StringFlagLooksBase64
	StringFlagLooksKey
	StringFlagLooksPath
)

func (f StringConstFlags) IsEmpty() bool          { return f&StringFlagEmpty != 0 }
func (f StringConstFlags) LooksLikeURL() bool     { return f&StringFlagLooksURL != 0 }
func (f StringConstFlags) LooksLikePackage() bool { return f&StringFlagLooksPackage != 0 }
func (f StringConstFlags) LooksLikeBase64() bool  { return f&StringFlagLooksBase64 != 0 }
func (f StringConstFlags) LooksLikeKey() bool     { return f&StringFlagLooksKey != 0 }

// FieldAccess — доступ к полю.
type FieldAccess struct {
	SourceLocation
	Op       string `json:"op"`
	Register string `json:"register"`
	Object   string `json:"object,omitempty"`
	Class    string `json:"class"`
	Field    string `json:"field"`
	Type     string `json:"type"`
	IsStatic bool   `json:"is_static,omitempty"`
	IsRead   bool   `json:"is_read,omitempty"`
	IsWrite  bool   `json:"is_write,omitempty"`
}

// Return — инструкция возврата.
type Return struct {
	SourceLocation
	Op       string `json:"op"`
	Register string `json:"register,omitempty"`
	IsVoid   bool   `json:"is_void,omitempty"`
}

// Label — метка.
type Label struct {
	SourceLocation
	Name string `json:"name"`
}

// Switch — switch конструкция.
type Switch struct {
	SourceLocation
	Type     string   `json:"type"`
	Register string   `json:"register"`
	Targets  []string `json:"targets"`
}

// TryCatch — блок try-catch.
type TryCatch struct {
	StartLabel    string `json:"start_label"`
	EndLabel      string `json:"end_label"`
	HandlerLabel  string `json:"handler_label"`
	ExceptionType string `json:"exception_type"`
}

// MethodMetrics — метрики метода.
// Thread-safety: immutable после заполнения парсером.
// НЕ использовать параллельно во время заполнения!
type MethodMetrics struct {
	InstructionCount     int                  `json:"instruction_count"`
	InvokeCount          int                  `json:"invoke_count"`
	ConditionCount       int                  `json:"condition_count"`
	StringConstCount     int                  `json:"string_const_count"`
	FieldAccessCount     int                  `json:"field_access_count"`
	ReturnCount          int                  `json:"return_count"`
	LabelCount           int                  `json:"label_count"`
	TryCatchCount        int                  `json:"try_catch_count"`
	CyclomaticComplexity int                  `json:"cyclomatic_complexity"`
	InvokesByType        [invokeTypeCount]int `json:"-"`
}

// MarshalJSON с экспортом InvokesByType.
// Thread-safety: безопасно только после завершения заполнения (фикс #4).
func (m MethodMetrics) MarshalJSON() ([]byte, error) {
	type alias MethodMetrics
	aux := struct {
		alias
		InvokesSummary map[string]int `json:"invokes_by_type,omitempty"`
	}{alias: alias(m)}

	// Добавляем только ненулевые
	for i := InvokeType(0); i < invokeTypeCount; i++ {
		if m.InvokesByType[i] > 0 {
			if aux.InvokesSummary == nil {
				aux.InvokesSummary = make(map[string]int)
			}
			aux.InvokesSummary[i.String()] = m.InvokesByType[i]
		}
	}
	return json.Marshal(aux)
}

func (m MethodMetrics) InvokeStaticCount() int    { return m.InvokesByType[InvokeStatic] }
func (m MethodMetrics) InvokeVirtualCount() int   { return m.InvokesByType[InvokeVirtual] }
func (m MethodMetrics) InvokeInterfaceCount() int { return m.InvokesByType[InvokeInterface] }
