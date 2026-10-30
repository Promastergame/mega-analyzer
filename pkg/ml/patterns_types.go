package ml

// ═══════════════════════════════════════════════════════════════════════════════
// VULNERABLE PATTERN — паттерн уязвимого метода
// ═══════════════════════════════════════════════════════════════════════════════

type VulnerablePattern struct {
	ID          string        `json:"id"`
	Category    PatchCategory `json:"category"`
	Description string        `json:"description"`

	// Имена методов (любое совпадение)
	MethodNames []string `json:"method_names"`

	// Имена классов/путей (любое совпадение)
	ClassPatterns []string `json:"class_patterns"`

	// Обязательные вызовы (invoke-* содержит это)
	RequiredCalls []string `json:"required_calls"`

	// Ключевые строки в коде (const-string содержит это)
	StringPatterns []string `json:"string_patterns"`

	// Return type (Z = boolean, V = void, I = int)
	ReturnType string `json:"return_type"`

	// Ожидаемый тип патча
	PatchType PatchType `json:"patch_type"`

	// Вес паттерна (1.0 = стандарт)
	Weight float64 `json:"weight"`

	// Минимум сколько должно совпасть для срабатывания
	MinMatchScore float64 `json:"min_match_score"`

	// NEW: Effectiveness tracking metadata (Task 1)
	Effectiveness *PatternEffectiveness `json:"effectiveness,omitempty"`
}

// PatchType — как патчить
type PatchType string

const (
	PatchReturnTrue   PatchType = "return_true"    // const/4 v0, 0x1; return v0
	PatchReturnFalse  PatchType = "return_false"   // const/4 v0, 0x0; return v0
	PatchReturnVoid   PatchType = "return_void"    // return-void
	PatchReturnMaxInt PatchType = "return_max_int" // const v0, 0x7fffffff; return v0 (unlimited)
	PatchReturnZero   PatchType = "return_zero"    // const/4 vX, 0x0 перед каждым return vX (цена = 0)
	PatchNop          PatchType = "nop"            // заменить invoke на nop
	PatchRemoveCheck  PatchType = "remove_check"   // убрать if-проверку
	PatchConstReplace PatchType = "const_replace"  // точечно заменить строковую константу
)

// ═══════════════════════════════════════════════════════════════════════════════
// 25 УЯЗВИМЫХ ПАТТЕРНОВ
// ═══════════════════════════════════════════════════════════════════════════════

var VulnerablePatterns = mustLoadVulnerablePatterns()

// ═══════════════════════════════════════════════════════════════════════════════
// SAFE PATTERNS — то что НЕ является патч-точкой
// ═══════════════════════════════════════════════════════════════════════════════

type SafePattern struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Indicators  []string `json:"indicators"`
	Penalty     float64  `json:"penalty"` // вычитаем из score
}

var SafePatterns = []SafePattern{
	{
		Name:        "getter_setter",
		Description: "Simple getter/setter method",
		Indicators: []string{
			// Getter patterns
			"get", "is", "has", "can", "should",
			// Setter patterns
			"set", "put", "add", "remove", "update",
			// Property accessors (Kotlin)
			"get$", "set$", "is$",
		},
		Penalty: -30, // Increased from -25 to ensure 20-40 point reduction
	},
	{
		Name:        "constructor",
		Description: "Constructor or static initializer",
		Indicators: []string{
			"<init>", "<clinit>",
		},
		Penalty: -50, // Strong penalty - constructors are never patch points
	},
	{
		Name:        "synthetic_accessor",
		Description: "Compiler-generated accessor",
		Indicators: []string{
			"access$", "synthetic", "$default", "$annotations",
			// Kotlin synthetic methods
			"get-", "set-", "component",
		},
		Penalty: -50, // Strong penalty - synthetic methods are never patch points
	},
	{
		Name:        "ui_callback",
		Description: "UI event callback",
		Indicators: []string{
			// Click events
			"onclick", "ontouch", "onlongclick", "ondoubleclick",
			// Scroll/drag events
			"onscroll", "ondrag", "onfling", "onswipe",
			// Focus events
			"onfocuschange", "onfocus", "onblur",
			// Input events
			"onkey", "ontextchanged", "oninput", "onchange",
			// Lifecycle callbacks
			"oncreate", "onresume", "onpause", "ondestroy",
			"onstart", "onstop", "onattach", "ondetach",
			"onbind", "onunbind", "onrebind",
			// View callbacks
			"onmeasure", "onlayout", "ondraw", "oninflate",
			// Navigation callbacks
			"onbackpressed", "onnavigationitemselected",
			// Dialog callbacks
			"ondismiss", "oncancel", "onshow",
		},
		Penalty: -35, // Increased from -30 to ensure proper reduction
	},
	{
		Name:        "tostring_equals",
		Description: "Standard Object methods",
		Indicators: []string{
			"tostring", "hashcode", "equals", "compareto",
			"clone", "finalize", "notify", "notifyall", "wait",
		},
		Penalty: -40,
	},
	{
		Name:        "logging",
		Description: "Logging/debug output",
		Indicators: []string{
			"log;->d(", "log;->i(", "log;->e(",
			"log;->w(", "log;->v(",
			"println", "logcat", "timber", "logger",
		},
		Penalty: -25, // Increased from -20
	},
	{
		Name:        "serialization",
		Description: "Serialization methods",
		Indicators: []string{
			"parcelable", "writetoparcel", "createfromparcel",
			"serializable", "writeobject", "readobject",
			"tojson", "fromjson",
		},
		Penalty: -30,
	},
	{
		Name:        "void_return",
		Description: "Void methods without security context",
		Indicators: []string{
			"settext", "setvisibility", "setcolor",
			"setbackground", "addview", "removeview",
			"startactivity", "sendbroadcast",
			"notify", "update",
		},
		Penalty: -25,
	},
	{
		Name:        "utility",
		Description: "Utility/helper methods",
		Indicators: []string{
			"format", "parse", "convert", "encode",
			"decode", "trim", "split", "join",
			"isempty", "isnull", "isblank",
			"contains", "indexof",
		},
		Penalty: -20,
	},
	{
		Name:        "network_data",
		Description: "Data fetching (not security)",
		Indicators: []string{
			"fetch", "download", "upload",
			"loaddata", "getresponse", "sendrequest",
			"getstream", "readbytes",
		},
		Penalty: -15,
	},
}
