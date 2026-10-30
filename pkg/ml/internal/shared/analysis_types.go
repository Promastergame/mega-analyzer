package shared

// SourceLanguage represents the detected source language.
type SourceLanguage string

const (
	LanguageJava        SourceLanguage = "Java"
	LanguageKotlin      SourceLanguage = "Kotlin"
	LanguageReactNative SourceLanguage = "React Native"
	LanguageFlutter     SourceLanguage = "Flutter"
	LanguageUnity       SourceLanguage = "Unity C#"
	LanguageUnknown     SourceLanguage = "Unknown"
)

// CallInfo describes a single invoke-* instruction.
type CallInfo struct {
	Type              string `json:"type"`
	Class             string `json:"class"`
	Method            string `json:"method"`
	FullCall          string `json:"full_call"`
	IsSecurityRelated bool   `json:"is_security_related"`
}

// MethodInfo contains extracted structural information for a smali method.
type MethodInfo struct {
	Economy       *EconomyInfo `json:"economy,omitempty"`
	Name          string `json:"name"`
	ClassName     string `json:"class_name"`
	FilePath      string `json:"file_path"`
	FullSignature string `json:"full_signature"`

	ReturnType     string `json:"return_type"`
	ReturnsBoolean bool   `json:"returns_boolean"`
	ReturnsVoid    bool   `json:"returns_void"`
	ReturnsInt     bool   `json:"returns_int"`

	IsPublic    bool `json:"is_public"`
	IsPrivate   bool `json:"is_private"`
	IsStatic    bool `json:"is_static"`
	IsFinal     bool `json:"is_final"`
	IsAbstract  bool `json:"is_abstract"`
	IsSynthetic bool `json:"is_synthetic"`

	InstructionCount   int  `json:"instruction_count"`
	RegisterCount      int  `json:"register_count"`
	HasLocalsDirective bool `json:"has_locals_directive"` // тело метода использует .locals (не .registers)
	ReturnCount        int  `json:"return_count"`
	IfCheckCount       int  `json:"if_check_count"`
	HasDualReturn      bool `json:"has_dual_return"`
	HasIfWithReturn    bool `json:"has_if_with_return"`
	IsShortMethod      bool `json:"is_short_method"`

	Calls          []CallInfo `json:"calls"`
	SecurityCalls  []string   `json:"security_calls"`
	HasSecurityAPI bool       `json:"has_security_api"`

	StringConsts       []string `json:"string_consts"`
	SecurityStrings    []string `json:"security_strings"`
	HasSecurityStrings bool     `json:"has_security_strings"`

	IsAppCode     bool `json:"is_app_code"`
	IsLibrary     bool `json:"is_library"`
	IsConstructor bool `json:"is_constructor"`
	IsAccessor    bool `json:"is_accessor"`
	IsCallback    bool `json:"is_callback"`

	NameLower        string   `json:"name_lower"`
	HasCheckPrefix   bool     `json:"has_check_prefix"`
	HasSecurityName  bool     `json:"has_security_name"`
	MatchedNameParts []string `json:"matched_name_parts"`

	SourceLanguage SourceLanguage `json:"source_language"`
	ClassPath      string         `json:"class_path"`

	// Context analysis fields (Requirements 6.7)
	SecurityContext   SecurityCheckType `json:"security_context"`
	ContextConfidence float64           `json:"context_confidence"`
	InferredIntent    string            `json:"inferred_intent"`

	RawBody      []string `json:"-"`
	MethodHeader string   `json:"-"`
	MethodFooter string   `json:"-"`
}

// ClassInfo contains the extracted information for a single smali class.
type ClassInfo struct {
	FilePath     string       `json:"file_path"`
	ClassName    string       `json:"class_name"`
	SuperClass   string       `json:"super_class"`
	IsAppCode    bool         `json:"is_app_code"`
	IsLibrary    bool         `json:"is_library"`
	Methods      []MethodInfo `json:"methods"`
	TotalMethods int          `json:"total_methods"`

	SecurityMethodCount int  `json:"security_method_count"`
	BooleanMethodCount  int  `json:"boolean_method_count"`
	HasSecurityContext  bool `json:"has_security_context"`
}
