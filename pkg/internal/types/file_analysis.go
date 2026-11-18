package types

import (
	"mega-analyzer/pkg/internal/cfg"
	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/media"
)

// ═══════════════════════════════════════════════════════════════════════════════
// FILE ANALYSIS
// ═══════════════════════════════════════════════════════════════════════════════

// Match — совпадение паттерна в коде.
type Match struct {
	SourceLocation
	Categorized
	Scored
	Text                 string               `json:"text"`
	Pattern              string               `json:"pattern"`
	Context              string               `json:"context,omitempty"`
	ResolvedContext      string               `json:"resolved_context,omitempty"`
	Strings              []string             `json:"strings,omitempty"`
	Metadata             map[string]string    `json:"metadata,omitempty"`
	MethodName           string               `json:"method_name,omitempty"`
	ClassName            string               `json:"class_name,omitempty"`
	IsCritical           bool                 `json:"is_critical,omitempty"`
	Severity             Severity             `json:"severity,omitempty"`
	EvidenceType         string               `json:"evidence_type,omitempty"`
	Confidence           string               `json:"confidence,omitempty"`
	ReasonForSeverity    string               `json:"reason_for_severity,omitempty"`
	FalsePositiveHints   string               `json:"false_positive_hints,omitempty"`
	RequiredNextEvidence string               `json:"required_next_evidence,omitempty"`
	Evidence             []finding.Evidence   `json:"evidence,omitempty"`
	Explanation          *finding.Explanation `json:"explanation,omitempty"`
}

func (m Match) TotalImportance() int {
	return int(m.Score*5) + int(m.Severity)*2
}

// DecisionPoint — точка принятия решения в коде.
type DecisionPoint struct {
	SourceLocation
	Scored
	Method      string       `json:"method"`
	Type        DecisionType `json:"type"`
	Category    Category     `json:"category"`
	Description string       `json:"description"`
}

// FileAnalysis — результат анализа файла.
type FileAnalysis struct {
	Path            string                `json:"path"`
	RelPath         string                `json:"rel_path,omitempty"`
	ResolvedName    string                `json:"resolved_name,omitempty"`
	Type            FileType              `json:"type"`
	Size            int64                 `json:"size"`
	Hash            string                `json:"hash,omitempty"`
	Entropy         float64               `json:"entropy,omitempty"`
	Matches         []Match               `json:"matches,omitempty"`
	DecisionPoints  []DecisionPoint       `json:"decision_points,omitempty"`
	SuspiciousScore float64               `json:"suspicious_score,omitempty"`
	ParseError      string                `json:"parse_error,omitempty"`
	SmaliClass      *SmaliClass           `json:"smali_class,omitempty"`
	XMLData         *XMLAnalysis          `json:"xml_data,omitempty"`
	IsAppCode       bool                  `json:"is_app_code,omitempty"`
	IsLibrary       bool                  `json:"is_library,omitempty"`
	Importance      int                   `json:"importance,omitempty"`
	CFG             *cfg.ControlFlowGraph `json:"cfg,omitempty"`
	// MethodCFGs caches immutable per-method graphs in the same order as
	// SmaliClass.Methods. Deobfuscation builds them during file processing;
	// crack-point discovery and GNN preparation only read them. Keeping this
	// internal avoids rebuilding the same CFG up to three times without
	// changing the serialized report format.
	MethodCFGs []*cfg.ControlFlowGraph `json:"-"`
	MediaData  *media.AnalysisResult   `json:"media_data,omitempty"`

	// RecoveredStrings holds plaintext recovered from this file's encrypted
	// string literals by the deobfuscation stage. It is re-scanned by the
	// pattern matcher and fed into rule evaluation, so a decrypted endpoint or
	// credential reaches detection the same way a cleartext one does.
	RecoveredStrings         []string                  `json:"recovered_strings,omitempty"`
	RecoveredArtifacts       []RecoveredArtifact       `json:"recovered_artifacts,omitempty"`
	RecoveredArtifactSummary *RecoveredArtifactSummary `json:"recovered_artifact_summary,omitempty"`

	// Deobfuscation summarises what the deobfuscation engine found in this
	// file: flattened control flow, opaque predicates, unreachable blocks and
	// decrypted literals, per method.
	Deobfuscation *DeobfuscationResult `json:"deobfuscation,omitempty"`

	// LineOffsets — индекс строк для быстрого поиска
	LineOffsets *LineOffsets `json:"-"`

	// ── Quality Analysis Fields (v2) ──
	// ObfuscationDensity — доля методов с коротким именем (≤2 символа) в файле.
	// > 0.40 = сильная обфускация → повышаем приоритет файла в scoring.
	ObfuscationDensity float64 `json:"obfuscation_density,omitempty"`

	// HasCheckerRole — есть ли методы с ролью "checker" (boolean, условия, license keywords).
	HasCheckerRole bool `json:"has_checker_role,omitempty"`
	// HasEnforcerRole — есть ли методы с ролью "enforcer" (System.exit, finish, kill).
	HasEnforcerRole bool `json:"has_enforcer_role,omitempty"`
	// HasHandlerRole — есть ли методы с ролью "handler" (callback, onResult, listener).
	HasHandlerRole bool `json:"has_handler_role,omitempty"`
}

// NewFileAnalysis создаёт FileAnalysis с правильной инициализацией.
func NewFileAnalysis(path string, typ FileType, size int64) *FileAnalysis {
	return &FileAnalysis{
		Path:           path,
		Type:           typ,
		Size:           size,
		Matches:        make([]Match, 0, 4),
		DecisionPoints: make([]DecisionPoint, 0, 2),
	}
}

func (f *FileAnalysis) HasMatches() bool { return len(f.Matches) > 0 }

func (f *FileAnalysis) CriticalMatchCount() int {
	count := 0
	for i := range f.Matches {
		if f.Matches[i].IsCritical {
			count++
		}
	}
	return count
}

// InitLineOffsets инициализирует индекс строк для быстрого поиска.
func (f *FileAnalysis) InitLineOffsets(content []byte) {
	f.LineOffsets = NewLineOffsets(content)
}

// GetLineAt возвращает номер строки по byte offset.
func (f *FileAnalysis) GetLineAt(byteIndex int) int {
	if f.LineOffsets != nil {
		return f.LineOffsets.LineAt(byteIndex)
	}
	return 0
}

// DeepCopy создаёт глубокую копию FileAnalysis.
func (f *FileAnalysis) DeepCopy() *FileAnalysis {
	if f == nil {
		return nil
	}
	cp := *f

	if len(f.Matches) > 0 {
		cp.Matches = make([]Match, len(f.Matches))
		copy(cp.Matches, f.Matches)
	}
	if len(f.DecisionPoints) > 0 {
		cp.DecisionPoints = make([]DecisionPoint, len(f.DecisionPoints))
		copy(cp.DecisionPoints, f.DecisionPoints)
	}
	if f.SmaliClass != nil {
		classCopy := *f.SmaliClass
		// Deep copy slices в SmaliClass
		if len(f.SmaliClass.Interfaces) > 0 {
			classCopy.Interfaces = make([]string, len(f.SmaliClass.Interfaces))
			copy(classCopy.Interfaces, f.SmaliClass.Interfaces)
		}
		if len(f.SmaliClass.Methods) > 0 {
			classCopy.Methods = make([]SmaliMethod, len(f.SmaliClass.Methods))
			copy(classCopy.Methods, f.SmaliClass.Methods)
		}
		if len(f.SmaliClass.Fields) > 0 {
			classCopy.Fields = make([]SmaliField, len(f.SmaliClass.Fields))
			copy(classCopy.Fields, f.SmaliClass.Fields)
		}
		cp.SmaliClass = &classCopy
	}
	if f.XMLData != nil {
		xmlCopy := *f.XMLData
		// Deep copy slices
		if len(f.XMLData.Permissions) > 0 {
			xmlCopy.Permissions = make([]string, len(f.XMLData.Permissions))
			copy(xmlCopy.Permissions, f.XMLData.Permissions)
		}
		if len(f.XMLData.Activities) > 0 {
			xmlCopy.Activities = make([]string, len(f.XMLData.Activities))
			copy(xmlCopy.Activities, f.XMLData.Activities)
		}
		if len(f.XMLData.MetaData) > 0 {
			xmlCopy.MetaData = make(map[string]string, len(f.XMLData.MetaData))
			for k, v := range f.XMLData.MetaData {
				xmlCopy.MetaData[k] = v
			}
		}
		cp.XMLData = &xmlCopy
	}
	// Runtime caches are not copied. A copied analysis may outlive or mutate
	// independently from the scan that populated them.
	cp.LineOffsets = nil
	cp.MethodCFGs = nil

	return &cp
}

// XMLAnalysis — результат анализа XML.
type XMLAnalysis struct {
	// Retained manifest text is internal source context, not a new detector.
	// Whole snapshots are bounded and hashed before optional AI review.
	ManifestSource          string            `json:"-"`
	ManifestSourceTruncated bool              `json:"-"`
	Permissions             []string          `json:"permissions,omitempty"`
	Activities              []string          `json:"activities,omitempty"`
	Services                []string          `json:"services,omitempty"`
	Receivers               []string          `json:"receivers,omitempty"`
	Providers               []string          `json:"providers,omitempty"`
	MetaData                map[string]string `json:"meta_data,omitempty"`
	Suspicious              []string          `json:"suspicious,omitempty"`
}
