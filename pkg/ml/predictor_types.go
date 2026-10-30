package ml

import (
	"mega-analyzer/pkg/ml/ensemble"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PATCH PREDICTOR — главный координатор поиска патч-точек
// ═══════════════════════════════════════════════════════════════════════════════

// PatchPrediction — полный результат предсказания патч-точек
type PatchPrediction struct {
	HighRisk          []PatchPoint    `json:"high_risk"`
	MediumRisk        []PatchPoint    `json:"medium_risk"`
	LowRisk           []PatchPoint    `json:"low_risk"`
	LibraryFindings   []PatchPoint    `json:"library_findings"`   // 🆕 deprioritized
	MalwareIndicators []PatchPoint    `json:"malware_indicators"` // 🔥 Phase 4: угрозы и вредоносы
	AuditFindings     []PatchPoint    `json:"audit_findings"`     // security audit findings, not patch artifacts
	Stats             PredictionStats `json:"stats"`
	Mode              PatchMode       `json:"mode"`
	PartialResults    bool            `json:"partial_results"` // 🆕 timeout warning
	MainFindings      []string        `json:"main_findings"`   // 🆕 что нашли
	TopIssues         []string        `json:"top_issues"`      // 🆕 топ-3
}

type PatchPoint struct {
	Economy                  *EconomyInfo              `json:"economy,omitempty"`
	RecommendationAssessment *RecommendationAssessment `json:"recommendation_assessment,omitempty"`
	FilePath                 string                    `json:"file_path"`
	ClassName                string                    `json:"class_name"`
	MethodName               string                    `json:"method_name"`
	MethodSignature          string                    `json:"method_signature"`

	RiskScore           float64                      `json:"risk_score"`
	RiskLevel           RiskClass                    `json:"risk_level"`
	Confidence          float64                      `json:"confidence"`
	ConfidenceBreakdown *ConfidenceBreakdown         `json:"confidence_breakdown,omitempty"`
	CategoryConfidence  *CategoryConformalConfidence `json:"category_confidence,omitempty"`

	// Runtime decision — единая финальная калибровка ПОСЛЕ всех сигналов
	// (ensemble, entry-point, interesting, DFG, structural, crack-point).
	// RuntimeDecision: auto_patch | needs_review | reject.
	RuntimeConfidence *RuntimeConfidence `json:"runtime_confidence,omitempty"`
	RuntimeDecision   string             `json:"runtime_decision,omitempty"`

	Category     PatchCategory `json:"category"`
	CategoryName string        `json:"category_name"`
	PatternID    string        `json:"pattern_id,omitempty"`
	PatternDesc  string        `json:"pattern_desc,omitempty"`

	SuggestedPatch PatchType `json:"suggested_patch"`
	PatchDesc      string    `json:"patch_desc"`

	WhyVulnerable []string `json:"why_vulnerable"`
	MatchedParts  []string `json:"matched_parts"`
	Warnings      []string `json:"warnings,omitempty"`

	IsAppCode      bool           `json:"is_app_code"`
	IsLibraryCode  bool           `json:"is_library_code"`
	LibraryName    string         `json:"library_name,omitempty"` // 🆕
	ReturnType     string         `json:"return_type"`
	SourceLanguage SourceLanguage `json:"source_language,omitempty"`

	// 🔥 NEW: Enhanced analysis data
	InterestingScore  *InterestingScore `json:"interesting_score,omitempty"`
	EntryPointInfo    *EntryPointInfo   `json:"entry_point_info,omitempty"`
	IsEntryPoint      bool              `json:"is_entry_point"`
	IsInteresting     bool              `json:"is_interesting"`
	NoiseFilterReason string            `json:"noise_filter_reason,omitempty"`

	// ═══════════════════════════════════════════════════════════════════════════════
	// DFG Analysis — Data Flow Graph trace for this patch point
	// ═══════════════════════════════════════════════════════════════════════════════
	DFG *DFGInfo `json:"dfg,omitempty"` // Структурированный DFG анализ (nil если не анализировался)
	// ═══════════════════════════════════════════════════════════════════════════════

	// ═══════════════════════════════════════════════════════════════════════════════
	// Structural Signals — Phase 2: guards / hard gates / funnels из CFG
	// ═══════════════════════════════════════════════════════════════════════════════
	Structural *StructuralSignals `json:"structural,omitempty"`
	// ═══════════════════════════════════════════════════════════════════════════════

	// ═══════════════════════════════════════════════════════════════════════════════
	// PatchValue — Phase 3: единая метрика приоритизации патчей.
	// "Что патчить ПЕРВЫМ" = (Risk × Impact) / (Cost × Detection × Breakage).
	// Tier через PatchValue.Tier(): 🥇 TOP / 🥈 GOOD / 🥉 OK / ⚠ LOW.
	// ═══════════════════════════════════════════════════════════════════════════════
	PatchValue *PatchValueBreakdown `json:"patch_value,omitempty"`
	// ═══════════════════════════════════════════════════════════════════════════════

	// ═══════════════════════════════════════════════════════════════════════════════
	// Phase 4: Decoy / Vulnerability detection
	//
	//   • Decoy — что метод НЕ делает (already-patched, opaque predicate, accessor,
	//     trivial passthrough). Снижает PatchValue до 5% от исходного.
	//   • VulnSignals — расширенный malware/vulnerability detector (15 паттернов).
	//     Если IsMalwareSuspect=true, точка перемещается в MalwareIndicators
	//     bucket вместо HighRisk/MediumRisk.
	// ═══════════════════════════════════════════════════════════════════════════════
	Decoy       *DecoyAnalysis        `json:"decoy_analysis,omitempty"`
	VulnSignals *VulnerabilitySignals `json:"vuln_signals,omitempty"`
	// ═══════════════════════════════════════════════════════════════════════════════

	// ═══════════════════════════════════════════════════════════════════════════════
	// Ensemble Boost — additive re-ranker (structural/entropy/taint feature blend).
	// nil when EnableEnsembleBoost is off or the method was filtered before boosting.
	// ═══════════════════════════════════════════════════════════════════════════════
	EnsembleScore *ensemble.Score `json:"ensemble_score,omitempty"`
	// ═══════════════════════════════════════════════════════════════════════════════

	// ═══════════════════════════════════════════════════════════════════════════════
	// Phase 4: Gate Detection Filter — если true, точка отфильтрована как НЕ gate
	// (equals, hashCode, toString, getter). Не показывается в результатах.
	// ═══════════════════════════════════════════════════════════════════════════════
	IsFiltered   bool   `json:"-"` // в JSON не экспортируется (внутренний флаг)
	FilterReason string `json:"filter_reason,omitempty"`
	// ═══════════════════════════════════════════════════════════════════════════════

	// CFG crack-point engine confirmed this method as a real security gate.
	CrackPointConfirmed bool   `json:"crack_point_confirmed,omitempty"`
	CrackPointCategory  string `json:"crack_point_category,omitempty"`

	// Semantic gate v2 (CFG/DFG-aware, not name-based)
	SemanticGate *SemanticGateResult `json:"semantic_gate,omitempty"`

	MethodBody   []string `json:"-"`
	MethodHeader string   `json:"-"`
}

type PredictionStats struct {
	TotalFilesScanned    int             `json:"total_files_scanned"`
	TotalMethodsFound    int             `json:"total_methods_found"`
	MethodsAnalyzed      int             `json:"methods_analyzed"`
	MethodsSkipped       int             `json:"methods_skipped"`
	FilteredMethods      int             `json:"filtered_methods"` // Phase 4: gate-filtered (equals/hashCode/etc)
	PatchPointsFound     int             `json:"patch_points_found"`
	HighRiskCount        int             `json:"high_risk_count"`
	MediumRiskCount      int             `json:"medium_risk_count"`
	LowRiskCount         int             `json:"low_risk_count"`
	LibraryFindingsCount int             `json:"library_findings_count"`
	MalwareFindingsCount int             `json:"malware_findings_count"`
	AuditFindingsCount   int             `json:"audit_findings_count"`
	ByCategory           map[string]int  `json:"by_category"`
	TopCategories        []CategoryCount `json:"top_categories"`
	AvgScore             float64         `json:"avg_score"`
	MaxScore             float64         `json:"max_score"`
	FilesDiscovered      int             `json:"files_discovered,omitempty"`
	FilesSkipped         int             `json:"files_skipped,omitempty"`
	FilesTooLarge        int             `json:"files_too_large,omitempty"`
	FileReadErrors       int             `json:"file_read_errors,omitempty"`
	ScanErrors           []string        `json:"scan_errors,omitempty"`

	// ── ML Health v2 (offline-first observability) ───────────────────────
	SchemaHash      string           `json:"schema_hash,omitempty"`      // FeatureRegistry hash (16 hex)
	SchemaVersion   int              `json:"schema_version,omitempty"`   // монотонный
	MLHealth        *MLHealth        `json:"ml_health,omitempty"`        // drift / ECE / pipeline
	PipelineMetrics *PipelineMetrics `json:"pipeline_metrics,omitempty"` // per-stage timing
}

type MLHealth struct {
	CalibrationStatus string   `json:"calibration_status"`
	MeasurementNotes  []string `json:"measurement_notes,omitempty"`
	DriftVerdict      string   `json:"drift_verdict,omitempty"` // stable / moderate_drift / significant_drift
	WorstPSI          float64  `json:"worst_psi,omitempty"`
	WorstFeature      string   `json:"worst_feature,omitempty"`
	ECE               float64  `json:"ece,omitempty"` // calibration error 0..1
	Brier             float64  `json:"brier,omitempty"`
	Throughput        float64  `json:"throughput,omitempty"` // methods/sec
	ReplaySize        int      `json:"replay_size,omitempty"`
	ReplayBalance     float64  `json:"replay_balance,omitempty"` // 0..1 positive ratio
	RetrainNeeded     bool     `json:"retrain_needed,omitempty"`
	RetrainReason     string   `json:"retrain_reason,omitempty"`
}

type CategoryCount struct {
	Category PatchCategory `json:"category"`
	Name     string        `json:"name"`
	Count    int           `json:"count"`
}
