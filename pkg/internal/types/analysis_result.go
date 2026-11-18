package types

import (
	"mega-analyzer/pkg/internal/decisionai"
	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/peinspect"
	"mega-analyzer/pkg/internal/sourceevidence"
	"mega-analyzer/pkg/ml/fusion"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// ANALYSIS RESULT — THREAD-SAFE
// ═══════════════════════════════════════════════════════════════════════════════

type AnalysisStats struct {
	TotalFiles    int `json:"total_files"`
	AnalyzedFiles int `json:"analyzed_files"`
	// AppCodeFiles is kept for JSON compatibility. For APK/DEX inputs it is a
	// count of application analysis units (normally DEX classes), not a count
	// of materialised .smali files.
	AppCodeFiles    int `json:"app_code_files"`
	TotalMatches    int `json:"total_matches"`
	CriticalMatches int `json:"critical_matches"`
}

// CoverageStats distinguishes physical artifacts from virtual analysis units.
// It is intentionally additive to preserve the legacy stats JSON contract.
type CoverageStats struct {
	Discovered      int  `json:"discovered"`
	Eligible        int  `json:"eligible"`
	Queued          int  `json:"queued"`
	Parsed          int  `json:"parsed"`
	ParseFailed     int  `json:"parse_failed"`
	FilesFailed     int  `json:"files_failed"`
	SkippedBySize   int  `json:"skipped_by_size"`
	SkippedByLimit  int  `json:"skipped_by_limit"`
	Unsupported     int  `json:"unsupported"`
	AnalyzedFiles   int  `json:"analyzed_files"`
	AnalyzedClasses int  `json:"analyzed_classes"`
	AnalyzedMethods int  `json:"analyzed_methods"`
	AnalysisUnits   int  `json:"analysis_units"`
	FindingsBearing int  `json:"findings_bearing"`
	LimitReached    bool `json:"limit_reached"`
	// NotAnalyzed lists queued files that never produced a FileAnalysis
	// (scan limits, cancellation or noise filtering). Capped; see
	// NotAnalyzedTotal for the full count.
	NotAnalyzed      []SkippedFile `json:"not_analyzed,omitempty"`
	NotAnalyzedTotal int           `json:"not_analyzed_total,omitempty"`
}

// SkippedFile is one queued-but-unanalyzed file in the coverage gap list.
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason,omitempty"`
}

// AnalysisCacheStats reports cache effectiveness for the current scan.
type AnalysisCacheStats struct {
	Enabled       bool    `json:"enabled"`
	MethodHits    int64   `json:"method_hits"`
	MethodMisses  int64   `json:"method_misses"`
	MethodStores  int64   `json:"method_stores"`
	HitRate       float64 `json:"hit_rate"`
	BytesReused   int64   `json:"bytes_reused"`
	HotEntries    int     `json:"hot_entries"`
	DiskBytes     int64   `json:"disk_bytes"`
	SchemaVersion uint32  `json:"schema_version"`
}

type DataFlowStep struct {
	File   string `json:"file,omitempty"`
	Method string `json:"method"`
	Type   string `json:"type"`
	Line   int    `json:"line,omitempty"`
}

type DataFlowFinding struct {
	Source       string         `json:"source"`
	Sink         string         `json:"sink"`
	Category     string         `json:"category"`
	ExploitChain string         `json:"exploit_chain,omitempty"`
	Label        uint64         `json:"label"`
	Severity     string         `json:"severity"`
	Confidence   float64        `json:"confidence"`
	Location     SourceLocation `json:"location"`
	Path         []DataFlowStep `json:"path"`
}

type DataFlowStats struct {
	IncompatibleCastFlowsPruned int  `json:"incompatible_cast_flows_pruned"`
	SliceSteps                  int  `json:"slice_steps"`
	SliceLimitReached           bool `json:"slice_limit_reached"`
	Cancelled                   bool `json:"cancelled"`
	SinksVisited                int  `json:"sinks_visited"`
	SlicesTruncated             int  `json:"slices_truncated"`
	CFGMethods                  int  `json:"cfg_methods"`
	CFGNodes                    int  `json:"cfg_nodes"`
	CFGEdges                    int  `json:"cfg_edges"`
	CFGIncompleteMethods        int  `json:"cfg_incomplete_methods"`
	ReachingDefinitionSteps     int  `json:"reaching_definition_steps"`
	ReachingDefinitionCacheHits int  `json:"reaching_definition_cache_hits"`
	UnreachableSinksSkipped     int  `json:"unreachable_sinks_skipped"`
	InformationalFlows          int  `json:"informational_flows"`
	ObservationsOmitted         int  `json:"observations_omitted"`
	MethodsDiscovered           int  `json:"methods_discovered"`
	MethodsAnalyzed             int  `json:"methods_analyzed"`
	MethodsTruncated            int  `json:"methods_truncated"`
	Iterations                  int  `json:"iterations"`
	CacheHits                   int  `json:"cache_hits"`
	CacheMisses                 int  `json:"cache_misses"`
	Flows                       int  `json:"flows"`
	Findings                    int  `json:"findings"`
	LimitReached                bool `json:"limit_reached"`
}

type PiracyAnalysis struct {
	Findings   []PiracyFinding `json:"findings,omitempty"`
	Sites      []string        `json:"sites,omitempty"`
	Confidence float64         `json:"confidence"`
	Risk       RiskLevel       `json:"risk"`
}

// 🆕 v9.0.0 — DEOBFUSCATION INSIGHTS
type RecoveredArtifact struct {
	ID              string            `json:"id"`
	Kind            string            `json:"kind"`
	SHA256          string            `json:"sha256"`
	Size            int               `json:"size"`
	Depth           int               `json:"depth,omitempty"`
	SourceMethod    string            `json:"source_method,omitempty"`
	SourceOffset    uint32            `json:"source_offset,omitempty"`
	SourceProofKind string            `json:"source_proof_kind,omitempty"`
	SourceProofID   string            `json:"source_proof_id,omitempty"`
	Preview         string            `json:"preview,omitempty"`
	Status          string            `json:"status,omitempty"`
	Reason          string            `json:"reason,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

type RecoveredArtifactSummary struct {
	Discovered int            `json:"discovered,omitempty"`
	Scanned    int            `json:"scanned,omitempty"`
	Skipped    int            `json:"skipped,omitempty"`
	Deduped    int            `json:"deduped,omitempty"`
	Budgeted   int            `json:"budgeted,omitempty"`
	Bytes      int64          `json:"bytes,omitempty"`
	ByKind     map[string]int `json:"by_kind,omitempty"`
}

type DeobfuscationResult struct {
	CFFFDetected        bool                      `json:"cff_detected"`
	OpaquePredicates    int                       `json:"opaque_predicates"`
	DeadCodeNodes       int                       `json:"dead_code_nodes"`
	RecoveredStrings    int                       `json:"recovered_strings"`
	ComplexityReduction float64                   `json:"complexity_reduction"`
	MethodsConsidered   int                       `json:"methods_considered,omitempty"`
	MethodsTransformed  int                       `json:"methods_transformed,omitempty"`
	ProofsAccepted      int                       `json:"proofs_accepted,omitempty"`
	FoldedConstants     int                       `json:"folded_constants,omitempty"`
	FoldedBranches      int                       `json:"folded_branches,omitempty"`
	BlocksBefore        int                       `json:"blocks_before,omitempty"`
	BlocksAfter         int                       `json:"blocks_after,omitempty"`
	EdgesBefore         int                       `json:"edges_before,omitempty"`
	EdgesAfter          int                       `json:"edges_after,omitempty"`
	InstructionsBefore  int                       `json:"instructions_before,omitempty"`
	InstructionsAfter   int                       `json:"instructions_after,omitempty"`
	EmulatorAttempts    int                       `json:"emulator_attempts,omitempty"`
	EmulatorRecoveries  int                       `json:"emulator_recoveries,omitempty"`
	EmulatorAbstentions int                       `json:"emulator_abstentions,omitempty"`
	EmulatorBudgets     int                       `json:"emulator_budgets_exhausted,omitempty"`
	JournalTruncated    bool                      `json:"journal_truncated,omitempty"`
	ClassInitialization *DeobfClassInitialization `json:"class_initialization,omitempty"`
	Methods             []DeobfMethod             `json:"methods,omitempty"`
}

type DeobfClassInitialization struct {
	Attempted       int                     `json:"attempted,omitempty"`
	Initialized     int                     `json:"initialized,omitempty"`
	Unavailable     int                     `json:"unavailable,omitempty"`
	Cycles          int                     `json:"cycles,omitempty"`
	Rollbacks       int                     `json:"rollbacks,omitempty"`
	Budgets         int                     `json:"budgets_exhausted,omitempty"`
	CommittedFields int                     `json:"committed_fields,omitempty"`
	Outcomes        []DeobfClassInitOutcome `json:"outcomes,omitempty"`
}

type DeobfClassInitOutcome struct {
	ClassName       string   `json:"class"`
	Initializer     string   `json:"initializer,omitempty"`
	SuperClass      string   `json:"superclass,omitempty"`
	Dependencies    []string `json:"dependencies,omitempty"`
	State           string   `json:"state"`
	Reason          string   `json:"reason,omitempty"`
	CommittedFields int      `json:"committed_fields,omitempty"`
}

type DeobfMethod struct {
	MethodName       string                `json:"method"`
	ClassName        string                `json:"class"`
	Findings         []string              `json:"findings,omitempty"`
	CandidateScore   int                   `json:"candidate_score,omitempty"`
	CandidateReasons []string              `json:"candidate_reasons,omitempty"`
	Transformed      bool                  `json:"transformed,omitempty"`
	Metrics          *DeobfMetrics         `json:"metrics,omitempty"`
	Emulation        *DeobfEmulation       `json:"emulation,omitempty"`
	RecoveredValues  []DeobfRecoveredValue `json:"recovered_values,omitempty"`
	Journal          []DeobfTransform      `json:"journal,omitempty"`
	JournalTruncated bool                  `json:"journal_truncated,omitempty"`
}

type DeobfEmulation struct {
	Status          string             `json:"status"`
	StopReason      string             `json:"stop_reason,omitempty"`
	Steps           int                `json:"steps,omitempty"`
	Branches        int                `json:"branches,omitempty"`
	Allocations     int                `json:"allocations,omitempty"`
	CallProofs      []DeobfCallProof   `json:"call_proofs,omitempty"`
	StaticProofs    []DeobfStaticProof `json:"static_proofs,omitempty"`
	CallMetrics     DeobfCallMetrics   `json:"call_metrics,omitempty"`
	Trace           []string           `json:"trace,omitempty"`
	TraceTruncated  bool               `json:"trace_truncated,omitempty"`
	ProofsTruncated bool               `json:"proofs_truncated,omitempty"`
}

type DeobfCallProof struct {
	Caller          string   `json:"caller"`
	Callee          string   `json:"callee"`
	Offset          uint32   `json:"offset"`
	Depth           int      `json:"depth"`
	Digest          string   `json:"digest,omitempty"`
	ArgumentSummary []string `json:"argument_summary,omitempty"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason,omitempty"`
	CacheHit        bool     `json:"cache_hit,omitempty"`
}

type DeobfStaticProof struct {
	ClassName string `json:"class,omitempty"`
	Field     string `json:"field"`
	Operation string `json:"operation"`
	Offset    uint32 `json:"offset,omitempty"`
	State     string `json:"state,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type DeobfCallMetrics struct {
	Attempts   int `json:"attempts,omitempty"`
	Completed  int `json:"completed,omitempty"`
	CacheHits  int `json:"cache_hits,omitempty"`
	Recursions int `json:"recursions,omitempty"`
	Impure     int `json:"impure,omitempty"`
	Unresolved int `json:"unresolved,omitempty"`
	Budgeted   int `json:"budgeted,omitempty"`
}

type DeobfRecoveredValue struct {
	Value      string   `json:"value"`
	Offset     uint32   `json:"offset"`
	Source     string   `json:"source"`
	Proof      string   `json:"proof"`
	Operations []string `json:"operations,omitempty"`
}

type DeobfMetrics struct {
	BlocksBefore       int `json:"blocks_before,omitempty"`
	BlocksAfter        int `json:"blocks_after,omitempty"`
	EdgesBefore        int `json:"edges_before,omitempty"`
	EdgesAfter         int `json:"edges_after,omitempty"`
	InstructionsBefore int `json:"instructions_before,omitempty"`
	InstructionsAfter  int `json:"instructions_after,omitempty"`
	FoldedConstants    int `json:"folded_constants,omitempty"`
	FoldedBranches     int `json:"folded_branches,omitempty"`
	RemovedBlocks      int `json:"removed_blocks,omitempty"`
	ProofsAccepted     int `json:"proofs_accepted,omitempty"`
}

type DeobfTransform struct {
	Pass       string `json:"pass"`
	BlockID    int    `json:"block_id"`
	InsnIndex  int    `json:"instruction_index"`
	Proof      string `json:"proof"`
	Confidence int    `json:"confidence"`
}

// 🆕 v9.0.0 — CRACK POINTS (Elite Research)
type CrackPointResult struct {
	Points        []CrackPoint `json:"points,omitempty"`
	TotalHighConf int          `json:"total_high_conf"`
	Summary       string       `json:"summary,omitempty"`
}

type CrackPoint struct {
	Location   SourceLocation `json:"location"`
	ClassName  string         `json:"class_name,omitempty"`
	Method     string         `json:"method"`
	Category   string         `json:"category"`
	Confidence float64        `json:"confidence"`
	Impact     int            `json:"impact"`
	Suggestion string         `json:"suggestion"`
	PatchRisk  string         `json:"patch_risk"`
	Evidence   []string       `json:"evidence,omitempty"`
}

// 🆕 v9.0.0 — ANOMALY DETECTION (Smart Noise Filter Bypass)
type AnomalyFinding struct {
	Location    SourceLocation `json:"location"`
	Library     string         `json:"library"`
	Description string         `json:"description"`
	Severity    Severity       `json:"severity"`
	BypassType  string         `json:"bypass_type"` // "sensitive_api", "atypical_behavior"
	Score       float64        `json:"score,omitempty"`
}

// GNNFinding represents a GNN-based vulnerability classification finding.
type GNNFinding struct {
	Method     string             `json:"method"`
	FilePath   string             `json:"file_path,omitempty"`
	VulnClass  string             `json:"vuln_class"`
	Confidence float32            `json:"confidence"`
	ClassProbs map[string]float32 `json:"class_probs,omitempty"`
	// Dummy marks findings produced by randomly initialized weights. They
	// carry no evidence value: verdict/patch-planning consumers must treat
	// them as absent, and reports must label them as such.
	Dummy bool `json:"dummy,omitempty"`
}

// EvidenceGraph is the optional, deterministic provenance layer connecting
// findings to files, methods, model verdicts, NCER results and immutable raw
// evidence. It is navigation/explanation data, not a separate verdict engine.
type EvidenceGraph struct {
	Version string         `json:"version"`
	Nodes   []EvidenceNode `json:"nodes,omitempty"`
	Edges   []EvidenceEdge `json:"edges,omitempty"`
}

type EvidenceNode struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	Label       string            `json:"label"`
	Description string            `json:"description,omitempty"`
	Path        string            `json:"path,omitempty"`
	Method      string            `json:"method,omitempty"`
	Score       float64           `json:"score,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

type EvidenceEdge struct {
	ID         string            `json:"id"`
	From       string            `json:"from"`
	To         string            `json:"to"`
	Relation   string            `json:"relation"`
	Label      string            `json:"label,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type EvidenceChain struct {
	Truncated bool           `json:"truncated"`
	Warnings  []string       `json:"warnings,omitempty"`
	RootID    string         `json:"root_id"`
	Summary   string         `json:"summary"`
	Nodes     []EvidenceNode `json:"nodes,omitempty"`
	Edges     []EvidenceEdge `json:"edges,omitempty"`
}

// AnalysisResult — полный результат анализа APK.
// Thread-safety: все мутации через методы под mu.
// После Finalize() становится immutable.
type AnalysisResult struct {
	mu        sync.RWMutex `json:"-"`
	finalized bool         `json:"-"` // после Finalize = immutable

	Timestamp  time.Time    `json:"timestamp"`
	Duration   Duration     `json:"duration"`
	TargetDir  string       `json:"target_dir"`
	AppPackage string       `json:"app_package,omitempty"`
	Run        *RunMetadata `json:"run,omitempty"`

	BundleAnalysis *BundleAnalysisSummary `json:"bundle_analysis,omitempty"`
	StaticOutputs  []StaticOutputStage    `json:"static_outputs,omitempty"`

	Stats    AnalysisStats      `json:"stats"`
	Coverage CoverageStats      `json:"coverage"`
	Cache    AnalysisCacheStats `json:"cache"`

	FilesByType       map[FileType]int `json:"files_by_type,omitempty"`
	MatchesByCategory map[Category]int `json:"matches_by_category,omitempty"`

	Files                map[string]*FileAnalysis `json:"files,omitempty"`
	CallGraph            *CallGraph               `json:"call_graph,omitempty"`
	Correlations         []Correlation            `json:"correlations,omitempty"`
	Hotspots             []Hotspot                `json:"hotspots,omitempty"`
	Recommendations      []Recommendation         `json:"recommendations,omitempty"`
	RuleMatches          []Match                  `json:"rule_matches,omitempty"`
	Findings             []finding.Finding        `json:"findings,omitempty"`
	FindingsByKind       map[finding.Kind]int     `json:"findings_by_kind,omitempty"`
	DataFlows            []DataFlowFinding        `json:"data_flows,omitempty"`
	DataFlowObservations []DataFlowFinding        `json:"data_flow_observations,omitempty"`
	DataFlowStats        DataFlowStats            `json:"data_flow_stats"`

	Piracy *PiracyAnalysis `json:"piracy,omitempty"`

	// 🆕 v9.0.0 Elite Features
	Deobfuscation *DeobfuscationResult `json:"deobfuscation,omitempty"`
	CrackPoint    *CrackPointResult    `json:"crack_point,omitempty"`
	Anomalies     []AnomalyFinding     `json:"anomalies,omitempty"`

	// 🧠 ML Fusion Intelligence Reports for cross-cutting domains
	VulnFusionReport     *fusion.Report `json:"vuln_fusion_report,omitempty"`
	BehaviorFusionReport *fusion.Report `json:"behavior_fusion_report,omitempty"`

	// ArtifactFindings — находки из этапа распаковки (например, native ELF scanning).
	ArtifactFindings []ArtifactFinding `json:"artifact_findings,omitempty"`

	// MachineCodeReports — полные machine-code отчёты для .so / ELF файлов,
	// собранные когда включён флаг --scan-native вместе с APK анализом.
	MachineCodeReports []MachineCodeReport `json:"machine_code_reports,omitempty"`

	// GNN-based vulnerability classification findings (requires omnisec_ml_gnn build tag)
	GNNFindings    []GNNFinding    `json:"gnn_findings,omitempty"`
	GNNDiagnostics *GNNDiagnostics `json:"gnn_diagnostics,omitempty"`

	// FP Filter results
	FPFilterResults *FPFilterOutput `json:"fp_filter_results,omitempty"`
	RiskProfile     interface{}     `json:"risk_profile,omitempty"`

	// DeobfQualityConfidence is a 0-1 composite score from the deobfmetrics
	// package, measuring how effective the deobfuscation stage was. Populated
	// only when EnableDeobfuscation=true and at least one class was analysed.
	DeobfQualityConfidence float64 `json:"deobf_quality_confidence,omitempty"`

	// NcerResult — causal discrepancy scores from the NCER reconciliation
	// pipeline. Populated only when MITM/HTTP telemetry was observed during the
	// analysis session. omitempty keeps existing outputs byte-for-byte identical
	// when no network capture occurred.
	NcerResult *NcerCausalResult `json:"ncer,omitempty"`

	// EvidenceGraph connects existing findings and evidence without changing
	// their verdicts. It remains absent when no graphable evidence was produced.
	EvidenceGraph *EvidenceGraph `json:"evidence_graph,omitempty"`

	// Advisory only: original findings and CI verdicts retain scanner semantics.
	DecisionAI       *decisionai.Report            `json:"decision_ai,omitempty"`
	DecisionAIImages *decisionai.ImageReviewReport `json:"decision_ai_images,omitempty"`
	SourceEvidence   *sourceevidence.Report        `json:"source_evidence,omitempty"`
}

// NcerCausalResult holds the causal discrepancy scores produced by the
// NCER reconciliation pipeline (pkg/ncer/reconcile). The JSON field names
// match the Rust ReconcileResult wire format exactly so the ncer bridge can
// populate this struct without a separate conversion step.
type NcerCausalResult struct {
	// BoundCount is the number of (request, response) pairs that were matched
	// within the binding window.
	BoundCount int `json:"bound_count"`
	// UnboundCount is the number of responses that had no matching request.
	UnboundCount int `json:"unbound_count"`
	// OrphanCount is the number of requests that never received a response.
	OrphanCount int `json:"orphan_count"`
	// TotalEvents is the total number of typed events produced by the parser.
	TotalEvents int `json:"total_events"`
	// DCausal is the causal discrepancy score in [0, 1]. 0 = all effects
	// explained; 1 = nothing explained.
	DCausal float32 `json:"d_causal"`
	// CoverageQuality is the fraction of effects that had a matching cause,
	// in [0, 1].
	CoverageQuality float32 `json:"coverage_quality"`
	// DAuthority is the fraction of observed sensitive actions with no
	// corresponding granted permission, in [0, 1]. Zero when no authority
	// events were observed during the session.
	DAuthority float32 `json:"d_authority"`
	// DInformation is the fraction of DNS resolutions with no matching
	// outbound flow within the binding window, in [0, 1].
	DInformation float32 `json:"d_information"`
	// DCapability is the fraction of granted permissions never exercised by
	// any observed action during the session, in [0, 1].
	DCapability float32 `json:"d_capability"`
	// DConsequence is a severity-weighted aggregate over the AnomalyFindings
	// attached to this session via Collector.SetAnomalyFindings, in [0, 1].
	// AnomalyFinding carries no host/URL field to key a per-event overlap
	// against NCER subjects, so this is a session-level signal ("how severe
	// were this session's other findings"), not a per-effect score. Zero
	// when no findings were attached.
	DConsequence float32 `json:"d_consequence"`
	// DNovelty is the fraction of this session's event fingerprints
	// (method+URL, DNS query name) not present in the per-target baseline
	// recorded by prior sessions, in [0, 1].
	DNovelty float32 `json:"d_novelty"`
	// EvidenceRefs holds content-addressed SHA-256 digests of immutable raw
	// evidence backing this NCER finding.
	EvidenceRefs []string `json:"evidence_refs"`
	// EvidenceVerified indicates whether every reference in EvidenceRefs was
	// successfully verified against content-addressed storage.
	EvidenceVerified bool `json:"evidence_verified"`
	// EvidenceCount is the number of evidence references.
	EvidenceCount int `json:"evidence_count"`
}

// ───────────────────────────────────────────────────────────────────────────────
// FP Filter Types (Anti-False-Positive / Noise-Reduction)
// ───────────────────────────────────────────────────────────────────────────────

type Verdict string

const (
	VerdictConfirmedAppRisk       Verdict = "confirmed_app_risk"
	VerdictConfirmedSDKRisk       Verdict = "confirmed_sdk_risk"
	VerdictSDKInteresting         Verdict = "sdk_interesting"
	VerdictSDKNoiseSuppressed     Verdict = "sdk_noise_suppressed"
	VerdictGenericNoiseSuppressed Verdict = "generic_noise_suppressed"
	VerdictNeedsContext           Verdict = "needs_context"
	VerdictObservation            Verdict = "observation"
)

type ScoreBreakdown struct {
	BaseScore              float64 `json:"base_score"`
	StrongSignalScore      float64 `json:"strong_signal_score"`
	SensitiveAPIScore      float64 `json:"sensitive_api_score"`
	DataflowScore          float64 `json:"dataflow_score"`
	CallgraphScore         float64 `json:"callgraph_score"`
	ExploitabilityScore    float64 `json:"exploitability_score"`
	AppReachabilityScore   float64 `json:"app_reachability_score"`
	GenericSDKNoiseScore   float64 `json:"generic_sdk_noise_score"`
	CommonBoilerplateScore float64 `json:"common_boilerplate_score"`
	DuplicatePatternScore  float64 `json:"duplicate_pattern_score"`
}

type StrongSignal struct {
	SignalType string  `json:"signal_type"`
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`
}

type SDKInfo struct {
	Name       string  `json:"name"`
	Category   string  `json:"category"`
	IsKnown    bool    `json:"is_known"`
	Confidence float64 `json:"confidence"`
}

type ClassifiedFinding struct {
	Original          *Match         `json:"original,omitempty"`
	Verdict           Verdict        `json:"verdict"`
	OriginalScore     float64        `json:"original_score"`
	FinalScore        float64        `json:"final_score"`
	StrongSignals     []StrongSignal `json:"strong_signals,omitempty"`
	SDKInfo           *SDKInfo       `json:"sdk_info,omitempty"`
	SuppressionReason string         `json:"suppression_reason,omitempty"`
	ScoreBreakdown    ScoreBreakdown `json:"score_breakdown"`
}

type FPFilterStats struct {
	TotalFindings          int `json:"total_findings"`
	SuppressedSDKNoise     int `json:"suppressed_sdk_noise"`
	ConfirmedSDKRisks      int `json:"confirmed_sdk_risks"`
	ConfirmedAppRisks      int `json:"confirmed_app_risks"`
	SDKInteresting         int `json:"sdk_interesting"`
	GenericNoiseSuppressed int `json:"generic_noise_suppressed"`
	NeedsContext           int `json:"needs_context"`
	Observations           int `json:"observations"`
}

type FPFilterOutput struct {
	Stats              FPFilterStats       `json:"stats"`
	ClassifiedFindings []ClassifiedFinding `json:"classified_findings,omitempty"`
	SuppressedFindings []ClassifiedFinding `json:"suppressed_findings,omitempty"`
	AggregatedPatterns interface{}         `json:"aggregated_patterns,omitempty"`
}

// MachineCodeReport — полный machine-code отчёт для одного native бинарника.
// Используется как в standalone-режиме, так и в составе APK-отчёта.
type MachineCodeReport struct {
	GeneratedAt   time.Time             `json:"generated_at"`
	EngineVersion string                `json:"engine_version"`
	Target        string                `json:"target"`
	Size          int64                 `json:"size_bytes"`
	Format        string                `json:"format"`
	Arch          string                `json:"arch"`
	Score         uint32                `json:"risk_score"`
	Verdict       string                `json:"verdict"`
	Hardening     MachineCodeHardening  `json:"hardening"`
	Findings      []MachineCodeFinding  `json:"findings"`
	Statistics    MachineCodeStatistics `json:"statistics"`
	Notes         []string              `json:"notes,omitempty"`
	// PE carries the structured PE analysis (sections, entry point, TLS,
	// overlay, signature, diagnostics) and DotNet the CLI metadata summary
	// with IL callsites, when the target is a PE image. Both ride the JSON
	// report untouched; the Markdown/HTML views project them into tables.
	PE     *peinspect.Metadata   `json:"pe,omitempty"`
	DotNet *peinspect.DotNetInfo `json:"dotnet,omitempty"`
	// CrackPoints — license/anti-tamper/anti-debug gates found by the pure-Go
	// symbol/string scan (works without the Rust bridge).
	CrackPoints []CrackPoint `json:"crack_points,omitempty"`
}

type MachineCodeHardening struct {
	NX            *bool  `json:"nx"`
	PIE           *bool  `json:"pie"`
	Relro         string `json:"relro"`
	StackCanary   *bool  `json:"stack_canary"`
	FortifySource *bool  `json:"fortify_source"`
	Stripped      *bool  `json:"stripped"`
	WxSections    int    `json:"wx_sections"`
}

type MachineCodeFinding struct {
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Confidence  string  `json:"confidence"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
	CWE         *string `json:"cwe,omitempty"`
	Remediation *string `json:"remediation,omitempty"`
	FileOffset  *uint64 `json:"file_offset,omitempty"`
	Payload     *string `json:"payload,omitempty"`
	PayloadFull *string `json:"payload_full,omitempty"`
}

type MachineCodeStatistics struct {
	TotalFindings      int            `json:"total_findings"`
	BySeverity         map[string]int `json:"by_severity"`
	ByCategory         map[string]int `json:"by_category"`
	WithCWE            int            `json:"with_cwe"`
	WeaponizedPayloads int            `json:"weaponized_payloads"`
}

// ArtifactFinding — результат анализа отдельного файла-артефакта (.so, .patch, и т.д.).
type ArtifactFinding struct {
	JVMEvidence *Match   `json:"jvm_evidence,omitempty"` // exact class/method/offset evidence, when available
	Path        string   `json:"path"`
	Severity    Severity `json:"severity"`
	Reason      string   `json:"reason"`
	Payload     string   `json:"payload,omitempty"`
	PayloadFull string   `json:"payload_full,omitempty"`
	Stages      []string `json:"stages,omitempty"`
}

func NewAnalysisResult(targetDir string) *AnalysisResult {
	return &AnalysisResult{
		Timestamp:         time.Now(),
		TargetDir:         targetDir,
		FilesByType:       make(map[FileType]int),
		MatchesByCategory: make(map[Category]int),
		Files:             make(map[string]*FileAnalysis),
		CallGraph:         NewCallGraph(),
		Correlations:      make([]Correlation, 0, 16),
		Hotspots:          make([]Hotspot, 0, 32),
		Recommendations:   make([]Recommendation, 0, 8),
		RuleMatches:       make([]Match, 0, 8),
		Findings:          make([]finding.Finding, 0, 16),
		FindingsByKind:    make(map[finding.Kind]int),
	}
}

// AddMatch добавляет совпадение thread-safe.
func (r *AnalysisResult) AddMatch(file string, match Match) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.finalized {
		return // immutable after Finalize
	}

	if fa, ok := r.Files[file]; ok {
		fa.Matches = append(fa.Matches, match)
	}
	r.Stats.TotalMatches++
	if match.IsCritical {
		r.Stats.CriticalMatches++
	}
	r.MatchesByCategory[match.Category]++
}

// AddFile добавляет файл thread-safe.
func (r *AnalysisResult) AddFile(path string, fa *FileAnalysis) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.finalized {
		return
	}
	r.Files[path] = fa
}

// GetFile возвращает файл thread-safe.
func (r *AnalysisResult) GetFile(path string) (*FileAnalysis, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fa, ok := r.Files[path]
	return fa, ok
}

// Finalize завершает анализ и делает результат immutable.
func (r *AnalysisResult) Finalize(startTime time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.finalized {
		return
	}

	r.Duration = Duration(time.Since(startTime))
	if r.MatchesByCategory == nil {
		r.MatchesByCategory = make(map[Category]int)
	} else {
		clear(r.MatchesByCategory)
	}
	r.Stats.TotalMatches = 0
	r.Stats.CriticalMatches = 0
	r.Stats.AppCodeFiles = 0
	// Analyzed files are distinct physical files actually processed. The
	// per-job Coverage counter also counts virtual DEX-class units and
	// re-queued files, which produced contradictions like "315 analyzed of
	// 313 total"; the Files map cannot exceed the real universe.
	r.Stats.AnalyzedFiles = len(r.Files)
	if r.Coverage.Queued > 0 {
		r.Stats.TotalFiles = r.Coverage.Queued
	} else {
		r.Stats.TotalFiles = len(r.Files)
	}
	// Late analysis units (recovered artifacts, decoded bundles) expand the
	// universe beyond the pre-scan walk; keep the pair self-consistent.
	if r.Stats.TotalFiles < r.Stats.AnalyzedFiles {
		r.Stats.TotalFiles = r.Stats.AnalyzedFiles
	}
	for _, fa := range r.Files {
		if fa == nil {
			continue
		}
		if fa.IsAppCode {
			r.Stats.AppCodeFiles++
		}
		for _, match := range fa.Matches {
			r.Stats.TotalMatches++
			if match.IsCritical {
				r.Stats.CriticalMatches++
			}
			if match.Category != "" {
				r.MatchesByCategory[match.Category]++
			}
		}
	}
	// Rule matches are global and must be counted once, not once per file.
	for _, match := range r.RuleMatches {
		r.Stats.TotalMatches++
		if match.IsCritical {
			r.Stats.CriticalMatches++
		}
		if match.Category != "" {
			r.MatchesByCategory[match.Category]++
		}
	}
	r.finalized = true
}

// IsFinalized проверяет, завершён ли анализ.
// ShareableTargetName returns a report-safe target name: the original input
// file name when the run recorded one, else the app package, else the base
// of TargetDir. Absolute local paths (temp extraction dirs, workspace
// folders such as F:/PROJECTS/...) must not leak into shared reports through
// the evidence graph, analysis.json target_dir or the HTML meta section.
func (r *AnalysisResult) ShareableTargetName() string {
	if r == nil {
		return ""
	}
	if r.Run != nil {
		if t := strings.TrimSpace(r.Run.Identity["target"]); t != "" {
			return filepath.Base(filepath.ToSlash(t))
		}
	}
	if r.AppPackage != "" {
		return r.AppPackage
	}
	if base := filepath.Base(filepath.ToSlash(strings.TrimSpace(r.TargetDir))); base != "." && base != "" && base != "/" {
		return base
	}
	return r.TargetDir
}

func (r *AnalysisResult) IsFinalized() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.finalized
}

// Merge объединяет результаты с deep copy (фикс #5).
func (r *AnalysisResult) Merge(other *AnalysisResult) {
	if other == nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.finalized {
		return
	}

	other.mu.RLock()
	defer other.mu.RUnlock()

	for path, fa := range other.Files {
		if _, exists := r.Files[path]; !exists {
			r.Files[path] = fa.DeepCopy()
		}
	}

	r.Stats.TotalFiles += other.Stats.TotalFiles
	r.Stats.TotalMatches += other.Stats.TotalMatches
	r.Stats.CriticalMatches += other.Stats.CriticalMatches

	for cat, count := range other.MatchesByCategory {
		r.MatchesByCategory[cat] += count
	}

	// Deep copy Correlations (фикс #5)
	for _, c := range other.Correlations {
		r.Correlations = append(r.Correlations, c.DeepCopy())
	}

	// Deep copy Hotspots
	for _, h := range other.Hotspots {
		hCopy := h
		if len(h.Categories) > 0 {
			hCopy.Categories = make([]Category, len(h.Categories))
			copy(hCopy.Categories, h.Categories)
		}
		if len(h.Reasons) > 0 {
			hCopy.Reasons = make([]string, len(h.Reasons))
			copy(hCopy.Reasons, h.Reasons)
		}
		if len(h.DecisionPoints) > 0 {
			hCopy.DecisionPoints = make([]DecisionPoint, len(h.DecisionPoints))
			copy(hCopy.DecisionPoints, h.DecisionPoints)
		}
		r.Hotspots = append(r.Hotspots, hCopy)
	}

	// Deep copy RuleMatches
	for _, m := range other.RuleMatches {
		mCopy := m
		if len(m.Metadata) > 0 {
			mCopy.Metadata = make(map[string]string, len(m.Metadata))
			for k, v := range m.Metadata {
				mCopy.Metadata[k] = v
			}
		}
		r.RuleMatches = append(r.RuleMatches, mCopy)
	}
}
