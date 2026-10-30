package report

import (
	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/media"
)

// ═══════════════════════════════════════════════════════════════════════════════
// VIEW TYPES — чистые данные для рендеринга
// Никакой логики, только структуры.
// Все RiskLevel = types.RiskLevel (единственный источник правды).
// ═══════════════════════════════════════════════════════════════════════════════

// ReportView — корневая структура отчёта.
type ReportView struct {
	BundleAnalysis  *types.BundleAnalysisSummary
	StaticOutputs   []types.StaticOutputStage
	Meta            MetaView
	Summary         SummaryView
	Stats           StatsView
	Detections      DetectionsView
	Hotspots        []HotspotView
	HotspotDetails  []HotspotDetailView
	RiskSummary     RiskSummaryView
	Suspicion       SuspicionBreakdown // canonical 0-100 risk score (CLI, HTML, Markdown)
	Recommendations []RecommendationView
	RuleFindings    []RuleFindingView
	BankingThreats  []RuleFindingView // critical/high banking trojan combos
	TypedFindings   []TypedFindingView

	// 🆕 v9.0.0 Elite Research Views
	Deobfuscation      DeobfuscationView
	CrackPoints        []CrackPointView
	Anomalies          []AnomalyView
	ArtifactFindings   []ArtifactFindingView
	MachineCodeReports []MachineCodeReportView
	MediaReports       []MediaReportView // NEW: Media Forensics

	// Artifacts (opt-in via --artifacts). Pointer so JSON/HTML can omit
	// the section entirely when the flag is off.
	Artifacts *ArtifactsView `json:",omitempty"`

	// NCER Causal Reconciliation result
	NcerResult *types.NcerCausalResult `json:",omitempty"`

	// EvidenceGraph is the optional deterministic provenance graph.
	EvidenceGraph *types.EvidenceGraph `json:",omitempty"`
}

type ArtifactFindingView struct {
	Path     string
	Severity string
	Emoji    string
	Reason   string
	Payload  string
	Stages   []string
}

type MachineCodeReportView struct {
	Target        string
	Format        string
	Arch          string
	Score         uint32
	Verdict       string
	FindingsCount int
	HardeningRows []MachineCodeHardeningRow
	Stats         MachineCodeStatsView
	Findings      []MachineCodeFindingView
	// PE projects the structured PE analysis (sections, entry point, TLS,
	// overlay, signature); DotNet the CLI metadata summary with IL
	// callsites. Nil for non-PE targets.
	PE     *MachineCodePEView
	DotNet *MachineCodeDotNetView
}

// MachineCodePEView is the UI projection of peinspect.Metadata.
type MachineCodePEView struct {
	EntryPoint  string
	TLS         string
	Overlay     string
	Analysis    string
	Sections    []MachineCodeSectionView
	Signature   string
	Diagnostics []string
}

type MachineCodeSectionView struct {
	Name        string
	Permissions string
	VirtualSize string
	FileSize    string
}

// MachineCodeDotNetView is the UI projection of peinspect.DotNetInfo.
// CallSites is display-capped; CallSitesMore counts the remainder carried
// by the JSON report.
type MachineCodeDotNetView struct {
	Assembly      string
	EntryPoint    string
	Framework     string
	PInvokes      []string
	Hints         []string
	ILStats       string
	CallSites     []MachineCodeILCallView
	CallSitesMore int
}

type MachineCodeILCallView struct {
	Caller string
	Op     string
	Target string
}

type MediaReportView struct {
	Path          string
	RiskScore     int
	SeverityClass string
	IsPolyglot    bool
	PrimaryFormat string
	HiddenFormats []string
	Regions       []MediaRegionView
	RecoveredData map[string]string
	Extra         *media.MediaMetadata // full forensic dump: EXIF tags, XMP, PNG chunks, ICC, thumbnail, trailing data
}

type MediaRegionView struct {
	Offset        string
	Size          int
	Type          string
	SeverityClass string
	Severity      float64
	// Reason explains in plain language why this region was flagged.
	Reason string
}

type MachineCodeHardeningRow struct {
	Mitigation string
	Status     string
}

type MachineCodeStatsView struct {
	TotalFindings      int
	WithCWE            int
	WeaponizedPayloads int
	BySeverity         []NameCount
	ByCategory         []NameCount
}

type NameCount struct {
	Name  string
	Count int
}

type MachineCodeFindingView struct {
	Title       string
	Category    string
	Severity    string
	Confidence  string
	CWE         string
	Offset      string
	Description string
	Evidence    string
	PayloadFull string
	Remediation string
}

type HTMLReportView struct {
	Report  ReportView
	Matches []HTMLMatchView
}

// ── META ─────────────────────────────────────────────────────────────────────

type MetaView struct {
	EngineVersion string
	ReportSchema  string
	Profile       string
	Timestamp     string
	Duration      string
	TargetDir     string
	TargetName    string
	AppPackage    string
}

// ── SUMMARY (5 секунд — понять стоит ли читать) ─────────────────────────────

type SummaryView struct {
	RiskLevel types.RiskLevel
	RiskEmoji string

	TotalHotspots    int
	CriticalHotspots int
	HighHotspots     int

	// Флаги обнаружения по группам
	DetectedGroups map[string]bool // key = types.GroupLicense, etc.

	// Топ категории
	TopCategories []CategorySummary

	// Одна строка вердикта
	Verdict string
}

type CategorySummary struct {
	Name     string
	Count    int
	Priority int
	Emoji    string
	Group    string
}

// ── STATISTICS ───────────────────────────────────────────────────────────────

type StatsView struct {
	TotalFiles        int
	AnalyzedFiles     int
	SkippedFiles      int
	AppCodeFiles      int
	LibraryCodeFiles  int // analyzed files with findings that are library/SDK code
	TotalMatches      int
	CriticalMatches   int
	HotspotsCount     int
	DecisionPoints    int
	PiracyFindings    int
	CorrelationsCount int
	Discovered        int
	Eligible          int
	Queued            int
	Parsed            int
	ParseFailed       int
	FilesFailed       int
	SkippedBySize     int
	SkippedByLimit    int
	Unsupported       int
	AnalyzedClasses   int
	AnalyzedMethods   int
	AnalysisUnits     int
	FindingsBearing   int
	CoverageLimited   bool
	CacheEnabled      bool
	CacheHits         int64
	CacheMisses       int64
	CacheHitRate      float64
	DataFlowFindings  int

	FilesByType        []FileTypeCount
	MatchesByCategory  []CategoryCount
	DecisionPointsList []DecisionPointView
}

type TypedFindingView struct {
	Kind        string
	RuleID      string
	Category    string
	Title       string
	Severity    string
	Confidence  float64
	CWE         string
	MASVS       string
	File        string
	Line        int
	Evidence    string
	Fingerprint string
	Detector    string
}

// DecisionPointView is one explicit decision point shown in the report so the
// "Decision Points: N" count is no longer opaque. See plan §1.9.
type DecisionPointView struct {
	Method      string
	Type        string
	Category    string
	Description string
	File        string
	Line        int
	Confidence  float64
}

type FileTypeCount struct {
	Type  string
	Emoji string
	Count int
}

type CategoryCount struct {
	Category string
	Priority int
	Emoji    string
	Count    int
	Group    string
}

// ── DETECTIONS (динамические группы) ─────────────────────────────────────────

type DetectionsView struct {
	Groups []DetectionGroupView // автогенерация из types.AllGroups
	Piracy PiracyView
}

type DetectionGroupView struct {
	Title string
	Icon  string
	Group string // types.GroupLicense, etc.
	Count int
	Items []DetectionItem
}

type DetectionItem struct {
	Category string
	Emoji    string
	Pattern  string
	File     string
	Line     int
	Critical bool
}

// HTMLMatchView — расширенное представление detection для HTML-рендера.
type HTMLMatchView struct {
	DetectionItem
	CategoryKey   string
	Group         string
	MatchID       string
	SnippetBefore []CodeLine
	SnippetMatch  CodeLine
	SnippetAfter  []CodeLine
}

type CodeLine struct {
	Number  int
	Content string
	IsMatch bool
}

type PiracyView struct {
	Count      int
	Sites      []string
	Confidence float64
	Risk       string
	Findings   []PiracyFindingView
}

type PiracyFindingView struct {
	Type        string
	Source      string
	Pattern     string
	File        string
	Line        int
	Confidence  float64
	Description string
	SiteName    string
	SiteDomain  string
}

// ── HOTSPOTS ─────────────────────────────────────────────────────────────────

type HotspotView struct {
	Rank           int
	Score          float64
	ScoreBar       string
	Risk           types.RiskLevel
	RiskEmoji      string
	Category       string
	CategoryEmoji  string
	Path           string
	PathShort      string
	FileName       string
	Reasons        string
	Confidence     float64
	MatchCount     int
	CriticalCount  int
	EvidenceNodeID string
	// ReasoningChain — AI-style step-by-step explanation (hotspots only).
	ReasoningChain []ChainStepView
}

type HotspotDetailView struct {
	Rank       int
	Path       string
	FileName   string
	Score      float64
	Risk       types.RiskLevel
	Confidence float64
	Categories []string
	Reasons    []string
	Methods    []MethodInfo
	WhyRisky   string
}

type MethodInfo struct {
	Name       string
	Signature  string
	Risk       types.RiskLevel
	Indicators []string
}

// ── RISK SUMMARY ─────────────────────────────────────────────────────────────

type RiskSummaryView struct {
	OverallRisk   types.RiskLevel
	Confidence    float64
	ByCategory    []RiskCategoryView
	KeyFindings   []string
	AttackSurface []string
}

type RiskCategoryView struct {
	Category   string
	Risk       types.RiskLevel
	Indicators int
	TopFile    string
}

// ── RECOMMENDATIONS ──────────────────────────────────────────────────────────

type RecommendationView struct {
	Priority      int
	Emoji         string
	Title         string
	Description   string
	Indicators    []string
	Risk          types.RiskLevel
	Confidence    float64
	Complexity    string
	Category      string
	AffectedFiles []string
	Note          string
	IsLegitimate  bool
}

// ── RULE-BASED THREATS ──────────────────────────────────────────────────────

type RuleFindingView struct {
	RuleID      string
	Name        string
	RuleSet     string
	Severity    string
	Score       int
	Description string
	References  string
	Tags        string
}

// ── ELITE RESEARCH VIEWS (🆕 v9.0.0) ──────────────────────────────────────────

type DeobfuscationView struct {
	Enabled             bool
	CFFFDetected        bool
	OpaquePredicates    int
	DeadCodeNodes       int
	RecoveredStrings    int
	ComplexityReduction float64
	MethodsConsidered   int
	MethodsTransformed  int
	ProofsAccepted      int
	FoldedConstants     int
	FoldedBranches      int
	BlocksBefore        int
	BlocksAfter         int
	EmulatorAttempts    int
	EmulatorRecoveries  int
	EmulatorAbstentions int
	EmulatorBudgets     int
	JournalTruncated    bool
	Methods             []DeobfMethodView
}

type DeobfMethodView struct {
	FullName         string
	Findings         []string
	Transformed      bool
	CandidateScore   int
	ProofsAccepted   int
	BlocksBefore     int
	BlocksAfter      int
	EmulationStatus  string
	EmulationReason  string
	RecoveredValues  []string
	JournalTruncated bool
}

type CrackPointView struct {
	Location      string
	File          string // base filename, shown for obfuscated method names
	Method        string
	Category      string
	Confidence    string
	ConfidenceVal float64
	Impact        int
	Suggestion    string
	PatchRisk     string
	RiskEmoji     string
	Evidence      []string
}

type AnomalyView struct {
	Location    string
	File        string
	Library     string
	Description string
	Severity    string
	Emoji       string
	BypassType  string
}
