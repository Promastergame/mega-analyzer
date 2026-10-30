// Package jspatcher implements a smart JavaScript bundle patcher for React Native
// and Hermes-compiled applications.
//
// It detects and patches: donations, server addresses, age checks, registration
// gates, premium/subscription locks, ads, license checks, and more.
//
// Architecture:
//
//	Bundle → Tokenizer (skip strings/comments) → Rule Engine → Context Analyzer
//	     → Confidence Scoring → Smart Patch Generator → Validator → Report
package jspatcher

import "mega-analyzer/pkg/internal/apkloader"

// ─── Category ────────────────────────────────────────────────────────────────

// JSPatchCategory is the semantic class of what a rule detects.
type JSPatchCategory string

const (
	CategoryDonate       JSPatchCategory = "donate"
	CategoryServer       JSPatchCategory = "server"
	CategoryAgeCheck     JSPatchCategory = "age_check"
	CategoryRegistration JSPatchCategory = "registration"
	CategoryPremium      JSPatchCategory = "premium"
	CategorySubscription JSPatchCategory = "subscription"
	CategoryAds          JSPatchCategory = "ads"
	CategoryLicense      JSPatchCategory = "license"
	CategorySecurity     JSPatchCategory = "security"
	CategoryTrial        JSPatchCategory = "trial"
	CategoryGeoBlock     JSPatchCategory = "geo_block"
	CategorySSLPinning   JSPatchCategory = "ssl_pinning"
)

// CategoryMeta holds human-readable info about a category.
type CategoryMeta struct {
	Name        string
	Description string
	Severity    string
	SortOrder   int
}

// AllCategoryMeta is the registry of human-readable category metadata.
var AllCategoryMeta = map[JSPatchCategory]CategoryMeta{
	CategoryDonate:       {"Donate", "Donation gates, payment prompts", "medium", 6},
	CategoryServer:       {"Server Address", "Hardcoded server URLs, IPs, WebSocket endpoints", "high", 1},
	CategoryAgeCheck:     {"Age Verification", "Age gates, adult content checks", "medium", 5},
	CategoryRegistration: {"Registration / Auth", "Login requirements, session checks", "high", 3},
	CategoryPremium:      {"Premium / Pro", "Premium feature locks, paywalls", "critical", 2},
	CategorySubscription: {"Subscription", "Subscription checks, recurring payment gates", "critical", 2},
	CategoryAds:          {"Ads", "Ad display logic, ad-free checks", "medium", 7},
	CategoryLicense:      {"License", "License validation, DRM checks", "critical", 2},
	CategorySecurity:     {"Security / Integrity", "Root/jailbreak checks, tamper detection", "high", 4},
	CategoryTrial:        {"Trial / Time Limit", "Trial expiry, time-limited features", "high", 4},
	CategoryGeoBlock:     {"Geo Block", "Region-based access restrictions", "medium", 8},
	CategorySSLPinning:   {"SSL Pinning", "Certificate pinning in fetch/axios/XHR", "high", 3},
}

// ─── Patch Strategy ───────────────────────────────────────────────────────────

// PatchStrategy describes HOW the patcher modifies the code.
type PatchStrategy string

const (
	// StrategyEarlyReturnTrue injects `return true;` at the start of the detected function body.
	StrategyEarlyReturnTrue PatchStrategy = "early_return_true"
	// StrategyEarlyReturnFalse injects `return false;` at the start of the detected function body.
	StrategyEarlyReturnFalse PatchStrategy = "early_return_false"
	// StrategyAssignTrue replaces the assigned value with `true`.
	StrategyAssignTrue PatchStrategy = "assign_true"
	// StrategyAssignFalse replaces the assigned value with `false`.
	StrategyAssignFalse PatchStrategy = "assign_false"
	// StrategyConditionTrue replaces the condition expression with `true`.
	StrategyConditionTrue PatchStrategy = "condition_true"
	// StrategyConditionFalse replaces the condition expression with `false`.
	StrategyConditionFalse PatchStrategy = "condition_false"
	// StrategyNOP comments out the entire matched statement.
	StrategyNOP PatchStrategy = "nop"
	// StrategyReplaceURL replaces a server URL/IP with the user-supplied address.
	StrategyReplaceURL PatchStrategy = "replace_url"
	// StrategyRemovePin removes SSL certificate pinning configuration.
	StrategyRemovePin PatchStrategy = "remove_pin"
	// StrategyInlineTrue replaces a function call site with `true` inline.
	StrategyInlineTrue PatchStrategy = "inline_true"
	// StrategyInlineFalse replaces a function call site with `false` inline.
	StrategyInlineFalse PatchStrategy = "inline_false"
	// StrategyInformational marks the match as log-only, no patch will be generated.
	StrategyInformational PatchStrategy = "informational"
)

// ─── Match Context ─────────────────────────────────────────────────────────────

// MatchContext captures the syntactic role of a matched identifier/expression.
// Determined without a full AST by looking at surrounding tokens/lines.
type MatchContext struct {
	AmbiguousRewrite bool // local evidence is valid but a whole-line rewrite would affect unrelated code
	// IsFunctionDecl is true when the match is part of a function definition.
	// E.g.: `function isPremium() {`, `const isPremium = () => {`
	IsFunctionDecl bool

	// IsAssignment is true when the identifier appears on the LHS of an assignment
	// or as the RHS value of a var/let/const declaration.
	IsAssignment bool

	// IsCondition is true when the match is inside if/while/ternary/logical expression.
	IsCondition bool

	// IsReturnStmt is true when the match is in a `return` expression.
	IsReturnStmt bool

	// IsNegated is true when the match is preceded by `!` (inverting the semantics).
	IsNegated bool

	// IsCallSite is true when the match is a function call: `isPremium()`.
	IsCallSite bool

	// IsPropertyAccess is true when accessed as `obj.isPremium`.
	IsPropertyAccess bool

	// IsAlreadyPatched is true if the surrounding lines already contain our patch marker.
	IsAlreadyPatched bool

	// RefCount is the number of times this symbol appears in the entire bundle.
	// High RefCount → high impact patch.
	RefCount int

	// FuncBodyLine is the line index (0-based) where the detected function body `{` starts.
	// -1 means not found (can't do early-return injection).
	FuncBodyLine int
}

// ─── Rule ─────────────────────────────────────────────────────────────────────

// JSPatchRule is a single detection + patch rule.
type JSPatchRule struct {
	// ID is a unique stable rule identifier (snake_case).
	ID string

	// Category groups this rule semantically.
	Category JSPatchCategory

	// Name is a short human-readable name.
	Name string

	// Description explains what this rule targets.
	Description string

	// Patterns are the primary regex patterns to look for (applied to code-only regions).
	// At least one must match to produce a finding.
	Patterns []string

	// ContextBoosts are regex patterns checked in the ±5 surrounding lines.
	// Each match adds +BoostPerSignal to confidence.
	ContextBoosts []string

	// ContextPenalties are regex patterns that REDUCE confidence when found nearby.
	// Prevents false positives in e.g. analytics/tracking code.
	ContextPenalties []string

	// DefaultStrategy is the preferred patch strategy.
	// The patcher may override this based on MatchContext.
	DefaultStrategy PatchStrategy

	// BaseConfidence is the starting confidence (0–100) before context signals.
	BaseConfidence int

	// ImpactNote describes what will change when this rule is patched.
	ImpactNote string

	// SymbolCapture is the regex group index (1-based) that captures the symbol name
	// for reference counting. 0 = use the whole match.
	SymbolCapture int
}

// ─── Match ────────────────────────────────────────────────────────────────────

// JSPatchMatch is a single detected finding in the bundle.
type JSPatchMatch struct {
	ByteStart          int                 `json:"byte_start"`
	ByteEnd            int                 `json:"byte_end"`
	GeneratedPositions []GeneratedPosition `json:"generated_positions,omitempty"`
	Rule               *JSPatchRule
	FilePath           string
	LineNum            int    // 1-based
	ColNum             int    // 0-based column of the match
	MatchedText        string // the raw matched text

	// FromSourceMap marks findings recovered from sourcesContent. They are
	// useful for analysis, but their line numbers do not address the generated
	// bundle and therefore must never be used to propose or apply a patch.
	FromSourceMap bool
	SourceMapPath string

	Context    MatchContext
	Confidence int // 0–100

	// SurroundingLines is the context window (up to ±5 lines) for display/analysis.
	SurroundingLines []string

	// ProposedPatch is nil until GeneratePatch is called.
	ProposedPatch *JSPatch
}

// ─── Patch ────────────────────────────────────────────────────────────────────

// JSPatch is the concrete change to apply to a source file.
type JSPatch struct {
	FilePath string
	LineNum  int // 1-based target line
	NumLines int // number of original lines to replace (usually 1)

	Before      string // original text (for diff/report)
	After       string // patched text
	Strategy    PatchStrategy
	Description string

	// IsValid is true if the patch passed bracket-balance validation.
	IsValid bool
	// ValidationError is set if IsValid is false.
	ValidationError string
}

// ─── Apply mode ──────────────────────────────────────────────────────────────

// ApplyMode controls whether patches are previewed or actually written.
type ApplyMode string

const (
	ApplyDryRun ApplyMode = "dry-run"
	ApplyWrite  ApplyMode = "write"
)

// ─── Applied Patch ────────────────────────────────────────────────────────────

// AppliedPatch records a successfully written change.
type AppliedPatch struct {
	FilePath string
	LineNum  int
	Before   string
	After    string
	Strategy PatchStrategy
}

// ─── Symbol Group ─────────────────────────────────────────────────────────────

// SymbolGroup aggregates all matches for the same logical symbol.
// Instead of reporting 47 occurrences of `isPremium`, we report one group
// with RefCount=47 and the single best patch point.
type SymbolGroup struct {
	Symbol     string // the detected symbol name
	Category   JSPatchCategory
	BestMatch  *JSPatchMatch   // highest-confidence match (the one to patch)
	AllMatches []*JSPatchMatch // all occurrences
	TotalRefs  int             // total in bundle
	Impact     string          // formatted impact description
}

// ─── Scan Result ──────────────────────────────────────────────────────────────

// JSPatchResult is the full output of scanning (and optionally patching) a bundle.
type JSPatchResult struct {
	AnalysisStatus string            `json:"analysis_status"`
	Diagnostics    []string          `json:"diagnostics,omitempty"`
	SourceMaps     SourceMapCoverage `json:"source_maps"`
	Target         string
	BundleType     string            // "hermes_bytecode" | "react_native_js" | "plain_js"
	IsHermes       bool              // patching not available for Hermes bytecode
	Hermes         []*HermesAnalysis `json:"hermes_analysis,omitempty"`
	CacheHit       bool              `json:"cache_hit,omitempty"`

	// Raw matches (before grouping)
	Matches []*JSPatchMatch

	// Grouped by symbol for display
	Groups []*SymbolGroup

	// Patches proposed or applied
	Patches []*JSPatch

	// Stats
	TotalFiles   int
	ScannedFiles int
	MatchCount   int
	GroupCount   int
	PatchCount   int
	SkippedCount int // below confidence threshold

	// Per-category breakdown
	ByCategory map[JSPatchCategory][]*JSPatchMatch

	// Applied patches (if ApplyWrite)
	Applied  []AppliedPatch
	BackedUp []string // paths to .orig backup files

	Errors []string
}

type HermesAnalysis struct {
	Status         string                        `json:"status"`
	Diagnostics    []string                      `json:"diagnostics,omitempty"`
	GraphCoverage  apkloader.HermesGraphCoverage `json:"graph_coverage"`
	TotalStrings   uint32                        `json:"total_strings"`
	TotalFunctions uint32                        `json:"total_functions"`
	TotalModules   uint32                        `json:"total_modules"`
	Path           string                        `json:"path"`
	Parsed         bool                          `json:"parsed"`
	ParseError     string                        `json:"parse_error,omitempty"`
	Version        uint32                        `json:"version,omitempty"`
	StringCount    int                           `json:"string_count"`
	FunctionCount  int                           `json:"function_count"`
	ModuleCount    int                           `json:"module_count"`
	Modules        []string                      `json:"modules,omitempty"`
	FunctionNames  []string                      `json:"function_names,omitempty"`
	Endpoints      []string                      `json:"endpoints,omitempty"`
	Bridges        []string                      `json:"bridges,omitempty"`
	CallEdges      []HermesCallEdgeSummary       `json:"call_edges,omitempty"`
}

type HermesCallEdgeSummary struct {
	CallerID       uint32  `json:"caller_id"`
	CalleeID       *uint32 `json:"callee_id"`
	Kind           string  `json:"kind"`
	Confidence     string  `json:"confidence"`
	Resolved       bool    `json:"resolved"`
	FunctionOffset uint32  `json:"function_offset"`
	CalleeRegister *uint32 `json:"callee_register,omitempty"`
	BuiltinID      *uint32 `json:"builtin_id,omitempty"`
	Caller         string  `json:"caller"`
	Callee         string  `json:"callee"`
	Offset         uint32  `json:"offset"`
}

// PatcherConfig controls scanner and patcher behaviour.
type PatcherConfig struct {
	HermesBudget string // compact|large; included in cache identity
	// MinConfidence is the minimum confidence required to include a match (0–100).
	MinConfidence int

	// ApplyMode is "dry-run" or "write".
	Apply ApplyMode

	// NewServerIP is the replacement address for server URL rules.
	// Format: "host:port" or "https://host:port".
	NewServerIP string

	// Backup controls whether .orig files are written before patching.
	Backup bool

	// Categories is an optional whitelist of categories to scan.
	// Empty = all categories.
	Categories []JSPatchCategory

	// OutputDir is where JSPATCH.md and jspatch.json are written.
	OutputDir string
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() PatcherConfig {
	return PatcherConfig{
		MinConfidence: 40,
		Apply:         ApplyDryRun,
		Backup:        true,
	}
}
