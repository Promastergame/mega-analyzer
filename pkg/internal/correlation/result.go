package correlation

import "time"

// Risk is the correlation-layer risk taxonomy. We keep it as plain
// strings (not types.RiskLevel) because the correlation report can be
// consumed standalone, without pulling the static analyzer's enum.
type Risk string

const (
	RiskInfo     Risk = "INFO"
	RiskLow      Risk = "LOW"
	RiskMedium   Risk = "MEDIUM"
	RiskHigh     Risk = "HIGH"
	RiskCritical Risk = "CRITICAL"
)

// Rank gives a numeric ordering useful for sort/comparison.
func (r Risk) Rank() int {
	switch r {
	case RiskCritical:
		return 4
	case RiskHigh:
		return 3
	case RiskMedium:
		return 2
	case RiskLow:
		return 1
	default:
		return 0
	}
}

// Likelihood mirrors the LOW/MEDIUM/HIGH model the user asked for. We
// deliberately do not say "exploit guaranteed".
type Likelihood string

const (
	LikelihoodLow    Likelihood = "LOW"
	LikelihoodMedium Likelihood = "MEDIUM"
	LikelihoodHigh   Likelihood = "HIGH"
)

// Rank gives a numeric ordering.
func (l Likelihood) Rank() int {
	switch l {
	case LikelihoodHigh:
		return 3
	case LikelihoodMedium:
		return 2
	default:
		return 1
	}
}

// LikelihoodFactors records *why* we assigned a likelihood. Each factor
// also carries a free-form reason so the report can show "we observed
// VirtualAllocEx + WriteProcessMemory at runtime" rather than just
// printing "true".
type LikelihoodFactors struct {
	Reachable         bool   `json:"reachable"`
	Controllable      bool   `json:"controllable"`
	ObservedAtRuntime bool   `json:"observed_at_runtime"`
	ReachReason       string `json:"reach_reason,omitempty"`
	ControlReason     string `json:"control_reason,omitempty"`
	RuntimeEvidence   string `json:"runtime_evidence,omitempty"`
}

// Finding is the evidence-first replacement for a single line in the
// previous "list of events" view. One Finding == one explainable risk,
// backed by a bundle of Signals.
type Finding struct {
	ID            string            `json:"id"`
	Title         string            `json:"title"`
	Category      string            `json:"category"`
	Risk          Risk              `json:"risk"`
	Likelihood    Likelihood        `json:"likelihood"`
	Factors       LikelihoodFactors `json:"factors"`
	Evidence      []*Signal         `json:"evidence"`
	Explanation   string            `json:"explanation"`
	Location      *Location         `json:"location,omitempty"`
	RelatedEvents []*Signal         `json:"related_events,omitempty"`
	Mitigations   []string          `json:"mitigations,omitempty"`

	// Workarounds: lab/research-time setup recommendations the user
	// asked us to surface ("how to verify this safely"). Examples:
	// "stand up a private HTTPS endpoint with a self-signed cert",
	// "intercept traffic with a local proxy", etc. They are NOT
	// exploitation steps.
	Workarounds []string `json:"workarounds,omitempty"`

	Tags []string `json:"tags,omitempty"`
}

// AttackChainStep is one logical phase of an attack chain. It groups
// together the signals that justify that step.
type AttackChainStep struct {
	Order       int       `json:"order"`
	Component   string    `json:"component"` // memory_analysis | network_analysis | security_audit | ...
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Timestamp   time.Time `json:"timestamp,omitempty"`
	Signals     []*Signal `json:"signals,omitempty"`
}

// AttackChain is a higher-level abstraction over Findings: a sequence of
// steps the analyst can read top-to-bottom.
type AttackChain struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	Description     string            `json:"description"`
	Risk            Risk              `json:"risk"`
	Likelihood      Likelihood        `json:"likelihood"`
	Factors         LikelihoodFactors `json:"factors"`
	InvolvedKinds   []SignalKind      `json:"involved_components"`
	ProcessKey      string            `json:"process_key,omitempty"`
	Sequence        []AttackChainStep `json:"sequence"`
	Evidence        []*Signal         `json:"evidence"`
	Explanation     string            `json:"explanation"`
	Mitigations     []string          `json:"mitigations,omitempty"`
	Workarounds     []string          `json:"workarounds,omitempty"`
	MITRETechniques []string          `json:"mitre_techniques,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
}

// TimelineEvent is a single sequence-ordered row, mostly for the
// "what happened, in order" section of the report.
type TimelineEvent struct {
	Order      int        `json:"order"`
	Timestamp  time.Time  `json:"timestamp,omitempty"`
	Kind       SignalKind `json:"kind"`
	ProcessKey string     `json:"process_key,omitempty"`
	Title      string     `json:"title"`
	Target     string     `json:"target,omitempty"`
	SignalID   string     `json:"signal_id"`
}

// Result is the full correlation post-processing output.
type Result struct {
	GeneratedAt   time.Time       `json:"generated_at"`
	SessionID     string          `json:"session_id,omitempty"`
	HasRuntime    bool            `json:"has_runtime"`
	HasStatic     bool            `json:"has_static"`
	OverallRisk   Risk            `json:"overall_risk"`
	OverallLikeli Likelihood      `json:"overall_likelihood"`
	Findings      []Finding       `json:"findings"`
	Chains        []AttackChain   `json:"attack_chains"`
	Timeline      []TimelineEvent `json:"timeline,omitempty"`
	Stats         ResultStats     `json:"stats"`
	Notes         []string        `json:"notes,omitempty"`
}

// ResultStats is a small "at a glance" summary block that the report
// can render without re-walking Findings.
type ResultStats struct {
	TotalSignals   int `json:"total_signals"`
	StaticSignals  int `json:"static_signals"`
	RuntimeSignals int `json:"runtime_signals"`
	TotalFindings  int `json:"total_findings"`
	TotalChains    int `json:"total_chains"`
	CriticalRisks  int `json:"critical_risks"`
	HighRisks      int `json:"high_risks"`
}
