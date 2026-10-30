// Package dataflow implements a bounded, summary-based Smali taint analysis.
package dataflow

type Label uint64

const (
	LabelNone      Label = 0
	LabelUserInput Label = 1 << iota
	LabelIntent
	LabelNetwork
	LabelFile
	LabelDatabase
	LabelLocation
	LabelCredential
	LabelPII
)

type Sanitizer uint8

const (
	SanitizerNone Sanitizer = 0
	SanitizerSQL  Sanitizer = 1 << iota
	SanitizerHTML
	SanitizerPath    // reserved for actual containment proofs, NOT normalizers/encoders
	SanitizerNumeric // value reduced to a primitive; labels must be dropped
)

type Config struct {
	MaxMethods           int
	MaxIterations        int
	MaxFindings          int
	MaxSliceSteps        int // whole-run backward-state budget; <=0 uses default
	MaxSliceDepth        int // recursion budget; <=0 uses default
	MaxSliceStepsPerSink int // fairness budget; a single sink cannot consume the entire run
}

func DefaultConfig() Config {
	return Config{MaxMethods: 200000, MaxIterations: 20, MaxFindings: 2000, MaxSliceSteps: 500000, MaxSliceDepth: 48, MaxSliceStepsPerSink: 4096}
}

type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Method string `json:"method"`
}

type Step struct {
	Method string `json:"method"`
	Type   string `json:"type"`
	Line   int    `json:"line,omitempty"`
	File   string `json:"file,omitempty"`
}

type Finding struct {
	Source       string   `json:"source"`
	Sink         string   `json:"sink"`
	Category     string   `json:"category"`
	ExploitChain string   `json:"exploit_chain,omitempty"`
	Label        Label    `json:"label"`
	Severity     string   `json:"severity"`
	Confidence   float64  `json:"confidence"`
	Location     Location `json:"location"`
	Path         []Step   `json:"path"`
}

// exploitChainName gives a data-flow finding an actionable, stable attack
// narrative. Unlike the legacy global correlations, it is emitted only after
// a concrete source-to-sink path has been reconstructed.
func exploitChainName(category string, labels Label) string {
	entry := "untrusted_input"
	if labels&LabelIntent != 0 {
		entry = "ipc_or_deep_link"
	} else if labels&LabelNetwork != 0 {
		entry = "network_response"
	} else if labels&LabelFile != 0 {
		entry = "untrusted_file"
	}
	switch category {
	case "dynamic_code_loading":
		return entry + "_to_code_execution"
	case "intent_redirection":
		return entry + "_to_component_hijack"
	case "webview_injection", "javascript_injection":
		return entry + "_to_webview_execution"
	case "path_traversal":
		return entry + "_to_filesystem_access"
	case "pending_intent_injection":
		return entry + "_to_pending_intent"
	case "webview_untrusted_origin":
		return entry + "_to_webview_origin"
	case "insecure_deserialization":
		return entry + "_to_deserialization"
	case "command_injection":
		return entry + "_to_command_execution"
	case "sql_injection":
		return entry + "_to_database_query"
	case "ssrf":
		return entry + "_to_server_side_request"
	}
	return "source_to_" + category
}

type Stats struct {
	IncompatibleCastFlowsPruned int  `json:"incompatible_cast_flows_pruned"`
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
}

type Result struct {
	Findings     []Finding `json:"findings"`
	Observations []Finding `json:"observations,omitempty"`
	Stats        Stats     `json:"stats"`
}

type SummaryCache interface {
	Get(signature string, body []string) ([]byte, bool)
	Put(signature string, body []string, data []byte)
}

type fact struct {
	Labels    Label            `json:"labels"`
	Params    uint64           `json:"params"`
	Sanitized Sanitizer        `json:"sanitized"`
	Sources   map[Label]string `json:"sources,omitempty"`
	Depth     int              `json:"depth"`
	ViaField  bool             `json:"via_field,omitempty"`
}

type sinkFlow struct {
	Sink      string    `json:"sink"`
	Category  string    `json:"category"`
	Severity  string    `json:"severity"`
	Sanitizer Sanitizer `json:"sanitizer,omitempty"`
	Fact      fact      `json:"fact"`
	Location  Location  `json:"location"`
}

type summary struct {
	Signature   string          `json:"signature"`
	Return      fact            `json:"return"`
	FieldWrites map[string]fact `json:"field_writes,omitempty"`
	Sinks       []sinkFlow      `json:"sinks,omitempty"`
}
