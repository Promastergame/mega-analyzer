package ml

import "strings"

// AnalysisScope controls what the analyzer may produce. Scopes are separate
// from PatchMode: mode describes intent, scope describes the allowed output.
type AnalysisScope string

const (
	ScopeAudit       AnalysisScope = "audit"
	ScopeDefensive   AnalysisScope = "defensive"
	ScopeTestFixture AnalysisScope = "test_fixture"
)

type ReviewPolicy struct {
	Scope          AnalysisScope `json:"scope"`
	ReviewRequired bool          `json:"review_required"`
	AllowApply     bool          `json:"allow_apply"`
	DiagnosticOnly bool          `json:"diagnostic_only"`
	Reasons        []string      `json:"reasons,omitempty"`
}

func DefaultReviewPolicy(scope AnalysisScope) ReviewPolicy {
	policy := ReviewPolicy{Scope: scope, ReviewRequired: true, DiagnosticOnly: true}
	switch scope {
	case ScopeDefensive:
		policy.AllowApply = false
		policy.Reasons = []string{"defensive changes require explicit review"}
	case ScopeTestFixture:
		policy.AllowApply = false
		policy.Reasons = []string{"test fixture output is isolated from production apply"}
	default:
		policy.AllowApply = false
		policy.Reasons = []string{"audit scope is diagnostic-only"}
	}
	return policy
}

type ServerDependency string

const (
	ServerDependencyUnknown  ServerDependency = "unknown"
	ServerDependencyLocal    ServerDependency = "local_only"
	ServerDependencyCached   ServerDependency = "cached_server_state"
	ServerDependencyOnline   ServerDependency = "online_validation"
	ServerDependencySigned   ServerDependency = "signed_response"
	ServerDependencyHardware ServerDependency = "hardware_backed"
)

type RuntimeDiagnostic struct {
	Kind        string   `json:"kind"`
	Method      string   `json:"method,omitempty"`
	SDK         string   `json:"sdk,omitempty"`
	Observation string   `json:"observation"`
	Evidence    []string `json:"evidence,omitempty"`
	Severity    string   `json:"severity"`
}

type CallChainTrace struct {
	Root          string           `json:"root"`
	Steps         []string         `json:"steps"`
	DecisionPoint string           `json:"decision_point,omitempty"`
	SDK           string           `json:"sdk,omitempty"`
	Dependency    ServerDependency `json:"dependency"`
	Confidence    float64          `json:"confidence"`
}

type DefensiveRecommendation struct {
	ID         string   `json:"id"`
	Category   string   `json:"category"`
	Title      string   `json:"title"`
	Why        string   `json:"why"`
	Evidence   []string `json:"evidence,omitempty"`
	Priority   string   `json:"priority"`
	ReviewOnly bool     `json:"review_only"`
}

// ClassifyServerDependency uses conservative evidence. It never claims that
// a local method can override a server or hardware decision.
func ClassifyServerDependency(mi *MethodInfo) ServerDependency {
	if mi == nil {
		return ServerDependencyUnknown
	}
	text := strings.ToLower(strings.Join(append(append([]string{mi.Name, mi.FullSignature}, mi.SecurityCalls...), mi.StringConsts...), " "))
	for _, token := range []string{"attestation", "strongbox", "hardwarebacked", "tee"} {
		if strings.Contains(text, token) {
			return ServerDependencyHardware
		}
	}
	for _, token := range []string{"signature", "receipt", "jws", "jwt", "hmac", "integritytoken"} {
		if strings.Contains(text, token) {
			return ServerDependencySigned
		}
	}
	for _, token := range []string{"okhttp", "retrofit", "httpurlconnection", "querypurchase", "token", "session", "auth"} {
		if strings.Contains(text, token) || mi.HasSecurityAPI {
			return ServerDependencyOnline
		}
	}
	for _, token := range []string{"preferences", "cache", "remoteconfig", "entitlement"} {
		if strings.Contains(text, token) {
			return ServerDependencyCached
		}
	}
	return ServerDependencyLocal
}

func BuildDefensiveRecommendations(mi *MethodInfo) []DefensiveRecommendation {
	if mi == nil {
		return nil
	}
	text := strings.ToLower(strings.Join(append(append([]string{mi.Name, mi.FullSignature}, mi.SecurityCalls...), mi.StringConsts...), " "))
	var out []DefensiveRecommendation
	add := func(id, category, title, why, priority string) {
		out = append(out, DefensiveRecommendation{ID: id, Category: category, Title: title, Why: why, Priority: priority, ReviewOnly: true})
	}
	if strings.Contains(text, "http://") || strings.Contains(text, "cleartext") {
		add("network_tls", "network", "Require TLS", "Cleartext transport can expose credentials and response data", "high")
	}
	if strings.Contains(text, "javascriptinterface") || strings.Contains(text, "setjavascriptenabled") {
		add("webview_bridge", "webview", "Review WebView bridge exposure", "JavaScript bridges can expose native functionality to untrusted content", "high")
	}
	if strings.Contains(text, "dexclassloader") || strings.Contains(text, "inmemorydexclassloader") {
		add("dynamic_code", "code_loading", "Review dynamic code loading", "Runtime-loaded code expands the executable attack surface", "high")
	}
	if strings.Contains(text, "md5") || strings.Contains(text, "sha1") || strings.Contains(text, "des") {
		add("weak_crypto", "cryptography", "Replace weak cryptography", "Legacy primitives are unsuitable for integrity or secrecy", "medium")
	}
	if strings.Contains(text, "sharedpreferences") && strings.Contains(text, "token") {
		add("secret_storage", "storage", "Review secret storage", "Tokens in ordinary preferences lack strong confidentiality and integrity", "high")
	}
	return out
}
