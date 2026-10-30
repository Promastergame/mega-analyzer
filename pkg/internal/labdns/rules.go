package labdns

import (
	"strings"
	"sync"
)

// SinkholeRuleConfig is the JSON-serialisable rule specification.
type SinkholeRuleConfig struct {
	Pattern string `json:"pattern"`          // domain or *.domain
	Target  string `json:"target,omitempty"` // IP to resolve to; default 127.0.0.1
	Name    string `json:"name,omitempty"`   // optional human name
}

// SinkholeRules is the runtime rule engine that decides whether a DNS
// query should be intercepted.
type SinkholeRules struct {
	mu        sync.RWMutex
	exact     map[string]sinkholeEntry // lowercase fqdn → entry
	wildcards []wildcardEntry
	blockAll  bool
	sinkIP    string // default sinkhole IP
}

type sinkholeEntry struct {
	target string
	name   string
}

type wildcardEntry struct {
	suffix string // e.g. ".tracker.io"
	target string
	name   string
}

// DefaultSinkholeIP is the default IP returned for sinkholed domains.
const DefaultSinkholeIP = "127.0.0.1"

// NewSinkholeRules creates a rule engine.
func NewSinkholeRules(blockAll bool, rules []SinkholeRuleConfig) *SinkholeRules {
	sr := &SinkholeRules{
		exact:    make(map[string]sinkholeEntry, len(rules)),
		blockAll: blockAll,
		sinkIP:   DefaultSinkholeIP,
	}
	for _, r := range rules {
		sr.AddRule(r)
	}
	return sr
}

// NewSinkholeRulesWithSafetyNet creates rules that additionally block
// Google SafetyNet / Play Protect attestation endpoints.
func NewSinkholeRulesWithSafetyNet(blockAll bool, rules []SinkholeRuleConfig) *SinkholeRules {
	safetyNet := []SinkholeRuleConfig{
		{Pattern: "play.googleapis.com", Name: "safetynet-play"},
		{Pattern: "www.googleapis.com", Name: "safetynet-www"},
		{Pattern: "android.googleapis.com", Name: "safetynet-android"},
		{Pattern: "firebaseinstallations.googleapis.com", Name: "firebase-installations"},
		{Pattern: "android.clients.google.com", Name: "google-checkin"},
		{Pattern: "play.google.com", Name: "google-play"},
		{Pattern: "*.googleusercontent.com", Name: "google-user-content"},
		{Pattern: "connectivitycheck.gstatic.com", Name: "connectivity-check"},
		{Pattern: "*.gstatic.com", Name: "gstatic"},
		{Pattern: "mtalk.google.com", Name: "gcm-push"},
		{Pattern: "alt1-mtalk.google.com", Name: "gcm-push-alt1"},
		{Pattern: "alt2-mtalk.google.com", Name: "gcm-push-alt2"},
	}
	combined := make([]SinkholeRuleConfig, 0, len(rules)+len(safetyNet))
	combined = append(combined, safetyNet...)
	combined = append(combined, rules...)
	return NewSinkholeRules(blockAll, combined)
}

// AddRule registers a new sinkhole rule at runtime.
func (sr *SinkholeRules) AddRule(r SinkholeRuleConfig) {
	target := r.Target

	pattern := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Pattern)), ".")

	sr.mu.Lock()
	defer sr.mu.Unlock()

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".tracker.io"
		sr.wildcards = append(sr.wildcards, wildcardEntry{
			suffix: suffix,
			target: target,
			name:   r.Name,
		})
		return
	}

	sr.exact[pattern] = sinkholeEntry{
		target: target,
		name:   r.Name,
	}
}

// matchResult is the outcome of a rule evaluation.
type matchResult struct {
	Matched  bool
	Target   string
	RuleName string
}

// Match checks a query name against all rules.
// The query name must be a lower-case FQDN without trailing dot.
func (sr *SinkholeRules) Match(queryName string) matchResult {
	name := strings.TrimSuffix(strings.ToLower(queryName), ".")

	sr.mu.RLock()
	defer sr.mu.RUnlock()

	if sr.blockAll {
		return matchResult{Matched: true, Target: sr.sinkIP, RuleName: "block-all"}
	}

	if entry, ok := sr.exact[name]; ok {
		target := entry.target
		if target == "" {
			target = sr.sinkIP
		}
		return matchResult{Matched: true, Target: target, RuleName: entry.name}
	}

	for _, wc := range sr.wildcards {
		// Project semantics: *.example.com covers subdomains and the apex example.com.
		if strings.HasSuffix(name, wc.suffix) || name == strings.TrimPrefix(wc.suffix, ".") {
			target := wc.target
			if target == "" {
				target = sr.sinkIP
			}
			return matchResult{Matched: true, Target: target, RuleName: wc.name}
		}
	}

	return matchResult{}
}

// BlockAll returns whether the engine is in full-isolation mode.
func (sr *SinkholeRules) BlockAll() bool {
	sr.mu.RLock()
	defer sr.mu.RUnlock()
	return sr.blockAll
}

// SetBlockAll enables or disables global blocking at runtime.
func (sr *SinkholeRules) SetBlockAll(v bool) {
	sr.mu.Lock()
	sr.blockAll = v
	sr.mu.Unlock()
}

// SetSinkIP sets the default target IP returned for sinkholed queries.
func (sr *SinkholeRules) SetSinkIP(ip string) {
	sr.mu.Lock()
	sr.sinkIP = ip
	sr.mu.Unlock()
}
