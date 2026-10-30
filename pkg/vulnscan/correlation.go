package vulnscan

import (
	"net/url"
	"sort"
	"strings"
)

// CorrelationRule synthesises a higher-order meta-finding when a specific set
// of primitive findings co-exist. This is what turns a flat list of issues
// into an attack narrative (a security-intelligence engine, not a linter).
type CorrelationRule struct {
	Name     string
	Requires [][]string // each inner slice is an OR-set of ID prefixes; all outer sets must match
	Logic    func(matched map[string][]Finding) *Finding
}

// matchPrefix returns findings whose ID starts with any of the given prefixes.
func matchPrefix(findings []Finding, prefixes []string) []Finding {
	var out []Finding
	for _, f := range findings {
		for _, p := range prefixes {
			if strings.HasPrefix(f.ID, p) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// findingHost extracts the host component of a finding's URL. It is the join
// condition for correlation rules.
func findingHost(f Finding) string {
	if f.URL == "" {
		return ""
	}
	if u, err := url.Parse(f.URL); err == nil && u.Host != "" {
		return strings.ToLower(u.Host)
	}
	return ""
}

// commonHost returns the host shared by every matched group, or "" when the
// primitives sit on different hosts (or carry no URL). Joining across hosts
// is a false chain: an open redirect on host B cannot amplify an SSRF on
// host A, and a merged multi-host report must not fabricate such narratives.
func commonHost(matched map[string][]Finding) string {
	var common map[string]bool
	for _, group := range matched {
		hosts := make(map[string]bool)
		for _, f := range group {
			if h := findingHost(f); h != "" {
				hosts[h] = true
			}
		}
		if len(hosts) == 0 {
			return "" // unattributable primitives cannot be joined
		}
		if common == nil {
			common = hosts
			continue
		}
		inter := make(map[string]bool)
		for h := range common {
			if hosts[h] {
				inter[h] = true
			}
		}
		common = inter
	}
	// Deterministic pick when several hosts satisfy the join.
	keys := make([]string, 0, len(common))
	for h := range common {
		keys = append(keys, h)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

// Evaluate runs a rule against the finding set, returning a meta-finding or
// nil. All matched primitive groups must share at least one host; the rule
// logic then receives only the findings on that host.
func (r CorrelationRule) Evaluate(findings []Finding) *Finding {
	matched := make(map[string][]Finding)
	for _, orset := range r.Requires {
		hits := matchPrefix(findings, orset)
		if len(hits) == 0 {
			return nil // a required condition is missing
		}
		matched[strings.Join(orset, "|")] = hits
	}

	host := commonHost(matched)
	if host == "" {
		return nil // primitives on different hosts: no valid chain
	}
	// Narrow every group to the joined host so Sources stay accurate.
	var firstHostFinding *Finding
	for key, group := range matched {
		var scoped []Finding
		for _, f := range group {
			if findingHost(f) == host {
				if firstHostFinding == nil {
					ff := f
					firstHostFinding = &ff
				}
				scoped = append(scoped, f)
			}
		}
		if len(scoped) == 0 {
			return nil
		}
		matched[key] = scoped
	}

	f := r.Logic(matched)
	if f != nil && f.URL == "" && firstHostFinding != nil {
		f.URL = firstHostFinding.URL
	}
	return f
}

func collectSources(matched map[string][]Finding) []string {
	var ids []string
	for _, group := range matched {
		for _, f := range group {
			ids = append(ids, f.ID)
		}
	}
	return ids
}

func anyPresent(findings []Finding, prefix string) bool {
	return len(matchPrefix(findings, []string{prefix})) > 0
}

// DefaultCorrelationRules encodes the chains called out in the plan.
func DefaultCorrelationRules() []CorrelationRule {
	return []CorrelationRule{
		{
			Name:     "SSRF via Open Redirect",
			Requires: [][]string{{"WS-SSRF"}, {"WS-REDIR"}},
			Logic: func(m map[string][]Finding) *Finding {
				f := Finding{Vulnerability: Vulnerability{
					ID:          "WS-CHAIN-SSRF-REDIR",
					Name:        "Attack Chain: Open Redirect amplifies SSRF into full internal network access",
					Description: "An open redirect can be combined with the server-side request forgery finding to pivot requests through the redirector and reach internal-only services, defeating naive allowlists.",
					Severity:    SeverityCritical,
					Mitigation:  "Fix both primitives: enforce a strict outbound allowlist for server-initiated requests AND validate redirect destinations against trusted hosts.",
				}}
				f.Correlated = true
				f.Sources = collectSources(m)
				EnrichWithTaxonomy(&f)
				ApplyConfidence(&f, SigMultiPayloadTrigger, SigDifferentialOnly)
				f.Confidence = 0.85
				f.Tier = TierForScore(f.Confidence)
				return &f
			},
		},
		{
			Name:     "Account takeover via IDOR + weak JWT",
			Requires: [][]string{{"WS-IDOR"}, {"WS-JWT"}},
			Logic: func(m map[string][]Finding) *Finding {
				f := Finding{Vulnerability: Vulnerability{
					ID:          "WS-CHAIN-ATO",
					Name:        "Attack Chain: Account Takeover (IDOR + weak JWT)",
					Description: "An insecure direct object reference combined with a forgeable/weak JWT allows an attacker to mint tokens for arbitrary users and read or modify their data - a full account-takeover path.",
					Severity:    SeverityCritical,
					Mitigation:  "Enforce server-side authorization on every object access and sign JWTs with a strong, rotated secret using a fixed algorithm allowlist.",
				}}
				f.Correlated = true
				f.Sources = collectSources(m)
				EnrichWithTaxonomy(&f)
				f.Confidence = 0.8
				f.Tier = TierForScore(f.Confidence)
				return &f
			},
		},
	}
}

// Correlate runs all rules and returns synthesised meta-findings. It also
// performs defence-gap analysis: reflected XSS with no CSP present is promoted
// to Confirmed, whereas the presence of a CSP is noted as a mitigating factor.
func Correlate(findings []Finding, rules []CorrelationRule) []Finding {
	var meta []Finding
	for _, r := range rules {
		if f := r.Evaluate(findings); f != nil {
			meta = append(meta, *f)
		}
	}
	return meta
}

// ApplyDefenceGapAnalysis mutates XSS findings' confidence based on whether a
// CSP is present (missing CSP shows up as a WS-HDR-ContentSecurityPolicy
// finding). Returns the (possibly modified) slice.
func ApplyDefenceGapAnalysis(findings []Finding) []Finding {
	cspMissing := false
	for _, f := range findings {
		if strings.Contains(f.ID, "ContentSecurityPolicy") || strings.Contains(strings.ToLower(f.Name), "content security policy") {
			cspMissing = true
			break
		}
	}
	for i := range findings {
		if strings.HasPrefix(findings[i].ID, "WS-XSS") {
			if cspMissing {
				ApplyConfidence(&findings[i], SigExecutableContext)
				if findings[i].Confidence < 0.85 {
					findings[i].Confidence = 0.85
					findings[i].Tier = TierForScore(findings[i].Confidence)
				}
				findings[i].Signals = append(findings[i].Signals, "no_csp_present")
			} else {
				findings[i].Signals = append(findings[i].Signals, "csp_present_mitigating")
			}
		}
	}
	_ = anyPresent // retained as an exported-style helper for rule authors
	return findings
}
