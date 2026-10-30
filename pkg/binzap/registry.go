package binzap

import (
	"fmt"
	"sort"
	"sync"
)

// RuleMetadata carries the production metadata attached to every rule (INC8):
// CWE mapping, baseline severity/confidence, remediation, exploitability and
// the pack it belongs to. Metadata is data, not global mutable state, and is
// supplied at registration time (dependency injection friendly).
type RuleMetadata struct {
	ID             string
	Name           string
	Category       string
	CWE            string
	Severity       Severity
	Confidence     Confidence
	Remediation    string
	Exploitability string
	Pack           string
	Standards      []string
}

// RuleEntry pairs a Rule implementation with its metadata and enabled state.
type RuleEntry struct {
	Rule    Rule
	Meta    RuleMetadata
	Enabled bool
}

// Registry is an explicit, injectable collection of rules. It replaces
// import-time global registration: callers build a registry, register packs,
// apply a profile/overrides, then run it.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*RuleEntry
	order   []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]*RuleEntry{}}
}

// Register adds a rule with metadata. Duplicate IDs are rejected so packs can
// be validated deterministically (supports the regression harness).
func (r *Registry) Register(rule Rule, meta RuleMetadata) error {
	if rule == nil {
		return fmt.Errorf("nil rule")
	}
	id := rule.ID()
	if meta.ID == "" {
		meta.ID = id
	}
	if meta.ID != id {
		return fmt.Errorf("metadata ID %q does not match rule ID %q", meta.ID, id)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[id]; exists {
		return fmt.Errorf("rule %q already registered", id)
	}
	r.entries[id] = &RuleEntry{Rule: rule, Meta: meta, Enabled: true}
	r.order = append(r.order, id)
	return nil
}

// MustRegister panics on error; convenient for building the default registry.
func (r *Registry) MustRegister(rule Rule, meta RuleMetadata) {
	if err := r.Register(rule, meta); err != nil {
		panic(err)
	}
}

// Get returns the entry for an ID.
func (r *Registry) Get(id string) (*RuleEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[id]
	return e, ok
}

// All returns entries in registration order.
func (r *Registry) All() []*RuleEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*RuleEntry, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.entries[id])
	}
	return out
}

// EnabledRules returns the enabled rules in registration order.
func (r *Registry) EnabledRules() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Rule
	for _, id := range r.order {
		if e := r.entries[id]; e.Enabled {
			out = append(out, e.Rule)
		}
	}
	return out
}

// MetadataByID exposes metadata for enrichment of raw findings.
func (r *Registry) MetadataByID() map[string]RuleMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]RuleMetadata, len(r.entries))
	for id, e := range r.entries {
		out[id] = e.Meta
	}
	return out
}

// Override adjusts a single rule's severity and/or enabled state.
type Override struct {
	Severity *Severity
	Enabled  *bool
}

// Apply applies an override to a rule by ID.
func (r *Registry) ApplyOverride(id string, o Override) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[id]
	if !ok {
		return fmt.Errorf("rule %q not found", id)
	}
	if o.Severity != nil {
		e.Meta.Severity = *o.Severity
	}
	if o.Enabled != nil {
		e.Enabled = *o.Enabled
	}
	return nil
}

// Profile selects a subset of rules to run (INC8: profiles + packs).
type Profile struct {
	Name         string
	Packs        []string // if non-empty, only these packs are enabled
	DisableRules []string
	EnableRules  []string
	MinSeverity  Severity // if set, rules below this baseline severity are disabled
}

// ApplyProfile enables/disables rules according to the profile.
func (r *Registry) ApplyProfile(p Profile) {
	packSet := map[string]bool{}
	for _, pk := range p.Packs {
		packSet[pk] = true
	}
	disabled := map[string]bool{}
	for _, id := range p.DisableRules {
		disabled[id] = true
	}
	enabled := map[string]bool{}
	for _, id := range p.EnableRules {
		enabled[id] = true
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		on := true
		if len(packSet) > 0 && !packSet[e.Meta.Pack] {
			on = false
		}
		if p.MinSeverity != "" && severityRank(e.Meta.Severity) < severityRank(p.MinSeverity) {
			on = false
		}
		if disabled[e.Meta.ID] {
			on = false
		}
		if enabled[e.Meta.ID] {
			on = true
		}
		e.Enabled = on
	}
}

// Packs returns the sorted set of distinct pack names.
func (r *Registry) Packs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	set := map[string]bool{}
	for _, e := range r.entries {
		set[e.Meta.Pack] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// passiveRuleMeta maps the built-in passive rules to CWE + remediation.
var passiveRuleMeta = map[string]RuleMetadata{
	"BZ-PASS-001": {Category: "crypto", CWE: "CWE-327", Pack: "core", Remediation: "Use AES-GCM / SHA-256+; drop MD5/DES/RC4/ECB."},
	"BZ-PASS-002": {Category: "anti-analysis", CWE: "CWE-693", Pack: "malware", Remediation: "Investigate emulator/debugger evasion; not a defect per se but a malware signal."},
	"BZ-PASS-003": {Category: "cmdi", CWE: "CWE-78", Pack: "core", Remediation: "Avoid Runtime.exec/su; validate any command input."},
	"BZ-PASS-004": {Category: "secrets", CWE: "CWE-798", Pack: "core", Remediation: "Move secrets out of code into secure storage / build-time injection."},
	"BZ-PASS-005": {Category: "reflection", CWE: "CWE-470", Pack: "core", Remediation: "Avoid resolving class/method names from untrusted input."},
	"BZ-PASS-006": {Category: "deser", CWE: "CWE-502", Pack: "core", Remediation: "Do not deserialize untrusted data with Java serialization."},
	"BZ-PASS-007": {Category: "path", CWE: "CWE-22", Pack: "core", Remediation: "Canonicalize and confine file paths to an allowed base."},
	"BZ-PASS-008": {Category: "privacy", CWE: "CWE-200", Pack: "mobile", Remediation: "Do not harvest clipboard contents; request minimal data."},
	"BZ-PASS-009": {Category: "backdoor", CWE: "CWE-489", Pack: "core", Remediation: "Remove debug backdoors and hidden developer switches from release builds."},
	"BZ-PASS-010": {Category: "config", CWE: "CWE-319", Pack: "core", Remediation: "Avoid hardcoded/cleartext endpoints; use HTTPS + configuration."},
}

// DefaultRegistry builds a registry from the built-in passive rules plus the
// mobile and malware packs. Dynamic (user) rules can be added by the caller.
func DefaultRegistry() *Registry {
	reg := NewRegistry()
	for _, rule := range PassiveRules {
		meta := passiveRuleMeta[rule.ID()]
		meta.ID = rule.ID()
		meta.Name = rule.Name()
		meta.Severity = rule.Severity()
		if meta.Confidence == "" {
			meta.Confidence = ConfidenceMedium
		}
		if meta.Pack == "" {
			meta.Pack = "core"
		}
		reg.MustRegister(rule, meta)
	}
	for _, e := range MobileRuleEntries() {
		reg.MustRegister(e.Rule, e.Meta)
	}
	for _, e := range MalwareRuleEntries() {
		reg.MustRegister(e.Rule, e.Meta)
	}
	return reg
}
