// Package nsc parses and audits Android Network Security
// Configuration files (`res/xml/network_security_config.xml`).
//
// References:
//   - https://developer.android.com/training/articles/security-config
//   - OWASP MSTG MASVS-NETWORK-1
//   - MobSF mobsf/StaticAnalyzer/views/android/network_security.py
//
// We re-implement the audit in Go on top of encoding/xml so the
// analyzer doesn't need to spawn Python for this check.
package nsc

import "time"

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
	SevSecure   Severity = "secure" // hardening signal, NOT a problem
)

// Issue is a single audit finding.
type Issue struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Score       int      `json:"score"`
	Domain      string   `json:"domain,omitempty"`
}

// Domain captures one parsed <domain-config>.
type Domain struct {
	Hosts                 []string `json:"hosts,omitempty"`
	IncludeSubdomains     bool     `json:"include_subdomains"`
	CleartextPermitted    *bool    `json:"cleartext_traffic_permitted,omitempty"`
	HasUserTrustAnchor    bool     `json:"has_user_trust_anchor"`
	HasCustomTrustAnchor  bool     `json:"has_custom_trust_anchor"`
	HasSystemTrustAnchor  bool     `json:"has_system_trust_anchor"`
	HasCertificatePinning bool     `json:"has_certificate_pinning"`
	PinExpirationISO      string   `json:"pin_expiration,omitempty"`
	PinCount              int      `json:"pin_count,omitempty"`
	PinDigests            []string `json:"pin_digests,omitempty"`
	HasDebugOverrides     bool     `json:"has_debug_overrides"`
	OverridePinsForLocal  bool     `json:"override_pins_local,omitempty"`
}

// Report is the NSC audit output.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Target      string    `json:"target"`
	Source      string    `json:"source,omitempty"` // path to the NSC XML

	Present                   bool     `json:"present"`
	BaseCleartextPermitted    bool     `json:"base_cleartext_permitted"`
	BaseHasUserTrustAnchor    bool     `json:"base_has_user_trust_anchor"`
	BaseHasCustomTrustAnchor  bool     `json:"base_has_custom_trust_anchor"`
	BaseHasCertificatePinning bool     `json:"base_has_certificate_pinning"`
	HasDebugOverrides         bool     `json:"has_debug_overrides"`
	DebugOverridesUserTrust   bool     `json:"debug_overrides_user_trust,omitempty"`
	DomainsCleartextPermitted []string `json:"domains_cleartext_permitted,omitempty"`
	DomainsWithPinning        []string `json:"domains_with_pinning,omitempty"`
	DomainsWithUserTrust      []string `json:"domains_with_user_trust,omitempty"`

	Domains []Domain `json:"domains,omitempty"`
	Issues  []Issue  `json:"issues,omitempty"`

	// Score is 0..100; higher = more permissive / weaker.
	// "secure" findings reduce the score (down to 0).
	Score   int    `json:"score"`
	Verdict string `json:"verdict,omitempty"` // "hardened" | "ok" | "weak" | "dangerous" | "absent"
}
