package nsc

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// timeNow is injectable for tests of time-dependent checks
// (pin-set expiration).
var timeNow = time.Now

// maxLocateWalkEntries bounds the recursive Locate fallback: walking an
// entire extracted tree is filename-only (no reads) but still capped.
const maxLocateWalkEntries = 100_000

// Locate looks for a network_security_config.xml under common
// locations inside an extracted APK directory. Returns the absolute
// path or empty string if none was found.
func Locate(root string) string {
	candidates := []string{
		filepath.Join(root, "res", "xml"),
		filepath.Join(root, "apktool_out", "res", "xml"),
		filepath.Join(root, "app", "src", "main", "res", "xml"),
	}
	want := []string{
		"network_security_config.xml",
		"network_security_config_release.xml",
		"network_security_config_debug.xml",
		"nsc.xml",
	}
	for _, dir := range candidates {
		if p := scanLocateDir(dir, want); p != "" {
			return p
		}
	}
	// Fallback for other layouts (jadx resources/, nested modules): one
	// bounded walk, lexical order, first filename hit wins.
	visited := 0
	var found string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if found != "" {
			return fs.SkipAll
		}
		if err != nil || d.IsDir() {
			return nil
		}
		visited++
		if visited > maxLocateWalkEntries {
			return fs.SkipAll
		}
		if matchLocateName(strings.ToLower(d.Name()), want) {
			found = path
			return fs.SkipAll
		}
		return nil
	})
	return found
}

func scanLocateDir(dir string, want []string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if matchLocateName(strings.ToLower(e.Name()), want) {
			return filepath.Join(dir, e.Name())
		}
	}
	return ""
}

func matchLocateName(name string, want []string) bool {
	for _, w := range want {
		if name == w {
			return true
		}
	}
	return strings.Contains(name, "network_security") || strings.Contains(name, "networksecurity")
}

// AuditFile parses + audits a NSC XML file.
func AuditFile(target, path string) (*Report, error) {
	return AuditFileEx(target, path, ManifestSignals{})
}

// AuditFileEx is AuditFile with explicit manifest signals (debuggable flag
// and usesCleartextTraffic override). Zero ManifestSignals preserves the
// old manifest-unaware behavior.
func AuditFileEx(target, path string, ms ManifestSignals) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	r, err := parse(target, path, data)
	if err != nil {
		return nil, err
	}
	r.GeneratedAt = time.Now().UTC()
	r.Issues = collectIssues(r, ms)
	r.Score, r.Verdict = scoreReport(r)
	return r, nil
}

// AuditDir locates and audits NSC under an extracted APK directory.
// If no NSC is found, returns an "absent" report (Present=false).
// The sibling manifest is located automatically so <debug-overrides> in a
// debuggable build and manifest-level cleartext overrides are judged with
// context instead of worst-case assumptions.
func AuditDir(target string) (*Report, error) {
	return AuditDirEx(target, manifestSignalsFor(target))
}

// AuditDirEx is AuditDir with explicit manifest signals.
func AuditDirEx(target string, ms ManifestSignals) (*Report, error) {
	path := Locate(target)
	if path == "" {
		return &Report{
			GeneratedAt: time.Now().UTC(),
			Target:      target,
			Present:     false,
			Verdict:     "absent",
		}, nil
	}
	return AuditFileEx(target, path, ms)
}

// manifestSignalsFor locates the manifest next to the target and reads it.
// Missing/unparseable manifests yield zero signals (old behavior).
func manifestSignalsFor(target string) ManifestSignals {
	if p := LocateManifest(target); p != "" {
		return ReadManifestSignals(p)
	}
	return ManifestSignals{}
}

// AuditBytes audits NSC XML provided directly as a byte slice.
// Useful for unit tests and callers that already have the data.
func AuditBytes(target string, data []byte) (*Report, error) {
	return AuditBytesEx(target, data, ManifestSignals{})
}

// AuditBytesEx is AuditBytes with explicit manifest signals.
func AuditBytesEx(target string, data []byte, ms ManifestSignals) (*Report, error) {
	if len(data) == 0 {
		return nil, errors.New("empty NSC bytes")
	}
	r, err := parse(target, "", data)
	if err != nil {
		return nil, err
	}
	r.GeneratedAt = time.Now().UTC()
	r.Issues = collectIssues(r, ms)
	r.Score, r.Verdict = scoreReport(r)
	return r, nil
}

func collectIssues(r *Report, ms ManifestSignals) []Issue {
	var issues []Issue
	if r.BaseCleartextPermitted {
		issues = append(issues, Issue{
			ID:          "nsc_base_cleartext_permitted",
			Title:       "Base config permits cleartext traffic",
			Description: "<base-config cleartextTrafficPermitted=\"true\"> defeats the platform default that blocks plain HTTP since API 28.",
			Severity:    SevHigh,
			Score:       18,
		})
	}
	if r.BaseHasUserTrustAnchor {
		issues = append(issues, Issue{
			ID:          "nsc_base_user_trust_anchors",
			Title:       "Base config trusts user-installed CAs",
			Description: "<trust-anchors><certificates src=\"user\"/></trust-anchors> at the base level lets any CA the user installed sign HTTPS traffic. Common MITM enabler.",
			Severity:    SevHigh,
			Score:       18,
		})
	}
	if r.HasDebugOverrides && !ms.Debuggable {
		issues = append(issues, Issue{
			ID:          "nsc_debug_overrides_present",
			Title:       "Debug overrides shipped in production NSC",
			Description: "<debug-overrides> is meant for android:debuggable=true builds. If it ships in release, it weakens TLS.",
			Severity:    SevMedium,
			Score:       8,
		})
	}
	// Manifest-level cleartext wins over the NSC: a hardened config next to
	// usesCleartextTraffic="true" is wide open, which the NSC alone cannot see.
	if ms.CleartextPermitted != nil && *ms.CleartextPermitted && !r.BaseCleartextPermitted {
		issues = append(issues, Issue{
			ID:          "nsc_manifest_cleartext_override",
			Title:       "Manifest overrides NSC cleartext policy",
			Description: "android:usesCleartextTraffic=\"true\" permits plain HTTP app-wide regardless of the network security config.",
			Severity:    SevHigh,
			Score:       18,
		})
	}
	if r.HasDebugOverrides && r.DebugOverridesUserTrust {
		issues = append(issues, Issue{
			ID:          "nsc_debug_overrides_user_trust",
			Title:       "Debug overrides trust user CAs",
			Description: "Debug overrides include user trust anchors — fine for local development, but if the app is also debuggable in release this becomes a MITM vector.",
			Severity:    SevLow,
			Score:       3,
		})
	}
	for _, dom := range r.Domains {
		if dom.CleartextPermitted != nil && *dom.CleartextPermitted {
			issues = append(issues, Issue{
				ID:          "nsc_domain_cleartext_permitted",
				Title:       "Domain config permits cleartext traffic",
				Description: "Domain whitelist for cleartext: " + strings.Join(dom.Hosts, ", "),
				Severity:    SevMedium,
				Score:       8,
				Domain:      strings.Join(dom.Hosts, ","),
			})
		}
		if dom.HasUserTrustAnchor && len(dom.Hosts) > 0 {
			issues = append(issues, Issue{
				ID:          "nsc_domain_user_trust",
				Title:       "Domain trusts user-installed CAs",
				Description: "User CAs accepted for domains: " + strings.Join(dom.Hosts, ", "),
				Severity:    SevHigh,
				Score:       12,
				Domain:      strings.Join(dom.Hosts, ","),
			})
		}
		if dom.HasCertificatePinning {
			issues = append(issues, Issue{
				ID:          "nsc_domain_pinning_present",
				Title:       "Certificate pinning configured",
				Description: "Pinning configured for: " + strings.Join(dom.Hosts, ", "),
				Severity:    SevSecure,
				Score:       -8,
				Domain:      strings.Join(dom.Hosts, ","),
			})
			issues = append(issues, pinSetIssues(dom)...)
		}
		if len(dom.Hosts) == 0 {
			issues = append(issues, Issue{
				ID:          "nsc_domain_no_hosts",
				Title:       "Domain config with no <domain> entries",
				Description: "A <domain-config> without any non-empty <domain> hosts never matches traffic; it is dead configuration and may hide intent.",
				Severity:    SevInfo,
				Score:       1,
			})
		}
		if dom.OverridePinsForLocal {
			issues = append(issues, Issue{
				ID:          "nsc_domain_override_pins",
				Title:       "overridePins=\"true\" on domain anchor",
				Description: "Custom anchor with overridePins on " + strings.Join(dom.Hosts, ", ") + " — bypasses pinning.",
				Severity:    SevHigh,
				Score:       12,
				Domain:      strings.Join(dom.Hosts, ","),
			})
		}
	}

	// Duplicate hosts across domain-configs: resolution order is
	// unspecified, so effective policy becomes unpredictable.
	seen := map[string]bool{}
	dupReported := map[string]bool{}
	for _, dom := range r.Domains {
		for _, h := range dom.Hosts {
			key := strings.ToLower(h)
			if seen[key] && !dupReported[key] {
				dupReported[key] = true
				issues = append(issues, Issue{
					ID:          "nsc_duplicate_domain",
					Title:       "Domain listed in multiple domain-configs",
					Description: "Host \"" + h + "\" appears in more than one <domain-config>; which config wins is unspecified, so the effective TLS policy is unpredictable.",
					Severity:    SevLow,
					Score:       3,
					Domain:      h,
				})
			}
			seen[key] = true
		}
	}

	// "Encourage hardening" hints
	if !r.BaseCleartextPermitted && !r.BaseHasUserTrustAnchor && r.Present {
		issues = append(issues, Issue{
			ID:          "nsc_base_hardened",
			Title:       "Base config rejects cleartext + user CAs",
			Description: "Default-deny base config — good baseline against MITM.",
			Severity:    SevSecure,
			Score:       -6,
		})
	}
	sort.SliceStable(issues, func(i, j int) bool {
		return severityRank(issues[i].Severity) > severityRank(issues[j].Severity)
	})
	return issues
}

// pinSetIssues audits the quality of a domain's <pin-set>: expiration
// hygiene, backup pin presence, and digest algorithm support.
func pinSetIssues(dom Domain) []Issue {
	var issues []Issue
	hosts := strings.Join(dom.Hosts, ", ")
	domainKey := strings.Join(dom.Hosts, ",")

	if dom.PinCount == 1 {
		issues = append(issues, Issue{
			ID:          "nsc_pin_set_no_backup",
			Title:       "Pin-set has no backup pin",
			Description: "Only one <pin> for " + hosts + ". Android docs require a backup pin; a single pin risks bricking connectivity on certificate rotation.",
			Severity:    SevLow,
			Score:       3,
			Domain:      domainKey,
		})
	}

	for _, d := range dom.PinDigests {
		if !strings.EqualFold(d, "SHA-256") {
			issues = append(issues, Issue{
				ID:          "nsc_pin_unknown_digest",
				Title:       "Pin uses unsupported digest algorithm",
				Description: "Digest \"" + d + "\" on " + hosts + " — Android only supports SHA-256; other digests are ignored, silently weakening pinning.",
				Severity:    SevMedium,
				Score:       6,
				Domain:      domainKey,
			})
			break
		}
	}

	if dom.PinExpirationISO != "" {
		exp, err := time.Parse("2006-01-02", dom.PinExpirationISO)
		switch {
		case err != nil:
			issues = append(issues, Issue{
				ID:          "nsc_pin_set_bad_expiration",
				Title:       "Pin-set expiration is not a valid date",
				Description: "expiration=\"" + dom.PinExpirationISO + "\" on " + hosts + " does not parse as yyyy-MM-dd.",
				Severity:    SevLow,
				Score:       2,
				Domain:      domainKey,
			})
		case exp.Before(timeNow().UTC().Truncate(24 * time.Hour)):
			issues = append(issues, Issue{
				ID:          "nsc_pin_set_expired",
				Title:       "Pin-set expiration date has passed",
				Description: "Pin-set for " + hosts + " expired on " + dom.PinExpirationISO + ". Android silently DISABLES pinning after expiration, so these hosts are no longer pinned.",
				Severity:    SevHigh,
				Score:       12,
				Domain:      domainKey,
			})
		case exp.Before(timeNow().UTC().Add(90 * 24 * time.Hour)):
			issues = append(issues, Issue{
				ID:          "nsc_pin_set_expires_soon",
				Title:       "Pin-set expires within 90 days",
				Description: "Pin-set for " + hosts + " expires on " + dom.PinExpirationISO + "; rotate pins before then or pinning turns off silently.",
				Severity:    SevLow,
				Score:       2,
				Domain:      domainKey,
			})
		}
	}
	return issues
}

func severityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	case SevSecure:
		return 0
	}
	return 0
}

func scoreReport(r *Report) (int, string) {
	if !r.Present {
		return 0, "absent"
	}
	score := 0
	for _, is := range r.Issues {
		score += is.Score
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	switch {
	case score >= 50:
		return score, "dangerous"
	case score >= 20:
		return score, "weak"
	case score >= 5:
		return score, "ok"
	default:
		return score, "hardened"
	}
}
