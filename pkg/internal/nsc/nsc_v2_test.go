package nsc

import (
	"strings"
	"testing"
	"time"
)

func withFakeNow(t *testing.T, now time.Time) {
	t.Helper()
	old := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = old })
}

func TestPinSet_Expired(t *testing.T) {
	withFakeNow(t, time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	xml := []byte(`
<network-security-config>
  <domain-config>
    <domain>api.example.com</domain>
    <pin-set expiration="2026-06-01">
      <pin digest="SHA-256">aaaa</pin>
      <pin digest="SHA-256">bbbb</pin>
    </pin-set>
  </domain-config>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	mustHaveIssue(t, r, "nsc_pin_set_expired")
}

func TestPinSet_ExpiresSoon(t *testing.T) {
	withFakeNow(t, time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
	xml := []byte(`
<network-security-config>
  <domain-config>
    <domain>api.example.com</domain>
    <pin-set expiration="2026-06-01">
      <pin digest="SHA-256">aaaa</pin>
      <pin digest="SHA-256">bbbb</pin>
    </pin-set>
  </domain-config>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	mustHaveIssue(t, r, "nsc_pin_set_expires_soon")
}

func TestPinSet_BadExpiration(t *testing.T) {
	xml := []byte(`
<network-security-config>
  <domain-config>
    <domain>api.example.com</domain>
    <pin-set expiration="not-a-date">
      <pin digest="SHA-256">aaaa</pin>
      <pin digest="SHA-256">bbbb</pin>
    </pin-set>
  </domain-config>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	mustHaveIssue(t, r, "nsc_pin_set_bad_expiration")
}

func TestPinSet_NoBackupPin(t *testing.T) {
	xml := []byte(`
<network-security-config>
  <domain-config>
    <domain>api.example.com</domain>
    <pin-set>
      <pin digest="SHA-256">aaaa</pin>
    </pin-set>
  </domain-config>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	mustHaveIssue(t, r, "nsc_pin_set_no_backup")
}

func TestPinSet_UnknownDigest(t *testing.T) {
	xml := []byte(`
<network-security-config>
  <domain-config>
    <domain>api.example.com</domain>
    <pin-set>
      <pin digest="SHA-1">aaaa</pin>
      <pin digest="SHA-256">bbbb</pin>
    </pin-set>
  </domain-config>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	mustHaveIssue(t, r, "nsc_pin_unknown_digest")
}

func TestDomainConfig_NoHosts(t *testing.T) {
	xml := []byte(`
<network-security-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain>   </domain>
  </domain-config>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	mustHaveIssue(t, r, "nsc_domain_no_hosts")
}

func TestDuplicateDomains(t *testing.T) {
	xml := []byte(`
<network-security-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain>API.example.com</domain>
  </domain-config>
  <domain-config cleartextTrafficPermitted="false">
    <domain>api.example.com</domain>
  </domain-config>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	mustHaveIssue(t, r, "nsc_duplicate_domain")
}

func TestParse_PinMetadata(t *testing.T) {
	xml := []byte(`
<network-security-config>
  <domain-config>
    <domain>api.example.com</domain>
    <pin-set expiration=" 2030-01-01 ">
      <pin digest=" SHA-256 ">aaaa</pin>
      <pin digest="SHA-256">bbbb</pin>
    </pin-set>
  </domain-config>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(r.Domains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(r.Domains))
	}
	d := r.Domains[0]
	if d.PinCount != 2 {
		t.Errorf("PinCount = %d, want 2", d.PinCount)
	}
	if d.PinExpirationISO != "2030-01-01" {
		t.Errorf("PinExpirationISO = %q, want trimmed date", d.PinExpirationISO)
	}
	if len(d.PinDigests) != 2 || d.PinDigests[0] != "SHA-256" {
		t.Errorf("PinDigests = %v", d.PinDigests)
	}
}

func TestRenderJSON(t *testing.T) {
	xml := []byte(`<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>`)
	r, err := AuditBytes("jsonapp", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	b, err := RenderJSON(r)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "\"target\": \"jsonapp\"") {
		t.Errorf("JSON missing target: %s", s)
	}
	if !strings.Contains(s, "nsc_base_cleartext_permitted") {
		t.Errorf("JSON missing issue id: %s", s)
	}
}

func TestHardenedStillHardenedWithExpiredPins(t *testing.T) {
	// Regression guard: secure signals should keep clamping the score
	// at 0 for otherwise hardened configs even when pins expired.
	withFakeNow(t, time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC))
	xml := []byte(`
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system" /></trust-anchors>
  </base-config>
  <domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set expiration="2026-01-01">
      <pin digest="SHA-256">aaaa</pin>
      <pin digest="SHA-256">bbbb</pin>
    </pin-set>
  </domain-config>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	mustHaveIssue(t, r, "nsc_pin_set_expired")
	mustHaveIssue(t, r, "nsc_base_hardened")
}
