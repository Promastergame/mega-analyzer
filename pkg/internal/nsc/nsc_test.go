package nsc

import (
	"strings"
	"testing"
)

func mustHaveIssue(t *testing.T, r *Report, id string) {
	t.Helper()
	for _, is := range r.Issues {
		if is.ID == id {
			return
		}
	}
	ids := []string{}
	for _, is := range r.Issues {
		ids = append(ids, is.ID)
	}
	t.Fatalf("expected issue %q not found, got: %v", id, ids)
}

func TestAuditBytes_LooseConfig(t *testing.T) {
	xml := []byte(`
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors>
      <certificates src="user" />
      <certificates src="system" />
    </trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">api.example.com</domain>
    <trust-anchors>
      <certificates src="user" />
    </trust-anchors>
  </domain-config>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !r.Present || !r.BaseCleartextPermitted || !r.BaseHasUserTrustAnchor {
		t.Fatalf("expected loose flags set, got %+v", r)
	}
	mustHaveIssue(t, r, "nsc_base_cleartext_permitted")
	mustHaveIssue(t, r, "nsc_base_user_trust_anchors")
	mustHaveIssue(t, r, "nsc_domain_cleartext_permitted")
	mustHaveIssue(t, r, "nsc_domain_user_trust")
	if r.Verdict != "dangerous" && r.Verdict != "weak" {
		t.Fatalf("verdict expected dangerous/weak, got %q (score=%d)", r.Verdict, r.Score)
	}
}

func TestAuditBytes_HardenedConfigWithPinning(t *testing.T) {
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
	if r.BaseCleartextPermitted {
		t.Error("base should be cleartext-blocked")
	}
	mustHaveIssue(t, r, "nsc_domain_pinning_present")
	mustHaveIssue(t, r, "nsc_base_hardened")
	if r.Verdict != "hardened" {
		t.Fatalf("verdict expected hardened, got %q (score=%d)", r.Verdict, r.Score)
	}
}

func TestAuditBytes_OverridePins(t *testing.T) {
	xml := []byte(`
<network-security-config>
  <domain-config>
    <domain>api.example.com</domain>
    <trust-anchors>
      <certificates src="@raw/dev_ca" overridePins="true" />
    </trust-anchors>
  </domain-config>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	mustHaveIssue(t, r, "nsc_domain_override_pins")
}

func TestAuditBytes_DebugOverrides(t *testing.T) {
	xml := []byte(`
<network-security-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user" />
    </trust-anchors>
  </debug-overrides>
</network-security-config>`)
	r, err := AuditBytes("test", xml)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !r.HasDebugOverrides || !r.DebugOverridesUserTrust {
		t.Errorf("debug-overrides flags not set: %+v", r)
	}
	mustHaveIssue(t, r, "nsc_debug_overrides_user_trust")
}

func TestAuditDir_Absent(t *testing.T) {
	dir := t.TempDir()
	r, err := AuditDir(dir)
	if err != nil {
		t.Fatalf("audit dir: %v", err)
	}
	if r.Present || r.Verdict != "absent" {
		t.Errorf("expected absent verdict, got %+v", r)
	}
}

func TestRenderMarkdown(t *testing.T) {
	xml := []byte(`<network-security-config><base-config cleartextTrafficPermitted="true"/></network-security-config>`)
	r, _ := AuditBytes("x", xml)
	out := RenderMarkdown(r)
	if !strings.Contains(out, "Network Security Config Audit") {
		t.Error("missing title")
	}
	if !strings.Contains(out, "Base config") {
		t.Error("missing base section")
	}
}
