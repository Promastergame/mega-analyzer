package nsc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocate_Found(t *testing.T) {
	dir := t.TempDir()
	xmlDir := filepath.Join(dir, "res", "xml")
	if err := os.MkdirAll(xmlDir, 0755); err != nil {
		t.Fatal(err)
	}
	xmlFile := filepath.Join(xmlDir, "network_security_config.xml")
	if err := os.WriteFile(xmlFile, []byte("<network-security-config/>"), 0644); err != nil {
		t.Fatal(err)
	}
	got := Locate(dir)
	if got == "" {
		t.Error("Locate should find network_security_config.xml")
	}
	if !strings.HasSuffix(got, "network_security_config.xml") {
		t.Errorf("unexpected path: %q", got)
	}
}

func TestLocate_NotFound(t *testing.T) {
	dir := t.TempDir()
	got := Locate(dir)
	if got != "" {
		t.Errorf("Locate should return empty for missing NSC, got %q", got)
	}
}

func TestLocate_AlternativeNames(t *testing.T) {
	for _, name := range []string{"nsc.xml", "network_security_config_debug.xml", "networksecurity_custom.xml"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			xmlDir := filepath.Join(dir, "res", "xml")
			if err := os.MkdirAll(xmlDir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(xmlDir, name), []byte("<network-security-config/>"), 0644); err != nil {
				t.Fatal(err)
			}
			got := Locate(dir)
			if name == "networksecurity_custom.xml" {
				if got == "" {
					t.Errorf("Locate should find files containing 'networksecurity', got empty for %q", name)
				}
			} else {
				if got == "" {
					t.Errorf("Locate should find %q, got empty", name)
				}
			}
		})
	}
}

func TestAuditFile_Valid(t *testing.T) {
	dir := t.TempDir()
	xmlPath := filepath.Join(dir, "network_security_config.xml")
	xml := []byte(`<network-security-config>
  <base-config cleartextTrafficPermitted="true"/>
</network-security-config>`)
	if err := os.WriteFile(xmlPath, xml, 0644); err != nil {
		t.Fatal(err)
	}
	r, err := AuditFile("myapp", xmlPath)
	if err != nil {
		t.Fatalf("AuditFile: %v", err)
	}
	if !r.Present {
		t.Error("report should be present")
	}
	if !r.BaseCleartextPermitted {
		t.Error("cleartext should be permitted")
	}
}

func TestAuditFile_Missing(t *testing.T) {
	_, err := AuditFile("myapp", "/nonexistent/path/nsc.xml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank(SevCritical) <= severityRank(SevHigh) {
		t.Error("critical must rank > high")
	}
	if severityRank(SevHigh) <= severityRank(SevMedium) {
		t.Error("high must rank > medium")
	}
	if severityRank(SevMedium) <= severityRank(SevLow) {
		t.Error("medium must rank > low")
	}
	if severityRank(SevLow) <= severityRank(SevInfo) {
		t.Error("low must rank > info")
	}
	if severityRank(SevInfo) <= severityRank(SevSecure) {
		t.Error("info must rank > secure")
	}
	if severityRank("unknown") != 0 {
		t.Error("unknown severity should rank 0")
	}
}

func TestScoreReport_AllVerdicts(t *testing.T) {
	absent := &Report{Present: false}
	score, verdict := scoreReport(absent)
	if score != 0 || verdict != "absent" {
		t.Errorf("absent: got %d/%q", score, verdict)
	}

	hardened := &Report{Present: true, Issues: []Issue{{Score: 2}}}
	score, verdict = scoreReport(hardened)
	if verdict != "hardened" {
		t.Errorf("hardened: got %d/%q", score, verdict)
	}

	ok := &Report{Present: true, Issues: []Issue{{Score: 7}}}
	score, verdict = scoreReport(ok)
	if verdict != "ok" {
		t.Errorf("ok: got %d/%q, want ok", score, verdict)
	}

	weak := &Report{Present: true, Issues: []Issue{{Score: 25}}}
	score, verdict = scoreReport(weak)
	if verdict != "weak" {
		t.Errorf("weak: got %d/%q", score, verdict)
	}

	dangerous := &Report{Present: true, Issues: []Issue{{Score: 60}}}
	score, verdict = scoreReport(dangerous)
	if verdict != "dangerous" {
		t.Errorf("dangerous: got %d/%q", score, verdict)
	}

	// negative scores clamp to 0
	neg := &Report{Present: true, Issues: []Issue{{Score: -50}}}
	score, _ = scoreReport(neg)
	if score != 0 {
		t.Errorf("negative score should clamp to 0, got %d", score)
	}

	// scores cap at 100
	big := &Report{Present: true, Issues: []Issue{{Score: 200}}}
	score, _ = scoreReport(big)
	if score != 100 {
		t.Errorf("score should cap at 100, got %d", score)
	}
}

func TestRenderMarkdown_Nil(t *testing.T) {
	out := RenderMarkdown(nil)
	if !strings.Contains(out, "Network Security Config Audit") {
		t.Error("nil report should still have title")
	}
	if !strings.Contains(out, "no report") {
		t.Error("nil report should say no report")
	}
}

func TestRenderMarkdown_Absent(t *testing.T) {
	r := &Report{Target: "myapp", Present: false, Verdict: "absent"}
	out := RenderMarkdown(r)
	if !strings.Contains(out, "absent") && !strings.Contains(out, "no `network_security_config") {
		t.Errorf("absent report should mention absence, got: %s", out)
	}
}

func TestRenderMarkdown_WithSource(t *testing.T) {
	r := &Report{Target: "myapp", Source: "/res/xml/nsc.xml", Present: true, Verdict: "hardened"}
	out := RenderMarkdown(r)
	if !strings.Contains(out, "/res/xml/nsc.xml") {
		t.Errorf("should include source path, got: %s", out)
	}
}

func TestRenderMarkdown_WithDomains(t *testing.T) {
	boolTrue := true
	r := &Report{
		Target:  "myapp",
		Present: true,
		Verdict: "weak",
		Domains: []Domain{
			{
				Hosts:              []string{"api.example.com"},
				CleartextPermitted: &boolTrue,
				IncludeSubdomains:  true,
			},
		},
		Issues: []Issue{
			{ID: "nsc_domain_cleartext_permitted", Title: "cleartext", Severity: SevMedium, Score: 8},
		},
	}
	out := RenderMarkdown(r)
	if !strings.Contains(out, "api.example.com") {
		t.Errorf("should mention domain, got: %s", out)
	}
	if !strings.Contains(out, "Findings") {
		t.Errorf("should have findings section, got: %s", out)
	}
}

func TestAuditBytes_Empty(t *testing.T) {
	_, err := AuditBytes("test", nil)
	if err == nil {
		t.Error("expected error for empty bytes")
	}
}
