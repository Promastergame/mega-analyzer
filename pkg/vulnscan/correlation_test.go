package vulnscan

import (
	"testing"
)

func chainFinding(id, url string) Finding {
	return Finding{Vulnerability: Vulnerability{ID: id, URL: url}}
}

func TestCorrelate_SameHostChainFires(t *testing.T) {
	findings := []Finding{
		chainFinding("WS-SSRF-003", "http://victim.example/fetch"),
		chainFinding("WS-REDIR-001", "http://victim.example/go"),
	}
	meta := Correlate(findings, DefaultCorrelationRules())
	if len(meta) != 1 {
		t.Fatalf("expected 1 chain meta-finding, got %d", len(meta))
	}
	if meta[0].ID != "WS-CHAIN-SSRF-REDIR" {
		t.Errorf("unexpected chain ID %q", meta[0].ID)
	}
	if meta[0].URL == "" {
		t.Error("chain meta-finding should inherit the joined host URL")
	}
	if len(meta[0].Sources) != 2 {
		t.Errorf("expected 2 sources, got %v", meta[0].Sources)
	}
}

func TestCorrelate_CrossHostChainSuppressed(t *testing.T) {
	findings := []Finding{
		chainFinding("WS-SSRF-003", "http://host-a.example/fetch"),
		chainFinding("WS-REDIR-001", "http://host-b.example/go"),
	}
	meta := Correlate(findings, DefaultCorrelationRules())
	for _, m := range meta {
		if m.ID == "WS-CHAIN-SSRF-REDIR" {
			t.Fatal("cross-host primitives must not form an SSRF+redirect chain")
		}
	}
}

func TestCorrelate_SourcesScopedToJoinedHost(t *testing.T) {
	findings := []Finding{
		chainFinding("WS-SSRF-003", "http://victim.example/fetch"),
		chainFinding("WS-SSRF-002", "http://other.example/fetch"), // different host, same prefix
		chainFinding("WS-REDIR-001", "http://victim.example/go"),
	}
	meta := Correlate(findings, DefaultCorrelationRules())
	if len(meta) != 1 {
		t.Fatalf("expected 1 chain meta-finding, got %d", len(meta))
	}
	for _, src := range meta[0].Sources {
		if src == "WS-SSRF-002" {
			t.Error("finding from a different host leaked into chain sources")
		}
	}
}

func TestCorrelate_NoURLNoChain(t *testing.T) {
	findings := []Finding{
		chainFinding("WS-IDOR-001", ""),
		chainFinding("WS-JWT-001", ""),
	}
	meta := Correlate(findings, DefaultCorrelationRules())
	for _, m := range meta {
		if m.ID == "WS-CHAIN-ATO" {
			t.Fatal("primitives without URLs must not form a chain (no join key)")
		}
	}
}

func TestFindingHost(t *testing.T) {
	cases := map[string]string{
		"http://Example.com:8080/path": "example.com:8080",
		"https://sub.host/x?y=1":       "sub.host",
		"":                             "",
		"::bad-url::":                  "",
	}
	for in, want := range cases {
		f := Finding{Vulnerability: Vulnerability{URL: in}}
		if got := findingHost(f); got != want {
			t.Errorf("findingHost(%q) = %q, want %q", in, got, want)
		}
	}
}
