package vulnscan

import (
	"strings"
	"testing"
)

func TestOASTServer_TokenUniqueness(t *testing.T) {
	oast := NewOASTServer(DefaultScannerConfig())

	seen := make(map[string]bool)
	for i := 0; i < 256; i++ {
		tok := oast.IssueToken()
		if len(tok) < 8 {
			t.Fatalf("token too short: %q", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate token issued: %q", tok)
		}
		seen[tok] = true
	}
}

func TestOASTServer_TokenAttribution(t *testing.T) {
	oast := NewOASTServer(DefaultScannerConfig())

	tok1 := oast.IssueToken()
	tok2 := oast.IssueToken()

	// Unrelated traffic (crawlers, other scanners) must not attribute.
	oast.AddHit("HTTP: /some-random-crawler-path")
	if _, ok := oast.HasTokenHit(tok1); ok {
		t.Error("unrelated hit falsely attributed to tok1")
	}
	if _, ok := oast.HasTokenHit(tok2); ok {
		t.Error("unrelated hit falsely attributed to tok2")
	}

	// A hit carrying tok2 must attribute to tok2 only.
	oast.AddHit("HTTP: /" + tok2)
	if _, ok := oast.HasTokenHit(tok1); ok {
		t.Error("hit carrying tok2 falsely attributed to tok1")
	}
	hit, ok := oast.HasTokenHit(tok2)
	if !ok || !strings.Contains(hit, tok2) {
		t.Errorf("expected tok2 hit, got hit=%q ok=%v", hit, ok)
	}
}

func TestOASTServer_KnownTokenDetection(t *testing.T) {
	oast := NewOASTServer(DefaultScannerConfig())
	tok := oast.IssueToken()

	if _, known := oast.hitContainsKnownToken("HTTP: /" + tok); !known {
		t.Error("issued token not recognised in hit")
	}
	if _, known := oast.hitContainsKnownToken("HTTP: /unknown-path"); known {
		t.Error("unknown path reported as known token")
	}
	// DNS-label dotted form of a long token must still match.
	long := strings.Repeat(tok, 8) // 128 chars > one DNS label
	oast.issued[long] = struct{}{}
	dotted := dnsLabelForm(long)
	if !strings.Contains(dotted, ".") {
		t.Fatalf("dnsLabelForm should split long tokens, got %q", dotted)
	}
	if _, known := oast.hitContainsKnownToken("DNS: " + dotted + ".oast.example"); !known {
		t.Error("dotted DNS form of issued token not recognised")
	}
}
