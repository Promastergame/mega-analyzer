package secrets

import (
	"strings"
	"testing"
)

func TestDetectProvidersModernTokens(t *testing.T) {
	telegram := "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"
	openai := "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	github := "github_pat_" + "A" + "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ____________________"
	text := "tg=" + telegram + " openai=" + openai + " gh=" + github

	findings := DetectProviders(text, "prod config")
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.RuleID] = true
		if f.Value == f.MaskedValue {
			t.Fatalf("secret %s was not masked: %q", f.RuleID, f.MaskedValue)
		}
		if f.Value != "" && f.Context != "" && contains(f.Context, f.Value) {
			t.Fatalf("secret %s leaked in context: %q", f.RuleID, f.Context)
		}
	}
	for _, id := range []string{"secret/telegram-bot-token", "secret/openai-key", "secret/github-fine-grained-token"} {
		if !seen[id] {
			t.Fatalf("expected %s in findings: %#v", id, findings)
		}
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func findRule(fs []ProviderFinding, ruleID string) *ProviderFinding {
	for i := range fs {
		if fs[i].RuleID == ruleID {
			return &fs[i]
		}
	}
	return nil
}

func TestDetectProviders_LowEntropyDemotedNotDropped(t *testing.T) {
	// A mailgun-shaped match whose body is all zeros is not a real key. It must
	// still be emitted (coverage preserved) but demoted out of the way.
	mg := findRule(DetectProviders("mailgun=key-00000000000000000000000000000000", "config"), "secret/mailgun-key")
	if mg == nil {
		t.Fatal("expected mailgun match to still be emitted (demoted, not dropped)")
	}
	if mg.Severity != "low" {
		t.Errorf("low-entropy mailgun should be demoted to low, got %q", mg.Severity)
	}
	if mg.Confidence >= 0.86 {
		t.Errorf("confidence should be cut for low-entropy match, got %.2f", mg.Confidence)
	}
}

func TestDetectProviders_HighEntropyKeyKept(t *testing.T) {
	mg := findRule(DetectProviders("mailgun=key-0123456789abcdef0fedcba987654321", "config"), "secret/mailgun-key")
	if mg == nil {
		t.Fatal("expected mailgun match")
	}
	if mg.Severity == "low" {
		t.Errorf("high-entropy mailgun key must not be demoted to low (got severity=low, conf=%.2f)", mg.Confidence)
	}
}

func TestDetectProviders_RepeatingGoogleKeyDemoted(t *testing.T) {
	g := findRule(DetectProviders("apikey=AIza"+strings.Repeat("a", 35), "config"), "secret/google-api")
	if g == nil {
		t.Fatal("expected google api key match")
	}
	if g.Severity != "low" {
		t.Errorf("repeating google key should be demoted to low, got %q", g.Severity)
	}
}

func TestMaskSecretKeepsShape(t *testing.T) {
	masked := MaskSecret("123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi")
	if masked == "" || masked == "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi" {
		t.Fatalf("unexpected mask: %q", masked)
	}
	if masked[:4] != "1234" {
		t.Fatalf("mask should preserve prefix shape, got %q", masked)
	}
}
