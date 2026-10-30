package secrets

import (
	"strings"
	"testing"
)

func TestDetectGeneric_QuotedAssignment(t *testing.T) {
	// A dense, high-entropy value assigned to a secret-named identifier.
	src := `db_password = "G7#kQ9pLzX2mW8vR4tY6nB1cH5jF3sD0"`
	fs := DetectGeneric(src, "config.py")
	f := findRule(fs, "secret/generic-assignment")
	if f == nil {
		t.Fatalf("expected a generic assignment finding, got %#v", fs)
	}
	if f.Severity != "high" {
		t.Errorf("password leak should be high severity, got %q", f.Severity)
	}
	if strings.Contains(f.Context, f.Value) {
		t.Errorf("raw secret leaked into context: %q", f.Context)
	}
	if f.MaskedValue == f.Value {
		t.Error("value should be masked")
	}
}

func TestDetectGeneric_EnvStyle(t *testing.T) {
	src := "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYzQ8pLm3vT9k\n"
	fs := DetectGeneric(src, ".env")
	if findRule(fs, "secret/generic-assignment") == nil {
		t.Fatalf("expected env-style secret to be detected, got %#v", fs)
	}
}

func TestDetectGeneric_JSONStyle(t *testing.T) {
	src := `{"client_secret":"aZ4Xq91Lmn82Bvc73Kdo55Twe10Rui44"}`
	fs := DetectGeneric(src, "creds.json")
	f := findRule(fs, "secret/generic-assignment")
	if f == nil {
		t.Fatalf("expected client_secret detection, got %#v", fs)
	}
	if f.Severity != "high" {
		t.Errorf("client_secret should be high, got %q", f.Severity)
	}
}

func TestDetectGeneric_IgnoresPlaceholders(t *testing.T) {
	for _, src := range []string{
		`api_key = "your_api_key_here"`,
		`password = "changeme"`,
		`token = "REPLACE_WITH_TOKEN"`,
		`secret = "xxxxxxxxxxxxxxxx"`,
		`api_key = "example"`,
	} {
		if fs := DetectGeneric(src, "config"); len(fs) != 0 {
			t.Errorf("placeholder %q should not be flagged, got %#v", src, fs)
		}
	}
}

func TestDetectGeneric_IgnoresURLsAndPaths(t *testing.T) {
	for _, src := range []string{
		`api_url = "https://api.example.com/v1/endpoint"`,
		`key_path = "/etc/ssl/private/server.key"`,
		`token_file = "./secrets/token.txt"`,
	} {
		if fs := DetectGeneric(src, "config"); len(fs) != 0 {
			t.Errorf("locator %q should not be flagged as a secret, got %#v", src, fs)
		}
	}
}

func TestDetectGeneric_IgnoresLowEntropyWords(t *testing.T) {
	for _, src := range []string{
		`auth_token = "enabled"`,
		`use_password = "true"`,
		`secret = "password"`,
	} {
		if fs := DetectGeneric(src, "config"); len(fs) != 0 {
			t.Errorf("low-signal value %q should not be flagged, got %#v", src, fs)
		}
	}
}

func TestDetectGeneric_TestContextDemoted(t *testing.T) {
	src := `test_api_secret = "G7kQ9pLzX2mW8vR4tY6nB1cH5jF3sD0a"`
	f := findRule(DetectGeneric(src, "test_config.py"), "secret/generic-assignment")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.Severity == "high" {
		t.Errorf("secret in test context should be demoted below high, got %q", f.Severity)
	}
}

func TestDetectGeneric_IgnoresNonSecretIdentifiers(t *testing.T) {
	// Identifiers without a secret keyword must never be scanned.
	src := `user_name = "G7kQ9pLzX2mW8vR4tY6nB1cH5jF3sD0"`
	if fs := DetectGeneric(src, "config"); len(fs) != 0 {
		t.Errorf("non-secret identifier should not be flagged, got %#v", fs)
	}
}

func TestDetectProviders_MergesGeneric(t *testing.T) {
	// DetectProviders should surface generic secrets alongside vendor ones.
	src := `api_secret = "Kd82Lm91aZ4Xq73Bvco55Twe10Rui44"`
	f := findRule(DetectProviders(src, "config"), "secret/generic-assignment")
	if f == nil {
		t.Fatal("DetectProviders should merge generic assignment findings")
	}
}

func TestDetectProviders_GenericDoesNotDuplicateVendor(t *testing.T) {
	// A Stripe key assigned to a secret-named var must be reported once (vendor),
	// not also as a generic finding.
	src := `stripe_secret = "sk_live_0123456789abcdefghijABCD"`
	fs := DetectProviders(src, "config")
	var stripe, generic int
	for _, f := range fs {
		switch f.RuleID {
		case "secret/stripe-key":
			stripe++
		case "secret/generic-assignment":
			generic++
		}
	}
	if stripe == 0 {
		t.Error("expected the Stripe vendor rule to fire")
	}
	if generic != 0 {
		t.Errorf("vendor-covered secret should not be double-reported as generic (got %d)", generic)
	}
}
