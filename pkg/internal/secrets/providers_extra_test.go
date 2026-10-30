package secrets

import (
	"strings"
	"testing"
)

func TestExtraProviderRules_Match(t *testing.T) {
	cases := []struct {
		ruleID string
		sample string
	}{
		{"secret/google-oauth-client-secret", "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"},
		{"secret/square-access-token", "sq0atp-abcdEFGH1234ijklMNOP56"},
		{"secret/square-app-secret", "sq0csp-abcdEFGH1234ijklMNOP5678qrstUVWX9012yz34567"},
		{"secret/shopify-token", "shpat_0123456789abcdef0123456789abcdef"},
		{"secret/digitalocean-token", "dop_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{"secret/vault-token", "hvs.CAESIABCDEFGHIJKLMNOPQRSTUVWX"},
		{"secret/doppler-token", "dp.pt.abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123"},
		{"secret/postman-key", "PMAK-0123456789abcdef01234567-0123456789abcdef0123456789abcdef01"},
		{"secret/newrelic-key", "NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ0"},
		{"secret/grafana-token", "glsa_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345_0a1b2c3d"},
		{"secret/linear-key", "lin_api_0123456789ABCDEFGHIJ0123456789abcdefghij"},
		{"secret/databricks-token", "dapi0123456789abcdef0123456789abcdef"},
		{"secret/planetscale-token", "pscale_tkn_abcdefghij0123456789ABCDEFGHIJ.klmno"},
		{"secret/notion-token", "ntn_0123456789abcdefghijABCDEFGHIJ0123456789xy"},
		{"secret/airtable-token", "pat0123456789abcd.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{"secret/rubygems-key", "rubygems_0123456789abcdef0123456789abcdef0123456789abcdef"},
		{"secret/azure-storage-key", "AccountKey=" + strings.Repeat("A", 86) + "=="},
	}
	for _, tc := range cases {
		findings := DetectProviders(tc.sample, "prod-config")
		if findRule(findings, tc.ruleID) == nil {
			t.Errorf("rule %s did not match sample %q; findings=%v", tc.ruleID, tc.sample, findings)
		}
	}
}

func TestExtraProviderRules_NoFalsePositiveOnProse(t *testing.T) {
	prose := "This document describes how our team rotates keys and audits access every quarter."
	if fs := DetectProviders(prose, "README.md"); len(fs) != 0 {
		t.Errorf("prose should not trip any secret rule, got %#v", fs)
	}
}

func TestAWSSecretKeyContextual(t *testing.T) {
	src := `aws_secret_access_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYzQ8pLm3vT9kQ"`
	if findRule(DetectProviders(src, "config"), "secret/aws-secret-key-context") == nil {
		t.Errorf("expected contextual AWS secret key detection")
	}
}

func TestBoostConfidenceMonotonicAndCapped(t *testing.T) {
	if got := boostConfidence(0.8); got <= 0.8 || got > 0.99 {
		t.Errorf("boost(0.8)=%v, want in (0.8, 0.99]", got)
	}
	if got := boostConfidence(0.99); got > 0.99 {
		t.Errorf("boost must stay capped at 0.99, got %v", got)
	}
}
