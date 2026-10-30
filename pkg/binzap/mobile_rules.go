package binzap

import (
	"fmt"
	"strings"

	"mega-analyzer/pkg/binzap/lex"
)

// This file implements the mobile-application analysis pack (INC6): WebView
// misconfiguration, insecure IPC / Intent handling, dangerous permission usage,
// and broken TLS certificate/hostname validation. Rules operate on the smali
// token stream via method references and string literals.

type methodRefRule struct {
	id, name    string
	severity    Severity
	confidence  Confidence
	cwe         string
	category    string
	remediation string
	needles     []string
	message     string
}

func (r *methodRefRule) ID() string         { return r.id }
func (r *methodRefRule) Name() string       { return r.name }
func (r *methodRefRule) Severity() Severity { return r.severity }

func (r *methodRefRule) Match(ctx ScanContext, tokens []lex.Token) []Finding {
	var findings []Finding
	for _, t := range tokens {
		if t.Type != lex.TokenMethodRef {
			continue
		}
		for _, needle := range r.needles {
			if strings.Contains(t.Value, needle) {
				findings = append(findings, Finding{
					RuleID:      r.id,
					RuleName:    r.name,
					Severity:    r.severity,
					Confidence:  r.confidence,
					Message:     fmt.Sprintf("%s (%s)", r.message, needle),
					File:        ctx.File,
					Line:        t.Line,
					Evidence:    t.Value,
					CWE:         r.cwe,
					Category:    r.category,
					Remediation: r.remediation,
				}.WithFingerprint())
				break
			}
		}
	}
	return findings
}

// MobileRules returns the mobile analysis rules as plain Rule values.
func MobileRules() []Rule {
	entries := MobileRuleEntries()
	out := make([]Rule, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Rule)
	}
	return out
}

// MobileRuleEntries returns the mobile rules together with their metadata.
func MobileRuleEntries() []RuleEntry {
	rules := []*methodRefRule{
		{
			id: "BZ-MOB-001", name: "WebView JavaScript bridge exposed", severity: SeverityHigh,
			confidence: ConfidenceHigh, cwe: "CWE-749", category: "webview",
			remediation: "Avoid addJavascriptInterface with untrusted content; target API-level annotations and validate origins.",
			needles:     []string{"addJavascriptInterface"},
			message:     "WebView exposes a native JavaScript bridge",
		},
		{
			id: "BZ-MOB-002", name: "WebView JavaScript enabled", severity: SeverityMedium,
			confidence: ConfidenceMedium, cwe: "CWE-749", category: "webview",
			remediation: "Only enable JavaScript when required; disable file access and universal access from file URLs.",
			needles:     []string{"setJavaScriptEnabled", "setAllowUniversalAccessFromFileURLs", "setAllowFileAccessFromFileURLs"},
			message:     "WebView is configured with risky settings",
		},
		{
			id: "BZ-MOB-003", name: "Insecure IPC / implicit Intent", severity: SeverityMedium,
			confidence: ConfidenceMedium, cwe: "CWE-927", category: "ipc",
			remediation: "Use explicit Intents, set package, and protect broadcasts with signature-level permissions.",
			needles:     []string{"sendBroadcast", "registerReceiver", "startActivity", "setPackage"},
			message:     "Potentially insecure inter-component communication",
		},
		{
			id: "BZ-MOB-004", name: "Broken TLS certificate validation", severity: SeverityCritical,
			confidence: ConfidenceHigh, cwe: "CWE-295", category: "tls",
			remediation: "Never trust all certificates; implement proper X509TrustManager and hostname verification / pinning.",
			needles:     []string{"checkServerTrusted", "ALLOW_ALL_HOSTNAME_VERIFIER", "setHostnameVerifier", "onReceivedSslError"},
			message:     "Certificate/hostname validation may be disabled",
		},
		{
			id: "BZ-MOB-005", name: "Dangerous permission / device data access", severity: SeverityMedium,
			confidence: ConfidenceLow, cwe: "CWE-250", category: "permission",
			remediation: "Request the minimum permissions; justify access to identifiers, SMS, location and contacts.",
			needles:     []string{"getDeviceId", "getSubscriberId", "getLastKnownLocation", "getSimSerialNumber", "sendTextMessage"},
			message:     "Access to sensitive device data / dangerous permission",
		},
	}

	entries := make([]RuleEntry, 0, len(rules))
	for _, r := range rules {
		entries = append(entries, RuleEntry{
			Rule:    r,
			Enabled: true,
			Meta: RuleMetadata{
				ID: r.id, Name: r.name, Category: r.category, CWE: r.cwe,
				Severity: r.severity, Confidence: r.confidence,
				Remediation: r.remediation, Pack: "mobile",
			},
		})
	}
	entries = append(entries, apkMobileRuleEntries()...)
	return entries
}
