package secrets

import (
	"fmt"
	"regexp"
	"strings"
)

// ProviderFinding is a provider-aware credential finding. It is intentionally
// independent from the report/finding structs used by other packages so the same
// detector can be reused by codescan, vulnscan, binzap and jarloader.
type ProviderFinding struct {
	RuleID      string
	Provider    string
	Name        string
	Value       string
	MaskedValue string
	Severity    string // info, low, medium, high, critical
	Confidence  float64
	Line        int
	Column      int
	Context     string
	Remediation string
	// Verified is true when an offline structural check (see verifier.go) proved
	// the candidate is well-formed for its credential type. It never contacts a
	// provider.
	Verified bool
	// Validation carries a short human-readable note from the structural check
	// (e.g. "well-formed JWT (alg=HS256), exp=2020-01-01"). Empty when no check
	// applied.
	Validation string
}

type providerRule struct {
	id          string
	provider    string
	name        string
	re          *regexp.Regexp
	severity    string
	confidence  float64
	remediation string
}

var providerRules = []providerRule{
	{
		id:          "secret/aws-access-key",
		provider:    "aws",
		name:        "AWS access key id",
		re:          regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b`),
		severity:    "critical",
		confidence:  0.98,
		remediation: "Revoke the AWS key, rotate related IAM credentials, and audit CloudTrail for abuse.",
	},
	{
		id:          "secret/google-api",
		provider:    "google",
		name:        "Google API key",
		re:          regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35,}\b`),
		severity:    "high",
		confidence:  0.97,
		remediation: "Restrict the Google API key by Android package/SHA-1, HTTP referrer, IP and allowed APIs; rotate if exposed.",
	},
	{
		id:          "secret/github-token",
		provider:    "github",
		name:        "GitHub classic token",
		re:          regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b`),
		severity:    "critical",
		confidence:  0.98,
		remediation: "Revoke the GitHub token immediately and review repository/org audit logs.",
	},
	{
		id:          "secret/github-fine-grained-token",
		provider:    "github",
		name:        "GitHub fine-grained PAT",
		re:          regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{80,}\b`),
		severity:    "critical",
		confidence:  0.98,
		remediation: "Revoke the GitHub fine-grained PAT and verify repository access scopes.",
	},
	{
		id:          "secret/gitlab-token",
		provider:    "gitlab",
		name:        "GitLab personal/project token",
		re:          regexp.MustCompile(`\bgl(?:pat|ptt|rt)-[0-9A-Za-z_-]{20,}\b`),
		severity:    "critical",
		confidence:  0.96,
		remediation: "Revoke the GitLab token and audit project/group events for unauthorized access.",
	},
	{
		id:          "secret/telegram-bot-token",
		provider:    "telegram",
		name:        "Telegram bot token",
		re:          regexp.MustCompile(`\b\d{8,10}:[A-Za-z0-9_-]{35}\b`),
		severity:    "critical",
		confidence:  0.99,
		remediation: "Revoke the Telegram bot token via BotFather and rotate all bot webhooks/secrets.",
	},
	{
		id:          "secret/discord-webhook",
		provider:    "discord",
		name:        "Discord webhook URL",
		re:          regexp.MustCompile(`https://(?:discord(?:app)?\.com)/api/webhooks/\d{15,25}/[A-Za-z0-9_-]{40,}`),
		severity:    "critical",
		confidence:  0.98,
		remediation: "Delete or rotate the Discord webhook; treat exposed webhook URLs as write credentials.",
	},
	{
		id:          "secret/discord-token",
		provider:    "discord",
		name:        "Discord bot/user token",
		re:          regexp.MustCompile(`\b(?:mfa\.[A-Za-z0-9_-]{80,}|[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})\b`),
		severity:    "critical",
		confidence:  0.82,
		remediation: "Rotate the Discord token and review bot/user account activity.",
	},
	{
		id:          "secret/slack-token",
		provider:    "slack",
		name:        "Slack token",
		re:          regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`),
		severity:    "critical",
		confidence:  0.96,
		remediation: "Revoke the Slack token, rotate affected app credentials, and review workspace audit logs.",
	},
	{
		id:          "secret/slack-webhook",
		provider:    "slack",
		name:        "Slack webhook URL",
		re:          regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}`),
		severity:    "critical",
		confidence:  0.98,
		remediation: "Revoke the Slack webhook and move webhook URLs into a secret manager.",
	},
	{
		id:          "secret/stripe-key",
		provider:    "stripe",
		name:        "Stripe secret/restricted key",
		re:          regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b`),
		severity:    "critical",
		confidence:  0.96,
		remediation: "Roll the Stripe key and verify no unauthorized charges, refunds or customer data reads occurred.",
	},
	{
		id:          "secret/openai-key",
		provider:    "openai",
		name:        "OpenAI API key",
		re:          regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b`),
		severity:    "critical",
		confidence:  0.9,
		remediation: "Revoke the OpenAI key, rotate it in all deployments, and review usage/billing logs.",
	},
	{
		id:          "secret/anthropic-key",
		provider:    "anthropic",
		name:        "Anthropic API key",
		re:          regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`),
		severity:    "critical",
		confidence:  0.95,
		remediation: "Revoke the Anthropic key and review usage logs.",
	},
	{
		id:          "secret/cloudflare-token",
		provider:    "cloudflare",
		name:        "Cloudflare API token",
		re:          regexp.MustCompile(`(?i)\b(?:cloudflare[_-]?(?:api[_-]?)?token|cf[_-]?api[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9_-]{30,}['"]?`),
		severity:    "critical",
		confidence:  0.84,
		remediation: "Revoke the Cloudflare API token and audit zone/account changes.",
	},
	{
		id:          "secret/huggingface-token",
		provider:    "huggingface",
		name:        "Hugging Face access token",
		re:          regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}\b`),
		severity:    "high",
		confidence:  0.9,
		remediation: "Revoke the Hugging Face token and audit model/dataset access.",
	},
	{
		id:          "secret/npm-token",
		provider:    "npm",
		name:        "npm access token",
		re:          regexp.MustCompile(`\bnpm_[A-Za-z0-9]{30,}\b`),
		severity:    "critical",
		confidence:  0.94,
		remediation: "Revoke the npm token and audit package publishing history.",
	},
	{
		id:          "secret/pypi-token",
		provider:    "pypi",
		name:        "PyPI upload token",
		re:          regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}\b`),
		severity:    "critical",
		confidence:  0.96,
		remediation: "Revoke the PyPI token and audit package releases for unauthorized uploads.",
	},
	{
		id:          "secret/sendgrid-key",
		provider:    "sendgrid",
		name:        "SendGrid API key",
		re:          regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`),
		severity:    "critical",
		confidence:  0.96,
		remediation: "Revoke the SendGrid key and audit mail-sending activity.",
	},
	{
		id:          "secret/mailgun-key",
		provider:    "mailgun",
		name:        "Mailgun API key",
		re:          regexp.MustCompile(`\bkey-[0-9a-fA-F]{32}\b`),
		severity:    "high",
		confidence:  0.86,
		remediation: "Rotate the Mailgun key and review recent sending activity.",
	},
	{
		id:          "secret/twilio-key",
		provider:    "twilio",
		name:        "Twilio API key SID",
		re:          regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
		severity:    "high",
		confidence:  0.9,
		remediation: "Rotate the Twilio API key and audit SMS/voice usage.",
	},
	{
		id:          "secret/sentry-dsn",
		provider:    "sentry",
		name:        "Sentry DSN",
		re:          regexp.MustCompile(`https://[0-9a-fA-F]{32}@o\d+\.ingest\.sentry\.io/\d+`),
		severity:    "medium",
		confidence:  0.9,
		remediation: "Treat exposed Sentry DSNs as telemetry write credentials; rotate if project policy requires it.",
	},
	{
		id:          "secret/jwt-token",
		provider:    "jwt",
		name:        "JSON Web Token",
		re:          regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
		severity:    "high",
		confidence:  0.95,
		remediation: "Avoid shipping live JWTs; revoke the token and shorten token lifetimes.",
	},
	{
		id:          "secret/private-key",
		provider:    "pem",
		name:        "Private key block",
		re:          regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
		severity:    "critical",
		confidence:  0.99,
		remediation: "Revoke/replace the private key and every certificate/token derived from it.",
	},
	{
		id:          "secret/firebase-db-url",
		provider:    "firebase",
		name:        "Firebase Realtime Database URL",
		re:          regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`),
		severity:    "medium",
		confidence:  0.82,
		remediation: "Review Firebase Realtime Database rules; URLs are public but misconfigured rules expose data.",
	},
	{
		id:          "secret/supabase-url-key-context",
		provider:    "supabase",
		name:        "Supabase URL/key context",
		re:          regexp.MustCompile(`https://[a-z0-9]{15,}\.supabase\.co|\b(?:anon|service_role)\s*[:=]\s*['"][A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}['"]`),
		severity:    "high",
		confidence:  0.82,
		remediation: "Verify Supabase Row Level Security and rotate service_role keys if exposed.",
	},
}

var providerPlaceholder = regexp.MustCompile(`(?i)(example|sample|dummy|placeholder|changeme|your[_-]?|xxx+|fake|test[_-]?key|token_here|<.*>|\$\{.*\}|@string/)`)

// DetectProviders scans text for provider-specific tokens and credentials. It is
// fully offline: it never calls provider APIs or any external service.
func DetectProviders(text string, context string) []ProviderFinding {
	var out []ProviderFinding
	seen := make(map[string]struct{})
	// matchedValues records credential strings already reported by a vendor rule
	// so the generic detector never double-reports the same leak.
	matchedValues := make(map[string]struct{})
	ctxLower := strings.ToLower(context)
	lines := buildLineIndex(text)

	for _, rule := range providerRules {
		matches := rule.re.FindAllStringIndex(text, 200)
		for _, loc := range matches {
			value := text[loc[0]:loc[1]]
			if rule.id == "secret/openai-key" && strings.HasPrefix(value, "sk-ant-") {
				// The more specific Anthropic rule owns sk-ant- values: skip the
				// broad OpenAI rule so one credential is not reported twice.
				continue
			}
			key := rule.id + "\x00" + value
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			matchedValues[value] = struct{}{}

			line, col := lines.lineCol(loc[0])
			severity, confidence := triageProvider(rule, value, ctxLower, text, loc[0], loc[1])

			// Offline structural verification: prove the match is well-formed (or
			// provably dead) without ever contacting the provider. A pass raises
			// confidence; an embedded expiry demotes the finding.
			v := VerifyStructure(rule.id, value)
			if v.Expired {
				severity = "low"
				confidence *= 0.5
			} else if v.Verified {
				confidence = boostConfidence(confidence)
			}

			if valueJudge != nil && !v.Verified && valueJudge(value) {
				// The pluggable value classifier says the body looks like junk:
				// demote (never drop) so coverage is preserved.
				severity = "low"
				confidence *= 0.6
				if v.Detail == "" {
					v.Detail = "value classifier: junk/placeholder-looking body"
				}
			}

			masked := MaskSecret(value)
			contextSnippet := strings.ReplaceAll(snippetAt(text, loc[0], loc[1]), value, masked)
			out = append(out, ProviderFinding{
				RuleID:      rule.id,
				Provider:    rule.provider,
				Name:        rule.name,
				Value:       value,
				MaskedValue: masked,
				Severity:    severity,
				Confidence:  confidence,
				Line:        line,
				Column:      col,
				Context:     contextSnippet,
				Remediation: rule.remediation,
				Verified:    v.Verified && !v.Expired,
				Validation:  v.Detail,
			})
		}
	}

	// Generic assignment-style secrets carry no vendor prefix; merge them in,
	// skipping anything a vendor rule already covered.
	for _, gf := range DetectGeneric(text, context) {
		if _, ok := matchedValues[gf.Value]; ok {
			continue
		}
		if isSubstringOfMatched(gf.Value, matchedValues) {
			continue
		}
		if valueJudge != nil && valueJudge(gf.Value) {
			gf.Severity = "low"
			gf.Confidence *= 0.6
		}
		out = append(out, gf)
	}
	return out
}

// boostConfidence nudges a verified finding upward without ever claiming
// certainty, capping below 1.0 so reports keep a residual doubt margin.
func boostConfidence(c float64) float64 {
	c += (1.0 - c) * 0.5
	if c > 0.99 {
		c = 0.99
	}
	return c
}

// isSubstringOfMatched reports whether value is contained in (or contains) a
// credential already reported by a vendor rule — e.g. a provider token that the
// generic detector also captured as the RHS of an assignment.
func isSubstringOfMatched(value string, matched map[string]struct{}) bool {
	for m := range matched {
		if strings.Contains(m, value) || strings.Contains(value, m) {
			return true
		}
	}
	return false
}

// entropySensitiveRules lists rules whose regex alphabet is permissive enough
// that a low-entropy, structured non-secret (e.g. "key-0000…0000", a 32-char
// run of one hex nibble, a doc-example token) can match the shape. For these we
// gate on the randomness of the credential's variable portion. Rules with a
// strong fixed prefix (AKIA…, ghp_…, xox[baprs]-…, sk_live_…) are NOT listed:
// their structure alone is a reliable signal, so we never demote them on
// entropy and keep true-positive strength high.
var entropySensitiveRules = map[string]bool{
	"secret/google-api":        true,
	"secret/openai-key":        true,
	"secret/mailgun-key":       true,
	"secret/twilio-key":        true,
	"secret/jwt-token":         true,
	"secret/huggingface-token": true,
	"secret/npm-token":         true,
	"secret/discord-token":     true,
}

// entropyBearingPart strips a rule's fixed prefix so entropy is measured over
// the actually-random portion of the credential, not the boilerplate marker.
func entropyBearingPart(ruleID, value string) string {
	if ruleID == "secret/jwt-token" {
		// Score the payload segment; headers ("eyJhbGci…") are near-constant.
		if parts := strings.Split(value, "."); len(parts) >= 2 && len(parts[1]) > 0 {
			return parts[1]
		}
	}
	for _, p := range []string{"sk-proj-", "sk-", "key-", "AIza", "hf_", "npm_", "SK", "SG."} {
		if strings.HasPrefix(value, p) {
			return value[len(p):]
		}
	}
	return value
}

// uniqueCharRatio is the fraction of distinct bytes in s — a cheap diversity
// signal that catches low-variety fillers (e.g. "aaaaaaaa…", "ABABAB…") that
// Shannon entropy alone can score deceptively high on.
func uniqueCharRatio(s string) float64 {
	if s == "" {
		return 0
	}
	var seen [256]bool
	distinct := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			distinct++
		}
	}
	return float64(distinct) / float64(len(s))
}

func triageProvider(rule providerRule, value string, ctxLower string, text string, start int, end int) (string, float64) {
	severity := rule.severity
	confidence := rule.confidence
	near := strings.ToLower(snippetAt(text, start, end)) + " " + ctxLower

	if providerPlaceholder.MatchString(value) || providerPlaceholder.MatchString(near) {
		if severity == "critical" || severity == "high" {
			severity = "medium"
		}
		confidence *= 0.65
	}

	// Entropy/charset shape gate for permissive-alphabet rules. We only ever
	// DEMOTE — the finding is still emitted so coverage is never lost — but a
	// structurally-implausible match drops in priority so it stops drowning real
	// keys. Real base64/hex secrets sit at ≥3.5 bits/char with rich charsets.
	if entropySensitiveRules[rule.id] {
		tok := entropyBearingPart(rule.id, value)
		ent := CalculateEntropy(tok)
		uniq := uniqueCharRatio(tok)
		switch {
		case isRepeatingString(tok) || ent < 2.5 || (len(tok) >= 16 && uniq < 0.18):
			// Strongly implausible as a real credential: a filler/sequence/label.
			severity = "low"
			confidence *= 0.4
		case ent < 3.0:
			// Borderline: keep it, but it is unlikely to be a live key.
			if severity == "critical" || severity == "high" {
				severity = "medium"
			}
			confidence *= 0.7
		}
	}
	if strings.Contains(near, "revoked") || strings.Contains(near, "expired") || strings.Contains(near, "disabled") || strings.Contains(near, "old_key") {
		severity = "low"
		confidence *= 0.5
	}
	if rule.provider == "google" && (strings.Contains(near, "firebase") || strings.Contains(near, "google_api_key")) && !strings.Contains(near, "maps") && !strings.Contains(near, "places") && !strings.Contains(near, "billing") {
		severity = "info"
		confidence *= 0.8
	}
	if rule.provider == "discord" && rule.id == "secret/discord-token" && strings.Contains(near, "discord.com/api/webhooks") {
		// Avoid double-reporting webhook URL path fragments as bot tokens.
		severity = "low"
		confidence *= 0.4
	}
	return severity, confidence
}

// MaskSecret returns a safe preview that preserves enough shape for triage while
// never exposing the full credential in reports.
func MaskSecret(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	prefix := 4
	suffix := 4
	if strings.HasPrefix(value, "github_pat_") {
		prefix = len("github_pat_") + 4
	}
	if i := strings.Index(value, ":"); i > 0 && i < 12 { // Telegram bot id prefix
		prefix = i + 2
	}
	if len(value) <= prefix+suffix {
		return value[:1] + strings.Repeat("*", len(value)-2) + value[len(value)-1:]
	}
	return value[:prefix] + strings.Repeat("*", 8) + value[len(value)-suffix:]
}

// LineCol returns 1-based line/column for byte offset.
func LineCol(text string, offset int) (int, int) {
	if offset > len(text) {
		offset = len(text)
	}
	line := 1
	col := 1
	for i := 0; i < offset; i++ {
		if text[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

func snippetAt(text string, start int, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(text) {
		end = len(text)
	}
	lo := start - 80
	if lo < 0 {
		lo = 0
	}
	hi := end + 80
	if hi > len(text) {
		hi = len(text)
	}
	s := strings.TrimSpace(text[lo:hi])
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 220 {
		s = s[:220] + "..."
	}
	return s
}

func (f ProviderFinding) String() string {
	return fmt.Sprintf("%s %s at %d:%d", f.Provider, f.MaskedValue, f.Line, f.Column)
}
