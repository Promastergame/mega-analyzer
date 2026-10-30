package secrets

import (
	"regexp"
	"strings"
)

// The provider rules in providers.go only fire on credentials with a
// recognizable vendor shape (AKIA…, ghp_…, sk_live_…). A large class of real
// leaks has no vendor prefix at all: an app config that hard-codes
// `api_secret = "9f2c…"` or an env line `DB_PASSWORD=…`. This file adds a
// generic, assignment-aware detector for those, gated hard on entropy and
// context so it stays precise enough to run inside DetectProviders on every
// caller (web scan, APK/JAR loaders, codescan, binzap).

// genericAssign matches `keyword-bearing identifier = "value"` in the common
// source/config styles: `foo_secret = "…"`, `apiKey: '…'`, JSON `"token":"…"`.
var genericAssign = regexp.MustCompile(
	`(?i)([A-Za-z0-9_.\-]*(?:api[_.\-]?key|secret|token|password|passwd|pwd|access[_.\-]?key|auth[_.\-]?token|client[_.\-]?secret|private[_.\-]?key|credential|passphrase)[A-Za-z0-9_.\-]*)` +
		`["']?\s*[:=]\s*["']([^"'\n\r]{8,200})["']`)

// genericEnv matches uppercase env-style assignments without quotes:
// `AWS_SECRET_ACCESS_KEY=wJal…`. Restricted to SHOUTING_CASE keys so ordinary
// prose never trips it.
var genericEnv = regexp.MustCompile(
	`(?m)^[ \t]*(?:export[ \t]+)?([A-Z0-9]+(?:_[A-Z0-9]+)*(?:_(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|ACCESS_?KEY|AUTH|CREDENTIAL|PASSPHRASE)))=([^\s"']{8,200})`)

// urlLike / pathLike values are common false positives for assignment matches
// (`base_url = "https://…"`, `key_path = "/etc/…"`): they carry a keyword but
// hold a locator, not a secret.
var (
	reURLValue  = regexp.MustCompile(`^[a-z][a-z0-9+.\-]*://`)
	rePathValue = regexp.MustCompile(`^(?:\.{0,2}/|[A-Za-z]:\\|\\\\|~/|\$\{?[A-Za-z_])`)
	// reScreamingSnake matches template constants like REPLACE_WITH_TOKEN or
	// INSERT_SECRET_HERE — symbolic placeholders, never real credentials.
	reScreamingSnake = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)
	// reTemplateWord catches free-form placeholder markers embedded in a value.
	reTemplateWord = regexp.MustCompile(`(?i)(replace|redact|insert[_-]|todo|fixme|goes[_-]?here|value[_-]?here|not[_-]?set)`)
)

// looksLikeIdentifierWord reports values that are plainly not secrets: a single
// lowercase word, a dotted class path, a boolean/enum token.
func looksLikeIdentifierWord(v string) bool {
	switch strings.ToLower(v) {
	case "true", "false", "null", "none", "nil", "undefined", "enabled", "disabled":
		return true
	}
	// A run of a single word with no digits/symbols is almost never a key.
	hasDigit, hasSym := false, false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= '0' && c <= '9' {
			hasDigit = true
		} else if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			hasSym = true
		}
	}
	return !hasDigit && !hasSym && len(v) < 16
}

// plausibleGenericSecret is the precision gate for a generic candidate value.
func plausibleGenericSecret(value string) bool {
	if len(value) < 8 {
		return false
	}
	if reURLValue.MatchString(value) || rePathValue.MatchString(value) {
		return false
	}
	if looksLikeIdentifierWord(value) {
		return false
	}
	if providerPlaceholder.MatchString(value) || rePlaceholderSeq.MatchString(value) {
		return false
	}
	if reScreamingSnake.MatchString(value) || reTemplateWord.MatchString(value) {
		return false
	}
	if isRepeatingString(value) {
		return false
	}
	ent := CalculateEntropy(value)
	uniq := uniqueCharRatio(value)
	// A real embedded secret is a dense, high-variety blob. Require either
	// strong entropy, or a long token with reasonable character diversity.
	if ent >= 3.6 && uniq >= 0.4 {
		return true
	}
	if len(value) >= 24 && ent >= 3.0 && uniq >= 0.5 {
		return true
	}
	return false
}

// severityForGeneric ranks a generic finding by keyword strength: a leaked
// password or private key is worse than an unlabeled "token".
func severityForGeneric(identifier string) (string, float64) {
	id := strings.ToLower(identifier)
	switch {
	case strings.Contains(id, "private_key"), strings.Contains(id, "privatekey"),
		strings.Contains(id, "secret_key"), strings.Contains(id, "secretkey"),
		strings.Contains(id, "client_secret"), strings.Contains(id, "clientsecret"):
		return "high", 0.72
	case strings.Contains(id, "password"), strings.Contains(id, "passwd"),
		strings.Contains(id, "passphrase"), strings.Contains(id, "credential"):
		return "high", 0.68
	default:
		return "medium", 0.6
	}
}

// DetectGeneric finds assignment-style secrets that carry no vendor prefix. It
// is deliberately conservative; every candidate must clear plausibleGenericSecret.
func DetectGeneric(text string, context string) []ProviderFinding {
	lines := buildLineIndex(text)
	var out []ProviderFinding
	seen := make(map[string]struct{})
	ctxLower := strings.ToLower(context)

	emit := func(identifier, value string, valueStart int) {
		value = strings.TrimSpace(value)
		if !plausibleGenericSecret(value) {
			return
		}
		key := identifier + "\x00" + value
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}

		severity, confidence := severityForGeneric(identifier)
		near := strings.ToLower(snippetAt(text, valueStart, valueStart+len(value))) + " " + ctxLower
		if strings.Contains(near, "test") || strings.Contains(near, "example") ||
			strings.Contains(near, "sample") || strings.Contains(near, "mock") ||
			strings.Contains(near, "dummy") || strings.Contains(near, "fixture") {
			if severity == "high" {
				severity = "medium"
			}
			confidence *= 0.7
		}
		line, col := lines.lineCol(valueStart)
		masked := MaskSecret(value)
		contextSnippet := strings.ReplaceAll(snippetAt(text, valueStart, valueStart+len(value)), value, masked)
		out = append(out, ProviderFinding{
			RuleID:      "secret/generic-assignment",
			Provider:    "generic",
			Name:        "Hard-coded secret in assignment (" + identifier + ")",
			Value:       value,
			MaskedValue: masked,
			Severity:    severity,
			Confidence:  confidence,
			Line:        line,
			Column:      col,
			Context:     contextSnippet,
			Remediation: "Move the secret to a secret manager or environment variable injected at runtime; never commit credentials to source or config.",
		})
	}

	for _, loc := range genericAssign.FindAllStringSubmatchIndex(text, 500) {
		identifier := text[loc[2]:loc[3]]
		value := text[loc[4]:loc[5]]
		emit(identifier, value, loc[4])
	}
	for _, loc := range genericEnv.FindAllStringSubmatchIndex(text, 500) {
		identifier := text[loc[2]:loc[3]]
		value := text[loc[4]:loc[5]]
		emit(identifier, value, loc[4])
	}
	return out
}
