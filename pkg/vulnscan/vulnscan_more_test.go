package vulnscan

import (
	"strings"
	"testing"
)

// ── checks_cookies.go ────────────────────────────────────────────────────────

func TestIsSessionCookie(t *testing.T) {
	yes := []string{"PHPSESSID", "connect.sid", "auth_token", "JWT", "laravel_session", "csrf_token"}
	for _, n := range yes {
		if !isSessionCookie(n) {
			t.Errorf("isSessionCookie(%q) = false, want true", n)
		}
	}
	no := []string{"theme", "lang", "tz", "color"}
	for _, n := range no {
		if isSessionCookie(n) {
			t.Errorf("isSessionCookie(%q) = true, want false", n)
		}
	}
}

// ── checks_jwt.go ─────────────────────────────────────────────────────────────

func TestIsJWT(t *testing.T) {
	valid := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	if !isJWT(valid) {
		t.Error("valid JWT not detected")
	}
	if isJWT("Bearer token") {
		t.Error("plain bearer token falsely flagged as JWT")
	}
	if isJWT("") {
		t.Error("empty string falsely flagged as JWT")
	}
	if isJWT("only.two") {
		t.Error("two-part string falsely flagged as JWT")
	}
}

// ── checks_redirect.go ────────────────────────────────────────────────────────

func TestIsExternalRedirect(t *testing.T) {
	cases := []struct {
		location, host string
		want           bool
	}{
		{"", "example.com", false},
		{"/relative/path", "example.com", false},
		{"https://evil.com/phish", "example.com", true},
		{"https://example.com/ok", "example.com", false},
		{"https://www.example.com/ok", "example.com", false},
		{"//evil.com/redirect", "example.com", true},
	}
	for _, c := range cases {
		if got := isExternalRedirect(c.location, c.host); got != c.want {
			t.Errorf("isExternalRedirect(%q,%q) = %v, want %v", c.location, c.host, got, c.want)
		}
	}
}

// ── curl_import.go ────────────────────────────────────────────────────────────

func TestTokenizeCurl_Basic(t *testing.T) {
	tokens, err := tokenizeCurl(`curl -X POST 'https://api.example.com/v1' -H 'Content-Type: application/json'`)
	if err != nil {
		t.Fatalf("tokenizeCurl: %v", err)
	}
	if len(tokens) < 5 {
		t.Errorf("expected ≥5 tokens, got %d: %v", len(tokens), tokens)
	}
}

func TestTokenizeCurl_SingleQuotes(t *testing.T) {
	tokens, err := tokenizeCurl(`curl 'https://example.com/path?q=hello world'`)
	if err != nil {
		t.Fatalf("tokenizeCurl: %v", err)
	}
	found := false
	for _, tok := range tokens {
		if strings.Contains(tok, "hello world") {
			found = true
		}
	}
	if !found {
		t.Errorf("space inside single-quotes should be preserved: %v", tokens)
	}
}

func TestTokenizeCurl_LineContinuation(t *testing.T) {
	cmd := "curl \\\n  -X GET \\\n  'https://example.com'"
	tokens, err := tokenizeCurl(cmd)
	if err != nil {
		t.Fatalf("tokenizeCurl: %v", err)
	}
	if len(tokens) < 3 {
		t.Errorf("expected ≥3 tokens after continuation, got %d: %v", len(tokens), tokens)
	}
}

func TestParseCurlCommand_Get(t *testing.T) {
	r, err := ParseCurlCommand(`curl https://api.example.com/users`)
	if err != nil {
		t.Fatalf("ParseCurlCommand: %v", err)
	}
	if r.Method != "GET" {
		t.Errorf("Method = %q, want GET", r.Method)
	}
	if r.URL != "https://api.example.com/users" {
		t.Errorf("URL = %q", r.URL)
	}
}

func TestParseCurlCommand_PostWithHeaders(t *testing.T) {
	cmd := `curl -X POST https://api.example.com/login -H 'Authorization: Bearer tok123' -d 'user=a&pass=b'`
	r, err := ParseCurlCommand(cmd)
	if err != nil {
		t.Fatalf("ParseCurlCommand: %v", err)
	}
	if r.Method != "POST" {
		t.Errorf("Method = %q, want POST", r.Method)
	}
	if r.Headers["Authorization"] != "Bearer tok123" {
		t.Errorf("Authorization header = %q", r.Headers["Authorization"])
	}
	if r.Body != "user=a&pass=b" {
		t.Errorf("Body = %q", r.Body)
	}
}

func TestParseCurlCommand_Insecure(t *testing.T) {
	r, err := ParseCurlCommand(`curl -k https://self-signed.example.com`)
	if err != nil {
		t.Fatalf("ParseCurlCommand: %v", err)
	}
	if !r.Insecure {
		t.Error("expected Insecure=true for -k flag")
	}
}

func TestExportVulnAsCurl_Get(t *testing.T) {
	v := Vulnerability{URL: "https://example.com/search", Parameter: "q", Payload: "<script>"}
	out := ExportVulnAsCurl(v, "GET", nil, "")
	if !strings.Contains(out, "curl") {
		t.Error("expected 'curl' in output")
	}
	if !strings.Contains(out, "example.com") {
		t.Error("expected URL in output")
	}
}

func TestExportVulnAsCurl_Post(t *testing.T) {
	v := Vulnerability{URL: "https://example.com/login", Parameter: "user", Payload: "' OR 1=1--"}
	out := ExportVulnAsCurl(v, "POST", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "user=admin&pass=secret")
	if !strings.Contains(out, "-X POST") {
		t.Errorf("expected -X POST, got:\n%s", out)
	}
	if !strings.Contains(out, "--data") {
		t.Errorf("expected --data, got:\n%s", out)
	}
}
