package vulnscan

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNewScanner(t *testing.T) {
	s, err := NewScanner("http://target.com")
	if err != nil {
		t.Fatal(err)
	}
	if s.Target != "http://target.com" {
		t.Errorf("Expected http://target.com, got %s", s.Target)
	}

	_, err = NewScanner("http://%24")
	if err == nil {
		t.Error("Expected error for invalid target URL")
	}
}

func TestPIDController(t *testing.T) {
	pid := NewPIDController(200.0, 50)
	if pid.Kp != 0.1 {
		t.Errorf("Expected Kp = 0.1, got %f", pid.Kp)
	}

	// Wait should not panic or hang
	pid.Wait()

	// Observe a fast request
	pid.Observe(50 * time.Millisecond)
	d1 := pid.Delay()

	// Observe a very slow request
	pid.Observe(1000 * time.Millisecond)
	d2 := pid.Delay()

	if d2 <= d1 {
		t.Errorf("Expected delay to increase for slow request: %v -> %v", d1, d2)
	}
}

func TestOASTServer(t *testing.T) {
	cfg := DefaultScannerConfig()
	// Use port 0 for random free port assignment
	cfg.OASTBindAddrDNS = "127.0.0.1:0"
	cfg.OASTBindAddrHTTP = "127.0.0.1:0"
	cfg.LabMode = true

	oast := NewOASTServer(cfg)
	err := oast.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer oast.Stop()

	// Test hits
	oast.AddHit("HTTP: /xss")
	hits := oast.GetHits()
	if len(hits) != 1 || hits[0] != "HTTP: /xss" {
		t.Errorf("Unexpected hits: %v", hits)
	}
}

func TestHTTPDesyncLocalListener(t *testing.T) {
	// Start local TCP listener on port 3000 to satisfy TestHTTPDesync dial
	l, err := net.Listen("tcp", "127.0.0.1:3000")
	if err != nil {
		t.Skip("Could not listen on port 3000, skipping desync test")
	}
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			conn.Read(buf)
		}
	}()

	cfg := DefaultScannerConfig()
	cfg.LabMode = true
	res := TestHTTPDesync("http://example.com", cfg)
	if res {
		t.Error("Expected false for mock smuggling test")
	}
}

func TestScannerActiveScan(t *testing.T) {
	// 1. Mock HTTP Server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Default handler below
	}))
	defer ts.Close()

	var returnHeaders bool
	var returnSecrets bool
	var reflectXSS bool
	var returnSQLErr bool

	ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if returnHeaders {
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Permissions-Policy", "geolocation=()")
		}

		if r.URL.Path == "/depth1" {
			w.Write([]byte("Depth 1 page contents"))
			return
		}

		if r.Method == "POST" && r.URL.Path == "/login" {
			r.ParseForm()
			user := r.Form.Get("username")
			if returnSQLErr && strings.Contains(user, "OR '1'='1") {
				w.Write([]byte("sqlite3.OperationalError: database error"))
				return
			}
			if reflectXSS {
				// Naive echo server: reflects any input verbatim (the
				// classic vulnerable sink the context-aware XSS check hunts).
				w.Write([]byte("Hello " + user))
				return
			}
			w.Write([]byte("Success login"))
			return
		}

		// Root page response
		w.Header().Set("Content-Type", "text/html")
		var body strings.Builder
		body.WriteString(`
		<html>
		<body>
			<a href="/depth1">Depth 1 link</a>
			<form action="/login" method="POST">
				<input type="text" name="username">
				<input type="password" name="password">
			</form>
		`)

		if returnSecrets {
			body.WriteString(`
				<!-- AWS Access Key -->
				AKIAIOSFODNN7EXAMPLE
				<!-- GitHub Token -->
				ghp_123456789012345678901234567890123456
				<!-- JWT Token -->
				eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
				<!-- Private Key -->
				-----BEGIN RSA PRIVATE KEY-----
				MIIEpAIBAAKCAQEA0y
				-----END RSA PRIVATE KEY-----
				password: "super_secret_value"
			`)
		}

		body.WriteString(`</body></html>`)
		w.Write([]byte(body.String()))
	})

	// 2. Setup Scanner targeting example.com
	s, err := NewScanner("http://example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Safety gate check: IOwnThisTarget must be true
	s.Config.IOwnThisTarget = false
	_, err = s.Scan()
	if err == nil || !strings.Contains(err.Error(), "safety gate") {
		t.Errorf("Expected safety gate error, got %v", err)
	}

	s.Config.IOwnThisTarget = true
	s.Config.MaxWorkers = 2
	s.Config.Timeout = 1 * time.Second

	// Intercept scanner http client
	s.Client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(ts.URL, "http://")
		return http.DefaultTransport.RoundTrip(req)
	})

	// Case 1: Missing headers, no secrets, no forms fuzzed (passive findings only)
	returnHeaders = false
	returnSecrets = false
	reflectXSS = false
	returnSQLErr = false

	vulns, err := s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	if len(vulns) < 6 {
		t.Errorf("Expected at least 6 header/referrer vulnerabilities, got %d", len(vulns))
	}

	// Case 2: Full scan with secrets & active fuzz triggers
	returnHeaders = true
	returnSecrets = true
	reflectXSS = true
	returnSQLErr = true

	vulns, err = s.Scan()
	if err != nil {
		t.Fatal(err)
	}

	foundXSS := false
	foundSQLi := false
	foundAWS := false
	foundGithub := false
	foundJWT := false
	foundPrivKey := false
	foundGenericSecret := false

	for _, v := range vulns {
		switch v.ID {
		case "WS-XSS-001":
			foundXSS = true
		case "WS-SQLI-001":
			foundSQLi = true
		case "WS-SECRET-AWS-ACCESS-KEY":
			foundAWS = true
		case "WS-SECRET-GITHUB-TOKEN":
			foundGithub = true
		case "WS-SECRET-JWT-TOKEN":
			foundJWT = true
		case "WS-SECRET-PRIVATE-KEY":
			foundPrivKey = true
		case "WS-SECRET-GENERIC-SECRET":
			foundGenericSecret = true
		}
	}

	if !foundXSS || !foundSQLi || !foundAWS || !foundGithub || !foundJWT || !foundPrivKey || !foundGenericSecret {
		t.Errorf("Missing expected vulnerabilities: XSS=%v, SQLi=%v, AWS=%v, Github=%v, JWT=%v, PrivKey=%v, Generic=%v",
			foundXSS, foundSQLi, foundAWS, foundGithub, foundJWT, foundPrivKey, foundGenericSecret)
	}

	// Test client HTTP call failure
	s.Client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})
	_, err = s.Scan()
	if err == nil {
		t.Error("Expected connection refused error, got nil")
	}
}

func TestGenerateMarkdownReport(t *testing.T) {
	vulns := []Vulnerability{
		{
			ID:          "WS-XSS-001",
			Name:        "Reflected XSS",
			Description: "XSS payload reflections",
			Severity:    SeverityCritical,
			URL:         "http://example.com/search",
			Parameter:   "q",
			Payload:     "<script>",
			Evidence:    "Reflected tag",
			Mitigation:  "Escape string",
		},
	}

	tmpDir := t.TempDir()
	reportPath := GenerateMarkdownReport(vulns, "http://example.com", tmpDir)

	if !strings.HasSuffix(reportPath, "WEB_SCAN_REPORT.md") {
		t.Errorf("Expected report path to end with WEB_SCAN_REPORT.md, got %s", reportPath)
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "Reflected XSS") || !strings.Contains(content, "Summary Matrix") {
		t.Error("Expected report to contain XSS vulnerability and Summary Matrix")
	}
}
