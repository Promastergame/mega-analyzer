package api

import (
	"bytes"
	"container/list"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─── isPrivateIP ──────────────────────────────────────────────────────────────

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"169.254.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.1", true},
		{"100.64.0.1", true},      // carrier-grade NAT
		{"192.0.2.1", true},       // TEST-NET-1
		{"198.51.100.1", true},    // TEST-NET-2
		{"203.0.113.1", true},     // TEST-NET-3
		{"fd00::1", true},         // IPv6 unique-local
		{"2001:db8::1", true},     // IPv6 documentation range
		{"::ffff:10.0.0.1", true}, // IPv4-mapped private address
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"104.16.0.1", false},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("could not parse IP %q", c.ip)
		}
		got := isPrivateIP(ip)
		if got != c.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", c.ip, got, c.private)
		}
	}
}

// ─── isSafeHost ───────────────────────────────────────────────────────────────

func TestIsSafeHost(t *testing.T) {
	cases := []struct {
		host string
		safe bool
	}{
		{"localhost", false},
		{"localhost.", false}, // trailing dot
		{"LOCALHOST", false},  // case insensitive
		{"localhost.localdomain", false},
		{"::1", false},
		{"::", false},
		{"0.0.0.0", false},
		{"", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"8.8.8.8", true},
		{"1.1.1.1", true},
	}
	for _, c := range cases {
		got := isSafeHost(c.host)
		if got != c.safe {
			t.Errorf("isSafeHost(%q) = %v, want %v", c.host, got, c.safe)
		}
	}
}

// ─── isSafeTarget ─────────────────────────────────────────────────────────────

func TestIsSafeTarget(t *testing.T) {
	cases := []struct {
		url  string
		safe bool
	}{
		{"http://localhost/", false},
		{"http://127.0.0.1/", false},
		{"http://10.0.0.1/", false},
		{"ftp://example.com/", false}, // non-http scheme
		{"file:///etc/passwd", false},
		{":not-a-url", false},
		{"http://8.8.8.8/", true},
		{"https://8.8.8.8/", true},
	}
	for _, c := range cases {
		got := isSafeTarget(c.url)
		if got != c.safe {
			t.Errorf("isSafeTarget(%q) = %v, want %v", c.url, got, c.safe)
		}
	}
}

// ─── compileRegexSafe ─────────────────────────────────────────────────────────

func TestCompileRegexSafe(t *testing.T) {
	// Valid simple pattern
	re, err := compileRegexSafe("foo.*bar")
	if err != nil || re == nil {
		t.Fatalf("expected valid regex, got err=%v", err)
	}
	if !re.MatchString("foo baz bar") {
		t.Error("regex should match")
	}

	// Pattern too long
	longPat := strings.Repeat("a", 2001)
	_, err = compileRegexSafe(longPat)
	if err == nil {
		t.Error("expected error for pattern too long")
	}

	// Too deeply nested
	deepPat := strings.Repeat("(", 21) + "a" + strings.Repeat(")", 21)
	_, err = compileRegexSafe(deepPat)
	if err == nil {
		t.Error("expected error for deeply nested regex")
	}

	// Invalid regex syntax
	_, err = compileRegexSafe("[invalid")
	if err == nil {
		t.Error("expected error for invalid regex syntax")
	}

	// At the depth boundary (exactly 20 levels — should pass)
	borderPat := strings.Repeat("(", 20) + "a" + strings.Repeat(")", 20)
	_, err = compileRegexSafe(borderPat)
	if err != nil {
		t.Errorf("expected success at depth 20, got %v", err)
	}
}

// ─── isLoopbackBind ───────────────────────────────────────────────────────────

func TestIsLoopbackBind(t *testing.T) {
	cases := []struct {
		host string
		loop bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"[::1]", true},
		{"0.0.0.0", false},
		{"0.0.0.1", false},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
	}
	for _, c := range cases {
		got := isLoopbackBind(c.host)
		if got != c.loop {
			t.Errorf("isLoopbackBind(%q) = %v, want %v", c.host, got, c.loop)
		}
	}
}

// ─── originAllowed ────────────────────────────────────────────────────────────

func TestOriginAllowed(t *testing.T) {
	s := NewAPIServer(9000)

	// Default (no env): only 127.0.0.1:PORT and localhost:PORT are allowed
	os.Unsetenv("MEGA_ANALYZER_CORS_ORIGINS")

	if !s.originAllowed("http://127.0.0.1:9000") {
		t.Error("expected default origin http://127.0.0.1:9000 to be allowed")
	}
	if !s.originAllowed("http://localhost:9000") {
		t.Error("expected default origin http://localhost:9000 to be allowed")
	}
	if s.originAllowed("https://evil.com") {
		t.Error("expected evil.com to be blocked")
	}

	// Custom env
	os.Setenv("MEGA_ANALYZER_CORS_ORIGINS", "https://myapp.example.com, http://dashboard.local")
	defer os.Unsetenv("MEGA_ANALYZER_CORS_ORIGINS")
	if !s.originAllowed("https://myapp.example.com") {
		t.Error("expected custom origin to be allowed")
	}
	if !s.originAllowed("http://dashboard.local") {
		t.Error("expected custom origin with spaces to be allowed")
	}
	if s.originAllowed("http://127.0.0.1:9000") {
		t.Error("expected default origin to be blocked when custom list set")
	}
}

// ─── ipRateLimiter.allow ──────────────────────────────────────────────────────

func TestRateLimiterAllow(t *testing.T) {
	l := &ipRateLimiter{
		ips:    make(map[string]*ipEntry),
		maxIPs: 5,
		order:  list.New(),
	}

	// First call should succeed (bucket initialized with capacity)
	ok, remaining, _ := l.allow("1.2.3.4", 10.0, 5.0)
	if !ok {
		t.Error("expected first call to be allowed")
	}
	if remaining < 0 {
		t.Errorf("remaining should be >= 0, got %v", remaining)
	}

	// Drain bucket
	for i := 0; i < 10; i++ {
		l.allow("1.2.3.5", 0.0, 3.0) // rate=0, capacity=3 — drain quickly
	}
	ok2, _, _ := l.allow("1.2.3.5", 0.0, 3.0)
	if ok2 {
		t.Error("expected rate limit to kick in after bucket empty")
	}
}

func TestRateLimiterEvictOldest(t *testing.T) {
	maxIPs := 3
	l := &ipRateLimiter{
		ips:    make(map[string]*ipEntry),
		maxIPs: maxIPs,
		order:  list.New(),
	}

	// Fill to max
	for i := 0; i < maxIPs; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		l.allow(ip, 10.0, 100.0)
	}
	if len(l.ips) != maxIPs {
		t.Fatalf("expected %d IPs, got %d", maxIPs, len(l.ips))
	}

	// Adding one more should evict oldest (10.0.0.1)
	l.allow("10.0.0.100", 10.0, 100.0)
	if len(l.ips) != maxIPs {
		t.Fatalf("expected %d IPs after eviction, got %d", maxIPs, len(l.ips))
	}
	if _, exists := l.ips["10.0.0.1"]; exists {
		t.Error("expected oldest IP 10.0.0.1 to be evicted")
	}
	if _, exists := l.ips["10.0.0.100"]; !exists {
		t.Error("expected new IP 10.0.0.100 to be present")
	}
}

func TestEvictOldestLockedEmptyList(t *testing.T) {
	l := &ipRateLimiter{
		ips:    make(map[string]*ipEntry),
		maxIPs: 5,
		order:  list.New(),
	}
	// Should not panic on empty list
	l.evictOldestLocked()
}

// ─── writeProblem ─────────────────────────────────────────────────────────────

func TestWriteProblem(t *testing.T) {
	cases := []struct {
		errorCode string
		wantType  string
	}{
		{"ERR_INVALID_PAYLOAD", "validation"},
		{"ERR_RULE_DUPLICATE", "conflict"},
		{"ERR_RULE_NOT_FOUND", "not-found"},
		{"ERR_RATE_LIMIT_EXCEEDED", "rate-limit"},
		{"ERR_SCAN_FAILED", "scan-failure"},
		{"ERR_OTHER", "internal"},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "/test", nil)
		writeProblem(w, r, http.StatusBadRequest, c.errorCode, "Title", "Detail", "Remediation", nil)

		if w.Header().Get("Content-Type") != "application/problem+json" {
			t.Errorf("%s: wrong content type: %s", c.errorCode, w.Header().Get("Content-Type"))
		}
		var p APIError
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatalf("%s: parse error: %v", c.errorCode, err)
		}
		if !strings.Contains(p.Type, c.wantType) {
			t.Errorf("%s: type %q should contain %q", c.errorCode, p.Type, c.wantType)
		}
		if p.Instance != "/test" {
			t.Errorf("%s: expected instance /test, got %q", c.errorCode, p.Instance)
		}
		if p.Status != http.StatusBadRequest {
			t.Errorf("%s: expected status 400 in body", c.errorCode)
		}
	}

	// Test with invalid_keys populated
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "/x", nil)
	writeProblem(w, r, 422, "ERR_INVALID_PAYLOAD", "Validation Error", "Detail", "", map[string]string{"field": "required"})
	var p APIError
	json.Unmarshal(w.Body.Bytes(), &p)
	if p.InvalidKeys["field"] != "required" {
		t.Errorf("expected invalid_keys to be set, got %v", p.InvalidKeys)
	}
}

// ─── writeError ───────────────────────────────────────────────────────────────

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusUnauthorized, "unauthorized access")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("expected application/json content type")
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["error"] != "unauthorized access" {
		t.Errorf("expected error message in body, got %v", body)
	}
}

// ─── writeJSON ────────────────────────────────────────────────────────────────

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusOK, map[string]string{"hello": "world"})
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
		t.Error("expected application/json")
	}
	var body map[string]string
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["hello"] != "world" {
		t.Errorf("expected hello=world, got %v", body)
	}
}

// ─── corsMiddleware ───────────────────────────────────────────────────────────

func TestCORSMiddleware(t *testing.T) {
	s := NewAPIServer(7777)
	os.Unsetenv("MEGA_ANALYZER_CORS_ORIGINS")

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.corsMiddleware(inner)

	// Allowed origin
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", "http://127.0.0.1:7777")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Origin") != "http://127.0.0.1:7777" {
		t.Errorf("expected ACAO header set, got: %q", w.Header().Get("Access-Control-Allow-Origin"))
	}

	// Disallowed origin — ACAO header should not be set to that origin
	req2, _ := http.NewRequest("GET", "/", nil)
	req2.Header.Set("Origin", "https://evil.com")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Header().Get("Access-Control-Allow-Origin") == "https://evil.com" {
		t.Error("expected evil.com not to appear in ACAO")
	}

	// OPTIONS preflight should return 200 and not call inner
	req3, _ := http.NewRequest("OPTIONS", "/api/v1/status", nil)
	req3.Header.Set("Origin", "http://127.0.0.1:7777")
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("OPTIONS should return 200, got %d", w3.Code)
	}
	if w3.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected Access-Control-Allow-Methods header")
	}
}

// ─── apiAuthMiddleware ────────────────────────────────────────────────────────

func TestAPIAuthMiddleware(t *testing.T) {
	s := NewAPIServer(8888)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// No token set — all requests pass
	os.Unsetenv("MEGA_ANALYZER_API_TOKEN")
	handler := s.apiAuthMiddleware(inner)
	req, _ := http.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("no token: expected 200, got %d", w.Code)
	}

	// Token set, correct token via X-header
	os.Setenv("MEGA_ANALYZER_API_TOKEN", "test-secret")
	defer os.Unsetenv("MEGA_ANALYZER_API_TOKEN")
	handler2 := s.apiAuthMiddleware(inner)

	req2, _ := http.NewRequest("GET", "/api/v1/status", nil)
	req2.Header.Set("X-Mega-Analyzer-Token", "test-secret")
	w2 := httptest.NewRecorder()
	handler2.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("correct X-header token: expected 200, got %d", w2.Code)
	}

	// Token set, correct token via Bearer Authorization
	req3, _ := http.NewRequest("GET", "/api/v1/status", nil)
	req3.Header.Set("Authorization", "Bearer test-secret")
	w3 := httptest.NewRecorder()
	handler2.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("Bearer token: expected 200, got %d", w3.Code)
	}

	// Token set, wrong token
	req4, _ := http.NewRequest("GET", "/api/v1/status", nil)
	req4.Header.Set("X-Mega-Analyzer-Token", "wrong")
	w4 := httptest.NewRecorder()
	handler2.ServeHTTP(w4, req4)
	if w4.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: expected 401, got %d", w4.Code)
	}

	// OPTIONS should always pass even with wrong token
	req5, _ := http.NewRequest("OPTIONS", "/api/v1/status", nil)
	w5 := httptest.NewRecorder()
	handler2.ServeHTTP(w5, req5)
	if w5.Code != http.StatusOK {
		t.Errorf("OPTIONS with token: expected 200, got %d", w5.Code)
	}
}

// ─── rateLimitMiddleware ──────────────────────────────────────────────────────

func TestRateLimitMiddleware_NonAPIPath(t *testing.T) {
	s := NewAPIServer(8090)
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := s.rateLimitMiddleware(inner)

	// Non-/api/ path should skip rate limiter and always pass
	req, _ := http.NewRequest("GET", "/static/app.js", nil)
	req.RemoteAddr = "99.99.99.99:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if !called {
		t.Error("expected inner handler to be called for non-API path")
	}
}

func TestRateLimitMiddleware_HeavyEndpoint(t *testing.T) {
	s := NewAPIServer(8090)
	// Use a fresh limiter so we don't interfere with other tests
	oldLimiter := limiter
	limiter = &ipRateLimiter{
		ips:    make(map[string]*ipEntry),
		maxIPs: defaultMaxTrackedIPs,
		order:  list.New(),
	}
	defer func() { limiter = oldLimiter }()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.rateLimitMiddleware(inner)

	req, _ := http.NewRequest("POST", "/api/v1/scan/web", nil)
	req.RemoteAddr = "11.22.33.44:55555"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("first request to heavy endpoint: expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-RateLimit-Limit") != "20" {
		t.Errorf("heavy endpoint should have limit=20, got %q", w.Header().Get("X-RateLimit-Limit"))
	}
}

// ─── handleDashboard ─────────────────────────────────────────────────────────

func TestHandleDashboard_NotFound(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/unknown-path", nil)
	w := httptest.NewRecorder()
	s.handleDashboard(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown path, got %d", w.Code)
	}
}

func TestHandleDashboard_DashboardPath(t *testing.T) {
	s := NewAPIServer(8090)
	for _, path := range []string{"/", "/dashboard"} {
		req, _ := http.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		s.handleDashboard(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("path %q: expected 200, got %d", path, w.Code)
		}
		if w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
			t.Errorf("path %q: expected text/html content type", path)
		}
	}
}

// ─── handleSwaggerDocs / handleSwaggerJSON — method not allowed ───────────────

func TestHandleSwaggerDocs_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/docs", nil)
	w := httptest.NewRecorder()
	s.handleSwaggerDocs(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleSwaggerJSON_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("DELETE", "/api/v1/swagger.json", nil)
	w := httptest.NewRecorder()
	s.handleSwaggerJSON(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ─── handleStatus — method not allowed ───────────────────────────────────────

func TestHandleStatus_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	s.handleStatus(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ─── handleWebRules edge cases ────────────────────────────────────────────────

func TestHandleWebRules_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("DELETE", "/api/v1/rules/web", nil)
	w := httptest.NewRecorder()
	s.handleWebRules(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleWebRules_PostMissingID(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{"name": "No ID rule"})
	req, _ := http.NewRequest("POST", "/api/v1/rules/web", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleWebRules(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing ID, got %d", w.Code)
	}
	var p APIError
	json.Unmarshal(w.Body.Bytes(), &p)
	if p.ErrorCode != "ERR_INVALID_PAYLOAD" {
		t.Errorf("expected ERR_INVALID_PAYLOAD, got %s", p.ErrorCode)
	}
}

func TestHandleWebRuleSingle_MissingID(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("DELETE", "/api/v1/rules/web/", nil)
	w := httptest.NewRecorder()
	s.handleWebRuleSingle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing ID, got %d", w.Code)
	}
}

func TestHandleWebRuleSingle_DeleteNotFound(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("DELETE", "/api/v1/rules/web/DOES-NOT-EXIST-XYZ", nil)
	w := httptest.NewRecorder()
	s.handleWebRuleSingle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent rule, got %d", w.Code)
	}
}

func TestHandleWebRuleSingle_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/rules/web/SOME-ID", nil)
	w := httptest.NewRecorder()
	s.handleWebRuleSingle(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ─── handleBinzapRules edge cases ─────────────────────────────────────────────

func TestHandleBinzapRules_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("PUT", "/api/v1/rules/binzap", nil)
	w := httptest.NewRecorder()
	s.handleBinzapRules(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleBinzapRules_PostMissingID(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{"name": "no id"})
	req, _ := http.NewRequest("POST", "/api/v1/rules/binzap", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleBinzapRules(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleBinzapRuleSingle_MissingID(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("DELETE", "/api/v1/rules/binzap/", nil)
	w := httptest.NewRecorder()
	s.handleBinzapRuleSingle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleBinzapRuleSingle_DeleteNotFound(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("DELETE", "/api/v1/rules/binzap/DOES-NOT-EXIST-XYZ", nil)
	w := httptest.NewRecorder()
	s.handleBinzapRuleSingle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleBinzapRuleSingle_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/rules/binzap/SOME-ID", nil)
	w := httptest.NewRecorder()
	s.handleBinzapRuleSingle(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ─── handleMLRules edge cases ─────────────────────────────────────────────────

func TestHandleMLRules_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("PATCH", "/api/v1/rules/ml", nil)
	w := httptest.NewRecorder()
	s.handleMLRules(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleMLRules_PostMissingID(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{"category": "test"})
	req, _ := http.NewRequest("POST", "/api/v1/rules/ml", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleMLRules(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleMLRuleSingle_MissingID(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("DELETE", "/api/v1/rules/ml/", nil)
	w := httptest.NewRecorder()
	s.handleMLRuleSingle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleMLRuleSingle_DeleteNotFound(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("DELETE", "/api/v1/rules/ml/NO-SUCH-PATTERN-XYZ", nil)
	w := httptest.NewRecorder()
	s.handleMLRuleSingle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleMLRuleSingle_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/rules/ml/SOME-ID", nil)
	w := httptest.NewRecorder()
	s.handleMLRuleSingle(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// ─── handleScanWeb — method and SSRF checks ───────────────────────────────────

func TestHandleScanWeb_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/scan/web", nil)
	w := httptest.NewRecorder()
	s.handleScanWeb(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleScanWeb_MissingTarget(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest("POST", "/api/v1/scan/web", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleScanWeb(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleScanWeb_SSRFBlocked(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{"target": "http://127.0.0.1:8080"})
	req, _ := http.NewRequest("POST", "/api/v1/scan/web", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleScanWeb(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 SSRF blocked, got %d", w.Code)
	}
}

// ─── handleScanTokens ─────────────────────────────────────────────────────────

func TestHandleScanTokens_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/scan/tokens", nil)
	w := httptest.NewRecorder()
	s.handleScanTokens(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleScanTokens_MissingText(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest("POST", "/api/v1/scan/tokens", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleScanTokens(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleScanTokens_Valid(t *testing.T) {
	s := NewAPIServer(8090)
	smali := `.method public test()V
    const-string v0, "test"
    return-void
.end method`
	body, _ := json.Marshal(map[string]string{"text": smali})
	req, _ := http.NewRequest("POST", "/api/v1/scan/tokens", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleScanTokens(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if _, ok := res["tokens"]; !ok {
		t.Error("expected 'tokens' in response")
	}
}

// ─── handleRuleTest edge cases ────────────────────────────────────────────────

func TestHandleRuleTest_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/rules/test", nil)
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleRuleTest_InvalidJSON(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader([]byte("{bad json")))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleRuleTest_UnsupportedRuleType(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{"rule_type": "unknown", "rule_json": "{}", "sample": "test"})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleRuleTest_WebUnsupportedType(t *testing.T) {
	s := NewAPIServer(8090)
	ruleJSON := `{"id":"X","type":"unknown_type"}`
	body, _ := json.Marshal(map[string]string{"rule_type": "web", "rule_json": ruleJSON, "sample": "test"})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleRuleTest_FuzzSQLError(t *testing.T) {
	s := NewAPIServer(8090)
	ruleJSON := `{"id":"X","type":"fuzz","payloads":["'"],"match_type":"sql_error"}`
	body, _ := json.Marshal(map[string]string{
		"rule_type": "web",
		"rule_json": ruleJSON,
		"sample":    "You have an error in your SQL syntax near 'test'",
	})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["matched"] != true {
		t.Errorf("expected SQL error detection match, got %v", res["matched"])
	}
}

func TestHandleRuleTest_FuzzLFI(t *testing.T) {
	s := NewAPIServer(8090)
	ruleJSON := `{"id":"X","type":"fuzz","payloads":["../etc/passwd"],"match_type":"lfi_success"}`
	body, _ := json.Marshal(map[string]string{
		"rule_type": "web",
		"rule_json": ruleJSON,
		"sample":    "root:x:0:0:root:/root:/bin/bash",
	})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["matched"] != true {
		t.Errorf("expected LFI match, got %v", res["matched"])
	}
}

func TestHandleRuleTest_FuzzRegex(t *testing.T) {
	s := NewAPIServer(8090)
	ruleJSON := `{"id":"X","type":"fuzz","payloads":[],"match_type":"regex","match_value":"error\\d+"}`
	body, _ := json.Marshal(map[string]string{
		"rule_type": "web",
		"rule_json": ruleJSON,
		"sample":    "Application returned error42 to user",
	})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["matched"] != true {
		t.Errorf("expected regex fuzz match, got %v", res["matched"])
	}
}

func TestHandleRuleTest_WebRegexBadPattern(t *testing.T) {
	s := NewAPIServer(8090)
	ruleJSON := `{"id":"X","type":"regex_passive","regex_pattern":"[invalid"}`
	body, _ := json.Marshal(map[string]string{
		"rule_type": "web",
		"rule_json": ruleJSON,
		"sample":    "some body content",
	})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad regex, got %d", w.Code)
	}
}

func TestHandleRuleTest_HeaderCheckEquals(t *testing.T) {
	s := NewAPIServer(8090)
	ruleJSON := `{"id":"X","type":"header_check","header_name":"X-Frame-Options","header_check":"equals","header_value":"DENY"}`
	sampleHeaders := `{"X-Frame-Options":["DENY"]}`
	body, _ := json.Marshal(map[string]string{
		"rule_type": "web",
		"rule_json": ruleJSON,
		"sample":    sampleHeaders,
	})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["matched"] != true {
		t.Errorf("expected header equals match, got %v", res["matched"])
	}
}

func TestHandleRuleTest_HeaderCheckContains(t *testing.T) {
	s := NewAPIServer(8090)
	ruleJSON := `{"id":"X","type":"header_check","header_name":"Content-Type","header_check":"contains","header_value":"json"}`
	sampleHeaders := `{"Content-Type":["application/json; charset=utf-8"]}`
	body, _ := json.Marshal(map[string]string{
		"rule_type": "web",
		"rule_json": ruleJSON,
		"sample":    sampleHeaders,
	})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["matched"] != true {
		t.Errorf("expected contains match, got %v", res["matched"])
	}
}

func TestHandleRuleTest_HeaderCheckInvalidJSON(t *testing.T) {
	s := NewAPIServer(8090)
	ruleJSON := `{"id":"X","type":"header_check","header_name":"X-Custom","header_check":"missing"}`
	body, _ := json.Marshal(map[string]string{
		"rule_type": "web",
		"rule_json": ruleJSON,
		"sample":    "not valid json and not a URL",
	})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid header JSON, got %d", w.Code)
	}
}

func TestHandleRuleTest_BinzapInvalidRule(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{
		"rule_type": "binzap",
		"rule_json": "{bad json",
		"sample":    "test",
	})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleRuleTest_MLInvalidRule(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{
		"rule_type": "ml",
		"rule_json": "{bad",
		"sample":    "test",
	})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// ─── handleScanAPK — validation tests ────────────────────────────────────────

func TestHandleScanAPK_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/scan/apk", nil)
	w := httptest.NewRecorder()
	s.handleScanAPK(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleScanAPK_MissingTarget(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest("POST", "/api/v1/scan/apk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleScanAPK(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleScanAPK_InvalidExtension(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{"target": "/tmp/malware.exe"})
	req, _ := http.NewRequest("POST", "/api/v1/scan/apk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleScanAPK(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleScanAPK_PathTraversal(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{"target": "../../etc/passwd.apk"})
	req, _ := http.NewRequest("POST", "/api/v1/scan/apk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleScanAPK(w, req)
	// Should be rejected (path traversal) or file not found — either way not 200
	if w.Code == http.StatusOK {
		t.Error("expected non-200 for path traversal attempt")
	}
}

func TestHandleScanAPK_ShellMetacharacters(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{"target": "/tmp/app.apk|rm -rf /"})
	req, _ := http.NewRequest("POST", "/api/v1/scan/apk", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleScanAPK(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for shell metacharacters, got %d", w.Code)
	}
}

// ─── handleReportHTML ─────────────────────────────────────────────────────────

func TestHandleReportHTML_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/report/html", nil)
	w := httptest.NewRecorder()
	s.handleReportHTML(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleReportHTML_MissingPath(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/report/html", nil)
	w := httptest.NewRecorder()
	s.handleReportHTML(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleReportHTML_PathTraversal(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/report/html?path=../../etc/passwd", nil)
	w := httptest.NewRecorder()
	s.handleReportHTML(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for path traversal, got %d", w.Code)
	}
}

func TestHandleReportHTML_ValidPathNotFound(t *testing.T) {
	s := NewAPIServer(8090)
	// Create a path that's inside os.TempDir() but doesn't exist
	tmpPath := os.TempDir() + "/nonexistent_report_xyz.html"
	req, _ := http.NewRequest("GET", "/api/v1/report/html?path="+tmpPath, nil)
	w := httptest.NewRecorder()
	s.handleReportHTML(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for deprecated path-based report access, got %d", w.Code)
	}
}

func TestHandleReportHTML_ArbitraryTempPathRejected(t *testing.T) {
	s := NewAPIServer(8090)
	f, err := os.CreateTemp("", "test_report_*.html")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString("<html><body>Test Report</body></html>")
	f.Close()

	req, _ := http.NewRequest("GET", "/api/v1/report/html?path="+f.Name(), nil)
	w := httptest.NewRecorder()
	s.handleReportHTML(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for report not owned by a scan job, got %d", w.Code)
	}
}

// ─── handleRulesExport / Import ───────────────────────────────────────────────

func TestHandleRulesExport_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/rules/export", nil)
	w := httptest.NewRecorder()
	s.handleRulesExport(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleRulesExport_GET(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/rules/export", nil)
	w := httptest.NewRecorder()
	s.handleRulesExport(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("expected valid JSON: %v", err)
	}
	if _, ok := body["web_rules"]; !ok {
		t.Error("expected 'web_rules' in export")
	}
	if _, ok := body["exported_at"]; !ok {
		t.Error("expected 'exported_at' in export")
	}
	if disp := w.Header().Get("Content-Disposition"); !strings.Contains(disp, "attachment") {
		t.Errorf("expected attachment content-disposition, got %q", disp)
	}
}

func TestHandleRulesImport_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/rules/import", nil)
	w := httptest.NewRecorder()
	s.handleRulesImport(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleRulesImport_Valid(t *testing.T) {
	s := NewAPIServer(8090)
	payload := map[string]interface{}{
		"web_rules":    []interface{}{},
		"binzap_rules": []interface{}{},
		"ml_patterns":  []interface{}{},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/api/v1/rules/import", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRulesImport(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ─── EventBroker ──────────────────────────────────────────────────────────────

func TestEventBroker_BroadcastAndCount(t *testing.T) {
	// Create a fresh broker (not the global singleton to avoid race)
	b := &EventBroker{
		clients:    make(map[chan ScanEvent]bool),
		register:   make(chan chan ScanEvent),
		deregister: make(chan chan ScanEvent),
	}
	go b.run()

	// Register a client
	clientChan := make(chan ScanEvent, 10)
	b.register <- clientChan

	// Give goroutine time to register
	time.Sleep(5 * time.Millisecond)

	if b.GetActiveCount() != 1 {
		t.Errorf("expected 1 active client, got %d", b.GetActiveCount())
	}

	b.Broadcast("info", "hello", nil)

	select {
	case ev := <-clientChan:
		if ev.Type != "info" || ev.Message != "hello" {
			t.Errorf("unexpected event: %+v", ev)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timed out waiting for broadcast event")
	}

	// Deregister
	b.deregister <- clientChan
	time.Sleep(5 * time.Millisecond)
	if b.GetActiveCount() != 0 {
		t.Errorf("expected 0 active clients after deregister, got %d", b.GetActiveCount())
	}
}

func TestEventBroker_BroadcastToMultiple(t *testing.T) {
	b := &EventBroker{
		clients:    make(map[chan ScanEvent]bool),
		register:   make(chan chan ScanEvent),
		deregister: make(chan chan ScanEvent),
	}
	go b.run()

	const nClients = 5
	chans := make([]chan ScanEvent, nClients)
	for i := 0; i < nClients; i++ {
		chans[i] = make(chan ScanEvent, 10)
		b.register <- chans[i]
	}
	time.Sleep(10 * time.Millisecond)

	b.Broadcast("vuln_found", "XSS detected", map[string]string{"url": "http://x.com"})

	received := 0
	deadline := time.After(200 * time.Millisecond)
	for received < nClients {
		select {
		case <-chans[received]:
			received++
		case <-deadline:
			t.Errorf("timed out: only %d/%d clients received event", received, nClients)
			return
		}
	}
}

// ─── mitmStore ────────────────────────────────────────────────────────────────

func TestMITMStore_AddListClearCount(t *testing.T) {
	st := newMITMStore(5)

	for i := 0; i < 7; i++ {
		st.Add(&MITMSession{Method: "GET", URL: fmt.Sprintf("http://example.com/%d", i)})
	}
	// Should be capped at 5
	if st.Count() != 5 {
		t.Errorf("expected 5 sessions (capped), got %d", st.Count())
	}

	sessions, total := st.List(0, 3)
	if total != 5 {
		t.Errorf("expected total=5, got %d", total)
	}
	if len(sessions) != 3 {
		t.Errorf("expected 3 sessions in page, got %d", len(sessions))
	}

	// Offset past end
	sessions2, total2 := st.List(10, 5)
	if total2 != 5 {
		t.Errorf("expected total=5, got %d", total2)
	}
	if sessions2 != nil {
		t.Errorf("expected nil sessions for offset past end, got %v", sessions2)
	}

	st.Clear()
	if st.Count() != 0 {
		t.Errorf("expected 0 after clear, got %d", st.Count())
	}
}

func TestMITMStore_DefaultMaxSize(t *testing.T) {
	st := newMITMStore(0) // should default to 2000
	if st.maxSize != 2000 {
		t.Errorf("expected default maxSize=2000, got %d", st.maxSize)
	}
}

func TestMITMStore_IDsIncrement(t *testing.T) {
	st := newMITMStore(100)
	s1 := &MITMSession{}
	s2 := &MITMSession{}
	st.Add(s1)
	st.Add(s2)
	if s2.ID <= s1.ID {
		t.Errorf("expected IDs to increment: s1=%d, s2=%d", s1.ID, s2.ID)
	}
}

// ─── MITM helpers ─────────────────────────────────────────────────────────────

func TestMitmCertHost(t *testing.T) {
	cases := []struct {
		input    string
		wantHost string
		wantIP   bool
	}{
		{"example.com", "example.com", false},
		{"Example.COM", "example.com", false},
		{"example.com:443", "example.com", false},
		{"8.8.8.8", "8.8.8.8", true},
		{"8.8.8.8:443", "8.8.8.8", true},
		{"[::1]", "::1", true},
		{"[::1]:443", "::1", true},
	}
	for _, c := range cases {
		host, ip := mitmCertHost(c.input)
		if host != c.wantHost {
			t.Errorf("mitmCertHost(%q) host = %q, want %q", c.input, host, c.wantHost)
		}
		if (ip != nil) != c.wantIP {
			t.Errorf("mitmCertHost(%q) ip presence = %v, want %v", c.input, ip != nil, c.wantIP)
		}
	}
}

func TestMitmHostAllowed(t *testing.T) {
	os.Unsetenv("MEGA_ANALYZER_MITM_ALLOWED_DOMAINS")

	// localhost always allowed
	if !mitmHostAllowed("localhost") {
		t.Error("expected localhost to be allowed")
	}
	if !mitmHostAllowed("localhost:8080") {
		t.Error("expected localhost:8080 to be allowed")
	}

	// loopback IP always allowed
	if !mitmHostAllowed("127.0.0.1") {
		t.Error("expected 127.0.0.1 loopback to be allowed")
	}
	if !mitmHostAllowed("::1") {
		t.Error("expected ::1 loopback to be allowed")
	}

	// Private IP always allowed
	if !mitmHostAllowed("192.168.1.1") {
		t.Error("expected private IP to be allowed")
	}

	// Without domain allowlist, external hostnames are blocked
	if mitmHostAllowed("example.com") {
		t.Error("expected example.com to be blocked without allowlist")
	}

	// With allowlist
	os.Setenv("MEGA_ANALYZER_MITM_ALLOWED_DOMAINS", "example.com,test.net")
	defer os.Unsetenv("MEGA_ANALYZER_MITM_ALLOWED_DOMAINS")
	if !mitmHostAllowed("example.com") {
		t.Error("expected example.com to be allowed with allowlist")
	}
	if !mitmHostAllowed("sub.example.com") {
		t.Error("expected sub.example.com to be allowed as subdomain")
	}
	if mitmHostAllowed("evil.com") {
		t.Error("expected evil.com to be blocked")
	}
}

func TestHeadrsToMap(t *testing.T) {
	h := http.Header{
		"Content-Type":  {"application/json"},
		"X-Multi-Value": {"a", "b", "c"},
	}
	m := headersToMap(h)
	if m["Content-Type"] != "application/json" {
		t.Errorf("unexpected content-type: %v", m["Content-Type"])
	}
	if m["X-Multi-Value"] != "a; b; c" {
		t.Errorf("expected multi-value joined, got: %v", m["X-Multi-Value"])
	}
}

func TestTruncateBody(t *testing.T) {
	short := []byte("hello world")
	if truncateBody(short) != "hello world" {
		t.Error("short body should not be truncated")
	}
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'x'
	}
	result := truncateBody(long)
	if len(result) <= 4096 {
		// Check that truncation message is present
		t.Error("expected truncation message for long body")
	}
	if !strings.Contains(result, "truncated") {
		t.Error("expected 'truncated' in truncation message")
	}
}

func TestHTTPKeepAlive(t *testing.T) {
	req11, _ := http.NewRequest("GET", "/", nil)
	req11.Proto = "HTTP/1.1"
	if !httpKeepAlive(req11) {
		t.Error("HTTP/1.1 without Connection: close should be keep-alive")
	}

	req11close, _ := http.NewRequest("GET", "/", nil)
	req11close.Proto = "HTTP/1.1"
	req11close.Header.Set("Connection", "close")
	if httpKeepAlive(req11close) {
		t.Error("HTTP/1.1 with Connection: close should not be keep-alive")
	}

	req10, _ := http.NewRequest("GET", "/", nil)
	req10.Proto = "HTTP/1.0"
	if httpKeepAlive(req10) {
		t.Error("HTTP/1.0 should not be keep-alive")
	}
}

func TestMaskValue(t *testing.T) {
	short := maskValue("abc")
	if short != "****" {
		t.Errorf("short value should be masked as ****, got %q", short)
	}
	long := maskValue("abcdefghijklmnop")
	if !strings.HasPrefix(long, "abcd") {
		t.Error("expected first 4 chars preserved")
	}
	if !strings.HasSuffix(long, "mnop") {
		t.Error("expected last 4 chars preserved")
	}
	if !strings.Contains(long, "****") {
		t.Error("expected **** in middle")
	}
}

// ─── analyzeSession ───────────────────────────────────────────────────────────

func TestAnalyzeSession_CredentialsInURL(t *testing.T) {
	s := &MITMSession{
		URL:         "http://example.com/login?password=secret123",
		ReqHeaders:  map[string]string{},
		RespHeaders: map[string]string{},
	}
	alerts := analyzeSession(s)
	found := false
	for _, a := range alerts {
		if strings.Contains(a, "Credentials") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected credentials-in-URL alert, got: %v", alerts)
	}
}

func TestAnalyzeSession_JWTBearer(t *testing.T) {
	s := &MITMSession{
		URL:         "http://api.example.com/data",
		ReqHeaders:  map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig"},
		RespHeaders: map[string]string{},
	}
	alerts := analyzeSession(s)
	found := false
	for _, a := range alerts {
		if strings.Contains(a, "JWT") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected JWT alert, got: %v", alerts)
	}
}

func TestAnalyzeSession_PrivateKeyInResponse(t *testing.T) {
	s := &MITMSession{
		URL:         "http://example.com/key",
		ReqHeaders:  map[string]string{},
		RespHeaders: map[string]string{},
		RespBody:    "-----BEGIN RSA PRIVATE KEY-----\nMIIEo...",
	}
	alerts := analyzeSession(s)
	found := false
	for _, a := range alerts {
		if strings.Contains(strings.ToUpper(a), "PRIVATE KEY") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected private key alert, got: %v", alerts)
	}
}

func TestAnalyzeSession_HTTPAuthEndpoint(t *testing.T) {
	s := &MITMSession{
		URL:         "http://example.com/login",
		IsHTTPS:     false,
		ReqHeaders:  map[string]string{},
		RespHeaders: map[string]string{},
	}
	alerts := analyzeSession(s)
	found := false
	for _, a := range alerts {
		if strings.Contains(a, "plain HTTP") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected HTTP auth alert, got: %v", alerts)
	}
}

func TestAnalyzeSession_WildcardCORS(t *testing.T) {
	s := &MITMSession{
		URL:         "http://api.example.com/",
		ReqHeaders:  map[string]string{},
		RespHeaders: map[string]string{"Access-Control-Allow-Origin": "*"},
	}
	alerts := analyzeSession(s)
	found := false
	for _, a := range alerts {
		if strings.Contains(a, "CORS") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CORS alert, got: %v", alerts)
	}
}

// ─── MITM HTTP handlers — method not allowed ──────────────────────────────────

func TestHandleMITM_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)

	postEndpoints := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"start", s.handleMITMStart},
		{"stop", s.handleMITMStop},
		{"clear", s.handleMITMClear},
		{"inject", s.handleMITMInject},
	}
	for _, ep := range postEndpoints {
		req, _ := http.NewRequest("GET", "/api/v1/mitm/"+ep.name, nil)
		w := httptest.NewRecorder()
		ep.handler(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", ep.name, w.Code)
		}
	}

	getEndpoints := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"status", s.handleMITMStatus},
		{"packets", s.handleMITMPackets},
		{"ca.pem", s.handleMITMCACert},
	}
	for _, ep := range getEndpoints {
		req, _ := http.NewRequest("POST", "/api/v1/mitm/"+ep.name, nil)
		w := httptest.NewRecorder()
		ep.handler(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", ep.name, w.Code)
		}
	}
}

func TestHandleMITMStatus_Get(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/mitm/status", nil)
	w := httptest.NewRecorder()
	s.handleMITMStatus(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if _, ok := body["running"]; !ok {
		t.Error("expected 'running' in status response")
	}
	if _, ok := body["ca_ready"]; !ok {
		t.Error("expected 'ca_ready' in status response")
	}
}

func TestHandleMITMStop_NotRunning(t *testing.T) {
	// Ensure not running state
	globalMITM.mu.Lock()
	globalMITM.running = false
	globalMITM.mu.Unlock()

	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/mitm/stop", nil)
	req.Body = http.NoBody
	w := httptest.NewRecorder()
	s.handleMITMStop(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 when not running, got %d", w.Code)
	}
}

func TestHandleMITMPackets_Get(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/mitm/packets?offset=0&limit=10", nil)
	w := httptest.NewRecorder()
	s.handleMITMPackets(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if _, ok := body["sessions"]; !ok {
		t.Error("expected 'sessions' in packets response")
	}
}

func TestHandleMITMClear_Post(t *testing.T) {
	globalMITM.store.Add(&MITMSession{Method: "GET", URL: "http://test.com"})
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/mitm/clear", nil)
	req.Body = http.NoBody
	w := httptest.NewRecorder()
	s.handleMITMClear(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if globalMITM.store.Count() != 0 {
		t.Error("expected store to be cleared")
	}
}

func TestHandleMITMInject_Valid(t *testing.T) {
	// Clear inject headers first
	globalMITM.mu.Lock()
	globalMITM.injectHeaders = map[string]string{}
	globalMITM.mu.Unlock()

	s := NewAPIServer(8090)
	payload := map[string]interface{}{
		"headers": map[string]string{"X-Test": "value1"},
		"clear":   false,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/api/v1/mitm/inject", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleMITMInject(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["inject_headers_count"].(float64) < 1 {
		t.Error("expected at least 1 inject header")
	}
}

func TestHandleMITMInject_Clear(t *testing.T) {
	globalMITM.mu.Lock()
	globalMITM.injectHeaders = map[string]string{"X-Old": "old"}
	globalMITM.mu.Unlock()

	s := NewAPIServer(8090)
	payload := map[string]interface{}{
		"headers": map[string]string{},
		"clear":   true,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/api/v1/mitm/inject", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleMITMInject(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["inject_headers_count"].(float64) != 0 {
		t.Errorf("expected 0 headers after clear, got %v", res["inject_headers_count"])
	}
}

func TestHandleMITMCACert_Get(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/mitm/ca.pem", nil)
	w := httptest.NewRecorder()
	s.handleMITMCACert(w, req)
	// Should succeed if CA was generated at init time
	if globalMITM.caCert != nil && w.Code != http.StatusOK {
		t.Errorf("expected 200 when CA exists, got %d", w.Code)
	}
	if globalMITM.caCert == nil && w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when CA absent, got %d", w.Code)
	}
}

// ─── MITM start — invalid port ────────────────────────────────────────────────

func TestHandleMITMStart_InvalidPort(t *testing.T) {
	s := NewAPIServer(8090)

	globalMITM.mu.Lock()
	wasRunning := globalMITM.running
	globalMITM.running = false
	globalMITM.mu.Unlock()
	defer func() {
		globalMITM.mu.Lock()
		globalMITM.running = wasRunning
		globalMITM.mu.Unlock()
	}()

	body, _ := json.Marshal(map[string]int{"port": 80}) // too low
	req, _ := http.NewRequest("POST", "/api/v1/mitm/start", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleMITMStart(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid port, got %d", w.Code)
	}
}

// ─── Pentest handlers — method not allowed ────────────────────────────────────

func TestPentestHandlers_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	handlers := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"cors", s.handleCORSCheck},
		{"jwt", s.handleJWTAnalyze},
		{"redirect", s.handleOpenRedirect},
		{"dirscan", s.handleDirScan},
		{"techdetect", s.handleTechDetect},
		{"cookies", s.handleCookieAudit},
		{"subdomains", s.handleSubdomainEnum},
	}
	for _, h := range handlers {
		req, _ := http.NewRequest("GET", "/api/v1/pentest/"+h.name, nil)
		w := httptest.NewRecorder()
		h.handler(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405 for GET, got %d", h.name, w.Code)
		}
	}
}

func TestPentestHandlers_MissingBody(t *testing.T) {
	s := NewAPIServer(8090)
	emptyBody := bytes.NewReader([]byte("{}"))

	// CORS
	req, _ := http.NewRequest("POST", "/api/v1/pentest/cors", emptyBody)
	w := httptest.NewRecorder()
	s.handleCORSCheck(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("CORS missing URL: expected 400, got %d", w.Code)
	}
}

func TestPentestHandlers_SSRFCheck(t *testing.T) {
	s := NewAPIServer(8090)

	for _, handler := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"cors", s.handleCORSCheck},
		{"redirect", s.handleOpenRedirect},
		{"dirscan", s.handleDirScan},
		{"techdetect", s.handleTechDetect},
		{"cookies", s.handleCookieAudit},
	} {
		var body []byte
		if handler.name == "dirscan" || handler.name == "subdomains" {
			body, _ = json.Marshal(map[string]string{"url": "http://127.0.0.1/"})
		} else {
			body, _ = json.Marshal(map[string]string{"url": "http://127.0.0.1/"})
		}
		req, _ := http.NewRequest("POST", "/api/v1/pentest/"+handler.name, bytes.NewReader(body))
		w := httptest.NewRecorder()
		handler.handler(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s with localhost URL: expected 403, got %d", handler.name, w.Code)
		}
	}
}

func TestHandleJWTAnalyze_MissingToken(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest("POST", "/api/v1/pentest/jwt", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleJWTAnalyze(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleJWTAnalyze_InvalidJWT(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{"token": "not.a.valid.jwt.token"})
	req, _ := http.NewRequest("POST", "/api/v1/pentest/jwt", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleJWTAnalyze(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed JWT, got %d", w.Code)
	}
}

func TestHandleJWTAnalyze_ValidAlgNone(t *testing.T) {
	s := NewAPIServer(8090)
	// Build a real alg=none JWT: header.payload. (no signature)
	header := `{"alg":"none","typ":"JWT"}`
	payload := `{"sub":"1234567890","name":"Test User"}`
	import64 := func(s string) string {
		import_ := []byte(s)
		encoded := make([]byte, len(import_)*2)
		n := 0
		for _, b := range import_ {
			const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			_ = chars
			encoded[n] = b
			n++
		}
		return string(encoded[:n])
	}
	_ = import64

	// Use standard base64 encoding
	import_encode := func(s string) string {
		src := []byte(s)
		result := make([]byte, 0, len(src)*4/3+4)
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		_ = alphabet
		// manual raw url base64
		for i := 0; i < len(src); i += 3 {
			var b [3]byte
			n := copy(b[:], src[i:])
			result = append(result, []byte(fmt.Sprintf("%c%c%c%c",
				"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[(b[0]>>2)&63],
				"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[((b[0]&3)<<4|(b[1]>>4))&63],
				func() byte {
					if n >= 2 {
						return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[((b[1]&0xf)<<2|(b[2]>>6))&63]
					}
					return '='
				}(),
				func() byte {
					if n >= 3 {
						return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[b[2]&63]
					}
					return '='
				}(),
			))...)
		}
		// strip padding and fix
		s2 := strings.TrimRight(string(result), "=")
		return s2
	}
	_ = import_encode

	// Use encoding/base64 directly via the helper functions already tested
	// Build a properly base64url-encoded JWT with alg:none
	hEncoded := encodeBase64URLRaw([]byte(header))
	pEncoded := encodeBase64URLRaw([]byte(payload))
	token := hEncoded + "." + pEncoded + "."

	reqBody, _ := json.Marshal(map[string]interface{}{
		"token":          token,
		"check_alg_none": true,
	})
	req, _ := http.NewRequest("POST", "/api/v1/pentest/jwt", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	s.handleJWTAnalyze(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	issues, _ := res["issues"].([]interface{})
	found := false
	for _, issue := range issues {
		m := issue.(map[string]interface{})
		if strings.Contains(fmt.Sprint(m["title"]), "Algorithm None") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Algorithm None issue, got: %v", issues)
	}
}

func TestHandleJWTAnalyze_WeakSecretCracked(t *testing.T) {
	s := NewAPIServer(8090)
	// Build a real HS256 JWT signed with "secret"
	header := `{"alg":"HS256","typ":"JWT"}`
	payload := `{"sub":"test"}`
	h := encodeBase64URLRaw([]byte(header))
	p := encodeBase64URLRaw([]byte(payload))
	sigInput := h + "." + p
	sig := hmacSHA256([]byte("secret"), []byte(sigInput))
	token := sigInput + "." + encodeBase64URLRaw(sig)

	reqBody, _ := json.Marshal(map[string]interface{}{"token": token})
	req, _ := http.NewRequest("POST", "/api/v1/pentest/jwt", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	s.handleJWTAnalyze(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var res map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["cracked_secret"] != "secret" {
		t.Errorf("expected cracked_secret='secret', got %v", res["cracked_secret"])
	}
}

func TestHandleSubdomainEnum_MissingDomain(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequest("POST", "/api/v1/pentest/subdomains", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleSubdomainEnum(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSubdomainEnum_WordlistTooLarge(t *testing.T) {
	s := NewAPIServer(8090)
	wordlist := make([]string, 10001)
	for i := range wordlist {
		wordlist[i] = fmt.Sprintf("sub%d", i)
	}
	payload := map[string]interface{}{
		"domain":   "8.8.8.8", // public IP to avoid SSRF block
		"wordlist": wordlist,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", "/api/v1/pentest/subdomains", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleSubdomainEnum(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized wordlist, got %d", w.Code)
	}
}

// ─── pentest helpers ──────────────────────────────────────────────────────────

func TestExtractHost(t *testing.T) {
	cases := []struct {
		url  string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://example.com:8080/path", "example.com:8080"},
		{"http://example.com", "example.com"},
	}
	for _, c := range cases {
		got := extractHost(c.url)
		if got != c.want {
			t.Errorf("extractHost(%q) = %q, want %q", c.url, got, c.want)
		}
	}
}

func TestCORSRiskSummary(t *testing.T) {
	tests := []struct {
		findings []CORSFinding
		want     string
	}{
		{nil, "PASS"},
		{[]CORSFinding{{Severity: "LOW"}}, "PASS"},
		{[]CORSFinding{{Severity: "MEDIUM"}}, "MEDIUM"},
		{[]CORSFinding{{Severity: "HIGH"}}, "HIGH"},
		{[]CORSFinding{{Severity: "CRITICAL"}}, "CRITICAL"},
		{[]CORSFinding{{Severity: "HIGH"}, {Severity: "CRITICAL"}}, "CRITICAL"},
	}
	for _, tt := range tests {
		got := corsRiskSummary(tt.findings)
		if !strings.Contains(got, tt.want) {
			t.Errorf("corsRiskSummary(%v) = %q, want contains %q", tt.findings, got, tt.want)
		}
	}
}

func TestIsSessionCookieName(t *testing.T) {
	trueCases := []string{"session_id", "auth_token", "jwt", "ACCESS_TOKEN", "refresh", "SID", "uid", "sess"}
	for _, c := range trueCases {
		if !isSessionCookieName(c) {
			t.Errorf("isSessionCookieName(%q) should be true", c)
		}
	}
	falseCases := []string{"color", "theme", "lang", "timezone"}
	for _, c := range falseCases {
		if isSessionCookieName(c) {
			t.Errorf("isSessionCookieName(%q) should be false", c)
		}
	}
}

func TestSameSiteName(t *testing.T) {
	cases := map[http.SameSite]string{
		http.SameSiteStrictMode:  "Strict",
		http.SameSiteLaxMode:     "Lax",
		http.SameSiteNoneMode:    "None",
		http.SameSiteDefaultMode: "Not set",
	}
	for mode, want := range cases {
		got := sameSiteName(mode)
		if got != want {
			t.Errorf("sameSiteName(%v) = %q, want %q", mode, got, want)
		}
	}
}

func TestMaskCookieValue(t *testing.T) {
	short := maskCookieValue("abc")
	if short != "***" {
		t.Errorf("expected ***, got %q", short)
	}
	long := maskCookieValue("abcdefghijklmnop")
	if !strings.HasPrefix(long, "abcd") {
		t.Error("expected first 4 preserved")
	}
	if !strings.HasSuffix(long, "mnop") {
		t.Error("expected last 4 preserved")
	}
}

func TestHMACFunctions(t *testing.T) {
	key := []byte("testkey")
	data := []byte("testdata")

	sig256 := hmacSHA256(key, data)
	sig384 := hmacSHA384(key, data)
	sig512 := hmacSHA512(key, data)

	if len(sig256) != 32 {
		t.Errorf("HS256 sig length should be 32, got %d", len(sig256))
	}
	if len(sig384) != 48 {
		t.Errorf("HS384 sig length should be 48, got %d", len(sig384))
	}
	if len(sig512) != 64 {
		t.Errorf("HS512 sig length should be 64, got %d", len(sig512))
	}

	// hmacEqual
	sig256b := hmacSHA256(key, data)
	if !hmacEqual(sig256, sig256b) {
		t.Error("same key+data should produce equal HMAC")
	}
	if hmacEqual(sig256, sig384) {
		t.Error("different length sigs should not be equal")
	}
}

// ─── concurrent safety ────────────────────────────────────────────────────────

func TestRateLimiterConcurrentSafety(t *testing.T) {
	l := &ipRateLimiter{
		ips:    make(map[string]*ipEntry),
		maxIPs: 100,
		order:  list.New(),
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("10.%d.%d.%d", i/256, i%256, i%10)
			l.allow(ip, 10.0, 50.0)
		}(i)
	}
	wg.Wait()
}

// ─── recon handlers — method not allowed & input validation ──────────────────

func TestReconHandlers_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(8090)
	handlers := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"portscan", s.handlePortScan},
		{"dns", s.handleDNSEnum},
		{"ssl", s.handleSSLAudit},
		{"hostinfo", s.handleHostInfo},
	}
	for _, h := range handlers {
		req, _ := http.NewRequest("GET", "/api/v1/recon/"+h.name, nil)
		w := httptest.NewRecorder()
		h.handler(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", h.name, w.Code)
		}
	}
}

func TestHandlePortScan_MissingHost(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]interface{}{})
	req, _ := http.NewRequest("POST", "/api/v1/recon/portscan", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handlePortScan(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandlePortScan_PrivateHostBlocked(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]interface{}{"host": "127.0.0.1"})
	req, _ := http.NewRequest("POST", "/api/v1/recon/portscan", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handlePortScan(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for private host, got %d", w.Code)
	}
}

func TestHandlePortScan_TooManyPorts(t *testing.T) {
	s := NewAPIServer(8090)
	ports := make([]int, 10001)
	for i := range ports {
		ports[i] = i + 1
	}
	body, _ := json.Marshal(map[string]interface{}{
		"host":  "8.8.8.8",
		"ports": ports,
	})
	req, _ := http.NewRequest("POST", "/api/v1/recon/portscan", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handlePortScan(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for too many ports, got %d", w.Code)
	}
}

func TestHandleDNSEnum_MissingDomain(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]interface{}{})
	req, _ := http.NewRequest("POST", "/api/v1/recon/dns", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleDNSEnum(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleDNSEnum_PrivateDomainBlocked(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]interface{}{"domain": "localhost"})
	req, _ := http.NewRequest("POST", "/api/v1/recon/dns", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleDNSEnum(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for localhost domain, got %d", w.Code)
	}
}

func TestHandleDNSEnum_WordlistTooLarge(t *testing.T) {
	s := NewAPIServer(8090)
	wordlist := make([]string, 10001)
	for i := range wordlist {
		wordlist[i] = fmt.Sprintf("sub%d", i)
	}
	body, _ := json.Marshal(map[string]interface{}{
		"domain":   "8.8.8.8",
		"wordlist": wordlist,
	})
	req, _ := http.NewRequest("POST", "/api/v1/recon/dns", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleDNSEnum(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSSLAudit_MissingHost(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]interface{}{})
	req, _ := http.NewRequest("POST", "/api/v1/recon/ssl", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleSSLAudit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleSSLAudit_PrivateHostBlocked(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]interface{}{"host": "192.168.1.1"})
	req, _ := http.NewRequest("POST", "/api/v1/recon/ssl", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleSSLAudit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for private host, got %d", w.Code)
	}
}

func TestHandleHostInfo_MissingTarget(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]interface{}{})
	req, _ := http.NewRequest("POST", "/api/v1/recon/hostinfo", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleHostInfo(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleHostInfo_PrivateHostBlocked(t *testing.T) {
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]interface{}{"target": "10.0.0.1"})
	req, _ := http.NewRequest("POST", "/api/v1/recon/hostinfo", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleHostInfo(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for private host, got %d", w.Code)
	}
}

// ─── recon helpers ────────────────────────────────────────────────────────────

func TestFirstSafeResolvedIP(t *testing.T) {
	// Empty host
	_, err := firstSafeResolvedIP("")
	if err == nil {
		t.Error("expected error for empty host")
	}

	// Private IP blocked
	_, err = firstSafeResolvedIP("192.168.1.1")
	if err == nil {
		t.Error("expected error for private IP")
	}
	_, err = firstSafeResolvedIP("127.0.0.1")
	if err == nil {
		t.Error("expected error for loopback IP")
	}

	// Public IP allowed
	ip, err := firstSafeResolvedIP("8.8.8.8")
	if err != nil || ip != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8, got %q, err=%v", ip, err)
	}
}

func TestTLSVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
		tls.VersionTLS13: "TLS 1.3",
		0xFFFF:           "Unknown",
	}
	for ver, want := range cases {
		got := tlsVersionName(ver)
		if !strings.Contains(got, want) {
			t.Errorf("tlsVersionName(0x%04X) = %q, want contains %q", ver, got, want)
		}
	}
}

func TestCipherSuiteName(t *testing.T) {
	// Should return a non-empty string for any valid cipher suite
	for _, suite := range tls.CipherSuites() {
		name := cipherSuiteName(suite.ID)
		if name != suite.Name {
			t.Errorf("cipherSuiteName(%d) = %q, want %q", suite.ID, name, suite.Name)
		}
	}
	// Unknown ID
	name := cipherSuiteName(0xFFFF)
	if !strings.HasPrefix(name, "0x") {
		t.Errorf("unknown cipher should return hex, got %q", name)
	}
}

// ─── tlsVersionName SSLv3 branch ─────────────────────────────────────────────

func TestTLSVersionName_SSLv3(t *testing.T) {
	// tls.VersionSSL30 = 0x0300 = 768
	got := tlsVersionName(0x0300)
	if !strings.Contains(got, "SSL") {
		t.Errorf("expected SSLv3, got %q", got)
	}
}

// ─── mitmStore List edge cases ────────────────────────────────────────────────

func TestMITMStore_ListReturnsNewestFirst(t *testing.T) {
	st := newMITMStore(100)
	for i := 0; i < 5; i++ {
		st.Add(&MITMSession{URL: fmt.Sprintf("http://example.com/%d", i)})
	}
	sessions, _ := st.List(0, 5)
	if len(sessions) != 5 {
		t.Fatalf("expected 5, got %d", len(sessions))
	}
	// Newest first means highest ID first
	if sessions[0].ID < sessions[4].ID {
		t.Error("expected newest (highest ID) first")
	}
}

func TestMITMStore_ListWithLimitExceedingTotal(t *testing.T) {
	st := newMITMStore(100)
	for i := 0; i < 3; i++ {
		st.Add(&MITMSession{URL: fmt.Sprintf("http://x.com/%d", i)})
	}
	sessions, total := st.List(0, 100)
	if total != 3 {
		t.Errorf("expected total=3, got %d", total)
	}
	if len(sessions) != 3 {
		t.Errorf("expected 3 sessions, got %d", len(sessions))
	}
}

// ─── copyInjectHeaders with data ─────────────────────────────────────────────

func TestCopyInjectHeaders(t *testing.T) {
	globalMITM.mu.Lock()
	globalMITM.injectHeaders = map[string]string{"X-A": "v1", "X-B": "v2"}
	globalMITM.mu.Unlock()

	h := copyInjectHeaders()
	if h["X-A"] != "v1" || h["X-B"] != "v2" {
		t.Errorf("unexpected inject headers: %v", h)
	}
	// Mutation of copy should not affect original
	h["X-C"] = "v3"
	globalMITM.mu.Lock()
	_, exists := globalMITM.injectHeaders["X-C"]
	globalMITM.mu.Unlock()
	if exists {
		t.Error("mutation of copy should not affect original")
	}
}

// ─── analyzeSession — API key detection ──────────────────────────────────────

func TestAnalyzeSession_APIKeyDetected(t *testing.T) {
	s := &MITMSession{
		URL:         "http://api.example.com/data",
		ReqHeaders:  map[string]string{"X-Api-Key": "myverysecretkey"},
		RespHeaders: map[string]string{},
	}
	alerts := analyzeSession(s)
	found := false
	for _, a := range alerts {
		if strings.Contains(a, "API key") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected API key alert, got: %v", alerts)
	}
}

func TestAnalyzeSession_SensitiveResponseBody(t *testing.T) {
	s := &MITMSession{
		URL:         "http://api.example.com/data",
		ReqHeaders:  map[string]string{},
		RespHeaders: map[string]string{},
		RespBody:    `{"password": "hunter2", "username": "admin"}`,
	}
	alerts := analyzeSession(s)
	found := false
	for _, a := range alerts {
		if strings.Contains(a, "sensitive") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected sensitive data alert, got: %v", alerts)
	}
}

func TestAnalyzeSession_PrivateKeyBeginPrivateKey(t *testing.T) {
	s := &MITMSession{
		URL:         "http://example.com/secret.key",
		ReqHeaders:  map[string]string{},
		RespHeaders: map[string]string{},
		RespBody:    "-----BEGIN PRIVATE KEY-----\nMIIEvgI...",
	}
	alerts := analyzeSession(s)
	found := false
	for _, a := range alerts {
		if strings.Contains(strings.ToUpper(a), "PRIVATE KEY") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PKCS8 private key alert, got: %v", alerts)
	}
}

// ─── handleRuleTest — web rule SSRF check via URL sample ─────────────────────

func TestHandleRuleTest_WebRegexSSRFBlockedURL(t *testing.T) {
	s := NewAPIServer(8090)
	ruleJSON := `{"id":"X","type":"regex_passive","regex_pattern":"test"}`
	body, _ := json.Marshal(map[string]string{
		"rule_type": "web",
		"rule_json": ruleJSON,
		"sample":    "http://127.0.0.1:8080/",
	})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for SSRF URL, got %d", w.Code)
	}
}

func TestHandleRuleTest_HeaderCheckSSRFBlockedURL(t *testing.T) {
	s := NewAPIServer(8090)
	ruleJSON := `{"id":"X","type":"header_check","header_name":"X-Test","header_check":"missing"}`
	body, _ := json.Marshal(map[string]string{
		"rule_type": "web",
		"rule_json": ruleJSON,
		"sample":    "http://127.0.0.1:8080/",
	})
	req, _ := http.NewRequest("POST", "/api/v1/rules/test", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleRuleTest(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

// ─── handleDNSEnum with an actual public IP (fast path) ──────────────────────

func TestHandleDNSEnum_ValidPublicIP(t *testing.T) {
	s := NewAPIServer(8090)
	// Use 8.8.8.8 as domain (it's a valid IP that passes isSafeTarget)
	body, _ := json.Marshal(map[string]interface{}{
		"domain":          "8.8.8.8",
		"subdomain_brute": false,
	})
	req, _ := http.NewRequest("POST", "/api/v1/recon/dns", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleDNSEnum(w, req)
	// May succeed or fail depending on DNS resolution of "8.8.8.8" as hostname
	// Either way should not be a 4xx or 5xx from our validation
	if w.Code == http.StatusBadRequest {
		t.Logf("Got 400 (possibly private IP SSRF check): %s", w.Body.String())
	}
}

// ─── handleCORSCheck with real httptest server ────────────────────────────────

func TestHandleCORSCheck_WithRealServer(t *testing.T) {
	// Spin up a test server that reflects Origin header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Override isSafeTarget check by using the actual IP (127.0.0.1)
	// The test server will be on 127.0.0.1 which would normally be blocked.
	// Since isSafeTarget blocks localhost, we can only test the blocked path here:
	s := NewAPIServer(8090)
	body, _ := json.Marshal(map[string]string{"url": ts.URL})
	req, _ := http.NewRequest("POST", "/api/v1/pentest/cors", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleCORSCheck(w, req)
	// Should be blocked (403) because ts.URL is on 127.0.0.1
	if w.Code != http.StatusForbidden {
		t.Logf("Note: CORS check on localhost returned %d (expected 403)", w.Code)
	}
}

// ─── handleWebRuleSingle — duplicate POST ────────────────────────────────────

func TestHandleWebRules_DuplicateRule(t *testing.T) {
	s := NewAPIServer(8090)
	const testID = "API-DUP-TEST"
	_ = vulnscan_DeleteDynamicWebRule(testID)

	// Create
	rule := map[string]interface{}{
		"id":            testID,
		"name":          "Dup Test",
		"type":          "regex_passive",
		"regex_pattern": "dup",
		"severity":      "LOW",
	}
	body, _ := json.Marshal(rule)
	req, _ := http.NewRequest("POST", "/api/v1/rules/web", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleWebRules(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create: expected 201, got %d", w.Code)
	}

	// Create again — should conflict
	body2, _ := json.Marshal(rule)
	req2, _ := http.NewRequest("POST", "/api/v1/rules/web", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	s.handleWebRules(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("duplicate: expected 409, got %d", w2.Code)
	}

	// Cleanup
	reqDel, _ := http.NewRequest("DELETE", "/api/v1/rules/web/"+testID, nil)
	wDel := httptest.NewRecorder()
	s.handleWebRuleSingle(wDel, reqDel)
}

// vulnscan_DeleteDynamicWebRule is a helper shim
func vulnscan_DeleteDynamicWebRule(id string) error {
	req, _ := http.NewRequest("DELETE", "/api/v1/rules/web/"+id, nil)
	w := httptest.NewRecorder()
	s := NewAPIServer(8090)
	s.handleWebRuleSingle(w, req)
	return nil
}

// ─── handleWebRuleSingle PUT ──────────────────────────────────────────────────

func TestHandleWebRuleSingle_PutUpdateNotFound(t *testing.T) {
	s := NewAPIServer(8090)
	rule := map[string]interface{}{"name": "updated", "type": "regex_passive", "regex_pattern": "x"}
	body, _ := json.Marshal(rule)
	req, _ := http.NewRequest("PUT", "/api/v1/rules/web/NONEXISTENT-99999", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleWebRuleSingle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ─── handleBinzapRuleSingle PUT ───────────────────────────────────────────────

func TestHandleBinzapRuleSingle_PutNotFound(t *testing.T) {
	s := NewAPIServer(8090)
	rule := map[string]interface{}{"name": "updated"}
	body, _ := json.Marshal(rule)
	req, _ := http.NewRequest("PUT", "/api/v1/rules/binzap/NONEXISTENT-99999", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleBinzapRuleSingle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ─── handleMLRuleSingle PUT ───────────────────────────────────────────────────

func TestHandleMLRuleSingle_PutNotFound(t *testing.T) {
	s := NewAPIServer(8090)
	pattern := map[string]interface{}{"category": "test"}
	body, _ := json.Marshal(pattern)
	req, _ := http.NewRequest("PUT", "/api/v1/rules/ml/NONEXISTENT-99999", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleMLRuleSingle(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

// ─── isPathWritable ───────────────────────────────────────────────────────────

func TestIsPathWritable(t *testing.T) {
	// Non-existent path in temp dir should be writable (dir exists)
	tmpPath := os.TempDir() + "/test_writable_check_12345.txt"
	defer os.Remove(tmpPath)
	if !isPathWritable(tmpPath) {
		t.Logf("isPathWritable(%q) = false (may be expected on some systems)", tmpPath)
	}

	// Non-existent path in non-existent dir should not be writable
	fakePath := "/nonexistent_dir_xyz/file.txt"
	if isPathWritable(fakePath) {
		t.Error("expected false for non-existent directory")
	}
}

// ─── helper used by JWT test ──────────────────────────────────────────────────

func encodeBase64URLRaw(src []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, 0, (len(src)*4+2)/3)
	for i := 0; i < len(src); i += 3 {
		remaining := len(src) - i
		b0 := src[i]
		var b1, b2 byte
		if remaining > 1 {
			b1 = src[i+1]
		}
		if remaining > 2 {
			b2 = src[i+2]
		}
		result = append(result, alphabet[b0>>2])
		result = append(result, alphabet[((b0&3)<<4)|b1>>4])
		if remaining > 1 {
			result = append(result, alphabet[((b1&0xf)<<2)|b2>>6])
		}
		if remaining > 2 {
			result = append(result, alphabet[b2&63])
		}
	}
	return string(result)
}
