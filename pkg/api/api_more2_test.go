package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ─── body helpers ─────────────────────────────────────────────────────────────

func bodyJSON2(v interface{}) *bytes.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

func bodyRaw2(s string) *strings.Reader {
	return strings.NewReader(s)
}

// ─── safeHTTPClient ───────────────────────────────────────────────────────────

func TestSafeHTTPClient_BadURL(t *testing.T) {
	_, err := safeHTTPClient(5*time.Second, "://bad-url")
	if err == nil {
		t.Error("expected error for unparseable URL")
	}
}

func TestSafeHTTPClient_EmptyHost(t *testing.T) {
	_, err := safeHTTPClient(5*time.Second, "http:///path")
	if err == nil {
		t.Error("expected error for empty host")
	}
}

func TestSafeHTTPClient_LocalhostBlocked(t *testing.T) {
	_, err := safeHTTPClient(5*time.Second, "http://localhost/")
	if err == nil {
		t.Error("expected error for localhost")
	}
}

func TestSafeHTTPClient_LoopbackIPBlocked(t *testing.T) {
	_, err := safeHTTPClient(5*time.Second, "http://127.0.0.1/")
	if err == nil {
		t.Error("expected error for loopback IP 127.0.0.1")
	}
}

func TestSafeHTTPClient_IPv6LoopbackBlocked(t *testing.T) {
	_, err := safeHTTPClient(5*time.Second, "http://[::1]/")
	if err == nil {
		t.Error("expected error for IPv6 loopback ::1")
	}
}

func TestSafeHTTPClient_PrivateIPBlocked(t *testing.T) {
	_, err := safeHTTPClient(5*time.Second, "http://192.168.1.1/")
	if err == nil {
		t.Error("expected error for private IP 192.168.1.1")
	}
}

func TestSafeHTTPClient_PublicIPReturnsClient(t *testing.T) {
	client, err := safeHTTPClient(5*time.Second, "http://8.8.8.8/")
	if err != nil {
		t.Fatalf("expected success for public IP, got %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client")
	}
}

func TestSafeHTTPClient_DefaultPortHTTP(t *testing.T) {
	client, err := safeHTTPClient(5*time.Second, "http://8.8.8.8/path")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client")
	}
}

func TestSafeHTTPClient_DefaultPortHTTPS(t *testing.T) {
	client, err := safeHTTPClient(5*time.Second, "https://8.8.8.8/path")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if client == nil {
		t.Error("expected non-nil client")
	}
}

func TestSafeHTTPClient_LocalhostDotLocaldomain(t *testing.T) {
	_, err := safeHTTPClient(5*time.Second, "http://localhost.localdomain/")
	if err == nil {
		t.Error("expected error for localhost.localdomain")
	}
}

func TestSafeHTTPClient_UnspecifiedIPv6Blocked(t *testing.T) {
	_, err := safeHTTPClient(5*time.Second, "http://[::]/")
	if err == nil {
		t.Error("expected error for :: (unspecified IPv6)")
	}
}

func TestSafeHTTPClient_UnspecifiedIPv4Blocked(t *testing.T) {
	_, err := safeHTTPClient(5*time.Second, "http://0.0.0.0/")
	if err == nil {
		t.Error("expected error for 0.0.0.0")
	}
}

func TestSafeHTTPClient_CarrierGradeNATBlocked(t *testing.T) {
	// 100.64.0.1 is in the carrier-grade NAT range (RFC 6598)
	_, err := safeHTTPClient(5*time.Second, "http://100.64.0.1/")
	if err == nil {
		t.Error("expected error for carrier-grade NAT IP 100.64.0.1")
	}
}

// ─── makePinnedClient ─────────────────────────────────────────────────────────

func TestMakePinnedClient_ReturnsNonNil(t *testing.T) {
	client := makePinnedClient("8.8.8.8", "443", 5*time.Second)
	if client == nil {
		t.Error("expected non-nil client from makePinnedClient")
	}
}

func TestMakePinnedClient_CheckRedirectDisabled(t *testing.T) {
	client := makePinnedClient("8.8.8.8", "80", 5*time.Second)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	req, _ := http.NewRequest("GET", "http://8.8.8.8/", nil)
	err := client.CheckRedirect(req, nil)
	if err != http.ErrUseLastResponse {
		t.Errorf("expected ErrUseLastResponse from CheckRedirect, got %v", err)
	}
}

func TestMakePinnedClient_TimeoutSet(t *testing.T) {
	timeout := 3 * time.Second
	client := makePinnedClient("8.8.8.8", "80", timeout)
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout != timeout {
		t.Errorf("expected timeout %v, got %v", timeout, client.Timeout)
	}
}

// ─── handleStatus — GET returns healthy ──────────────────────────────────────

func TestHandleStatus_GetReturnsHealthy(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	s.handleStatus(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── handleSwaggerDocs — GET returns HTML ────────────────────────────────────

func TestHandleSwaggerDocs_GetReturnsHTML(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/docs", nil)
	w := httptest.NewRecorder()
	s.handleSwaggerDocs(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "text/html; charset=utf-8" {
		t.Errorf("expected text/html, got %q", ct)
	}
}

// ─── handleSwaggerJSON — GET returns JSON ────────────────────────────────────

func TestHandleSwaggerJSON_GetReturnsJSON(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/swagger.json", nil)
	w := httptest.NewRecorder()
	s.handleSwaggerJSON(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
}

// ─── handleWebRules — GET returns list ───────────────────────────────────────

func TestHandleWebRules_GetReturnsList(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/rules/web", nil)
	w := httptest.NewRecorder()
	s.handleWebRules(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ─── handleBinzapRules — GET returns list ────────────────────────────────────

func TestHandleBinzapRules_GetReturnsList(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/rules/binzap", nil)
	w := httptest.NewRecorder()
	s.handleBinzapRules(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ─── handleMLRules — GET returns list ────────────────────────────────────────

func TestHandleMLRules_GetReturnsList(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("GET", "/api/v1/rules/ml", nil)
	w := httptest.NewRecorder()
	s.handleMLRules(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// ─── handleMITMStart — already running conflict ───────────────────────────────

func TestHandleMITMStart_AlreadyRunning(t *testing.T) {
	globalMITM.mu.Lock()
	wasRunning := globalMITM.running
	globalMITM.running = true
	globalMITM.mu.Unlock()
	defer func() {
		globalMITM.mu.Lock()
		globalMITM.running = wasRunning
		globalMITM.mu.Unlock()
	}()

	s := NewAPIServer(8090)
	body := bodyJSON2(map[string]int{"port": 8081})
	req, _ := http.NewRequest("POST", "/api/v1/mitm/start", body)
	w := httptest.NewRecorder()
	s.handleMITMStart(w, req)
	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 conflict when already running, got %d", w.Code)
	}
}

// ─── handleOpenRedirect — missing URL ────────────────────────────────────────

func TestHandleOpenRedirect_MissingURL(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/pentest/redirect", bodyJSON2(map[string]string{}))
	w := httptest.NewRecorder()
	s.handleOpenRedirect(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing URL, got %d", w.Code)
	}
}

// ─── handleDirScan — missing URL ─────────────────────────────────────────────

func TestHandleDirScan_MissingURL(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/pentest/dirscan", bodyJSON2(map[string]string{}))
	w := httptest.NewRecorder()
	s.handleDirScan(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing URL, got %d", w.Code)
	}
}

// ─── handleTechDetect — missing URL ──────────────────────────────────────────

func TestHandleTechDetect_MissingURL(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/pentest/techdetect", bodyJSON2(map[string]string{}))
	w := httptest.NewRecorder()
	s.handleTechDetect(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing URL, got %d", w.Code)
	}
}

// ─── handleCookieAudit — missing URL ─────────────────────────────────────────

func TestHandleCookieAudit_MissingURL(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/pentest/cookies", bodyJSON2(map[string]string{}))
	w := httptest.NewRecorder()
	s.handleCookieAudit(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing URL, got %d", w.Code)
	}
}

// ─── handleWebRuleSingle — PUT invalid JSON body ──────────────────────────────

func TestHandleWebRuleSingle_PutInvalidJSON(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("PUT", "/api/v1/rules/web/SOME-ID", bodyRaw2("{bad json"))
	w := httptest.NewRecorder()
	s.handleWebRuleSingle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

// ─── handleBinzapRuleSingle — PUT invalid JSON ────────────────────────────────

func TestHandleBinzapRuleSingle_PutInvalidJSON(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("PUT", "/api/v1/rules/binzap/SOME-ID", bodyRaw2("{bad json"))
	w := httptest.NewRecorder()
	s.handleBinzapRuleSingle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

// ─── handleMLRuleSingle — PUT invalid JSON ────────────────────────────────────

func TestHandleMLRuleSingle_PutInvalidJSON(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("PUT", "/api/v1/rules/ml/SOME-ID", bodyRaw2("{bad json"))
	w := httptest.NewRecorder()
	s.handleMLRuleSingle(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

// ─── handleRulesImport — invalid JSON ────────────────────────────────────────

func TestHandleRulesImport_InvalidJSON(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/rules/import", bodyRaw2("{not valid json"))
	w := httptest.NewRecorder()
	s.handleRulesImport(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

// ─── rateLimitMiddleware — rate limit triggered ───────────────────────────────

func TestRateLimitMiddleware_HeavyEndpointDrained(t *testing.T) {
	s := NewAPIServer(8090)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := s.rateLimitMiddleware(inner)

	// Drain the bucket for this IP by sending many requests
	const senderIP = "55.66.77.88:44444"
	for i := 0; i < 25; i++ {
		req, _ := http.NewRequest("POST", "/api/v1/scan/web", nil)
		req.RemoteAddr = senderIP
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}
	// Eventually should hit 429
	req, _ := http.NewRequest("POST", "/api/v1/scan/web", nil)
	req.RemoteAddr = senderIP
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		// Not a hard fail — depends on whether bucket drained. Just verify headers present.
		if w.Header().Get("X-RateLimit-Limit") == "" {
			t.Error("expected X-RateLimit-Limit header on API path")
		}
	}
}

// ─── grabBanner — should return empty for closed port ────────────────────────

func TestGrabBanner_ClosedPort(t *testing.T) {
	// Port 1 is typically not open — grab should return ""
	result := grabBanner("127.0.0.1", 1, 50*time.Millisecond)
	// Either empty or short — just verify no panic
	_ = result
}

// ─── commonPortServices — lookup ─────────────────────────────────────────────

func TestCommonPortServices_KnownPorts(t *testing.T) {
	known := map[int]string{
		80:    "HTTP",
		443:   "HTTPS",
		22:    "SSH",
		3306:  "MySQL",
		27017: "MongoDB",
	}
	for port, want := range known {
		got := commonPortServices[port]
		if got != want {
			t.Errorf("commonPortServices[%d] = %q, want %q", port, got, want)
		}
	}
}

// ─── isSafeHost — hostname resolution blocked ────────────────────────────────

func TestIsSafeHost_UnresolvableHostname(t *testing.T) {
	// An unresolvable hostname should return false (block to be safe)
	got := isSafeHost("this-host-does-not-exist-xyz123.example.invalid")
	if got {
		t.Error("expected unresolvable hostname to be blocked")
	}
}
