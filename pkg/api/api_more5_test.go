package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── pentest_handlers.go: error paths ─────────────────────────────────────

func TestHandleCORSCheck_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pentest/cors", nil)
	rr := httptest.NewRecorder()
	s.handleCORSCheck(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleCORSCheck_MissingURL(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"url": ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pentest/cors", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleCORSCheck(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleCORSCheck_SSRFBlocked(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"url": "http://127.0.0.1/"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pentest/cors", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleCORSCheck(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 SSRF, got %d", rr.Code)
	}
}

func TestHandleOpenRedirect_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pentest/open-redirect", nil)
	rr := httptest.NewRecorder()
	s.handleOpenRedirect(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleOpenRedirect_SSRF(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"url": "http://10.0.0.1/"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pentest/open-redirect", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleOpenRedirect(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 SSRF, got %d", rr.Code)
	}
}

func TestHandleDirScan_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pentest/dirscan", nil)
	rr := httptest.NewRecorder()
	s.handleDirScan(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleDirScan_SSRF(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"url": "http://192.168.0.1/"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pentest/dirscan", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleDirScan(rr, req)
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusBadRequest {
		t.Errorf("expected 403/400 SSRF, got %d", rr.Code)
	}
}

func TestHandleTechDetect_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pentest/techdetect", nil)
	rr := httptest.NewRecorder()
	s.handleTechDetect(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleTechDetect_SSRF(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"url": "http://localhost/"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pentest/techdetect", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleTechDetect(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 SSRF, got %d", rr.Code)
	}
}

func TestHandleCookieAudit_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pentest/cookie-audit", nil)
	rr := httptest.NewRecorder()
	s.handleCookieAudit(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleCookieAudit_SSRF(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"url": "http://10.0.0.1/"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pentest/cookie-audit", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleCookieAudit(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 SSRF, got %d", rr.Code)
	}
}

func TestHandleSubdomainEnum_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pentest/subdomain-enum", nil)
	rr := httptest.NewRecorder()
	s.handleSubdomainEnum(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// ─── recon_handlers.go: error paths ───────────────────────────────────────

func TestHandlePortScan_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/recon/portscan", nil)
	rr := httptest.NewRecorder()
	s.handlePortScan(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandlePortScan_SSRF(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"host": "127.0.0.1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/recon/portscan", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handlePortScan(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleDNSEnum_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/recon/dns", nil)
	rr := httptest.NewRecorder()
	s.handleDNSEnum(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleSSLAudit_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/recon/ssl", nil)
	rr := httptest.NewRecorder()
	s.handleSSLAudit(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleSSLAudit_PrivateIP(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"host": "192.168.1.1"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/recon/ssl", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleSSLAudit(rr, req)
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusBadRequest {
		t.Errorf("expected 403/400 for private IP, got %d", rr.Code)
	}
}

func TestHandleHostInfo_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/recon/hostinfo", nil)
	rr := httptest.NewRecorder()
	s.handleHostInfo(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleHostInfo_MissingHost(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"target": ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/recon/hostinfo", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleHostInfo(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleHostInfo_PrivateIP(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"target": "10.10.10.10"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/recon/hostinfo", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleHostInfo(rr, req)
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusBadRequest {
		t.Errorf("expected 403/400, got %d", rr.Code)
	}
}

// ─── helper functions ──────────────────────────────────────────────────────

func TestCorsRiskSummary_Critical(t *testing.T) {
	findings := []CORSFinding{{Severity: "CRITICAL"}}
	res := corsRiskSummary(findings)
	if !strings.Contains(res, "CRITICAL") {
		t.Errorf("expected CRITICAL in summary, got %q", res)
	}
}

func TestCorsRiskSummary_High(t *testing.T) {
	findings := []CORSFinding{{Severity: "HIGH"}}
	res := corsRiskSummary(findings)
	if !strings.Contains(res, "HIGH") {
		t.Errorf("expected HIGH in summary, got %q", res)
	}
}

func TestCorsRiskSummary_Medium(t *testing.T) {
	findings := []CORSFinding{{Severity: "MEDIUM"}}
	res := corsRiskSummary(findings)
	if !strings.Contains(res, "MEDIUM") {
		t.Errorf("expected MEDIUM in summary, got %q", res)
	}
}

func TestCorsRiskSummary_Pass(t *testing.T) {
	res := corsRiskSummary(nil)
	if !strings.Contains(res, "PASS") {
		t.Errorf("expected PASS in summary, got %q", res)
	}
}

func TestFirstSafeResolvedIP_PrivateIP(t *testing.T) {
	_, err := firstSafeResolvedIP("192.168.1.1")
	if err == nil {
		t.Error("expected error for private IP")
	}
}

func TestFirstSafeResolvedIP_Loopback(t *testing.T) {
	_, err := firstSafeResolvedIP("127.0.0.1")
	if err == nil {
		t.Error("expected error for loopback IP")
	}
}

func TestFirstSafeResolvedIP_Empty(t *testing.T) {
	_, err := firstSafeResolvedIP("")
	if err == nil {
		t.Error("expected error for empty host")
	}
}

func TestHandleJWTAnalyze_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pentest/jwt", nil)
	rr := httptest.NewRecorder()
	s.handleJWTAnalyze(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleJWTAnalyze_InvalidToken(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"token": "not.a.jwt"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pentest/jwt", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleJWTAnalyze(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JWT, got %d", rr.Code)
	}
}

func TestHandleScanWeb_BadMethod(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan/web", nil)
	rr := httptest.NewRecorder()
	s.handleScanWeb(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHandleScanWeb_MissingURL(t *testing.T) {
	s := NewAPIServer(0)
	body, _ := json.Marshal(map[string]string{"url": ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scan/web", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleScanWeb(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}
