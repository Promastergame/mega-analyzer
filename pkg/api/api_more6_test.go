package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestAPIServer_RulesSingle_MethodNotAllowed(t *testing.T) {
	s := NewAPIServer(0)

	// handleWebRuleSingle
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/web/test-id", nil)
	rr := httptest.NewRecorder()
	s.handleWebRuleSingle(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}

	// handleBinzapRuleSingle
	req = httptest.NewRequest(http.MethodGet, "/api/v1/rules/binzap/test-id", nil)
	rr = httptest.NewRecorder()
	s.handleBinzapRuleSingle(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}

	// handleMLRuleSingle
	req = httptest.NewRequest(http.MethodGet, "/api/v1/rules/ml/test-id", nil)
	rr = httptest.NewRecorder()
	s.handleMLRuleSingle(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestAPIServer_RulesSingle_InvalidJSON(t *testing.T) {
	s := NewAPIServer(0)

	// handleWebRuleSingle
	req := httptest.NewRequest(http.MethodPut, "/api/v1/rules/web/test-id", bytes.NewReader([]byte(`{invalid-json`)))
	rr := httptest.NewRecorder()
	s.handleWebRuleSingle(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}

	// handleBinzapRuleSingle
	req = httptest.NewRequest(http.MethodPut, "/api/v1/rules/binzap/test-id", bytes.NewReader([]byte(`{invalid-json`)))
	rr = httptest.NewRecorder()
	s.handleBinzapRuleSingle(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}

	// handleMLRuleSingle
	req = httptest.NewRequest(http.MethodPut, "/api/v1/rules/ml/test-id", bytes.NewReader([]byte(`{invalid-json`)))
	rr = httptest.NewRecorder()
	s.handleMLRuleSingle(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAPIServer_RulesSingle_MissingID(t *testing.T) {
	s := NewAPIServer(0)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/rules/web/", nil)
	rr := httptest.NewRecorder()
	s.handleWebRuleSingle(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAPIServer_RulesExport(t *testing.T) {
	s := NewAPIServer(0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/export", nil)
	rr := httptest.NewRecorder()
	s.handleRulesExport(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestAPIServer_RulesImport_Invalid(t *testing.T) {
	s := NewAPIServer(0)

	// GET not allowed
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/import", nil)
	rr := httptest.NewRecorder()
	s.handleRulesImport(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}

	// POST bad JSON
	req = httptest.NewRequest(http.MethodPost, "/api/v1/rules/import", bytes.NewReader([]byte(`{invalid`)))
	rr = httptest.NewRecorder()
	s.handleRulesImport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAPIServer_RuleTest_Invalid(t *testing.T) {
	s := NewAPIServer(0)

	// GET not allowed
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/test", nil)
	rr := httptest.NewRecorder()
	s.handleRuleTest(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}

	// POST bad JSON
	req = httptest.NewRequest(http.MethodPost, "/api/v1/rules/test", bytes.NewReader([]byte(`{invalid`)))
	rr = httptest.NewRecorder()
	s.handleRuleTest(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAPIServer_ScanAPK_Invalid(t *testing.T) {
	s := NewAPIServer(0)

	// GET not allowed
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan/apk", nil)
	rr := httptest.NewRecorder()
	s.handleScanAPK(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}

	// POST bad payload / missing multipart file
	req = httptest.NewRequest(http.MethodPost, "/api/v1/scan/apk", bytes.NewReader([]byte(`invalid-form`)))
	rr = httptest.NewRecorder()
	s.handleScanAPK(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestAPIServer_ReportHTML_NotFound(t *testing.T) {
	s := NewAPIServer(0)

	tempReport := filepath.Join(os.TempDir(), "nonexistent-id.html")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/report/some-id?path="+tempReport, nil)
	rr := httptest.NewRecorder()
	s.handleReportHTML(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for deprecated path-based report access, got %d", rr.Code)
	}
}

func TestAPIServer_OriginAllowed(t *testing.T) {
	s := NewAPIServer(0)
	if !s.originAllowed("http://localhost:0") {
		t.Error("expected true for localhost:0")
	}
	if !s.originAllowed("http://127.0.0.1:0") {
		t.Error("expected true for 127.0.0.1:0")
	}
	if s.originAllowed("http://malicious.com") {
		t.Error("expected false for malicious domain")
	}
}

func TestAPIServer_Middlewares(t *testing.T) {
	s := NewAPIServer(0)

	// Rate limit middleware
	handler := s.rateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("rate limit expected 200, got %d", rr.Code)
	}

	// CORS middleware
	handler = s.corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "http://localhost:0")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("CORS expected 200, got %d", rr.Code)
	}
}
