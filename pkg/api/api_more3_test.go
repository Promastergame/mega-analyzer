package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleBinzapRules_PostInvalidJSON(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/rules/binzap", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	s.handleBinzapRules(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleMLRules_PostInvalidJSON(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/rules/ml", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	s.handleMLRules(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestHandleScanAPK_InvalidJSON(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/scan/apk", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	s.handleScanAPK(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestHandleMITMStart_PrivilegedPort(t *testing.T) {
	globalMITM.mu.Lock()
	wasRunning := globalMITM.running
	globalMITM.running = false
	globalMITM.mu.Unlock()
	defer func() {
		globalMITM.mu.Lock()
		globalMITM.running = wasRunning
		globalMITM.mu.Unlock()
	}()

	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/mitm/start", strings.NewReader(`{"port": 80}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleMITMStart(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for privileged port, got %d", w.Code)
	}
}

func TestHandleWebRules_PostInvalidJSON(t *testing.T) {
	s := NewAPIServer(8090)
	req, _ := http.NewRequest("POST", "/api/v1/rules/web", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	s.handleWebRules(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
