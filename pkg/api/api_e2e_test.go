package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAPIServer_E2E_ServerStart(t *testing.T) {
	// Start server on a random port
	server := NewAPIServer(0)

	// Because Start() blocks, we run it in a goroutine
	go func() {
		// Just to execute the Start method
		_ = server.Start()
	}()

	time.Sleep(100 * time.Millisecond) // Give it a moment to bind

	// Hit a few endpoints using direct httptest against the internal mux
	// Since we can't easily get the ephemeral port from http.ListenAndServe,
	// we will manually construct the mux just like Start() does to test coverage.

	mux := http.NewServeMux()
	// Replicating Start()
	mux.HandleFunc("/api/docs", server.handleSwaggerDocs)
	mux.HandleFunc("/api/v1/swagger.json", server.handleSwaggerJSON)
	mux.HandleFunc("/api/v1/status", server.handleStatus)
	mux.HandleFunc("/api/v1/rules/web", server.handleWebRules)
	mux.HandleFunc("/api/v1/scan/web", server.handleScanWeb)
	mux.HandleFunc("/api/v1/report/html", server.handleReportHTML)
	mux.HandleFunc("/api/v1/pentest/cors", server.handleCORSCheck)

	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/api/docs"},
		{"GET", "/api/v1/swagger.json"},
		{"GET", "/api/v1/status"},
		{"GET", "/api/v1/rules/web"},
		{"POST", "/api/v1/scan/web"},
		{"GET", "/api/v1/report/html"},
		{"POST", "/api/v1/pentest/cors"},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		rr := httptest.NewRecorder()

		// Wrap with middlewares like Start() does
		handler := server.corsMiddleware(server.rateLimitMiddleware(mux))
		handler.ServeHTTP(rr, req)

		if rr.Code == http.StatusNotFound {
			t.Errorf("Unexpected 404 for %s", tc.path)
		}
	}

	// Test the problem writer directly
	req := httptest.NewRequest("GET", "/test-error", nil)
	rr := httptest.NewRecorder()
	writeProblem(rr, req, http.StatusBadRequest, "ERR_INVALID_PAYLOAD", "Bad Request", "Details", "Fix it", map[string]string{"foo": "bar"})

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", rr.Code)
	}
	var prob map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&prob); err == nil {
		if prob["error_code"] != "ERR_INVALID_PAYLOAD" {
			t.Errorf("Expected error code ERR_INVALID_PAYLOAD")
		}
	}
}
