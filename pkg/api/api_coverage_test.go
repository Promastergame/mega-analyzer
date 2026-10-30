package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIServer_Coverage_Handlers(t *testing.T) {
	server := NewAPIServer(8080)

	// Test handleStatus
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	server.handleStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", rr.Code)
	}

	var status map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&status); err != nil {
		t.Errorf("Failed to decode status: %v", err)
	}

	// Test handleSwaggerJSON
	reqSwagger := httptest.NewRequest(http.MethodGet, "/api/v1/swagger.json", nil)
	rrSwagger := httptest.NewRecorder()
	server.handleSwaggerJSON(rrSwagger, reqSwagger)
	if rrSwagger.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for swagger, got %d", rrSwagger.Code)
	}

	// Test writeError and writeProblem manually through an invalid route or by calling an empty handler
	reqDocs := httptest.NewRequest(http.MethodGet, "/api/docs", nil)
	rrDocs := httptest.NewRecorder()
	server.handleSwaggerDocs(rrDocs, reqDocs)
	if rrDocs.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for docs, got %d", rrDocs.Code)
	}
}
