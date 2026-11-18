package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebMenuEndpoints(t *testing.T) {
	mux := http.NewServeMux()
	token := "test-secret-token-12345"
	registerWebMenu(mux, token)

	tests := []struct {
		name         string
		path         string
		method       string
		expectedCode int
		contains     []string
	}{
		{
			name:         "root menu",
			path:         "/",
			method:       "GET",
			expectedCode: http.StatusOK,
			contains:     []string{"Веб-меню DecisionAI", "test-secret-token-12345", "/playground", "/games", "/collect"},
		},
		{
			name:         "menu alias",
			path:         "/menu",
			method:       "GET",
			expectedCode: http.StatusOK,
			contains:     []string{"Веб-меню DecisionAI", "SYSTEM ONE"},
		},
		{
			name:         "text page",
			path:         "/text",
			method:       "GET",
			expectedCode: http.StatusOK,
			contains:     []string{"test-secret-token-12345"},
		},
		{
			name:         "eval page",
			path:         "/eval",
			method:       "GET",
			expectedCode: http.StatusOK,
			contains:     []string{"<!doctype html>"},
		},
		{
			name:         "rules page",
			path:         "/rules",
			method:       "GET",
			expectedCode: http.StatusOK,
			contains:     []string{"test-secret-token-12345"},
		},
		{
			name:         "eval report json",
			path:         "/api/eval-report",
			method:       "GET",
			expectedCode: http.StatusOK,
			contains:     []string{"suites"},
		},
		{
			name:         "post to menu not allowed",
			path:         "/",
			method:       "POST",
			expectedCode: http.StatusMethodNotAllowed,
		},
		{
			name:         "unknown path",
			path:         "/unknown-tool",
			method:       "GET",
			expectedCode: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tc.expectedCode {
				t.Fatalf("expected status %d, got %d", tc.expectedCode, rec.Code)
			}
			body := rec.Body.String()
			for _, substr := range tc.contains {
				if !strings.Contains(body, substr) {
					t.Errorf("response for %s missing expected substring %q", tc.path, substr)
				}
			}
			if tc.expectedCode == http.StatusOK && tc.path != "/api/eval-report" {
				csp := rec.Header().Get("Content-Security-Policy")
				if csp == "" {
					t.Errorf("missing Content-Security-Policy for %s", tc.path)
				}
				if strings.Contains(body, "__TOKEN__") || strings.Contains(body, "__SESSION_TOKEN__") {
					t.Errorf("unsubstituted token placeholder found in %s", tc.path)
				}
			}
		})
	}
}

func TestEvalReportJSONIsValid(t *testing.T) {
	mux := http.NewServeMux()
	registerWebMenu(mux, "token")

	req := httptest.NewRequest("GET", "/api/eval-report", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var rep map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&rep); err != nil {
		t.Fatalf("eval-report is not valid JSON: %v", err)
	}
}
