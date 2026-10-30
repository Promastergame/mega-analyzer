package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostGuardRejectsRebindingOnEveryMethod(t *testing.T) {
	t.Setenv("MEGA_ANALYZER_API_BIND", "127.0.0.1")
	t.Setenv("MEGA_ANALYZER_API_TOKEN", "")
	s := NewAPIServer(5000)
	h := s.hostGuard(s.apiAuthMiddleware(s.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))))
	for _, method := range []string{"GET", "POST", "OPTIONS", "HEAD"} {
		for _, host := range []string{"attacker.invalid:5000", "127.0.0.1.attacker.invalid:5000", "localhost:5001", "", "localhost@attacker.invalid:5000"} {
			r := httptest.NewRequest(method, "/api/v1/mitm/packets", nil)
			r.Host = host
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)
			if rr.Code != 403 {
				t.Errorf("%s host %q: got %d", method, host, rr.Code)
			}
		}
	}
	for _, host := range []string{"localhost:5000", "127.0.0.1:5000", "[::1]:5000"} {
		r := httptest.NewRequest("GET", "/api/v1/status", nil)
		r.Host = host
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if rr.Code != 204 {
			t.Errorf("local host %q: got %d", host, rr.Code)
		}
	}
}

func TestHostGuardNetworkNameRequiresAllowlistAndToken(t *testing.T) {
	t.Setenv("MEGA_ANALYZER_API_BIND", "0.0.0.0")
	t.Setenv("MEGA_ANALYZER_API_TOKEN", "test-token")
	t.Setenv("MEGA_ANALYZER_API_HOSTS", "analyzer.internal")
	s := NewAPIServer(5000)
	h := s.hostGuard(s.apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })))
	for _, tc := range []struct {
		host, token string
		code        int
	}{
		{"analyzer.internal:5000", "test-token", 204},
		{"analyzer.internal:8443", "test-token", 204},
		{"127.0.0.1:32768", "test-token", 204},
		{"analyzer.internal:5000", "", 401},
		{"other.internal:5000", "test-token", 403},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Host = tc.host
		r.Header.Set("X-Mega-Analyzer-Token", tc.token)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if rr.Code != tc.code {
			t.Errorf("host=%s token=%q: got %d", tc.host, tc.token, rr.Code)
		}
	}
}

func TestDocsShellCanLoadBeforeEnteringToken(t *testing.T) {
	t.Setenv("MEGA_ANALYZER_API_TOKEN", "test-token")
	s := NewAPIServer(5000)
	h := s.apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		path string
		code int
	}{{"/api/docs", 204}, {"/api/docs/assets/openapi.js", 204}, {"/api/v1/swagger.json", 401}, {"/api/v1/status", 401}} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", tc.path, nil))
		if rr.Code != tc.code {
			t.Errorf("%s: got %d", tc.path, rr.Code)
		}
	}
}
