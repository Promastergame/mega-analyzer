package vulnscan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// gatewayScanner builds a Scanner whose client traffic flows through the real
// RequestGateway (no transport substitution) against the given test server.
func gatewayScanner(t *testing.T, ts *httptest.Server) *Scanner {
	t.Helper()
	s, err := NewScanner(ts.URL)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	s.Gateway.Telemetry = NewScanTelemetry()
	return s
}

func TestGatewayInjectsAuthCredentials(t *testing.T) {
	var gotAuth, gotCookie string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
	}))
	defer ts.Close()

	s := gatewayScanner(t, ts)
	s.Config.AuthBearer = "tok-123"
	s.Config.AuthCookie = "session=abc"

	resp, err := s.Client.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tok-123")
	}
	if gotCookie != "session=abc" {
		t.Errorf("Cookie = %q, want %q", gotCookie, "session=abc")
	}
	if n := s.Gateway.Telemetry.RequestsSent.Load(); n != 1 {
		t.Errorf("telemetry requests = %d, want 1", n)
	}
	if n := s.Gateway.Telemetry.ResponsesOK.Load(); n != 1 {
		t.Errorf("telemetry ok responses = %d, want 1", n)
	}
}

func TestGatewayAnonymousOptOut(t *testing.T) {
	var gotAuth, gotCookie string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
	}))
	defer ts.Close()

	s := gatewayScanner(t, ts)
	s.Config.AuthBearer = "tok-123"
	s.Config.AuthCookie = "session=abc"

	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req = WithAnonymousRequest(req)
	resp, err := s.Client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty for anonymous probe", gotAuth)
	}
	if gotCookie != "" {
		t.Errorf("Cookie = %q, want empty for anonymous probe", gotCookie)
	}
}

func TestGatewayPreservesExplicitHeaders(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer ts.Close()

	s := gatewayScanner(t, ts)
	s.Config.AuthBearer = "tok-123"

	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secondary-identity")
	resp, err := s.Client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer secondary-identity" {
		t.Errorf("Authorization = %q, want explicit header preserved", gotAuth)
	}
}

func TestGatewayAIMDBackpressure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "slow down")
	}))
	defer ts.Close()

	s := gatewayScanner(t, ts)
	s.Gateway.AIMD = NewAIMDController(8, 16)

	resp, err := s.Client.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if c := s.Gateway.AIMD.Concurrency(); c != 4 {
		t.Errorf("AIMD concurrency after 429 = %d, want 4 (halved from 8)", c)
	}
}
