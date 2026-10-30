package vulnscan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckAPI_UsesOnlySafeTraceProbe(t *testing.T) {
	methods := make(chan string, 2)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods <- r.Method
		if r.Method == http.MethodTrace {
			fmt.Fprintf(w, "%s: %s", "X-Mega-Analyzer-Trace-Probe", r.Header.Get("X-Mega-Analyzer-Trace-Probe"))
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	vulns := s.checkAPI()
	if len(vulns) != 1 || vulns[0].ID != "WS-API-001" {
		t.Fatalf("expected TRACE finding, got %#v", vulns)
	}

	select {
	case method := <-methods:
		if method != http.MethodTrace {
			t.Fatalf("unsafe method %q was sent", method)
		}
	default:
		t.Fatal("expected a TRACE probe")
	}
	select {
	case method := <-methods:
		t.Fatalf("unexpected extra probe %q", method)
	default:
	}
}

func TestCheckAPI_RequiresEchoOfUniqueProbe(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("TRACE / HTTP/1.1"))
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	if vulns := s.checkAPI(); len(vulns) != 0 {
		t.Fatalf("generic TRACE-looking body must not be reported, got %#v", vulns)
	}
}
