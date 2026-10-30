package vulnscan

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRunConfirmationPass_ReproducedEvidenceKept(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.LogFunc = func(string) {}

	vulns := []Vulnerability{{
		ID: "TEST-001", Severity: SeverityHigh, URL: "http://example.com/x",
		Evidence: "sig",
		Probe:    &ReplayProbe{Retry: func(*Scanner) (bool, error) { return true, nil }},
	}}

	kept := s.runConfirmationPass(vulns)
	if len(kept) != 1 {
		t.Fatalf("expected finding kept, got %d findings", len(kept))
	}
	if !strings.Contains(kept[0].Evidence, "reconfirmed on retransmit") {
		t.Errorf("evidence should be annotated with reconfirmation, got %q", kept[0].Evidence)
	}
}

func TestRunConfirmationPass_FlakyEvidenceDropped(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.LogFunc = func(string) {}

	vulns := []Vulnerability{{
		ID: "TEST-001", Severity: SeverityCritical, URL: "http://example.com/x",
		Evidence: "sig",
		Probe:    &ReplayProbe{Retry: func(*Scanner) (bool, error) { return false, nil }},
	}}

	kept := s.runConfirmationPass(vulns)
	if len(kept) != 0 {
		t.Fatalf("expected finding dropped, got %d findings", len(kept))
	}
}

func TestRunConfirmationPass_TransportErrorInconclusive(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.LogFunc = func(string) {}

	vulns := []Vulnerability{{
		ID: "TEST-001", Severity: SeverityHigh, URL: "http://example.com/x",
		Evidence: "sig",
		Probe:    &ReplayProbe{Retry: func(*Scanner) (bool, error) { return false, errors.New("connection reset") }},
	}}

	kept := s.runConfirmationPass(vulns)
	if len(kept) != 1 {
		t.Fatalf("transport error must keep the finding (inconclusive), got %d findings", len(kept))
	}
}

func TestRunConfirmationPass_LowSeverityNotRetransmitted(t *testing.T) {
	s, _ := NewScanner("http://example.com")
	s.LogFunc = func(string) {}

	calls := 0
	vulns := []Vulnerability{
		{ID: "TEST-LOW", Severity: SeverityLow, URL: "http://example.com/x",
			Probe: &ReplayProbe{Retry: func(*Scanner) (bool, error) { calls++; return false, nil }}},
		{ID: "TEST-MED", Severity: SeverityMedium, URL: "http://example.com/y",
			Probe: &ReplayProbe{Retry: func(*Scanner) (bool, error) { calls++; return false, nil }}},
		{ID: "TEST-NOPROBE", Severity: SeverityCritical, URL: "http://example.com/z"},
	}

	kept := s.runConfirmationPass(vulns)
	if len(kept) != 3 {
		t.Fatalf("expected all 3 findings kept, got %d", len(kept))
	}
	if calls != 0 {
		t.Errorf("probe retranmitted for non-High/Critical findings: %d calls", calls)
	}
}

// TestConfirmationPass_FlakyXSSDropped is end-to-end: a server that reflects
// the payload for the detection phase but stops reflecting afterwards must
// not yield a reported XSS finding.
func TestConfirmationPass_FlakyXSSDropped(t *testing.T) {
	var reqCount atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		if q == "" {
			r.ParseForm() //nolint:errcheck
			q = r.FormValue("q")
		}
		// Reflect only the first two requests (canary + payload probe);
		// the confirmation retransmit arrives third and sees no reflection.
		if n <= 2 && q != "" {
			fmt.Fprintf(w, "<html><body><div>%s</div></body></html>", q)
			return
		}
		fmt.Fprint(w, "<html><body>sanitized</body></html>")
	}))
	defer ts.Close()

	s, err := NewScanner(ts.URL)
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	s.LogFunc = func(string) {}
	s.Config.IOwnThisTarget = true
	s.Throttle = NewPIDController(200, 1000)

	form := Form{Action: ts.URL + "/search", Method: "GET", Inputs: []string{"q"}}
	vulns := s.testXSS(form)
	if len(vulns) == 0 {
		t.Skip("detection phase did not trigger; flaky test precondition not met")
	}
	if vulns[0].Probe == nil {
		t.Fatal("expected XSS finding to carry a replay probe")
	}

	kept := s.runConfirmationPass(vulns)
	if len(kept) != 0 {
		t.Fatalf("flaky XSS evidence must be dropped by confirmation, got %d findings", len(kept))
	}
}
