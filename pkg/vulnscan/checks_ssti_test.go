package vulnscan

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// newSSTIScanner wires a Scanner to the given test server via a rewriting
// transport, mirroring TestScannerActiveScan.
func newSSTIScanner(t *testing.T, ts *httptest.Server) *Scanner {
	t.Helper()
	s, err := NewScanner("http://example.com")
	if err != nil {
		t.Fatal(err)
	}
	s.Client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(ts.URL, "http://")
		return http.DefaultTransport.RoundTrip(req)
	})
	return s
}

func TestCheckSSTI_ConfirmedEvaluation(t *testing.T) {
	reExpr := regexp.MustCompile(`\{\{(\d+)\*(\d+)\}\}`)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		val := r.Form.Get("name")
		out := reExpr.ReplaceAllStringFunc(val, func(m string) string {
			parts := reExpr.FindStringSubmatch(m)
			a, _ := strconv.Atoi(parts[1])
			b, _ := strconv.Atoi(parts[2])
			return strconv.Itoa(a * b)
		})
		w.Write([]byte("<html><body>Hello " + out + "</body></html>"))
	}))
	defer ts.Close()

	s := newSSTIScanner(t, ts)
	form := Form{Method: "POST", Action: "http://example.com/tpl", Inputs: []string{"name"}}

	vulns := s.checkSSTI(form)

	found := false
	for _, v := range vulns {
		if v.ID == "WS-SSTI-001" {
			found = true
			if v.Severity != SeverityCritical {
				t.Errorf("confirmed SSTI should be Critical, got %v", v.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected confirmed SSTI (WS-SSTI-001), got: %v", vulns)
	}
}

func TestCheckSSTI_ErrorFingerprint(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		val := r.Form.Get("name")
		if strings.Contains(val, "{{") {
			w.Write([]byte("jinja2.exceptions.TemplateSyntaxError: unexpected end of template"))
			return
		}
		w.Write([]byte("Hello " + val))
	}))
	defer ts.Close()

	s := newSSTIScanner(t, ts)
	form := Form{Method: "POST", Action: "http://example.com/tpl", Inputs: []string{"name"}}

	vulns := s.checkSSTI(form)

	found := false
	for _, v := range vulns {
		if v.ID == "WS-SSTI-002" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SSTI error fingerprint (WS-SSTI-002), got: %v", vulns)
	}
}

func TestCheckSSTI_NoFalsePositiveOnStaticNumbers(t *testing.T) {
	// A page that merely contains big numbers and never evaluates input must
	// not produce SSTI findings (the classic fixed-marker false positive).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Prices: 7777, 7777999, order 12345678. Hello.</body></html>"))
	}))
	defer ts.Close()

	s := newSSTIScanner(t, ts)
	form := Form{Method: "POST", Action: "http://example.com/tpl", Inputs: []string{"name"}}

	vulns := s.checkSSTI(form)
	for _, v := range vulns {
		if v.ID == "WS-SSTI-001" {
			t.Errorf("unexpected confirmed SSTI on static page: %v", v)
		}
	}
}
