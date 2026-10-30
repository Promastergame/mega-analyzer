package vulnscan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// migratedFormCheckIDs lists every legacy form fuzzer that must be reachable
// through the check registry after the pipeline unification.
var migratedFormCheckIDs = []string{
	"WS-FORM-XSS", "WS-FORM-SQLI", "WS-FORM-LFI", "WS-FORM-IDOR",
	"WS-FORM-HPP", "WS-FORM-PROTO", "WS-FORM-UPLOAD", "WS-FORM-SSTI",
	"WS-FORM-SSRF", "WS-FORM-RACE",
}

func lookupCheck(t *testing.T, id string) CheckDescriptor {
	t.Helper()
	for _, d := range RegisteredChecks() {
		if d.ID == id {
			return d
		}
	}
	t.Fatalf("check %s not registered", id)
	return CheckDescriptor{}
}

func TestFormChecksRegistered(t *testing.T) {
	for _, id := range migratedFormCheckIDs {
		d := lookupCheck(t, id)
		if d.Phase != PhaseActive {
			t.Errorf("%s: expected PhaseActive, got %v", id, d.Phase)
		}
		if d.Invasiveness != InvDestructive {
			t.Errorf("%s: expected InvDestructive, got %v", id, d.Invasiveness)
		}
		if d.Run == nil {
			t.Errorf("%s: runner is nil", id)
		}
		if len(d.CWE) == 0 || len(d.OWASP) == 0 {
			t.Errorf("%s: missing taxonomy metadata", id)
		}
	}
}

func TestFormChecksExcludedBySafeInvasiveness(t *testing.T) {
	safe := FilterByInvasiveness(RegisteredChecks(), InvSafe)
	for _, d := range safe {
		for _, id := range migratedFormCheckIDs {
			if d.ID == id {
				t.Errorf("destructive form check %s leaked through InvSafe filter", id)
			}
		}
	}
}

// TestFormRegistryBridge_XSSThroughSurface drives the migrated XSS check
// through the registry runner on a surface built from a form, verifying the
// Form round-trip and that replay probes survive the Finding conversion.
func TestFormRegistryBridge_XSSThroughSurface(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		if q == "" {
			r.ParseForm() //nolint:errcheck
			q = r.FormValue("q")
		}
		fmt.Fprintf(w, "<html><body><div>%s</div></body></html>", q)
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
	surface := attackSurfaceFromForm(form)

	d := lookupCheck(t, "WS-FORM-XSS")
	findings := d.Run(s, &surface)
	if len(findings) == 0 {
		t.Fatal("expected XSS finding through registry bridge")
	}
	if findings[0].Probe == nil {
		t.Error("replay probe lost during Finding conversion")
	}
	if findings[0].ID == "" {
		t.Error("finding lost its identity through the bridge")
	}
}

func TestFormRegistryBridge_NilSurface(t *testing.T) {
	s, err := NewScanner("http://example.com")
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	s.LogFunc = func(string) {}
	for _, id := range migratedFormCheckIDs {
		d := lookupCheck(t, id)
		if got := d.Run(s, nil); got != nil {
			t.Errorf("%s: nil surface must yield no findings, got %d", id, len(got))
		}
	}
}
