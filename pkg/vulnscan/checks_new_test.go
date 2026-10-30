package vulnscan

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// newNewCheckScanner wires a Scanner to the given test server via a rewriting
// transport, mirroring newSSTIScanner.
func newNewCheckScanner(t *testing.T, ts *httptest.Server) *Scanner {
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

func surfaceAt(path string) *AttackSurface {
	as := attackSurfaceFromForm(Form{Action: "http://example.com" + path, Method: "GET", Inputs: []string{"q"}})
	as.BaseRequest = &BaseRequest{Method: "GET", URL: "http://example.com" + path}
	return &as
}

// --- XXE ---

// vulnerableXMLParser simulates a parser that expands internal entities: it
// extracts ENTITY definitions and substitutes references in the document.
func vulnerableXMLParser(body string) string {
	reEnt := regexp.MustCompile(`<!ENTITY (\w+) "([^"]*)">`)
	ents := map[string]string{}
	for _, m := range reEnt.FindAllStringSubmatch(body, -1) {
		ents[m[1]] = m[2]
	}
	out := body
	for name, val := range ents {
		out = strings.ReplaceAll(out, "&"+name+";", val)
	}
	return out
}

func TestCheckXXE_EntityExpansionConfirmed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Write([]byte(vulnerableXMLParser(string(raw))))
	}))
	defer ts.Close()

	s := newNewCheckScanner(t, ts)
	findings := runXXE(s, surfaceAt("/parse"))
	if len(findings) == 0 {
		t.Fatal("expected XXE finding on entity-expanding parser")
	}
	if findings[0].ID != "WS-XXE-001" {
		t.Errorf("unexpected finding ID %s", findings[0].ID)
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected High severity, got %v", findings[0].Severity)
	}
}

func TestCheckXXE_NoFalsePositiveOnRawEcho(t *testing.T) {
	// A server that echoes the raw request body back must NOT trigger: the
	// contiguous canary exists only after entity expansion.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Write(raw)
	}))
	defer ts.Close()

	s := newNewCheckScanner(t, ts)
	if findings := runXXE(s, surfaceAt("/echo")); len(findings) != 0 {
		t.Fatalf("raw echo server must not produce XXE findings, got %d", len(findings))
	}
}

// --- CRLF ---

func TestCheckCRLF_HeaderInjection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("q")
		// Simulate a sink that copies user input into response headers: every
		// CRLF-delimited chunk becomes its own header line.
		for i, chunk := range strings.Split(val, "\r\n") {
			if i == 0 {
				continue
			}
			if idx := strings.Index(chunk, ": "); idx > 0 {
				w.Header().Set(chunk[:idx], chunk[idx+2:])
			}
		}
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	s := newNewCheckScanner(t, ts)
	findings := runCRLF(s, surfaceAt("/redirect"))
	if len(findings) == 0 {
		t.Fatal("expected CRLF header-injection finding")
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("expected Medium severity, got %v", findings[0].Severity)
	}
}

func TestCheckCRLF_NewlineReflectionDifferential(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "value=%s", r.URL.Query().Get("q"))
	}))
	defer ts.Close()

	s := newNewCheckScanner(t, ts)
	findings := runCRLF(s, surfaceAt("/reflect"))
	if len(findings) != 1 {
		t.Fatalf("expected exactly one newline-reflection finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityLow {
		t.Errorf("expected Low severity newline reflection, got %v", findings[0].Severity)
	}
}

func TestCheckCRLF_EncodedEchoNoFinding(t *testing.T) {
	// A sink that HTML-escapes output shows the literal %0d%0a sequence, so
	// no real newline ever appears before the canary.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect the raw (still percent-encoded) query: no decoded newline
		// ever reaches the output.
		w.Write([]byte("value=" + r.URL.RawQuery))
	}))
	defer ts.Close()

	s := newNewCheckScanner(t, ts)
	if findings := runCRLF(s, surfaceAt("/safe")); len(findings) != 0 {
		t.Fatalf("escaped sink must not produce CRLF findings, got %d", len(findings))
	}
}

// --- Verb tampering ---

func TestCheckVerbTampering_BypassConfirmed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := newNewCheckScanner(t, ts)
	findings := runVerbTampering(s, surfaceAt("/admin"))
	if len(findings) != 1 {
		t.Fatalf("expected one verb-tampering finding, got %d", len(findings))
	}
	if findings[0].ID != "WS-VERB-001" {
		t.Errorf("unexpected finding ID %s", findings[0].ID)
	}
	if findings[0].Payload == http.MethodGet {
		t.Error("bypass verb must differ from the denied baseline verb")
	}
}

func TestCheckVerbTampering_AllMethodsDenied(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	s := newNewCheckScanner(t, ts)
	if findings := runVerbTampering(s, surfaceAt("/admin")); len(findings) != 0 {
		t.Fatalf("uniformly denied resource must not produce findings, got %d", len(findings))
	}
}

func TestCheckVerbTampering_NothingProtected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := newNewCheckScanner(t, ts)
	if findings := runVerbTampering(s, surfaceAt("/public")); len(findings) != 0 {
		t.Fatalf("unprotected resource must not produce findings (no differential), got %d", len(findings))
	}
}
