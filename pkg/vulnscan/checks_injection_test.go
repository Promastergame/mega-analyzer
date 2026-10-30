package vulnscan

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestRunCommandInjection_RejectsDirectPayloadReflection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.URL.Query().Get("q"))
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	surface := attackSurfaceFromForm(Form{Action: ts.URL, Method: http.MethodGet, Inputs: []string{"q"}})
	if findings := runCommandInjection(s, &surface); len(findings) != 0 {
		t.Fatalf("direct payload reflection must not confirm command injection, got %#v", findings)
	}
}

func TestEngineRunActiveChecks_FindsEncodedCommandOutput(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := r.URL.Query().Get("q")
		if canary, ok := decodePrintfCanary(payload); ok {
			fmt.Fprint(w, canary)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	s := newTestScanner(t, ts)
	forms := []Form{{Action: ts.URL, Method: http.MethodGet, Inputs: []string{"q"}}}
	findings, err := NewEngine(s).RunActiveChecks(t.Context(), forms)
	if err != nil {
		t.Fatalf("RunActiveChecks: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "WS-CMDI-001" {
		t.Fatalf("expected one command-injection finding, got %#v", findings)
	}
}

func decodePrintfCanary(payload string) (string, bool) {
	const prefix = ";printf '"
	if !strings.HasPrefix(payload, prefix) || !strings.HasSuffix(payload, "'") {
		return "", false
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(payload, prefix), "'")
	if len(encoded) == 0 || len(encoded)%4 != 0 {
		return "", false
	}
	decoded := make([]byte, 0, len(encoded)/4)
	for len(encoded) > 0 {
		if encoded[0] != '\\' {
			return "", false
		}
		value, err := strconv.ParseUint(encoded[1:4], 8, 8)
		if err != nil {
			return "", false
		}
		decoded = append(decoded, byte(value))
		encoded = encoded[4:]
	}
	return string(decoded), true
}
