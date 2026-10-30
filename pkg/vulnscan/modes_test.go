package vulnscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseScanMode(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want ScanMode
	}{
		{"status", ScanModeStatus},
		{"alive", ScanModeStatus},
		{"safe", ScanModePassive},
		{"vulnerabilities", ScanModeActive},
	} {
		got, err := ParseScanMode(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("ParseScanMode(%q) = %q, %v; want %q", tc.raw, got, err, tc.want)
		}
	}
	if _, err := ParseScanMode("fuzz-everything"); err == nil {
		t.Fatal("expected invalid mode error")
	}
}

func TestCheckStatusOnlyMakesOneGET(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("body", 100)))
	}))
	defer srv.Close()

	scanner, err := NewScanner(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.ScanWithMode(context.Background(), ScanModeStatus)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status == nil || !result.Status.OK || result.Status.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status result: %+v", result.Status)
	}
	if len(result.Findings) != 0 || requests != 1 {
		t.Fatalf("status mode findings/requests = %d/%d, want 0/1", len(result.Findings), requests)
	}
}

func TestPassiveModeDoesNotRequireOwnershipOrFuzz(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/" {
			t.Errorf("unexpected passive request path %s", r.URL.Path)
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"public_key":"-----BEGIN PRIVATE KEY-----"}`))
	}))
	defer srv.Close()

	scanner, err := NewScanner(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.ScanWithMode(context.Background(), ScanModePassive)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status == nil || result.Status.OK || result.Status.StatusCode != http.StatusAccepted {
		t.Fatalf("unexpected passive status: %+v", result.Status)
	}
	if requests != 1 {
		t.Fatalf("passive mode made %d requests, want 1", requests)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected passive findings from response body/headers")
	}
}

func TestActiveModeStillHasSafetyGate(t *testing.T) {
	scanner, err := NewScanner("http://127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	_, err = scanner.ScanWithMode(context.Background(), ScanModeActive)
	if err == nil || !strings.Contains(err.Error(), "i-own-this-target") {
		t.Fatalf("expected active safety gate, got %v", err)
	}
}
