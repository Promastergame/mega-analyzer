package web

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/vmware"
)

func TestVMwareScreenIsBoundToActiveJob(t *testing.T) {
	s, _, _ := vmwareTestServer(t)
	job := newScanJob("vm-screen-test", "", t.TempDir())
	job.mode = "sandbox"
	calls := 0
	job.vmwareScreen = func(context.Context) ([]byte, error) { calls++; return []byte("frame"), nil }
	jobsMu.Lock()
	jobs[job.id] = job
	jobsMu.Unlock()
	defer func() { jobsMu.Lock(); delete(jobs, job.id); jobsMu.Unlock() }()
	request := func(method, query, token, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://127.0.0.1:7474/api/vmware/screen?"+query, nil)
		r.Header.Set("X-MA-Token", token)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		s.routes().ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		method, query, token, origin string
		status                       int
	}{
		{"GET", "job=vm-screen-test", "", "", 401},
		{"GET", "job=vm-screen-test", "test-token", "https://evil.invalid", 403},
		{"POST", "job=vm-screen-test", "test-token", "", 405},
		{"GET", "vmx=C:/host.vmx", "test-token", "", 404},
		{"GET", "job=missing", "test-token", "", 404},
	} {
		w := request(tc.method, tc.query, tc.token, tc.origin)
		if w.Code != tc.status {
			t.Fatalf("status=%d want=%d: %s", w.Code, tc.status, w.Body)
		}
	}
	if calls != 0 {
		t.Fatal("rejected request reached capture")
	}
	w := request("GET", "job=vm-screen-test", "test-token", "")
	if w.Code != 200 || w.Body.String() != "frame" || w.Header().Get("Content-Type") != "image/png" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("frame: %d %s", w.Code, w.Body)
	}
	job.stopped = true
	if w := request("GET", "job=vm-screen-test", "test-token", ""); w.Code != 409 {
		t.Fatal("stopped job captured")
	}
	job.stopped, job.done = false, true
	if w := request("GET", "job=vm-screen-test", "test-token", ""); w.Code != 409 {
		t.Fatal("completed job captured")
	}
	if calls != 1 {
		t.Fatal("inactive job reached capture")
	}
	job.done = false
	for _, cause := range []error{errors.New("secret credential"), vmware.ErrBusy, context.Canceled} {
		job.vmwareScreen = func(context.Context) ([]byte, error) { return nil, cause }
		w := request("GET", "job=vm-screen-test", "test-token", "")
		if w.Code == 200 || strings.Contains(w.Body.String(), "secret credential") {
			t.Fatal("capture failure leaked details")
		}
	}
}
