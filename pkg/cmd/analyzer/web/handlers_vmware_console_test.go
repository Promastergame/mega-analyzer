package web

import (
	"net/http/httptest"
	"testing"

	"mega-analyzer/pkg/internal/vmware"
)

func TestVMwareConsoleRoutesRequireActiveJobAndOrigin(t *testing.T) {
	s, _, _ := vmwareTestServer(t)
	job := newScanJob("console-guard-test", "", t.TempDir())
	job.mode = "sandbox"
	job.vmwareConsole = &vmware.Console{}
	jobsMu.Lock()
	jobs[job.id] = job
	jobsMu.Unlock()
	defer func() { jobsMu.Lock(); delete(jobs, job.id); jobsMu.Unlock() }()
	for _, route := range []string{"console", "console-info"} {
		for _, tc := range []struct {
			method, id, token, origin string
			stopped, done             bool
			code                      int
		}{
			{"GET", job.id, "", "", false, false, 401},
			{"GET", job.id, "test-token", "https://evil.invalid", false, false, 403},
			{"POST", job.id, "test-token", "", false, false, 405},
			{"GET", "missing", "test-token", "", false, false, 409},
			{"GET", job.id, "test-token", "", true, false, 409},
			{"GET", job.id, "test-token", "", false, true, 409},
		} {
			job.stopped, job.done = tc.stopped, tc.done
			r := httptest.NewRequest(tc.method, "http://127.0.0.1:7474/api/vmware/"+route+"?job="+tc.id, nil)
			r.Header.Set("X-MA-Token", tc.token)
			r.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			s.routes().ServeHTTP(w, r)
			if w.Code != tc.code {
				t.Fatalf("%s status=%d want=%d", route, w.Code, tc.code)
			}
		}
	}
}
