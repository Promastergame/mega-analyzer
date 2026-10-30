package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsMiddlewareSSE(t *testing.T) {
	t.Setenv("MEGA_ANALYZER_API_TOKEN", "")
	s := NewAPIServer(8090)
	mux := http.NewServeMux()
	mux.Handle("/api/v1/scan/events", GetBroker())
	h := s.rateLimitMiddleware(s.metricsMiddleware(s.apiAuthMiddleware(s.csrfMiddleware(s.corsMiddleware(mux)))))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/scan/events", nil).WithContext(ctx)
	r.RemoteAddr = "192.0.2.201:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !w.Flushed || !strings.Contains(w.Body.String(), "Diagnostic Event Stream Established") {
		t.Fatalf("SSE: status=%d flushed=%v body=%s", w.Code, w.Flushed, w.Body.String())
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	readDeadline, writeDeadline time.Time
	readSet, writeSet           bool
}

func (w *deadlineRecorder) SetReadDeadline(d time.Time) error {
	w.readDeadline, w.readSet = d, true
	return nil
}

func (w *deadlineRecorder) SetWriteDeadline(d time.Time) error {
	w.writeDeadline, w.writeSet = d, true
	return nil
}

func TestMetricsMiddlewareUploadDeadlines(t *testing.T) {
	s := &APIServer{}
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	h := s.metricsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		if err := rc.SetReadDeadline(time.Time{}); err != nil {
			t.Errorf("read deadline: %v", err)
		}
		if err := rc.SetWriteDeadline(time.Time{}); err != nil {
			t.Errorf("write deadline: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/artifacts", nil))
	if !w.readSet || !w.writeSet || !w.readDeadline.IsZero() || !w.writeDeadline.IsZero() {
		t.Fatalf("upload deadlines did not reach the underlying writer: %+v", w)
	}
}

func TestMetricsMiddlewareWithoutFlusher(t *testing.T) {
	s := &APIServer{}
	w := httptest.NewRecorder()
	s.metricsMiddleware(GetBroker()).ServeHTTP(&noFlusherWriter{w}, httptest.NewRequest(http.MethodGet, "/events", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("unsupported streaming status = %d", w.Code)
	}
}

func TestMetricsRouteCardinality(t *testing.T) {
	s := &APIServer{}
	mux := http.NewServeMux()
	noContent := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }
	mux.HandleFunc("GET /api/v1/status", noContent)
	mux.HandleFunc("GET /api/v1/scans/", noContent)
	mux.HandleFunc("PUT /api/v1/rules/web/", noContent)
	mux.HandleFunc("/", s.handleDashboard)
	h := s.metricsMiddleware(mux)
	cases := []struct{ method, path, route, code string }{
		{"GET", "/api/v1/status", "/api/v1/status", "204"},
		{"GET", "/api/v1/scans/job-1/report/analysis.json", "/api/v1/scans/:id", "204"},
		{"PUT", "/api/v1/rules/web/rule-1", "/api/v1/rules/web/:id", "204"},
		{"GET", "/", "/", "200"},
		{"GET", "/dashboard", "/dashboard", "200"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			key := tc.method + "\x00" + tc.route + "\x00" + tc.code
			before := metricHits(key)
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.path, nil))
			if got := metricHits(key) - before; got != 1 {
				t.Errorf("expected one request for %q, got %d", key, got)
			}
		})
	}
	for _, method := range []string{"GET", "CUSTOM"} {
		code := "404"
		if method == "CUSTOM" {
			code = "405"
		}
		key := metricMethod(method) + "\x00unmatched\x00" + code
		before := metricHits(key)
		for i := 0; i < 100; i++ {
			verb := method
			if method == "CUSTOM" {
				verb = fmt.Sprintf("CUSTOM%d", i)
			}
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(verb, fmt.Sprintf("/missing-%d", i), nil))
		}
		if got := metricHits(key) - before; got != 100 {
			t.Errorf("unknown routes/methods did not share %q: got %d requests", key, got)
		}
	}
	promMetrics.mu.Lock()
	defer promMetrics.mu.Unlock()
	for key := range promMetrics.httpHits {
		if strings.Contains(key, "/missing-") || strings.HasPrefix(key, "CUSTOM") {
			t.Errorf("client-controlled metric key: %q", key)
		}
	}
}

func metricHits(key string) uint64 {
	promMetrics.mu.Lock()
	defer promMetrics.mu.Unlock()
	if c := promMetrics.httpHits[key]; c != nil {
		return c.Load()
	}
	return 0
}

func TestStatusRecorderFirstResponseStatus(t *testing.T) {
	for _, implicit := range []bool{false, true} {
		w := httptest.NewRecorder()
		rec := &statusRecorder{ResponseWriter: w}
		want := http.StatusCreated
		if implicit {
			_, _ = rec.Write([]byte("body"))
			want = http.StatusOK
		} else {
			rec.WriteHeader(want)
		}
		rec.WriteHeader(http.StatusInternalServerError)
		if rec.status != want || w.Code != want {
			t.Errorf("implicit=%v: recorded=%d actual=%d want=%d", implicit, rec.status, w.Code, want)
		}
	}
}
