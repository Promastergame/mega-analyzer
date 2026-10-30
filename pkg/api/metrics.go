package api

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mega-analyzer/pkg/binzap"
	"mega-analyzer/pkg/buildinfo"
	"mega-analyzer/pkg/ml"
	"mega-analyzer/pkg/vulnscan"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PROMETHEUS METRICS — stdlib-only text exposition (zero external deps).
// Exposes: scans, rate-limit rejects, HTTP request counts + durations,
// rule counts, build info. Endpoint: GET /metrics
// ═══════════════════════════════════════════════════════════════════════════════

var promMetrics = struct {
	scansTotal        atomic.Uint64
	scanDurationNanos atomic.Uint64 // sum
	scanDurationCount atomic.Uint64
	rateLimitRejects  atomic.Uint64

	mu       sync.Mutex
	httpHits map[string]*atomic.Uint64 // key: method\x00route\x00code
	httpSum  map[string]*atomic.Uint64 // sum nanos per key
}{
	httpHits: make(map[string]*atomic.Uint64),
	httpSum:  make(map[string]*atomic.Uint64),
}

func metricRoute(r *http.Request) string {
	// Use the mux's registered pattern, never a client-supplied path. Requests
	// rejected before routing and unknown paths share one bounded label.
	pattern := r.Pattern
	if _, path, ok := strings.Cut(pattern, " "); ok {
		pattern = path
	}
	if pattern == "" || (pattern == "/" && r.URL.Path != "/" && r.URL.Path != "/dashboard") {
		return "unmatched"
	}
	if pattern == "/" {
		return r.URL.Path
	}
	// Collapse ID suffixes to :id to bound cardinality:
	// /api/v1/rules/web/<id> -> /api/v1/rules/web/:id
	// /api/v1/scans/<id> -> /api/v1/scans/:id
	for _, p := range []string{"/api/v1/rules/web/", "/api/v1/rules/binzap/", "/api/v1/rules/ml/", "/api/v1/scans/"} {
		if strings.HasPrefix(pattern, p) {
			return p + ":id"
		}
	}
	return pattern
}

func metricMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return method
	default:
		return "OTHER"
	}
}

func observeHTTP(method, route, code string, d time.Duration) {
	key := method + "\x00" + route + "\x00" + code
	promMetrics.mu.Lock()
	c, ok := promMetrics.httpHits[key]
	if !ok {
		c = &atomic.Uint64{}
		promMetrics.httpHits[key] = c
	}
	s, ok := promMetrics.httpSum[key]
	if !ok {
		s = &atomic.Uint64{}
		promMetrics.httpSum[key] = s
	}
	promMetrics.mu.Unlock()
	c.Add(1)
	s.Add(uint64(d.Nanoseconds()))
}

func incScan(d time.Duration) {
	promMetrics.scansTotal.Add(1)
	promMetrics.scanDurationNanos.Add(uint64(d.Nanoseconds()))
	promMetrics.scanDurationCount.Add(1)
}

func incRateLimitReject() {
	promMetrics.rateLimitRejects.Add(1)
}

// statusRecorder captures the status code for metrics.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status != 0 {
		return
	}
	if code >= 100 && code < 200 {
		r.ResponseWriter.WriteHeader(code)
		return
	}
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(p)
}

// Unwrap lets ResponseController reach connection deadlines (large uploads)
// and other optional capabilities through the metrics wrapper.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

type flushingStatusRecorder struct{ *statusRecorder }

func (r *flushingStatusRecorder) Flush() {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(r.ResponseWriter).Flush()
}

func (s *APIServer) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		var wrapped http.ResponseWriter = rec
		if _, ok := w.(http.Flusher); ok {
			wrapped = &flushingStatusRecorder{rec}
		}
		next.ServeHTTP(wrapped, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		observeHTTP(metricMethod(r.Method), metricRoute(r), strconv.Itoa(status), time.Since(start))
	})
}

func promEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func (s *APIServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeProblem(w, r, http.StatusMethodNotAllowed, "ERR_METHOD_NOT_ALLOWED", "Method Not Allowed", "Use GET.", "Use GET.", nil)
		return
	}
	var b strings.Builder

	b.WriteString("# HELP mega_analyzer_info Build info.\n# TYPE mega_analyzer_info gauge\n")
	fmt.Fprintf(&b, "mega_analyzer_info{version=\"%s\"} 1\n", promEscape(buildinfo.Version))

	scans := promMetrics.scansTotal.Load()
	sumNanos := promMetrics.scanDurationNanos.Load()
	cnt := promMetrics.scanDurationCount.Load()
	avg := 0.0
	if cnt > 0 {
		avg = float64(sumNanos) / float64(cnt) / 1e9
	}
	b.WriteString("# HELP mega_analyzer_scans_total Total scans executed.\n# TYPE mega_analyzer_scans_total counter\n")
	fmt.Fprintf(&b, "mega_analyzer_scans_total %d\n", scans)
	b.WriteString("# HELP mega_analyzer_scan_duration_seconds_avg Average scan duration.\n# TYPE mega_analyzer_scan_duration_seconds_avg gauge\n")
	fmt.Fprintf(&b, "mega_analyzer_scan_duration_seconds_avg %f\n", avg)
	b.WriteString("# HELP mega_analyzer_scan_duration_seconds_sum Total scan time.\n# TYPE mega_analyzer_scan_duration_seconds_sum counter\n")
	fmt.Fprintf(&b, "mega_analyzer_scan_duration_seconds_sum %f\n", float64(sumNanos)/1e9)

	b.WriteString("# HELP mega_analyzer_rate_limit_rejections_total Rate-limited requests.\n# TYPE mega_analyzer_rate_limit_rejections_total counter\n")
	fmt.Fprintf(&b, "mega_analyzer_rate_limit_rejections_total %d\n", promMetrics.rateLimitRejects.Load())

	b.WriteString("# HELP mega_analyzer_rules_count Dynamic rules loaded.\n# TYPE mega_analyzer_rules_count gauge\n")
	fmt.Fprintf(&b, "mega_analyzer_rules_count{kind=\"web\"} %d\n", len(vulnscan.GetDynamicWebRules()))
	fmt.Fprintf(&b, "mega_analyzer_rules_count{kind=\"binzap\"} %d\n", len(binzap.GetRawDynamicBinzapRules()))
	fmt.Fprintf(&b, "mega_analyzer_rules_count{kind=\"ml\"} %d\n", len(ml.GetDynamicMLPatterns()))

	b.WriteString("# HELP mega_analyzer_http_requests_total HTTP requests by route.\n# TYPE mega_analyzer_http_requests_total counter\n")
	b.WriteString("# HELP mega_analyzer_http_request_duration_seconds_sum Total latency by route.\n# TYPE mega_analyzer_http_request_duration_seconds_sum counter\n")

	type row struct {
		method, route, code string
		hits, sum           uint64
	}
	promMetrics.mu.Lock()
	rows := make([]row, 0, len(promMetrics.httpHits))
	for k, c := range promMetrics.httpHits {
		parts := strings.SplitN(k, "\x00", 3)
		if len(parts) != 3 {
			continue
		}
		var sum uint64
		if s, ok := promMetrics.httpSum[k]; ok {
			sum = s.Load()
		}
		rows = append(rows, row{parts[0], parts[1], parts[2], c.Load(), sum})
	}
	promMetrics.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].route != rows[j].route {
			return rows[i].route < rows[j].route
		}
		if rows[i].method != rows[j].method {
			return rows[i].method < rows[j].method
		}
		return rows[i].code < rows[j].code
	})
	for _, r := range rows {
		fmt.Fprintf(&b, "mega_analyzer_http_requests_total{method=\"%s\",route=\"%s\",code=\"%s\"} %d\n",
			promEscape(r.method), promEscape(r.route), promEscape(r.code), r.hits)
		fmt.Fprintf(&b, "mega_analyzer_http_request_duration_seconds_sum{method=\"%s\",route=\"%s\",code=\"%s\"} %f\n",
			promEscape(r.method), promEscape(r.route), promEscape(r.code), float64(r.sum)/1e9)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}
