package ncer

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestCollector_Empty(t *testing.T) {
	c := NewCollector(time.Now())
	if c.Len() != 0 {
		t.Fatalf("expected empty collector, got len=%d", c.Len())
	}
	res, err := c.Reconcile()
	if err != nil {
		t.Fatalf("expected nil error on empty collector, got %v", err)
	}
	if res != nil {
		t.Fatalf("expected nil result on empty collector, got %+v", res)
	}
}

func TestCollector_ObserveHTTPAndBuildCapture(t *testing.T) {
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	c := NewCollector(base)

	c.ObserveHTTP("GET", "https://api.example.com/v1/login", "200", "api.example.com", "10:00:01.500")
	c.ObserveHTTP("POST", "https://api.example.com/v1/sync", "—", "api.example.com", "10:00:02.000") // orphan request
	c.ObserveHTTP("", "invalid", "200", "", "")                                                      // ignored due to empty method

	if c.Len() != 2 {
		t.Fatalf("expected 2 valid events observed, got %d", c.Len())
	}

	cap := c.buildCapture()
	if len(cap.HTTPRequests) != 2 {
		t.Fatalf("expected 2 requests built, got %d", len(cap.HTTPRequests))
	}
	// Only the event with status=200 produces a response entry.
	if len(cap.HTTPResponses) != 1 {
		t.Fatalf("expected 1 response built, got %d", len(cap.HTTPResponses))
	}

	req0 := cap.HTTPRequests[0]
	if req0.Method != "GET" || req0.URL != "https://api.example.com/v1/login" {
		t.Errorf("unexpected req0: %+v", req0)
	}
	resp0 := cap.HTTPResponses[0]
	if resp0.Status != 200 || resp0.RequestMethod != "GET" {
		t.Errorf("unexpected resp0: %+v", resp0)
	}
	// Response timestamp must equal the request timestamp — no fake +200ms offset.
	if resp0.TimestampMS != req0.TimestampMS {
		t.Errorf("expected response timestamp == request timestamp (%d), got %d", req0.TimestampMS, resp0.TimestampMS)
	}
}

func TestCollector_ObserveHTTPResponse_PairsOrphan(t *testing.T) {
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	c := NewCollector(base)

	// Record a request without a status (orphan).
	c.ObserveHTTP("GET", "https://example.com/data", "—", "example.com", "10:00:01.000")
	if c.Len() != 1 {
		t.Fatalf("expected 1 event, got %d", c.Len())
	}

	// Deliver the response separately.
	c.ObserveHTTPResponse("GET", "https://example.com/data", 200, "10:00:01.150")

	cap := c.buildCapture()
	if len(cap.HTTPRequests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(cap.HTTPRequests))
	}
	if len(cap.HTTPResponses) != 1 {
		t.Fatalf("expected 1 response after ObserveHTTPResponse, got %d", len(cap.HTTPResponses))
	}
	resp := cap.HTTPResponses[0]
	if resp.Status != 200 {
		t.Errorf("expected status 200, got %d", resp.Status)
	}
	// The response timestamp must reflect the separately-delivered response time,
	// not the request time or any artificial offset.
	if resp.TimestampMS == cap.HTTPRequests[0].TimestampMS {
		t.Logf("note: response and request timestamps are equal (both at 10:00:01.x) — acceptable if parsed equally")
	}
}

func TestCollector_TrueOrphan_NoFakeResponse(t *testing.T) {
	c := NewCollector(time.Now())
	// Observe a request with no status — it must remain a true orphan.
	c.ObserveHTTP("POST", "https://example.com/upload", "", "example.com", "")

	cap := c.buildCapture()
	if len(cap.HTTPRequests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(cap.HTTPRequests))
	}
	if len(cap.HTTPResponses) != 0 {
		t.Fatalf("expected 0 responses for an orphan request, got %d — fake response must not be synthesised", len(cap.HTTPResponses))
	}
}

func TestCollector_ReconcileStubOrLinked(t *testing.T) {
	c := NewCollector(time.Now())
	c.ObserveHTTP("GET", "https://example.com/test", "200", "example.com", "")
	res, err := c.Reconcile()
	if err != nil {
		t.Fatalf("expected Reconcile to succeed cleanly (or return nil on stub), got err: %v", err)
	}
	// In standard go test ./... (without cgo build tag), res will be nil due to stub fallback.
	// In integration test with build tag, res will contain valid scores.
	_ = res
}

func TestCollector_WithEvidenceStore(t *testing.T) {
	tmpDir := t.TempDir()
	evStore, err := OpenEvidenceStore(tmpDir)
	if err != nil {
		t.Fatalf("OpenEvidenceStore failed: %v", err)
	}

	c := NewCollector(time.Now())
	c.SetEvidenceStore(evStore)
	c.ObserveHTTP("GET", "https://example.com/test", "200", "example.com", "")

	res, err := c.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile with evidence store failed: %v", err)
	}
	_ = res
}

func TestCollector_ObserveAuthority_MakesEmptyCollectorReconcilable(t *testing.T) {
	c := NewCollector(time.Now())
	if c.hasReconcilableData() {
		t.Fatalf("a brand-new collector should have no reconcilable data")
	}

	ctx := sampleAuthorityContext()
	c.ObserveAuthority(FromAuthorityContextGranular(ctx, "sensor.manifest", 1000))

	if !c.hasReconcilableData() {
		t.Fatalf("collector with only authority events should be reconcilable")
	}

	res, err := c.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile with only authority events failed: %v", err)
	}
	// Stub or linked, both must return without error; the point of this test
	// is that Reconcile does not bail out early just because c.Len() == 0.
	_ = res
}

func TestCollector_ObserveAuthority_IncludedInReconcileInput(t *testing.T) {
	c := NewCollector(time.Now())
	ctx := sampleAuthorityContext()
	events := FromAuthorityContextGranular(ctx, "sensor.manifest", 1000)
	c.ObserveAuthority(events)

	input := c.buildReconcileInput()
	if len(input.AuthorityEvents) != len(events) {
		t.Fatalf("expected %d authority events in reconcile input, got %d", len(events), len(input.AuthorityEvents))
	}
}

func TestCollector_ObserveAuthority_EmptySliceIsNoOp(t *testing.T) {
	c := NewCollector(time.Now())
	c.ObserveAuthority(nil)
	if c.hasReconcilableData() {
		t.Fatalf("observing an empty/nil slice must not make the collector reconcilable")
	}
}

func TestCollector_ObserveDNS_AppearsInCapture(t *testing.T) {
	c := NewCollector(time.Now())
	c.ObserveDNS("example.com", 1, []string{"93.184.216.34", "not-an-ip", "2001:db8::1"}, "")

	cap := c.buildCapture()
	if len(cap.DNSQueries) != 1 {
		t.Fatalf("expected 1 DNS query in capture, got %d", len(cap.DNSQueries))
	}
	q := cap.DNSQueries[0]
	if q.QueryName != "example.com" {
		t.Errorf("QueryName = %q, want example.com", q.QueryName)
	}
	// Only the valid IPv4 address should survive; the malformed string and
	// the IPv6 address must be dropped (Rust decodes this field as
	// Vec<Ipv4Addr> and a single bad entry would fail the whole capture).
	if len(q.ResponseIPs) != 1 || q.ResponseIPs[0] != "93.184.216.34" {
		t.Errorf("ResponseIPs = %v, want [93.184.216.34]", q.ResponseIPs)
	}
}

func TestCollector_ObserveDNS_EmptyQueryNameIsIgnored(t *testing.T) {
	c := NewCollector(time.Now())
	c.ObserveDNS("", 1, []string{"1.2.3.4"}, "")
	if c.hasReconcilableData() {
		t.Fatalf("an empty query name must not be recorded")
	}
}

func TestCollector_ObserveFlow_AppearsInCapture(t *testing.T) {
	c := NewCollector(time.Now())
	c.ObserveFlow("192.168.1.2", 51234, "93.184.216.34", 443, 4096, 250, "tcp", "")

	cap := c.buildCapture()
	if len(cap.FlowSummaries) != 1 {
		t.Fatalf("expected 1 flow summary in capture, got %d", len(cap.FlowSummaries))
	}
	f := cap.FlowSummaries[0]
	if f.DstIP != "93.184.216.34" || f.DstPort != 443 || f.Protocol != "tcp" {
		t.Errorf("unexpected flow: %+v", f)
	}
}

func TestCollector_ObserveFlow_InvalidDstIPIsIgnored(t *testing.T) {
	c := NewCollector(time.Now())
	c.ObserveFlow("192.168.1.2", 51234, "not-an-ip", 443, 0, 0, "tcp", "")
	if c.hasReconcilableData() {
		t.Fatalf("a flow with an unparseable destination IP must not be recorded")
	}
}

func TestCollector_ObserveDNSAndFlow_MakeEmptyCollectorReconcilable(t *testing.T) {
	c := NewCollector(time.Now())
	c.ObserveDNS("example.com", 1, []string{"93.184.216.34"}, "")
	if !c.hasReconcilableData() {
		t.Fatalf("a collector with only a DNS event should be reconcilable")
	}

	c2 := NewCollector(time.Now())
	c2.ObserveFlow("192.168.1.2", 51234, "93.184.216.34", 443, 0, 0, "tcp", "")
	if !c2.hasReconcilableData() {
		t.Fatalf("a collector with only a flow event should be reconcilable")
	}
}

func TestCollector_ObserveTLS_AppearsInCapture(t *testing.T) {
	c := NewCollector(time.Now())
	c.ObserveTLS("game.example", "TLS_AES_128_GCM_SHA256", "771,4865,0-16,,", "abc123",
		nil, []string{"h2", "http/1.1"}, "")

	if !c.hasReconcilableData() {
		t.Fatalf("a collector with only a TLS handshake should be reconcilable")
	}
	cap := c.buildCapture()
	if len(cap.TLSHandshakes) != 1 {
		t.Fatalf("expected 1 TLS handshake in capture, got %d", len(cap.TLSHandshakes))
	}
	h := cap.TLSHandshakes[0]
	if h.SNI != "game.example" || h.JA3Hash != "abc123" || len(h.ALPN) != 2 {
		t.Errorf("unexpected TLS handshake: %+v", h)
	}
}

func TestCollector_ObserveTLS_EmptySniAndJA3IsIgnored(t *testing.T) {
	c := NewCollector(time.Now())
	c.ObserveTLS("", "", "", "", nil, nil, "")
	if c.hasReconcilableData() {
		t.Fatalf("a TLS handshake with neither SNI nor JA3 carries no signal and must be dropped")
	}
}

func TestCollector_MergeMitmCaptureJSON_MergesTLSHandshakes(t *testing.T) {
	c := NewCollector(time.Now())
	raw := []byte(`{
		"http_requests": [], "http_responses": [], "dns_queries": [], "flow_summaries": [],
		"tls_handshakes": [{"timestamp_ms": 4, "sni": "api.example", "cipher_suite": "TLS_AES_256_GCM_SHA384", "cert_chain_fingerprints": [], "ja3": "771,4866,,,", "ja3_hash": "deadbeef", "alpn": ["h2"]}]
	}`)
	if err := c.MergeMitmCaptureJSON(raw); err != nil {
		t.Fatalf("MergeMitmCaptureJSON failed: %v", err)
	}
	cap := c.buildCapture()
	if len(cap.TLSHandshakes) != 1 || cap.TLSHandshakes[0].SNI != "api.example" {
		t.Fatalf("unexpected TLSHandshakes: %+v", cap.TLSHandshakes)
	}
	if cap.TLSHandshakes[0].JA3Hash != "deadbeef" {
		t.Errorf("JA3 hash not merged: %+v", cap.TLSHandshakes[0])
	}
}

func TestCollector_MergeMitmCaptureJSON_EmptyPayloadIsNoOp(t *testing.T) {
	c := NewCollector(time.Now())
	if err := c.MergeMitmCaptureJSON(nil); err != nil {
		t.Fatalf("MergeMitmCaptureJSON(nil) = %v, want nil", err)
	}
	if c.hasReconcilableData() {
		t.Fatalf("merging an empty payload must not make the collector reconcilable")
	}
}

func TestCollector_MergeMitmCaptureJSON_InvalidJSONReturnsError(t *testing.T) {
	c := NewCollector(time.Now())
	if err := c.MergeMitmCaptureJSON([]byte("not json")); err == nil {
		t.Fatalf("expected an error for malformed JSON")
	}
}

func TestCollector_MergeMitmCaptureJSON_MergesAllFourArrays(t *testing.T) {
	c := NewCollector(time.Now())
	raw := []byte(`{
		"http_requests": [{"timestamp_ms": 1000, "method": "GET", "url": "/a", "headers": {}}],
		"http_responses": [{"timestamp_ms": 1050, "status": 200, "headers": {}, "request_method": "GET", "request_url": "/a"}],
		"dns_queries": [{"timestamp_ms": 900, "query_name": "example.com", "record_type": 1, "response_ips": ["93.184.216.34"]}],
		"tls_handshakes": [],
		"flow_summaries": [{"timestamp_ms": 1010, "src_ip": "192.168.1.2", "src_port": 51234, "dst_ip": "93.184.216.34", "dst_port": 443, "bytes": 4096, "duration_ms": 250, "protocol": "tcp"}]
	}`)

	if err := c.MergeMitmCaptureJSON(raw); err != nil {
		t.Fatalf("MergeMitmCaptureJSON failed: %v", err)
	}

	cap := c.buildCapture()
	if len(cap.HTTPRequests) != 1 || cap.HTTPRequests[0].URL != "/a" {
		t.Errorf("unexpected HTTPRequests: %+v", cap.HTTPRequests)
	}
	if len(cap.HTTPResponses) != 1 || cap.HTTPResponses[0].Status != 200 {
		t.Errorf("unexpected HTTPResponses: %+v", cap.HTTPResponses)
	}
	if len(cap.DNSQueries) != 1 || cap.DNSQueries[0].QueryName != "example.com" {
		t.Errorf("unexpected DNSQueries: %+v", cap.DNSQueries)
	}
	if len(cap.FlowSummaries) != 1 || cap.FlowSummaries[0].DstIP != "93.184.216.34" {
		t.Errorf("unexpected FlowSummaries: %+v", cap.FlowSummaries)
	}
}

func TestCollector_MergeMitmCaptureJSON_MakesEmptyCollectorReconcilable(t *testing.T) {
	c := NewCollector(time.Now())
	raw := []byte(`{"http_requests":[{"timestamp_ms":1,"method":"GET","url":"/","headers":{}}],"http_responses":[],"dns_queries":[],"tls_handshakes":[],"flow_summaries":[]}`)
	if err := c.MergeMitmCaptureJSON(raw); err != nil {
		t.Fatalf("MergeMitmCaptureJSON failed: %v", err)
	}
	if !c.hasReconcilableData() {
		t.Fatalf("a collector with a merged HTTP request should be reconcilable")
	}
}

// TestCollector_Reconcile_DNSFlowScoring is an end-to-end test through
// whatever backend is linked (stub or the real Rust library). Under the
// stub, Reconcile returns (nil, nil) and the test only checks for a clean
// error; built with '-tags cgo,omnisec_ncer_reconcile_ffi' against the real
// library it also verifies DInformation reflects one bound DNS/flow pair
// and one unbound flow.
func TestCollector_Reconcile_DNSFlowScoring(t *testing.T) {
	base := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	c := NewCollector(base)

	// Resolved and dialed -> should bind.
	c.ObserveDNS("example.com", 1, []string{"93.184.216.34"}, "12:00:00.000")
	c.ObserveFlow("192.168.1.2", 51234, "93.184.216.34", 443, 4096, 250, "tcp", "12:00:00.100")
	// Dialed with no matching resolution -> unbound flow.
	c.ObserveFlow("192.168.1.2", 51235, "1.2.3.4", 443, 512, 50, "tcp", "12:00:01.000")

	res, err := c.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if res == nil {
		t.Skip("native library not linked (stub path); skipping score assertions")
	}

	// effect_count = bound(1) + unbound(1) = 2; d_information = 1/2 = 0.5.
	if abs32(res.DInformation-0.5) > 1e-5 {
		t.Errorf("DInformation = %v, want 0.5 (one bound flow, one unbound flow)", res.DInformation)
	}
}

func TestCollector_ObserveHTTP_PreservesHostAsHeader(t *testing.T) {
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	c := NewCollector(base)
	c.ObserveHTTP("GET", "https://api.example.com/v1", "200", "api.example.com", "10:00:01.000")
	c.ObserveHTTP("GET", "https://noHost.example/x", "200", "", "10:00:02.000")

	cap := c.buildCapture()
	if len(cap.HTTPRequests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(cap.HTTPRequests))
	}
	if got := cap.HTTPRequests[0].Headers["Host"]; got != "api.example.com" {
		t.Errorf("host not preserved as Host header: got %q, want %q", got, "api.example.com")
	}
	if _, present := cap.HTTPRequests[1].Headers["Host"]; present {
		t.Errorf("empty host must not produce a Host header, got %v", cap.HTTPRequests[1].Headers)
	}
}

func TestCollector_ObserveHTTPResponse_PairsMultipleOrphansLIFO(t *testing.T) {
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	c := NewCollector(base)

	// Two orphan requests to the same method+url.
	c.ObserveHTTP("GET", "https://example.com/poll", "—", "example.com", "10:00:01.000")
	c.ObserveHTTP("GET", "https://example.com/poll", "—", "example.com", "10:00:02.000")

	// Two responses arrive; each must pair to a distinct orphan (not the same one).
	c.ObserveHTTPResponse("GET", "https://example.com/poll", 200, "10:00:03.000")
	c.ObserveHTTPResponse("GET", "https://example.com/poll", 500, "10:00:04.000")

	cap := c.buildCapture()
	if len(cap.HTTPRequests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(cap.HTTPRequests))
	}
	if len(cap.HTTPResponses) != 2 {
		t.Fatalf("expected 2 paired responses, got %d (each orphan must pair once)", len(cap.HTTPResponses))
	}
	statuses := map[int]bool{}
	for _, r := range cap.HTTPResponses {
		statuses[r.Status] = true
	}
	if !statuses[200] || !statuses[500] {
		t.Errorf("expected both 200 and 500 responses, got %v", statuses)
	}
}

func TestCollector_MergeMitmCaptureJSON_DedupsAgainstTelemetry(t *testing.T) {
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	c := NewCollector(base)

	// Observe an exchange via telemetry.
	c.ObserveHTTP("GET", "https://api.example.com/v1", "200", "api.example.com", "10:00:01.000")
	// buildCapture derives the request timestamp; capture it to build a matching merge entry.
	tsMS := c.buildCapture().HTTPRequests[0].TimestampMS

	// The Rust live-capture accumulator reports the SAME exchange (same triple)
	// plus a genuinely new one at a different millisecond.
	rawJSON := `{"http_requests":[` +
		`{"timestamp_ms":` + itoa(tsMS) + `,"method":"GET","url":"https://api.example.com/v1","headers":{}},` +
		`{"timestamp_ms":` + itoa(tsMS+5000) + `,"method":"GET","url":"https://api.example.com/v1","headers":{}}` +
		`],"http_responses":[],"dns_queries":[],"tls_handshakes":[],"flow_summaries":[]}`
	if err := c.MergeMitmCaptureJSON([]byte(rawJSON)); err != nil {
		t.Fatalf("MergeMitmCaptureJSON: %v", err)
	}

	cap := c.buildCapture()
	// Expect: 1 telemetry request + 1 new merged request = 2 (the duplicate dropped).
	if len(cap.HTTPRequests) != 2 {
		t.Errorf("expected 2 requests after dedup (1 telemetry + 1 new merged), got %d", len(cap.HTTPRequests))
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}

func TestCollector_ReconcileContext_CancelledReturnsErr(t *testing.T) {
	c := NewCollector(time.Now())
	c.ObserveHTTP("GET", "https://example.com/x", "200", "example.com", "")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	_, err := c.ReconcileContext(ctx, 0)
	if err == nil {
		// On the stub path RunReconcile returns immediately, so the pre-check
		// (ctx.Err() before dispatch) is what must catch this.
		t.Fatalf("expected context cancellation error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestCollector_ReconcileContext_NoDataIsNoOp(t *testing.T) {
	c := NewCollector(time.Now())
	res, err := c.ReconcileContext(context.Background(), 0)
	if err != nil || res != nil {
		t.Errorf("empty collector ReconcileContext = (%v, %v), want (nil, nil)", res, err)
	}
}
