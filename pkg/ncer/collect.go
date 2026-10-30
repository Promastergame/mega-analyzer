// Package ncer provides helpers for integrating the NCER causal reconciliation
// pipeline into the Mega-Analyzer analysis flow.
//
// The primary entry point is [Collector], which accumulates HTTP telemetry
// events emitted by the live MITM/sandbox monitoring goroutines, converts them
// into the MitmCapture JSON format expected by the Rust FFI bridge, and calls
// [reconcile.RunReconcile] at session end to produce a [types.NcerCausalResult].
//
// # Integration contract
//
//  1. Create one [Collector] per analysis session.
//  2. Call [Collector.Observe] for every [TelemetryEvent]-like value that has
//     Type == "http".
//  3. Call [Collector.Reconcile] once when the session ends.
//  4. If Reconcile returns a non-nil [*types.NcerCausalResult], store it in
//     [types.AnalysisResult.NcerResult].
//
// When the Rust library is not linked (stub path) Reconcile returns
// (nil, nil) so the caller never needs to check for [reconcile.ErrRustNotLinked]
// explicitly.
package ncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"mega-analyzer/pkg/internal/types"
	"mega-analyzer/pkg/ncer/reconcile"
)

// httpEvent is the minimal subset of a TelemetryEvent that the collector cares
// about. The caller passes these individually so the ncer package stays
// independent of the cmd/analyzer package (which defines TelemetryEvent).
type httpEvent struct {
	timestampMS int64  // Unix ms; 0 if unknown
	method      string // GET, POST, …
	url         string // full URL
	status      int    // HTTP status code; 0 for requests with no known response
	host        string // request host header / SNI; the DNS↔flow↔request correlation key
	// responseTS is the timestamp of the real observed response. When non-zero
	// it is used as the response timestamp in buildCapture instead of the request
	// timestamp. Populated by ObserveHTTPResponse, and for events that already
	// carry an HTTP status at observe-time (e.g. mitmproxy which reports request
	// and response in the same event), by ObserveHTTP.
	responseTS int64
}

// dnsEvent is one DNS query+answer observed during the session, as recorded
// by ObserveDNS.
type dnsEvent struct {
	timestampMS int64
	queryName   string
	recordType  uint16
	responseIPs []string // dotted-quad IPv4 strings only; see mitmDNSQuery's doc
}

// tlsEvent is one TLS handshake observed during the session, as recorded by
// ObserveTLS (typically drained from the Rust live-capture accumulator).
type tlsEvent struct {
	timestampMS int64
	sni         string
	cipherSuite string
	certFPs     []string
	ja3         string
	ja3Hash     string
	alpn        []string
}

// flowEvent is one outbound network flow observed during the session, as
// recorded by ObserveFlow.
type flowEvent struct {
	timestampMS int64
	srcIP       string
	srcPort     uint16
	dstIP       string
	dstPort     uint16
	bytes       uint64
	durationMS  uint64
	protocol    string
}

// mitmHTTPRequest is the JSON shape for one HTTP request inside a MitmCapture.
// Field names match the Rust omnisec_mitm::capture::MitmCapture exactly.
type mitmHTTPRequest struct {
	TimestampMS int64             `json:"timestamp_ms"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
}

// mitmHTTPResponse mirrors MitmCapture's http_responses array.
type mitmHTTPResponse struct {
	TimestampMS   int64             `json:"timestamp_ms"`
	Status        int               `json:"status"`
	Headers       map[string]string `json:"headers"`
	RequestMethod string            `json:"request_method"`
	RequestURL    string            `json:"request_url"`
}

// mitmDNSQuery mirrors omnisec_mitm::capture::DnsQueryCapture exactly.
// ResponseIPs must be dotted-quad IPv4 strings: the Rust side deserializes
// this field as Vec<Ipv4Addr> (see capture.rs), so an IPv6 address or a
// malformed string fails the whole capture's JSON decode on the Rust side.
type mitmDNSQuery struct {
	TimestampMS int64    `json:"timestamp_ms"`
	QueryName   string   `json:"query_name"`
	RecordType  uint16   `json:"record_type"`
	ResponseIPs []string `json:"response_ips"`
}

// mitmFlowSummary mirrors omnisec_mitm::capture::FlowSummaryCapture exactly.
type mitmFlowSummary struct {
	TimestampMS int64  `json:"timestamp_ms"`
	SrcIP       string `json:"src_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	Bytes       uint64 `json:"bytes"`
	DurationMS  uint64 `json:"duration_ms"`
	Protocol    string `json:"protocol"`
}

// mitmTLSHandshake mirrors omnisec_mitm::capture::TlsHandshakeCapture exactly.
// Since the network-interception overhaul, ssl.rs's CONNECT handler dissects
// the client's ClientHello (SNI, cipher suite, JA3, ALPN) before tunnelling,
// so this array now carries live data. The ja3/ja3_hash/alpn fields carry
// omitempty so captures that predate that path still round-trip.
type mitmTLSHandshake struct {
	TimestampMS           int64    `json:"timestamp_ms"`
	SNI                   string   `json:"sni"`
	CipherSuite           string   `json:"cipher_suite"`
	CertChainFingerprints []string `json:"cert_chain_fingerprints"`
	JA3                   string   `json:"ja3,omitempty"`
	JA3Hash               string   `json:"ja3_hash,omitempty"`
	ALPN                  []string `json:"alpn,omitempty"`
}

// mitmCapture is the Go representation of omnisec_mitm::capture::MitmCapture.
type mitmCapture struct {
	HTTPRequests  []mitmHTTPRequest  `json:"http_requests"`
	HTTPResponses []mitmHTTPResponse `json:"http_responses"`
	DNSQueries    []mitmDNSQuery     `json:"dns_queries"`
	TLSHandshakes []mitmTLSHandshake `json:"tls_handshakes"`
	FlowSummaries []mitmFlowSummary  `json:"flow_summaries"`
}

// reconcileInput is the JSON shape sent across the FFI boundary: a
// mitmCapture flattened with an optional authority_events array, matching
// omnisec-ncer-reconcile-ffi::ReconcileInput exactly (see that crate's doc
// comment for why the capture fields are flattened rather than nested).
type reconcileInput struct {
	mitmCapture
	AuthorityEvents []TypedEvent `json:"authority_events,omitempty"`
}

// Collector accumulates HTTP telemetry events and converts them for causal
// reconciliation.  It is safe for concurrent use.
type Collector struct {
	mu                 sync.Mutex
	baseTime           time.Time
	events             []httpEvent
	dnsEvents          []dnsEvent
	flowEvents         []flowEvent
	tlsEvents          []tlsEvent
	extraHTTPRequests  []mitmHTTPRequest  // drained from mitmbridge.TakeCapture, passed through as-is
	extraHTTPResponses []mitmHTTPResponse // drained from mitmbridge.TakeCapture, passed through as-is
	evidenceStore      *EvidenceStore
	anomalyFindings    []types.AnomalyFinding
	baselineDir        string
	authorityEvents    []TypedEvent

	// tsMu guards the midnight-rollover tracking state below. It is separate
	// from mu because parseTimestampMS runs before the Observe* methods take
	// mu, and a session's telemetry stream can cross midnight: the wire format
	// is "HH:MM:SS.mmm" with no date, so once the clock wraps past 00:00 the
	// raw time-of-day jumps backwards. We detect that wrap and advance a
	// whole-day offset so emitted Unix-ms timestamps stay monotonic instead of
	// leaping ~24h into the past (which would break the reconciler's 5 s
	// binding window).
	tsMu          sync.Mutex
	tsLastTODMs   int64 // last observed time-of-day in ms since local midnight; -1 until first parse
	tsDayOffsetMs int64 // accumulated whole-day offset in ms from rollovers

	// orphanIdx maps an httpKey (method+url) to the indices in c.events of
	// pending-orphan requests (status == 0) awaiting a response, most-recent
	// last. It lets ObserveHTTPResponse pair a late response in O(1) amortised
	// time instead of scanning all of c.events backwards — the old O(n) scan
	// made a session of n exchanges O(n²). Guarded by c.mu alongside c.events.
	orphanIdx map[string][]int

	// seenExchange records httpExchangeKey(method,url,timestampMS) for every
	// request recorded via ObserveHTTP, so MergeMitmCaptureJSON can drop an
	// entry that is byte-for-byte the same exchange already observed through
	// the telemetry path — the two sources (mitmproxy telemetry and the Rust
	// live-capture accumulator) can both report the same request, and counting
	// it twice inflates TotalEvents and skews d_causal/coverage. Guarded by
	// c.mu.
	seenExchange map[string]struct{}
}

// NewCollector returns a new Collector. baseTime is used to synthesise
// timestamps for events that carry only a formatted time string.
func NewCollector(baseTime time.Time) *Collector {
	if baseTime.IsZero() {
		baseTime = time.Now()
	}
	return &Collector{baseTime: baseTime, tsLastTODMs: -1}
}

// SetEvidenceStore attaches an EvidenceStore to the collector so reconciliation
// inputs are stored and verified as immutable content-addressed evidence.
func (c *Collector) SetEvidenceStore(store *EvidenceStore) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evidenceStore = store
}

// SetAnomalyFindings attaches the session's AnomalyFindings so Reconcile can
// derive DConsequence from their severity. Optional: DConsequence stays 0.0
// if this is never called.
func (c *Collector) SetAnomalyFindings(findings []types.AnomalyFinding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.anomalyFindings = append([]types.AnomalyFinding(nil), findings...)
}

// SetBaselineDir sets the directory used to persist the per-target
// fingerprint baseline that DNovelty is scored against (see novelty.go). If
// never called, novelty scoring is skipped and DNovelty stays 0.0.
func (c *Collector) SetBaselineDir(dir string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.baselineDir = dir
}

// ObserveAuthority appends per-permission/per-action TypedEvents (see
// FromAuthorityContextGranular) to be sent alongside the capture at
// reconciliation time, so the Rust authority binder can compute
// d_authority/d_capability. Safe to call multiple times per session (e.g.
// once per Android package under analysis); events accumulate.
func (c *Collector) ObserveAuthority(events []TypedEvent) {
	if len(events) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.authorityEvents = append(c.authorityEvents, events...)
}

// ObserveHTTP records one HTTP exchange.  method and url are required;
// statusStr is the response status code as a string (e.g. "200") and may be
// empty or "—" for requests whose response has not yet been observed.
// host is the request's host header / SNI — the key that lets a request be
// correlated with a DNS resolution and outbound flow for the same host; it may
// be empty when the caller cannot supply it. timestampStr is the HH:MM:SS.mmm
// formatted timestamp emitted by the TelemetryEvent stream; an empty string
// uses the deterministic timestamp fallback (see parseTimestampMS).
//
// When statusStr is a valid non-zero status code the event is recorded as a
// paired request+response. The response timestamp is set to the same value as
// the request timestamp because the caller (e.g. mitmproxy) already observed
// both sides and reports them in a single event — no artificial RTT offset is
// applied. If the caller learns about the response later, use
// ObserveHTTPResponse instead.
func (c *Collector) ObserveHTTP(method, url, statusStr, host, timestampStr string) {
	if method == "" || url == "" {
		return
	}
	ev := httpEvent{method: method, url: url, host: host}
	ev.timestampMS = c.parseTimestampMS(timestampStr)
	if s, err := strconv.Atoi(statusStr); err == nil && s > 0 {
		ev.status = s
		// The response is considered simultaneous with the request: both were
		// delivered in the same telemetry event. No artificial RTT offset.
		ev.responseTS = ev.timestampMS
	}
	c.mu.Lock()
	idx := len(c.events)
	c.events = append(c.events, ev)
	if ev.status == 0 {
		// Register this request as a pending orphan so a later
		// ObserveHTTPResponse can pair it in O(1).
		if c.orphanIdx == nil {
			c.orphanIdx = make(map[string][]int)
		}
		key := httpKey(method, url)
		c.orphanIdx[key] = append(c.orphanIdx[key], idx)
	}
	c.recordExchangeLocked(method, url, ev.timestampMS)
	c.mu.Unlock()
}

// httpKey is the pairing key for matching a response to its request.
func httpKey(method, url string) string {
	return method + " " + url
}

// httpExchangeKey identifies a specific observed exchange for cross-source
// dedup: same method+url at the same millisecond is the same exchange.
func httpExchangeKey(method, url string, timestampMS int64) string {
	return method + " " + url + " " + strconv.FormatInt(timestampMS, 10)
}

// recordExchangeLocked notes that (method,url,timestampMS) has been observed
// so MergeMitmCaptureJSON can dedup an identical entry. Caller holds c.mu.
func (c *Collector) recordExchangeLocked(method, url string, timestampMS int64) {
	if c.seenExchange == nil {
		c.seenExchange = make(map[string]struct{})
	}
	c.seenExchange[httpExchangeKey(method, url, timestampMS)] = struct{}{}
}

// ObserveHTTPResponse records the response side of a previously observed
// request identified by (method, url). It updates the most recent matching
// pending-orphan event (status == 0) in place. This is intended for callers
// that learn about a response after the fact — e.g. when the Rust live capture
// path delivers request and response as separate events.
//
// If no matching orphan is found a new paired event is appended so the
// response is not silently dropped.
func (c *Collector) ObserveHTTPResponse(method, url string, status int, timestampStr string) {
	if method == "" || url == "" || status <= 0 {
		return
	}
	ts := c.parseTimestampMS(timestampStr)

	c.mu.Lock()
	defer c.mu.Unlock()

	// Pop the most recent pending orphan for this (method,url) via the index,
	// in O(1) amortised time instead of scanning all of c.events.
	key := httpKey(method, url)
	if idxs := c.orphanIdx[key]; len(idxs) > 0 {
		// Take the most recent orphan (last appended).
		last := len(idxs) - 1
		evIdx := idxs[last]
		c.orphanIdx[key] = idxs[:last]
		if len(c.orphanIdx[key]) == 0 {
			delete(c.orphanIdx, key)
		}
		ev := &c.events[evIdx]
		ev.status = status
		ev.responseTS = ts
		return
	}

	// No matching orphan found — append a synthetic paired event so the
	// response is not silently dropped.
	ev := httpEvent{
		method:      method,
		url:         url,
		timestampMS: ts,
		status:      status,
		responseTS:  ts,
	}
	c.events = append(c.events, ev)
	c.recordExchangeLocked(method, url, ts)
}

// ObserveDNS records one DNS query and its resolved addresses so the Rust
// dns_flow_binder can later match it against an ObserveFlow'd destination.
// responseIPs must be dotted-quad IPv4 strings — Rust deserializes this
// field as Vec<Ipv4Addr> (see rust/crates/omnisec-mitm/src/capture.rs), so
// any entry that fails net.ParseIP as IPv4 is dropped rather than sent,
// since a single malformed entry would fail the whole capture's JSON decode
// on the Rust side. queryName is required; a query with no resolved IPs at
// all is still recorded (as an unresolved query — a legitimate finding, not
// an error).
func (c *Collector) ObserveDNS(queryName string, recordType uint16, responseIPs []string, timestampStr string) {
	if queryName == "" {
		return
	}
	ips := make([]string, 0, len(responseIPs))
	for _, ip := range responseIPs {
		if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
			ips = append(ips, parsed.To4().String())
		}
	}
	ev := dnsEvent{
		timestampMS: c.parseTimestampMS(timestampStr),
		queryName:   queryName,
		recordType:  recordType,
		responseIPs: ips,
	}
	c.mu.Lock()
	c.dnsEvents = append(c.dnsEvents, ev)
	c.mu.Unlock()
}

// ObserveTLS records one intercepted TLS handshake (SNI, cipher suite, JA3
// client fingerprint, ALPN) so it crosses into Rust as a tls_handshake event.
// sni may be empty (some clients omit SNI); a handshake with neither an SNI
// nor a JA3 fingerprint carries no signal and is dropped.
func (c *Collector) ObserveTLS(sni, cipherSuite, ja3, ja3Hash string, certFPs, alpn []string, timestampStr string) {
	if sni == "" && ja3Hash == "" {
		return
	}
	ev := tlsEvent{
		timestampMS: c.parseTimestampMS(timestampStr),
		sni:         sni,
		cipherSuite: cipherSuite,
		certFPs:     append([]string(nil), certFPs...),
		ja3:         ja3,
		ja3Hash:     ja3Hash,
		alpn:        append([]string(nil), alpn...),
	}
	c.mu.Lock()
	c.tlsEvents = append(c.tlsEvents, ev)
	c.mu.Unlock()
}

// ObserveFlow records one outbound network flow so the Rust dns_flow_binder
// can match its destination IP against a preceding ObserveDNS resolution.
// dstIP is required; entries with an unparseable dstIP are dropped for the
// same reason as ObserveDNS's responseIPs — Rust's capture schema expects a
// valid IpAddr and a decode failure would drop the entire capture.
func (c *Collector) ObserveFlow(srcIP string, srcPort uint16, dstIP string, dstPort uint16, bytes, durationMS uint64, protocol, timestampStr string) {
	if dstIP == "" || net.ParseIP(dstIP) == nil {
		return
	}
	ev := flowEvent{
		timestampMS: c.parseTimestampMS(timestampStr),
		srcIP:       srcIP,
		srcPort:     srcPort,
		dstIP:       dstIP,
		dstPort:     dstPort,
		bytes:       bytes,
		durationMS:  durationMS,
		protocol:    protocol,
	}
	c.mu.Lock()
	c.flowEvents = append(c.flowEvents, ev)
	c.mu.Unlock()
}

// MergeMitmCaptureJSON parses raw MitmCapture JSON — the shape
// mitmbridge.TakeCapture returns, draining the Rust live-capture
// accumulator populated by the SSL-strip/DNS-spoof/obfs proxy runners — and
// merges its request/response/DNS/flow/TLS entries into this collector's
// accumulated state, so a subsequent Reconcile includes them alongside
// telemetry-derived events. tls_handshakes are now merged too, since ssl.rs's
// CONNECT handler populates them live (see mitmCapture's doc comment).
//
// Unlike ObserveHTTP, request/response entries pass through verbatim rather
// than going through method+url+status pairing here — Rust's bind_effects
// already does that pairing downstream, so re-deriving it in Go would just
// duplicate logic and risk disagreeing with it.
//
// Cross-source dedup: an HTTP request whose (method, url, timestamp_ms)
// exactly matches one already recorded through the telemetry path
// (ObserveHTTP) is dropped, since the same exchange can reach the collector
// from both mitmproxy telemetry and the Rust live-capture accumulator, and
// counting it twice inflates TotalEvents and skews d_causal/coverage. Only
// exact triples are treated as duplicates — a genuine re-request of the same
// URL at a different millisecond is kept.
//
// An empty payload (e.g. draining a store nothing ever wrote to) is a safe
// no-op, not an error.
func (c *Collector) MergeMitmCaptureJSON(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}

	var drained mitmCapture
	if err := json.Unmarshal(raw, &drained); err != nil {
		return fmt.Errorf("ncer: unmarshal drained mitm capture: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range drained.HTTPRequests {
		key := httpExchangeKey(r.Method, r.URL, r.TimestampMS)
		if _, dup := c.seenExchange[key]; dup {
			continue // already recorded via telemetry; don't double-count
		}
		c.recordExchangeLocked(r.Method, r.URL, r.TimestampMS)
		c.extraHTTPRequests = append(c.extraHTTPRequests, r)
	}
	c.extraHTTPResponses = append(c.extraHTTPResponses, drained.HTTPResponses...)
	for _, q := range drained.DNSQueries {
		c.dnsEvents = append(c.dnsEvents, dnsEvent{
			timestampMS: q.TimestampMS,
			queryName:   q.QueryName,
			recordType:  q.RecordType,
			responseIPs: q.ResponseIPs,
		})
	}
	for _, f := range drained.FlowSummaries {
		c.flowEvents = append(c.flowEvents, flowEvent{
			timestampMS: f.TimestampMS,
			srcIP:       f.SrcIP,
			srcPort:     f.SrcPort,
			dstIP:       f.DstIP,
			dstPort:     f.DstPort,
			bytes:       f.Bytes,
			durationMS:  f.DurationMS,
			protocol:    f.Protocol,
		})
	}
	for _, t := range drained.TLSHandshakes {
		c.tlsEvents = append(c.tlsEvents, tlsEvent{
			timestampMS: t.TimestampMS,
			sni:         t.SNI,
			cipherSuite: t.CipherSuite,
			certFPs:     t.CertChainFingerprints,
			ja3:         t.JA3,
			ja3Hash:     t.JA3Hash,
			alpn:        t.ALPN,
		})
	}
	return nil
}

// parseTimestampMS converts an "HH:MM:SS.mmm" wire timestamp (a time-of-day
// with no date, relative to c.baseTime's date) into a Unix millisecond
// timestamp that stays monotonic across a session that crosses midnight.
//
// The parse is done by hand rather than with fmt.Sscanf: this runs once per
// observed event on the hot path, and Sscanf allocates and reflects on every
// call. On any malformed input the fallback is deterministic — the last
// timestamp handed out (or c.baseTime at session start) — never time.Now(),
// so a given input stream always produces the same output regardless of when
// it is replayed.
//
// Midnight rollover: the wire format carries no date, so when the clock wraps
// past 00:00 the raw time-of-day drops by nearly a full day. We track the
// previous time-of-day and, on a large backward jump, advance a whole-day
// offset so the emitted Unix-ms value keeps increasing instead of leaping ~24h
// backwards (which would shatter the reconciler's 5 s binding window).
func (c *Collector) parseTimestampMS(s string) int64 {
	base := c.baseTime
	midnight := time.Date(base.Year(), base.Month(), base.Day(), 0, 0, 0, 0, base.Location())
	midnightMs := midnight.UnixMilli()

	c.tsMu.Lock()
	defer c.tsMu.Unlock()

	todMs, ok := parseTimeOfDayMS(s)
	if !ok {
		// Deterministic fallback: reuse the last time-of-day (or 0 at start),
		// never wall-clock time.
		if c.tsLastTODMs >= 0 {
			return midnightMs + c.tsDayOffsetMs + c.tsLastTODMs
		}
		return midnightMs
	}

	// Detect a backward wrap of more than 12h and treat it as a new day. A
	// small backward step (out-of-order events within the same second) is not
	// a rollover and must not inflate the offset.
	if c.tsLastTODMs >= 0 && todMs+12*60*60*1000 < c.tsLastTODMs {
		c.tsDayOffsetMs += 24 * 60 * 60 * 1000
	}
	c.tsLastTODMs = todMs
	return midnightMs + c.tsDayOffsetMs + todMs
}

// parseTimeOfDayMS parses "HH:MM:SS.mmm" (the fractional part optional and of
// any length, interpreted as a decimal fraction of a second) into milliseconds
// since midnight. It reports ok=false for any structurally invalid input or
// out-of-range field, so the caller can apply a deterministic fallback. An
// empty string is invalid.
func parseTimeOfDayMS(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	// Split off the optional fractional-seconds part. A dot with no digits
	// after it (e.g. "10:00:00.") is malformed.
	frac := ""
	if dot := indexByte(s, '.'); dot >= 0 {
		frac = s[dot+1:]
		s = s[:dot]
		if frac == "" {
			return 0, false
		}
	}
	// s must be HH:MM:SS.
	h, rest, ok := splitField(s, ':')
	if !ok {
		return 0, false
	}
	m, sec, ok := splitField(rest, ':')
	if !ok {
		return 0, false
	}
	hh, ok := atoiFixed(h)
	if !ok || hh < 0 || hh > 23 {
		return 0, false
	}
	mm, ok := atoiFixed(m)
	if !ok || mm < 0 || mm > 59 {
		return 0, false
	}
	ss, ok := atoiFixed(sec)
	if !ok || ss < 0 || ss > 60 { // allow 60 for leap seconds
		return 0, false
	}
	ms := 0
	if frac != "" {
		f, ok := atoiFixed(frac)
		if !ok {
			return 0, false
		}
		// Normalise the fraction to milliseconds regardless of its length:
		// ".5" -> 500ms, ".123456" -> 123ms.
		switch {
		case len(frac) == 1:
			ms = f * 100
		case len(frac) == 2:
			ms = f * 10
		case len(frac) == 3:
			ms = f
		default: // 4+ digits: keep the first 3
			for len(frac) > 3 {
				f /= 10
				frac = frac[:len(frac)-1]
			}
			ms = f
		}
	}
	total := int64(hh)*3600000 + int64(mm)*60000 + int64(ss)*1000 + int64(ms)
	return total, true
}

// splitField splits s at the first occurrence of sep into (before, after),
// reporting ok=false if sep is absent.
func splitField(s string, sep byte) (string, string, bool) {
	i := indexByte(s, sep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// indexByte returns the index of the first b in s, or -1.
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// atoiFixed parses a non-empty run of ASCII digits into an int, reporting
// ok=false for empty input or any non-digit byte. It never allocates.
func atoiFixed(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		d := s[i]
		if d < '0' || d > '9' {
			return 0, false
		}
		n = n*10 + int(d-'0')
	}
	return n, true
}

// Len returns the number of HTTP events recorded so far.
func (c *Collector) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// hasReconcilableData reports whether the collector has anything worth
// sending through the reconciliation pipeline: HTTP events, or authority
// events on their own (a session with no HTTP traffic but Android permission
// data still has a meaningful d_authority/d_capability to compute).
func (c *Collector) hasReconcilableData() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events) > 0 || len(c.authorityEvents) > 0 ||
		len(c.dnsEvents) > 0 || len(c.flowEvents) > 0 || len(c.tlsEvents) > 0 ||
		len(c.extraHTTPRequests) > 0 || len(c.extraHTTPResponses) > 0
}

// buildCapture converts accumulated events into a MitmCapture.
//
// Each event that has a status code produces both a request and a matching
// response. The response timestamp comes from ev.responseTS — the real observed
// response time — which for mitmproxy-sourced events equals the request
// timestamp (both reported in one event), and for ObserveHTTPResponse-updated
// events is the actual response arrival time. No artificial RTT offset is ever
// applied.
//
// Events without a status code produce only a request entry (true orphans).
//
// DNS queries, flow summaries and TLS handshakes (see
// ObserveDNS/ObserveFlow/ObserveTLS) are included verbatim.
// Request/response entries merged via MergeMitmCaptureJSON are included
// verbatim too, ahead of the ones derived from httpEvent.
func (c *Collector) buildCapture() mitmCapture {
	c.mu.Lock()
	evs := make([]httpEvent, len(c.events))
	copy(evs, c.events)
	dnsEvs := make([]dnsEvent, len(c.dnsEvents))
	copy(dnsEvs, c.dnsEvents)
	flowEvs := make([]flowEvent, len(c.flowEvents))
	copy(flowEvs, c.flowEvents)
	tlsEvs := make([]tlsEvent, len(c.tlsEvents))
	copy(tlsEvs, c.tlsEvents)
	extraReqs := append([]mitmHTTPRequest(nil), c.extraHTTPRequests...)
	extraResps := append([]mitmHTTPResponse(nil), c.extraHTTPResponses...)
	c.mu.Unlock()

	cap := mitmCapture{
		HTTPRequests:  make([]mitmHTTPRequest, 0, len(evs)+len(extraReqs)),
		HTTPResponses: make([]mitmHTTPResponse, 0, len(evs)+len(extraResps)),
		DNSQueries:    make([]mitmDNSQuery, 0, len(dnsEvs)),
		TLSHandshakes: make([]mitmTLSHandshake, 0, len(tlsEvs)),
		FlowSummaries: make([]mitmFlowSummary, 0, len(flowEvs)),
	}
	cap.HTTPRequests = append(cap.HTTPRequests, extraReqs...)
	cap.HTTPResponses = append(cap.HTTPResponses, extraResps...)
	for _, ev := range evs {
		// Carry the host as a Host header when known: it is the key the Rust
		// dns_flow_binder uses to correlate this request with a DNS resolution
		// and outbound flow for the same host. Empty host -> no header, rather
		// than an empty-valued one.
		headers := map[string]string{}
		if ev.host != "" {
			headers["Host"] = ev.host
		}
		cap.HTTPRequests = append(cap.HTTPRequests, mitmHTTPRequest{
			TimestampMS: ev.timestampMS,
			Method:      ev.method,
			URL:         ev.url,
			Headers:     headers,
		})
		if ev.status > 0 {
			// Use the real response timestamp. For mitmproxy-sourced events this
			// equals the request timestamp (no offset); for ObserveHTTPResponse-
			// updated events it is the actual arrival time.
			responseTS := ev.responseTS
			if responseTS == 0 {
				responseTS = ev.timestampMS
			}
			cap.HTTPResponses = append(cap.HTTPResponses, mitmHTTPResponse{
				TimestampMS:   responseTS,
				Status:        ev.status,
				Headers:       map[string]string{},
				RequestMethod: ev.method,
				RequestURL:    ev.url,
			})
		}
	}
	for _, ev := range dnsEvs {
		ips := ev.responseIPs
		if ips == nil {
			ips = []string{}
		}
		cap.DNSQueries = append(cap.DNSQueries, mitmDNSQuery{
			TimestampMS: ev.timestampMS,
			QueryName:   ev.queryName,
			RecordType:  ev.recordType,
			ResponseIPs: ips,
		})
	}
	for _, ev := range flowEvs {
		cap.FlowSummaries = append(cap.FlowSummaries, mitmFlowSummary{
			TimestampMS: ev.timestampMS,
			SrcIP:       ev.srcIP,
			SrcPort:     ev.srcPort,
			DstIP:       ev.dstIP,
			DstPort:     ev.dstPort,
			Bytes:       ev.bytes,
			DurationMS:  ev.durationMS,
			Protocol:    ev.protocol,
		})
	}
	for _, ev := range tlsEvs {
		fps := ev.certFPs
		if fps == nil {
			fps = []string{}
		}
		cap.TLSHandshakes = append(cap.TLSHandshakes, mitmTLSHandshake{
			TimestampMS:           ev.timestampMS,
			SNI:                   ev.sni,
			CipherSuite:           ev.cipherSuite,
			CertChainFingerprints: fps,
			JA3:                   ev.ja3,
			JA3Hash:               ev.ja3Hash,
			ALPN:                  ev.alpn,
		})
	}
	return cap
}

// buildReconcileInput wraps buildCapture's HTTP capture together with any
// accumulated authority events into the flattened JSON shape
// omnisec_ncer_reconcile expects (see reconcileInput's doc comment).
func (c *Collector) buildReconcileInput() reconcileInput {
	c.mu.Lock()
	authEvents := append([]TypedEvent(nil), c.authorityEvents...)
	c.mu.Unlock()

	return reconcileInput{
		mitmCapture:     c.buildCapture(),
		AuthorityEvents: authEvents,
	}
}

// Reconcile runs the NCER causal reconciliation pipeline over the accumulated
// events with the Rust-side default binding window (5 s). It returns (nil, nil)
// when:
//   - neither HTTP nor authority events were observed (nothing to reconcile);
//   - the Rust library is not linked (stub path, ErrRustNotLinked).
//
// Any other error is returned so the caller can log it as a warning. It is
// shorthand for ReconcileContext(context.Background(), 0).
func (c *Collector) Reconcile() (*types.NcerCausalResult, error) {
	return c.ReconcileContext(context.Background(), 0)
}

// ReconcileWithWindow is like Reconcile but uses the caller-supplied binding
// window instead of the Rust-side 5-second default. A zero or negative window
// falls back to the Rust default. Shorthand for
// ReconcileContext(context.Background(), window).
func (c *Collector) ReconcileWithWindow(window time.Duration) (*types.NcerCausalResult, error) {
	return c.ReconcileContext(context.Background(), window)
}

// ReconcileContext is the single implementation behind Reconcile and
// ReconcileWithWindow. It runs the pipeline with the given binding window
// (window <= 0 uses the Rust-side default) and honours ctx: if ctx is
// cancelled or times out before the FFI call returns, ReconcileContext returns
// ctx.Err() instead of blocking forever on a hung native call. The FFI call
// itself cannot be interrupted, so its goroutine is left to finish and its
// result discarded — bounding the *caller's* wait, not the native work.
//
// Returns (nil, nil) when there is nothing to reconcile or the Rust library is
// not linked (stub path).
func (c *Collector) ReconcileContext(ctx context.Context, window time.Duration) (*types.NcerCausalResult, error) {
	if !c.hasReconcilableData() {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	input := c.buildReconcileInput()
	jsonBytes, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("ncer: marshal capture: %w", err)
	}

	r, err := c.runReconcileCtx(ctx, jsonBytes, window)
	if err != nil {
		if errors.Is(err, reconcile.ErrRustNotLinked) {
			// Silent: stub path is the expected state in normal go test ./...
			return nil, nil
		}
		return nil, err
	}
	if r == nil {
		return nil, nil
	}

	evidenceRefs, verified := c.trackEvidence(jsonBytes)

	result := &types.NcerCausalResult{
		BoundCount:       r.BoundCount,
		UnboundCount:     r.UnboundCount,
		OrphanCount:      r.OrphanCount,
		TotalEvents:      r.TotalEvents,
		DCausal:          r.DCausal,
		CoverageQuality:  r.CoverageQuality,
		DAuthority:       r.DAuthority,
		DInformation:     r.DInformation,
		DCapability:      r.DCapability,
		EvidenceRefs:     evidenceRefs,
		EvidenceVerified: verified,
		EvidenceCount:    len(evidenceRefs),
	}
	c.scoreConsequenceAndNovelty(result)
	return result, nil
}

// runReconcileCtx invokes the FFI reconciliation (windowed when window > 0)
// on a background goroutine and returns as soon as either it completes or ctx
// is done, whichever comes first. The native call is uninterruptible, so on
// ctx cancellation the goroutine is abandoned to finish on its own; a
// buffered result channel ensures it never blocks on send when nobody is
// listening.
func (c *Collector) runReconcileCtx(ctx context.Context, jsonBytes []byte, window time.Duration) (*reconcile.Result, error) {
	type ffiResult struct {
		r   *reconcile.Result
		err error
	}
	ch := make(chan ffiResult, 1)
	go func() {
		var r *reconcile.Result
		var err error
		if window > 0 {
			r, err = reconcile.RunReconcileWindowed(jsonBytes, window)
		} else {
			r, err = reconcile.RunReconcile(jsonBytes)
		}
		ch <- ffiResult{r: r, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		if res.err != nil {
			if errors.Is(res.err, reconcile.ErrRustNotLinked) {
				return nil, res.err
			}
			return nil, fmt.Errorf("ncer: reconcile: %w", res.err)
		}
		return res.r, nil
	}
}

// trackEvidence stores the reconciled capture JSON in the collector's
// EvidenceStore (if attached) and returns the resulting evidence references
// and whether they were verified. The Rust FFI result carries no evidence of
// its own (see reconcile.Result's doc comment); evidence tracking is entirely
// this collector's job, keyed on the hash of the capture JSON reconciled.
func (c *Collector) trackEvidence(jsonBytes []byte) (refs []string, verified bool) {
	c.mu.Lock()
	store := c.evidenceStore
	c.mu.Unlock()

	if store == nil {
		// No store attached: derive the hash but mark unverified.
		return []string{hexSHA256(jsonBytes)}, false
	}

	hash, err := store.Store(jsonBytes)
	if err != nil || hash == "" {
		return []string{}, false
	}
	ok, verr := store.Verify(hash)
	return []string{hash}, verr == nil && ok
}

// scoreConsequenceAndNovelty fills in DConsequence and DNovelty, the two
// DiscrepancyVector sub-dimensions Rust never computes (see reconcile.Result's
// doc comment). Implemented in consequence.go and novelty.go respectively.
func (c *Collector) scoreConsequenceAndNovelty(result *types.NcerCausalResult) {
	c.scoreConsequence(result)
	c.scoreNovelty(result)
}
