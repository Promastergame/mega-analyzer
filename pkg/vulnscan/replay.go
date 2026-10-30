package vulnscan

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sort"
)

// RecordedExchange is one Ledger interaction flattened for offline replay.
// Recorded responses are evidence; a replayed response proves the client
// logic behaves the same on the same bytes, never that the server would
// answer identically today.
type RecordedExchange struct {
	Method       string
	URL          string
	RequestBody  []byte
	Status       int
	Headers      http.Header
	ResponseBody []byte
}

// SnapshotExchanges copies recorded interactions (optionally filtered by
// check ID, empty means all) into replayable exchanges, oldest first.
func SnapshotExchanges(ledger *Ledger, checkID string) []RecordedExchange {
	if ledger == nil {
		return nil
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	var out []RecordedExchange
	for k := 0; k < ledger.size; k++ {
		in := ledger.entries[(ledger.head+k)%ledger.maxSize]
		if checkID != "" && in.CheckID != checkID {
			continue
		}
		if in.Request == nil || in.Response == nil {
			continue
		}
		var reqBody []byte
		if in.Request.Body != nil && in.Request.GetBody != nil {
			if rc, err := in.Request.GetBody(); err == nil && rc != nil {
				reqBody, _ = io.ReadAll(io.LimitReader(rc, 5<<20))
				rc.Close()
			}
		}
		headers := http.Header{}
		for k, v := range in.Response.Header {
			headers[k] = append([]string(nil), v...)
		}
		out = append(out, RecordedExchange{
			Method:       in.Request.Method,
			URL:          in.Request.URL.String(),
			RequestBody:  reqBody,
			Status:       in.Response.StatusCode,
			Headers:      headers,
			ResponseBody: append([]byte(nil), in.Body...),
		})
	}
	return out
}

// ReplayTransport serves recorded exchanges without touching the network.
// Unknown requests are an explicit offline error, never forwarded. Bodies
// must match exactly: a replay with different dynamic values is a new
// scenario, not a reproduction.
type ReplayTransport struct {
	Exchanges []RecordedExchange
	// MatchBody disables body comparison (for GET-heavy scenarios).
	MatchBody bool
	Calls     int
	Misses    int
}

// RoundTrip implements http.RoundTripper.
func (t *ReplayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.Calls++
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(io.LimitReader(req.Body, 5<<20))
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	for _, ex := range t.Exchanges {
		if ex.Method != req.Method || ex.URL != req.URL.String() {
			continue
		}
		if t.MatchBody && !bytes.Equal(ex.RequestBody, reqBody) {
			continue
		}
		resp := &http.Response{
			Status:        fmt.Sprintf("%d %s", ex.Status, http.StatusText(ex.Status)),
			StatusCode:    ex.Status,
			Header:        ex.Headers.Clone(),
			Body:          io.NopCloser(bytes.NewReader(ex.ResponseBody)),
			ContentLength: int64(len(ex.ResponseBody)),
			Request:       req,
		}
		return resp, nil
	}
	t.Misses++
	return nil, fmt.Errorf("replay: no recorded exchange for %s %s (offline mode, %d recorded)", req.Method, req.URL.String(), len(t.Exchanges))
}

// ReplayClient builds an offline client serving this scanner's recorded
// exchanges for one check (empty checkID replays everything).
func (s *Scanner) ReplayClient(checkID string) *http.Client {
	return &http.Client{
		Transport: &ReplayTransport{Exchanges: SnapshotExchanges(s.Ledger, checkID), MatchBody: true},
	}
}

// ReplaySummary describes a replay run for evidence notes.
func (t *ReplayTransport) ReplaySummary() string {
	keys := make([]string, 0, len(t.Exchanges))
	for _, ex := range t.Exchanges {
		keys = append(keys, ex.Method+" "+ex.URL)
	}
	sort.Strings(keys)
	return fmt.Sprintf("replay: %d calls, %d misses, %d recorded", t.Calls, t.Misses, len(keys))
}
