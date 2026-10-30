package vulnscan

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"
)

type gatewayCtxKey int

const ctxAnonymousRequest gatewayCtxKey = iota

// WithAnonymousRequest marks a request so the gateway skips credential
// injection for it. Differential checks (BOLA, auth-bypass) need genuinely
// unauthenticated probes even when authenticated scanning is configured.
func WithAnonymousRequest(req *http.Request) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), ctxAnonymousRequest, true))
}

func isAnonymousRequest(req *http.Request) bool {
	v, _ := req.Context().Value(ctxAnonymousRequest).(bool)
	return v
}

// RequestGateway is the single instrumented HTTP layer every scanner request
// passes through. It centralises concerns that were previously scattered (or
// missing) across checks:
//
//   - rate pacing (PID throttle) — one controller for BOTH pipelines
//   - authenticated scanning (cookie/bearer injection)
//   - scope/sanitization enforcement (allowlist, CRLF, scheme)
//   - request/response telemetry
//   - AIMD backpressure feedback on 429/5xx (previously dead code)
//
// Checks must no longer call Throttle.Wait/Observe themselves; the gateway
// owns the pacing loop.
type RequestGateway struct {
	inner     http.RoundTripper
	scanner   *Scanner
	Sanitizer *RequestSanitizer
	Telemetry *ScanTelemetry
	AIMD      *AIMDController
}

// NewRequestGateway builds a gateway bound to a scanner. Throttle/config are
// read lazily so a PID controller installed after construction (Scan does
// this) is honoured automatically.
func NewRequestGateway(s *Scanner) *RequestGateway {
	return &RequestGateway{
		inner:   http.DefaultTransport,
		scanner: s,
	}
}

// RoundTrip implements http.RoundTripper.
func (g *RequestGateway) RoundTrip(req *http.Request) (*http.Response, error) {
	if g.Sanitizer != nil {
		if err := g.Sanitizer.Validate(req); err != nil {
			return nil, err
		}
	}

	cfg := g.scanner.Config
	// Authenticated scanning: inject configured credentials unless the check
	// already set its own (e.g. BOLA tests sending a secondary identity) or
	// explicitly opted out (differential anonymous probes).
	if !isAnonymousRequest(req) {
		if cfg.AuthCookie != "" && req.Header.Get("Cookie") == "" {
			req.Header.Set("Cookie", cfg.AuthCookie)
		}
		if cfg.AuthBearer != "" && req.Header.Get("Authorization") == "" {
			req.Header.Set("Authorization", "Bearer "+cfg.AuthBearer)
		}
	}

	if throttle := g.scanner.Throttle; throttle != nil {
		throttle.Wait()
	}
	if g.Telemetry != nil {
		g.Telemetry.OnRequest()
	}

	start := time.Now()
	resp, err := g.inner.RoundTrip(req)
	elapsed := time.Since(start)

	if g.scanner != nil && g.scanner.Ledger != nil && resp != nil && resp.Body != nil && err == nil {
		g.scanner.Ledger.Record(recordInteraction(req, resp, elapsed))
	}

	if throttle := g.scanner.Throttle; throttle != nil {
		throttle.Observe(elapsed)
	}

	if err != nil {
		if g.Telemetry != nil {
			g.Telemetry.OnResponse(false)
		}
		return nil, err
	}
	if g.Telemetry != nil {
		g.Telemetry.OnResponse(true)
	}

	// Backpressure: feed server pressure signals into the AIMD controller so
	// concurrency collapses on 429/502/503/504 and recovers on success.
	if g.AIMD != nil {
		if IsServerPressure(resp.StatusCode) {
			g.AIMD.OnServerPressure()
		} else if resp.StatusCode < 500 {
			g.AIMD.OnSuccess()
		}
	}

	return resp, nil
}

// recordInteraction snapshots one exchange for the forensic Ledger. The body
// is bounded so an adversarial target cannot exhaust scanner memory; overlong
// bodies are tagged "truncated". The response body is restored so callers
// observe the gateway as transparent.
func recordInteraction(req *http.Request, resp *http.Response, elapsed time.Duration) Interaction {
	const recordBodyLimit = 256 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, recordBodyLimit+1))
	resp.Body.Close()
	if err != nil {
		body = nil
	}
	truncated := len(body) > recordBodyLimit
	if truncated {
		body = body[:recordBodyLimit]
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	tags := []string{req.Method}
	if truncated {
		tags = append(tags, "truncated")
	}
	return Interaction{
		Request:  req.Clone(req.Context()),
		Response: resp,
		Body:     body,
		Duration: elapsed,
		CheckID:  checkIDFromContext(req.Context()),
		Tags:     tags,
	}
}
