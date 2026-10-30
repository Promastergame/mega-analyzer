package vulnscan

import (
	"io"
	"net/http"
)

// BodyNeed expresses how much of a response body a check actually requires,
// enabling memory-bounded reads. An adversarial target returning a 10GB body
// can no longer OOM the scanner via io.ReadAll.
type BodyNeed int

const (
	NeedHeaders   BodyNeed = iota // no body needed
	NeedPrefix                    // first 64KB (most signature checks)
	NeedFull                      // up to 5MB (full-page analysis)
	NeedStreaming                 // caller consumes resp.Body directly
)

const (
	prefixCap = 64 * 1024
	fullCap   = 5 * 1024 * 1024
)

// ReadBodyLimited reads at most as many bytes as the check needs. The caller
// still owns closing resp.Body.
func ReadBodyLimited(resp *http.Response, need BodyNeed) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	switch need {
	case NeedHeaders, NeedStreaming:
		return nil, nil
	case NeedPrefix:
		return io.ReadAll(io.LimitReader(resp.Body, prefixCap))
	case NeedFull:
		return io.ReadAll(io.LimitReader(resp.Body, fullCap))
	default:
		return io.ReadAll(io.LimitReader(resp.Body, fullCap))
	}
}

// ReadBodyBounded reads up to maxBytes, honouring an explicit caller bound
// (e.g. from ScannerConfig.MaxBodyBytes).
func ReadBodyBounded(resp *http.Response, maxBytes int64) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	if maxBytes <= 0 {
		maxBytes = fullCap
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

// readBody reads a response body capped by the scanner's configured
// MaxBodyBytes (default 5MB), so a hostile target cannot OOM the scanner
// with an oversized response. The caller still owns closing resp.Body.
func (s *Scanner) readBody(resp *http.Response) []byte {
	body, _ := ReadBodyBounded(resp, int64(maxOrDefault(s.Config.MaxBodyBytes, fullCap)))
	return body
}
