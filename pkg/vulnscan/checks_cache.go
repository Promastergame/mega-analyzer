package vulnscan

import (
	"fmt"
	"net/http"
	"strings"
)

const cachePoisonProbeHost = "webcache-poisoning-test.evil.com"

type cacheProbe struct {
	body     string
	cacheHit bool
}

// checkCachePoisoning attempts Web Cache Poisoning via unkeyed headers.
func (s *Scanner) checkCachePoisoning() []Vulnerability {
	baseline, ok := s.cacheProbe("", "")
	if !ok {
		return nil
	}

	unkeyedHeaders := []struct {
		name  string
		value string
	}{
		{"X-Forwarded-Host", cachePoisonProbeHost},
		{"X-Host", cachePoisonProbeHost},
		{"X-Original-URL", "/" + cachePoisonProbeHost},
		{"X-Rewrite-URL", "/" + cachePoisonProbeHost},
	}

	for _, header := range unkeyedHeaders {
		if strings.Contains(baseline.body, cachePoisonProbeHost) {
			return nil
		}
		poisoned, ok := s.cacheProbe(header.name, header.value)
		if !ok || !strings.Contains(poisoned.body, cachePoisonProbeHost) {
			continue
		}
		confirmed, ok := s.cacheProbe("", "")
		if !ok || !strings.Contains(confirmed.body, cachePoisonProbeHost) {
			continue
		}

		return []Vulnerability{{
			ID:          "WS-CACHE-001",
			Name:        "Web Cache Poisoning via Unkeyed Header",
			Description: fmt.Sprintf("The unkeyed header '%s' was reflected and its value persisted into a subsequent request without that header.", header.name),
			Severity:    SeverityHigh,
			URL:         s.Target,
			Payload:     fmt.Sprintf("%s: %s", header.name, header.value),
			Evidence:    fmt.Sprintf("Poisoned value appeared in an unkeyed follow-up response. Cache signals observed: %v", poisoned.cacheHit || confirmed.cacheHit),
			Mitigation:  "Include all influential headers in the cache key or disable caching for responses that depend on them. Ignore or sanitize arbitrary X-Forwarded-* headers unless they come from a trusted proxy.",
		}}
	}

	return nil
}

func (s *Scanner) cacheProbe(headerName, value string) (cacheProbe, bool) {
	req, err := http.NewRequest(http.MethodGet, s.Target, nil)
	if err != nil {
		return cacheProbe{}, false
	}
	req.Header.Set("User-Agent", s.Config.UserAgent)
	if headerName != "" {
		req.Header.Set(headerName, value)
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return cacheProbe{}, false
	}
	defer resp.Body.Close()

	body, err := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
	if err != nil {
		return cacheProbe{}, false
	}

	return cacheProbe{body: string(body), cacheHit: hasCacheHit(resp.Header)}, true
}

func hasCacheHit(headers http.Header) bool {
	for _, name := range []string{"X-Cache", "Cf-Cache-Status", "X-Drupal-Cache", "Age"} {
		value := headers.Get(name)
		if value != "" && (name == "Age" || strings.Contains(strings.ToLower(value), "hit")) {
			return true
		}
	}
	return false
}
