package vulnscan

import (
	"net/http"
	"strings"
)

// checkAPI security misconfigurations.
func (s *Scanner) checkAPI() []Vulnerability {
	const probeHeader = "X-Mega-Analyzer-Trace-Probe"
	const probeValue = "mzc-trace-probe"

	req, err := http.NewRequest(http.MethodTrace, s.Target, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", s.Config.UserAgent)
	req.Header.Set(probeHeader, probeValue)

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
	if err != nil || resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil
	}
	body := string(bodyBytes)
	if !strings.Contains(body, probeHeader) || !strings.Contains(body, probeValue) {
		return nil
	}

	return []Vulnerability{{
		ID:          "WS-API-001",
		Name:        "HTTP TRACE Method Enabled (Cross-Site Tracing)",
		Description: "The HTTP TRACE method is enabled and reflects a request header. This can enable Cross-Site Tracing attacks in unsafe browser configurations.",
		Severity:    SeverityMedium,
		URL:         s.Target,
		Evidence:    "Server returned a successful TRACE response containing the scanner's unique probe header.",
		Mitigation:  "Disable the HTTP TRACE method in the web server configuration.",
	}}
}
