package vulnscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ScanMode controls how much traffic the web scanner is allowed to generate.
// Status and passive modes issue exactly one GET request. Active mode runs the
// full crawler and vulnerability checks and therefore keeps the ownership gate.
type ScanMode string

const (
	ScanModeStatus  ScanMode = "status"
	ScanModePassive ScanMode = "passive"
	ScanModeActive  ScanMode = "active"
)

// ParseScanMode normalizes a user-facing mode name. A few explicit aliases are
// accepted so API and CLI callers can use "alive" or "vulnerabilities" without
// creating additional execution modes.
func ParseScanMode(raw string) (ScanMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "status", "alive", "health":
		return ScanModeStatus, nil
	case "passive", "safe":
		return ScanModePassive, nil
	case "active", "vuln", "vulns", "vulnerability", "vulnerabilities":
		return ScanModeActive, nil
	default:
		return "", fmt.Errorf("invalid web scan mode %q (valid: status, passive, active)", raw)
	}
}

// StatusResult is the result of the low-impact availability check.
// Reachable means that an HTTP response was received; OK is deliberately
// stricter and is true only for HTTP 200, as requested by the CLI contract.
type StatusResult struct {
	URL        string        `json:"url"`
	StatusCode int           `json:"status_code"`
	Status     string        `json:"status"`
	Reachable  bool          `json:"reachable"`
	OK         bool          `json:"ok"`
	Duration   time.Duration `json:"duration"`
}

// ModeResult is the common result envelope used by the unified analyzer.
// Findings is populated by passive and active modes. Status is populated by
// status and passive modes.
type ModeResult struct {
	Mode     ScanMode        `json:"mode"`
	Status   *StatusResult   `json:"status,omitempty"`
	Findings []Vulnerability `json:"findings,omitempty"`
}

// ScanWithMode dispatches to one of the bounded scanner modes. It never turns
// a low-impact mode into an active scan implicitly.
func (s *Scanner) ScanWithMode(ctx context.Context, mode ScanMode) (*ModeResult, error) {
	canonical, err := ParseScanMode(string(mode))
	if err != nil {
		return nil, err
	}
	mode = canonical
	if ctx == nil {
		ctx = context.Background()
	}
	switch mode {
	case ScanModeStatus:
		status, err := s.CheckStatus(ctx)
		if err != nil {
			return nil, err
		}
		return &ModeResult{Mode: mode, Status: status}, nil
	case ScanModePassive:
		status, findings, err := s.ScanPassive(ctx)
		if err != nil {
			return nil, err
		}
		return &ModeResult{Mode: mode, Status: status, Findings: findings}, nil
	case ScanModeActive:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		findings, err := s.Scan()
		if err != nil {
			return nil, err
		}
		return &ModeResult{Mode: mode, Findings: findings}, nil
	default:
		return nil, fmt.Errorf("unsupported web scan mode %q", mode)
	}
}

// CheckStatus performs one GET request and reports whether the server returned
// HTTP 200. Redirects are not followed by the default scanner client, so the
// result always describes the exact URL supplied by the caller.
func (s *Scanner) CheckStatus(ctx context.Context) (*StatusResult, error) {
	resp, duration, err := s.getOnce(ctx)
	if err != nil {
		return nil, fmt.Errorf("status check failed: %w", err)
	}
	defer resp.Body.Close()

	// Drain only a tiny prefix so a health check cannot accidentally download a
	// large page while still allowing the HTTP transport to reuse short bodies.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))

	return newStatusResult(s.Target, resp, duration), nil
}

// ScanPassive performs a single GET and analyzes only the returned headers and
// body. It does not crawl, render a DOM, mutate parameters, fuzz forms, probe
// endpoints, or require the active-scan ownership acknowledgement.
func (s *Scanner) ScanPassive(ctx context.Context) (*StatusResult, []Vulnerability, error) {
	resp, duration, err := s.getOnce(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("passive scan failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ReadBodyBounded(resp, int64(s.Config.MaxBodyBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("passive scan response: %w", err)
	}
	body := string(bodyBytes)

	findings := make([]Vulnerability, 0)
	findings = append(findings, s.checkSecurityHeaders(resp.Header)...)
	findings = append(findings, s.RunDynamicHeaderRules(resp.Header)...)
	findings = append(findings, s.checkCookieFlags(resp)...)
	findings = append(findings, s.checkJWTs(resp, body)...)
	findings = append(findings, s.detectSecrets(body, s.Target)...)
	findings = append(findings, s.RunDynamicPassiveRules(body, s.Target)...)

	return newStatusResult(s.Target, resp, duration), findings, nil
}

func (s *Scanner) getOnce(ctx context.Context) (*http.Response, time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.Target, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", s.Config.UserAgent)

	baseHost := ""
	if s.BaseURL != nil {
		baseHost = s.BaseURL.Host
	}
	sanitizer := NewRequestSanitizer(s.Config, baseHost)
	if err := sanitizer.Validate(req); err != nil {
		return nil, 0, err
	}

	start := time.Now()
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return nil, duration, err
	}
	return resp, duration, nil
}

func newStatusResult(target string, resp *http.Response, duration time.Duration) *StatusResult {
	return &StatusResult{
		URL:        target,
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Reachable:  true,
		OK:         resp.StatusCode == http.StatusOK,
		Duration:   duration,
	}
}
