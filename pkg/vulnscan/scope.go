package vulnscan

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// RequestSanitizer validates every outbound request before it is sent. It
// makes TargetAllowlist (previously dead code) live, and hardens the scanner
// against being turned into a proxy or SSRF primitive via crafted curl / raw
// HTTP imports.
type RequestSanitizer struct {
	AllowedHosts []string
	MaxBodyBytes int64
	AllowPrivate bool // permit RFC1918 / loopback (lab mode only)
}

// NewRequestSanitizer builds a sanitizer from scanner configuration.
func NewRequestSanitizer(cfg ScannerConfig, baseHost string) *RequestSanitizer {
	hosts := append([]string{}, cfg.TargetAllowlist...)
	if baseHost != "" {
		hosts = append(hosts, baseHost)
	}
	maxBody := int64(cfg.MaxBodyBytes)
	if maxBody <= 0 {
		maxBody = 5 * 1024 * 1024
	}
	return &RequestSanitizer{
		AllowedHosts: hosts,
		MaxBodyBytes: maxBody,
		AllowPrivate: cfg.LabMode || cfg.IOwnThisTarget,
	}
}

// hostAllowed reports whether host matches the allowlist. An empty allowlist
// means "same host only" is enforced elsewhere; here empty means allow.
func (s *RequestSanitizer) hostAllowed(host string) bool {
	if len(s.AllowedHosts) == 0 {
		return true
	}
	host = strings.ToLower(stripPort(host))
	for _, h := range s.AllowedHosts {
		h = strings.ToLower(stripPort(strings.TrimSpace(h)))
		if h == "" {
			continue
		}
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

func stripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host[i:], "]") {
		return host[:i]
	}
	return host
}

// Validate enforces the request invariants described in the hardening plan.
func (s *RequestSanitizer) Validate(req *http.Request) error {
	if req == nil || req.URL == nil {
		return errors.New("sanitizer: nil request")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("sanitizer: disallowed scheme %q", req.URL.Scheme)
	}
	if !s.hostAllowed(req.URL.Host) {
		return fmt.Errorf("sanitizer: host %q not in scope", req.URL.Host)
	}
	// Reject CRLF smuggling in header names/values.
	for k, vs := range req.Header {
		if containsCRLF(k) {
			return fmt.Errorf("sanitizer: CRLF in header name %q", k)
		}
		for _, v := range vs {
			if containsCRLF(v) {
				return fmt.Errorf("sanitizer: CRLF in header %q value", k)
			}
		}
	}
	if containsCRLF(req.URL.Path) || containsCRLF(req.URL.RawQuery) {
		return errors.New("sanitizer: CRLF in request line")
	}
	if s.MaxBodyBytes > 0 && req.ContentLength > s.MaxBodyBytes {
		return fmt.Errorf("sanitizer: body size %d exceeds bound %d", req.ContentLength, s.MaxBodyBytes)
	}
	return nil
}

func containsCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// InScope is a lightweight scope check usable directly from the crawler to
// prevent it from escaping to third-party domains.
func (s *Scanner) InScope(rawurl string) bool {
	u, err := url.Parse(rawurl)
	if err != nil {
		return false
	}
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(stripPort(u.Host))
	if host == "" {
		return true // relative URL, same origin
	}

	// Explicit allowlist wins.
	if len(s.Config.TargetAllowlist) > 0 {
		for _, h := range s.Config.TargetAllowlist {
			h = strings.ToLower(stripPort(strings.TrimSpace(h)))
			if h != "" && (host == h || strings.HasSuffix(host, "."+h)) {
				return true
			}
		}
		return false
	}

	// Default: restrict to the base host.
	if s.BaseURL != nil {
		base := strings.ToLower(stripPort(s.BaseURL.Host))
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return true
}
