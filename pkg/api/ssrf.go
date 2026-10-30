package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SSRF PROTECTION — IP validation, DNS-rebinding prevention, safe HTTP client
// ═══════════════════════════════════════════════════════════════════════════════

var ssrfPrivateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",
		"169.254.0.0/16",
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"2001:db8::/32",
		"fc00::/7",
		"0.0.0.0/8",
		"240.0.0.0/4",
		"::/128",
		"::1/128",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			ssrfPrivateRanges = append(ssrfPrivateRanges, network)
		}
	}
}

// Deprecated: test-only global bypass. Prefer SSRFValidator injection via
// NewSSRFValidator / SetDefaultSSRFValidator or APIServer.SetSSRFValidator.
// Kept for backward compatibility with existing tests.
var isTestingBypassSSRF atomic.Bool

// SSRFValidator is an injectable SSRF policy. Bypass=true disables private-IP
// blocking (tests only — never enable in production).
type SSRFValidator struct {
	Bypass atomic.Bool
}

// NewSSRFValidator returns a validator with bypass preset (tests).
func NewSSRFValidator(bypass bool) *SSRFValidator {
	v := &SSRFValidator{}
	v.Bypass.Store(bypass)
	return v
}

var defaultSSRFValidator = NewSSRFValidator(false)

// SetDefaultSSRFValidator replaces the process-wide validator (tests / DI).
// Passing nil restores the default strict validator.
func SetDefaultSSRFValidator(v *SSRFValidator) {
	if v == nil {
		v = NewSSRFValidator(false)
	}
	defaultSSRFValidator = v
}

func ssrfBypassed() bool {
	return isTestingBypassSSRF.Load() || defaultSSRFValidator.Bypass.Load()
}

func (v *SSRFValidator) isPrivateIP(ip net.IP) bool {
	if v != nil && v.Bypass.Load() {
		return false
	}
	return isPrivateIPStrict(ip)
}

func isPrivateIPStrict(ip net.IP) bool {
	if ssrfBypassed() {
		return false
	}
	if ip == nil {
		return true
	}
	// Normalize IPv4-mapped IPv6 before applying explicit IPv4 ranges.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || !ip.IsGlobalUnicast() {
		return true
	}
	for _, network := range ssrfPrivateRanges {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateIP(ip net.IP) bool {
	return isPrivateIPStrict(ip)
}

func isSafeTarget(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	// Block non-HTTP(S) schemes
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	return isSafeHost(u.Hostname())
}

// isSafeHost checks whether a hostname (without port) is safe to connect to.
// Handles: localhost with trailing dot, IPv6 loopback, zero-IP, DNS aliases.
func isSafeHost(host string) bool {
	// Test-only bypass (production default is false). Kept behind both the
	// legacy global and the injectable validator so old tests keep passing
	// while new code can use SetDefaultSSRFValidator / per-server override.
	if ssrfBypassed() {
		return true
	}
	clean := strings.TrimSuffix(strings.ToLower(host), ".")
	if clean == "" {
		return false
	}
	// Block any form of localhost
	if clean == "localhost" || clean == "localhost.localdomain" {
		return false
	}
	// Block IPv6 loopback / unspecified
	if clean == "::1" || clean == "::" || clean == "0.0.0.0" {
		return false
	}
	// If the host is a literal IP, check it directly
	if ip := net.ParseIP(clean); ip != nil {
		return !isPrivateIP(ip)
	}
	// Host is a hostname — resolve it to catch DNS rebinding attacks
	addrs, err := net.LookupHost(clean)
	if err != nil {
		// Cannot resolve — block to be safe
		return false
	}
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil || isPrivateIP(ip) {
			return false
		}
	}
	return true
}

// safeHTTPClient returns an *http.Client whose Dialer pins the target IP
// after validation, preventing TOCTOU DNS rebinding between check and connect.
func safeHTTPClient(timeout time.Duration, targetURL string) (*http.Client, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("bad url: %w", err)
	}
	host := u.Hostname()
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme: %s", scheme)
	}
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	clean := strings.TrimSuffix(strings.ToLower(host), ".")
	if clean == "" {
		return nil, fmt.Errorf("empty host")
	}
	if clean == "localhost" || clean == "localhost.localdomain" ||
		clean == "::1" || clean == "::" || clean == "0.0.0.0" {
		return nil, fmt.Errorf("blocked host: %s", clean)
	}
	if ip := net.ParseIP(clean); ip != nil {
		if isPrivateIP(ip) {
			return nil, fmt.Errorf("private IP: %s", ip)
		}
		return makePinnedClient(ip.String(), port, timeout), nil
	}

	addrs, err := net.LookupHost(clean)
	if err != nil {
		return nil, fmt.Errorf("dns resolve: %w", err)
	}
	var pinned net.IP
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil || isPrivateIP(ip) {
			return nil, fmt.Errorf("unsafe IP resolved for %s", clean)
		}
		if pinned == nil {
			pinned = ip
		}
	}
	if pinned != nil {
		return makePinnedClient(pinned.String(), port, timeout), nil
	}
	return nil, fmt.Errorf("no safe IP resolved for %s", clean)
}

func makePinnedClient(ip, port string, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: timeout}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Ignore addr; always dial the pre-resolved IP
				return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
			},
		},
	}
}

// ─── Per-server DI ──────────────────────────────────────────────────────────

// SetSSRFValidator overrides the SSRF policy for this server instance.
// Passing nil clears the override (falls back to the process default).
// New code (and new tests) should prefer this over the legacy global.
func (s *APIServer) SetSSRFValidator(v *SSRFValidator) {
	s.ssrfMu.Lock()
	defer s.ssrfMu.Unlock()
	s.ssrfValidator = v
}

func (s *APIServer) getSSRFValidator() *SSRFValidator {
	s.ssrfMu.RLock()
	v := s.ssrfValidator
	s.ssrfMu.RUnlock()
	if v != nil {
		return v
	}
	return defaultSSRFValidator
}

// isSafeTargetLocal honors the server validator plus the legacy global.
func (s *APIServer) isSafeTargetLocal(urlStr string) bool {
	if isTestingBypassSSRF.Load() {
		return true
	}
	if v := s.getSSRFValidator(); v != nil && v.Bypass.Load() {
		return true
	}
	return isSafeTarget(urlStr)
}

// compileRegexSafe wraps regexp.Compile with safeguards.
//
// Go's regexp package uses RE2 (Thompson NFA), which is immune to catastrophic
// backtracking by construction — it runs in O(n) time and O(n) space regardless
// of pattern complexity. The checks below are defense-in-depth: length cap
// prevents memory exhaustion from enormous patterns, and the alternation depth
// check catches pathological regex generators.
func compileRegexSafe(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > 2000 {
		return nil, fmt.Errorf("regex pattern too long: %d bytes (max 2000)", len(pattern))
	}
	// Reject patterns with deeply nested alternation groups ((a|b)|(c|(d|e))|...)
	// as a defense-in-depth signal of generated/obfuscated attacks.
	depth := 0
	maxDepth := 0
	for _, ch := range pattern {
		if ch == '(' {
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		}
		if ch == ')' {
			depth--
		}
	}
	if maxDepth > 20 {
		return nil, fmt.Errorf("regex nesting too deep: %d levels (max 20)", maxDepth)
	}
	return regexp.Compile(pattern)
}
