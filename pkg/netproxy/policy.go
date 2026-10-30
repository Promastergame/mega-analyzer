package netproxy

import (
	"net"
	"os"
	"strings"
)

// upstreamAllowed enforces the project-wide offline-by-default policy for the
// standalone TCP/UDP proxy package. Local/private lab addresses are allowed;
// public hostnames/IPs require explicit MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS.
func upstreamAllowed(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSuffix(strings.ToLower(host), "."), "[]")
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() {
			return true
		}
		allowedCSV := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS"))
		for _, allowed := range strings.Split(allowedCSV, ",") {
			if aip := net.ParseIP(strings.TrimSpace(allowed)); aip != nil && aip.Equal(ip) {
				return true
			}
		}
		return false
	}
	allowedCSV := strings.TrimSpace(os.Getenv("MEGA_ANALYZER_NETPROXY_ALLOWED_DOMAINS"))
	if allowedCSV == "" {
		return false
	}
	for _, allowed := range strings.Split(allowedCSV, ",") {
		allowed = strings.Trim(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(allowed)), "."), "[]")
		if allowed == "" {
			continue
		}
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
		if ip := net.ParseIP(allowed); ip != nil && host == ip.String() {
			return true
		}
	}
	return false
}
