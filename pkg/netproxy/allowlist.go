package netproxy

import (
	"net"
	"strings"
)

// certificateHost normalises a host[:port] into a lowercase hostname or, if it
// is a literal IP, returns the parsed net.IP as well.
func certificateHost(hostport string) (string, net.IP) {
	h := strings.TrimSpace(hostport)
	if splitHost, _, err := net.SplitHostPort(h); err == nil {
		h = splitHost
	}
	h = strings.Trim(strings.TrimSuffix(h, "."), "[]")
	if ip := net.ParseIP(h); ip != nil {
		return h, ip
	}
	return strings.ToLower(h), nil
}

// isAllowedServerAddr enforces the allowlist / offline policy.
//
// Behaviour change vs. the old code: loopback / private / link-local addresses
// (and "localhost") are only auto-allowed when config.AllowPrivateAddrs is set.
// Previously they were ALWAYS allowed, which is effectively an SSRF gate into
// the internal network. Set AllowPrivateAddrs=true for a local lab.
func (proxy *AdvancedMITMProxy) isAllowedServerAddr(serverAddr string) bool {
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}
	host, _ = certificateHost(host)
	if host == "" {
		return false
	}

	if ip := net.ParseIP(host); ip != nil {
		if proxy.config.AllowPrivateAddrs &&
			(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			return true
		}
		for _, allowed := range proxy.config.AllowedDomains {
			if aip := net.ParseIP(strings.TrimSpace(allowed)); aip != nil && aip.Equal(ip) {
				return true
			}
		}
		return false
	}

	if host == "localhost" {
		return proxy.config.AllowPrivateAddrs
	}
	for _, allowed := range proxy.config.AllowedDomains {
		allowed = strings.Trim(strings.ToLower(strings.TrimSpace(allowed)), ".")
		if allowed == "" {
			continue
		}
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}
