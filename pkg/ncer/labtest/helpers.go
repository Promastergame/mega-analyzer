// Package labtest drives real HTTP traffic from the intentionally
// vulnerable servers under labs/servers/ through this repo's own ncer
// causal-reconciliation pipeline (pkg/ncer) and DNS sinkhole
// (pkg/internal/labdns), so that pipeline has real, exploitable traffic to
// observe and — for the tracker-beacon case — block.
//
// The lab servers are intentionally kept independent (no Go import
// coupling: they live in their own go.mod files under labs/servers/go/
// and labs/servers/django/). Tests here talk to them purely over HTTP,
// exactly like any other client would. Tests that need a specific lab
// server running skip themselves (via skipUnlessReachable) when that
// server isn't listening — e.g. when the docker-compose lab
// (labs/servers/docker-compose.lab.yml) hasn't been started — rather than
// failing the whole suite.
package labtest

import (
	"context"
	"net"
	"net/http"
	"time"
)

// skipUnlessReachable reports whether a TCP connection to addr succeeds
// within timeout. Tests use this to skip gracefully when a labs/servers/
// server isn't running locally, instead of failing.
func reachable(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// httpClient is a short-timeout client suitable for talking to local lab
// servers only.
var httpClient = &http.Client{Timeout: 5 * time.Second}

// newResolvingClient returns an *http.Client whose DNS resolution for HTTP
// requests is redirected to dnsServerAddr (a "host:port" pointing at a
// pkg/internal/labdns.LabDNS instance or any other DNS server) instead of
// the OS resolver. This lets a test observe what happens when a client
// resolves a hostname through a specific (possibly sinkholing) DNS server,
// without needing root or /etc/hosts access.
func newResolvingClient(dnsServerAddr string, timeout time.Duration) *http.Client {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, dnsServerAddr)
		},
	}
	dialer := &net.Dialer{
		Timeout:  timeout,
		Resolver: resolver,
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}
}
