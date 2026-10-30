package vulnscan

// HTTP/2 cleartext (h2c) smuggling exposure (CWE-444). Many reverse proxies
// blindly forward Upgrade/Connection headers; if the backend honors an h2c
// upgrade, request smuggling past the proxy becomes possible. We send a single
// benign upgrade probe over raw TCP (http:// only, to avoid TLS complexity) and
// look for a 101 Switching Protocols with an h2c token.

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// checkH2CSmuggling probes for backend h2c upgrade acceptance.
func (s *Scanner) checkH2CSmuggling() []Vulnerability {
	var list []Vulnerability
	if s.BaseURL == nil || s.BaseURL.Scheme != "http" {
		return list // https path skipped: needs TLS/ALPN handling
	}

	host := s.BaseURL.Host
	if host == "" {
		return list
	}
	addr := host
	if !strings.Contains(host, ":") {
		addr = host + ":80"
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return list
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	path := s.BaseURL.RequestURI()
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + hostOnly(host) + "\r\n" +
		"Connection: Upgrade, HTTP2-Settings\r\n" +
		"Upgrade: h2c\r\n" +
		"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n" +
		"User-Agent: " + s.Config.UserAgent + "\r\n" +
		"\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		return list
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return list
	}

	var headerBlob strings.Builder
	headerBlob.WriteString(statusLine)
	for i := 0; i < 30; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		headerBlob.WriteString(line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	if strings.Contains(statusLine, "101") &&
		strings.Contains(strings.ToLower(headerBlob.String()), "h2c") {
		list = append(list, Vulnerability{
			ID:          "WS-DESYNC-002",
			Name:        "HTTP/2 Cleartext (h2c) Smuggling Exposure",
			Description: "The server accepted an h2c upgrade (101 Switching Protocols with an h2c token). If a front-end proxy forwards the Upgrade header without terminating it, an attacker can tunnel smuggled requests directly to the backend, bypassing proxy-level access controls.",
			Severity:    SeverityHigh,
			URL:         s.Target,
			Payload:     "Upgrade: h2c",
			Evidence:    fmt.Sprintf("Response: %s", strings.TrimSpace(statusLine)),
			Mitigation:  "Strip hop-by-hop Upgrade/Connection headers at the edge proxy and disable h2c upgrades on backends that sit behind a proxy.",
		})
	}

	return list
}

func hostOnly(host string) string {
	if i := strings.LastIndex(host, ":"); i >= 0 {
		// keep host for names like [::1]:80 simple-cased
		if !strings.Contains(host[i:], "]") {
			return host[:i]
		}
	}
	return host
}
