package networkrefs

import "net"

// ResolverRole is an offline identity hint for well-known public resolvers.
// Identity is not a reputation verdict and says nothing about traffic content.
func ResolverRole(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	switch ip.String() {
	case "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001":
		return "public DNS resolver (Cloudflare)"
	case "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844":
		return "public DNS resolver (Google)"
	case "9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9":
		return "public DNS resolver (Quad9)"
	}
	return ""
}
