// Package netproxy implements an advanced lab MITM proxy used by
// mega-analyzer for TLS interception, TLS ClientHello fingerprinting,
// protocol inference, replay/fuzzing and secret scanning.
//
// The package is split across several files so it is not one monolith:
//
//	config.go     - AdvancedMITMConfig, validation and defaults
//	mitm.go       - AdvancedMITMProxy struct, New, connection tracking, Close
//	ca.go         - CertificateAuthority: generate/load the lab CA
//	leaf.go       - per-host leaf certificate minting
//	certcache.go  - cached, single-flight leaf certificate generation
//	intercept.go  - TLS interception + bounded bidirectional relay
//	ja3.go        - TLS ClientHello metadata capture (NOT canonical JA3)
//	secrets.go    - regex-based secret scanning
//	allowlist.go  - upstream allowlist / offline policy + host parsing
//	events.go     - the MITM event channel
//	engines.go    - protocol inference / replay / fuzzing data types
//
// The transparent recording proxy (a separate feature) lives alongside it:
//
//	proxy.go      - TCPProxy + PacketRecorder (framed capture/record)
//	udp_proxy.go  - UDPProxy with per-session NAT + ordered forwarding
//	policy.go     - offline-by-default upstream policy for TCP/UDP proxy
//	editor.go     - interactive packet editor
//	msgpack.go    - MessagePack inspection helpers
//
// SECURITY NOTE: this is a lab tool. It forges certificates and, when
// configured, intercepts live TLS. Never point it at hosts you are not
// authorised to intercept.
package netproxy
