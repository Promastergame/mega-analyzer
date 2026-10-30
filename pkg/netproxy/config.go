package netproxy

import (
	"fmt"
	"time"
)

// AdvancedMITMConfig определяет расширенную конфигурацию MITM.
type AdvancedMITMConfig struct {
	// --- TLS ---
	EnableTLS         bool
	GenerateLabCA     bool
	CAKeyPath         string
	CACertPath        string
	CertCachePath     string
	EnableALPNLogging bool
	EnableSNILogging  bool
	EnableJA3Analysis bool

	// EnableCertPinningBypass is kept only for backwards-compatible config
	// parsing. Certificate pinning is a CLIENT-side defence and cannot be
	// bypassed from the server side of a TLS handshake; a real bypass must
	// happen in the client (e.g. a Frida hook). This flag does nothing here.
	//
	// Deprecated: has no effect in this package.
	EnableCertPinningBypass bool

	// PermittedDNSDomains, when non-empty, is written into a freshly generated
	// CA's X.509 Name Constraints so a forged leaf is only trusted for those
	// DNS suffixes even if the CA key leaks. NOTE: DNS constraints do NOT bound
	// IP-SAN leaves; use only DNS hosts if you rely on this for containment.
	PermittedDNSDomains []string

	// InsecureUpstreamTLS disables verification of the upstream server's
	// certificate. Malware C2 / lab targets frequently use self-signed or
	// otherwise invalid certs, and with verification on the interception would
	// fail exactly on the interesting hosts. Off by default (verification on).
	InsecureUpstreamTLS bool

	// AllowPrivateAddrs, when true, unconditionally allows loopback, private
	// (RFC1918) and link-local upstreams regardless of AllowedDomains. This is
	// convenient for a local lab but is effectively an SSRF gate into the
	// internal network, so it is OFF by default. Set it to true for local labs.
	AllowPrivateAddrs bool

	// MaxActiveConns bounds concurrently intercepted connections (0 = unlimited).
	MaxActiveConns int

	// HandshakeTimeout bounds the client-facing TLS handshake (0 => 15s).
	HandshakeTimeout time.Duration
	// DialTimeout bounds upstream dials (0 => 10s).
	DialTimeout time.Duration

	// MaxBytesPerConn caps how many bytes are relayed in EACH direction of an
	// intercepted connection (0 => unlimited). It bounds memory/capture for very
	// large or hostile streams; the bare io.Copy the relay used before had no
	// such ceiling. When the cap is reached that direction is half-closed.
	MaxBytesPerConn int64

	// RelayIdleTimeout is the per-read deadline applied to each relay direction
	// (0 => defaultRelayIdleTimeout). A stalled peer can no longer pin a relay
	// goroutine and its buffers open forever, which the old deadline-less
	// io.Copy allowed.
	RelayIdleTimeout time.Duration

	// --- UDP/QUIC ---
	EnableUDP  bool
	EnableQUIC bool
	UDPPort    int
	QUICPort   int

	// --- Протокол инферирования ---
	EnableProtocolInference bool
	InferenceOutputPath     string

	// --- Фаззинг и воспроизведение ---
	EnableReplay        bool
	EnableFuzzing       bool
	ReplayOutputPath    string
	FuzzingMutationRate float64

	// --- Конфиденциальность ---
	EnableRedaction      bool
	SecretScannerEnabled bool
	RetentionTTL         time.Duration
	AllowedDomains       []string
	AllowedPackages      []string
}

const (
	defaultHandshakeTimeout = 15 * time.Second
	defaultDialTimeout      = 10 * time.Second
	// defaultRelayIdleTimeout is applied to each relay direction when
	// RelayIdleTimeout is 0, so an idle/stuck connection is always eventually
	// reclaimed instead of leaking.
	defaultRelayIdleTimeout = 5 * time.Minute
)

// validate rejects obviously wrong configuration up front instead of failing
// deep inside a handshake.
func (c *AdvancedMITMConfig) validate() error {
	if c.FuzzingMutationRate < 0 || c.FuzzingMutationRate > 1 {
		return fmt.Errorf("FuzzingMutationRate must be in [0,1], got %v", c.FuzzingMutationRate)
	}
	if c.MaxActiveConns < 0 {
		return fmt.Errorf("MaxActiveConns must be >= 0, got %d", c.MaxActiveConns)
	}
	if c.MaxBytesPerConn < 0 {
		return fmt.Errorf("MaxBytesPerConn must be >= 0, got %d", c.MaxBytesPerConn)
	}
	if c.EnableTLS && c.GenerateLabCA {
		if c.CAKeyPath == "" || c.CACertPath == "" {
			return fmt.Errorf("CAKeyPath and CACertPath are required when GenerateLabCA is set")
		}
	}
	return nil
}

func (c *AdvancedMITMConfig) handshakeTimeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return defaultHandshakeTimeout
}

func (c *AdvancedMITMConfig) dialTimeout() time.Duration {
	if c.DialTimeout > 0 {
		return c.DialTimeout
	}
	return defaultDialTimeout
}

// maxBytesPerConn returns the per-direction byte cap (0 = unlimited).
func (c *AdvancedMITMConfig) maxBytesPerConn() int64 { return c.MaxBytesPerConn }

// relayIdleTimeout returns the per-read idle deadline for a relay direction,
// falling back to defaultRelayIdleTimeout when unset.
func (c *AdvancedMITMConfig) relayIdleTimeout() time.Duration {
	if c.RelayIdleTimeout > 0 {
		return c.RelayIdleTimeout
	}
	return defaultRelayIdleTimeout
}
