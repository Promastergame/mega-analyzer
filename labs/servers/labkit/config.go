package labkit

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Duration is a time.Duration that marshals to/from JSON as a human-readable
// string ("200ms", "1.5s"). For convenience it also accepts a bare number,
// which is interpreted as nanoseconds.
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// MarshalJSON renders the duration as a string such as "200ms".
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// UnmarshalJSON accepts either a duration string ("200ms") or a numeric
// nanosecond count.
func (d *Duration) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		v, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("duration must be a string or number: %w", err)
	}
	*d = Duration(n)
	return nil
}

// Config is the top-level declarative description of a lab. It is normally
// loaded from a JSON file with LoadConfig, but can also be built in code.
type Config struct {
	// LogLevel is one of debug, info, warn, error (default info).
	LogLevel string `json:"log_level"`
	// AllowNonLoopback lifts the safety guard that restricts every server to
	// the loopback interface. Leave it false unless you know exactly why you
	// need it; labkit is a local lab, not an exposed service.
	AllowNonLoopback bool `json:"allow_non_loopback"`
	// Servers is the set of services to supervise.
	Servers []ServerConfig `json:"servers"`
}

// ServerConfig describes a single service. Exactly one of the protocol-
// specific blocks (HTTP/TCP/UDP) is consulted, selected by Kind.
type ServerConfig struct {
	Name     string         `json:"name"`
	Kind     string         `json:"kind"` // "http", "tcp", "udp"
	Addr     string         `json:"addr"` // host:port; empty host => 127.0.0.1
	Scenario ScenarioConfig `json:"scenario"`

	HTTP *HTTPConfig `json:"http,omitempty"`
	TCP  *TCPConfig  `json:"tcp,omitempty"`
	UDP  *UDPConfig  `json:"udp,omitempty"`
}

// LoadConfig reads and validates a JSON config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks the config for structural problems and enforces the
// loopback-only safety guard. It returns the first problem it finds, with a
// message that names the offending server so diagnostics are never silent.
func (c *Config) Validate() error {
	if len(c.Servers) == 0 {
		return fmt.Errorf("config has no servers")
	}
	seen := make(map[string]struct{}, len(c.Servers))
	for i := range c.Servers {
		s := &c.Servers[i]
		if s.Name == "" {
			return fmt.Errorf("servers[%d]: name is required", i)
		}
		if _, dup := seen[s.Name]; dup {
			return fmt.Errorf("duplicate server name %q", s.Name)
		}
		seen[s.Name] = struct{}{}

		host, _, err := net.SplitHostPort(s.Addr)
		if err != nil {
			return fmt.Errorf("server %q: invalid addr %q: %w", s.Name, s.Addr, err)
		}
		if !c.AllowNonLoopback && !isLoopbackHost(host) {
			return fmt.Errorf("server %q: addr %q is not loopback; set allow_non_loopback to override (not recommended)", s.Name, s.Addr)
		}

		switch s.Kind {
		case "http":
			if s.TCP != nil || s.UDP != nil {
				return fmt.Errorf("server %q: kind=http must not set tcp/udp blocks", s.Name)
			}
		case "tcp":
			if s.HTTP != nil || s.UDP != nil {
				return fmt.Errorf("server %q: kind=tcp must not set http/udp blocks", s.Name)
			}
		case "udp":
			if s.HTTP != nil || s.TCP != nil {
				return fmt.Errorf("server %q: kind=udp must not set http/tcp blocks", s.Name)
			}
		default:
			return fmt.Errorf("server %q: unknown kind %q (want http, tcp or udp)", s.Name, s.Kind)
		}
	}
	return nil
}

// isLoopbackHost reports whether host is safe to bind for a local-only lab:
// an empty host (which defaults to loopback), "localhost", or any loopback IP.
func isLoopbackHost(host string) bool {
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// normalizeAddr fills in a loopback host when the caller left it blank, so
// "" or ":8080" both bind to 127.0.0.1.
func normalizeAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}
