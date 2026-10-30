package labkit

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// UDPConfig configures a UDP datagram service.
type UDPConfig struct {
	// Mode is "echo" (default) or "discard".
	Mode string `json:"mode"`
	// MaxPacketBytes bounds the read buffer (default 65507, the max UDP
	// payload over IPv4).
	MaxPacketBytes int `json:"max_packet_bytes"`
}

// UDPServer is a supervised UDP datagram service.
type UDPServer struct {
	name     string
	cfg      UDPConfig
	conn     *net.UDPConn
	log      *Logger
	metrics  *Metrics
	scenario *Scenario

	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

func newUDPServer(sc ServerConfig, d deps) (*UDPServer, error) {
	cfg := UDPConfig{}
	if sc.UDP != nil {
		cfg = *sc.UDP
	}
	if cfg.Mode == "" {
		cfg.Mode = "echo"
	}
	if cfg.Mode != "echo" && cfg.Mode != "discard" {
		return nil, fmt.Errorf("unknown mode %q", cfg.Mode)
	}
	if cfg.MaxPacketBytes <= 0 {
		cfg.MaxPacketBytes = 65507
	}
	udpAddr, err := net.ResolveUDPAddr("udp", sc.Addr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", sc.Addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", sc.Addr, err)
	}
	return &UDPServer{
		name:     sc.Name,
		cfg:      cfg,
		conn:     conn,
		log:      d.log,
		metrics:  d.metrics,
		scenario: d.scenario,
		closed:   make(chan struct{}),
	}, nil
}

// Name implements Service.
func (s *UDPServer) Name() string { return s.name }

// Addr implements Service.
func (s *UDPServer) Addr() string { return s.conn.LocalAddr().String() }

// Start implements Service.
func (s *UDPServer) Start() error {
	s.wg.Add(1)
	go s.readLoop()
	return nil
}

func (s *UDPServer) readLoop() {
	defer s.wg.Done()
	buf := make([]byte, s.cfg.MaxPacketBytes)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				s.metrics.Inc("udp.read_errors")
				return
			}
		}
		s.metrics.Inc("udp.packets")
		s.metrics.Add("udp.bytes", int64(n))

		out := s.scenario.Roll()
		if out.Latency > 0 {
			time.Sleep(out.Latency)
		}
		if out.Fault != FaultNone {
			s.metrics.Inc("udp.injected_drop")
			continue // drop the datagram
		}
		if s.cfg.Mode == "discard" {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		if _, err := s.conn.WriteToUDP(payload, addr); err != nil {
			s.metrics.Inc("udp.write_errors")
		}
	}
}

// Close implements Service.
func (s *UDPServer) Close(ctx context.Context) error {
	s.once.Do(func() { close(s.closed) })
	_ = s.conn.Close()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
