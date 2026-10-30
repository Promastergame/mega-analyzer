package labkit

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// TCPConfig configures a TCP service.
type TCPConfig struct {
	// Framing is one of "line" (newline-delimited), "length" (4-byte
	// big-endian length prefix) or "raw" (stream copy). Default "line".
	Framing string `json:"framing"`
	// Mode is "echo" (default) or "discard".
	Mode string `json:"mode"`
	// MaxConns bounds concurrent connections (default 1024).
	MaxConns int `json:"max_conns"`
	// ReadTimeout bounds how long a connection may idle (default 30s).
	ReadTimeout Duration `json:"read_timeout"`
	// MaxMessageBytes bounds a single framed message (default 64 KiB).
	MaxMessageBytes int `json:"max_message_bytes"`
}

func (c *TCPConfig) withDefaults() {
	if c.Framing == "" {
		c.Framing = "line"
	}
	if c.Mode == "" {
		c.Mode = "echo"
	}
	if c.MaxConns <= 0 {
		c.MaxConns = 1024
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = Duration(30 * time.Second)
	}
	if c.MaxMessageBytes <= 0 {
		c.MaxMessageBytes = 64 << 10
	}
}

// TCPServer is a supervised, bounded-concurrency TCP acceptor.
type TCPServer struct {
	name     string
	cfg      TCPConfig
	ln       net.Listener
	log      *Logger
	metrics  *Metrics
	scenario *Scenario

	sem    chan struct{}
	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once

	connMu sync.Mutex
	conns  map[net.Conn]struct{}
}

func newTCPServer(sc ServerConfig, d deps) (*TCPServer, error) {
	cfg := TCPConfig{}
	if sc.TCP != nil {
		cfg = *sc.TCP
	}
	cfg.withDefaults()
	switch cfg.Framing {
	case "line", "length", "raw":
	default:
		return nil, fmt.Errorf("unknown framing %q", cfg.Framing)
	}
	if cfg.Mode != "echo" && cfg.Mode != "discard" {
		return nil, fmt.Errorf("unknown mode %q", cfg.Mode)
	}
	ln, err := net.Listen("tcp", sc.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", sc.Addr, err)
	}
	return &TCPServer{
		name:     sc.Name,
		cfg:      cfg,
		ln:       ln,
		log:      d.log,
		metrics:  d.metrics,
		scenario: d.scenario,
		sem:      make(chan struct{}, cfg.MaxConns),
		closed:   make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

// Name implements Service.
func (s *TCPServer) Name() string { return s.name }

// Addr implements Service.
func (s *TCPServer) Addr() string { return s.ln.Addr().String() }

// Start implements Service.
func (s *TCPServer) Start() error {
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

func (s *TCPServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				s.log.Warn("accept failed", Fields{"err": err.Error()})
				continue
			}
		}
		select {
		case s.sem <- struct{}{}:
		default:
			// At capacity: refuse rather than queue unboundedly.
			s.metrics.Inc("tcp.rejected")
			_ = conn.Close()
			continue
		}
		s.trackConn(conn)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer s.untrackConn(conn)
			s.handleConn(conn)
		}()
	}
}

func (s *TCPServer) trackConn(c net.Conn) {
	s.connMu.Lock()
	s.conns[c] = struct{}{}
	s.connMu.Unlock()
}

func (s *TCPServer) untrackConn(c net.Conn) {
	s.connMu.Lock()
	delete(s.conns, c)
	s.connMu.Unlock()
	_ = c.Close()
}

func (s *TCPServer) handleConn(conn net.Conn) {
	s.metrics.Inc("tcp.connections")
	idle := s.cfg.ReadTimeout.D()
	r := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(idle))
		msg, err := s.readMessage(r)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.metrics.Inc("tcp.read_errors")
			}
			return
		}
		s.metrics.Inc("tcp.messages")
		s.metrics.Add("tcp.bytes", int64(len(msg)))

		out := s.scenario.Roll()
		if out.Latency > 0 {
			time.Sleep(out.Latency)
		}
		if out.Fault == FaultError || out.Fault == FaultTimeout {
			s.metrics.Inc("tcp.injected_fault")
			return // drop the connection
		}
		if s.cfg.Mode == "discard" {
			continue
		}
		_ = conn.SetWriteDeadline(time.Now().Add(idle))
		if err := s.writeMessage(conn, msg); err != nil {
			s.metrics.Inc("tcp.write_errors")
			return
		}
	}
}

// readMessage reads one message according to the configured framing.
func (s *TCPServer) readMessage(r *bufio.Reader) ([]byte, error) {
	switch s.cfg.Framing {
	case "line":
		line, err := readLimitedLine(r, s.cfg.MaxMessageBytes)
		return line, err
	case "length":
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint32(lenBuf[:]))
		if n < 0 || n > s.cfg.MaxMessageBytes {
			return nil, fmt.Errorf("framed length %d exceeds max %d", n, s.cfg.MaxMessageBytes)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return buf, nil
	default: // raw
		buf := make([]byte, 4096)
		n, err := r.Read(buf)
		if n > 0 {
			return buf[:n], nil
		}
		return nil, err
	}
}

func (s *TCPServer) writeMessage(w io.Writer, msg []byte) error {
	switch s.cfg.Framing {
	case "length":
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(msg)))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return err
		}
		_, err := w.Write(msg)
		return err
	default: // line and raw echo the bytes as received
		_, err := w.Write(msg)
		return err
	}
}

// readLimitedLine reads up to max bytes or a newline, whichever comes first,
// returning the bytes including the trailing newline when present.
func readLimitedLine(r *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			if len(out) > 0 {
				return out, nil
			}
			return nil, err
		}
		out = append(out, b)
		if b == '\n' {
			return out, nil
		}
		if len(out) >= max {
			return nil, fmt.Errorf("line exceeds max %d bytes", max)
		}
	}
}

// Close implements Service. It stops accepting, then waits for active
// connections to drain until ctx expires, after which stragglers are forced
// closed.
func (s *TCPServer) Close(ctx context.Context) error {
	s.once.Do(func() { close(s.closed) })
	_ = s.ln.Close()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.connMu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.connMu.Unlock()
		<-done
		return ctx.Err()
	}
}
