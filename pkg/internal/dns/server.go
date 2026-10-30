package dns

import (
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// ResponseWriter is used by a Handler to construct a DNS response.
type ResponseWriter interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	WriteMsg(*Msg) error
	Write([]byte) (int, error)
	Close() error
}

// Handler responds to a DNS request.
type Handler interface {
	ServeDNS(w ResponseWriter, r *Msg)
}

// HandlerFunc adapts a function to a Handler.
type HandlerFunc func(ResponseWriter, *Msg)

// ServeDNS calls f(w, r).
func (f HandlerFunc) ServeDNS(w ResponseWriter, r *Msg) { f(w, r) }

// ServeMux routes queries to handlers by longest-suffix match on the name.
type ServeMux struct {
	mu sync.RWMutex
	z  map[string]Handler
}

// NewServeMux allocates an empty ServeMux.
func NewServeMux() *ServeMux {
	return &ServeMux{z: make(map[string]Handler)}
}

// Handle registers a handler for the given name pattern.
func (mux *ServeMux) Handle(pattern string, handler Handler) {
	if pattern == "" {
		pattern = "."
	}
	mux.mu.Lock()
	mux.z[Fqdn(strings.ToLower(pattern))] = handler
	mux.mu.Unlock()
}

// HandleFunc registers a handler function for the given name pattern.
func (mux *ServeMux) HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	mux.Handle(pattern, HandlerFunc(handler))
}

func (mux *ServeMux) match(q string) Handler {
	q = Fqdn(strings.ToLower(q))
	mux.mu.RLock()
	defer mux.mu.RUnlock()
	for {
		if h, ok := mux.z[q]; ok {
			return h
		}
		if q == "." {
			return nil
		}
		i := strings.IndexByte(q, '.')
		if i < 0 {
			return nil
		}
		q = q[i+1:]
		if q == "" {
			q = "."
		}
	}
}

// ServeDNS dispatches to the matched handler, or refuses if none matches.
func (mux *ServeMux) ServeDNS(w ResponseWriter, r *Msg) {
	var h Handler
	if len(r.Question) > 0 {
		h = mux.match(r.Question[0].Name)
	}
	if h != nil {
		h.ServeDNS(w, r)
		return
	}
	_ = w.WriteMsg(new(Msg).SetRcode(r, RcodeRefused))
}

// DefaultServeMux is the mux used by the package-level HandleFunc and by a
// Server with no Handler set.
var DefaultServeMux = NewServeMux()

// HandleFunc registers a handler function on the DefaultServeMux.
func HandleFunc(pattern string, handler func(ResponseWriter, *Msg)) {
	DefaultServeMux.HandleFunc(pattern, handler)
}

// ── Server ──────────────────────────────────────────────────

// Server is a minimal DNS server. Set Addr+Net for ListenAndServe, or set
// PacketConn (UDP) or Listener (TCP) and call ActivateAndServe.
type Server struct {
	Addr       string
	Net        string
	Handler    Handler
	PacketConn net.PacketConn
	Listener   net.Listener

	mu       sync.Mutex
	shutdown bool
}

func (s *Server) handler() Handler {
	if s.Handler != nil {
		return s.Handler
	}
	return DefaultServeMux
}

func (s *Server) isShutdown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shutdown
}

// ListenAndServe binds according to Addr/Net and serves until Shutdown.
func (s *Server) ListenAndServe() error {
	network := s.Net
	if network == "" {
		network = "udp"
	}
	switch {
	case strings.HasPrefix(network, "udp"):
		pc, err := net.ListenPacket(network, s.Addr)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.PacketConn = pc
		s.mu.Unlock()
		return s.serveUDP(pc)
	case strings.HasPrefix(network, "tcp"):
		l, err := net.Listen(network, s.Addr)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.Listener = l
		s.mu.Unlock()
		return s.serveTCP(l)
	default:
		return errors.New("dns: unsupported network " + network)
	}
}

// ActivateAndServe serves on the pre-set PacketConn and/or Listener.
func (s *Server) ActivateAndServe() error {
	if s.PacketConn != nil {
		return s.serveUDP(s.PacketConn)
	}
	if s.Listener != nil {
		return s.serveTCP(s.Listener)
	}
	return errors.New("dns: no active connection to serve")
}

// Shutdown stops the server and closes its listeners.
func (s *Server) Shutdown() error {
	s.mu.Lock()
	s.shutdown = true
	pc := s.PacketConn
	l := s.Listener
	s.mu.Unlock()
	var err error
	if pc != nil {
		err = pc.Close()
	}
	if l != nil {
		if e := l.Close(); err == nil {
			err = e
		}
	}
	return err
}

func (s *Server) serveUDP(pc net.PacketConn) error {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if s.isShutdown() {
				return nil
			}
			return err
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go func() {
			m, uerr := Unpack(data)
			if uerr != nil {
				return
			}
			s.handler().ServeDNS(&udpResponseWriter{pc: pc, addr: addr}, m)
		}()
	}
}

func (s *Server) serveTCP(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			if s.isShutdown() {
				return nil
			}
			return err
		}
		go s.serveTCPConn(conn)
	}
}

func (s *Server) serveTCPConn(conn net.Conn) {
	defer conn.Close()
	for {
		var lenBuf [2]byte
		if _, err := readFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if msgLen == 0 {
			return
		}
		data := make([]byte, msgLen)
		if _, err := readFull(conn, data); err != nil {
			return
		}
		m, err := Unpack(data)
		if err != nil {
			return
		}
		s.handler().ServeDNS(&tcpResponseWriter{conn: conn}, m)
	}
}

func readFull(conn net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := conn.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// ── Response writers ────────────────────────────────────────

type udpResponseWriter struct {
	pc   net.PacketConn
	addr net.Addr
}

func (w *udpResponseWriter) LocalAddr() net.Addr  { return w.pc.LocalAddr() }
func (w *udpResponseWriter) RemoteAddr() net.Addr { return w.addr }
func (w *udpResponseWriter) Close() error         { return nil }
func (w *udpResponseWriter) Write(b []byte) (int, error) {
	return w.pc.WriteTo(b, w.addr)
}
func (w *udpResponseWriter) WriteMsg(m *Msg) error {
	b, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = w.pc.WriteTo(b, w.addr)
	return err
}

type tcpResponseWriter struct {
	conn net.Conn
}

func (w *tcpResponseWriter) LocalAddr() net.Addr         { return w.conn.LocalAddr() }
func (w *tcpResponseWriter) RemoteAddr() net.Addr        { return w.conn.RemoteAddr() }
func (w *tcpResponseWriter) Close() error                { return w.conn.Close() }
func (w *tcpResponseWriter) Write(b []byte) (int, error) { return w.conn.Write(b) }
func (w *tcpResponseWriter) WriteMsg(m *Msg) error {
	b, err := m.Pack()
	if err != nil {
		return err
	}
	if len(b) > 65535 {
		return errors.New("dns: message exceeds TCP frame size")
	}
	frame := make([]byte, 2+len(b))
	frame[0] = byte(len(b) >> 8)
	frame[1] = byte(len(b))
	copy(frame[2:], b)
	_, err = w.conn.Write(frame)
	return err
}

// ── Client ──────────────────────────────────────────────────

// Client performs synchronous DNS queries.
type Client struct {
	Net     string
	Timeout time.Duration
}

// Exchange sends req to the server at addr and returns the reply and RTT.
func (c *Client) Exchange(req *Msg, addr string) (*Msg, time.Duration, error) {
	network := c.Net
	if network == "" {
		network = "udp"
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	packed, err := req.Pack()
	if err != nil {
		return nil, 0, err
	}

	start := time.Now()
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if strings.HasPrefix(network, "tcp") {
		frame := make([]byte, 2+len(packed))
		frame[0] = byte(len(packed) >> 8)
		frame[1] = byte(len(packed))
		copy(frame[2:], packed)
		if _, err := conn.Write(frame); err != nil {
			return nil, 0, err
		}
		var lenBuf [2]byte
		if _, err := readFull(conn, lenBuf[:]); err != nil {
			return nil, 0, err
		}
		resp := make([]byte, int(lenBuf[0])<<8|int(lenBuf[1]))
		if _, err := readFull(conn, resp); err != nil {
			return nil, 0, err
		}
		m, err := Unpack(resp)
		return m, time.Since(start), err
	}

	if _, err := conn.Write(packed); err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, err
	}
	m, err := Unpack(buf[:n])
	return m, time.Since(start), err
}
