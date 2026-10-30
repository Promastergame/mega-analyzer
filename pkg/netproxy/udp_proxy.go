package netproxy

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// UDPProxy provides MITM proxying for connectionless UDP traffic.
type UDPProxy struct {
	config   ProxyConfig
	conn     *net.UDPConn
	recorder *PacketRecorder
	editor   *PacketEditor
	done     chan struct{}
	wg       sync.WaitGroup
	stopOnce sync.Once

	mu       sync.RWMutex
	natTable map[string]*udpClientSession

	clientDrops atomic.Uint64 // client->server datagrams dropped (session queue full)
	evictions   atomic.Uint64 // sessions evicted by the LRU cap
}

const (
	// maxUDPSessions bounds the NAT table so a flood of datagrams from many
	// (possibly spoofed) source addresses can't grow sockets/goroutines/memory
	// without limit — cleanupLoop only reclaims idle sessions after 5 minutes,
	// far too slow to contain a burst. When the cap is hit, the
	// least-recently-active session is evicted to make room.
	maxUDPSessions = 4096
	// udpSessionQueueLen is the depth of a session's ordered send queue. UDP is
	// lossy by nature, so a full queue drops the datagram (counted) rather than
	// blocking the shared receive loop.
	udpSessionQueueLen = 256
)

type udpClientSession struct {
	clientAddr *net.UDPAddr
	serverConn *net.UDPConn
	lastActive atomic.Int64
	// sendQueue carries client->server datagrams to this session's single
	// worker (clientSendLoop) so they are forwarded in arrival order. The
	// previous design spawned a goroutine per datagram, which let concurrent
	// writes to serverConn reorder — corrupting sequence/nonce fields in game
	// and crypto protocols. One worker per session preserves ordering.
	sendQueue chan []byte
	quit      chan struct{}
	quitOnce  sync.Once
}

func (s *udpClientSession) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

func (s *udpClientSession) lastActiveTime() time.Time {
	return time.Unix(0, s.lastActive.Load())
}

// teardown closes the session's upstream socket and signals its workers to
// exit, exactly once, so it is safe to call from the cleanup loop, the LRU
// evictor, and the server-read loop concurrently.
func (s *udpClientSession) teardown() {
	s.quitOnce.Do(func() {
		close(s.quit)
		if s.serverConn != nil {
			s.serverConn.Close()
		}
	})
}

func writeUDPAll(conn *net.UDPConn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("short UDP write")
		}
		data = data[n:]
	}
	return nil
}

// NewUDPProxy creates a new UDP proxy.
func NewUDPProxy(config ProxyConfig) *UDPProxy {
	if config.HeaderParser == nil {
		config.HeaderParser = defaultHeaderParser
	}
	return &UDPProxy{
		config:   config,
		done:     make(chan struct{}),
		editor:   NewPacketEditor(),
		natTable: make(map[string]*udpClientSession),
	}
}

// Start begins listening on the UDP port.
func (p *UDPProxy) Start() error {
	var err error

	if p.config.RecordPath != "" {
		p.recorder, err = NewPacketRecorder(p.config.RecordPath)
		if err != nil {
			return fmt.Errorf("create recorder: %w", err)
		}
	}

	addr, err := net.ResolveUDPAddr("udp", p.config.ListenAddr)
	if err != nil {
		return err
	}

	p.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", p.config.ListenAddr, err)
	}

	p.wg.Add(1)
	go p.receiveLoop()

	p.wg.Add(1)
	go p.cleanupLoop()

	return nil
}

// Stop shuts down the UDP proxy.
func (p *UDPProxy) Stop() error {
	p.stopOnce.Do(func() {
		close(p.done)
		if p.conn != nil {
			_ = p.conn.Close()
		}
	})
	p.wg.Wait()
	if p.recorder != nil {
		return p.recorder.Close()
	}
	return nil
}

// Stats returns proxy statistics.
func (p *UDPProxy) Stats() uint64 {
	if p.recorder != nil {
		return p.recorder.Count()
	}
	return 0
}

// SessionCount returns the current number of live NAT sessions.
func (p *UDPProxy) SessionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.natTable)
}

// DroppedClientDatagrams returns how many client->server datagrams were dropped
// because a session's ordered send queue was full (backpressure).
func (p *UDPProxy) DroppedClientDatagrams() uint64 {
	return p.clientDrops.Load()
}

// EvictedSessions returns how many sessions the LRU cap has evicted.
func (p *UDPProxy) EvictedSessions() uint64 {
	return p.evictions.Load()
}

func (p *UDPProxy) receiveLoop() {
	defer p.wg.Done()
	buf := make([]byte, 65536)
	var retryDelay time.Duration

	for {
		select {
		case <-p.done:
			return
		default:
		}

		p.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				retryDelay = 0
				continue
			}
			select {
			case <-p.done:
				return
			default:
			}
			// Back off on persistent errors instead of busy-spinning.
			if retryDelay == 0 {
				retryDelay = 5 * time.Millisecond
			} else {
				retryDelay *= 2
			}
			if retryDelay > time.Second {
				retryDelay = time.Second
			}
			time.Sleep(retryDelay)
			continue
		}
		retryDelay = 0

		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])
			p.dispatchClientPacket(data, clientAddr)
		}
	}
}

// dispatchClientPacket routes one client datagram to its session's ordered
// send queue. Enqueuing (rather than spawning a goroutine per datagram) is what
// preserves per-session ordering. A full queue drops the datagram — acceptable
// for UDP and far better than blocking the single shared receive loop, which
// would stall every other client.
func (p *UDPProxy) dispatchClientPacket(data []byte, clientAddr *net.UDPAddr) {
	session := p.getSession(clientAddr)
	if session == nil {
		return
	}
	session.touch()
	select {
	case session.sendQueue <- data:
	case <-p.done:
	default:
		p.clientDrops.Add(1)
	}
}

// clientSendLoop is the single per-session worker that forwards queued client
// datagrams to the upstream in arrival order.
func (p *UDPProxy) clientSendLoop(session *udpClientSession) {
	defer p.wg.Done()
	for {
		select {
		case <-p.done:
			return
		case <-session.quit:
			return
		case data := <-session.sendQueue:
			p.forwardClientPacket(session, data)
		}
	}
}

func (p *UDPProxy) forwardClientPacket(session *udpClientSession, data []byte) {
	msgType, payloadOff := p.config.HeaderParser(data)

	pkt := Packet{
		Timestamp:   time.Now(),
		Direction:   DirectionClientToServer,
		Size:        len(data),
		Data:        data,
		MessageType: msgType,
	}

	if p.config.Interactive && msgType != 0 {
		if !p.editor.IsIgnored(msgType) {
			patchedData := p.editor.PromptAndRewrite(pkt, payloadOff)
			if patchedData != nil {
				data = patchedData
				pkt.Data = patchedData
				pkt.Size = len(patchedData)
			}
		}
	}

	if p.recorder != nil {
		p.recorder.Record(pkt)
	}

	if p.config.OnPacket != nil {
		p.config.OnPacket(pkt)
	}

	_ = writeUDPAll(session.serverConn, data)
}

func (p *UDPProxy) getSession(clientAddr *net.UDPAddr) *udpClientSession {
	key := clientAddr.String()

	p.mu.RLock()
	session, exists := p.natTable[key]
	p.mu.RUnlock()

	if exists {
		return session
	}

	if !upstreamAllowed(p.config.UpstreamAddr) {
		fmt.Printf("Blocked UDP upstream by offline/allowlist policy: %s\n", p.config.UpstreamAddr)
		return nil
	}

	// Create new session
	p.mu.Lock()
	defer p.mu.Unlock()

	// double check
	if session, exists = p.natTable[key]; exists {
		return session
	}

	serverAddr, err := net.ResolveUDPAddr("udp", p.config.UpstreamAddr)
	if err != nil {
		fmt.Printf("Error resolving upstream %s: %v\n", p.config.UpstreamAddr, err)
		return nil
	}

	serverConn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		fmt.Printf("Error dialing upstream: %v\n", err)
		return nil
	}

	// Enforce the session cap before inserting: evict the least-recently-active
	// session to make room, so a burst of unique source addresses can't grow
	// the table without bound.
	if len(p.natTable) >= maxUDPSessions {
		p.evictLRULocked()
	}

	session = &udpClientSession{
		clientAddr: clientAddr,
		serverConn: serverConn,
		sendQueue:  make(chan []byte, udpSessionQueueLen),
		quit:       make(chan struct{}),
	}
	session.touch()

	p.natTable[key] = session

	p.wg.Add(1)
	go p.serverReceiveLoop(session, key)
	p.wg.Add(1)
	go p.clientSendLoop(session)

	return session
}

// evictLRULocked removes the least-recently-active session from the NAT table
// and tears it down. Caller must hold p.mu.
func (p *UDPProxy) evictLRULocked() {
	var oldestKey string
	var oldest *udpClientSession
	for k, s := range p.natTable {
		if oldest == nil || s.lastActiveTime().Before(oldest.lastActiveTime()) {
			oldestKey, oldest = k, s
		}
	}
	if oldest != nil {
		delete(p.natTable, oldestKey)
		oldest.teardown()
		p.evictions.Add(1)
	}
}

func (p *UDPProxy) serverReceiveLoop(session *udpClientSession, key string) {
	defer p.wg.Done()
	buf := make([]byte, 65536)

	for {
		select {
		case <-p.done:
			return
		default:
		}

		session.serverConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := session.serverConn.ReadFromUDP(buf)

		p.mu.RLock()
		activeSession, exists := p.natTable[key]
		p.mu.RUnlock()

		if !exists || activeSession != session {
			// Session was cleaned up or replaced
			session.teardown()
			return
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// Non-timeout read error: this session's upstream socket is
			// unusable. Remove it from the NAT table so the next client
			// packet creates a fresh session instead of the client being
			// silently blackholed forever.
			p.mu.Lock()
			if p.natTable[key] == session {
				delete(p.natTable, key)
			}
			p.mu.Unlock()
			session.teardown()
			return
		}

		if n > 0 {
			session.touch()
			data := make([]byte, n)
			copy(data, buf[:n])

			msgType, payloadOff := p.config.HeaderParser(data)

			pkt := Packet{
				Timestamp:   time.Now(),
				Direction:   DirectionServerToClient,
				Size:        len(data),
				Data:        data,
				MessageType: msgType,
			}

			if p.config.Interactive && msgType != 0 {
				if !p.editor.IsIgnored(msgType) {
					patchedData := p.editor.PromptAndRewrite(pkt, payloadOff)
					if patchedData != nil {
						data = patchedData
						pkt.Data = patchedData
						pkt.Size = len(patchedData)
					}
				}
			}

			if p.recorder != nil {
				p.recorder.Record(pkt)
			}

			if p.config.OnPacket != nil {
				p.config.OnPacket(pkt)
			}

			p.conn.WriteToUDP(data, session.clientAddr)
		}
	}
}

func (p *UDPProxy) cleanupLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()
			for key, session := range p.natTable {
				if now.Sub(session.lastActiveTime()) > 5*time.Minute {
					session.teardown()
					delete(p.natTable, key)
				}
			}
			p.mu.Unlock()
		}
	}
}
