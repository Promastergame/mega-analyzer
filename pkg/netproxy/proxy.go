// Package netproxy provides a transparent TCP/UDP proxy for intercepting
// game client ↔ server traffic (MITM). This is the foundation of the
// Private Server Toolkit in Mega-Analyzer.
//
// Architecture:
//
//	Game Client → netproxy (record + inspect) → Real Server
//	                  ↓
//	           Packet Log (.pcap-like)
//
// Features:
//   - TCP and UDP proxy with configurable upstream
//   - Packet recording to structured JSON log
//   - Real-time packet viewer (CLI callback)
//   - SSL/TLS termination for encrypted game protocols
//   - Auto-detection of common serialization formats (Protobuf, MessagePack)
package netproxy

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"sync"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// PACKET TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// Direction indicates which side sent the packet.
type Direction string

const (
	DirectionClientToServer Direction = "C→S"
	DirectionServerToClient Direction = "S→C"
)

// Packet represents a single intercepted network packet.
type Packet struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Direction Direction `json:"direction"`
	Size      int       `json:"size"`
	Data      []byte    `json:"data"`

	// Parsed fields (populated by protocol dissectors)
	MessageType uint16 `json:"message_type,omitempty"`
	MessageName string `json:"message_name,omitempty"`
	Decoded     any    `json:"decoded,omitempty"`
}

// HexDump returns a hex representation of the first N bytes.
func (p *Packet) HexDump(maxBytes int) string {
	data := p.Data
	if len(data) > maxBytes {
		data = data[:maxBytes]
	}
	return hex.Dump(data)
}

// Summary returns a one-line summary of the packet.
func (p *Packet) Summary() string {
	name := p.MessageName
	if name == "" {
		name = fmt.Sprintf("0x%04X", p.MessageType)
	}
	return fmt.Sprintf("[%s] %s %s (%d bytes)",
		p.Timestamp.Format("15:04:05.000"),
		p.Direction, name, p.Size)
}

// ═══════════════════════════════════════════════════════════════════════════════
// PACKET RECORDER
// ═══════════════════════════════════════════════════════════════════════════════

// PacketRecorder records intercepted packets to a file.
//
// The in-memory ring is a true O(1) circular buffer (head/count over a
// fixed-size slice): the old implementation copied the entire retained window
// on every Record once it filled, which is O(n) per packet — quadratic under
// sustained load. Disk writes go through a buffered channel to a single writer
// goroutine, so a slow disk backpressures via the channel instead of
// serialising every connection behind synchronous I/O under the lock. A full
// channel drops the write (counted in dropped) rather than blocking the
// network path; write errors are counted too instead of being swallowed.
type PacketRecorder struct {
	mu       sync.Mutex
	ring     []Packet // fixed-capacity circular buffer
	head     int      // index of the oldest element
	size     int      // number of valid elements in the ring
	capacity int

	file      *os.File
	encoder   *json.Encoder
	writeCh   chan Packet
	writerWG  sync.WaitGroup
	closeOnce sync.Once

	count     atomic.Uint64
	dropped   atomic.Uint64
	writeErrs atomic.Uint64
	closed    atomic.Bool
}

const (
	recorderRingCapacity = 10000
	recorderWriteBuffer  = 4096
)

// NewPacketRecorder creates a new recorder writing to the given path.
func NewPacketRecorder(path string) (*PacketRecorder, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create recorder dir: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("create recorder file: %w", err)
	}

	r := &PacketRecorder{
		ring:     make([]Packet, recorderRingCapacity),
		capacity: recorderRingCapacity,
		file:     f,
		encoder:  json.NewEncoder(f),
		writeCh:  make(chan Packet, recorderWriteBuffer),
	}
	r.writerWG.Add(1)
	go r.writeLoop()
	return r, nil
}

// writeLoop drains queued packets to disk on a single goroutine, keeping disk
// I/O off the network hot path.
func (r *PacketRecorder) writeLoop() {
	defer r.writerWG.Done()
	for p := range r.writeCh {
		if err := r.encoder.Encode(p); err != nil {
			r.writeErrs.Add(1)
		}
	}
}

// Record adds a packet to the recording.
func (r *PacketRecorder) Record(p Packet) {
	p.ID = r.count.Add(1)

	r.mu.Lock()
	// O(1) circular-buffer insert: overwrite the oldest slot once full.
	if r.size < r.capacity {
		r.ring[(r.head+r.size)%r.capacity] = p
		r.size++
	} else {
		r.ring[r.head] = p
		r.head = (r.head + 1) % r.capacity
	}
	// Enqueue the write while still holding r.mu so it cannot race Close's
	// channel close (which also takes r.mu) — sending on a closed channel would
	// panic. After Close, writes are simply dropped (counted).
	if r.closed.Load() {
		r.mu.Unlock()
		r.dropped.Add(1)
		return
	}
	select {
	case r.writeCh <- p:
	default:
		// Buffer full: drop (counted) so a slow disk never blocks the network path.
		r.dropped.Add(1)
	}
	r.mu.Unlock()
}

// Packets returns all recorded packets currently retained in the ring, oldest
// first.
func (r *PacketRecorder) Packets() []Packet {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Packet, r.size)
	for i := 0; i < r.size; i++ {
		out[i] = r.ring[(r.head+i)%r.capacity]
	}
	return out
}

// Count returns the number of recorded packets.
func (r *PacketRecorder) Count() uint64 {
	return r.count.Load()
}

// DroppedWrites returns how many packets were not written to disk because the
// async write buffer was full (backpressure from a slow disk).
func (r *PacketRecorder) DroppedWrites() uint64 {
	return r.dropped.Load()
}

// WriteErrors returns how many disk encode errors the writer observed.
func (r *PacketRecorder) WriteErrors() uint64 {
	return r.writeErrs.Load()
}

// Close flushes pending writes and closes the recording file.
func (r *PacketRecorder) Close() error {
	r.closeOnce.Do(func() {
		// Take r.mu so the close cannot interleave with an in-flight Record
		// send on writeCh. Record checks r.closed under the same lock.
		r.mu.Lock()
		r.closed.Store(true)
		close(r.writeCh)
		r.mu.Unlock()
	})
	r.writerWG.Wait() // ensure all queued writes are flushed to the encoder
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// TCP PROXY
// ═══════════════════════════════════════════════════════════════════════════════

// ProxyConfig configures the MITM proxy.
type ProxyConfig struct {
	// ListenAddr is the local address to listen on (e.g. ":9339")
	ListenAddr string
	// UpstreamAddr is the real server address (e.g. "game-server.com:9339")
	UpstreamAddr string
	// RecordPath is the file path for packet recording (empty = no recording)
	RecordPath string
	// OnPacket is called for each intercepted packet (for real-time display)
	OnPacket func(Packet)
	// HeaderParser extracts message type from packet header.
	// Default: first 2 bytes as big-endian uint16.
	HeaderParser func([]byte) (messageType uint16, payloadOffset int)
	// Interactive enables live console prompting for altering packet payloads.
	Interactive bool
	// Protocol specifies TCP or UDP. Defaults to TCP.
	Protocol string
	// CryptoDecrypt Hook for decrypting payload (e.g. RC4/Sodium) before parsing.
	CryptoDecrypt func(data []byte) []byte
	// CryptoEncrypt Hook for re-encrypting payload before sending.
	CryptoEncrypt func(data []byte) []byte
	// InterceptEdit if provided, is called synchronously to allow TUI/GUI to edit packet.
	// If it returns non-nil, the payload is replaced.
	InterceptEdit func(pkt Packet, payloadOff int) []byte
}

// TCPProxy is a transparent TCP proxy that records traffic.
type TCPProxy struct {
	config   ProxyConfig
	listener net.Listener
	recorder *PacketRecorder
	done     chan struct{}
	wg       sync.WaitGroup
	stopOnce sync.Once
	editor   *PacketEditor
}

// NewTCPProxy creates a new TCP proxy with the given configuration.
func NewTCPProxy(config ProxyConfig) *TCPProxy {
	if config.HeaderParser == nil {
		config.HeaderParser = defaultHeaderParser
	}
	return &TCPProxy{
		config: config,
		done:   make(chan struct{}),
		editor: NewPacketEditor(),
	}
}

// Start begins listening and proxying connections.
func (p *TCPProxy) Start() error {
	var err error

	// Set up recorder if path is specified
	if p.config.RecordPath != "" {
		p.recorder, err = NewPacketRecorder(p.config.RecordPath)
		if err != nil {
			return fmt.Errorf("create recorder: %w", err)
		}
	}

	p.listener, err = net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", p.config.ListenAddr, err)
	}

	p.wg.Add(1)
	go p.acceptLoop()

	return nil
}

// Stop gracefully shuts down the proxy.
func (p *TCPProxy) Stop() error {
	p.stopOnce.Do(func() {
		close(p.done)
		if p.listener != nil {
			_ = p.listener.Close()
		}
	})
	p.wg.Wait()
	if p.recorder != nil {
		return p.recorder.Close()
	}
	return nil
}

// Stats returns proxy statistics.
func (p *TCPProxy) Stats() (packets uint64) {
	if p.recorder != nil {
		return p.recorder.Count()
	}
	return 0
}

func (p *TCPProxy) acceptLoop() {
	defer p.wg.Done()
	var retryDelay time.Duration
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.done:
				return
			default:
			}
			// Back off on persistent errors (e.g. EMFILE) instead of
			// busy-spinning the CPU; reset once Accept succeeds again.
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
		p.wg.Add(1)
		go p.handleConnection(conn)
	}
}

func (p *TCPProxy) handleConnection(clientConn net.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()

	if !upstreamAllowed(p.config.UpstreamAddr) {
		return
	}

	// Connect to upstream server
	serverConn, err := net.DialTimeout("tcp", p.config.UpstreamAddr, 10*time.Second)
	if err != nil {
		return
	}
	defer serverConn.Close()

	done := make(chan error, 2)
	go func() { done <- p.relay(clientConn, serverConn, DirectionClientToServer) }()
	go func() { done <- p.relay(serverConn, clientConn, DirectionServerToClient) }()

	// When either side finishes, wake the peer immediately instead of waiting for
	// the 30s read deadline.
	firstErr := <-done
	_ = clientConn.SetDeadline(time.Now())
	_ = serverConn.SetDeadline(time.Now())
	secondErr := <-done
	_ = firstErr
	_ = secondErr
}

func (p *TCPProxy) relay(src, dst net.Conn, dir Direction) error {
	readBuf := make([]byte, 65536)
	var streamBuf []byte
	const maxFrameSize = 16 * 1024 * 1024

	for {
		select {
		case <-p.done:
			return nil
		default:
		}

		_ = src.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := src.Read(readBuf)
		if n > 0 {
			streamBuf = append(streamBuf, readBuf[:n]...)

			for {
				if len(streamBuf) < 2 {
					break
				}

				msgType, payloadOff := p.config.HeaderParser(streamBuf)

				// Standard Supercell framing: 7-byte header with length
				if payloadOff == 7 {
					if len(streamBuf) < 7 {
						break
					}
					payloadLen := int(streamBuf[2])<<16 | int(streamBuf[3])<<8 | int(streamBuf[4])
					totalLen := 7 + payloadLen
					// payloadLen is derived from unsigned bytes and can be 0 for
					// legitimate header-only/keep-alive frames, so only the upper
					// bound is invalid here.
					if totalLen > maxFrameSize {
						return fmt.Errorf("invalid frame length %d", totalLen)
					}

					if len(streamBuf) < totalLen {
						break
					}

					wireData := make([]byte, totalLen)
					copy(wireData, streamBuf[:totalLen])
					streamBuf = streamBuf[totalLen:]

					viewData := p.decodeForInspection(wireData)
					viewMsgType, viewPayloadOff := p.config.HeaderParser(viewData)
					if viewPayloadOff != 0 {
						msgType, payloadOff = viewMsgType, viewPayloadOff
					}
					pkt := Packet{
						Timestamp:   time.Now(),
						Direction:   dir,
						Size:        len(viewData),
						Data:        viewData,
						MessageType: msgType,
					}

					forward := wireData
					if p.config.Interactive && msgType != 0 {
						if p.config.InterceptEdit != nil {
							patchedData := p.config.InterceptEdit(pkt, payloadOff)
							if patchedData != nil {
								pkt.Data = patchedData
								pkt.Size = len(patchedData)
								forward = p.encodeForForward(patchedData)
							}
						} else if !p.editor.IsIgnored(msgType) {
							_ = src.SetReadDeadline(time.Time{})
							patchedData := p.editor.PromptAndRewrite(pkt, payloadOff)
							_ = src.SetReadDeadline(time.Now().Add(30 * time.Second))

							if patchedData != nil {
								pkt.Data = patchedData
								pkt.Size = len(patchedData)
								forward = p.encodeForForward(patchedData)
							}
						}
					}

					if p.recorder != nil {
						p.recorder.Record(pkt)
					}
					if p.config.OnPacket != nil {
						p.config.OnPacket(pkt)
					}
					if err := writeAll(dst, forward); err != nil {
						return err
					}
				} else {
					// Fallback for non-7-byte custom protocols: forward the current TCP chunk.
					wireData := make([]byte, len(streamBuf))
					copy(wireData, streamBuf)
					streamBuf = nil
					viewData := p.decodeForInspection(wireData)
					msgType, payloadOff = p.config.HeaderParser(viewData)

					pkt := Packet{
						Timestamp:   time.Now(),
						Direction:   dir,
						Size:        len(viewData),
						Data:        viewData,
						MessageType: msgType,
					}

					forward := wireData
					if p.config.Interactive && msgType != 0 {
						if p.config.InterceptEdit != nil {
							patchedData := p.config.InterceptEdit(pkt, payloadOff)
							if patchedData != nil {
								pkt.Data = patchedData
								pkt.Size = len(patchedData)
								forward = p.encodeForForward(patchedData)
							}
						} else if !p.editor.IsIgnored(msgType) {
							_ = src.SetReadDeadline(time.Time{})
							patchedData := p.editor.PromptAndRewrite(pkt, payloadOff)
							_ = src.SetReadDeadline(time.Now().Add(30 * time.Second))

							if patchedData != nil {
								pkt.Data = patchedData
								pkt.Size = len(patchedData)
								forward = p.encodeForForward(patchedData)
							}
						}
					}

					if p.recorder != nil {
						p.recorder.Record(pkt)
					}
					if p.config.OnPacket != nil {
						p.config.OnPacket(pkt)
					}
					if err := writeAll(dst, forward); err != nil {
						return err
					}
					break
				}
			}
		}

		if err != nil {
			return err
		}
	}
}

func (p *TCPProxy) decodeForInspection(data []byte) []byte {
	if p.config.CryptoDecrypt == nil {
		return data
	}
	out := p.config.CryptoDecrypt(data)
	if out == nil {
		return data
	}
	return out
}

func (p *TCPProxy) encodeForForward(data []byte) []byte {
	if p.config.CryptoEncrypt == nil {
		return data
	}
	out := p.config.CryptoEncrypt(data)
	if out == nil {
		return data
	}
	return out
}

func writeAll(dst net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("short write")
		}
		data = data[n:]
	}
	return nil
}

// defaultHeaderParser reads the first 2 bytes as big-endian message type.
func defaultHeaderParser(data []byte) (uint16, int) {
	if len(data) < 2 {
		return 0, 0
	}
	return binary.BigEndian.Uint16(data[:2]), 2
}
