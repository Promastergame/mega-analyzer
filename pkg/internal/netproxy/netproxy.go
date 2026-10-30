// Package netproxy provides a lightweight TCP MITM proxy for intercepting
// and recording binary game-client traffic.
package netproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"mega-analyzer/pkg/internal/deobfuscation"
)

// Direction indicates which side of the connection originated a packet.
type Direction string

const (
	// DirectionClientToServer marks traffic flowing from client → server.
	DirectionClientToServer Direction = "client→server"
	// DirectionServerToClient marks traffic flowing from server → client.
	DirectionServerToClient Direction = "server→client"
)

// Packet represents a single intercepted network packet.
type Packet struct {
	// ConnectionID identifies one TCP session, including across appended captures.
	ConnectionID string
	// ClientAddr and ServerAddr are the actual remote socket endpoints.
	ClientAddr string
	ServerAddr string
	// PayloadOffset is the framing header length (zero for raw TCP chunks).
	PayloadOffset int
	// Direction indicates who sent the packet.
	Direction Direction
	// Data is the raw payload bytes.
	Data []byte
	// Timestamp is when the packet was captured.
	Timestamp time.Time
	// MessageType is the decoded message-type / opcode from the packet header
	// (first two bytes interpreted as big-endian uint16). Zero when unknown.
	MessageType uint16
	// Size is the number of payload bytes (len(Data)).
	Size int
}

func (connection Packet) packet(dir Direction, data []byte) Packet {
	return Packet{
		ConnectionID: connection.ConnectionID,
		ClientAddr:   connection.ClientAddr,
		ServerAddr:   connection.ServerAddr,
		Direction:    dir,
		Data:         data,
		Timestamp:    time.Now(),
		MessageType:  parseMessageType(data),
		Size:         len(data),
	}
}

// Summary returns a human-readable one-liner describing the packet.
func (p Packet) Summary() string {
	preview := ""
	if len(p.Data) > 0 {
		n := 16
		if len(p.Data) < n {
			n = len(p.Data)
		}
		preview = hex.EncodeToString(p.Data[:n])
		if len(p.Data) > 16 {
			preview += "…"
		}
	}
	session := ""
	if p.ConnectionID != "" {
		session = " [" + p.ConnectionID + "]"
	}
	return fmt.Sprintf("[%s]%s %s  %d bytes  %s",
		p.Timestamp.Format("15:04:05.000"),
		session,
		p.Direction,
		len(p.Data),
		preview,
	)
}

// HexDump returns a formatted hex+ASCII dump of up to maxBytes bytes of the
// packet payload, suitable for display in a terminal.
func (p Packet) HexDump(maxBytes int) string {
	data := p.Data
	if len(data) > maxBytes {
		data = data[:maxBytes]
	}
	if len(data) == 0 {
		return "(empty)"
	}

	var out string
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		row := data[i:end]

		// Offset
		out += fmt.Sprintf("%04x  ", i)

		// Hex bytes
		for j, b := range row {
			out += fmt.Sprintf("%02x ", b)
			if j == 7 {
				out += " "
			}
		}
		// Padding for short rows
		for j := len(row); j < 16; j++ {
			out += "   "
			if j == 7 {
				out += " "
			}
		}

		// ASCII
		out += " |"
		for _, b := range row {
			if b >= 0x20 && b < 0x7f {
				out += string(rune(b))
			} else {
				out += "."
			}
		}
		out += "|\n"
	}
	if len(p.Data) > maxBytes {
		out += fmt.Sprintf("… (%d bytes truncated)\n", len(p.Data)-maxBytes)
	}
	return out
}

// ProxyConfig holds configuration for a TCPProxy instance.
type ProxyConfig struct {
	// ListenAddr is the local address to bind (e.g. ":8080").
	ListenAddr string
	// UpstreamAddr is the real server the proxy forwards to.
	UpstreamAddr string
	// RecordPath is an optional file path for saving captured packets.
	// Leave empty to disable recording.
	RecordPath string
	// OnPacket is called for every captured packet (may be nil).
	OnPacket func(Packet)
	// RedactAuthorization masks common HTTP auth/cookie headers before JSONL recording.
	RedactAuthorization bool
	// Interactive enables an interactive packet-editing mode.
	Interactive bool
	// InterceptEdit, when non-nil, is called for every packet in interactive
	// mode before the data is forwarded. The callback may return a replacement
	// payload, or nil to forward the original data unchanged.
	// payloadOff is the byte offset at which the application payload starts
	// (after any framing header).
	InterceptEdit func(pkt Packet, payloadOff int) []byte
	// Framer, when non-nil, reassembles the TCP byte stream into discrete
	// protocol frames so that each Packet, recorded line and interactive edit
	// corresponds to one real message rather than an arbitrary network read.
	// When nil the proxy relays one Packet per raw Read (legacy behavior).
	Framer Framer
}

// TCPProxy is a simple TCP man-in-the-middle proxy.
type TCPProxy struct {
	config      ProxyConfig
	listener    net.Listener
	wg          sync.WaitGroup
	quit        chan struct{}
	packets     atomic.Int64
	connections atomic.Uint64
	sessionID   string
	ctx         context.Context
	cancel      context.CancelFunc
	stopDone    chan struct{}
	recorder    *captureWriter
	mu          sync.Mutex
	stopped     bool
}

// CaptureRecord is the stable JSONL schema used by RecordPath.
type CaptureRecord struct {
	ConnectionID  string    `json:"connection_id,omitempty"`
	ClientAddr    string    `json:"client_addr,omitempty"`
	ServerAddr    string    `json:"server_addr,omitempty"`
	PayloadOffset int       `json:"payload_offset,omitempty"`
	Timestamp     time.Time `json:"ts"`
	Direction     Direction `json:"direction"`
	MessageType   uint16    `json:"message_type"`
	Size          int       `json:"size"`
	DataBase64    string    `json:"data_b64"`
}

// captureWriteBuffer is the depth of the recorder's async write queue. A full
// queue drops the record (counted) rather than blocking the network relay on a
// slow disk.
const captureWriteBuffer = 4096

// captureWriter serialises intercepted packets to a JSONL file on a single
// background goroutine. The previous recorder re-opened the file (open + write
// + close) under a global mutex for every packet, serialising every connection
// behind synchronous disk I/O on the hot path. Here the file is opened once and
// wrapped in a bufio.Writer; the relay goroutines only enqueue on a buffered
// channel, so JSON marshalling and disk writes never touch the network path.
type captureWriter struct {
	redact bool
	file   *os.File
	w      *bufio.Writer

	// Redaction follows each connection/direction before queue admission, so a
	// dropped record cannot desynchronise the parser for subsequent headers.
	// Protected by mu; entries are released when the connection ends.
	redactors map[captureStreamKey]*headerRedactor

	ch        chan Packet
	wg        sync.WaitGroup
	closeOnce sync.Once
	closed    atomic.Bool
	mu        sync.Mutex // guards the closed-check ↔ close(ch) transition

	dropped   atomic.Uint64
	writeErrs atomic.Uint64
	closeErr  error
}

type captureStreamKey struct {
	connectionID string
	direction    Direction
}

// newCaptureWriter opens path for append and starts the writer goroutine.
func newCaptureWriter(path string, redact bool) (*captureWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("netproxy: record open %s: %w", path, err)
	}
	cw := &captureWriter{
		redact: redact,
		file:   f,
		w:      bufio.NewWriter(f),
		ch:     make(chan Packet, captureWriteBuffer),
	}
	if redact {
		cw.redactors = make(map[captureStreamKey]*headerRedactor)
	}
	cw.wg.Add(1)
	go cw.loop()
	return cw, nil
}

// loop drains queued packets to disk, flushing the buffered writer on exit.
func (cw *captureWriter) loop() {
	defer cw.wg.Done()
	for pkt := range cw.ch {
		cw.writePacket(pkt)
	}
	if err := cw.w.Flush(); err != nil {
		cw.writeErrs.Add(1)
	}
}

func (cw *captureWriter) writePacket(pkt Packet) {
	data := pkt.Data
	rec := CaptureRecord{
		ConnectionID:  pkt.ConnectionID,
		ClientAddr:    pkt.ClientAddr,
		ServerAddr:    pkt.ServerAddr,
		PayloadOffset: pkt.PayloadOffset,
		Timestamp:     pkt.Timestamp,
		Direction:     pkt.Direction,
		MessageType:   pkt.MessageType,
		Size:          pkt.Size,
		DataBase64:    base64.StdEncoding.EncodeToString(data),
	}
	line, err := json.Marshal(rec)
	if err != nil {
		cw.writeErrs.Add(1)
		return
	}
	if _, err := cw.w.Write(line); err != nil {
		cw.writeErrs.Add(1)
		return
	}
	if err := cw.w.WriteByte('\n'); err != nil {
		cw.writeErrs.Add(1)
	}
}

// enqueue hands a packet to the writer goroutine. It never blocks the caller:
// a full queue (slow disk) drops the record, counted in dropped. The closed
// check under mu makes a send-after-close impossible even though the proxy's
// lifecycle already orders Stop's close after all relay goroutines exit.
func (cw *captureWriter) enqueue(pkt Packet) {
	cw.mu.Lock()
	if cw.closed.Load() {
		cw.mu.Unlock()
		cw.dropped.Add(1)
		return
	}
	if cw.redact {
		key := captureStreamKey{pkt.ConnectionID, pkt.Direction}
		redactor := cw.redactors[key]
		if redactor == nil {
			redactor = &headerRedactor{isResponse: pkt.Direction == DirectionServerToClient}
			cw.redactors[key] = redactor
		}
		pkt.Data = redactor.process(pkt.Data)
	} else {
		// Hooks may edit the forwarding buffer in place after enqueue returns.
		// The recorder owns a snapshot of the intercepted bytes.
		pkt.Data = bytes.Clone(pkt.Data)
	}
	select {
	case cw.ch <- pkt:
	default:
		cw.dropped.Add(1)
	}
	cw.mu.Unlock()
}

func (cw *captureWriter) endConnection(id string) {
	cw.mu.Lock()
	delete(cw.redactors, captureStreamKey{id, DirectionClientToServer})
	delete(cw.redactors, captureStreamKey{id, DirectionServerToClient})
	cw.mu.Unlock()
}

// close stops the writer, flushes buffered records and closes the file.
func (cw *captureWriter) close() error {
	cw.closeOnce.Do(func() {
		cw.mu.Lock()
		cw.closed.Store(true)
		close(cw.ch)
		cw.mu.Unlock()
		cw.wg.Wait()
		cw.closeErr = cw.file.Close()
		if cw.closeErr != nil {
			cw.writeErrs.Add(1)
		}
	})
	return cw.closeErr
}

// NewTCPProxy creates a new TCPProxy with the given configuration.
// Call Start to begin accepting connections.
func NewTCPProxy(config ProxyConfig) *TCPProxy {
	ctx, cancel := context.WithCancel(context.Background())
	return &TCPProxy{
		config:    config,
		quit:      make(chan struct{}),
		sessionID: rand.Text(),
		ctx:       ctx,
		cancel:    cancel,
		stopDone:  make(chan struct{}),
	}
}

// Start begins listening for incoming connections and returns once ready.
func (p *TCPProxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return fmt.Errorf("netproxy: proxy is stopped")
	}
	if p.listener != nil {
		return fmt.Errorf("netproxy: proxy is already started")
	}
	if p.config.RecordPath != "" {
		rec, err := newCaptureWriter(p.config.RecordPath, p.config.RedactAuthorization)
		if err != nil {
			return err
		}
		p.recorder = rec
	}

	ln, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		if p.recorder != nil {
			_ = p.recorder.close()
			p.recorder = nil
		}
		return fmt.Errorf("netproxy: listen %s: %w", p.config.ListenAddr, err)
	}
	p.listener = ln

	log.Printf("netproxy: listening on %s → %s", p.config.ListenAddr, p.config.UpstreamAddr)

	// Keep the accept loop in the group so Stop cannot race Wait against the
	// first accepted connection's Add.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.acceptLoop(ln)
	}()
	return nil
}

// Stop gracefully shuts down the proxy and waits for all active sessions to
// finish.
func (p *TCPProxy) Stop() {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		<-p.stopDone
		return
	}
	p.stopped = true
	p.mu.Unlock()
	defer close(p.stopDone)

	close(p.quit)
	p.cancel()
	if p.listener != nil {
		p.listener.Close()
	}
	p.wg.Wait()
	// All relay goroutines have exited, so no further enqueue can race the
	// recorder's close: flush and close it after the wait.
	if p.recorder != nil {
		_ = p.recorder.close()
	}
}

// Stats returns the total number of packets intercepted so far.
func (p *TCPProxy) Stats() int {
	return int(p.packets.Load())
}

// Connections returns the number of accepted TCP sessions.
func (p *TCPProxy) Connections() uint64 { return p.connections.Load() }

// acceptLoop accepts connections until the listener is closed.
func (p *TCPProxy) acceptLoop(ln net.Listener) {
	var retryDelay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.quit:
				return
			default:
			}
			// A transient error (e.g. too many open files) should not
			// permanently kill the accept loop; back off and keep trying
			// instead of busy-spinning.
			log.Printf("netproxy: accept error: %v", err)
			if retryDelay == 0 {
				retryDelay = 5 * time.Millisecond
			} else {
				retryDelay *= 2
			}
			if retryDelay > time.Second {
				retryDelay = time.Second
			}
			timer := time.NewTimer(retryDelay)
			select {
			case <-p.quit:
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		retryDelay = 0
		select {
		case <-p.quit:
			_ = conn.Close()
			return
		default:
		}
		id := fmt.Sprintf("%s-%d", p.sessionID, p.connections.Add(1))
		p.wg.Add(1)
		go p.handleConn(conn, id)
	}
}

// parseMessageType extracts the big-endian uint16 opcode from the first two
// bytes of a payload, returning 0 when the payload is too short.
func parseMessageType(data []byte) uint16 {
	if len(data) < 2 {
		return 0
	}
	return uint16(data[0])<<8 | uint16(data[1])
}

// handleConn proxies data between the client connection and the upstream server.
func (p *TCPProxy) handleConn(client net.Conn, id string) {
	defer p.wg.Done()
	defer client.Close()
	stopClient := context.AfterFunc(p.ctx, func() { _ = client.Close() })
	defer stopClient()

	if !upstreamAllowed(p.config.UpstreamAddr) {
		log.Printf("netproxy: blocked upstream by offline/allowlist policy: %s", p.config.UpstreamAddr)
		return
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	upstream, err := dialer.DialContext(p.ctx, "tcp", p.config.UpstreamAddr)
	if err != nil {
		log.Printf("netproxy: dial upstream %s: %v", p.config.UpstreamAddr, err)
		return
	}
	defer upstream.Close()
	stopUpstream := context.AfterFunc(p.ctx, func() { _ = upstream.Close() })
	defer stopUpstream()
	if p.recorder != nil {
		defer p.recorder.endConnection(id)
	}
	connection := Packet{ConnectionID: id, ClientAddr: client.RemoteAddr().String(), ServerAddr: upstream.RemoteAddr().String()}

	// Sniff protocol using a buffered reader
	reader := bufio.NewReader(client)
	// Set a short read deadline to avoid blocking forever on small client handshakes.
	// Peek the TLS record length first; a fixed 24-byte peek is too short for JA3.
	_ = client.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	peekBytes, peekErr := reader.Peek(5)
	if peekErr == nil && len(peekBytes) == 5 && peekBytes[0] == 0x16 && peekBytes[1] == 0x03 {
		recLen := int(peekBytes[3])<<8 | int(peekBytes[4])
		if recLen > 0 && recLen <= 64*1024 {
			if full, err := reader.Peek(5 + recLen); err == nil {
				peekBytes = full
			}
		}
	} else if preamble, err := reader.Peek(len("PRI * HTTP/2.0")); err == nil {
		peekBytes = preamble
	}
	_ = client.SetReadDeadline(time.Time{}) // Reset deadline
	protocol := "custom-binary"
	ja3Fingerprint := ""

	if len(peekBytes) > 0 {
		if bytes.HasPrefix(peekBytes, []byte("PRI * HTTP/2.0")) {
			protocol = "http2/grpc"
		} else if len(peekBytes) >= 3 && peekBytes[0] == 0x16 && peekBytes[1] == 0x03 {
			protocol = "tls"
			if _, hash := JA3(peekBytes); hash != "" {
				ja3Fingerprint = hash
			}
		}
	}

	if protocol == "tls" {
		log.Printf("netproxy: [SNIFFER] Sniffed TLS stream, JA3 Fingerprint: %s", ja3Fingerprint)
	} else if protocol == "http2/grpc" {
		log.Printf("netproxy: [SNIFFER] Sniffed gRPC / HTTP2 stream")
	} else {
		log.Printf("netproxy: [SNIFFER] Sniffed custom binary stream")
	}

	_ = peekErr // keep compiler happy if unused

	done := make(chan struct{}, 2)

	relay := func(dst net.Conn, src io.Reader, dir Direction) {
		defer func() {
			// Preserve the opposite direction after EOF. Closing the whole socket
			// here loses in-flight request or response bytes; a TCP half-close
			// communicates EOF while allowing the peer relay to drain.
			closeWrite(dst)
			done <- struct{}{}
		}()
		if p.config.Framer != nil {
			p.relayFramed(dst, src, dir, connection)
			return
		}
		buf := make([]byte, 64*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				payload := make([]byte, n)
				copy(payload, buf[:n])

				pkt := connection.packet(dir, payload)
				forward := p.processPacket(pkt, 0)
				if _, werr := dst.Write(forward); werr != nil {
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					// Ignore common close errors.
				}
				return
			}
		}
	}

	go relay(upstream, reader, DirectionClientToServer)
	go relay(client, upstream, DirectionServerToClient)

	// A proxy session is complete only after both directions have drained.
	// During shutdown close both sockets once to unblock pending reads, then
	// still join both goroutines before the recorder can be closed.
	completed := 0
	shutdown := p.quit
	for completed < 2 {
		select {
		case <-done:
			completed++
		case <-shutdown:
			_ = client.Close()
			_ = upstream.Close()
			shutdown = nil
		}
	}
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(conn net.Conn) {
	if conn == nil {
		return
	}
	if halfCloser, ok := conn.(closeWriter); ok {
		_ = halfCloser.CloseWrite()
	}
}

// relayFramed reassembles the TCP byte stream into discrete frames using
// p.config.Framer, emitting exactly one Packet per real protocol message. On
// loss of frame sync it flushes the buffer as a raw packet and continues in
// raw mode for the remainder of the connection, so a single malformed frame
// can never wedge the proxy.
func (p *TCPProxy) relayFramed(dst net.Conn, src io.Reader, dir Direction, connection Packet) {
	framer := p.config.Framer
	readBuf := make([]byte, 64*1024)
	var acc []byte
	flushRaw := func(b []byte) bool {
		if len(b) == 0 {
			return true
		}
		pkt := connection.packet(dir, bytes.Clone(b))
		_, werr := dst.Write(p.processPacket(pkt, 0))
		return werr == nil
	}
	for {
		n, err := src.Read(readBuf)
		if n > 0 {
			acc = append(acc, readBuf[:n]...)
			for len(acc) > 0 {
				frameLen, headerLen, ok := framer(acc)
				if !ok {
					// Lost sync: forward whatever we have raw and degrade to
					// raw relaying for the rest of this direction.
					if !flushRaw(acc) {
						return
					}
					acc = nil
					if !p.copyRaw(dst, src, dir, readBuf, connection) {
						return
					}
					return
				}
				if frameLen == 0 {
					break // need more bytes for the next frame
				}
				frame := acc[:frameLen]
				pkt := connection.packet(dir, bytes.Clone(frame))
				if !p.writeForward(dst, pkt, headerLen) {
					return
				}
				acc = acc[frameLen:]
			}
		}
		if err != nil {
			flushRaw(acc) // forward any trailing partial frame on close
			return
		}
	}
}

// copyRaw drains src to dst in raw mode after frame sync is lost, still routing
// each chunk through processPacket so recording and hooks keep working.
func (p *TCPProxy) copyRaw(dst net.Conn, src io.Reader, dir Direction, buf []byte, connection Packet) bool {
	for {
		n, err := src.Read(buf)
		if n > 0 {
			pkt := connection.packet(dir, bytes.Clone(buf[:n]))
			if _, werr := dst.Write(p.processPacket(pkt, 0)); werr != nil {
				return false
			}
		}
		if err != nil {
			return true
		}
	}
}

// writeForward processes a framed packet and writes the result to dst.
func (p *TCPProxy) writeForward(dst net.Conn, pkt Packet, payloadOff int) bool {
	_, werr := dst.Write(p.processPacket(pkt, payloadOff))
	return werr == nil
}

// processPacket runs the capture, recording, interactive-edit and bundle-inject
// pipeline for a single packet and returns the bytes to forward upstream. It is
// shared by the raw and framed relay paths so both behave identically apart
// from where message boundaries are drawn. payloadOff is the offset at which
// the application payload begins (0 when unframed).
func (p *TCPProxy) processPacket(pkt Packet, payloadOff int) []byte {
	pkt.PayloadOffset = payloadOff
	p.packets.Add(1)

	if p.recorder != nil {
		p.recorder.enqueue(pkt)
	}
	if p.config.OnPacket != nil {
		p.config.OnPacket(pkt)
	}

	forward := pkt.Data
	if p.config.Interactive && p.config.InterceptEdit != nil {
		if edited := p.config.InterceptEdit(pkt, payloadOff); edited != nil {
			forward = edited
		}
	}

	// [BundleInjector] - On-the-fly JavaScript bundle interception and injection.
	// The precheck is allocation-free: game traffic is binary, so the fast first-
	// byte test rejects almost every packet before any scanning. The old path
	// allocated strings.ToLower(string(forward[:200])) on every S→C packet >200B.
	if pkt.Direction == DirectionServerToClient && isJavaScriptHTTPResponse(forward) {
		log.Printf("netproxy: [BUNDLE INJECTOR] Intercepted JavaScript response on-the-fly!")

		parts := bytes.SplitN(forward, []byte("\r\n\r\n"), 2)
		if len(parts) == 2 {
			jsBody := string(parts[1])

			engine := deobfuscation.NewJSDeobfuscator(deobfuscation.DefaultJSOptions())
			jsBody = engine.Deobfuscate(jsBody)

			hook := `
// --- MEGA-ANALYZER INJECTED HOOK ---
(function(){
	var originalFetch = global.fetch;
	global.fetch = function() {
		console.log("[Mega-Analyzer] Intercepted fetch:", arguments);
		return originalFetch.apply(this, arguments);
	};
})();
// -----------------------------------
`
			jsBody = hook + jsBody
			forward = rewriteHTTPBody(forward, []byte(jsBody))
			log.Printf("netproxy: [BUNDLE INJECTOR] Successfully injected and deobfuscated bundle!")
		}
	}
	return forward
}

// DroppedRecords returns how many capture records were dropped because the
// async write buffer was full (backpressure from a slow disk). Zero when
// recording is disabled.
func (p *TCPProxy) DroppedRecords() uint64 {
	if p.recorder == nil {
		return 0
	}
	return p.recorder.dropped.Load()
}

// RecordWriteErrors returns how many capture records failed to marshal or write.
func (p *TCPProxy) RecordWriteErrors() uint64 {
	if p.recorder == nil {
		return 0
	}
	return p.recorder.writeErrs.Load()
}

// isJavaScriptHTTPResponse reports whether data is the head of an HTTP 200
// response carrying a JavaScript Content-Type. It scans only the header region
// (up to bundleScanLimit bytes) case-insensitively over the raw bytes, so it
// never allocates — the common case (binary game traffic) is rejected on the
// first byte, since an HTTP response always begins with "HTTP/".
func isJavaScriptHTTPResponse(data []byte) bool {
	// An HTTP/1.x response starts with "HTTP/1.". Reject everything else without
	// scanning — this is the fast path for the binary game protocol.
	if len(data) < 12 || !bytes.HasPrefix(data, []byte("HTTP/1.")) {
		return false
	}
	head := data
	if len(head) > bundleScanLimit {
		head = head[:bundleScanLimit]
	}
	if !containsFold(head, []byte("200 ok")) {
		return false
	}
	return containsFold(head, []byte("content-type: application/javascript")) ||
		containsFold(head, []byte("content-type: text/javascript")) ||
		containsFold(head, []byte("content-type: application/x-javascript"))
}

// bundleScanLimit caps how far into a response the JavaScript-bundle precheck
// scans for the status line and Content-Type header.
const bundleScanLimit = 512

// containsFold reports whether needle (assumed lowercase ASCII) appears in
// haystack under ASCII case-folding, without allocating.
func containsFold(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	last := len(haystack) - len(needle)
	for i := 0; i <= last; i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			c := haystack[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
