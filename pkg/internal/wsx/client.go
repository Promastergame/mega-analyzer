package wsx

import (
	"bufio"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ClientConn is a minimal RFC 6455 WebSocket client connection. It speaks
// plaintext ws:// only (no TLS), which is all the local Chrome DevTools
// endpoint requires.
type ClientConn struct {
	conn net.Conn
	r    *bufio.Reader
	wmu  sync.Mutex
	in   bool // reassembly: inside a fragmented message
}

// Dial connects to a ws:// endpoint and performs the client handshake.
func Dial(rawURL string) (*ClientConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ws" {
		return nil, errors.New("wsx: only ws:// scheme is supported")
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	conn, err := net.DialTimeout("tcp", host, 15*time.Second)
	if err != nil {
		return nil, err
	}

	var kb [16]byte
	if _, err := crand.Read(kb[:]); err != nil {
		conn.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(kb[:])
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !strings.Contains(status, " 101 ") {
		conn.Close()
		return nil, errors.New("wsx: unexpected handshake status: " + strings.TrimSpace(status))
	}
	var accept string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if idx := strings.IndexByte(line, ':'); idx > 0 {
			if strings.EqualFold(strings.TrimSpace(line[:idx]), "Sec-WebSocket-Accept") {
				accept = strings.TrimSpace(line[idx+1:])
			}
		}
	}
	if accept != acceptKey(key) {
		conn.Close()
		return nil, errors.New("wsx: handshake accept key mismatch")
	}
	return &ClientConn{conn: conn, r: br}, nil
}

// Close closes the underlying connection.
func (c *ClientConn) Close() error { return c.conn.Close() }

// WriteText sends a masked text message.
func (c *ClientConn) WriteText(payload []byte) error {
	return c.writeMasked(OpText, payload)
}

// WriteBinary sends a masked binary message.
func (c *ClientConn) WriteBinary(payload []byte) error {
	return c.writeMasked(OpBinary, payload)
}

// writeMasked writes a single final, client-masked frame (RFC 6455 requires
// all client-to-server frames to be masked).
func (c *ClientConn) writeMasked(op OpCode, payload []byte) error {
	n := len(payload)
	var hdr []byte
	b0 := byte(0x80) | byte(op) // FIN + opcode
	switch {
	case n < 126:
		hdr = []byte{b0, 0x80 | byte(n)}
	case n < 65536:
		hdr = []byte{b0, 0x80 | 126, byte(n >> 8), byte(n)}
	default:
		hdr = make([]byte, 10)
		hdr[0] = b0
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	var mask [4]byte
	if _, err := crand.Read(mask[:]); err != nil {
		return err
	}
	frame := make([]byte, 0, len(hdr)+4+n)
	frame = append(frame, hdr...)
	frame = append(frame, mask[:]...)
	for i := 0; i < n; i++ {
		frame = append(frame, payload[i]^mask[i&3])
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.conn.Write(frame)
	return err
}

// ReadMessage reads the next complete data message, transparently handling
// control frames (ping -> pong, pong dropped, close -> io.EOF) and fragment
// reassembly.
func (c *ClientConn) ReadMessage() (OpCode, []byte, error) {
	var msg []byte
	var msgOp OpCode
	inMsg := false
	for {
		fin, op, payload, err := readFrame(c.r)
		if err != nil {
			return 0, nil, err
		}
		switch op {
		case OpPing:
			if err := c.writeMasked(OpPong, payload); err != nil {
				return 0, nil, err
			}
			continue
		case OpPong:
			continue
		case OpClose:
			_ = c.writeMasked(OpClose, nil)
			return OpClose, nil, io.EOF
		case OpContinuation:
			if !inMsg {
				return 0, nil, errors.New("wsx: continuation frame without start frame")
			}
			msg = append(msg, payload...)
		case OpText, OpBinary:
			if inMsg {
				return 0, nil, errors.New("wsx: new data frame before previous finished")
			}
			inMsg = true
			msgOp = op
			msg = append(msg, payload...)
		default:
			return 0, nil, errors.New("wsx: unknown opcode")
		}
		if fin && inMsg {
			return msgOp, msg, nil
		}
	}
}
