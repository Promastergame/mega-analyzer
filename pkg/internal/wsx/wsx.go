// Package wsx is a tiny, dependency-free WebSocket server implementation
// (RFC 6455) used to replace github.com/gobwas/ws + wsutil. It only implements
// what this project needs: an HTTP upgrade helper plus server-side text/binary
// writes and a client-data reader that transparently answers ping/close control
// frames and reassembles fragmented messages.
package wsx

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

// OpCode is a WebSocket frame opcode.
type OpCode byte

const (
	OpContinuation OpCode = 0x0
	OpText         OpCode = 0x1
	OpBinary       OpCode = 0x2
	OpClose        OpCode = 0x8
	OpPing         OpCode = 0x9
	OpPong         OpCode = 0xA
)

// wsMagic is the RFC 6455 GUID appended to Sec-WebSocket-Key.
const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Handshake is returned by UpgradeHTTP. It is intentionally minimal; callers in
// this project ignore it, but it keeps a gobwas-compatible 4-value signature.
type Handshake struct {
	Protocol string
}

// wsConn wraps a hijacked connection. Reads go through the buffered reader
// returned by Hijack (it may already hold bytes), and all writes are serialized
// by wmu so a ping/pong reply never interleaves with an application write.
type wsConn struct {
	net.Conn
	r   *bufio.Reader
	wmu sync.Mutex
}

func (c *wsConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// UpgradeHTTP performs the server side of the RFC 6455 opening handshake and
// hijacks the underlying TCP connection.
func UpgradeHTTP(r *http.Request, w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, Handshake, error) {
	if !headerContainsToken(r.Header, "Connection", "upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
		return nil, nil, Handshake{}, errors.New("wsx: not a websocket upgrade")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, nil, Handshake{}, errors.New("wsx: missing Sec-WebSocket-Key")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "connection not hijackable", http.StatusInternalServerError)
		return nil, nil, Handshake{}, errors.New("wsx: response writer is not a http.Hijacker")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, nil, Handshake{}, err
	}

	accept := acceptKey(key)
	var b strings.Builder
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Accept: ")
	b.WriteString(accept)
	b.WriteString("\r\n\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		conn.Close()
		return nil, nil, Handshake{}, err
	}

	wc := &wsConn{Conn: conn, r: brw.Reader}
	return wc, brw, Handshake{}, nil
}

func acceptKey(key string) string {
	h := sha1.New()
	io.WriteString(h, key+wsMagic)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func headerContainsToken(h http.Header, name, token string) bool {
	for _, v := range h[http.CanonicalHeaderKey(name)] {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// WriteServerText writes payload as a single unfragmented text frame.
func WriteServerText(conn net.Conn, payload []byte) error {
	return writeFrame(conn, OpText, payload)
}

// WriteServerBinary writes payload as a single unfragmented binary frame.
func WriteServerBinary(conn net.Conn, payload []byte) error {
	return writeFrame(conn, OpBinary, payload)
}

// writeFrame encodes and writes one server frame (never masked, FIN=1).
func writeFrame(conn net.Conn, op OpCode, payload []byte) error {
	n := len(payload)
	var hdr []byte
	switch {
	case n < 126:
		hdr = []byte{0x80 | byte(op), byte(n)}
	case n < 65536:
		hdr = []byte{0x80 | byte(op), 126, byte(n >> 8), byte(n)}
	default:
		hdr = make([]byte, 10)
		hdr[0] = 0x80 | byte(op)
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
	}
	frame := make([]byte, 0, len(hdr)+n)
	frame = append(frame, hdr...)
	frame = append(frame, payload...)

	if wc, ok := conn.(*wsConn); ok {
		wc.wmu.Lock()
		defer wc.wmu.Unlock()
	}
	_, err := conn.Write(frame)
	return err
}

// ReadClientData reads the next application (text/binary) message from the
// client. It transparently replies to ping frames, drops pong frames, honors
// close frames (returning io.EOF), and reassembles fragmented messages.
func ReadClientData(conn net.Conn) ([]byte, OpCode, error) {
	var rd io.Reader = conn
	if wc, ok := conn.(*wsConn); ok {
		rd = wc.r
	}

	var msg []byte
	var msgOp OpCode
	inMessage := false

	for {
		fin, op, payload, err := readFrame(rd)
		if err != nil {
			return nil, 0, err
		}
		if uint64(len(msg))+uint64(len(payload)) > MaxFrameSize {
			return nil, 0, ErrFrameTooLarge
		}

		switch op {
		case OpPing:
			if err := writeFrame(conn, OpPong, payload); err != nil {
				return nil, 0, err
			}
			continue
		case OpPong:
			continue
		case OpClose:
			_ = writeFrame(conn, OpClose, nil)
			return nil, OpClose, io.EOF
		case OpContinuation:
			if !inMessage {
				return nil, 0, errors.New("wsx: continuation frame without start frame")
			}
			msg = append(msg, payload...)
		case OpText, OpBinary:
			if inMessage {
				return nil, 0, errors.New("wsx: new data frame before previous finished")
			}
			inMessage = true
			msgOp = op
			msg = append(msg, payload...)
		default:
			return nil, 0, errors.New("wsx: unknown opcode")
		}

		if fin && inMessage {
			return msg, msgOp, nil
		}
	}
}

// readFrame reads a single WebSocket frame and returns its FIN bit, opcode and
// unmasked payload.
func readFrame(r io.Reader) (bool, OpCode, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return false, 0, nil, err
	}
	fin := h[0]&0x80 != 0
	op := OpCode(h[0] & 0x0f)
	masked := h[1]&0x80 != 0
	length := uint64(h[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > MaxFrameSize {
		return false, 0, nil, ErrFrameTooLarge
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return false, 0, nil, err
		}
	}

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return false, 0, nil, err
		}
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i&3]
		}
	}
	return fin, op, payload, nil
}
