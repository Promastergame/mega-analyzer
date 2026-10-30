package labkit

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// wsGUID is the magic value from RFC 6455 §1.3 used to derive the handshake
// accept token.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// wsMaxPayload bounds a single frame's payload so a hostile or buggy client
// cannot make the lab allocate without limit.
const wsMaxPayload = 1 << 20 // 1 MiB

// wsOpcode is a WebSocket frame opcode (RFC 6455 §5.2).
type wsOpcode byte

const (
	opContinuation wsOpcode = 0x0
	opText         wsOpcode = 0x1
	opBinary       wsOpcode = 0x2
	opClose        wsOpcode = 0x8
	opPing         wsOpcode = 0x9
	opPong         wsOpcode = 0xA
)

// wsFrame is one decoded WebSocket frame.
type wsFrame struct {
	fin     bool
	opcode  wsOpcode
	masked  bool
	maskKey [4]byte
	payload []byte
}

// computeAcceptKey derives the Sec-WebSocket-Accept response value from the
// client's Sec-WebSocket-Key, per RFC 6455 §4.2.2.
func computeAcceptKey(key string) string {
	h := sha1.New()
	io.WriteString(h, key+wsGUID)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// isWebSocketUpgrade reports whether r is a valid RFC 6455 upgrade request.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		tokenListContains(r.Header.Get("Connection"), "upgrade") &&
		r.Header.Get("Sec-WebSocket-Key") != "" &&
		r.Header.Get("Sec-WebSocket-Version") == "13"
}

func tokenListContains(header, want string) bool {
	for _, part := range strings.Split(header, ",") {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	return false
}

// webSocketEcho returns an http.Handler that performs the RFC 6455 handshake,
// hijacks the connection, and echoes text/binary messages back to the client.
// It answers pings with pongs and closes cleanly on a close frame.
func webSocketEcho(log *Logger, m *Metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			http.Error(w, "expected websocket upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			log.Error("ws hijack failed", Fields{"err": err.Error()})
			return
		}
		defer conn.Close()

		accept := computeAcceptKey(r.Header.Get("Sec-WebSocket-Key"))
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
		if _, err := brw.WriteString(resp); err != nil {
			return
		}
		if err := brw.Flush(); err != nil {
			return
		}
		m.Inc("ws.connections")
		log.Info("ws connected", Fields{"remote": r.RemoteAddr})

		if err := wsEchoLoop(brw, m); err != nil && err != io.EOF {
			log.Debug("ws closed", Fields{"reason": err.Error()})
		}
	})
}

// wsEchoLoop reads messages and echoes them until the peer closes or errors.
func wsEchoLoop(brw *bufio.ReadWriter, m *Metrics) error {
	var msg []byte
	var msgOp wsOpcode
	for {
		f, err := readFrame(brw.Reader)
		if err != nil {
			return err
		}
		switch f.opcode {
		case opPing:
			if err := writeFrame(brw.Writer, wsFrame{fin: true, opcode: opPong, payload: f.payload}); err != nil {
				return err
			}
			if err := brw.Flush(); err != nil {
				return err
			}
			m.Inc("ws.pings")
		case opPong:
			// Ignore unsolicited pongs.
		case opClose:
			_ = writeFrame(brw.Writer, wsFrame{fin: true, opcode: opClose, payload: f.payload})
			_ = brw.Flush()
			return io.EOF
		case opText, opBinary:
			msg = append(msg[:0], f.payload...)
			msgOp = f.opcode
			if f.fin {
				if err := wsSend(brw, msgOp, msg, m); err != nil {
					return err
				}
			}
		case opContinuation:
			msg = append(msg, f.payload...)
			if len(msg) > wsMaxPayload {
				return fmt.Errorf("assembled message exceeds %d bytes", wsMaxPayload)
			}
			if f.fin {
				if err := wsSend(brw, msgOp, msg, m); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unsupported opcode 0x%x", f.opcode)
		}
	}
}

func wsSend(brw *bufio.ReadWriter, op wsOpcode, payload []byte, m *Metrics) error {
	if err := writeFrame(brw.Writer, wsFrame{fin: true, opcode: op, payload: payload}); err != nil {
		return err
	}
	m.Inc("ws.messages")
	m.Add("ws.bytes", int64(len(payload)))
	return brw.Flush()
}

// readFrame decodes a single WebSocket frame. Masked client payloads are
// unmasked in place before returning.
func readFrame(r *bufio.Reader) (wsFrame, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return wsFrame{}, err
	}
	f := wsFrame{
		fin:    hdr[0]&0x80 != 0,
		opcode: wsOpcode(hdr[0] & 0x0f),
		masked: hdr[1]&0x80 != 0,
	}
	length := uint64(hdr[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrame{}, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return wsFrame{}, err
		}
		length = binary.BigEndian.Uint64(ext[:])
	}
	if length > wsMaxPayload {
		return wsFrame{}, fmt.Errorf("frame payload %d exceeds %d", length, wsMaxPayload)
	}
	if f.masked {
		if _, err := io.ReadFull(r, f.maskKey[:]); err != nil {
			return wsFrame{}, err
		}
	}
	f.payload = make([]byte, length)
	if _, err := io.ReadFull(r, f.payload); err != nil {
		return wsFrame{}, err
	}
	if f.masked {
		for i := range f.payload {
			f.payload[i] ^= f.maskKey[i%4]
		}
	}
	return f, nil
}

// writeFrame encodes a single WebSocket frame. If f.masked is set the payload
// is masked with f.maskKey (used by the test client; servers send unmasked).
func writeFrame(w *bufio.Writer, f wsFrame) error {
	b0 := byte(f.opcode)
	if f.fin {
		b0 |= 0x80
	}
	if err := w.WriteByte(b0); err != nil {
		return err
	}
	n := len(f.payload)
	var b1 byte
	if f.masked {
		b1 = 0x80
	}
	switch {
	case n <= 125:
		if err := w.WriteByte(b1 | byte(n)); err != nil {
			return err
		}
	case n <= 0xffff:
		if err := w.WriteByte(b1 | 126); err != nil {
			return err
		}
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		if _, err := w.Write(ext[:]); err != nil {
			return err
		}
	default:
		if err := w.WriteByte(b1 | 127); err != nil {
			return err
		}
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		if _, err := w.Write(ext[:]); err != nil {
			return err
		}
	}
	if f.masked {
		if _, err := w.Write(f.maskKey[:]); err != nil {
			return err
		}
		masked := make([]byte, n)
		for i := 0; i < n; i++ {
			masked[i] = f.payload[i] ^ f.maskKey[i%4]
		}
		_, err := w.Write(masked)
		return err
	}
	_, err := w.Write(f.payload)
	return err
}
