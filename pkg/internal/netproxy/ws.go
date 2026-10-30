package netproxy

import "encoding/binary"

// WebSocket frame decoding (RFC 6455).
//
// The BundleInjector already hooks the JS `fetch` API, but WebSocket traffic —
// the transport most live games actually use for real-time messaging — flowed
// through the proxy as opaque bytes. These helpers decode the WebSocket frame
// layer so a captured upgraded connection can be dissected into discrete
// messages (opcode, FIN, payload) and, for client frames, unmasked.

// WSOpcode is a WebSocket frame opcode (RFC 6455 §5.2).
type WSOpcode uint8

const (
	// WSContinuation continues a fragmented message.
	WSContinuation WSOpcode = 0x0
	// WSText is a UTF-8 text frame.
	WSText WSOpcode = 0x1
	// WSBinary is a binary frame.
	WSBinary WSOpcode = 0x2
	// WSClose is a connection-close control frame.
	WSClose WSOpcode = 0x8
	// WSPing is a ping control frame.
	WSPing WSOpcode = 0x9
	// WSPong is a pong control frame.
	WSPong WSOpcode = 0xA
)

// String names the opcode for display.
func (o WSOpcode) String() string {
	switch o {
	case WSContinuation:
		return "continuation"
	case WSText:
		return "text"
	case WSBinary:
		return "binary"
	case WSClose:
		return "close"
	case WSPing:
		return "ping"
	case WSPong:
		return "pong"
	default:
		return "reserved"
	}
}

// WSFrame is a single decoded WebSocket frame with its payload already
// unmasked (if it was masked).
type WSFrame struct {
	// Fin is true when this is the final fragment of a message.
	Fin bool
	// Opcode is the frame opcode.
	Opcode WSOpcode
	// Masked reports whether the frame was sent masked (client→server frames
	// must be masked per RFC 6455).
	Masked bool
	// Payload is the (unmasked) application payload.
	Payload []byte
}

// DecodeWSFrame decodes exactly one WebSocket frame from the front of data.
// It returns the frame, the number of bytes consumed, and ok=false when data
// does not yet contain a complete frame (the caller should read more bytes).
func DecodeWSFrame(data []byte) (WSFrame, int, bool) {
	if len(data) < 2 {
		return WSFrame{}, 0, false
	}
	b0, b1 := data[0], data[1]
	fin := b0&0x80 != 0
	opcode := WSOpcode(b0 & 0x0f)
	masked := b1&0x80 != 0
	length := uint64(b1 & 0x7f)

	off := 2
	switch length {
	case 126:
		if len(data) < off+2 {
			return WSFrame{}, 0, false
		}
		length = uint64(binary.BigEndian.Uint16(data[off : off+2]))
		off += 2
	case 127:
		if len(data) < off+8 {
			return WSFrame{}, 0, false
		}
		length = binary.BigEndian.Uint64(data[off : off+8])
		off += 8
	}

	var maskKey []byte
	if masked {
		if len(data) < off+4 {
			return WSFrame{}, 0, false
		}
		maskKey = data[off : off+4]
		off += 4
	}

	// Guard against absurd declared lengths that would overflow an int index.
	if length > uint64(len(data)) {
		return WSFrame{}, 0, false
	}
	end := off + int(length)
	if len(data) < end {
		return WSFrame{}, 0, false
	}

	payload := make([]byte, int(length))
	copy(payload, data[off:end])
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return WSFrame{
		Fin:     fin,
		Opcode:  opcode,
		Masked:  masked,
		Payload: payload,
	}, end, true
}

// DecodeWSFrames decodes as many complete WebSocket frames as data contains,
// returning them plus the number of trailing bytes that form an incomplete
// frame (to be prepended to the next read).
func DecodeWSFrames(data []byte) (frames []WSFrame, remaining int) {
	off := 0
	for off < len(data) {
		frame, n, ok := DecodeWSFrame(data[off:])
		if !ok {
			break
		}
		frames = append(frames, frame)
		off += n
	}
	return frames, len(data) - off
}
