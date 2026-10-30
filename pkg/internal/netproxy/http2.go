package netproxy

import "encoding/binary"

// HTTP/2 frame-layer decoding (RFC 7540 §4.1, §6).
//
// The sniffer already recognises the HTTP/2 connection preface, but the
// framing layer beneath it was never decoded, so multiplexed streams were
// invisible. These helpers split an HTTP/2 byte stream into its frames —
// length, type, flags and stream id — and expose DATA/HEADERS payloads so a
// gRPC or HTTP/2 game protocol can be dissected per stream. HPACK header
// decompression is intentionally out of scope here; this is the framing layer
// that a header decoder would sit on top of.

// H2Preface is the fixed client connection preface.
const H2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// H2FrameType is an HTTP/2 frame type (RFC 7540 §6).
type H2FrameType uint8

const (
	// H2Data carries stream data (request/response bodies, gRPC messages).
	H2Data H2FrameType = 0x0
	// H2Headers carries an HPACK-encoded header block.
	H2Headers H2FrameType = 0x1
	// H2Priority sets stream priority.
	H2Priority H2FrameType = 0x2
	// H2RSTStream terminates a stream.
	H2RSTStream H2FrameType = 0x3
	// H2Settings carries connection settings.
	H2Settings H2FrameType = 0x4
	// H2PushPromise reserves a stream for a server push.
	H2PushPromise H2FrameType = 0x5
	// H2Ping is a connection liveness probe.
	H2Ping H2FrameType = 0x6
	// H2GoAway begins connection shutdown.
	H2GoAway H2FrameType = 0x7
	// H2WindowUpdate adjusts flow-control windows.
	H2WindowUpdate H2FrameType = 0x8
	// H2Continuation continues a header block.
	H2Continuation H2FrameType = 0x9
)

// String names the frame type for display.
func (t H2FrameType) String() string {
	switch t {
	case H2Data:
		return "DATA"
	case H2Headers:
		return "HEADERS"
	case H2Priority:
		return "PRIORITY"
	case H2RSTStream:
		return "RST_STREAM"
	case H2Settings:
		return "SETTINGS"
	case H2PushPromise:
		return "PUSH_PROMISE"
	case H2Ping:
		return "PING"
	case H2GoAway:
		return "GOAWAY"
	case H2WindowUpdate:
		return "WINDOW_UPDATE"
	case H2Continuation:
		return "CONTINUATION"
	default:
		return "UNKNOWN"
	}
}

// H2Frame is a single decoded HTTP/2 frame.
type H2Frame struct {
	// Type is the frame type.
	Type H2FrameType
	// Flags is the raw flags byte.
	Flags uint8
	// StreamID is the 31-bit stream identifier (0 = connection-level).
	StreamID uint32
	// Payload is the frame payload (raw; HPACK not decoded for HEADERS).
	Payload []byte
}

// EndStream reports whether the END_STREAM flag (0x1) is set. Meaningful for
// DATA and HEADERS frames.
func (f H2Frame) EndStream() bool { return f.Flags&0x1 != 0 }

// DecodeH2Frame decodes one HTTP/2 frame from the front of data. It returns the
// frame, bytes consumed, and ok=false if a complete frame is not yet present.
// data must not include the 24-byte connection preface (strip it first with
// StripH2Preface).
func DecodeH2Frame(data []byte) (H2Frame, int, bool) {
	const headerLen = 9
	if len(data) < headerLen {
		return H2Frame{}, 0, false
	}
	length := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	ftype := H2FrameType(data[3])
	flags := data[4]
	streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7fffffff

	end := headerLen + int(length)
	if len(data) < end {
		return H2Frame{}, 0, false
	}
	payload := make([]byte, int(length))
	copy(payload, data[headerLen:end])
	return H2Frame{
		Type:     ftype,
		Flags:    flags,
		StreamID: streamID,
		Payload:  payload,
	}, end, true
}

// StripH2Preface removes the client connection preface if data begins with it,
// returning the remaining bytes and whether the preface was present.
func StripH2Preface(data []byte) ([]byte, bool) {
	if len(data) >= len(H2Preface) && string(data[:len(H2Preface)]) == H2Preface {
		return data[len(H2Preface):], true
	}
	return data, false
}

// DecodeH2Frames decodes all complete frames in data (after stripping any
// preface), returning them plus the count of trailing incomplete bytes.
func DecodeH2Frames(data []byte) (frames []H2Frame, remaining int) {
	data, _ = StripH2Preface(data)
	off := 0
	for off < len(data) {
		frame, n, ok := DecodeH2Frame(data[off:])
		if !ok {
			break
		}
		frames = append(frames, frame)
		off += n
	}
	return frames, len(data) - off
}
