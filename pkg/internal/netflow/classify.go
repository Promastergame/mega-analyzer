// Package netflow adds a streaming flow-tracking, protocol-classification and
// display-filter layer on top of the raw packet stream produced by
// pkg/internal/netproxy. Where netproxy relays and records bytes, netflow
// reasons about them: it groups packets into bidirectional flows keyed by
// their 5-tuple, classifies each flow's application protocol independently of
// its port (nDPI-style), and lets callers select flows/packets with a
// Wireshark-style display-filter expression.
//
// It is the Go-side counterpart to the Rust omnisec-capture crate and shares
// its classification vocabulary so a flow labelled "tls" here means the same
// thing there.
package netflow

import "strings"

// Protocol is a recognised application-layer protocol.
type Protocol string

const (
	// ProtoHTTP1 is an HTTP/1.x request or response.
	ProtoHTTP1 Protocol = "http1"
	// ProtoHTTP2 is an HTTP/2 connection preface.
	ProtoHTTP2 Protocol = "http2"
	// ProtoWebSocket is a WebSocket upgrade handshake.
	ProtoWebSocket Protocol = "websocket"
	// ProtoTLS is a TLS record (handshake or application data).
	ProtoTLS Protocol = "tls"
	// ProtoDNS is a DNS message.
	ProtoDNS Protocol = "dns"
	// ProtoSSH is an SSH transport banner.
	ProtoSSH Protocol = "ssh"
	// ProtoUnknown means no known signature matched.
	ProtoUnknown Protocol = "unknown"
)

// http2Preface is the fixed 24-byte HTTP/2 connection preface.
const http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

var httpMethods = []string{
	"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
}

// Classify identifies the application protocol carried by a stream prefix,
// working from the bytes rather than the port. transport is "tcp" or "udp" and
// disambiguates transport-specific cases (e.g. a bare DNS datagram over UDP).
// It returns the most specific protocol it can prove, else ProtoUnknown.
func Classify(payload []byte, transport string) Protocol {
	if len(payload) == 0 {
		return ProtoUnknown
	}

	// HTTP/2 preface (checked before HTTP/1 since it starts with "PRI ").
	if strings.HasPrefix(string(payload), http2Preface[:min(len(payload), len(http2Preface))]) &&
		len(payload) >= 4 && string(payload[:4]) == "PRI " {
		return ProtoHTTP2
	}

	// TLS record: content type 20..23, legacy version 0x03xx.
	if len(payload) >= 3 && payload[0] >= 0x14 && payload[0] <= 0x17 &&
		payload[1] == 0x03 && payload[2] <= 0x04 {
		return ProtoTLS
	}

	if strings.HasPrefix(string(payload), "SSH-") {
		return ProtoSSH
	}

	if isHTTP1(payload) {
		if headerHasWebSocketUpgrade(payload) {
			return ProtoWebSocket
		}
		return ProtoHTTP1
	}

	if transport == "udp" && looksLikeDNS(payload) {
		return ProtoDNS
	}

	return ProtoUnknown
}

func isHTTP1(payload []byte) bool {
	s := string(payload)
	if strings.HasPrefix(s, "HTTP/1.") {
		return true
	}
	for _, m := range httpMethods {
		if strings.HasPrefix(s, m) {
			return true
		}
	}
	return false
}

func headerHasWebSocketUpgrade(payload []byte) bool {
	end := strings.Index(string(payload), "\r\n\r\n")
	if end < 0 {
		end = len(payload)
	}
	head := strings.ToLower(string(payload[:end]))
	return strings.Contains(head, "upgrade:") && strings.Contains(head, "websocket")
}

// TLSSNI extracts the Server Name Indication from a TLS ClientHello record,
// returning "" if the bytes are not a parseable ClientHello or carry no SNI.
func TLSSNI(record []byte) string {
	// Record header: type(1)=0x16 version(2) length(2).
	if len(record) < 5 || record[0] != 0x16 {
		return ""
	}
	p := record[5:]
	// Handshake header: type(1)=1 length(3).
	if len(p) < 4 || p[0] != 0x01 {
		return ""
	}
	p = p[4:]
	if len(p) < 34 {
		return ""
	}
	p = p[34:] // client_version(2)+random(32)
	if len(p) < 1 {
		return ""
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return ""
	}
	p = p[sidLen:]
	if len(p) < 2 {
		return ""
	}
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen {
		return ""
	}
	p = p[csLen:]
	if len(p) < 1 {
		return ""
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return ""
	}
	p = p[cmLen:]
	if len(p) < 2 {
		return ""
	}
	extTotal := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) > extTotal {
		p = p[:extTotal]
	}
	for len(p) >= 4 {
		extType := int(p[0])<<8 | int(p[1])
		extLen := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < extLen {
			break
		}
		body := p[:extLen]
		p = p[extLen:]
		if extType == 0x0000 { // server_name
			if len(body) < 2 {
				continue
			}
			q := body[2:]
			for len(q) >= 3 {
				nameType := q[0]
				nameLen := int(q[1])<<8 | int(q[2])
				q = q[3:]
				if len(q) < nameLen {
					break
				}
				if nameType == 0 {
					return string(q[:nameLen])
				}
				q = q[nameLen:]
			}
		}
	}
	return ""
}

func looksLikeDNS(payload []byte) bool {
	if len(payload) < 12 {
		return false
	}
	flags := uint16(payload[2])<<8 | uint16(payload[3])
	if flags&0x0070 != 0 { // reserved (Z) bits must be zero
		return false
	}
	opcode := (flags >> 11) & 0x0f
	switch opcode {
	case 0, 1, 2, 4, 5:
	default:
		return false
	}
	qd := uint16(payload[4])<<8 | uint16(payload[5])
	return qd >= 1 && qd <= 64
}
