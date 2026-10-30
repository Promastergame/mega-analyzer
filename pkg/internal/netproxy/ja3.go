package netproxy

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3 computes a proper JA3 fingerprint from a raw TLS ClientHello record.
//
// JA3 = MD5( SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats )
// where each list is '-' joined and GREASE values are removed (RFC 8701).
//
// The previous implementation hashed the first 24 raw bytes, which is NOT a
// JA3 fingerprint and is useless for client identification. This parses the
// handshake properly and returns both the raw JA3 string and its MD5 hash.
//
// On any parse error it returns empty strings; callers should treat that as
// "not a parseable ClientHello".
func JA3(record []byte) (ja3 string, hash string) {
	ch, ok := parseClientHello(record)
	if !ok {
		return "", ""
	}
	ja3 = ch.string()
	sum := md5.Sum([]byte(ja3))
	return ja3, hex.EncodeToString(sum[:])
}

type clientHello struct {
	version    uint16
	ciphers    []uint16
	extensions []uint16
	curves     []uint16
	pointFmts  []uint16
}

func (c clientHello) string() string {
	var sb strings.Builder
	sb.WriteString(strconv.Itoa(int(c.version)))
	sb.WriteByte(',')
	sb.WriteString(joinU16(c.ciphers))
	sb.WriteByte(',')
	sb.WriteString(joinU16(c.extensions))
	sb.WriteByte(',')
	sb.WriteString(joinU16(c.curves))
	sb.WriteByte(',')
	sb.WriteString(joinU16(c.pointFmts))
	return sb.String()
}

func joinU16(v []uint16) string {
	parts := make([]string, 0, len(v))
	for _, x := range v {
		parts = append(parts, strconv.Itoa(int(x)))
	}
	return strings.Join(parts, "-")
}

// isGREASE reports whether a value is a GREASE placeholder (RFC 8701).
func isGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && (v>>8) == (v&0xff)
}

// parseClientHello extracts the JA3-relevant fields from a TLS record that
// begins with a Handshake (0x16) record containing a ClientHello (type 1).
func parseClientHello(b []byte) (clientHello, bool) {
	var ch clientHello
	// TLS record header: type(1) version(2) length(2)
	if len(b) < 5 || b[0] != 0x16 {
		return ch, false
	}
	p := b[5:] // handshake message
	// Handshake header: type(1) length(3)
	if len(p) < 4 || p[0] != 0x01 {
		return ch, false
	}
	p = p[4:]
	// client_version(2) + random(32)
	if len(p) < 34 {
		return ch, false
	}
	ch.version = binary.BigEndian.Uint16(p[0:2])
	p = p[34:]
	// session_id
	if len(p) < 1 {
		return ch, false
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return ch, false
	}
	p = p[sidLen:]
	// cipher_suites
	if len(p) < 2 {
		return ch, false
	}
	csLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if len(p) < csLen {
		return ch, false
	}
	for i := 0; i+1 < csLen; i += 2 {
		c := binary.BigEndian.Uint16(p[i : i+2])
		if !isGREASE(c) {
			ch.ciphers = append(ch.ciphers, c)
		}
	}
	p = p[csLen:]
	// compression_methods
	if len(p) < 1 {
		return ch, false
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return ch, false
	}
	p = p[cmLen:]
	// extensions (optional in old TLS but always present in practice)
	if len(p) < 2 {
		return ch, true
	}
	extTotal := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if len(p) < extTotal {
		extTotal = len(p)
	}
	p = p[:extTotal]
	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p[0:2])
		extLen := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if len(p) < extLen {
			break
		}
		body := p[:extLen]
		p = p[extLen:]
		if !isGREASE(extType) {
			ch.extensions = append(ch.extensions, extType)
		}
		switch extType {
		case 0x000a: // supported_groups (elliptic curves)
			if len(body) >= 2 {
				n := int(binary.BigEndian.Uint16(body[0:2]))
				curves := body[2:]
				for i := 0; i+1 < n && i+1 < len(curves); i += 2 {
					g := binary.BigEndian.Uint16(curves[i : i+2])
					if !isGREASE(g) {
						ch.curves = append(ch.curves, g)
					}
				}
			}
		case 0x000b: // ec_point_formats
			if len(body) >= 1 {
				n := int(body[0])
				for i := 0; i < n && i+1 < len(body); i++ {
					ch.pointFmts = append(ch.pointFmts, uint16(body[1+i]))
				}
			}
		}
	}
	return ch, true
}
