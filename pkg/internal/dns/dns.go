// Package dns is a small, dependency-free DNS implementation providing the
// subset of the github.com/miekg/dns API that this project uses: message
// pack/unpack, a UDP+TCP server with a ServeMux, a UDP/TCP client, and the
// A/AAAA/CNAME resource records. It is intentionally minimal but wire-correct
// for the common query/response path (RFC 1035), including name-compression
// pointers on decode.
package dns

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Record types and classes.
const (
	TypeNone  uint16 = 0
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33

	ClassINET uint16 = 1
)

// Opcodes.
const (
	OpcodeQuery  = 0
	OpcodeIQuery = 1
	OpcodeStatus = 2
)

// Response codes.
const (
	RcodeSuccess        = 0
	RcodeFormatError    = 1
	RcodeServerFailure  = 2
	RcodeNameError      = 3 // NXDOMAIN
	RcodeNotImplemented = 4
	RcodeRefused        = 5
)

// TypeToString maps record types to their textual representation.
var TypeToString = map[uint16]string{
	TypeNone:  "None",
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeSOA:   "SOA",
	TypePTR:   "PTR",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
	TypeSRV:   "SRV",
}

var errTruncated = errors.New("dns: buffer size too small")

// Fqdn returns the fully qualified domain name (adds a trailing dot).
func Fqdn(s string) string {
	if s == "" {
		return "."
	}
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// ── Message types ────────────────────────────────────────────

// Question is a single DNS question.
type Question struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

// Msg is a DNS message (header + sections).
type Msg struct {
	Id                 uint16
	Response           bool
	Opcode             int
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	Rcode              int
	Compress           bool

	Question []Question
	Answer   []RR
	Ns       []RR
	Extra    []RR
}

// SetQuestion prepares m as a single-question recursive query.
func (m *Msg) SetQuestion(name string, qtype uint16) *Msg {
	m.Id = genID()
	m.RecursionDesired = true
	m.Question = []Question{{Name: Fqdn(name), Qtype: qtype, Qclass: ClassINET}}
	return m
}

// SetReply turns m into a reply for req.
func (m *Msg) SetReply(req *Msg) *Msg {
	m.Id = req.Id
	m.Response = true
	m.Opcode = req.Opcode
	if m.Opcode == OpcodeQuery {
		m.RecursionDesired = req.RecursionDesired
	}
	m.Rcode = RcodeSuccess
	if len(req.Question) > 0 {
		m.Question = make([]Question, len(req.Question))
		copy(m.Question, req.Question)
	}
	return m
}

// SetRcode turns m into a reply for req carrying the given response code.
func (m *Msg) SetRcode(req *Msg, rcode int) *Msg {
	m.SetReply(req)
	m.Rcode = rcode
	return m
}

// ── Resource records ─────────────────────────────────────────

// RR_Header is the common header shared by all resource records.
type RR_Header struct {
	Name     string
	Rrtype   uint16
	Class    uint16
	Ttl      uint32
	Rdlength uint16
}

func (h *RR_Header) String() string {
	class := "IN"
	if h.Class != ClassINET && h.Class != 0 {
		class = strconv.Itoa(int(h.Class))
	}
	t := TypeToString[h.Rrtype]
	if t == "" {
		t = "TYPE" + strconv.Itoa(int(h.Rrtype))
	}
	return fmt.Sprintf("%s\t%d\t%s\t%s", h.Name, h.Ttl, class, t)
}

// RR is the interface implemented by all resource records.
type RR interface {
	Header() *RR_Header
	String() string
	rdata() []byte
}

// A is an IPv4 address record.
type A struct {
	Hdr RR_Header
	A   net.IP
}

func (rr *A) Header() *RR_Header { return &rr.Hdr }
func (rr *A) String() string     { return rr.Hdr.String() + "\t" + rr.A.String() }
func (rr *A) rdata() []byte {
	ip := rr.A.To4()
	if ip == nil {
		return make([]byte, 4)
	}
	return []byte(ip)
}

// AAAA is an IPv6 address record.
type AAAA struct {
	Hdr  RR_Header
	AAAA net.IP
}

func (rr *AAAA) Header() *RR_Header { return &rr.Hdr }
func (rr *AAAA) String() string     { return rr.Hdr.String() + "\t" + rr.AAAA.String() }
func (rr *AAAA) rdata() []byte {
	ip := rr.AAAA.To16()
	if ip == nil {
		return make([]byte, 16)
	}
	return []byte(ip)
}

// CNAME is a canonical-name record.
type CNAME struct {
	Hdr    RR_Header
	Target string
}

func (rr *CNAME) Header() *RR_Header { return &rr.Hdr }
func (rr *CNAME) String() string     { return rr.Hdr.String() + "\t" + rr.Target }
func (rr *CNAME) rdata() []byte {
	b, _ := packName(rr.Target)
	return b
}

// genericRR holds records whose type we do not decode specifically.
type genericRR struct {
	Hdr   RR_Header
	RData []byte
}

func (rr *genericRR) Header() *RR_Header { return &rr.Hdr }
func (rr *genericRR) String() string     { return rr.Hdr.String() + "\t\\# " + strconv.Itoa(len(rr.RData)) }
func (rr *genericRR) rdata() []byte      { return rr.RData }

func rrType(rr RR) uint16 {
	switch rr.(type) {
	case *A:
		return TypeA
	case *AAAA:
		return TypeAAAA
	case *CNAME:
		return TypeCNAME
	}
	return rr.Header().Rrtype
}

// NewRR parses a one-line record such as "example.com. A 127.0.0.1".
// Supported forms: NAME [TTL] [CLASS] TYPE RDATA, for A/AAAA/CNAME.
func NewRR(s string) (RR, error) {
	fields := strings.Fields(s)
	if len(fields) < 3 {
		return nil, fmt.Errorf("dns: cannot parse RR %q", s)
	}
	name := Fqdn(fields[0])
	rest := fields[1:]
	ttl := uint32(3600)
	if v, err := strconv.Atoi(rest[0]); err == nil {
		ttl = uint32(v)
		rest = rest[1:]
	}
	if len(rest) > 0 && strings.EqualFold(rest[0], "IN") {
		rest = rest[1:]
	}
	if len(rest) < 2 {
		return nil, fmt.Errorf("dns: cannot parse RR %q", s)
	}
	typ := strings.ToUpper(rest[0])
	rdata := rest[1]
	hdr := RR_Header{Name: name, Class: ClassINET, Ttl: ttl}
	switch typ {
	case "A":
		ip := net.ParseIP(rdata)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("dns: bad A address %q", rdata)
		}
		hdr.Rrtype = TypeA
		return &A{Hdr: hdr, A: ip.To4()}, nil
	case "AAAA":
		ip := net.ParseIP(rdata)
		if ip == nil {
			return nil, fmt.Errorf("dns: bad AAAA address %q", rdata)
		}
		hdr.Rrtype = TypeAAAA
		return &AAAA{Hdr: hdr, AAAA: ip.To16()}, nil
	case "CNAME":
		hdr.Rrtype = TypeCNAME
		return &CNAME{Hdr: hdr, Target: Fqdn(rdata)}, nil
	}
	return nil, fmt.Errorf("dns: unsupported RR type %q", typ)
}

// ── Wire encoding ────────────────────────────────────────────

func packName(name string) ([]byte, error) {
	name = Fqdn(strings.ToLower(name))
	if name == "." {
		return []byte{0}, nil
	}
	var buf []byte
	for _, l := range strings.Split(name, ".") {
		if l == "" {
			continue
		}
		if len(l) > 63 {
			return nil, errors.New("dns: label exceeds 63 octets")
		}
		buf = append(buf, byte(len(l)))
		buf = append(buf, l...)
	}
	buf = append(buf, 0)
	return buf, nil
}

func unpackName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	ptrs := 0
	endOff := off
	jumped := false
	for {
		if off >= len(msg) {
			return "", 0, errTruncated
		}
		c := msg[off]
		switch {
		case c == 0:
			off++
			if !jumped {
				endOff = off
			}
			if sb.Len() == 0 {
				return ".", endOff, nil
			}
			return sb.String(), endOff, nil
		case c&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errTruncated
			}
			ptr := int(c&0x3F)<<8 | int(msg[off+1])
			if !jumped {
				endOff = off + 2
			}
			off = ptr
			jumped = true
			ptrs++
			if ptrs > 100 {
				return "", 0, errors.New("dns: too many compression pointers")
			}
		default:
			l := int(c)
			off++
			if off+l > len(msg) {
				return "", 0, errTruncated
			}
			sb.Write(msg[off : off+l])
			sb.WriteByte('.')
			off += l
		}
	}
}

// Pack serializes the message to wire format.
func (m *Msg) Pack() ([]byte, error) {
	var hdr [12]byte
	binary.BigEndian.PutUint16(hdr[0:], m.Id)
	var b2 byte
	if m.Response {
		b2 |= 0x80
	}
	b2 |= byte(m.Opcode&0x0f) << 3
	if m.Authoritative {
		b2 |= 0x04
	}
	if m.Truncated {
		b2 |= 0x02
	}
	if m.RecursionDesired {
		b2 |= 0x01
	}
	hdr[2] = b2
	var b3 byte
	if m.RecursionAvailable {
		b3 |= 0x80
	}
	b3 |= byte(m.Rcode & 0x0f)
	hdr[3] = b3
	binary.BigEndian.PutUint16(hdr[4:], uint16(len(m.Question)))
	binary.BigEndian.PutUint16(hdr[6:], uint16(len(m.Answer)))
	binary.BigEndian.PutUint16(hdr[8:], uint16(len(m.Ns)))
	binary.BigEndian.PutUint16(hdr[10:], uint16(len(m.Extra)))

	buf := append([]byte{}, hdr[:]...)
	for _, q := range m.Question {
		nb, err := packName(q.Name)
		if err != nil {
			return nil, err
		}
		buf = append(buf, nb...)
		var t [4]byte
		binary.BigEndian.PutUint16(t[0:], q.Qtype)
		cls := q.Qclass
		if cls == 0 {
			cls = ClassINET
		}
		binary.BigEndian.PutUint16(t[2:], cls)
		buf = append(buf, t[:]...)
	}
	for _, section := range [][]RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range section {
			b, err := packRR(rr)
			if err != nil {
				return nil, err
			}
			buf = append(buf, b...)
		}
	}
	return buf, nil
}

func packRR(rr RR) ([]byte, error) {
	h := rr.Header()
	nb, err := packName(h.Name)
	if err != nil {
		return nil, err
	}
	buf := append([]byte{}, nb...)
	var t [8]byte
	binary.BigEndian.PutUint16(t[0:], rrType(rr))
	cls := h.Class
	if cls == 0 {
		cls = ClassINET
	}
	binary.BigEndian.PutUint16(t[2:], cls)
	binary.BigEndian.PutUint32(t[4:], h.Ttl)
	buf = append(buf, t[:]...)
	rd := rr.rdata()
	var l [2]byte
	binary.BigEndian.PutUint16(l[0:], uint16(len(rd)))
	buf = append(buf, l[:]...)
	buf = append(buf, rd...)
	return buf, nil
}

// Unpack parses a wire-format message.
func Unpack(data []byte) (*Msg, error) {
	if len(data) < 12 {
		return nil, errTruncated
	}
	m := new(Msg)
	m.Id = binary.BigEndian.Uint16(data[0:])
	b2, b3 := data[2], data[3]
	m.Response = b2&0x80 != 0
	m.Opcode = int(b2>>3) & 0x0f
	m.Authoritative = b2&0x04 != 0
	m.Truncated = b2&0x02 != 0
	m.RecursionDesired = b2&0x01 != 0
	m.RecursionAvailable = b3&0x80 != 0
	m.Rcode = int(b3 & 0x0f)
	qd := int(binary.BigEndian.Uint16(data[4:]))
	an := int(binary.BigEndian.Uint16(data[6:]))
	ns := int(binary.BigEndian.Uint16(data[8:]))
	ar := int(binary.BigEndian.Uint16(data[10:]))

	off := 12
	var err error
	for i := 0; i < qd; i++ {
		var name string
		name, off, err = unpackName(data, off)
		if err != nil {
			return nil, err
		}
		if off+4 > len(data) {
			return nil, errTruncated
		}
		q := Question{
			Name:   name,
			Qtype:  binary.BigEndian.Uint16(data[off:]),
			Qclass: binary.BigEndian.Uint16(data[off+2:]),
		}
		off += 4
		m.Question = append(m.Question, q)
	}
	if m.Answer, off, err = unpackRRs(data, off, an); err != nil {
		return nil, err
	}
	if m.Ns, off, err = unpackRRs(data, off, ns); err != nil {
		return nil, err
	}
	if m.Extra, off, err = unpackRRs(data, off, ar); err != nil {
		return nil, err
	}
	return m, nil
}

func unpackRRs(data []byte, off, count int) ([]RR, int, error) {
	var out []RR
	for i := 0; i < count; i++ {
		name, no, err := unpackName(data, off)
		if err != nil {
			return nil, 0, err
		}
		off = no
		if off+10 > len(data) {
			return nil, 0, errTruncated
		}
		rrtype := binary.BigEndian.Uint16(data[off:])
		class := binary.BigEndian.Uint16(data[off+2:])
		ttl := binary.BigEndian.Uint32(data[off+4:])
		rdlen := int(binary.BigEndian.Uint16(data[off+8:]))
		off += 10
		if off+rdlen > len(data) {
			return nil, 0, errTruncated
		}
		hdr := RR_Header{Name: name, Rrtype: rrtype, Class: class, Ttl: ttl, Rdlength: uint16(rdlen)}
		var rr RR
		switch rrtype {
		case TypeA:
			if rdlen >= 4 {
				rr = &A{Hdr: hdr, A: net.IP(append([]byte{}, data[off:off+4]...))}
			}
		case TypeAAAA:
			if rdlen >= 16 {
				rr = &AAAA{Hdr: hdr, AAAA: net.IP(append([]byte{}, data[off:off+16]...))}
			}
		case TypeCNAME:
			target, _, nerr := unpackName(data, off)
			if nerr != nil {
				return nil, 0, nerr
			}
			rr = &CNAME{Hdr: hdr, Target: target}
		}
		if rr == nil {
			rr = &genericRR{Hdr: hdr, RData: append([]byte{}, data[off:off+rdlen]...)}
		}
		off += rdlen
		out = append(out, rr)
	}
	return out, off, nil
}

func genID() uint16 {
	var b [2]byte
	if _, err := crand.Read(b[:]); err != nil {
		return uint16(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint16(b[:])
}
