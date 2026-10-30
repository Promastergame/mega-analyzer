package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRecordsAndMessageRoundTrip(t *testing.T) {
	var records []RR
	for _, tt := range []struct {
		text string
		typ  uint16
		ttl  uint32
		data string
	}{
		{"Example.Test 60 IN A 192.0.2.1", TypeA, 60, "192.0.2.1"},
		{"v6.example.test AAAA 2001:db8::1", TypeAAAA, 3600, "2001:db8::1"},
		{"alias.example.test in CNAME Example.Test", TypeCNAME, 3600, "Example.Test."},
	} {
		rr, err := NewRR(tt.text)
		if err != nil {
			t.Fatal(err)
		}
		if rr.Header().Rrtype != tt.typ || rr.Header().Ttl != tt.ttl || !strings.Contains(rr.String(), tt.data) {
			t.Fatalf("record=%s", rr)
		}
		records = append(records, rr)
	}
	raw := &genericRR{Hdr: RR_Header{Name: "unknown.test.", Rrtype: 65000, Class: 3, Ttl: 5}, RData: []byte{1, 2, 3}}
	if !strings.Contains(raw.String(), "TYPE65000") || !strings.Contains(raw.String(), "\\# 3") {
		t.Fatal(raw.String())
	}
	q := new(Msg).SetQuestion("Example.Test", TypeA)
	q.Id = 42
	reply := new(Msg).SetReply(q)
	reply.Authoritative = true
	reply.Truncated = true
	reply.RecursionAvailable = true
	reply.Rcode = RcodeNameError
	reply.Answer = records
	reply.Ns = []RR{raw}
	reply.Extra = []RR{records[0]}
	b, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unpack(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Id != 42 || !got.Response || !got.Authoritative || !got.Truncated || !got.RecursionDesired || !got.RecursionAvailable || got.Rcode != RcodeNameError || len(got.Answer) != 3 || len(got.Ns) != 1 || len(got.Extra) != 1 {
		t.Fatalf("message=%+v", got)
	}
	if got.Question[0].Name != "example.test." || got.Answer[0].(*A).A.String() != "192.0.2.1" || got.Answer[1].(*AAAA).AAAA.String() != "2001:db8::1" || got.Answer[2].(*CNAME).Target != "example.test." || !bytes.Equal(got.Ns[0].(*genericRR).RData, raw.RData) {
		t.Fatal("record wire round-trip changed data")
	}
	q.Question[0].Name = "changed."
	if reply.Question[0].Name == "changed." {
		t.Fatal("reply aliases query questions")
	}
	status := new(Msg).SetReply(&Msg{Opcode: OpcodeStatus, RecursionDesired: true})
	if status.Opcode != OpcodeStatus || status.RecursionDesired {
		t.Fatal("non-query reply flags")
	}
	for _, s := range []string{"", "a", "a."} {
		if !strings.HasSuffix(Fqdn(s), ".") {
			t.Fatal(s)
		}
	}
	if !bytes.Equal((&A{}).rdata(), make([]byte, 4)) || !bytes.Equal((&AAAA{}).rdata(), make([]byte, 16)) {
		t.Fatal("invalid IP fallback")
	}
}

func TestInvalidRecordsNamesAndTruncatedMessages(t *testing.T) {
	for _, s := range []string{"", "host 1 IN", "host A nope", "host A ::1", "host AAAA nope", "host TXT text"} {
		if rr, err := NewRR(s); err == nil {
			t.Errorf("accepted invalid RR %q: %v", s, rr)
		}
	}
	long := strings.Repeat("a", 64) + ".test"
	if _, err := packName(long); err == nil {
		t.Fatal("oversize label accepted")
	}
	if _, err := (&Msg{Question: []Question{{Name: long}}}).Pack(); err == nil {
		t.Fatal("invalid question packed")
	}
	rr := &A{Hdr: RR_Header{Name: long}, A: net.IPv4(1, 2, 3, 4)}
	if _, err := (&Msg{Answer: []RR{rr}}).Pack(); err == nil {
		t.Fatal("invalid RR packed")
	}
	b, err := new(Msg).SetQuestion("example.test", TypeA).Pack()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(b); i++ {
		if _, err := Unpack(b[:i]); err == nil {
			t.Errorf("truncation %d accepted", i)
		}
	}
	for _, data := range [][]byte{nil, {0xc0}, {0xc0, 0}, {0xc0, 0xff}, {3, 'a'}} {
		if _, _, err := unpackName(data, 0); err == nil {
			t.Errorf("invalid name %x accepted", data)
		}
	}
	compressed := []byte{1, 'a', 0, 0xc0, 0}
	name, next, err := unpackName(compressed, 3)
	if err != nil || name != "a." || next != 5 {
		t.Fatalf("pointer=%q %d %v", name, next, err)
	}
	// Truncate each RR section separately, not only the question section.
	for section := 0; section < 3; section++ {
		m := &Msg{}
		r := &genericRR{Hdr: RR_Header{Name: "x.", Rrtype: TypeTXT}, RData: []byte{1, 'a'}}
		switch section {
		case 0:
			m.Answer = []RR{r}
		case 1:
			m.Ns = []RR{r}
		case 2:
			m.Extra = []RR{r}
		}
		p, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		for i := 12; i < len(p); i++ {
			if _, err := Unpack(p[:i]); err == nil {
				t.Errorf("section %d truncated at %d accepted", section, i)
			}
		}
	}
	// An A with insufficient rdata is retained as an opaque record.
	m := &Msg{Answer: []RR{&genericRR{Hdr: RR_Header{Name: "x.", Rrtype: TypeA}, RData: []byte{1}}}}
	p, _ := m.Pack()
	out, err := Unpack(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.Answer[0].(*genericRR); !ok {
		t.Fatal("short A should remain opaque")
	}
	// A compressed CNAME target with an invalid pointer must fail.
	rrbytes := []byte{0, 0, 5, 0, 1, 0, 0, 0, 0, 0, 2, 0xc0, 0xff}
	if _, _, err := unpackRRs(rrbytes, 0, 1); err == nil {
		t.Fatal("invalid CNAME target accepted")
	}
}

type recordedWriter struct{ message *Msg }

func (w *recordedWriter) LocalAddr() net.Addr         { return nil }
func (w *recordedWriter) RemoteAddr() net.Addr        { return nil }
func (w *recordedWriter) WriteMsg(m *Msg) error       { w.message = m; return nil }
func (w *recordedWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *recordedWriter) Close() error                { return nil }

func TestServeMuxLongestSuffixAndRefusal(t *testing.T) {
	mux := NewServeMux()
	var hit string
	for _, name := range []string{"", "Example.Test", "api.example.test"} {
		name := name
		mux.HandleFunc(name, func(ResponseWriter, *Msg) { hit = name })
	}
	for _, tt := range []struct{ query, want string }{{"API.EXAMPLE.TEST", "api.example.test"}, {"child.example.test", "Example.Test"}, {"other.test", ""}} {
		hit = "not called"
		mux.ServeDNS(&recordedWriter{}, new(Msg).SetQuestion(tt.query, TypeA))
		if hit != tt.want {
			t.Errorf("route %s=%q want %q", tt.query, hit, tt.want)
		}
	}
	for _, req := range []*Msg{new(Msg).SetQuestion("unknown.test", TypeA), {}} {
		w := &recordedWriter{}
		NewServeMux().ServeDNS(w, req)
		if w.message == nil || w.message.Rcode != RcodeRefused || !w.message.Response {
			t.Fatal("unmatched query not refused")
		}
	}
	old := DefaultServeMux
	DefaultServeMux = NewServeMux()
	t.Cleanup(func() { DefaultServeMux = old })
	HandleFunc("unit.test", func(w ResponseWriter, r *Msg) { w.WriteMsg(new(Msg).SetReply(r)) })
	if (&Server{}).handler() != DefaultServeMux {
		t.Fatal("default handler")
	}
	w := &recordedWriter{}
	DefaultServeMux.ServeDNS(w, new(Msg).SetQuestion("unit.test", TypeA))
	if w.message == nil || w.message.Rcode != 0 {
		t.Fatal("default mux")
	}
}

func TestLocalUDPAndTCPExchange(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			handlerDone := make(chan error, 1)
			s := &Server{Net: network, Handler: HandlerFunc(func(w ResponseWriter, r *Msg) {
				if w.LocalAddr() == nil || w.RemoteAddr() == nil {
					handlerDone <- errors.New("missing connection addresses")
					return
				}
				reply := new(Msg).SetReply(r)
				rr, _ := NewRR("example.test. 30 IN A 192.0.2.7")
				reply.Answer = []RR{rr}
				handlerDone <- w.WriteMsg(reply)
			})}
			var addr string
			if network == "udp" {
				pc, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				s.PacketConn = pc
				addr = pc.LocalAddr().String()
			} else {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				s.Listener = l
				addr = l.Addr().String()
			}
			done := make(chan error, 1)
			go func() { done <- s.ActivateAndServe() }()
			t.Cleanup(func() {
				s.Shutdown()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("server shutdown timed out")
				}
			})
			req := new(Msg).SetQuestion("example.test", TypeA)
			got, elapsed, err := (&Client{Net: network, Timeout: 3 * time.Second}).Exchange(req, addr)
			if err != nil {
				t.Fatal(err)
			}
			if got.Id != req.Id || !got.Response || len(got.Answer) != 1 || got.Answer[0].(*A).A.String() != "192.0.2.7" || elapsed < 0 {
				t.Fatalf("reply=%+v rtt=%v", got, elapsed)
			}
			select {
			case err := <-handlerDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("handler did not finish")
			}
		})
	}
}

func TestServerAndClientFailurePaths(t *testing.T) {
	if err := (&Server{}).ActivateAndServe(); err == nil {
		t.Fatal("missing listener accepted")
	}
	for _, network := range []string{"bogus", "udp", "tcp"} {
		if err := (&Server{Net: network, Addr: "127.0.0.1:invalid-port"}).ListenAndServe(); err == nil {
			t.Errorf("bad listen %s succeeded", network)
		}
	}
	for _, network := range []string{"tcp", "udp"} {
		c := &Client{Net: network, Timeout: time.Second}
		if _, _, err := c.Exchange(new(Msg).SetQuestion("x", TypeA), "127.0.0.1:bad-port"); err == nil {
			t.Fatal("bad address accepted")
		}
	}
	if _, _, err := (&Client{}).Exchange(&Msg{Question: []Question{{Name: strings.Repeat("a", 64)}}}, "127.0.0.1:1"); err == nil {
		t.Fatal("invalid query accepted")
	}
	// Wire length is big-endian and queries with no explicit class use IN.
	b, err := (&Msg{Question: []Question{{Name: ".", Qtype: TypeA}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(b[len(b)-2:]) != ClassINET {
		t.Fatal("default query class")
	}
	for _, typ := range []uint16{TypeA, TypeAAAA, TypeCNAME} {
		var rr RR
		switch typ {
		case TypeA:
			rr = &A{Hdr: RR_Header{Name: "."}}
		case TypeAAAA:
			rr = &AAAA{Hdr: RR_Header{Name: "."}}
		case TypeCNAME:
			rr = &CNAME{Hdr: RR_Header{Name: "."}, Target: "."}
		}
		got, err := packRR(rr)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got[1:3], []byte{0, byte(typ)}) {
			t.Fatal(fmt.Sprintf("record type %x", got))
		}
	}
}
