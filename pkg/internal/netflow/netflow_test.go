package netflow

import (
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name      string
		payload   []byte
		transport string
		want      Protocol
	}{
		{"http request", []byte("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"), "tcp", ProtoHTTP1},
		{"http response", []byte("HTTP/1.1 200 OK\r\n\r\n"), "tcp", ProtoHTTP1},
		{"http2 preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), "tcp", ProtoHTTP2},
		{"tls handshake", []byte{0x16, 0x03, 0x01, 0x00, 0x05}, "tcp", ProtoTLS},
		{"tls appdata", []byte{0x17, 0x03, 0x03, 0x00, 0x05}, "tcp", ProtoTLS},
		{"ssh banner", []byte("SSH-2.0-OpenSSH\r\n"), "tcp", ProtoSSH},
		{"websocket", []byte("GET /c HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"), "tcp", ProtoWebSocket},
		{"dns udp", []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, "udp", ProtoDNS},
		{"dns bytes over tcp not dns", []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}, "tcp", ProtoUnknown},
		{"random", []byte{0xde, 0xad, 0xbe, 0xef}, "tcp", ProtoUnknown},
		{"empty", nil, "tcp", ProtoUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.payload, tc.transport); got != tc.want {
				t.Errorf("Classify() = %q, want %q", got, tc.want)
			}
		})
	}
}

// buildClientHello builds a minimal TLS ClientHello with an SNI extension.
func buildClientHello(host string) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id len
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 1, 0) // compression

	hb := []byte(host)
	sni := []byte{byte((len(hb) + 3) >> 8), byte(len(hb) + 3), 0, byte(len(hb) >> 8), byte(len(hb))}
	sni = append(sni, hb...)
	exts := []byte{0x00, 0x00, byte(len(sni) >> 8), byte(len(sni))}
	exts = append(exts, sni...)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)
	return rec
}

func TestTLSSNI(t *testing.T) {
	sni := TLSSNI(buildClientHello("game.example.com"))
	if sni != "game.example.com" {
		t.Fatalf("TLSSNI = %q, want game.example.com", sni)
	}
	if TLSSNI([]byte("not tls")) != "" {
		t.Errorf("expected empty SNI for non-TLS bytes")
	}
}

func TestFlowTable_ReconstructsAndClassifies(t *testing.T) {
	ft := NewFlowTable()
	now := time.Now()
	ft.Observe("tcp", "10.0.0.9", 5000, "93.1.2.3", 80, C2S, now, []byte("GET / HTTP/1.1\r\n"))
	ft.Observe("tcp", "10.0.0.9", 5000, "93.1.2.3", 80, C2S, now, []byte("Host: x\r\n\r\n"))
	ft.Observe("tcp", "93.1.2.3", 80, "10.0.0.9", 5000, S2C, now, []byte("HTTP/1.1 200 OK\r\n\r\nhi"))

	if ft.Len() != 1 {
		t.Fatalf("expected 1 flow, got %d", ft.Len())
	}
	f := ft.Flows()[0]
	if f.Protocol != ProtoHTTP1 {
		t.Errorf("protocol = %q, want http1", f.Protocol)
	}
	if string(f.ClientStream()) != "GET / HTTP/1.1\r\nHost: x\r\n\r\n" {
		t.Errorf("client stream reassembly wrong: %q", f.ClientStream())
	}
	if string(f.ServerStream()) != "HTTP/1.1 200 OK\r\n\r\nhi" {
		t.Errorf("server stream reassembly wrong: %q", f.ServerStream())
	}
	if f.BytesC2S == 0 || f.BytesS2C == 0 {
		t.Errorf("byte counters not updated: c2s=%d s2c=%d", f.BytesC2S, f.BytesS2C)
	}
}

func TestFlowTable_BothDirectionsShareKey(t *testing.T) {
	ft := NewFlowTable()
	now := time.Now()
	ft.Observe("tcp", "1.1.1.1", 2000, "2.2.2.2", 443, C2S, now, []byte{0x16, 0x03, 0x03, 0, 1, 0})
	ft.Observe("tcp", "2.2.2.2", 443, "1.1.1.1", 2000, S2C, now, []byte{0x16, 0x03, 0x03, 0, 1, 0})
	if ft.Len() != 1 {
		t.Fatalf("both directions should map to one flow, got %d", ft.Len())
	}
}

func TestFlowTable_ExtractsTLSSNI(t *testing.T) {
	ft := NewFlowTable()
	ch := buildClientHello("api.example.com")
	ft.Observe("tcp", "10.0.0.1", 5000, "93.1.2.3", 443, C2S, time.Now(), ch)
	f := ft.Flows()[0]
	if f.Protocol != ProtoTLS {
		t.Fatalf("protocol = %q, want tls", f.Protocol)
	}
	if f.SNI != "api.example.com" {
		t.Errorf("SNI = %q, want api.example.com", f.SNI)
	}
}

func mustCompile(t *testing.T, expr string) *Filter {
	t.Helper()
	f, err := Compile(expr)
	if err != nil {
		t.Fatalf("Compile(%q) failed: %v", expr, err)
	}
	return f
}

func TestFilter_Match(t *testing.T) {
	rec := Record{
		Protocol:  ProtoTLS,
		SrcIP:     "10.0.0.5",
		DstIP:     "93.184.216.34",
		SrcPort:   51000,
		DstPort:   443,
		Direction: "c2s",
		Length:    1500,
		SNI:       "ads.example.com",
		Payload:   []byte("hello password world"),
	}

	cases := []struct {
		expr string
		want bool
	}{
		{"proto == tls", true},
		{"proto == http1", false},
		{"tls", true}, // bare protocol shorthand
		{"websocket", false},
		{"port == 443", true},
		{"port.src == 51000", true},
		{"port.dst == 80", false},
		{"len > 1400", true},
		{"len <= 1000", false},
		{"ip == 10.0.0.5", true},
		{"ip == 8.8.8.8", false},
		{"ip.dst == 93.184.216.34", true},
		{"sni contains \"ads\"", true},
		{`sni matches "\.example\.com$"`, true},
		{"payload contains \"password\"", true},
		{"payload contains \"secret\"", false},
		{"proto == tls and port == 443", true},
		{"proto == tls and port == 80", false},
		{"proto == http1 or port == 443", true},
		{"not proto == http1", true},
		{"not (proto == tls)", false},
		{"(proto == tls or proto == http2) and len > 1000", true},
		{"ip != 1.2.3.4", true},
		{"ip != 10.0.0.5", false}, // != means neither endpoint equals
		{"", true},                // empty matches everything
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			f := mustCompile(t, tc.expr)
			if got := f.Match(rec); got != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.expr, got, tc.want)
			}
		})
	}
}

func TestFilter_CompileErrors(t *testing.T) {
	bad := []string{
		"proto ==",           // missing value
		"== tls",             // missing field
		"proto == tls and",   // dangling and
		"(proto == tls",      // unbalanced paren
		"bogus == 1",         // unknown field
		"sni matches \"[\"",  // bad regexp
		"proto == tls extra", // trailing token
	}
	for _, expr := range bad {
		t.Run(expr, func(t *testing.T) {
			if _, err := Compile(expr); err == nil {
				t.Errorf("Compile(%q) succeeded, want error", expr)
			}
		})
	}
}

func TestFlowTable_Select(t *testing.T) {
	ft := NewFlowTable()
	now := time.Now()
	ft.Observe("tcp", "10.0.0.1", 5000, "1.1.1.1", 443, C2S, now, []byte{0x16, 0x03, 0x03, 0, 1, 0})
	ft.Observe("tcp", "10.0.0.1", 5001, "2.2.2.2", 80, C2S, now, []byte("GET / HTTP/1.1\r\n\r\n"))

	tlsFlows := ft.Select(mustCompile(t, "proto == tls"))
	if len(tlsFlows) != 1 || tlsFlows[0].Protocol != ProtoTLS {
		t.Fatalf("expected exactly one tls flow, got %d", len(tlsFlows))
	}
	port80 := ft.Select(mustCompile(t, "port == 80"))
	if len(port80) != 1 || port80[0].Protocol != ProtoHTTP1 {
		t.Fatalf("expected exactly one port-80 http flow, got %d", len(port80))
	}
}
