package netproxy

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCaptureWriter_RoundTrip drives a real proxy with recording enabled and
// verifies the async writer flushes a valid JSONL record on Stop.
func TestCaptureWriter_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	recPath := filepath.Join(dir, "capture.jsonl")

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Echo one read back so both directions produce a packet.
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		if n > 0 {
			_, _ = conn.Write(buf[:n])
		}
	}()

	proxy := NewTCPProxy(ProxyConfig{
		ListenAddr:   "127.0.0.1:0",
		UpstreamAddr: upstream.Addr().String(),
		RecordPath:   recPath,
	})
	if err := proxy.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}

	client, err := net.Dial("tcp", proxy.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	payload := []byte{0x12, 0x34, 0xde, 0xad, 0xbe, 0xef}
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if tcp, ok := client.(*net.TCPConn); ok {
		if err := tcp.CloseWrite(); err != nil {
			t.Fatalf("close client write side: %v", err)
		}
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(client, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != string(payload) {
		t.Fatalf("echo = %x, want %x", echo, payload)
	}
	_ = client.Close()

	proxy.Stop() // flushes and closes the recorder

	f, err := os.Open(recPath)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	defer f.Close()

	var records []CaptureRecord
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var rec CaptureRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("unmarshal record %q: %v", sc.Text(), err)
		}
		records = append(records, rec)
	}
	if len(records) == 0 {
		t.Fatal("expected at least one recorded packet, got none")
	}

	// The client→server packet must be present and decode back to the payload.
	var found bool
	for _, rec := range records {
		if rec.Direction != DirectionClientToServer {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(rec.DataBase64)
		if err != nil {
			t.Fatalf("decode data_b64: %v", err)
		}
		if string(data) == string(payload) {
			found = true
			if rec.MessageType != 0x1234 {
				t.Errorf("message_type = 0x%x, want 0x1234", rec.MessageType)
			}
		}
	}
	if !found {
		t.Errorf("client→server payload not found in %d records", len(records))
	}
	if got := proxy.RecordWriteErrors(); got != 0 {
		t.Errorf("unexpected write errors: %d", got)
	}
}

func TestIsJavaScriptHTTPResponse(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{
			name: "lowercase js response",
			in:   "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nvar x=1;",
			want: true,
		},
		{
			name: "mixed-case headers still match",
			in:   "HTTP/1.1 200 ok\r\nCONTENT-TYPE: TEXT/JAVASCRIPT\r\n\r\nvar x=1;",
			want: true,
		},
		{
			name: "x-javascript variant",
			in:   "HTTP/1.0 200 OK\r\nContent-Type: application/x-javascript\r\n\r\nvar x=1;",
			want: true,
		},
		{
			name: "html response rejected",
			in:   "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>",
			want: false,
		},
		{
			name: "non-200 rejected",
			in:   "HTTP/1.1 404 Not Found\r\nContent-Type: application/javascript\r\n\r\n",
			want: false,
		},
		{
			name: "binary traffic fast-rejected",
			in:   "\x00\x01\x02\x03 not http at all but long enough to exceed twelve bytes",
			want: false,
		},
		{
			name: "too short",
			in:   "HTTP/1.1",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isJavaScriptHTTPResponse([]byte(tc.in)); got != tc.want {
				t.Errorf("isJavaScriptHTTPResponse(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestContainsFold(t *testing.T) {
	cases := []struct {
		haystack string
		needle   string
		want     bool
	}{
		{"Content-Type: TEXT/JAVASCRIPT", "content-type: text/javascript", true},
		{"HTTP/1.1 200 OK", "200 ok", true},
		{"nothing here", "missing", false},
		{"short", "longer needle", false},
		{"anything", "", true},
		{"aBcDeF", "abcdef", true},
	}
	for _, tc := range cases {
		if got := containsFold([]byte(tc.haystack), []byte(tc.needle)); got != tc.want {
			t.Errorf("containsFold(%q, %q) = %v, want %v", tc.haystack, tc.needle, got, tc.want)
		}
	}
}
