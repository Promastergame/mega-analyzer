package labkit

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"
	"time"
)

func TestComputeAcceptKeyRFCExample(t *testing.T) {
	// Example from RFC 6455 §1.3.
	got := computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==")
	want := "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	if got != want {
		t.Fatalf("accept key = %q, want %q", got, want)
	}
}

func TestFrameCodecRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("hi"),
		bytes.Repeat([]byte("x"), 200),   // 16-bit length path
		bytes.Repeat([]byte("y"), 70000), // 64-bit length path
	}
	for _, payload := range cases {
		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		in := wsFrame{fin: true, opcode: opBinary, masked: true, maskKey: [4]byte{9, 8, 7, 6}, payload: payload}
		if err := writeFrame(bw, in); err != nil {
			t.Fatal(err)
		}
		if err := bw.Flush(); err != nil {
			t.Fatal(err)
		}
		out, err := readFrame(bufio.NewReader(&buf))
		if err != nil {
			t.Fatal(err)
		}
		if out.opcode != opBinary || !out.fin {
			t.Fatalf("header mismatch: %+v", out)
		}
		if !bytes.Equal(out.payload, payload) {
			t.Fatalf("payload mismatch: got %d bytes", len(out.payload))
		}
	}
}

func TestWebSocketEchoIntegration(t *testing.T) {
	cfg := &Config{Servers: []ServerConfig{{
		Name: "ws", Kind: "http", Addr: "127.0.0.1:0",
		HTTP: &HTTPConfig{Routes: []RouteConfig{{Path: "/ws", WebSocket: true}}},
	}}}
	mgr := startManager(t, cfg)
	addr := serviceAddr(t, mgr, "ws")

	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)

	req := "GET /ws HTTP/1.1\r\n" +
		"Host: lab\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := bw.WriteString(req); err != nil {
		t.Fatal(err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}

	// Read the handshake response headers.
	var header strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading handshake: %v", err)
		}
		header.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	if !strings.Contains(header.String(), "101 Switching Protocols") {
		t.Fatalf("no 101 in handshake: %q", header.String())
	}
	if !strings.Contains(header.String(), "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") {
		t.Fatalf("bad accept header: %q", header.String())
	}

	// Send a masked text frame and expect the same payload echoed unmasked.
	msg := []byte("hello lab")
	if err := writeFrame(bw, wsFrame{fin: true, opcode: opText, masked: true, maskKey: [4]byte{1, 2, 3, 4}, payload: msg}); err != nil {
		t.Fatal(err)
	}
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	echo, err := readFrame(br)
	if err != nil {
		t.Fatal(err)
	}
	if echo.opcode != opText || string(echo.payload) != string(msg) {
		t.Fatalf("echo mismatch: op=%x payload=%q", echo.opcode, echo.payload)
	}
	if echo.masked {
		t.Fatalf("server frames must not be masked")
	}
}
