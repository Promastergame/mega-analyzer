package netproxy

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPacketHelpers(t *testing.T) {
	// Test Summary
	pkt := Packet{
		Direction: DirectionClientToServer,
		Data:      []byte{0x01, 0x02, 0x03},
		Timestamp: time.Now(),
		Size:      3,
	}
	summary := pkt.Summary()
	if summary == "" {
		t.Error("Summary returned empty string")
	}

	pktLong := Packet{
		Direction: DirectionServerToClient,
		Data:      bytes.Repeat([]byte{0x41}, 32),
		Timestamp: time.Now(),
		Size:      32,
	}
	summaryLong := pktLong.Summary()
	if summaryLong == "" {
		t.Error("Summary for long packet returned empty string")
	}

	// Test HexDump
	emptyDump := Packet{Data: nil}.HexDump(16)
	if emptyDump != "(empty)" {
		t.Errorf("Expected empty dump, got %q", emptyDump)
	}

	shortDump := pkt.HexDump(16)
	if shortDump == "" {
		t.Error("HexDump returned empty string")
	}

	longDump := pktLong.HexDump(16)
	if longDump == "" {
		t.Error("HexDump returned empty string")
	}
}

func TestParseMessageType(t *testing.T) {
	if parseMessageType(nil) != 0 {
		t.Error("parseMessageType(nil) should be 0")
	}
	if parseMessageType([]byte{0x01}) != 0 {
		t.Error("parseMessageType(short) should be 0")
	}
	if parseMessageType([]byte{0x12, 0x34}) != 0x1234 {
		t.Errorf("parseMessageType got %x, want 0x1234", parseMessageType([]byte{0x12, 0x34}))
	}
}

func TestSnifferAndJA3Fingerprint(t *testing.T) {
	// Allocate a free port for the proxy listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // Free the port so proxy can bind to it

	// Launch upstream mock server
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer upstreamLn.Close()

	go func() {
		conn, err := upstreamLn.Accept()
		if err == nil {
			defer conn.Close()
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
		}
	}()

	proxy := NewTCPProxy(ProxyConfig{
		ListenAddr:   addr,
		UpstreamAddr: upstreamLn.Addr().String(),
	})
	if err := proxy.Start(); err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	defer proxy.Stop()

	// Check Stats
	if proxy.Stats() != 0 {
		t.Errorf("Expected 0 stats, got %d", proxy.Stats())
	}

	// 1. Test TLS client handshake payload
	t.Run("TLS Sniffing", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer conn.Close()

		tlsPayload := []byte{0x16, 0x03, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x10, 0x03, 0x03}
		hasher := md5.New()
		hasher.Write(tlsPayload)
		expectedJA3 := hex.EncodeToString(hasher.Sum(nil))

		_, err = conn.Write(tlsPayload)
		if err != nil {
			t.Fatalf("Failed to write: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		// Verify expected JA3 computation
		computed := make([]byte, len(tlsPayload))
		copy(computed, tlsPayload)
		h := md5.New()
		h.Write(computed)
		gotJA3 := hex.EncodeToString(h.Sum(nil))

		if gotJA3 != expectedJA3 {
			t.Errorf("JA3 mismatch: got %s, want %s", gotJA3, expectedJA3)
		}
	})

	// 2. Test gRPC / HTTP2 preamble payload
	t.Run("gRPC HTTP2 Sniffing", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer conn.Close()

		grpcPayload := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		_, err = conn.Write(grpcPayload)
		if err != nil {
			t.Fatalf("Failed to write: %v", err)
		}

		time.Sleep(50 * time.Millisecond)

		if !bytes.HasPrefix(grpcPayload, []byte("PRI * HTTP/2.0")) {
			t.Errorf("Failed to detect gRPC prefix")
		}
	})
}

func TestRedactAuthorizationHeaders(t *testing.T) {
	d := &headerRedactor{isResponse: false}
	payload := []byte("GET / HTTP/1.1\r\nAuthorization: Bearer secret\r\nCookie: sid=secret\r\nX-Test: ok\r\n\r\n")
	redacted := string(d.process(payload))
	if strings.Contains(redacted, "Bearer secret") || strings.Contains(redacted, "sid=secret") {
		t.Fatalf("secret headers were not redacted: %q", redacted)
	}
	if !strings.Contains(redacted, "Authorization: <redacted>") || !strings.Contains(redacted, "Cookie: <redacted>") {
		t.Fatalf("redacted markers missing: %q", redacted)
	}
	if !strings.Contains(redacted, "X-Test: ok") {
		t.Fatalf("non-sensitive header lost: %q", redacted)
	}
}

func TestRedactAuthorizationHeadersLeavesBinaryPayload(t *testing.T) {
	d := &headerRedactor{isResponse: false}
	payload := []byte{0x01, ':', 0xff, 0x00}
	redacted := d.process(payload)
	if !bytes.Equal(redacted, payload) {
		t.Fatalf("binary payload changed: %x -> %x", payload, redacted)
	}
}

func TestRedactAuthorizationHeadersPreservesBody(t *testing.T) {
	d := &headerRedactor{isResponse: false}
	// Request with headers and a body. The body contains cookie-like text and is
	// framed by Content-Length so it is passed through, not treated as headers.
	body := "Cookie: should_not_redact"
	payload := []byte("POST / HTTP/1.1\r\nAuthorization: Bearer secret\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n" + body)
	redacted := string(d.process(payload))

	if !strings.Contains(redacted, "Cookie: should_not_redact") {
		t.Errorf("HTTP body was incorrectly modified or redacted: %q", redacted)
	}
	if strings.Contains(redacted, "Bearer secret") {
		t.Errorf("HTTP headers were not redacted: %q", redacted)
	}
}
