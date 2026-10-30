package netproxy

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestLengthPrefixFramer_SupercellSplitAndCoalesce(t *testing.T) {
	framer := SupercellFramer()

	// Build two Supercell frames: type 0x2774 (10100), payloads of 3 and 1 byte.
	frame := func(typ uint16, payload []byte) []byte {
		hdr := []byte{
			byte(typ >> 8), byte(typ),
			byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)),
			0x00, 0x00, // version
		}
		return append(hdr, payload...)
	}
	f1 := frame(10100, []byte{0xAA, 0xBB, 0xCC})
	f2 := frame(10101, []byte{0xDD})

	// Partial header: not enough to cut a frame yet.
	if fl, _, ok := framer(f1[:4]); !ok || fl != 0 {
		t.Fatalf("partial header: got frameLen=%d ok=%v, want 0,true", fl, ok)
	}
	// Full header but payload incomplete.
	if fl, _, ok := framer(f1[:8]); !ok || fl != 0 {
		t.Fatalf("missing payload: got frameLen=%d ok=%v, want 0,true", fl, ok)
	}
	// Two frames glued together: must cut exactly the first.
	glued := append(append([]byte(nil), f1...), f2...)
	fl, hl, ok := framer(glued)
	if !ok || fl != len(f1) || hl != 7 {
		t.Fatalf("coalesced: got frameLen=%d headerLen=%d ok=%v, want %d,7,true", fl, hl, ok, len(f1))
	}
}

func TestLengthPrefixFramer_LostSync(t *testing.T) {
	framer := LengthPrefixFramer(7, 2, 3, false, 1024)
	// Length field claims ~16 MiB of payload — way over maxFrame ⇒ desync.
	buf := []byte{0x00, 0x01, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x01, 0x02}
	if _, _, ok := framer(buf); ok {
		t.Fatal("expected ok=false on oversized length field")
	}
}

// TestFramedRelay_EmitsOneePacketPerFrame drives a real proxy with a Framer and
// verifies that two frames sent in a single Write are observed as two packets,
// each carrying the correct opcode — proving boundary recovery works.
func TestFramedRelay_EmitsOnePacketPerFrame(t *testing.T) {
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()
	go func() {
		c, err := upstreamLn.Accept()
		if err == nil {
			io_drain(c)
		}
	}()

	var mu sync.Mutex
	var opcodes []uint16
	proxy := NewTCPProxy(ProxyConfig{
		ListenAddr:   "127.0.0.1:0",
		UpstreamAddr: upstreamLn.Addr().String(),
		Framer:       SupercellFramer(),
		OnPacket: func(pkt Packet) {
			mu.Lock()
			opcodes = append(opcodes, pkt.MessageType)
			mu.Unlock()
		},
	})
	// Bind to an ephemeral port via a pre-listen trick.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	proxy.config.ListenAddr = addr
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	defer proxy.Stop()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	frame := func(typ uint16, payload []byte) []byte {
		hdr := []byte{byte(typ >> 8), byte(typ),
			byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), 0, 0}
		return append(hdr, payload...)
	}
	glued := append(frame(10100, []byte{1, 2, 3}), frame(10101, []byte{9})...)
	if _, err := conn.Write(glued); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(opcodes)
		mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(opcodes) != 2 {
		t.Fatalf("expected 2 framed packets, got %d (%v)", len(opcodes), opcodes)
	}
	if opcodes[0] != 10100 || opcodes[1] != 10101 {
		t.Fatalf("opcodes mismatch: got %v, want [10100 10101]", opcodes)
	}
}

func io_drain(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 4096)
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}
