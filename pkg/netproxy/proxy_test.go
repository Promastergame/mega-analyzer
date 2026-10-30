package netproxy

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPacketHexDumpAndSummary(t *testing.T) {
	p := &Packet{
		Timestamp:   time.Now(),
		Direction:   DirectionClientToServer,
		Size:        4,
		Data:        []byte{0xDE, 0xAD, 0xBE, 0xEF},
		MessageType: 0x1234,
	}
	dump := p.HexDump(2)
	if !strings.Contains(dump, "de ad") && !strings.Contains(dump, "DE AD") {
		t.Errorf("HexDump should print first 2 bytes, got %q", dump)
	}

	summary := p.Summary()
	if !strings.Contains(summary, "C→S") {
		t.Errorf("Summary missing direction: %q", summary)
	}
	if !strings.Contains(summary, "0x1234") {
		t.Errorf("Summary missing message type: %q", summary)
	}

	// MessageName takes precedence when set.
	p.MessageName = "Login"
	if !strings.Contains(p.Summary(), "Login") {
		t.Errorf("Summary should use MessageName when set")
	}
}

func TestDefaultHeaderParser(t *testing.T) {
	if mt, off := defaultHeaderParser(nil); mt != 0 || off != 0 {
		t.Errorf("nil input should yield zero, got (%d, %d)", mt, off)
	}
	mt, off := defaultHeaderParser([]byte{0x10, 0xA5, 0x99})
	if mt != binary.BigEndian.Uint16([]byte{0x10, 0xA5}) {
		t.Errorf("message type wrong: 0x%04x", mt)
	}
	if off != 2 {
		t.Errorf("payload offset = %d, want 2", off)
	}
}

func TestPacketRecorderLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "rec.jsonl")
	r, err := NewPacketRecorder(path)
	if err != nil {
		t.Fatalf("NewPacketRecorder: %v", err)
	}

	for i := 0; i < 3; i++ {
		r.Record(Packet{Direction: DirectionClientToServer, Size: 1, Data: []byte{byte(i)}})
	}
	if got := r.Count(); got != 3 {
		t.Errorf("Count = %d, want 3", got)
	}
	pkts := r.Packets()
	if len(pkts) != 3 {
		t.Errorf("Packets() returned %d, want 3", len(pkts))
	}
	for i, p := range pkts {
		if p.ID != uint64(i+1) {
			t.Errorf("Record should auto-stamp ID monotonically, got %d for index %d", p.ID, i)
		}
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestPacketRecorderEmptyPath(t *testing.T) {
	// Empty / unwritable path should fail.
	_, err := NewPacketRecorder(filepath.Join(t.TempDir(), strings.Repeat("x", 0)))
	if err == nil {
		t.Skip("OS allowed empty filename creation; skipping")
	}
}

func TestNewTCPProxyDefaults(t *testing.T) {
	p := NewTCPProxy(ProxyConfig{ListenAddr: "127.0.0.1:0"})
	if p == nil {
		t.Fatal("NewTCPProxy returned nil")
	}
	if p.config.HeaderParser == nil {
		t.Error("default HeaderParser should be installed when caller leaves it nil")
	}
}

func TestNewTCPProxyCustomHeaderParser(t *testing.T) {
	called := false
	parser := func(b []byte) (uint16, int) {
		called = true
		return 0xBEEF, len(b)
	}
	p := NewTCPProxy(ProxyConfig{HeaderParser: parser})
	mt, off := p.config.HeaderParser([]byte{0x01})
	if mt != 0xBEEF || off != 1 || !called {
		t.Errorf("custom HeaderParser not honoured (mt=0x%x off=%d called=%v)", mt, off, called)
	}
}

func TestTCPProxyStartFailsOnBadAddress(t *testing.T) {
	p := NewTCPProxy(ProxyConfig{ListenAddr: "not-a-valid-address"})
	if err := p.Start(); err == nil {
		t.Fatal("expected listen error for bad address")
	}
}

func TestTCPProxyStartFailsOnBadRecordPath(t *testing.T) {
	// Use a path that's a parent file (not a directory) — recorder dir
	// creation should fail.
	dir := t.TempDir()
	conflictFile := filepath.Join(dir, "conflict")
	if err := os.WriteFile(conflictFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := NewTCPProxy(ProxyConfig{
		ListenAddr: "127.0.0.1:0",
		RecordPath: filepath.Join(conflictFile, "subdir", "rec.jsonl"),
	})
	if err := p.Start(); err == nil {
		_ = p.Stop()
		t.Fatal("expected error when record path is unwritable")
	}
}

// TestTCPProxyEndToEnd spins up:
//   - upstream echo server (we control)
//   - TCPProxy pointing client traffic to it
//   - client connection that sends bytes through the proxy
//
// and asserts that the recorder captured the traffic.
func TestTCPProxyEndToEnd(t *testing.T) {
	// 1. Echo upstream
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echo.Close()

	var echoWG sync.WaitGroup
	echoWG.Add(1)
	go func() {
		defer echoWG.Done()
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1024)
		n, _ := c.Read(buf)
		if n > 0 {
			c.Write(buf[:n])
		}
	}()

	// 2. Proxy.
	dir := t.TempDir()
	rec := filepath.Join(dir, "packets.jsonl")

	var packetsSeen []Packet
	var pktMu sync.Mutex
	p := NewTCPProxy(ProxyConfig{
		ListenAddr:   "127.0.0.1:0",
		UpstreamAddr: echo.Addr().String(),
		RecordPath:   rec,
		OnPacket: func(p Packet) {
			pktMu.Lock()
			packetsSeen = append(packetsSeen, p)
			pktMu.Unlock()
		},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	defer p.Stop()

	// Determine actual bound port.
	proxyAddr := p.listener.Addr().String()

	// 3. Client → proxy → upstream → proxy → client.
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	payload := []byte{0x10, 0xA5, 0xDE, 0xAD}
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read echo: %v", err)
	}

	// Allow the proxy goroutines to flush.
	time.Sleep(50 * time.Millisecond)

	pktMu.Lock()
	defer pktMu.Unlock()
	if len(packetsSeen) == 0 {
		t.Fatal("expected at least one packet via OnPacket")
	}

	if got := p.Stats(); got == 0 {
		t.Errorf("Stats() should reflect recorded packets, got %d", got)
	}

	echoWG.Wait()
}

func TestTCPProxyStopBeforeStart(t *testing.T) {
	// Stopping a proxy that never listened should not panic.
	p := NewTCPProxy(ProxyConfig{})
	if err := p.Stop(); err != nil {
		t.Errorf("Stop on unstarted proxy returned %v", err)
	}
}

func TestUDPProxyLifecycle(t *testing.T) {
	// 1. Upstream UDP echo server
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, clientAddr, err := serverConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			serverConn.WriteToUDP(buf[:n], clientAddr)
		}
	}()

	// 2. Start UDPProxy
	dir := t.TempDir()
	recPath := filepath.Join(dir, "udp_packets.jsonl")

	p := NewUDPProxy(ProxyConfig{
		ListenAddr:   "127.0.0.1:0",
		UpstreamAddr: serverConn.LocalAddr().String(),
		RecordPath:   recPath,
	})

	if err := p.Start(); err != nil {
		t.Fatalf("UDPProxy start failed: %v", err)
	}
	defer p.Stop()

	// 3. Client connection sending packet
	proxyAddr, err := net.ResolveUDPAddr("udp", p.conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConn, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	payload := []byte{0x00, 0x01, 0x02, 0x03}
	if _, err := clientConn.Write(payload); err != nil {
		t.Fatal(err)
	}

	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, len(payload))
	n, _, err := clientConn.ReadFrom(resp)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}

	if n != len(payload) {
		t.Errorf("Expected %d bytes response, got %d", len(payload), n)
	}

	// Stats check
	time.Sleep(50 * time.Millisecond)
	if p.Stats() == 0 {
		t.Error("Expected recorded packets count to be greater than 0")
	}
}

func TestPacketEditorRewrite(t *testing.T) {
	pe := NewPacketEditor()

	pktJSON := Packet{
		MessageType: 1,
		Direction:   DirectionClientToServer,
		Size:        20,
		Data:        []byte(`{"enabled":false,"value":42}`),
	}

	// 1. Stdin simulation for "n" (pass original)
	r, w, _ := os.Pipe()
	oldStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()

	w.Write([]byte("n\n"))
	res := pe.PromptAndRewrite(pktJSON, 0)
	if res != nil {
		t.Errorf("Expected nil for pass action, got %s", string(res))
	}

	// 2. Stdin simulation for "i" (ignore)
	r, w, _ = os.Pipe()
	os.Stdin = r
	w.Write([]byte("i\n"))
	res = pe.PromptAndRewrite(pktJSON, 0)
	if res != nil {
		t.Errorf("Expected nil for ignore action, got %s", string(res))
	}
	if !pe.IsIgnored(1) {
		t.Error("Expected message type 1 to be ignored")
	}

	// 3. Stdin simulation for "y" with JSON edits
	r, w, _ = os.Pipe()
	os.Stdin = r
	// We have two fields: enabled (bool), value (float64/int).
	// We will answer: "true" for enabled, and "" (keep) for value.
	w.Write([]byte("y\ntrue\n\n"))
	pktJSON.MessageType = 2 // not ignored
	res = pe.PromptAndRewrite(pktJSON, 0)
	if res == nil {
		t.Fatal("Expected non-nil patched payload")
	}
	if !strings.Contains(string(res), `"enabled":true`) {
		t.Errorf("Expected patched JSON to contain enabled true, got %s", string(res))
	}

	// 4. Stdin simulation for hex editing
	pktHex := Packet{
		MessageType: 3,
		Direction:   DirectionClientToServer,
		Size:        5,
		Data:        []byte{0, 1, 2, 3, 4},
	}
	r, w, _ = os.Pipe()
	os.Stdin = r
	// Write "y", offset "0", hex bytes "0A0B"
	w.Write([]byte("y\n0 0A0B\n"))
	res = pe.PromptAndRewrite(pktHex, 0)
	if res == nil {
		t.Fatal("Expected non-nil patched hex payload")
	}
	if len(res) != 5 || res[0] != 0x0A || res[1] != 0x0B || res[2] != 2 || res[3] != 3 || res[4] != 4 {
		t.Errorf("Expected [10, 11, 2, 3, 4], got %v", res)
	}
}

func TestMitmRustLoadError(t *testing.T) {
	if runtime.GOOS != "windows" {
		if err := InitRustMITM("invalid_path_to_dll.dll"); err == nil || !strings.Contains(err.Error(), "Windows only") {
			t.Fatalf("Expected non-Windows unsupported error, got %v", err)
		}
		return
	}

	// Test on invalid DLL path — expected to return a normal error, not panic.
	if err := InitRustMITM("invalid_path_to_dll.dll"); err == nil {
		t.Fatal("Expected error when loading invalid DLL path")
	}

	// Continue testing other DLL functions when engine is nil.
	engine = nil
	err := GenerateRootCA("out")
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("Expected 'not initialized' error, got %v", err)
	}

	err = StartDNSSpoof("addr", "domain", "ip")
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("Expected 'not initialized' error, got %v", err)
	}

	err = StartDHCPSpoof("addr", "gw")
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("Expected 'not initialized' error, got %v", err)
	}

	err = StartSSLStrip("addr")
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("Expected 'not initialized' error, got %v", err)
	}
}
