package netproxy

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This test is the end-to-end demonstration of the whole toolkit: it stands up
// the standalone, intentionally-vulnerable coin lab server
// (labs/servers/go/coin-client-authoritative) as a REAL external process, puts
// our TCPProxy in the middle, and rewrites the coin balance a client reports
// from 5 to 777 on the wire. The server — which trusts the client's number —
// then approves a 100-coin purchase the player could never actually afford.
//
// The lab server has zero knowledge of this proxy: they share only TCP bytes,
// exactly like a real client/server pair with an attacker on the path. The lab
// is a separate Go module (its own go.mod, excluded from the workspace), so we
// build and launch it with `go run` under GOWORK=off rather than importing it.

// coin protocol constants, duplicated here on purpose: the test speaks the
// lab's wire format as an outside party would, without importing the lab.
const (
	coinHdrLen = 6

	coinMsgHello     uint16 = 0x0001
	coinMsgBuyItem   uint16 = 0x0010
	coinMsgWelcome   uint16 = 0x8001
	coinMsgBuyOK     uint16 = 0x8010
	coinMsgBuyDenied uint16 = 0x8011

	coinHonestBalance uint32 = 5
	coinForgedBalance uint32 = 777
	coinItemPrice     uint32 = 100
)

func coinEncode(msgType uint16, payload []byte) []byte {
	buf := make([]byte, coinHdrLen+len(payload))
	binary.BigEndian.PutUint16(buf[0:2], msgType)
	binary.BigEndian.PutUint32(buf[2:6], uint32(len(payload)))
	copy(buf[coinHdrLen:], payload)
	return buf
}

func coinReadFrame(r io.Reader) (uint16, []byte, error) {
	var hdr [coinHdrLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	msgType := binary.BigEndian.Uint16(hdr[0:2])
	n := binary.BigEndian.Uint32(hdr[2:6])
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return msgType, payload, nil
}

func coinBuyPayload(clientBalance uint32, itemID uint16) []byte {
	p := make([]byte, 6)
	binary.BigEndian.PutUint32(p[0:4], clientBalance)
	binary.BigEndian.PutUint16(p[4:6], itemID)
	return p
}

// TestCoinLabMITM_ForgeBalance is the headline demo: honestly-5-coins client,
// proxy forges 777, server approves the 100-coin purchase.
func TestCoinLabMITM_ForgeBalance(t *testing.T) {
	labAddr, stopLab := startCoinLab(t)
	defer stopLab()

	// Interception hook: on the client→server BuyItem frame, rewrite the
	// 4-byte clientBalance field (right after the 6-byte header) to 777. Every
	// other frame passes through untouched.
	var forged atomic.Bool
	intercept := func(pkt Packet, payloadOff int) []byte {
		if pkt.Direction != DirectionClientToServer {
			return nil
		}
		if len(pkt.Data) < coinHdrLen+4 {
			return nil
		}
		if binary.BigEndian.Uint16(pkt.Data[0:2]) != coinMsgBuyItem {
			return nil
		}
		out := append([]byte(nil), pkt.Data...)
		// payloadOff is the start of the application payload (== coinHdrLen).
		binary.BigEndian.PutUint32(out[payloadOff:payloadOff+4], coinForgedBalance)
		forged.Store(true)
		return out
	}

	proxy := NewTCPProxy(ProxyConfig{
		ListenAddr:    "127.0.0.1:0",
		UpstreamAddr:  labAddr,
		Interactive:   true, // required for InterceptEdit to fire
		InterceptEdit: intercept,
		// The lab's [2B type][4B len] header is a length-prefix frame: len is the
		// payload size and does not include the 6-byte header.
		Framer: LengthPrefixFramer(coinHdrLen, 2, 4, false, 1<<20),
	})
	if err := proxy.Start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer proxy.Stop()

	proxyAddr := proxy.listener.Addr().String()
	conn, err := net.DialTimeout("tcp", proxyAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 1. Hello → Welcome, and confirm the server's honest starting balance is 5.
	if _, err := conn.Write(coinEncode(coinMsgHello, nil)); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	mt, payload, err := coinReadFrame(conn)
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if mt != coinMsgWelcome {
		t.Fatalf("expected Welcome (0x%04x), got 0x%04x", coinMsgWelcome, mt)
	}
	if bal := binary.BigEndian.Uint32(payload[0:4]); bal != coinHonestBalance {
		t.Fatalf("server starting balance = %d, want %d", bal, coinHonestBalance)
	}

	// 2. Buy the 100-coin item while HONESTLY reporting only 5 coins. The client
	//    sends 5; the proxy rewrites it to 777 in flight.
	if _, err := conn.Write(coinEncode(coinMsgBuyItem, coinBuyPayload(coinHonestBalance, 1))); err != nil {
		t.Fatalf("write buy: %v", err)
	}
	mt, _, err = coinReadFrame(conn)
	if err != nil {
		t.Fatalf("read buy result: %v", err)
	}

	if !forged.Load() {
		t.Fatal("interception hook never fired — the BuyItem frame was not rewritten")
	}
	switch mt {
	case coinMsgBuyOK:
		// Success: the server approved a purchase the honest client could not afford.
	case coinMsgBuyDenied:
		t.Fatalf("purchase was denied — the MITM balance forgery did not take effect")
	default:
		t.Fatalf("unexpected reply 0x%04x to BuyItem", mt)
	}
}

// TestCoinLabMITM_ControlNoProxy is the control: the same honest 5-coin buy,
// sent DIRECTLY to the lab with no proxy in between, must be denied. This proves
// the purchase only succeeds because of the interception, not because the
// server is simply broken for everyone.
func TestCoinLabMITM_ControlNoProxy(t *testing.T) {
	labAddr, stopLab := startCoinLab(t)
	defer stopLab()

	conn, err := net.DialTimeout("tcp", labAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial lab: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(coinEncode(coinMsgBuyItem, coinBuyPayload(coinHonestBalance, 1))); err != nil {
		t.Fatalf("write buy: %v", err)
	}
	mt, _, err := coinReadFrame(conn)
	if err != nil {
		t.Fatalf("read buy result: %v", err)
	}
	if mt != coinMsgBuyDenied {
		t.Fatalf("honest 5-coin buy should be denied without a proxy, got reply 0x%04x", mt)
	}
}

// startCoinLab builds and launches the standalone coin lab server on an
// ephemeral port, returning its address and a stop function. It skips the test
// (rather than failing) when the lab module or the go toolchain isn't available,
// so the suite stays green in environments without them.
func startCoinLab(t *testing.T) (addr string, stop func()) {
	t.Helper()

	labDir, err := filepath.Abs(filepath.Join("..", "..", "..", "labs", "servers", "go", "coin-client-authoritative"))
	if err != nil {
		t.Fatalf("resolve lab dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(labDir, "go.mod")); err != nil {
		t.Skipf("coin lab module not found at %s: %v", labDir, err)
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH; skipping external lab process test")
	}

	// Bind :0 so the OS picks a free port; the lab logs the bound address.
	cmd := exec.Command("go", "run", ".")
	cmd.Dir = labDir
	cmd.Env = append(os.Environ(), "LISTEN_ADDR=127.0.0.1:0", "GOWORK=off")

	stderr, err := cmd.StderrPipe() // the lab logs via the std logger → stderr
	if err != nil {
		t.Fatalf("stderr pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start lab: %v", err)
	}

	stopped := make(chan struct{})
	stop = func() {
		_ = cmd.Process.Kill()
		<-stopped
	}
	go func() {
		_ = cmd.Wait()
		close(stopped)
	}()

	// Scrape the "listening on <addr>" line from the lab's log output.
	addrCh := make(chan string, 1)
	var once sync.Once
	go func() {
		buf := make([]byte, 4096)
		var acc strings.Builder
		for {
			n, rerr := stderr.Read(buf)
			if n > 0 {
				acc.WriteString(string(buf[:n]))
				if a := parseListenAddr(acc.String()); a != "" {
					once.Do(func() { addrCh <- a })
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	select {
	case addr = <-addrCh:
	case <-time.After(30 * time.Second): // `go run` may compile on first call
		stop()
		t.Skip("coin lab did not report a listen address in time (slow/absent toolchain)")
	}
	// Give the listener a beat to be fully ready after logging.
	if !waitDial(addr, 3*time.Second) {
		stop()
		t.Skipf("coin lab reported %s but is not accepting connections", addr)
	}
	return addr, stop
}

// parseListenAddr extracts host:port from a "...listening on 127.0.0.1:NNNNN..."
// log line, returning "" until such a line is present.
func parseListenAddr(s string) string {
	const marker = "listening on "
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}
	rest := s[i+len(marker):]
	// The address ends at the first space or newline.
	end := strings.IndexAny(rest, " \r\n")
	if end < 0 {
		return "" // wait for the rest of the line
	}
	candidate := rest[:end]
	if _, _, err := net.SplitHostPort(candidate); err != nil {
		return ""
	}
	return candidate
}

func waitDial(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
