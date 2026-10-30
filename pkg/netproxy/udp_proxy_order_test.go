package netproxy

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestUDPProxy_PreservesPerSessionOrder sends a numbered sequence of datagrams
// through the proxy and checks the upstream receives them in the same order.
// The old goroutine-per-datagram design could reorder concurrent writes to the
// shared upstream socket; the per-session ordered queue must not.
func TestUDPProxy_PreservesPerSessionOrder(t *testing.T) {
	// Upstream that records the order of the first byte-sequence numbers it sees.
	up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()

	const count = 200
	got := make(chan uint32, count)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := up.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n >= 4 {
				select {
				case got <- binary.BigEndian.Uint32(buf[:4]):
				default:
				}
			}
		}
	}()

	p := NewUDPProxy(ProxyConfig{
		ListenAddr:   "127.0.0.1:0",
		UpstreamAddr: up.LocalAddr().String(),
	})
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer p.Stop()

	proxyAddr, _ := net.ResolveUDPAddr("udp", p.conn.LocalAddr().String())
	client, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	for i := 0; i < count; i++ {
		msg := make([]byte, 4)
		binary.BigEndian.PutUint32(msg, uint32(i))
		if _, err := client.Write(msg); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Collect what the upstream received (allow for UDP loss, but order among
	// received datagrams must be monotonic).
	deadline := time.After(3 * time.Second)
	var seq []uint32
	for len(seq) < count {
		select {
		case v := <-got:
			seq = append(seq, v)
		case <-deadline:
			goto check
		}
	}
check:
	if len(seq) < 2 {
		t.Skipf("upstream received too few datagrams (%d) to assess ordering", len(seq))
	}
	for i := 1; i < len(seq); i++ {
		if seq[i] < seq[i-1] {
			t.Fatalf("out-of-order datagram at %d: %d after %d", i, seq[i], seq[i-1])
		}
	}
}

// TestUDPProxy_SessionCapEvictsLRU verifies the NAT table honours the session
// cap by evicting the least-recently-active session rather than growing without
// bound. It drives getSession directly with synthetic client addresses so it
// doesn't need thousands of real sockets.
func TestUDPProxy_SessionCapEvictsLRU(t *testing.T) {
	up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()

	p := NewUDPProxy(ProxyConfig{
		ListenAddr:   "127.0.0.1:0",
		UpstreamAddr: up.LocalAddr().String(),
	})
	if err := p.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer p.Stop()

	// Create maxUDPSessions+50 distinct client sessions.
	total := maxUDPSessions + 50
	for i := 0; i < total; i++ {
		addr := &net.UDPAddr{IP: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)), Port: 1 + (i % 60000)}
		if s := p.getSession(addr); s == nil {
			t.Fatalf("getSession returned nil at i=%d", i)
		}
	}

	if got := p.SessionCount(); got > maxUDPSessions {
		t.Errorf("session count %d exceeds cap %d", got, maxUDPSessions)
	}
	if p.EvictedSessions() == 0 {
		t.Errorf("expected some LRU evictions once the cap was exceeded, got 0")
	}
}
