package labkit

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestTCPLineEcho(t *testing.T) {
	cfg := &Config{Servers: []ServerConfig{{
		Name: "tcp", Kind: "tcp", Addr: "127.0.0.1:0",
		TCP: &TCPConfig{Framing: "line"},
	}}}
	mgr := startManager(t, cfg)
	conn, err := net.DialTimeout("tcp", serviceAddr(t, mgr, "tcp"), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "ping\n" {
		t.Fatalf("echo = %q, want %q", line, "ping\n")
	}
}

func TestTCPLengthFramedEcho(t *testing.T) {
	cfg := &Config{Servers: []ServerConfig{{
		Name: "tcp", Kind: "tcp", Addr: "127.0.0.1:0",
		TCP: &TCPConfig{Framing: "length"},
	}}}
	mgr := startManager(t, cfg)
	conn, err := net.DialTimeout("tcp", serviceAddr(t, mgr, "tcp"), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := []byte("framed-message")
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := conn.Write(append(hdr[:], payload...)); err != nil {
		t.Fatal(err)
	}

	var rhdr [4]byte
	if _, err := io.ReadFull(conn, rhdr[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(rhdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("echo = %q, want %q", buf, payload)
	}
}

func TestUDPEcho(t *testing.T) {
	cfg := &Config{Servers: []ServerConfig{{
		Name: "udp", Kind: "udp", Addr: "127.0.0.1:0",
		UDP: &UDPConfig{},
	}}}
	mgr := startManager(t, cfg)
	raddr, err := net.ResolveUDPAddr("udp", serviceAddr(t, mgr, "udp"))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("datagram")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "datagram" {
		t.Fatalf("echo = %q", buf[:n])
	}
}

func TestManagerStartRejectsDoubleStart(t *testing.T) {
	cfg := &Config{Servers: []ServerConfig{{Name: "u", Kind: "udp", Addr: "127.0.0.1:0", UDP: &UDPConfig{}}}}
	mgr := startManager(t, cfg)
	if err := mgr.Start(); err == nil {
		t.Fatal("expected error on double Start")
	}
}
