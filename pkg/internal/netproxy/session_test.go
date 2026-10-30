package netproxy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func readSessionCapture(t *testing.T, path string) []CaptureRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records []CaptureRecord
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		var record CaptureRecord
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

func TestCaptureParallelConnections(t *testing.T) {
	for _, framed := range []bool{false, true} {
		t.Run(fmt.Sprintf("framed=%t", framed), func(t *testing.T) {
			upstream, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			go func() {
				for {
					conn, err := upstream.Accept()
					if err != nil {
						return
					}
					go func() {
						defer conn.Close()
						_, _ = io.Copy(conn, conn)
					}()
				}
			}()
			capture := filepath.Join(t.TempDir(), "capture.jsonl")
			var eventMu sync.Mutex
			var events []NetEvent
			config := ProxyConfig{
				ListenAddr: "127.0.0.1:0", UpstreamAddr: upstream.Addr().String(), RecordPath: capture,
				OnPacket: func(packet Packet) {
					eventMu.Lock()
					defer eventMu.Unlock()
					events = append(events, NewNetEvent("packet", packet, packet.PayloadOffset))
				},
			}
			if framed {
				config.Framer = LengthPrefixFramer(2, 0, 2, false, 1024)
			}
			proxy := NewTCPProxy(config)
			if err := proxy.Start(); err != nil {
				t.Fatal(err)
			}
			defer proxy.Stop()
			clients := make([]*net.TCPConn, 2)
			payloads := make(map[string][]byte)
			for i := range clients {
				conn, err := net.Dial("tcp", proxy.listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				clients[i] = conn.(*net.TCPConn)
				defer conn.Close()
				data := []byte(fmt.Sprintf(`{"client":%d,"message":"separate streams"}`, i))
				if framed {
					frame := make([]byte, 2+len(data))
					binary.BigEndian.PutUint16(frame, uint16(len(data)))
					copy(frame[2:], data)
					data = frame
				}
				payloads[conn.LocalAddr().String()] = data
			}
			errors := make(chan error, len(clients))
			for _, client := range clients {
				go func() {
					_ = client.SetDeadline(time.Now().Add(5 * time.Second))
					payload := payloads[client.LocalAddr().String()]
					if _, err := client.Write(payload); err != nil {
						errors <- err
						return
					}
					_ = client.CloseWrite()
					echo, err := io.ReadAll(client)
					if err == nil && !bytes.Equal(echo, payload) {
						err = fmt.Errorf("echo differs: %q", echo)
					}
					errors <- err
				}()
			}
			for range clients {
				if err := <-errors; err != nil {
					t.Fatal(err)
				}
			}
			proxy.Stop()
			if proxy.Connections() != 2 || proxy.RecordWriteErrors() != 0 || proxy.DroppedRecords() != 0 {
				t.Fatalf("connections=%d errors=%d dropped=%d", proxy.Connections(), proxy.RecordWriteErrors(), proxy.DroppedRecords())
			}
			byConnection := map[string]map[Direction][]byte{}
			byClient := map[string]string{}
			for _, record := range readSessionCapture(t, capture) {
				if record.ConnectionID == "" || record.ServerAddr != upstream.Addr().String() || payloads[record.ClientAddr] == nil {
					t.Fatalf("missing or incorrect endpoint metadata: %+v", record)
				}
				if previous := byClient[record.ClientAddr]; previous != "" && previous != record.ConnectionID {
					t.Fatal("one socket changed connection ID")
				}
				byClient[record.ClientAddr] = record.ConnectionID
				if byConnection[record.ConnectionID] == nil {
					byConnection[record.ConnectionID] = map[Direction][]byte{}
				}
				data, err := base64.StdEncoding.DecodeString(record.DataBase64)
				if err != nil {
					t.Fatal(err)
				}
				byConnection[record.ConnectionID][record.Direction] = append(byConnection[record.ConnectionID][record.Direction], data...)
				if framed && record.PayloadOffset != 2 {
					t.Fatalf("framing offset lost: %+v", record)
				}
			}
			if len(byConnection) != 2 {
				t.Fatalf("parallel clients merged into %d connections", len(byConnection))
			}
			for client, id := range byClient {
				for _, direction := range []Direction{DirectionClientToServer, DirectionServerToClient} {
					if !bytes.Equal(byConnection[id][direction], payloads[client]) {
						t.Fatalf("capture stream corrupted: %s %s", id, direction)
					}
				}
			}
			for _, event := range events {
				if byClient[event.ClientAddr] != event.ConnectionID || event.ServerAddr != upstream.Addr().String() {
					t.Fatalf("live event lost connection metadata: %+v", event)
				}
				if framed && (event.Decoded == nil || event.PayloadOffset != 2) {
					t.Fatalf("live event failed to decode the payload: %+v", event)
				}
			}
		})
	}
}

func TestCaptureRedactionIsolatedByConnection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "redacted.jsonl")
	writer, err := newCaptureWriter(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.close()
	packets := []Packet{
		{ConnectionID: "a", Direction: DirectionClientToServer, Data: []byte("GET /a HTTP/1.1\r\nAuthor")},
		{ConnectionID: "b", Direction: DirectionClientToServer, Data: []byte("POST /b HTTP/1.1\r\nAuthorization: secret-b\r\nContent-Length: 4\r\n\r\nbody")},
		{ConnectionID: "a", Direction: DirectionClientToServer, Data: []byte("ization: secret-a\r\nX-Test: retained\r\n\r\n")},
		{ConnectionID: "a", Direction: DirectionServerToClient, Data: []byte("HTTP/1.1 200 OK\r\nSet-Cookie: secret-cookie-a\r\nContent-Length: 9\r\n\r\n")},
		{ConnectionID: "b", Direction: DirectionServerToClient, Data: []byte("HTTP/1.1 200 OK\r\nSet-Cookie: secret-cookie-b\r\nContent-Length: 0\r\n\r\n")},
		{ConnectionID: "a", Direction: DirectionServerToClient, Data: []byte("123456789")},
	}
	for _, packet := range packets {
		packet.Size = len(packet.Data)
		writer.enqueue(packet)
	}
	writer.endConnection("a")
	writer.endConnection("b")
	if len(writer.redactors) != 0 {
		t.Fatal("closed connections retained redaction state")
	}
	if err := writer.close(); err != nil {
		t.Fatal(err)
	}
	var captured strings.Builder
	for _, record := range readSessionCapture(t, path) {
		data, err := base64.StdEncoding.DecodeString(record.DataBase64)
		if err != nil {
			t.Fatal(err)
		}
		captured.Write(data)
	}
	if strings.Contains(captured.String(), "secret-") || !strings.Contains(captured.String(), "X-Test: retained") || !strings.Contains(captured.String(), "123456789") {
		t.Fatalf("cross-connection redaction corruption: %s", captured.String())
	}
}

func TestCaptureRedactionSurvivesQueueDrop(t *testing.T) {
	writer := &captureWriter{redact: true, redactors: make(map[captureStreamKey]*headerRedactor), ch: make(chan Packet, 1)}
	writer.enqueue(Packet{ConnectionID: "a", Direction: DirectionClientToServer, Data: []byte("GET / HTTP/1.1\r\nAuthor")})
	writer.enqueue(Packet{ConnectionID: "a", Direction: DirectionClientToServer, Data: []byte("ization: secret-prefix")})
	<-writer.ch
	writer.enqueue(Packet{ConnectionID: "a", Direction: DirectionClientToServer, Data: []byte("-secret-suffix\r\n\r\n")})
	if packet := <-writer.ch; bytes.Contains(packet.Data, []byte("secret")) {
		t.Fatalf("dropped packet desynchronised redaction: %q", packet.Data)
	}
	if writer.dropped.Load() != 1 {
		t.Fatal("queue drop was not counted")
	}
}

func TestCaptureSnapshotsBeforeInPlaceEdit(t *testing.T) {
	proxy := NewTCPProxy(ProxyConfig{Interactive: true, InterceptEdit: func(packet Packet, _ int) []byte {
		copy(packet.Data, "edited")
		return packet.Data
	}})
	defer proxy.cancel()
	proxy.recorder = &captureWriter{ch: make(chan Packet, 1)}
	forward := proxy.processPacket(Packet{Data: []byte("before"), Size: 6}, 0)
	if string(forward) != "edited" || string((<-proxy.recorder.ch).Data) != "before" {
		t.Fatal("in-place forwarding edit changed the captured input")
	}
}

func TestProxyStopDuringIdleHandshake(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := upstream.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	proxy := NewTCPProxy(ProxyConfig{ListenAddr: "127.0.0.1:0", UpstreamAddr: upstream.Addr().String()})
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	defer proxy.Stop()
	client, err := net.Dial("tcp", proxy.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not connect to upstream")
	}
	done := make(chan struct{}, 3)
	for range 3 {
		go func() { proxy.Stop(); done <- struct{}{} }()
	}
	for range 3 {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Stop blocked on an idle connection")
		}
	}
	if err := proxy.Start(); err == nil {
		t.Fatal("stopped proxy unexpectedly restarted")
	}
}
