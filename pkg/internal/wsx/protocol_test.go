package wsx

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Independent encoder: assertions do not use the production writer to build
// their expected input, and include all three frame length encodings.
func fixtureFrame(fin bool, op OpCode, payload []byte, masked bool) []byte {
	h := []byte{byte(op), 0}
	if fin {
		h[0] |= 0x80
	}
	n := len(payload)
	switch {
	case n < 126:
		h[1] = byte(n)
	case n <= 65535:
		h[1] = 126
		h = append(h, byte(n>>8), byte(n))
	default:
		h[1] = 127
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(n))
		h = append(h, ext...)
	}
	body := append([]byte(nil), payload...)
	if masked {
		h[1] |= 0x80
		mask := []byte{1, 23, 45, 67}
		h = append(h, mask...)
		for i := range body {
			body[i] ^= mask[i%4]
		}
	}
	return append(h, body...)
}

func pipeFixture(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

func TestFrameReadAndWriteBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 125, 126, 65535, 65536} {
		for _, masked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/masked=%v", n, masked), func(t *testing.T) {
				data := bytes.Repeat([]byte{0xab}, n)
				fin, op, got, err := readFrame(bytes.NewReader(fixtureFrame(true, OpBinary, data, masked)))
				if err != nil || !fin || op != OpBinary || !bytes.Equal(got, data) {
					t.Fatalf("frame: fin=%v op=%v len=%d err=%v", fin, op, len(got), err)
				}
			})
		}
	}
	for _, client := range []bool{false, true} {
		for _, n := range []int{0, 125, 126, 65536} {
			t.Run(fmt.Sprintf("write/client=%v/n=%d", client, n), func(t *testing.T) {
				a, b := pipeFixture(t)
				data := bytes.Repeat([]byte("z"), n)
				done := make(chan error, 1)
				go func() {
					if client {
						c := &ClientConn{conn: a, r: bufio.NewReader(a)}
						done <- c.WriteBinary(data)
					} else {
						done <- WriteServerBinary(a, data)
					}
				}()
				rd := bufio.NewReader(b)
				hdr, err := rd.Peek(2)
				if err != nil {
					t.Fatal(err)
				}
				if (hdr[1]&0x80 != 0) != client {
					t.Fatal("wrong mask bit")
				}
				fin, op, got, err := readFrame(rd)
				if err != nil || !fin || op != OpBinary || !bytes.Equal(got, data) {
					t.Fatalf("write frame=%v %v %d %v", fin, op, len(got), err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestMalformedFrames(t *testing.T) {
	for _, data := range [][]byte{nil, {0x81}, {0x81, 126, 0}, {0x81, 127, 0}, {0x81, 0x80, 1, 2, 3}, {0x81, 2, 'a'}} {
		if _, _, _, err := readFrame(bytes.NewReader(data)); err == nil {
			t.Errorf("truncated frame %x accepted", data)
		}
	}
	h := make([]byte, 10)
	h[0] = 0x82
	h[1] = 127
	binary.BigEndian.PutUint64(h[2:], MaxFrameSize+1)
	if _, _, _, err := readFrame(bytes.NewReader(h)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversize=%v", err)
	}
}

func TestMessageFragmentationAndProtocolErrors(t *testing.T) {
	for _, client := range []bool{false, true} {
		t.Run(fmt.Sprintf("client=%v", client), func(t *testing.T) {
			for _, tt := range []struct {
				name   string
				frames [][]byte
				want   string
				bad    string
			}{
				{"fragments", [][]byte{fixtureFrame(false, OpText, []byte("ab"), false), fixtureFrame(true, OpPong, nil, false), fixtureFrame(true, OpContinuation, []byte("cd"), false)}, "abcd", ""},
				{"orphan", [][]byte{fixtureFrame(true, OpContinuation, nil, false)}, "", "continuation"},
				{"interleaved", [][]byte{fixtureFrame(false, OpText, nil, false), fixtureFrame(true, OpBinary, nil, false)}, "", "previous finished"},
				{"unknown", [][]byte{fixtureFrame(true, OpCode(3), nil, false)}, "", "unknown opcode"},
				{"truncated", [][]byte{{0x81}}, "", ""},
			} {
				t.Run(tt.name, func(t *testing.T) {
					a, b := pipeFixture(t)
					done := make(chan error, 1)
					go func() { _, err := b.Write(bytes.Join(tt.frames, nil)); b.Close(); done <- err }()
					var got []byte
					var op OpCode
					var err error
					if client {
						op, got, err = (&ClientConn{conn: a, r: bufio.NewReader(a)}).ReadMessage()
					} else {
						got, op, err = ReadClientData(a)
					}
					if tt.want != "" {
						if err != nil || op != OpText || string(got) != tt.want {
							t.Fatalf("message=%q %v %v", got, op, err)
						}
					} else if err == nil || (tt.bad != "" && !strings.Contains(err.Error(), tt.bad)) {
						t.Fatalf("error=%v want %q", err, tt.bad)
					}
					if writeErr := <-done; writeErr != nil {
						t.Fatal(writeErr)
					}
				})
			}
		})
	}
}

func TestPingAndClose(t *testing.T) {
	for _, client := range []bool{false, true} {
		for _, op := range []OpCode{OpPing, OpClose} {
			t.Run(fmt.Sprintf("client=%v/op=%d", client, op), func(t *testing.T) {
				a, b := pipeFixture(t)
				done := make(chan error, 1)
				go func() {
					if _, err := b.Write(fixtureFrame(true, op, []byte("hi"), false)); err != nil {
						done <- err
						return
					}
					_, reply, payload, err := readFrame(b)
					want := OpPong
					if op == OpClose {
						want = OpClose
					}
					if err == nil && (reply != want || (op == OpPing && string(payload) != "hi")) {
						err = fmt.Errorf("reply=%v payload=%q", reply, payload)
					}
					if err == nil && op == OpPing {
						_, err = b.Write(fixtureFrame(true, OpText, []byte("done"), false))
					}
					done <- err
				}()
				var got []byte
				var err error
				if client {
					_, got, err = (&ClientConn{conn: a, r: bufio.NewReader(a)}).ReadMessage()
				} else {
					got, _, err = ReadClientData(a)
				}
				if op == OpClose {
					if !errors.Is(err, io.EOF) {
						t.Fatalf("close err=%v", err)
					}
				} else if err != nil || string(got) != "done" {
					t.Fatalf("ping message=%q err=%v", got, err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestHandshakeAndLoopback(t *testing.T) {
	if got := acceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatal(got)
	}
	for _, tt := range []struct {
		connection, upgrade, key string
		status                   int
	}{
		{"", "", "", 400}, {"keep-alive, UpGrAdE", "websocket", "", 400}, {"upgrade", "websocket", "abc", 500},
	} {
		r := httptest.NewRequest("GET", "http://localhost/", nil)
		r.Header.Set("Connection", tt.connection)
		r.Header.Set("Upgrade", tt.upgrade)
		r.Header.Set("Sec-WebSocket-Key", tt.key)
		w := httptest.NewRecorder()
		if _, _, _, err := UpgradeHTTP(r, w); err == nil || w.Code != tt.status {
			t.Fatalf("upgrade status=%d err=%v", w.Code, err)
		}
	}
	h := http.Header{"Connection": []string{"keep-alive", " UpGrAdE, other"}}
	if !headerContainsToken(h, "connection", "upgrade") || headerContainsToken(h, "Connection", "grade") {
		t.Fatal("token matching")
	}
	done := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _, _, err := UpgradeHTTP(r, w)
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if r.URL.RequestURI() != "/devtools?id=1" {
			done <- fmt.Errorf("URI=%s", r.URL)
			return
		}
		p, op, err := ReadClientData(c)
		if err == nil && (op != OpText || string(p) != "hello") {
			err = fmt.Errorf("request=%v %q", op, p)
		}
		if err == nil {
			err = WriteServerText(c, []byte("world"))
		}
		done <- err
	}))
	defer srv.Close()
	c, err := Dial("ws" + strings.TrimPrefix(srv.URL, "http") + "/devtools?id=1")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.WriteText([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	op, p, err := c.ReadMessage()
	if err != nil || op != OpText || string(p) != "world" {
		t.Fatalf("response=%v %q %v", op, p, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDialRejectsInvalidHandshakes(t *testing.T) {
	for _, url := range []string{"://bad", "https://example.invalid"} {
		if _, err := Dial(url); err == nil {
			t.Errorf("accepted %q", url)
		}
	}
	for _, status := range []int{http.StatusForbidden, http.StatusSwitchingProtocols} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Sec-WebSocket-Accept", "wrong")
				w.WriteHeader(status)
			}))
			defer srv.Close()
			if c, err := Dial("ws" + strings.TrimPrefix(srv.URL, "http")); err == nil {
				c.Close()
				t.Fatal("bad handshake accepted")
			}
		})
	}
}
